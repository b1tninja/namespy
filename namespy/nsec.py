"""Authenticated denial of existence: the NSEC and NSEC3 proof rules.

Nothing here touches the network or a signature. A proof is a set of records plus a name, and the
question is whether those records *say* what a resolver needs them to say -- which is a surprising
amount of logic, because the assertion lives in the arithmetic of ordering rather than in anything
a record states in words. Signature verification stays with the verification leg: a proof whose
records are unverified proves nothing, and this module is deliberately unable to be fooled about
that distinction, since it reports what records assert and not whether they are authentic.

Two shapes of one argument, not interchangeable:

* **NSEC** (RFC 4035 §5.4) compares owner names. An NSEC RR names its owner and the next owner in
  canonical order, so a name strictly between them is proven not to exist. This hands the zone's
  name list to anyone who asks, which is the whole reason NSEC3 exists.
* **NSEC3** (RFC 5155 §8) compares *hashes* of owner names. Same shape, but the comparison values
  come from the record's own Hash Algorithm, Iterations and Salt, and a span with the Opt-Out flag
  set proves nothing about what it covers (§6¶3).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .dnssec import decode_base32hex
from .names import DomainName

if TYPE_CHECKING:  # pragma: no cover - typing only; neither module imports this one
    from .rdata import RData_RRSIG

#: An owner name paired with the record at it. Proof checking needs both and the codecs hold only
#: the RDATA -- the owner arrives in the RR header -- so every entry point takes pairs rather than
#: pretending otherwise. Callers holding packet records pass ``(record.name, record.rdata)``.
NsecEntry = tuple  # (name-ish, RData_NSEC)
Nsec3Entry = tuple  # (name-ish, RData_NSEC3)


class ProofError(ValueError):
    """A denial-of-existence proof that cannot be built from the records given.

    The subclasses are deliberately distinguishable because the resolver's next step differs: a
    proof that is merely absent means the response was incomplete, and RFC 4035 §5.4¶6 says a
    resolver MUST re-ask (typically over TCP) when truncation cost it the records; a proof that is
    internally contradictory means the zone or the path to it is broken and no retry will help.
    """


class IncompleteProofError(ProofError):
    """Nothing in the record set proves the fact; the response was short of what is needed."""


class ContradictoryProofError(ProofError):
    """The records prove something that cannot be true -- "bogus" in RFC 5155 §8.3's word."""


def _entry[Record](owner, record: Record) -> tuple[DomainName, Record]:
    return (owner if isinstance(owner, DomainName) else DomainName(owner), record)


# --------------------------------------------------------------- canonical DNS name order


def name_order_key(owner) -> tuple[bytes, ...]:
    """The sort key implementing canonical DNS name order (RFC 4034 §6.1).

    The labels, lowercased, compared from the rightmost inwards -- which is the reversed label
    tuple, so ordinary tuple comparison *is* §6.1's ordering: labels are unsigned left-justified
    octet strings in which "the absence of a octet sorts before a zero value octet" (§6.1¶1),
    exactly how Python compares bytes, and a name whose labels run out sorts before the longer name
    sharing them -- "example" before "a.example", as §6.1¶3-¶4 show.
    """
    labels = [bytes(label).lower() for label in DomainName(owner).labels() if label]
    return tuple(reversed(labels))


def canonical_name_before(first, second) -> bool:
    """Whether one name precedes another in canonical DNS name order (§6.1)."""
    return name_order_key(first) < name_order_key(second)


def sort_canonical(names: Iterable) -> list:
    """Names in canonical DNS name order -- the order an NSEC chain is built in."""
    return sorted(names, key=name_order_key)


# ------------------------------------------------------------------------- the span rules


def name_between(name, first, second) -> bool:
    """Whether ``name`` sorts strictly between two endpoints, handling the zone's wrap.

    Strict on both ends, because a name equal to an endpoint does not fall *between* anything -- it
    *matches*, which is a different proof with different consequences (RFC 4035 §5.4¶3 versus
    §5.4¶4).

    The wrap is the part implementations get wrong. The last NSEC in a zone points back at the
    apex (RFC 4034 §4.1.1¶1) and the last NSEC3 back at the first hash (RFC 5155 §7.1¶19), so its
    second endpoint sorts *before* its first. Read naively, that span covers nothing, and every
    name after the final owner then looks unproven -- a resolver with that bug reports a legitimate
    NXDOMAIN as bogus, which is a self-inflicted outage whose symptoms resemble an attack. Endpoints
    that arrive equal mean a zone with a single owner name, whose span covers everything else; that
    falls out of the same expression rather than needing a case of its own.
    """
    key = name_order_key(name)
    start = name_order_key(first)
    end = name_order_key(second)
    if start < end:
        return start < key < end
    return key > start or key < end


def hash_between(digest: bytes, first: bytes, second: bytes) -> bool:
    """The same span test for NSEC3, over digests rather than names.

    Hash order is octet order: §3.3's hashed labels all have the same unpadded base32hex length and
    the alphabet has no cased letters, so comparing digests as octet strings reproduces the
    canonical order of the owner names those labels form -- which is the "hash order" §7.1¶5 sorts
    the chain into. The wrap case is identical in reasoning and in code, for the same §7.1¶19
    last-record rule.
    """
    if first < second:
        return first < digest < second
    return digest > first or digest < second


# ------------------------------------------------------------------------ NSEC proof rules


def nsec_matches(owner, name) -> bool:
    """Whether an NSEC RR's owner name is the name in question (RFC 4035 §5.4¶3).

    Compared in canonical order rather than as text, so a response that changed case is still the
    same owner name -- and a proof that depends on the case the signer happened to use is a proof
    that will fail on somebody's zone eventually.
    """
    return name_order_key(owner) == name_order_key(name)


def nsec_proves_nxdomain(entry, name) -> bool:
    """Whether this NSEC proves the name does not exist (RFC 4035 §5.4¶4)."""
    owner, record = _entry(*entry)
    return name_between(name, owner, record.next_domain)


def nsec_proves_no_type(entry, name, rtype: int) -> bool:
    """Whether this NSEC proves ``rtype`` absent at ``name`` (RFC 4035 §5.4¶3, §5.4¶7).

    The second condition is the one most implementations start out getting wrong: §5.4¶7 requires
    a validator to **ignore the NSEC and RRSIG bits** in an NSEC RR, because a validated NSEC
    already proves both exist at its owner name. Honouring those bits would let a bitmap that
    forgot them "disprove" the record carrying it, so an NSEC never establishes the absence of
    either type here, whatever its bitmap says.
    """
    from .enums import DnsRType

    owner, record = _entry(*entry)
    if not nsec_matches(owner, name):
        return False
    if int(rtype) in (int(DnsRType.NSEC), int(DnsRType.RRSIG)):
        return False
    return not record.has_type(rtype)


def wildcard_at(encloser) -> DomainName:
    """``*.example.com.`` -- the source of synthesis for an encloser (RFC 4592 §3.3.1¶3-¶4).

    RFC 4592 fixes the only shape a synthesising wildcard can take: the asterisk label *immediately*
    descending from the closest encloser, with §3.3.1¶6-¶7 making the consequence blunt -- if that
    one name does not exist there is no synthesis and "no search for an alternate". So a wildcard
    proof is a span test against a single name, not a hunt for any wildcard that might have matched.
    """
    name = DomainName(encloser)
    labels = [label for label in name.labels() if label]
    if labels and labels[0] == b"*":
        return name
    return DomainName(f"*.{name}")


def nsec_proves_no_wildcard(entry, encloser) -> bool:
    """Whether this NSEC proves no wildcard stood at ``encloser`` (RFC 4035 §5.4¶4)."""
    return nsec_proves_nxdomain(entry, wildcard_at(encloser))


def nsec_owner_is_explicit(entry, rrsig: RData_RRSIG) -> bool:
    """§5.4¶3's second sentence: the NSEC's label count against the covering RRSIG's Labels field.

    "If the number of labels in an authenticated NSEC RR's owner name equals the Labels field of
    the covering RRSIG RR, then the existence of the NSEC RR proves that wildcard expansion could
    not have been used to match the request." An RRSIG made through a wildcard carries the
    wildcard's smaller count, so equality is what distinguishes an explicit owner name from a
    synthesis -- and it is where the Labels field earns its keep on the NSEC side of the argument.
    """
    from .dnssec import rrsig_label_count

    owner, _ = _entry(*entry)
    return rrsig_label_count(owner) == int(rrsig.labels)


def find_nsec_matching(name, entries: Iterable[NsecEntry]) -> NsecEntry | None:
    """The NSEC whose owner name is ``name``, if the set holds one."""
    for entry in entries:
        if nsec_matches(_entry(*entry)[0], name):
            return entry
    return None


def find_nsec_covering(name, entries: Iterable[NsecEntry]) -> NsecEntry | None:
    """The NSEC whose span contains ``name``, if the set holds one."""
    for entry in entries:
        if nsec_proves_nxdomain(entry, name):
            return entry
    return None


# ----------------------------------------------------------------------- NSEC3 proof rules


def nsec3_owner_digest(entry, zone) -> bytes | None:
    """The digest an NSEC3 record's owner name stands for, or None if it is not one.

    §7.1¶10 makes an NSEC3 owner name exactly one label -- the base32hex hash -- prepended to the
    zone name, so anything else is not part of this zone's chain: a record from another zone, a
    label that is not valid base32hex, or a moved RRset. §8.3¶12 worries about exactly this, since
    a record from the wrong zone proves nothing about this one.
    """
    owner, _ = _entry(*entry)
    key = name_order_key(owner)
    apex = name_order_key(DomainName(zone))
    if len(key) != len(apex) + 1 or key[: len(apex)] != apex:
        return None
    try:
        return decode_base32hex(key[-1].decode("latin-1"))
    except ValueError:
        return None


def nsec3_matches(entry, name, zone) -> bool:
    """Whether this NSEC3 is the record for ``name`` (RFC 5155 §8.3¶7).

    The record's own hash parameters decide, and §7.2¶3 requires every NSEC3 in a response to share
    them -- :func:`usable_nsec3` enforces that before a set reaches these predicates.
    """
    _, record = _entry(*entry)
    digest = nsec3_owner_digest(entry, zone)
    return digest is not None and digest == record.hash_owner(name)


def nsec3_covers(entry, name, zone) -> bool:
    """Whether the hash of ``name`` falls inside this record's span (RFC 5155 §6¶2, §8.3¶8).

    §6¶2 defines covering for Opt-Out with the same "between the owner name of the NSEC3 RR and the
    next hashed owner name" wording used everywhere else, so one predicate serves both. What Opt-Out
    changes is what a covering record *proves*, tested by :func:`nsec3_proves_nothing`, not how the
    span is computed.
    """
    _, record = _entry(*entry)
    digest = nsec3_owner_digest(entry, zone)
    if digest is None:
        return False
    return hash_between(record.hash_owner(name), digest, record.next_hashed_owner)


def nsec3_proves_nothing(entry) -> bool:
    """Whether this record must be treated as asserting nothing: the Opt-Out case (§6¶3).

    "An Opt-Out NSEC3 RR does not assert the existence or non-existence of the insecure delegations
    that it may cover." Reading an Opt-Out span as a denial turns every unsigned delegation in a big
    zone into proof that whatever name an attacker likes does not exist -- that is the attack, not an
    optimisation. §8.6 and §8.9 do use Opt-Out spans, but only to establish that a delegation is
    *insecure*, never to deny an authoritative name.
    """
    _, record = _entry(*entry)
    return record.opt_out


def nsec3_proves_no_type(entry, name, zone, rtype: int) -> bool:
    """Whether this NSEC3 proves ``rtype`` absent at ``name`` (RFC 5155 §8.5, §7.1¶5).

    §7.1¶5 means a signed zone's NSEC3 never lists the NSEC3 type, so the absence of that bit proves
    nothing and is refused rather than read as a denial -- the same mistake RFC 4035 §5.4¶7 rules out
    for NSEC. §8.5¶2 notes the related case that an empty non-terminal's record has an empty Type Bit
    Maps field, which correctly denies every type that can exist.
    """
    from .enums import DnsRType

    if int(rtype) == int(DnsRType.NSEC3):
        return False
    return nsec3_matches(entry, name, zone) and not _entry(*entry)[1].has_type(rtype)


def find_nsec3_matching(name, entries: Iterable[Nsec3Entry], zone) -> Nsec3Entry | None:
    """The NSEC3 that matches ``name``, if the set holds one."""
    for entry in entries:
        if nsec3_matches(entry, name, zone):
            return entry
    return None


def find_nsec3_covering(name, entries: Iterable[Nsec3Entry], zone) -> Nsec3Entry | None:
    """The NSEC3 whose span contains ``name``, if the set holds one."""
    for entry in entries:
        if nsec3_covers(entry, name, zone):
            return entry
    return None


def usable_nsec3(entries: Iterable[Nsec3Entry], *, strict_parameters: bool = True) -> list:
    """The records a validator may build a proof from (RFC 5155 §8.1, §8.2).

    Two MUST-ignore filters: unknown hash algorithms (§8.1, whose "the practical result ... will
    generally be considered bogus" is the correct outcome rather than a bug to hide) and any Flags
    value other than zero or one (§8.2¶1). Both drop records instead of raising, since the rest of
    the set may still prove the fact.

    Mixed parameters are then refused. §8.2¶2 says a validator MAY treat such a response as bogus and
    this package takes the option, because hashes computed under different salts or iteration counts
    are not comparable: a set that mixes them lets a server pair a matching record with a covering
    record computed *differently*, giving two proofs that are each internally consistent and
    together prove nothing.
    """
    from .dnssec import Nsec3HashAlgorithm

    known = {int(algorithm) for algorithm in Nsec3HashAlgorithm}
    usable = [
        entry
        for entry in entries
        if _entry(*entry)[1].hash_algorithm in known and _entry(*entry)[1].flags <= 1
    ]
    if strict_parameters:
        parameters = {
            (
                _entry(*entry)[1].hash_algorithm,
                _entry(*entry)[1].iterations,
                _entry(*entry)[1].salt,
            )
            for entry in usable
        }
        if len(parameters) > 1:
            raise ContradictoryProofError(
                f"the response holds NSEC3 RRs with {len(parameters)} different hash algorithm / "
                f"iterations / salt combinations (RFC 5155 §7.2¶3, §8.2¶2)"
            )
    return usable


def nsec3_record_is_from_proper_zone(entry) -> bool:
    """§8.3¶12: the encloser's record must belong to the zone making the claim.

    "The DNAME type bit must not be set and the NS type bit may only be set if the SOA type bit is
    set. If this is not the case, it would be an indication that an attacker is using them to falsely
    deny the existence of RRs for which the server is not authoritative." A DNAME at the claimed
    encloser means the names below it belong to the target's zone, and a bare NS without SOA is a
    delegation point where the parent is not authoritative either -- so a proof built from such a
    name denies nothing, however well signed it is.
    """
    from .enums import DnsRType

    _, record = _entry(*entry)
    if record.has_type(DnsRType.DNAME):
        return False  # names below a DNAME belong to the target's zone, not this one
    return not record.has_type(DnsRType.NS) or record.has_type(DnsRType.SOA)


@dataclass(frozen=True)
class ClosestEncloserProof:
    """The (up to) two NSEC3 RRs proving that an ancestor of a name is its closest encloser."""

    encloser: DomainName
    encloser_entry: Nsec3Entry
    next_closer: DomainName
    next_closer_entry: Nsec3Entry

    @property
    def via_opt_out(self) -> bool:
        """Whether the covering record is Opt-Out, which decides the AD bit (RFC 5155 §9.2).

        §9.2¶1: the AD bit "MUST NOT be set when returning a response containing a closest (provable)
        encloser proof in which the NSEC3 RR that covers the next closer name has the Opt-Out bit
        set", because names inside that span may exist as insecure delegations, so not everything in
        the response has been cryptographically verified. Setting the bit is the resolver layer's
        job; this flag is how it will know not to.
        """
        return nsec3_proves_nothing(self.next_closer_entry)


def closest_encloser_proof(qname, entries, zone) -> ClosestEncloserProof:
    """RFC 5155 §8.3's algorithm, implemented as written.

    Walk from QNAME toward the root carrying one flag: "the name one label longer than this one is
    covered by a record in the set". The flag is cleared only when a name has no matching record, and
    set whenever a name is covered -- the order §8.3¶7-¶8 list those bullets in, and the asymmetry
    matters, because the parent that turns out to be the encloser has to keep the flag its child
    raised.

    A name that matches while the flag is clear cannot belong in a denial: it exists, and §8.3¶10
    calls a response offering this bogus rather than merely unhelpful. A name that matches with the
    flag set is the closest encloser -- RFC 4592 §3.3.1's "node ... that has the most labels matching
    the query name" -- the covered longer name is the next closer, and those two records are the
    proof.

    Finding no match at all on the way down is an *incomplete* proof rather than a contradiction: the
    records were not in the response, which RFC 4035 §5.4¶6 answers by asking again, over TCP if need
    be.
    """
    usable = usable_nsec3(entries)
    sname = DomainName(qname)
    apex_labels = len([label for label in DomainName(zone).labels() if label])
    flag = False
    flagged_name: DomainName | None = None
    covering: Nsec3Entry | None = None

    while True:
        matching = find_nsec3_matching(sname, usable, zone)
        coverer = find_nsec3_covering(sname, usable, zone)
        if matching is None:
            flag = False
            covering = None
        if coverer is not None:
            flag = True
            covering = coverer
            flagged_name = sname
        if matching is not None and flag:
            if covering is None or flagged_name is None:  # pragma: no cover - flag implies both
                raise ContradictoryProofError(
                    f"the NSEC3 RR matching {sname} is itself covered by another record, which "
                    f"cannot happen for a name that exists (RFC 5155 §8.3)"
                )
            if not nsec3_record_is_from_proper_zone(matching):
                raise ContradictoryProofError(
                    f"the NSEC3 RR matching {sname} carries a DNAME, or an NS without an SOA, so "
                    f"this server is not authoritative below it and cannot deny names there "
                    f"(RFC 5155 §8.3¶12)"
                )
            return ClosestEncloserProof(
                encloser=sname,
                encloser_entry=matching,
                next_closer=flagged_name,
                next_closer_entry=covering,
            )
        if matching is not None:
            raise ContradictoryProofError(
                f"the response offers a closest encloser proof for {sname}, but an NSEC3 RR matches "
                f"it, so the name exists (RFC 5155 §8.3¶10)"
            )
        labels = [label for label in sname.labels() if label]
        if len(labels) <= apex_labels:
            raise IncompleteProofError(
                f"no NSEC3 RR in the response matches or covers any ancestor of {qname} down to the "
                f"zone apex {DomainName(zone)} (RFC 5155 §8.3)"
            )
        sname = DomainName(".".join(label.decode("latin-1") for label in labels[1:]) + ".")


@dataclass(frozen=True)
class Nsec3NxdomainProof:
    """A complete Name Error proof: the closest encloser, plus the denial of its wildcard."""

    closest: ClosestEncloserProof
    wildcard: DomainName
    wildcard_entry: Nsec3Entry


def nsec3_proves_nxdomain(qname, entries, zone) -> Nsec3NxdomainProof:
    """RFC 5155 §8.4's whole Name Error check, not merely the encloser half.

    "A validator MUST verify that there is a closest encloser proof for QNAME present in the response
    **and** that there is an NSEC3 RR that covers the wildcard at the closest encloser." That second
    clause is what stops a server denying "hostile.example.com." because it holds no such name while
    a ``*.example.com.`` wildcard in fact answers for it: proving the encloser exists and the child
    does not is only half of establishing that NXDOMAIN was the right answer.

    IncompleteProofError when either half is missing -- the wildcard record is often what truncation
    drops first, being the third one.
    """
    usable = usable_nsec3(entries)
    closest = closest_encloser_proof(qname, usable, zone)
    wildcard = wildcard_at(closest.encloser)
    covering = find_nsec3_covering(wildcard, usable, zone)
    if covering is None:
        raise IncompleteProofError(
            f"the response proves the closest encloser {closest.encloser} but holds no NSEC3 RR "
            f"covering the wildcard {wildcard} (RFC 5155 §8.4)"
        )
    return Nsec3NxdomainProof(closest=closest, wildcard=wildcard, wildcard_entry=covering)
