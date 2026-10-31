"""The RFC 4035 §5.3.1 check: does this signature authenticate this RRset under these keys.

Two functions, one question each. :func:`verify_rrsig` asks it of an RRset and a zone's
DNSKEY RRset; :func:`authenticate_dnskey_rrset` asks the question one link up -- whether
the apex DNSKEY RRset itself is authenticated by a trusted DS or trust anchor, the
RFC 4035 §5.2 step that decides whether any :func:`verify_rrsig` answer means anything.
The chain of trust is these two questions composed, and they stay two because their
failures mean different things: a failed RRset signature is a forged answer, a failed
chain link is a broken or absent path, and a resolver walks away from each differently.
Everything the answers need is on the table already: the
canonical-RRset reconstruction from `namespy.dnssec`, the key and signature layouts from
the encoding legs, the algorithm policy from `namespy.crypto`. What this module owns is
the *procedure* -- the order the conditions are checked in, which failures mean *invalid*
and which mean *we could not run the arithmetic*, and the §5.3.1¶10 loop over every key
whose tag and algorithm match, because a validator "cannot predetermine which DNSKEY RR
to use" and MUST try each.

What a VALID verdict does **not** mean: that the response is secure. §5.3.1¶11 is explicit
that authentication "is only meaningful if the validator authenticates the DNSKEY RR
before using it", and ¶12-¶13 make that a question about the apex DNSKEY RRset and the
parent's DS -- what :func:`authenticate_dnskey_rrset` answers, one link up. A VALID verdict here means *some key
in the set you handed me signed these bytes*, and nothing about what that key is worth.
Likewise ¶2 (same owner and class as the RRSIG) and ¶3 (the signer's name is the zone
that contains the RRset) are equalities across RR headers this codec layer cannot see --
the RDATA holds no owner or class -- so they belong to the caller, the same way the
entry-pair discipline hands `namespy.nsec` its owners.

Three outcomes, not two, because the resolver's next step differs between them:

* **VALID** -- the arithmetic ran and accepted.
* **INVALID** -- the RRset does not authenticate: the signtime window is shut, the type
  covered is wrong, no DNSKEY matches, or every matching key refused the signature. This
  is bogus-material territory: retrying will not help.
* **UNSUPPORTED** -- nothing could be tried: RFC 9904's MAY-tier or an unregistered
  algorithm, an install without `namespy[crypto]`, or matching keys whose bytes the
  backend cannot build a key from. RFC 9080 §3.1 named the state Indeterminate for
  exactly this reason -- "we could not check" must not be laundered into "it is forged",
  because the difference is whether the resolver drops the answer or keeps walking.

The MUST NOT algorithms of RFC 9904 Table 2 (RSAMD5, DSA) land on INVALID rather than
UNSUPPORTED: §1.2¶3 says the point of the marking is "so that recursive resolvers can
remove support for validating it" -- a validator is entitled to conclude nothing more, and
a signature nobody may validate authenticates nothing, however well the bytes would have
verified.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from .crypto import (
    SIGNATURE_ALGORITHMS,
    SignatureMaterialError,
    ValidationRequirement,
    backend_supports,
    validation_requirement,
    verify_dnskey_signature,
)
from .dnssec import (
    DNSKEY_PROTOCOL_VALUE,
    ds_digest,
    known_digest_octets,
    rrsig_signed_data,
)
from .enums import DnsRType
from .names import DomainName

if TYPE_CHECKING:  # pragma: no cover - typing only; the records arrive duck-typed
    from .rdata import RData_DNSKEY, RData_DS, RData_RRSIG

__all__ = [
    "ChainOutcome",
    "ChainVerdict",
    "SignatureOutcome",
    "SignatureVerdict",
    "authenticate_dnskey_rrset",
    "verify_rrsig",
]


class SignatureOutcome(Enum):
    """The three answers §5.3.1 can leave a validator with, read through RFC 9080 §3.1."""

    VALID = "valid"
    INVALID = "invalid"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class SignatureVerdict:
    """What one §5.3.1 run concluded, and in whose words an operator should read it.

    *reason* is written for the log line rather than the unit test: it names the
    condition that decided, cites the document that wrote it, and for UNSUPPORTED says
    what would have made the check possible. *attempts* counts arithmetic that actually
    ran -- keys skipped as unreadable material are not attempts, which is what keeps
    "tried and refused" countable apart from "could not try".
    """

    outcome: SignatureOutcome
    reason: str
    algorithm: int
    key_tag: int | None = None
    attempts: int = 0

    @property
    def verified(self) -> bool:
        """True only for VALID -- the one answer that authenticates the RRset."""
        return self.outcome is SignatureOutcome.VALID


def verify_rrsig(
    rrsig: RData_RRSIG,
    owner,
    rdatas: Iterable,
    dnskeys: Iterable[RData_DNSKEY],
    *,
    now: float | None = None,
    rclass: int = 1,
) -> SignatureVerdict:
    """Run §5.3.1's conditions over one RRset, then the arithmetic over every matching key.

    ``owner`` and ``rdatas`` are the RRset being authenticated -- the owner as it appears
    in the RR header (a wildcard-expanded name, not ``*.example.``: §3.1.3's undoing is
    :func:`namespy.dnssec.signed_owner_name`'s job, driven by the RRSIG's own Labels
    field). ``dnskeys`` is the apex DNSKEY RRset of the zone the RRSIG names as signer;
    ¶3's equality between that name and the RRset's zone is the caller's, as is ¶2's
    owner-and-class agreement, neither of which an RDATA can see.

    The checks run cheapest-first -- policy, window, signed-byte reconstruction, key
    matching, arithmetic -- so that the *reason* a validator stopped is the first true
    one, not the most expensive one.
    """
    algorithm = int(rrsig.algorithm)
    records = tuple(rdatas)
    if not records:
        raise ValueError("verify_rrsig needs an RRset: rdatas is empty")

    requirement = validation_requirement(algorithm)
    if requirement is ValidationRequirement.MUST_NOT:
        return SignatureVerdict(
            SignatureOutcome.INVALID,
            f"algorithm {algorithm} is MUST NOT for validation in RFC 9904 Table 2; a "
            f"signature made with it authenticates nothing, because §1.2¶3 marks it so "
            f"precisely that resolvers stop validating it",
            algorithm=algorithm,
        )
    if algorithm not in SIGNATURE_ALGORITHMS:
        return SignatureVerdict(
            SignatureOutcome.UNSUPPORTED,
            f"no primitive for algorithm {algorithm} (RFC 9904 status: "
            f"{requirement.value}); this package cannot attempt it",
            algorithm=algorithm,
        )

    covered = int(rrsig.type_covered)
    if any(int(record.RType) != covered for record in records):
        return SignatureVerdict(
            SignatureOutcome.INVALID,
            f"the RRSIG covers type {covered} but the RRset holds records of another "
            f"type (RFC 4035 §5.3.1¶4)",
            algorithm=algorithm,
        )

    if not rrsig.within_validity(now):
        return SignatureVerdict(
            SignatureOutcome.INVALID,
            f"the signature is outside its validity window "
            f"(inception {rrsig.inception}, expiration {rrsig.expiration}); RFC 4034 "
            f"§3.1.5¶1: it MUST NOT be used for authentication",
            algorithm=algorithm,
            key_tag=rrsig.key_tag,
        )

    try:
        message = rrsig_signed_data(rrsig, owner, records, rclass=rclass)
    except ValueError as exc:
        return SignatureVerdict(
            SignatureOutcome.INVALID,
            f"the signed bytes cannot be reconstructed: {exc}",
            algorithm=algorithm,
            key_tag=rrsig.key_tag,
        )

    candidates: list[RData_DNSKEY] = []
    disqualified: list[str] = []
    for key in dnskeys:
        if int(key.algorithm) != algorithm or int(key.key_tag) != int(rrsig.key_tag):
            continue
        if int(key.protocol) != DNSKEY_PROTOCOL_VALUE:
            disqualified.append(
                f"protocol {key.protocol} (RFC 4034 §2.1.2: invalid for verification unless 3)"
            )
        elif not key.is_zone_key:
            disqualified.append("Zone Flag bit unset (RFC 4035 §5.3.1¶9)")
        else:
            candidates.append(key)
    if not candidates:
        if disqualified:
            return SignatureVerdict(
                SignatureOutcome.INVALID,
                "the matching DNSKEY cannot be verified with: " + "; ".join(disqualified),
                algorithm=algorithm,
                key_tag=rrsig.key_tag,
            )
        return SignatureVerdict(
            SignatureOutcome.INVALID,
            f"no DNSKEY in the set matches algorithm {algorithm} and key tag "
            f"{rrsig.key_tag} (RFC 4035 §5.3.1¶8)",
            algorithm=algorithm,
            key_tag=rrsig.key_tag,
        )

    if not backend_supports(algorithm):
        return SignatureVerdict(
            SignatureOutcome.UNSUPPORTED,
            "everything up to the arithmetic passed; this install has no backend to "
            "run it with -- install namespy[crypto]",
            algorithm=algorithm,
            key_tag=rrsig.key_tag,
        )

    spec = SIGNATURE_ALGORITHMS[algorithm]
    attempts = 0
    unreadable = ""
    for key in candidates:
        try:
            ok = verify_dnskey_signature(algorithm, key.public_key, rrsig.signature, message)
        except SignatureMaterialError as exc:
            unreadable = str(exc)
            continue
        attempts += 1
        if ok:
            return SignatureVerdict(
                SignatureOutcome.VALID,
                f"the signature verifies under {spec.spec}'s {spec.primitive.value} primitive",
                algorithm=algorithm,
                key_tag=rrsig.key_tag,
                attempts=attempts,
            )
    if attempts:
        return SignatureVerdict(
            SignatureOutcome.INVALID,
            f"the signature did not verify under any of the {attempts} matching key(s) "
            f"-- RFC 4035 §5.3.1¶10 required trying each, and each refused",
            algorithm=algorithm,
            key_tag=rrsig.key_tag,
            attempts=attempts,
        )
    return SignatureVerdict(
        SignatureOutcome.UNSUPPORTED,
        f"the {len(candidates)} matching key(s) carried no material the backend could "
        f"be handed: {unreadable}",
        algorithm=algorithm,
        key_tag=rrsig.key_tag,
        attempts=0,
    )


# ----------------------------------------------------------------------- one link of the chain


class ChainOutcome(Enum):
    """RFC 4033 §5's vocabulary for a zone's keys, at the DS-to-DNSKEY link.

    SECURE: the anchor's key signed the apex RRset. BOGUS: the link exists and is wrong
    -- no key matches the trusted digest, or the matching key's signature does not
    verify. INDETERMINATE: the link could not be examined (RFC 9080 §3.1's state), which
    a validator must not report as either of the others.
    """

    SECURE = "secure"
    BOGUS = "bogus"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True)
class ChainVerdict:
    """The link's answer: outcome, operator's words, and the key that closed it."""

    outcome: ChainOutcome
    reason: str
    matched_key_tag: int | None = None
    attempts: int = 0

    @property
    def secure(self) -> bool:
        return self.outcome is ChainOutcome.SECURE


def authenticate_dnskey_rrset(
    zone,
    dnskeys: Iterable[RData_DNSKEY],
    rrsigs: Iterable[RData_RRSIG],
    trusted: Iterable[RData_DS],
    *,
    now: float | None = None,
    rclass: int = 1,
) -> ChainVerdict:
    """Answer RFC 4035 §5.2¶2 for one zone: does a trusted DS introduce these keys?

    ``trusted`` is a parent's already-authenticated DS RRset -- or, at the top of the
    walk, the trust anchors of `namespy.anchors` in their DS form. ¶5's three conjuncts
    run in order: a DNSKEY whose tag, algorithm and owner-plus-RDATA digest match a
    trusted DS (with RFC 4034 §5.2's bit-7 proviso deciding which pairs may even be
    considered); that key's private key having signed this very apex DNSKEY RRset; and
    the resulting RRSIG verifying -- which is :func:`verify_rrsig` again, run with the
    RRset as both subject and key pool, the self-signature shape §5.3.1¶13 describes.

    ¶3 -- that the DS itself was authenticated by the parent -- is the *caller's*
    conjunct, and deliberately not this function's: at the root the anchors stand in by
    definition, and one level up the resolver has already run this same function to say
    so. A function that re-checked its own trust point could only check it against
    itself.

    The failure taxonomy is where the care went: digest types this package cannot
    compute yield INDETERMINATE, not BOGUS (§5.2¶8 and §5.2¶10 route the
    no-supported-algorithm case to "treat the child as unsigned", a different
    operational answer from "the parent lied"), while a matched key whose signature
    every candidate RRSIG fails is the §5.2¶5 refusal -- bogus, and no retry changes it.
    """
    records = list(dnskeys)
    if not records:
        raise ValueError("authenticate_dnskey_rrset needs the apex DNSKEY RRset: dnskeys is empty")
    trust_points = list(trusted)
    if not trust_points:
        raise ValueError(
            "authenticate_dnskey_rrset needs at least one trust point: trusted is empty"
        )
    signatures = list(rrsigs)

    pairs: list[RData_DNSKEY] = []
    incomparable = 0
    disqualified = False
    for ds in trust_points:
        if known_digest_octets(int(ds.digest_type)) is None:
            incomparable += 1
            continue
        for key in records:
            if int(key.key_tag) != int(ds.key_tag) or int(key.algorithm) != int(ds.algorithm):
                continue
            if ds_digest(zone, bytes(key), int(ds.digest_type)) != bytes(ds.digest):
                continue
            if not key.is_zone_key:
                # RFC 4034 §5.2¶1 reaches further than a mismatch: a DS that points at a
                # key without bit 7 is unusable *as well as* the key -- the report should
                # say the pair was excluded, not that nothing matched.
                disqualified = True
                continue
            pairs.append(key)
    if not pairs:
        if incomparable == len(trust_points):
            return ChainVerdict(
                ChainOutcome.INDETERMINATE,
                "no trust point carries a digest type this package can compute; RFC "
                "4035 §5.2¶10 says treat the child as unsigned, not as forged",
            )
        if disqualified:
            return ChainVerdict(
                ChainOutcome.BOGUS,
                "the digest-matched DNSKEY lacks the Zone Flag bit; RFC 4034 §5.2¶1 "
                "excludes it and the DS naming it from the validation process",
            )
        return ChainVerdict(
            ChainOutcome.BOGUS,
            f"no DNSKEY in the {len(records)}-record apex RRset matches any trusted DS "
            f"digest (RFC 4035 §5.2¶4)",
        )

    if not signatures:
        return ChainVerdict(
            ChainOutcome.BOGUS,
            "the apex DNSKEY RRset carries no RRSIG at all; §5.2¶5 requires the "
            "matched key's private key to have signed it",
            matched_key_tag=pairs[0].key_tag,
        )

    apex = DomainName(zone)
    dnskey_type = int(DnsRType.DNSKEY)
    attempts = 0
    blocked: str | None = None
    for key in pairs:
        for rrsig in signatures:
            if int(rrsig.type_covered) != dnskey_type:
                continue
            if int(rrsig.key_tag) != int(key.key_tag) or int(rrsig.algorithm) != int(key.algorithm):
                continue
            if rrsig.signer_name != apex:
                # A signature by this key tag from a *different* zone is not §5.2¶5's
                # "signed the child zone's apex DNSKEY RRset"; tags are 16 bits wide and
                # collisions exist, so the signer's name decides, not the tag.
                continue
            verdict = verify_rrsig(rrsig, zone, records, records, now=now, rclass=rclass)
            attempts += verdict.attempts
            if verdict.verified:
                return ChainVerdict(
                    ChainOutcome.SECURE,
                    f"the DS-matched key tag {key.key_tag} signed this apex DNSKEY "
                    f"RRset and its signature verifies (RFC 4035 §5.2¶2-¶5)",
                    matched_key_tag=key.key_tag,
                    attempts=attempts,
                )
            if verdict.outcome is SignatureOutcome.UNSUPPORTED:
                blocked = verdict.reason
    if blocked is not None and not attempts:
        # Nothing could be examined: no arithmetic ran, which is the one state a
        # validator must not upgrade to "forged" -- or downgrade to silence.
        return ChainVerdict(
            ChainOutcome.INDETERMINATE,
            f"the candidate signatures could not be examined: {blocked}",
            matched_key_tag=pairs[0].key_tag,
        )
    return ChainVerdict(
        ChainOutcome.BOGUS,
        f"none of the {len(signatures)} RRSIG(s) verifies as a signature by a "
        f"DS-matched key over this RRset (RFC 4035 §5.2¶5)",
        attempts=attempts,
    )
