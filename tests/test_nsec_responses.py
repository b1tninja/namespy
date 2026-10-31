"""Response-shape validators: NSEC3 (RFC 5155 §8.5-§8.9) and NSEC (RFC 4035 §5.4).

The geometry of spans and bitmaps belongs to ``test_nsec_proofs.py``; what belongs here is
the *shape* of a response -- which record a given answer owes, and what it means when one
is missing (retry, per RFC 4035 §5.4¶6) or contradicts the answer handed with it (bogus,
per RFC 5155 §8.3¶10). The chains are built the same way: names hashed with this package's
own NSEC3 hash and chained in hash order, with the last record wrapping to the first.

Two of the branches below exist only because of verified erratum 3441, and one test per
branch says which paragraph of it it pins. As on the predicate side, nothing here is
verified: these functions report what a set of records asserts about the response holding
them, and forged records remain the verification leg's future problem.
"""

import pytest

from namespy.dnssec import encode_base32hex, nsec3_hash
from namespy.enums import DnsRType
from namespy.names import DomainName
from namespy.nsec import (
    ContradictoryProofError,
    IncompleteProofError,
    find_nsec3_matching,
    nsec3_covers,
    nsec3_proves_no_data,
    nsec3_proves_no_ds,
    nsec3_proves_unsigned_delegation,
    nsec3_proves_wildcard_answer,
    nsec3_proves_wildcard_no_data,
    nsec_proves_no_data,
    nsec_proves_nxdomain_response,
    nsec_proves_wildcard_answer,
)
from namespy.rdata import RData_NSEC, RData_NSEC3, RData_RRSIG

ZONE = "example.com."
SALT = bytes.fromhex("1234")
A = int(DnsRType.A)
AAAA = int(DnsRType.AAAA)
CNAME = int(DnsRType.CNAME)
DS = int(DnsRType.DS)
MX = int(DnsRType.MX)
NS = int(DnsRType.NS)
NSEC3 = int(DnsRType.NSEC3)
SOA = int(DnsRType.SOA)


def _hash(name, salt=SALT, iterations=0) -> bytes:
    return nsec3_hash(name, iterations=iterations, salt=salt)


def _owner(digest: bytes) -> DomainName:
    """An NSEC3 owner name: the hash as one base32hex label, prepended to the zone (§7.1¶10)."""
    return DomainName(f"{encode_base32hex(digest)}.{ZONE}")


def _nsec3_chain(names, types_by_name=None, *, flags=0, opt_out=(), salt=SALT, iterations=0):
    """A signed zone's NSEC3 RRset, built as RFC 5155 §7.1¶7-¶19 describes.

    *opt_out* names the owners whose records get the Opt-Out flag in addition to any set
    for the whole chain -- §6¶5 makes mixing legal, and half the tests below are about
    which side of a mixed chain a proof is resting on.
    """
    hashed = sorted((_hash(name, salt, iterations), name) for name in names)
    entries = []
    for index, (digest, name) in enumerate(hashed):
        following = hashed[(index + 1) % len(hashed)][0]
        types = (types_by_name or {}).get(name, [A])
        entry_flags = flags | (1 if name in opt_out else 0)
        entries.append(
            (_owner(digest), RData_NSEC3(1, entry_flags, iterations, salt, following, types))
        )
    return entries


def _nsec_chain(pairs):
    """[(owner, next, types)] into proof entries, in the order an NSEC chain would arrive."""
    return [
        (DomainName(owner), RData_NSEC(DomainName(next_name), types))
        for owner, next_name, types in pairs
    ]


def _rrsig(labels: int) -> RData_RRSIG:
    """An RRSIG over an NSEC RRset carrying just the one field any test below reads."""
    return RData_RRSIG(
        type_covered=int(DnsRType.NSEC),
        algorithm=13,
        labels=labels,
        original_ttl=300,
        expiration=2,
        inception=1,
        key_tag=1,
        signer_name=ZONE,
        signature=b"\x00",
    )


# ------------------------------------------------------------- No Data, QTYPE is not DS (§8.5)


def test_a_matching_record_with_the_bit_clear_denies_the_type():
    """§8.5¶1: the chain matches QNAME and its bitmap does not list QTYPE."""
    chain = _nsec3_chain([ZONE, "b.example.com."], {"b.example.com.": [A]})
    proof = nsec3_proves_no_data("b.example.com.", MX, chain, ZONE)
    assert proof.matching == find_nsec3_matching("b.example.com.", chain, ZONE)
    assert proof.closest is None
    assert not proof.via_opt_out


def test_an_empty_bitmap_denies_everything_at_an_empty_non_terminal():
    """§8.5¶2's note, which the erratum left standing: an ENT's record denies by being empty."""
    chain = _nsec3_chain([ZONE, "sub.example.com."], {"sub.example.com.": []})
    proof = nsec3_proves_no_data("sub.example.com.", A, chain, ZONE)
    assert proof.matching is not None


def test_a_bitmap_that_lists_the_type_contradicts_the_answer():
    """The response says no such RRset; the bitmap its own proof cites says there is one."""
    chain = _nsec3_chain([ZONE, "b.example.com."], {"b.example.com.": [A]})
    with pytest.raises(ContradictoryProofError, match="lists type"):
        nsec3_proves_no_data("b.example.com.", A, chain, ZONE)


def test_a_bitmap_that_lists_cname_contradicts_a_withheld_cname():
    """§8.5¶1 checks two bits, not one: with CNAME set, a CNAME answer was the one due."""
    chain = _nsec3_chain([ZONE, "b.example.com."], {"b.example.com.": [A, CNAME]})
    with pytest.raises(ContradictoryProofError, match="CNAME"):
        nsec3_proves_no_data("b.example.com.", MX, chain, ZONE)


def test_no_record_can_deny_the_nsec3_type_at_its_own_name():
    """A name matching a record owns one, so No Data for NSEC3 denies the proof citing it.

    §7.1¶5 keeps the NSEC3 bit out of every bitmap, which is the trap: read naively, an
    empty-of-NSEC3 bitmap would deny NSEC3 at its own owner name, forever, for every name.
    """
    chain = _nsec3_chain([ZONE, "b.example.com."], {"b.example.com.": [A]})
    with pytest.raises(ContradictoryProofError, match="holds an"):
        nsec3_proves_no_data("b.example.com.", NSEC3, chain, ZONE)


def test_erratum_3441_accepts_a_provable_encloser_through_an_opt_out_span():
    """The amended second half of §8.5, which is the whole reason §8.5 branches at all.

    An Opt-Out chain holds no record at an insecure delegation (§6¶1), so the No Data a
    multi-label delegation earns at its parent is denied by the closest *provable* encloser
    proof -- encloser matched, next closer covered by a record asserting nothing on
    purpose. This is that paragraph, and the reason "no matching record" stopped meaning
    "incomplete" the moment Opt-Out shipped.
    """
    chain = _nsec3_chain([ZONE, "a.example.com."], flags=1)
    proof = nsec3_proves_no_data("b.example.com.", A, chain, ZONE)
    assert proof.matching is None
    assert proof.closest is not None
    assert proof.closest.encloser == DomainName(ZONE)
    assert proof.closest.next_closer == DomainName("b.example.com.")
    assert proof.via_opt_out


def test_erratum_3441_refuses_an_asserting_span_for_a_name_that_exists():
    """The same shape without the flag is not a weaker proof -- it is a lie.

    An asserting record covering QNAME proves QNAME does not exist, and a No Data response
    is the type-specific answer for a name that does. §8.5 as amended accepts the encloser
    proof only through an Opt-Out span; anything else is two claims that cannot both hold.
    """
    chain = _nsec3_chain([ZONE, "a.example.com."])
    with pytest.raises(ContradictoryProofError, match="erratum 3441"):
        nsec3_proves_no_data("b.example.com.", A, chain, ZONE)


def test_a_matching_opt_out_record_still_asserts_at_its_own_name():
    """§6¶4 is the matching branch's licence: a record speaks for its owner name, flag or not.

    Opt-Out empties the *span*, not the bitmap; RFC 5155 §8.6 reads exactly that bitmap of
    an Opt-Out record at a delegation, and §8.5's does the same for any other QTYPE.
    """
    chain = _nsec3_chain(
        [ZONE, "d.example.com."], {"d.example.com.": [NS]}, opt_out={"d.example.com."}
    )
    proof = nsec3_proves_no_data("d.example.com.", A, chain, ZONE)
    assert proof.matching is not None
    assert not proof.via_opt_out


def test_a_response_with_no_records_is_a_retry_not_a_verdict():
    """RFC 4035 §5.4¶6 still owns the empty case: nothing here means ask again, not bogus."""
    with pytest.raises(IncompleteProofError, match="no NSEC3 RR"):
        nsec3_proves_no_data("b.example.com.", A, [], ZONE)


# ------------------------------------------------------------------- No Data for DS (§8.6)


def test_the_ds_answer_reads_the_ds_bit_and_proves_insecurity():
    """§8.6¶1: NS set and DS clear at the matching record *is* the insecure delegation.

    The one denial the whole validation pipeline turns on: it is what tells a resolver the
    child below this name is not signed and to stop expecting proofs there.
    """
    chain = _nsec3_chain([ZONE, "sub.example.com."], {"sub.example.com.": [NS]})
    proof = nsec3_proves_no_ds("sub.example.com.", chain, ZONE)
    assert proof.matching is not None
    assert not proof.via_opt_out


def test_a_ds_bit_at_the_delegation_says_the_child_is_secure():
    """§8.6¶1 refused: the bitmap claims a DS exists, and the No Data answer denies it."""
    chain = _nsec3_chain([ZONE, "sub.example.com."], {"sub.example.com.": [NS, DS]})
    with pytest.raises(ContradictoryProofError, match="lists type"):
        nsec3_proves_no_ds("sub.example.com.", chain, ZONE)


def test_a_cname_bit_disqualifies_the_ds_answer_too():
    """§8.6¶1 names CNAME beside DS for the same reason §8.5¶1 does: a withheld CNAME lies."""
    chain = _nsec3_chain([ZONE, "sub.example.com."], {"sub.example.com.": [NS, CNAME]})
    with pytest.raises(ContradictoryProofError, match="CNAME"):
        nsec3_proves_no_ds("sub.example.com.", chain, ZONE)


def test_ds_no_data_through_the_opt_out_span():
    """§8.6¶2: no matching record, so insecurity must rest on an Opt-Out next closer."""
    chain = _nsec3_chain([ZONE, "a.example.com."], flags=1)
    proof = nsec3_proves_no_ds("sub.example.com.", chain, ZONE)
    assert proof.matching is None
    assert proof.closest.encloser == DomainName(ZONE)
    assert proof.via_opt_out


def test_ds_no_data_refuses_an_asserting_next_closer():
    """§8.6¶2's Opt-Out requirement is not decoration: assert-and-deny is contradiction."""
    chain = _nsec3_chain([ZONE, "a.example.com."])
    with pytest.raises(ContradictoryProofError, match=r"§8\.6¶2"):
        nsec3_proves_no_ds("sub.example.com.", chain, ZONE)


# ------------------------------------------------------------ Wildcard No Data (§8.7)


def test_a_wildcard_without_the_type_carries_a_no_data_answer():
    """§8.7: the encloser proof, and a wildcard matched with QTYPE and CNAME both clear.

    The response this validates is the strange one -- No Data for a name that does not
    exist -- and the wildcard's existence is what makes it right: the name would have been
    answered, had the wildcard held the type.
    """
    chain = _nsec3_chain([ZONE, "*.example.com.", "z.example.com."], {"*.example.com.": [A]})
    proof = nsec3_proves_wildcard_no_data("x.example.com.", AAAA, chain, ZONE)
    assert proof.closest.encloser == DomainName(ZONE)
    assert proof.wildcard == DomainName("*.example.com.")
    assert proof.wildcard_entry == find_nsec3_matching("*.example.com.", chain, ZONE)


def test_the_wildcard_must_be_matched_not_merely_covered():
    """§8.7 says "matches" for a reason: a denied wildcard is §8.4's, and contradicts this.

    A chain that spans the wildcard asserts it does not exist -- which makes Name Error
    the owed answer, so records proving that shape under a No Data response are two
    responses' worth of claims in one message.
    """
    chain = _nsec3_chain([ZONE, "z.example.com."])
    with pytest.raises(ContradictoryProofError, match="Name"):
        nsec3_proves_wildcard_no_data("x.example.com.", AAAA, chain, ZONE)


def test_a_missing_wildcard_record_is_the_third_record_truncation_costs():
    """The encloser half is intact and the wildcard half is simply not there: ask again."""
    chain = _nsec3_chain([ZONE, "b.example.com."])
    wildcard = DomainName("*.b.example.com.")
    without = [entry for entry in chain if not nsec3_covers(entry, wildcard, ZONE)]
    assert len(without) == len(chain) - 1, "this scenario needs one record holding the wildcard"
    with pytest.raises(IncompleteProofError, match=r"wildcard \*\.b\.example\.com\."):
        nsec3_proves_wildcard_no_data("x.b.example.com.", AAAA, without, ZONE)


def test_a_wildcard_that_has_the_type_contradicts_no_data():
    """§8.7¶1's bits again: a wildcard holding QTYPE could have answered, so No Data lied."""
    chain = _nsec3_chain([ZONE, "*.example.com.", "z.example.com."], {"*.example.com.": [AAAA]})
    with pytest.raises(ContradictoryProofError, match="lists type"):
        nsec3_proves_wildcard_no_data("x.example.com.", AAAA, chain, ZONE)


def test_an_opt_out_encloser_proof_cannot_carry_a_wildcard_answer():
    """§6¶3 again, from the other side: insecurity below the cut, and no signed wildcard there.

    An Opt-Out next closer puts the path to QNAME under an unsigned delegation; the
    wildcard one label above that cut is in the signed zone and cannot have answered
    beneath it -- synthesis stops at zone cuts (RFC 4592 §2.1). Records that claim
    otherwise are contradicted by their own span flags.
    """
    chain = _nsec3_chain([ZONE, "b.example.com."], flags=1)
    with pytest.raises(ContradictoryProofError, match="Opt-Out"):
        nsec3_proves_wildcard_no_data("x.b.example.com.", AAAA, chain, ZONE)


# ---------------------------------------------------------------- Wildcard answer (§8.8)


def test_a_wildcard_answer_needs_the_next_closer_covered():
    """§8.8¶2: one record proves the synthesised name was absent, and this test names it.

    The synthesising name is not on the wire -- it is what the caller read out of the
    covering RRSIG's Labels field -- so the validator's whole job is the span test on the
    next closer: QNAME did not exist, and no nearer name could have answered it.
    """
    chain = _nsec3_chain([ZONE, "b.example.com.", "c.example.com."])
    proof = nsec3_proves_wildcard_answer("x.y.example.com.", "*.example.com.", chain, ZONE)
    assert proof.encloser == DomainName(ZONE)
    assert proof.next_closer == DomainName("y.example.com.")
    assert nsec3_covers(proof.next_closer_entry, "y.example.com.", ZONE)
    assert not proof.via_opt_out


def test_a_wildcard_answer_through_an_opt_out_span_is_flagged_for_ad():
    """§8.8 permits the Opt-Out span; §9.2¶1 is what it obliges on the way out: no AD."""
    chain = _nsec3_chain([ZONE, "b.example.com.", "c.example.com."], flags=1)
    proof = nsec3_proves_wildcard_answer("x.y.example.com.", "*.example.com.", chain, ZONE)
    assert proof.via_opt_out


def test_a_matching_record_under_a_wildcard_answer_is_bogus():
    """§8.8¶2 reads "QNAME itself did not exist" as a check, not a comment: matching is bogus."""
    chain = _nsec3_chain([ZONE, "b.example.com.", "c.example.com."])
    with pytest.raises(ContradictoryProofError, match="answered from itself"):
        nsec3_proves_wildcard_answer("b.example.com.", "*.example.com.", chain, ZONE)


def test_a_wildcard_answer_missing_its_span_is_incomplete():
    """No record covers the next closer: the answer may be fine, but nothing proves it."""
    chain = _nsec3_chain([ZONE, "b.example.com.", "c.example.com."])
    without = [entry for entry in chain if not nsec3_covers(entry, "y.example.com.", ZONE)]
    assert len(without) == len(chain) - 1, "this scenario needs exactly one covering record"
    with pytest.raises(IncompleteProofError, match="next closer"):
        nsec3_proves_wildcard_answer("x.y.example.com.", "*.example.com.", without, ZONE)


def test_the_synthesising_name_is_checked_as_the_caller_derives_it():
    """The wildcard arrives from Labels arithmetic, so a wrong derivation is a loud ValueError.

    RFC 5155 §8.8's name is the answer's owner with its first label replaced by the
    asterisk; anything else means the caller misread the RRSIG, which is a programming
    error rather than a hostile zone.
    """
    chain = _nsec3_chain([ZONE, "b.example.com."])
    with pytest.raises(ValueError, match="not a synthesising name"):
        nsec3_proves_wildcard_answer("x.b.example.com.", "b.example.com.", chain, ZONE)
    with pytest.raises(ValueError, match="does not sit beneath"):
        nsec3_proves_wildcard_answer("example.com.", "*.b.example.com.", chain, ZONE)


# ------------------------------------------------ Referral to an unsigned subzone (§8.9)


def test_a_matching_parent_record_proves_the_delegation_insecure():
    """§8.9¶2: NS set and DS clear from the parent, and the descent may stop being secure."""
    chain = _nsec3_chain([ZONE, "sub.example.com."], {"sub.example.com.": [NS]})
    proof = nsec3_proves_unsigned_delegation("sub.example.com.", chain, ZONE)
    assert proof.matching is not None
    assert proof.closest is None
    assert not proof.via_opt_out


def test_the_ds_bit_turns_the_referral_into_a_secure_step():
    """§8.9¶2 refused: DS set means the child *is* signed, referral be damned."""
    chain = _nsec3_chain([ZONE, "sub.example.com."], {"sub.example.com.": [NS, DS]})
    with pytest.raises(ContradictoryProofError, match="child"):
        nsec3_proves_unsigned_delegation("sub.example.com.", chain, ZONE)


def test_an_soa_bit_at_the_delegation_exposes_the_record_as_the_child_s():
    """§8.9¶2's parent test. Only an apex owns SOA, and a delegation is not the parent's apex.

    A record matching the delegation name while listing SOA can only belong to the child
    zone -- quoting the child's own chain as though it were the parent's word about where
    the parent's authority ends.
    """
    chain = _nsec3_chain([ZONE, "sub.example.com."], {"sub.example.com.": [NS, SOA]})
    with pytest.raises(ContradictoryProofError, match="child zone rather than the parent"):
        nsec3_proves_unsigned_delegation("sub.example.com.", chain, ZONE)


def test_a_record_without_ns_denies_the_referral_it_is_offered_for():
    """§8.9¶2 again: the referral asserts a delegation; the matching bitmap must agree."""
    chain = _nsec3_chain([ZONE, "sub.example.com."], {"sub.example.com.": [A]})
    with pytest.raises(ContradictoryProofError, match="does not list NS"):
        nsec3_proves_unsigned_delegation("sub.example.com.", chain, ZONE)


def test_an_opt_out_span_proves_insecurity_without_a_record_of_its_own():
    """§8.9¶4: no matching record, and the Opt-Out span covering the delegation is enough."""
    chain = _nsec3_chain([ZONE, "a.example.com."], flags=1)
    proof = nsec3_proves_unsigned_delegation("gone.example.com.", chain, ZONE)
    assert proof.matching is None
    assert proof.closest.next_closer == DomainName("gone.example.com.")
    assert proof.via_opt_out


def test_an_asserting_span_cannot_mark_a_delegation_unsigned():
    """§8.9¶4 read strictly: an asserting cover denies the delegation's own existence."""
    chain = _nsec3_chain([ZONE, "a.example.com."])
    with pytest.raises(ContradictoryProofError, match=r"§8\.9¶4"):
        nsec3_proves_unsigned_delegation("gone.example.com.", chain, ZONE)


# ------------------------------------------------------------- NSEC, response level (§5.4)


CHAIN3 = [
    ("example.com.", "a.example.com.", [SOA, NS]),
    ("a.example.com.", "z.example.com.", [A]),
    ("z.example.com.", "example.com.", [A]),
]


def test_nsec_no_data_reads_the_bitmap_at_its_owner():
    """§5.4¶3: the matching NSEC lists what exists, and MX is not on the list."""
    chain = _nsec_chain(CHAIN3)
    proof = nsec_proves_no_data("a.example.com.", MX, chain)
    assert proof.matching is not None
    assert proof.wildcard is None
    assert proof.owner_explicit is None  # no RRSIG offered, no judgement made


def test_the_covering_rrsig_labels_prove_the_name_is_explicit():
    """§5.4¶3's second sentence: equal label counts are what a wildcard leaves unequal."""
    chain = _nsec_chain(CHAIN3)
    proof = nsec_proves_no_data("a.example.com.", MX, chain, rrsig=_rrsig(3))
    assert proof.owner_explicit
    with pytest.raises(ContradictoryProofError, match="synthesised through a wildcard"):
        nsec_proves_no_data("a.example.com.", MX, chain, rrsig=_rrsig(2))


def test_nsec_no_data_refuses_a_bitmap_that_lists_the_type_or_cname():
    """The same two bitmap reads as §8.5, because the record's claim is the same."""
    chain = _nsec_chain(CHAIN3)
    with pytest.raises(ContradictoryProofError, match="lists type"):
        nsec_proves_no_data("a.example.com.", A, chain)
    cname_chain = _nsec_chain(
        [
            ("example.com.", "m.example.com.", [SOA]),
            ("m.example.com.", "z.example.com.", [A, CNAME]),
            ("z.example.com.", "example.com.", [A]),
        ]
    )
    with pytest.raises(ContradictoryProofError, match="CNAME"):
        nsec_proves_no_data("m.example.com.", MX, cname_chain)


def test_nsec_and_rrsig_types_are_ignored_not_read():
    """§5.4¶7 made unprovable here: those bits say nothing, so their absence says less."""
    chain = _nsec_chain(CHAIN3)
    with pytest.raises(ContradictoryProofError, match="unprovable"):
        nsec_proves_no_data("a.example.com.", int(DnsRType.RRSIG), chain)


def test_no_data_below_a_wildcard_needs_the_wildcard_matched():
    """§5.4¶3 with §5.4¶6: the name is absent, and an existing type-less wildcard explains why.

    The chain's canonical order does the teaching here: ``*.example.com.`` sorts below
    every letter (the asterisk is 0x2A), so the wildcard's own NSEC opens the span that
    covers ``q.example.com.`` -- and §8.7's matching-not-covering discipline carries over.
    """
    chain = _nsec_chain(
        [
            ("example.com.", "*.example.com.", [SOA]),
            ("*.example.com.", "z.example.com.", [A]),
            ("z.example.com.", "example.com.", [A]),
        ]
    )
    proof = nsec_proves_no_data("q.example.com.", AAAA, chain)
    assert proof.matching is None
    assert proof.wildcard == DomainName("*.example.com.")
    assert proof.wildcard_entry is not None


def test_denying_the_wildcard_is_the_shape_of_an_nxdomain():
    """A No Data answer resting on a wildcard the same records deny: two answers, one reply."""
    chain = _nsec_chain(
        [("example.com.", "z.example.com.", [SOA]), ("z.example.com.", "example.com.", [A])]
    )
    with pytest.raises(ContradictoryProofError, match="Name"):
        nsec_proves_no_data("m.example.com.", AAAA, chain)


def test_an_empty_nsec_set_is_a_retry_not_a_verdict():
    """RFC 4035 §5.4¶6's plainest case: no records at all means ask again, not bogus."""
    with pytest.raises(IncompleteProofError, match="no NSEC RR at all"):
        nsec_proves_no_data("m.example.com.", AAAA, [])


def test_nsec_nxdomain_refuses_a_wildcard_that_stood():
    """An NXDOMAIN whose own records match the wildcard: the shape the proof disowns.

    The wildcard's NSEC has no span over itself -- endpoints match, they are never
    covered -- so once a record matches ``*.example.com.`` there is no wildcard denial to
    find, and the response is contradicted rather than left unproven.
    """
    chain = _nsec_chain(
        [
            ("example.com.", "*.example.com.", [SOA]),
            ("*.example.com.", "z.example.com.", [A]),
            ("z.example.com.", "example.com.", [A]),
        ]
    )
    with pytest.raises(ContradictoryProofError, match="matches the wildcard"):
        nsec_proves_nxdomain_response("m.example.com.", chain)


def test_the_walk_gives_up_at_the_root_as_incomplete():
    """A zone's single span cannot name a foreign TLD absent: no encloser exists here."""
    chain = _nsec_chain([("a.example.com.", "z.example.com.", [A])])
    with pytest.raises(IncompleteProofError, match="up to the root"):
        nsec_proves_nxdomain_response("other.net.", chain)


def test_nsec_nxdomain_needs_the_wildcard_denied_too():
    """§5.4¶4's full claim: name absent *and* no wildcard at the encloser to answer anyway."""
    chain = _nsec_chain(CHAIN3)
    proof = nsec_proves_nxdomain_response("m.example.com.", chain)
    assert proof.encloser == DomainName("example.com.")
    assert proof.next_closer == DomainName("m.example.com.")
    assert proof.wildcard == DomainName("*.example.com.")


def test_nsec_nxdomain_refuses_a_name_that_exists():
    """A matching NSEC at QNAME is §5.4¶3's territory; offering it as a denial is bogus."""
    chain = _nsec_chain(CHAIN3)
    with pytest.raises(ContradictoryProofError, match="the name exists"):
        nsec_proves_nxdomain_response("a.example.com.", chain)


def test_nsec_nxdomain_refuses_a_delegation_as_encloser():
    """No authority below a bare NS, hashed or not: the proper-zone rule needs no hashes."""
    chain = _nsec_chain(
        [
            ("example.com.", "b.example.com.", [SOA]),
            ("b.example.com.", "z.example.com.", [NS]),
            ("z.example.com.", "example.com.", [A]),
        ]
    )
    with pytest.raises(ContradictoryProofError, match="not authoritative"):
        nsec_proves_nxdomain_response("x.b.example.com.", chain)


def test_one_span_carries_both_halves_of_the_nsec_nxdomain():
    """The encloser's own record denies the wildcard too, because * sorts first (0x2A).

    No such compression exists under NSEC3 -- hashes reorder the zone, so §8.4's wildcard
    is regularly a third record and truncation costs it -- but NSEC's canonical order puts
    ``*.example.com.`` directly above the apex, inside the apex's own span, where a
    truncated response can only drop it by dropping the encloser proof with it.
    """
    chain = _nsec_chain(
        [("example.com.", "z.example.com.", [SOA]), ("z.example.com.", "example.com.", [A])]
    )
    proof = nsec_proves_nxdomain_response("m.example.com.", chain)
    assert proof.encloser_entry == proof.wildcard_entry


def test_nsec_wildcard_answer_needs_a_span_and_a_star():
    """§8.8's two requirements under NSEC: a real synthesising name, and QNAME covered."""
    chain = _nsec_chain([("example.com.", "z.example.com.", [SOA])])
    proof = nsec_proves_wildcard_answer("m.example.com.", "*.example.com.", chain)
    assert proof.covering_entry is not None
    with pytest.raises(ValueError, match="not a synthesising name"):
        nsec_proves_wildcard_answer("m.example.com.", "example.com.", chain)
    big_chain = _nsec_chain(CHAIN3)
    with pytest.raises(ContradictoryProofError, match="answered from itself"):
        nsec_proves_wildcard_answer("a.example.com.", "*.example.com.", big_chain)
    endpoint_only = _nsec_chain([("a.example.com.", "z.example.com.", [A])])
    with pytest.raises(IncompleteProofError, match="span covers"):
        nsec_proves_wildcard_answer("z.example.com.", "*.example.com.", endpoint_only)
