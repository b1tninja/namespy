"""Denial-of-existence proofs: NSEC (RFC 4035 §5.4) and NSEC3 (RFC 5155 §6-§9).

Two kinds of test, deliberately. The canonical-name-order tests check against the vector RFC 4034
§6.1¶4 prints, which is the one part of this logic with a published expected value. Everything else
is built from synthetic zones -- owner names hashed with this package's own NSEC3 hash and chained in
hash order as RFC 5155 §7.1 describes -- because the interesting behaviour here is the *geometry* of
spans, and geometry can be constructed exactly: a name between two hashes, a name equal to an
endpoint, a span that wraps at the end of the zone.

What is not tested is authentication. These functions report what a set of records asserts; whether
the records are genuine belongs to the verification leg, and a proof that passes here on forged
records is the caller's future problem, not a hole in this module.
"""

import pytest

from namespy.dnssec import encode_base32hex, nsec3_hash
from namespy.enums import DnsRType
from namespy.names import DomainName
from namespy.nsec import (
    ContradictoryProofError,
    IncompleteProofError,
    closest_encloser_proof,
    find_nsec3_covering,
    find_nsec3_matching,
    find_nsec_covering,
    find_nsec_matching,
    hash_between,
    name_order_key,
    nsec3_covers,
    nsec3_matches,
    nsec3_owner_digest,
    nsec3_proves_no_type,
    nsec3_proves_nxdomain,
    nsec_matches,
    nsec_owner_is_explicit,
    nsec_proves_no_type,
    nsec_proves_no_wildcard,
    nsec_proves_nxdomain,
    sort_canonical,
    usable_nsec3,
    wildcard_at,
)
from namespy.rdata import RData_NSEC, RData_NSEC3, RData_RRSIG

ZONE = "example.com."
SALT = bytes.fromhex("1234")
A = int(DnsRType.A)
SOA = int(DnsRType.SOA)
NS = int(DnsRType.NS)


def _hash(name, salt=SALT, iterations=0) -> bytes:
    return nsec3_hash(name, iterations=iterations, salt=salt)


def _owner(digest: bytes) -> DomainName:
    """An NSEC3 owner name: the hash as one base32hex label, prepended to the zone (§7.1¶10)."""
    return DomainName(f"{encode_base32hex(digest)}.{ZONE}")


def _nsec_chain(pairs):
    """[(owner, next, types)] into proof entries, in the order an NSEC chain would arrive."""
    return [
        (DomainName(owner), RData_NSEC(DomainName(next_name), types))
        for owner, next_name, types in pairs
    ]


def _nsec3_chain(names, types_by_name=None, *, flags=0, salt=SALT, iterations=0):
    """A signed zone's NSEC3 RRset, built as RFC 5155 §7.1¶7-¶19 describes.

    The last record's next hashed owner name wraps back to the first, which §7.1¶19 requires and
    more than one test below depends on.
    """
    hashed = sorted((_hash(name, salt, iterations), name) for name in names)
    entries = []
    for index, (digest, name) in enumerate(hashed):
        following = hashed[(index + 1) % len(hashed)][0]
        types = (types_by_name or {}).get(name, [A])
        entries.append((_owner(digest), RData_NSEC3(1, flags, iterations, salt, following, types)))
    return entries


# ------------------------------------------------------ canonical DNS name order (§6.1)


def test_canonical_order_matches_the_published_vector():
    """RFC 4034 §6.1¶4 prints nine names in canonical order; sorting must reproduce it exactly.

    The vector is awkward on purpose: "example" before its own children (absence of a label sorts
    first), Z.a.example before zABC.a.EXAMPLE (case folding), and \\001 then * then \\200 under
    z.example in octet order. A sort that gets any one of the three wrong still looks plausible.
    """
    vector = [
        "example.",
        "a.example.",
        "yljkjljk.a.example.",
        "Z.a.example.",
        "zABC.a.EXAMPLE.",
        "z.example.",
        "\x01.z.example.",
        "*.z.example.",
        "\x80.z.example.",
    ]
    wire = [bytes(DomainName(name)) for name in vector]
    assert [bytes(DomainName(name)) for name in sort_canonical(reversed(vector))] == wire
    assert [
        bytes(DomainName(name))
        for name in sort_canonical([vector[i] for i in (4, 0, 8, 2, 6, 1, 7, 3, 5)])
    ] == wire
    assert name_order_key("Z.a.EXAMPLE") == (b"example", b"a", b"z")


def test_name_between_is_strict_on_both_endpoints():
    """A name equal to an endpoint matches rather than being covered (§5.4¶3 against §5.4¶4)."""
    entry = _nsec_chain([("a.example.", "z.example.", [A])])[0]
    assert nsec_proves_nxdomain(entry, "b.example.")
    assert not nsec_proves_nxdomain(entry, "a.example.")
    assert not nsec_proves_nxdomain(entry, "z.example.")
    assert nsec_matches("A.Example.", "a.example.")


def test_the_wrap_span_covers_the_end_of_the_zone():
    """§4.1.1¶1: the last NSEC points at the apex, so its span wraps past the end of the zone.

    Without the wrap branch this record seems to cover nothing, and every name after the zone's last
    owner name -- exactly what a passer-by probes -- comes back unprovable.
    """
    entry = _nsec_chain([("z.example.", "a.example.", [A])])[0]
    assert nsec_proves_nxdomain(entry, "zz.example.")
    assert nsec_proves_nxdomain(entry, "0.example.")
    assert not nsec_proves_nxdomain(entry, "a.example.")
    assert not nsec_proves_nxdomain(entry, "z.example.")


def test_a_zone_with_one_owner_name_covers_everything_else():
    """Equal endpoints mean a single-name zone, whose one NSEC denies every other name."""
    only = _nsec_chain([("example.", "example.", [SOA, NS])])[0]
    assert nsec_proves_nxdomain(only, "anything.example.")
    assert not nsec_proves_nxdomain(only, "example.")


def test_hash_between_wraps_like_name_between():
    """The digest span is the same geometry, and §7.1¶19 gives it the same wrap."""
    assert hash_between(b"\x80\x00", b"\x00\x00", b"\xff\xff")
    assert not hash_between(b"\x00\x00", b"\x00\x00", b"\xff\xff")
    assert hash_between(b"\x00\x00", b"\xff" * 20, b"\x01" * 20)
    assert hash_between(b"\xfe" * 20, b"\xf0" * 20, b"\x01" * 20)
    # The wrap span from the maximum digest can only run to the low end, so 0xfe*20 is not in it.
    assert not hash_between(b"\xfe" * 20, b"\xff" * 20, b"\x01" * 20)


# -------------------------------------------------------------------- NSEC proof rules (§5.4)


def test_nsec_proves_a_type_absent_at_its_owner_only():
    """§5.4¶3: the bitmap lists what exists at the owner, so absence is proven at that name only."""
    entry = _nsec_chain([("a.example.", "z.example.", [A])])[0]
    assert nsec_proves_no_type(entry, "a.example.", int(DnsRType.MX))
    assert not nsec_proves_no_type(entry, "a.example.", A)
    assert not nsec_proves_no_type(entry, "b.example.", int(DnsRType.MX))


@pytest.mark.parametrize("rtype", [int(DnsRType.NSEC), int(DnsRType.RRSIG)])
def test_the_nsec_and_rrsig_bits_are_never_read(rtype):
    """§5.4¶7: "a validator MUST ignore the settings of the NSEC and RRSIG bits".

    A validated NSEC already proves both types exist at its owner name, so a signer that left them
    out of the bitmap must not be allowed to have it "disprove" the record carrying it.
    """
    entry = _nsec_chain([("a.example.", "z.example.", [A])])[0]
    assert not nsec_proves_no_type(entry, "a.example.", rtype)


def test_an_rrsig_label_count_says_whether_the_owner_was_explicit():
    """§5.4¶3's second sentence: the NSEC side of the wildcard argument, and the only place the
    Labels field does work there."""
    entry = _nsec_chain([("a.example.", "z.example.", [A])])[0]

    def rrsig(labels):
        return RData_RRSIG(
            type_covered=A,
            algorithm=13,
            labels=labels,
            original_ttl=300,
            expiration=2,
            inception=1,
            key_tag=1,
            signer_name=ZONE,
            signature=b"\x00",
        )

    assert nsec_owner_is_explicit(entry, rrsig(2))  # a.example. signed as itself
    assert not nsec_owner_is_explicit(entry, rrsig(1))  # signed through *.example.


def test_the_wildcard_that_matters_is_the_one_at_the_encloser():
    """RFC 4592 §3.3.1¶4: the only synthesising name is <asterisk>.<closest encloser>.

    The three-record chain also fixes where the asterisk actually sorts: 0x2A is below every
    letter, so ``*.example.`` falls between the apex and ``a.example.`` rather than in the middle of
    the alphabet -- the same octet-order lesson RFC 4034 §6.1¶4's vector teaches with \\001 and \\200.
    """
    assert str(wildcard_at("example.com.")) == "*.example.com."
    assert str(wildcard_at("*.example.com.")) == "*.example.com."
    chain = _nsec_chain(
        [
            ("example.", "a.example.", [SOA, NS]),
            ("a.example.", "z.example.", [A]),
            ("z.example.", "example.", [A]),
        ]
    )
    assert nsec_proves_no_wildcard(chain[0], "example.")
    assert not nsec_proves_no_wildcard(chain[1], "example.")
    assert not nsec_proves_no_wildcard(chain[2], "example.")


def test_the_finders_return_the_record_the_proof_rests_on():
    """A resolver must name the record it relied on, to log it and to verify its RRSIG."""
    chain = _nsec_chain(
        [
            ("example.", "a.example.", [SOA, NS]),
            ("a.example.", "z.example.", [A]),
            ("z.example.", "example.", [A]),
        ]
    )
    assert find_nsec_matching("a.example.", chain) == chain[1]
    assert find_nsec_covering("0.example.", chain) == chain[0]
    assert find_nsec_covering("m.example.", chain) == chain[1]
    assert find_nsec_covering("zz.example.", chain) == chain[2]  # the wrap span
    assert find_nsec_matching("nope.example.", chain) is None


# ------------------------------------------------------------------- NSEC3 proof rules


def test_nsec3_owner_digest_reads_the_chain_and_rejects_foreign_names():
    """§7.1¶10's owner shape is the only thing that makes a record part of this zone's chain."""
    entry = _nsec3_chain([ZONE])[0]
    assert nsec3_owner_digest(entry, ZONE) == _hash(ZONE)
    assert nsec3_owner_digest((DomainName("not-a-hash.example.com."), entry[1]), ZONE) is None
    elsewhere = DomainName(f"{encode_base32hex(_hash('x.'))}.other.com.")
    assert nsec3_owner_digest((elsewhere, entry[1]), ZONE) is None


def test_nsec3_matches_and_covers_partition_the_zone():
    """Every name either matches a record or is covered by one, and never both."""
    names = [ZONE, "a.example.com.", "z.example.com."]
    chain = _nsec3_chain(names)
    for name in names:
        entry = find_nsec3_matching(name, chain, ZONE)
        assert entry is not None
        assert nsec3_matches(entry, name, ZONE)
        assert not nsec3_covers(entry, name, ZONE)
    for missing in ["b.example.com.", "m.example.com.", "0.example.com.", "zz.example.com."]:
        covering = find_nsec3_covering(missing, chain, ZONE)
        assert covering is not None, missing
        assert not nsec3_matches(covering, missing, ZONE)


def test_hash_order_is_octet_order():
    """Why §7.1¶5 can speak of "hash order" and §7.1¶17 can just sort.

    Hashed labels are equal-length and drawn from an alphabet with no cased letters, so canonical
    order of the owner names and octet order of the digests produce the same chain. A hash algorithm
    with variable-length digests would break that, which is worth having a test notice.
    """
    names = [ZONE, "a.example.com.", "mid.example.com.", "z.example.com.", "*.example.com."]
    digests = [_hash(name) for name in names]
    assert sort_canonical([_owner(digest) for digest in digests]) == [
        _owner(digest) for digest in sorted(digests)
    ]


def test_nsec3_denies_a_type_at_a_matching_name_only():
    """§8.5, and §7.1¶5: a signed zone never lists NSEC3 in its own bitmap, so that bit proves none."""
    chain = _nsec3_chain([ZONE, "a.example.com."], {"a.example.com.": [A]})
    entry = find_nsec3_matching("a.example.com.", chain, ZONE)
    assert nsec3_proves_no_type(entry, "a.example.com.", ZONE, int(DnsRType.MX))
    assert not nsec3_proves_no_type(entry, "a.example.com.", ZONE, A)
    assert not nsec3_proves_no_type(entry, "a.example.com.", ZONE, int(DnsRType.NSEC3))
    assert not nsec3_proves_no_type(entry, "z.example.com.", ZONE, int(DnsRType.MX))


def test_an_empty_bitmap_denies_everything_at_an_empty_non_terminal():
    """§8.5¶2: an empty non-terminal's NSEC3 has an empty Type Bit Maps field and still proves it."""
    chain = _nsec3_chain([ZONE, "sub.example.com."], {"sub.example.com.": []})
    entry = find_nsec3_matching("sub.example.com.", chain, ZONE)
    assert nsec3_proves_no_type(entry, "sub.example.com.", ZONE, A)


def test_unusable_records_are_filtered_and_mixed_parameters_are_refused():
    """§8.1 and §8.2¶1 are MUST-ignore; §8.2¶2 permits treating mixed parameters as bogus."""
    chain = _nsec3_chain([ZONE])
    owner, record = chain[0]
    assert usable_nsec3(chain) == chain
    assert usable_nsec3([(owner, RData_NSEC3(99, 0, 0, SALT, b"\x00" * 20, [A]))]) == []
    assert usable_nsec3([(owner, RData_NSEC3(1, 2, 0, SALT, b"\x00" * 20, [A]))]) == []
    mixed = [(owner, record), (owner, RData_NSEC3(1, 0, 7, SALT, b"\x00" * 20, [A]))]
    with pytest.raises(ContradictoryProofError, match="iterations"):
        usable_nsec3(mixed)
    assert len(usable_nsec3(mixed, strict_parameters=False)) == 2


def test_the_closest_encloser_proof_names_both_records():
    """§8.3: the encloser is the matched ancestor, the next closer is the covered child.

    The shape is RFC 5155 §7.2.1¶7's own example -- prove "gamma.example." exists and
    "beta.gamma.example." does not -- shortened to two labels so the intent stays readable.
    """
    chain = _nsec3_chain([ZONE, "b.example.com.", "c.example.com."])
    proof = closest_encloser_proof("x.b.example.com.", chain, ZONE)
    assert proof.encloser == DomainName("b.example.com.")
    assert proof.next_closer == DomainName("x.b.example.com.")
    assert nsec3_matches(proof.encloser_entry, "b.example.com.", ZONE)
    assert nsec3_covers(proof.next_closer_entry, "x.b.example.com.", ZONE)
    assert not proof.via_opt_out


def test_a_deeper_query_walks_up_to_the_real_encloser():
    """The flag carries across iterations, so the walk stops at the *closest* matching ancestor."""
    chain = _nsec3_chain([ZONE, "b.example.com.", "c.example.com."])
    proof = closest_encloser_proof("x.y.b.example.com.", chain, ZONE)
    assert proof.encloser == DomainName("b.example.com.")
    assert proof.next_closer == DomainName("y.b.example.com.")


def test_a_proof_for_a_name_that_exists_is_bogus_not_merely_missing():
    """§8.3¶10: a matching NSEC3 with the flag clear means the name exists."""
    chain = _nsec3_chain([ZONE, "b.example.com."])
    with pytest.raises(ContradictoryProofError, match="the name exists"):
        closest_encloser_proof("b.example.com.", chain, ZONE)


def test_no_records_at_all_is_an_incomplete_proof():
    """RFC 4035 §5.4¶6: a response short of its proof means ask again, not bogus."""
    with pytest.raises(IncompleteProofError, match="no NSEC3 RR"):
        closest_encloser_proof("x.example.com.", [], ZONE)


@pytest.mark.parametrize(
    ("types", "clause"),
    [([NS], "NS without SOA"), ([int(DnsRType.DNAME)], "DNAME at the encloser")],
)
def test_a_delegation_or_dname_cannot_deny_names_below_it(types, clause):
    """§8.3¶12: the encloser's record must belong to the zone making the claim.

    The server is not authoritative below a DNAME target or a bare delegation, so a "proof" built
    from such a name denies nothing -- it only looks as though it does.
    """
    chain = _nsec3_chain([ZONE, "b.example.com."], {"b.example.com.": types})
    with pytest.raises(ContradictoryProofError, match=r"RFC 5155 §8\.3"):
        closest_encloser_proof("x.b.example.com.", chain, ZONE)


def test_the_name_error_proof_also_denies_the_wildcard():
    """§8.4: a closest encloser proof *and* the wildcard at the encloser covered."""
    chain = _nsec3_chain([ZONE, "b.example.com."])
    proof = nsec3_proves_nxdomain("x.b.example.com.", chain, ZONE)
    assert proof.wildcard == DomainName("*.b.example.com.")
    assert nsec3_covers(proof.wildcard_entry, "*.b.example.com.", ZONE)
    assert proof.closest.encloser == DomainName("b.example.com.")


def test_a_missing_wildcard_record_makes_the_proof_incomplete():
    """Truncation usually costs the third record; that is a retry rather than a bogus zone."""
    chain = _nsec3_chain([ZONE, "b.example.com."])
    wildcard = DomainName("*.b.example.com.")
    without = [entry for entry in chain if not nsec3_covers(entry, wildcard, ZONE)]
    assert len(without) == len(chain) - 1
    with pytest.raises(IncompleteProofError, match=r"\*\.b\.example\.com\."):
        nsec3_proves_nxdomain("x.b.example.com.", without, ZONE)


def test_an_opt_out_span_is_flagged_for_the_ad_bit():
    """§9.2¶1: when Opt-Out covers the next closer, the response may not claim AD."""
    plain = _nsec3_chain([ZONE, "b.example.com."])
    opted_out = _nsec3_chain([ZONE, "b.example.com."], flags=1)
    assert not closest_encloser_proof("x.b.example.com.", plain, ZONE).via_opt_out
    assert closest_encloser_proof("x.b.example.com.", opted_out, ZONE).via_opt_out
