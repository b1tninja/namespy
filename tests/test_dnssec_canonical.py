"""The canonical RRset a DNSSEC signature actually covers (RFC 4034 §6.2-§6.3, §3.1.8.1).

No published vector exists for these bytes -- RFC 4034 gives the construction in prose and the
IETF never attached an example RRset to it -- so the tests are built to be read against that
prose: the concatenation is spelled out octet by octet, the ordering rule is the one sentence
§6.3¶1 writes, and the type-list tests quote the two errata (1062, 1063) that reconcile RFC 4034
§6.2 item 3 with RFC 3597 §7. Where a test could be satisfied by an accident of implementation, it
says which accident it is ruling out.

What is *not* here is any signature arithmetic: this produces the octets a signature covers, and
verifying one is still the dependency's job.
"""

import struct

import pytest

from namespy.dnssec import (
    CANONICAL_DOWNCASE_TYPES,
    CanonicalizationError,
    DuplicateRecordError,
    canonical_rdata_octets,
    canonical_rr_bytes,
    canonical_rrset_bytes,
    canonical_rrset_rdatas,
    rrsig_label_count,
    rrsig_signed_data,
    signed_owner_name,
)
from namespy.enums import DnsRClass, DnsRType
from namespy.names import DomainName
from namespy.rdata import RData_MX, RData_NSEC, RData_RRSIG, RData_SOA, RData_SRV

EXAMPLE = "example.com."
EXAMPLE_WIRE = b"\x07example\x03com\x00"
WILD_WIRE = b"\x01*\x07example\x03com\x00"


def _rrsig(**changes) -> RData_RRSIG:
    fields = {
        "type_covered": int(DnsRType.A),
        "algorithm": 13,
        "labels": 2,
        "original_ttl": 3600,
        "expiration": 1429574399,
        "inception": 1129852800,
        "key_tag": 40430,
        "signer_name": "Example.com.",
        "signature": b"\x0a" * 8,
    }
    fields.update(changes)
    return RData_RRSIG(**fields)


def test_signed_data_is_rrsig_rdata_followed_by_every_rr():
    """§3.1.8.1¶2's ``sign(RRSIG_RDATA | RR(1) | RR(2)...)``, byte for byte.

    The expected value is assembled here from the figure in §3.1 and the sentence in §3.1.8.1¶5
    rather than from the implementation, so a shared misreading cannot make both sides agree.
    """
    record = _rrsig()
    rdatas = [bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])]
    signed = rrsig_signed_data(record, EXAMPLE, rdatas, rclass=int(DnsRClass.IN))

    head = struct.pack("!HBBIIIH", int(DnsRType.A), 13, 2, 3600, 1429574399, 1129852800, 40430)
    # §3.1.8.1¶4: the Signer's Name in canonical form, so the mixed case above is gone.
    expected = head + EXAMPLE_WIRE
    for rdata in sorted(rdatas):
        expected += (
            EXAMPLE_WIRE + struct.pack("!HHIH", int(DnsRType.A), int(DnsRClass.IN), 3600, 4) + rdata
        )
    assert signed == expected
    # Once for the Signer's Name, once per RR: any other count means the owner was not repeated
    # or the signer was hashed with its original mixed case still on it.
    assert signed.count(EXAMPLE_WIRE) == 3


def test_the_owner_used_is_the_wildcard_the_labels_field_points_at():
    """§3.1.3 plus §3.1.8.1¶6: the signed owner is the wildcard, not the served name.

    Here Labels is 2 against an owner of 3 labels, so every RR must carry ``*.example.com.``. A
    validator that hashed the answer's own name would reject a correct wildcard signature, which
    looks exactly like an attack.

    ``example.com.`` also appears in the RRSIG prefix as the Signer's Name, and the wildcard name
    ends with it, so the comparison is made on the RR portion rather than on the whole string --
    a substring test here would pass for the wrong reason or fail for one.
    """
    record = _rrsig(labels=2)
    signed = rrsig_signed_data(record, "www.example.com.", [bytes([192, 0, 2, 1])])
    tail = signed[len(record.signed_data_prefix()) :]
    assert tail.startswith(WILD_WIRE)

    exact = _rrsig(labels=3)
    tail = rrsig_signed_data(exact, "www.example.com.", [bytes([192, 0, 2, 1])])[
        len(exact.signed_data_prefix()) :
    ]
    assert tail.startswith(b"\x03www" + EXAMPLE_WIRE)


def test_each_rr_repeats_owner_type_class_and_ttl():
    """§3.1.8.1¶5-¶9: ten octets of context per RR, not once per set.

    Counted from the end of the RRSIG prefix: each record must cost exactly owner + 10 + RDATA.
    An implementation that hoisted the owner out here would produce a shorter string and fail every
    signature it checked.
    """
    record = _rrsig(labels=2)
    owner_len = len(bytes(DomainName(EXAMPLE)))
    one = rrsig_signed_data(record, EXAMPLE, [bytes([192, 0, 2, 1])])
    two = rrsig_signed_data(record, EXAMPLE, [bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])])
    assert len(two) - len(one) == owner_len + 10 + 4


def test_rrset_ordering_puts_a_shorter_prefix_before_a_longer_one():
    """§6.3¶1: "the absence of an octet sorts before a zero octet".

    That clause rules out any comparison that looks at length first or reads the RDATA as a
    number. 00 is the hardest case: it must sort before 0000, and 0000 before 0001.
    """
    unordered = [b"\x00\x01", b"\x00\x00", b"\x01", b"\x00"]
    assert canonical_rrset_rdatas(int(DnsRType.A), unordered) == (
        b"\x00",
        b"\x00\x00",
        b"\x00\x01",
        b"\x01",
    )


def test_duplicate_rdata_is_a_protocol_error_unless_asked_otherwise():
    """§6.3¶2: MUST treat a duplicate as a protocol error; if lenient, drop all but one.

    Both branches are the specification's, so both are asserted: the default refuses, and the
    opt-in yields a set with the duplicate gone rather than one still holding two identical RRs --
    the latter would sign a string no signer produced.
    """
    rdatas = [b"\x00\x00\x00\x01", b"\x00\x00\x00\x01", b"\x00\x00\x00\x02"]
    with pytest.raises(DuplicateRecordError, match="protocol error"):
        canonical_rrset_rdatas(int(DnsRType.A), rdatas)

    deduped = canonical_rrset_rdatas(int(DnsRType.A), rdatas, tolerate_duplicates=True)
    assert deduped == (b"\x00\x00\x00\x01", b"\x00\x00\x00\x02")


# ------------------------------------------------------- which types downcase (item 3)


def test_the_downcase_list_is_the_reconciled_union_of_the_two_lists():
    """25 types: RFC 3597 §7¶4's set plus RRSIG and NSEC from RFC 4034 §6.2 item 3.

    Each document carries a verified erratum against the other (1062, 1063) for omitting entries,
    and the union is what implementations converge on. Asserted as mnemonics so the test reads as
    the sentence it encodes -- including the HINFO that appears in both lists while holding no
    domain name, harmless because item 3 speaks only of names contained in RDATA.
    """
    from namespy.rdata import type_name_of

    assert {type_name_of(number) for number in CANONICAL_DOWNCASE_TYPES} == {
        "NS",
        "MD",
        "MF",
        "CNAME",
        "SOA",
        "MB",
        "MG",
        "MR",
        "PTR",
        "HINFO",
        "MINFO",
        "MX",
        "RP",
        "AFSDB",
        "RT",
        "SIG",
        "PX",
        "NXT",
        "NAPTR",
        "KX",
        "SRV",
        "DNAME",
        "A6",
        "RRSIG",
        "NSEC",
    }


@pytest.mark.parametrize(
    ("record", "raw", "canonical"),
    [
        (
            RData_MX("Mail.Example.COM.", 10),
            b"\x00\x0a\x04Mail\x07Example\x03COM\x00",
            b"\x00\x0a\x04mail\x07example\x03com\x00",
        ),
        (
            RData_SRV("Target.Example.COM.", 1, 2, 443),
            b"\x00\x01\x00\x02\x01\xbb\x06Target\x07Example\x03COM\x00",
            b"\x00\x01\x00\x02\x01\xbb\x06target\x07example\x03com\x00",
        ),
        (
            RData_NSEC("Next.Example.COM.", [int(DnsRType.A)]),
            b"\x04Next\x07Example\x03COM\x00\x00\x01\x40",
            b"\x04next\x07example\x03com\x00\x00\x01\x40",
        ),
    ],
)
def test_a_listed_type_has_its_embedded_name_downcased(record, raw, canonical):
    """§6.2 item 3, one record per shape: name-only, prefixed, and name-plus-bitmap."""
    assert bytes(record) == raw
    assert record.canonical_wire() == canonical
    assert canonical_rdata_octets(int(record.RType), raw) == canonical


def test_canonicalisation_leaves_numeric_fields_alone():
    """MX preference 0x4142 and SRV port 0x4142 are not letters.

    This is the test that forbids the tempting implementation of lowering the whole RDATA: both
    values sit inside A-Z as bytes, and the canonical form must still carry the number. Only the
    name octets move.
    """
    mx = RData_MX("Ab.COM.", 0x4142)
    assert mx.canonical_wire() == b"\x41\x42\x02ab\x03com\x00"

    srv = RData_SRV("Ab.COM.", 0x4142, 0x5A5A, 0x4142)
    assert srv.canonical_wire().startswith(b"\x41\x42\x5a\x5a\x41\x42")
    assert srv.canonical_wire().endswith(b"\x02ab\x03com\x00")


def test_soa_downcases_both_names_and_keeps_the_timers():
    """§6.2 item 3 lists SOA: two names, then five 32-bit numbers that are not names."""
    soa = RData_SOA(
        "Ns1.Example.COM.",
        "Host.Example.COM.",
        serial=0x01020304,
        refresh=0x0A0B0C0D,
        retry=1,
        expire=2,
        minimum=3,
    )
    canonical = soa.canonical_wire()
    assert canonical.startswith(b"\x03ns1\x07example\x03com\x00\x04host\x07example\x03com\x00")
    assert canonical.endswith(struct.pack("!IIIII", 0x01020304, 0x0A0B0C0D, 1, 2, 3))


def test_rrsig_downcases_its_signer_and_not_its_signature():
    """The signature is opaque octets; only the Signer's Name is a name (§6.2 item 3)."""
    opaque = bytes(range(65, 91))  # every octet inside A-Z
    record = _rrsig(signature=opaque)
    canonical = record.canonical_wire()
    assert canonical.endswith(opaque)
    assert record.signed_data_prefix() == canonical[: -len(opaque)]
    assert EXAMPLE_WIRE in record.signed_data_prefix()


def test_a_type_after_rfc_3597_keeps_the_case_of_its_embedded_name():
    """RFC 3597 §7¶5: for types defined after it, embedded names are NOT downcased.

    HTTPS carries a real domain name in target-name and RFC 9460 says nothing about canonical
    form, so §7¶5 governs and the case survives. Deliberately the opposite of the "downcase names
    in RDATA" instinct, which is why it needs its own test.
    """
    https_rdata = bytes([0, 0]) + b"\x04Http\x07Example\x03COM\x00"
    assert canonical_rdata_octets(int(DnsRType.HTTPS), https_rdata) == https_rdata


def test_a_listed_type_with_no_codec_refuses_to_be_hashed():
    """NAPTR is in the list and has no codec here, so canonicalisation is refused.

    Returning the raw octets would be a guess about where the names sit, and the only symptom of
    guessing wrong is a valid signature that fails -- which reads as an attack. The message names
    the type, because that is what tells the next person which codec to write.
    """
    with pytest.raises(CanonicalizationError, match="35"):
        canonical_rdata_octets(int(DnsRType.NAPTR), b"\x00\x01\x00\x03abc")


def test_canonical_rr_bytes_is_the_public_single_record_case():
    """The one-RR building block, checked against the same §3.1.8.1¶5 layout."""
    blob = canonical_rr_bytes(EXAMPLE, int(DnsRType.TXT), int(DnsRClass.IN), 300, b"\x03abc")
    assert blob == EXAMPLE_WIRE + struct.pack("!HHIH", int(DnsRType.TXT), 1, 300, 4) + b"\x03abc"

    # The set form of the same thing, for a single record.
    assert (
        canonical_rrset_bytes(EXAMPLE, int(DnsRType.TXT), int(DnsRClass.IN), 300, [b"\x03abc"])
        == blob
    )


# ---------------------------------------------------------- Labels and wildcards (§3.1.3)


@pytest.mark.parametrize(
    ("owner", "labels"),
    [
        ("www.example.com.", 3),
        ("*.example.com.", 2),
        (".", 0),
        ("a.b.example.com.", 4),
    ],
)
def test_labels_count_excludes_root_and_wildcard(owner, labels):
    """§3.1.3¶3, whose own examples are 3 for www.example.com., 2 for *.example.com., 0 for root.

    The section says "the wildcard label", singular, and a zone cannot hold a second one: a
    wildcard is by definition a single leftmost label, so subtracting one is the whole rule rather
    than a special case of a general one.
    """
    assert rrsig_label_count(owner) == labels


@pytest.mark.parametrize(
    ("owner", "labels", "expected", "wildcard"),
    [
        ("www.example.com.", 3, "www.example.com.", False),
        ("www.example.com.", 2, "*.example.com.", True),
        ("a.b.example.com.", 2, "*.example.com.", True),
        ("a.b.example.com.", 3, "*.b.example.com.", True),
        ("*.example.com.", 2, "*.example.com.", True),
        (".", 0, ".", False),
    ],
)
def test_the_signed_owner_is_reconstructed_from_labels(owner, labels, expected, wildcard):
    """§3.1.3¶2: replace the expanded run of labels with one ``*`` and keep the rest."""
    name, was_wildcard = signed_owner_name(owner, labels)
    assert name == DomainName(expected)
    assert was_wildcard is wildcard


def test_labels_larger_than_the_owner_name_is_refused():
    """§3.1.3¶3: Labels "MUST be less than or equal to" the owner's label count.

    A record that breaks that cannot describe any name, and clamping it would let a validator
    hash an owner name that no signer ever signed.
    """
    with pytest.raises(ValueError, match="exceeds"):
        signed_owner_name("www.example.com.", 4)


def test_a_set_downcases_its_owner_once_per_record():
    """§6.2 item 2: the owner is downcased wherever it appears, not just in the RRset header.

    Built from an all-uppercase owner so the difference is visible in every RR rather than once.
    """
    blob = canonical_rr_bytes("EXAMPLE.COM.", int(DnsRType.TXT), int(DnsRClass.IN), 300, b"\x03abc")
    assert blob.startswith(EXAMPLE_WIRE)
    assert b"E" not in blob[: len(EXAMPLE_WIRE)]
