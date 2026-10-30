"""Invariants that hold across the protocol constant tables.

``DnsRType`` and ``DnsQType`` are written out as two explicit tables rather than
derived from one another, because deriving them (``class DnsQType(DnsRType)``
plus extra members) is impossible for an :class:`Enum` with members -- and, more
practically, so that a type checker can resolve ``DnsRType.SOA`` instead of
seeing an inherited union. The cost of duplication is drift, and these tests are
what pays for it: every type in the RR space must exist in the query space, and
the query-only pseudo-types must exist nowhere else.

.. rubric:: References

* RFC 1035 section 3.2.3 (QTYPE/QCLASS wildcards), section 6 (``AXFR``)
* RFC 6891 section 6.1.3 (extended RCODE), section 6.1.1 (``OPT`` is not stored)
* RFC 3597 section 3 (unknown types must not be treated as errors)
* RFC 6895 section 3.1 (the data TYPE / QTYPE / Meta-TYPE subcategories, and the
  bands the allocation policy leaves unassigned)
"""

import pytest

from namespy.enums import (
    DnsOpCode,
    DnsQClass,
    DnsQType,
    DnsRClass,
    DnsResponseCode,
    DnsRType,
    is_data_rrtype,
    rrtype_class,
)


def test_every_rr_type_is_also_a_query_type() -> None:
    """QTYPE is a strict superset of RTYPE (RFC 1035 section 3.2.3)."""
    missing = {int(member) for member in DnsRType} - {int(member) for member in DnsQType}
    assert not missing, f"query space is missing RR types: {sorted(missing)}"


@pytest.mark.parametrize(
    "qtype_only",
    [
        DnsQType.AXFR,
        DnsQType.MAILB,
        DnsQType.MAILA,
        DnsQType.ANY,
    ],
)
def test_query_only_pseudo_types_are_not_rr_types(qtype_only) -> None:
    """252-255 and ``AXFR`` may appear in a question but never in a zone.

    RFC 1035 section 3.2.3 restricts them to the question section; treating one
    as a stored type is how a resolver ends up caching a phantom RRset.
    """
    assert int(qtype_only) not in {int(member) for member in DnsRType}


def test_opt_is_in_the_type_space_but_is_pseudo_data() -> None:
    """``OPT`` (41) must decode, yet must never be treated as zone data.

    IANA lists 41 in the RR TYPEs registry with a pseudo-record annotation, so a
    receiver has to recognise it -- :meth:`namespy.packet.DnsPacket.opt` cannot
    work otherwise. RFC 6891 section 6.1.1 then forbids storing it ("OPT RRs
    MUST NOT be cached, forwarded, or stored in or loaded from master files"),
    which is why it
    is excluded from the cache key path rather than from the enum.
    """
    assert int(DnsQType.OPT) == 41
    assert DnsRType(41) is DnsRType.OPT
    assert DnsQType(41) is DnsQType.OPT
    # The companion rule -- that nothing on the cache or answer path may key on
    # OPT -- belongs with the code that enforces it, so it is asserted in
    # test_cache.py and test_resolve_steps.py rather than against the enum.


def test_registry_extends_past_one_byte() -> None:
    """TYPE is a 16-bit field (RFC 1035 section 3.2.2), and real types sit above 255.

    ``URI`` (256) and ``CAA`` (257) matter because a ``value < 256`` fast path --
    or any code that assumes a type fits in an octet -- would silently treat them
    as unknown. ``65535`` is reserved and must never appear on the wire
    (RFC 6895 section 3.1).
    """
    assert DnsRType(256) is DnsRType.URI
    assert DnsRType(257) is DnsRType.CAA
    assert int(DnsQType(257)) == 257
    assert any(int(m) == 65535 for m in DnsRType)


def test_query_only_members_are_exactly_the_mb_wildcards_and_transfers() -> None:
    """Pin the whole query-only delta, so a new member cannot slip in silently.

    RFC 1035 section 3.2.3 assigns 253/254 to the obsolete MB/MF/MR wildcard and
    255 to ``*``; the same QTYPE table assigns ``AXFR`` (252, a request for a
    transfer of an entire zone). ``IXFR`` (251, RFC 1995)
    is deliberately excluded because it is a transfer request that a server can
    also answer with, and appears in the RR space too.
    """
    query_only = {int(m) for m in DnsQType} - {int(m) for m in DnsRType}
    assert query_only == {252, 253, 254, 255}


def test_registry_numbers_that_are_easy_to_get_wrong() -> None:
    """Pinned because these specific values have moved or been misprinted.

    ``BADVERS`` took slot 16 when RFC 6891 section 6.1.3 defined it, pushing the
    TSIG codes up from the numbering in RFC 2930 section 2.6. RFC 7873's own
    IANA table printed ``BADCOOKIE=23``, which collides with ``BADALG``; the
    registry places it at 25.
    """
    assert DnsResponseCode.BADVERS == 16
    assert DnsResponseCode.BADSIG == 17
    assert DnsResponseCode.BADALG == 23
    assert DnsResponseCode.BADCOOKIE == 25


def test_extended_rcodes_are_representable() -> None:
    """Values above 15 exist only through EDNS(0) (RFC 6891 section 6.1.3)."""
    assert DnsResponseCode(16) is DnsResponseCode.BADVERS
    assert int(DnsResponseCode.NO_ERROR) == 0
    assert max(int(member) for member in DnsResponseCode if member.value <= 15) == 10


@pytest.mark.parametrize("value", [11, 12, 13, 14, 15, 26, 4096])
def test_unassigned_rcodes_decode_without_raising(value: int) -> None:
    """11-15 are unassigned; RFC 5625 section 6.3 permits dropping, not rejecting.

    Returning the raw int keeps an unfamiliar code inspectable instead of turning
    a whole response into an exception.
    """
    decoded = DnsResponseCode.parse(value)
    assert decoded is value or isinstance(decoded, int)
    assert int(decoded) == value


@pytest.mark.parametrize("value", [6, 7, 999])
def test_unassigned_opcodes_decode_without_raising(value: int) -> None:
    """An unassigned OPCODE is not a syntax error (RFC 2929 section 3.1)."""
    assert int(DnsOpCode.parse(value)) == value


def test_unknown_rr_type_degrades_to_int_not_exception() -> None:
    """RFC 3597 section 3 requires unknown types to pass through transparently."""
    assert DnsRType.parse(65300) == 65300
    assert isinstance(DnsRType.parse(65300), int)
    assert not isinstance(DnsRType.parse(65300), DnsRType)
    assert DnsRType.parse(int(DnsRType.A)) is DnsRType.A


def test_class_spaces_share_the_same_numbers() -> None:
    """QCLASS and RCLASS overlap completely except for the wildcard semantics."""
    assert {int(m) for m in DnsRClass} >= {int(m) for m in DnsQClass} - {255}
    assert int(DnsQClass.ANY) == 255
    assert int(DnsRClass.NONE) == 254


def test_rcode_str_is_the_mnemonic() -> None:
    """Formatting a response for a human should print a word, not ``16``.

    The mnemonics are uppercase because the member name *is* the mnemonic --
    ``mnemonic()`` returns ``.name``. Lowercase members would render a response
    as ``refused`` where every other tool prints ``REFUSED``, and the enum
    convention that forces the uppercase form is PEP 8's, not a preference.
    """
    assert str(DnsResponseCode.NAME_ERROR) == "NAME_ERROR"
    assert f"{DnsResponseCode.REFUSED}" == "REFUSED"
    assert DnsResponseCode.mnemonic(DnsResponseCode.NAME_ERROR) == "NAME_ERROR"


def test_mnemonic_labels_an_unknown_code() -> None:
    """An unregistered RCODE has no member, so it must still render usefully.

    RFC 6891 section 6.1.3 widens RCODE to 12 bits and the registry keeps
    growing, so a decoder cannot assume it has seen every value. ``parse``
    degrades to a plain ``int``, which is why ``mnemonic`` is a classmethod on
    the constant space rather than a method on a member: there is no member to
    call it on. RFC 3597 section 5's ``TYPE<n>`` convention is the model -- the
    rendering says which space a bare number came from, because type 1 and class
    1 are both ``1`` and mean ``A`` and ``IN``.
    """
    unknown = DnsResponseCode.parse(11)
    assert isinstance(unknown, int)
    assert DnsResponseCode.mnemonic(unknown) == "RCODE11"
    assert DnsRType.mnemonic(1) == "A"
    assert DnsRClass.mnemonic(1) == "IN"


# ------------------------------------------------- the data / QTYPE / Meta split
#
# RFC 6895 section 3.1 partitions the 16-bit space into three subcategories and
# allocates the rest to nobody. Nothing in the protocol asks the question often
# enough to be worth a type, but RFC 10029 section 3.1 asks it of every QTx and
# section 3.3 turns a wrong answer into a FORMERR, so the partition needs its own
# tests -- including the two boundaries people get wrong: OPT, a Meta-RR assigned a
# number inside the data band, and the 128-255 gap that stops "data" from being one
# contiguous run.


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, "reserved"),  # SIG(0)'s special indicator, "never allocated for ordinary use"
        (1, "data"),
        (41, "meta"),  # OPT, and the reason a range check alone is not enough
        (127, "data"),  # last of the low data band
        (128, "reserved"),  # first of the Q/Meta band, allocated to nobody yet
        (200, "reserved"),
        (249, "meta"),  # TKEY
        (250, "meta"),  # TSIG
        (251, "query"),  # IXFR
        (252, "query"),  # AXFR
        (255, "query"),  # ANY
        (256, "data"),  # URI, and the first number above the gap
        (32768, "data"),  # TA, assigned from 32,768 upward per section 3.1
        (61439, "data"),  # last number the policy allocates to data
        (61440, "reserved"),  # "Reserved for future use. IETF Review required"
        (65280, "reserved"),  # "Reserved for Private Use"
        (65535, "reserved"),  # "Reserved (Standards Action)"
    ],
)
def test_every_band_of_the_rrtype_space_classifies(value: int, expected: str) -> None:
    """The boundaries of RFC 6895 section 3.1's allocation table, each one tested at
    the number where the policy changes rather than in the middle of a band."""
    assert expected == rrtype_class(value)


def test_the_meta_and_query_sets_are_the_ones_rfc_6895_counts() -> None:
    """Section 3.1 counts its own subcategories -- "There are currently three
    Meta-TYPEs assigned: OPT, TSIG, and TKEY. There are currently five QTYPEs
    assigned: * (ALL/ANY), MAILA, MAILB, AXFR, and IXFR" -- so the classification must
    agree with that arithmetic exactly. A sixth Meta-TYPE appearing in this module's
    answer would mean it had invented one."""
    meta = {value for value in range(0x10000) if rrtype_class(value) == "meta"}
    query = {value for value in range(0x10000) if rrtype_class(value) == "query"}
    assert {41, 249, 250} == meta
    assert {251, 252, 253, 254, 255} == query


def test_a_number_outside_the_field_is_not_a_type_at_all() -> None:
    """The field is 16 bits, so 65536 is not an unassigned type -- it cannot arrive on
    the wire. Classifying it would let a caller's arithmetic bug pass as a policy
    judgement."""
    for bad in (-1, 0x10000):
        with pytest.raises(ValueError, match="16-bit field"):
            rrtype_class(bad)


def test_is_data_rrtype_is_the_same_question_not_a_second_opinion() -> None:
    """Two predicates that can disagree are one too many; the convenience function has
    to be exactly the classifier read one way."""
    for value in (0, 1, 41, 127, 128, 249, 251, 255, 256, 61439, 61440, 65535):
        assert is_data_rrtype(value) == (rrtype_class(value) == "data"), value


def test_the_query_only_and_meta_types_are_never_data() -> None:
    """The eight numbers RFC 6895 section 3.1 counts as QTYPEs and Meta-TYPEs are
    spelled out here rather than derived from the enums, because both enums carry all
    of them -- ``DnsRType`` has to know OPT, TSIG and TKEY to decode a message that
    contains one -- so a set difference between the two enums would (correctly) come
    out as just 251-255 and prove nothing about the Meta-TYPEs.

    They are also exactly the numbers RFC 10029 section 3.3 refuses as a QTx, so this
    is the same list read by two different documents.
    """
    for value in (41, 249, 250, 251, 252, 253, 254, 255):
        assert not is_data_rrtype(value), DnsQType.mnemonic(value)
