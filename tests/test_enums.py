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
* RFC 6891 section 6.1.3 (extended RCODE), section 6.3 (``OPT`` is not stored)
* RFC 3597 section 3 (unknown types must not be treated as errors)
"""

import pytest

from aiodns.enums import (
    DnsOpCode,
    DnsQClass,
    DnsQType,
    DnsRClass,
    DnsResponseCode,
    DnsRType,
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
    receiver has to recognise it -- :meth:`aiodns.packet.DnsPacket.opt` cannot
    work otherwise. RFC 6891 section 6.3 then forbids storing it, which is why it
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
    255 to ``*``; RFC 1035 section 6 assigns ``AXFR``. ``IXFR`` (251, RFC 1995)
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
    assert DnsResponseCode.badvers == 16
    assert DnsResponseCode.badsig == 17
    assert DnsResponseCode.badalg == 23
    assert DnsResponseCode.badcookie == 25


def test_extended_rcodes_are_representable() -> None:
    """Values above 15 exist only through EDNS(0) (RFC 6891 section 6.1.3)."""
    assert DnsResponseCode(16) is DnsResponseCode.badvers
    assert int(DnsResponseCode.no_error) == 0
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
    """Formatting a response for a human should not print ``16`` or ``16``."""
    assert str(DnsResponseCode.name_error) == "name_error"
    assert f"{DnsResponseCode.refused}" == "refused"
