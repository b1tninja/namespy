"""Wire-format regression tests for :mod:`namespy.packet` and :mod:`namespy.rdata`.

Each test marks a bug the parser used to have, or a rule from the standards that
the previous revision broke. The hostile corpus is constructed rather than
mutated: every case is a payload a hostile server can send, and each must fail as
:class:`~namespy.wire.DnsPacketParseError` rather than as ``AttributeError``,
``IndexError``, ``struct.error`` -- or, worse, silently succeed.
"""

import struct

import pytest

from namespy.enums import DnsQR, DnsQType, DnsRClass, DnsResponseCode, DnsRType
from namespy.names import DomainName
from namespy.packet import (
    DnsPacket,
    DnsPacketParseError,
    DnsQuestion,
    DnsRecord,
    Query,
    Response,
    clamp_ttl,
)
from namespy.rdata import (
    RData,
    RData_A,
    RData_AAAA,
    RData_MX,
    RData_NS,
    RData_SOA,
    RData_SRV,
    RData_TXT,
    all_rdata_classes,
    generic_presentation,
    rdata_class_for,
    split_charstrings,
    type_name_of,
)

NAME = DomainName("www.example.com")


def rr_wire(name: bytes, rtype: int, rclass: int, ttl: int, rdata: bytes) -> bytes:
    return name + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def message(*, qname=b"\x07example\x03com\x00", qtype=1, answers=(), nameservers=(), tc=False):
    """A minimal response: one question plus the given raw RR octets."""
    flags1 = 0b10000000 | (0b00000010 if tc else 0)
    return b"".join(
        (
            struct.pack("!HBBHHHH", 1, flags1, 0x80, 1, len(answers), len(nameservers), 0),
            qname + struct.pack("!HH", qtype, 1),
            *answers,
            *nameservers,
        )
    )


# ------------------------------------------------------------ unknown types


def test_https_rr_does_not_kill_the_parse() -> None:
    """Type 65 crashed the listener: the enum lookup left an int, then ``.value``.

    RFC 9460 made ``HTTPS`` common enough that any browser-facing answer could
    carry one, and RFC 3597 section 3 requires it to be handled opaquely.
    """
    payload = message(answers=[rr_wire(b"\x07example\x03com\x00", 65, 1, 300, b"\x00\x00\x03\x00")])
    packet, consumed = DnsPacket.parse(payload)
    assert int(packet.answers[0].rtype) == 65
    assert consumed == len(payload)
    assert packet.answers[0].rdata.to_presentation() == r"\# 4 00000300"


def test_private_type_round_trips() -> None:
    """An unregistered type must survive parse and re-serialisation intact."""
    raw = rr_wire(b"\x01t\x07example\x03com\x00", 65300, 1, 60, b"\xaa\xbb")
    packet, _ = DnsPacket.parse(message(answers=[raw]))
    assert bytes(packet.answers[0]).endswith(raw)


def test_unknown_rdata_has_no_registered_codec() -> None:
    assert rdata_class_for(65) is None
    assert rdata_class_for(int(DnsRType.A)) is RData_A


# ------------------------------------------------------------------- SOA


def test_soa_serialises() -> None:
    """``bytes()`` on an SOA raised ``AttributeError`` because ``blob`` was unset."""
    soa = RData_SOA("ns1.example.com", "hostmaster.example.com", 1, 7200, 3600, 1209600, 300)
    wire = bytes(soa)
    assert wire == bytes(RData_SOA.parse_from(wire, 0, len(wire)))


def test_soa_exposes_minimum() -> None:
    """RFC 2308 section 5 makes MINIMUM the negative-cache TTL; it was absent."""
    assert RData_SOA("ns1.example.com", "host.example.com", 1, 2, 3, 4, 3600).minimum == 3600


@pytest.mark.parametrize(
    ("older", "newer", "naive_is_right"),
    [
        (4, 5, True),
        (0x7FFFFFFE, 0x7FFFFFFF, True),
        (0x7FFFFFFF, 0x80000000, True),
        (0xFFFFFFF0, 0x00000010, False),
    ],
)
def test_soa_serial_comparison_wraps(older: int, newer: int, naive_is_right: bool) -> None:
    """RFC 1035 section 3.3.13 mandates RFC 1982 serial number space arithmetic.

    The wrap case is the one that breaks a naive ``>``: once a zone's serial passes
    2**31, plain integer comparison calls a fresh serial older than a stale one and
    a secondary refuses the update forever.
    """
    assert RData_SOA.serial_ahead(newer, older)
    assert not RData_SOA.serial_ahead(older, newer)
    assert (newer > older) is naive_is_right


def test_soa_cannot_read_past_its_rdlength() -> None:
    """RFC 9267 section 5: an RDATA field read stops at the declared length."""
    body = bytes(DomainName("ns1.example.com")) + b"\x00" * 3
    raw = rr_wire(b"\x07example\x03com\x00", int(DnsRType.SOA), 1, 60, body)
    with pytest.raises(DnsPacketParseError, match="RDATA"):
        DnsPacket.parse(message(answers=[raw]))


def test_nxdomain_with_soa_round_trip() -> None:
    soa = DnsRecord(
        DomainName("example.com"),
        DnsRType.SOA,
        DnsRClass.IN,
        900,
        rdata=RData_SOA("ns1.example.com", "host.example.com", 42, 1, 2, 3, 300),
    )
    response = Response(
        ID=0x9999,
        QR=DnsQR.RESPONSE,
        RCODE=DnsResponseCode.NAME_ERROR,
        questions=[DnsQuestion(DomainName("missing.example.com"), DnsQType.A)],
        nameservers=[soa],
    )
    parsed, _ = DnsPacket.parse(bytes(response))
    assert DnsResponseCode.NAME_ERROR == parsed.RCODE
    assert parsed.nameservers[0].rdata.minimum == 300


# ------------------------------------------------------------ addresses


def test_a_rejects_wrong_rdlength() -> None:
    """RFC 1035 section 3.4.1 fixes RDLENGTH for A at four octets."""
    short = rr_wire(b"\x07example\x03com\x00", int(DnsRType.A), 1, 60, b"\x7f\x00\x00")
    with pytest.raises(DnsPacketParseError, match="must be exactly 4"):
        DnsPacket.parse(message(answers=[short]))


def test_aaaa_parses() -> None:
    blob = bytes(RData_AAAA("2001:db8::1"))
    raw = rr_wire(b"\x07example\x03com\x00", int(DnsRType.AAAA), 1, 60, blob)
    packet, _ = DnsPacket.parse(message(answers=[raw]))
    assert packet.answers[0].rdata.to_presentation() == "2001:db8::1"


# ----------------------------------------------------- names inside RDATA


def test_ns_rdata_canonicalises_pointers() -> None:
    """Stored RDATA must not keep a pointer into a datagram that no longer exists.

    :mod:`namespy.cache.sqlite` writes ``bytes(record)`` and re-parses it at offset
    zero, where the original offsets are meaningless.
    """
    qname = b"\x07example\x03com\x00"
    # A pointer to offset 12, where the question's QNAME begins in message().
    raw = rr_wire(qname, int(DnsRType.NS), 1, 10800, b"\x03ns1\xc0\x0c")
    packet, _ = DnsPacket.parse(message(answers=[raw]))
    rdata = packet.answers[0].rdata
    assert rdata.to_presentation() == "ns1.example.com."
    assert b"\xc0" not in bytes(rdata)
    assert RData_NS.parse_from(bytes(rdata), 0, len(bytes(rdata))) == rdata


def test_name_inside_rdata_cannot_overrun() -> None:
    """A name in RDATA may point backwards but must not consume the next record."""
    body = b"\x03ns1" + bytes(DomainName("somewhere.example.org"))
    raw = rr_wire(b"\x07example\x03com\x00", int(DnsRType.NS), 1, 10800, body[:6])
    with pytest.raises(DnsPacketParseError):
        DnsPacket.parse(message(answers=[raw]))


# ---------------------------------------------------- character strings


def test_txt_survives_a_claimed_overrun() -> None:
    """RFC 9267 section 5: a character-string header must fit inside RDLENGTH."""
    with pytest.raises(DnsPacketParseError, match="remain inside"):
        RData_TXT.parse_from(b"\x05ab", 0, 2)


def test_txt_long_text_splits_at_255() -> None:
    """RFC 1035 section 3.3.14 requires a string over 255 octets to be chunked."""
    text = "x" * 600
    record = RData_TXT.from_text(text)
    assert [len(part) for part in record.strings] == [255, 255, 90]
    assert RData_TXT.parse_from(bytes(record), 0, len(bytes(record))).text == text


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"", [b""]),  # empty text is one zero-length string, not zero strings
        (b"x" * 255, [b"x" * 255]),  # exactly at the limit stays whole
        (b"x" * 256, [b"x" * 255, b"x"]),  # one octet over forces a second string
    ],
)
def test_split_charstrings_boundaries(payload: bytes, expected: list[bytes]) -> None:
    """The chunker must not invent an empty trailing chunk nor merge at the edge.

    An extra ``b""`` at the end would change the wire form and so the RDATA hash,
    which the cache keys on; two chunks where one belongs breaks re-signing and
    any consumer that compares RDATA byte-for-byte.
    """
    assert split_charstrings(payload) == expected


def test_txt_empty_text_is_one_empty_string() -> None:
    """``""`` on the wire is ``\\x00`` -- a single zero-length character-string."""
    assert bytes(RData_TXT.from_text("")) == b"\x00"
    assert RData_TXT.parse_from(b"\x00", 0, 1).text == ""


def test_txt_rejects_an_oversized_single_string() -> None:
    """Constructing an un-splittable string is a caller error, not a wire error."""
    with pytest.raises(ValueError, match="exceeds"):
        RData_TXT([b"y" * 256])


def test_txt_escapes_nonprinting_octets() -> None:
    """RFC 2181 section 11 permits arbitrary octets, so rendering must be lossless.

    ``\\DDD`` is the RFC 1035 section 5.1 escape; a quote and a backslash each take
    one escape of their own, so three backslashes precede the octet escape here.
    """
    assert RData_TXT([b'a"\\\x01']).to_presentation() == r'"a\"\\\001"'


# ----------------------------------------------------------- MX and SRV


def test_null_mx_is_recognised() -> None:
    """RFC 7505: preference 0 pointing at the root means "do not send mail"."""
    assert RData_MX(DomainName.root_label(), 0).is_null_mx
    assert not RData_MX("mail.example.com", 10).is_null_mx


def test_mx_rejects_a_truncated_exchange() -> None:
    with pytest.raises(DnsPacketParseError):
        RData_MX.parse_from(b"\x00\x0a\x05mail", 0, 5)


def test_srv_round_trip_and_zero_port() -> None:
    """RFC 2782 section 3: a port of 0 means the service is deliberately absent."""
    srv = RData_SRV("svc.example.com", 1, 200, 0)
    wire = bytes(srv)
    again = RData_SRV.parse_from(wire, 0, len(wire))
    assert (again.priority, again.weight, again.port) == (1, 200, 0)


def test_generic_presentation_matches_rfc3597() -> None:
    """RFC 3597 section 5 fixes the ``\\# <len> <hex>`` form."""
    assert generic_presentation(b"\xde\xad\xbe\xef") == r"\# 4 deadbeef"
    assert str(RData(b"\xde\xad\xbe\xef")) == r"\# 4 deadbeef"


# ---------------------------------------------------------------- EDNS(0)


def _opt(ttl: int, payload: int = 1232) -> DnsRecord:
    return DnsRecord(DomainName.root_label(), 41, payload, ttl, rdata=b"")


def _with_opt(*records, ttl: int, rcode: int = 0) -> bytes:
    return bytes(
        Response(
            ID=7,
            QR=DnsQR.RESPONSE,
            RCODE=rcode,
            questions=[DnsQuestion(NAME, DnsQType.A)],
            additional_records=[_opt(ttl)],
            answers=list(records),
        )
    )


def test_opt_ad_flag_and_payload_size() -> None:
    """RFC 6891 sections 6.1.3-6.1.4: FLAGS live in OPT's TTL low half, CLASS carries the size."""
    parsed, _ = DnsPacket.parse(_with_opt(ttl=1 << 15))
    assert parsed.opt() is not None
    assert parsed.ad
    assert not parsed.cd
    assert parsed.requestor_payload_size == 1232


def test_extended_rcode_shifts_by_four() -> None:
    """RFC 6891 section 6.1.3: the header RCODE is 4 bits, so EXTENDED is ``<< 4``.

    Reading the header field as an octet would report BADVERS (16) as 256.
    """
    parsed, _ = DnsPacket.parse(_with_opt(ttl=1 << 24))
    assert parsed.extended_rcode == 16
    assert int(parsed.RCODE) == 0


def test_no_opt_means_header_rcode() -> None:
    parsed, _ = DnsPacket.parse(
        bytes(
            Response(
                ID=1,
                QR=DnsQR.RESPONSE,
                RCODE=DnsResponseCode.NOT_AUTH,
                questions=[DnsQuestion(NAME, DnsQType.A)],
            )
        )
    )
    assert parsed.opt() is None
    assert parsed.extended_rcode == 9
    assert not parsed.ad


def test_header_rcode_above_fifteen_needs_opt() -> None:
    response = Response(ID=1, QR=DnsQR.RESPONSE, RCODE=16, questions=[])
    with pytest.raises(ValueError, match="EDNS"):
        bytes(response)


# ------------------------------------------------------------ message level


def test_extra_record_beyond_counts_is_rejected() -> None:
    """An RR the header never promised is trailing octets, not a misplaced answer.

    The original loop filled sections from "whatever is left" and so accepted
    this, letting a sender smuggle a record past the section accounting.
    """
    answer = rr_wire(bytes(NAME), int(DnsRType.A), 1, 60, b"\x01\x02\x03\x04")
    header = struct.pack("!HBBHHHH", 1, 0b10000000, 0x80, 1, 1, 0, 0)
    question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    with pytest.raises(DnsPacketParseError, match="after the last RR"):
        DnsPacket.parse(header + question + answer + answer)


def test_rdlength_overrun_is_rejected() -> None:
    """The old ``data[offset:][:length]`` produced a short RDATA instead of failing."""
    name = bytes(NAME)
    raw = name + struct.pack("!HHIH", 1, 1, 60, 999) + b"\x01\x02\x03"
    with pytest.raises(DnsPacketParseError, match="overruns the message"):
        DnsPacket.parse(message(answers=[raw]))


def test_multi_question_message_decodes_although_no_server_accepts_it() -> None:
    """Decoding is not accepting (RFC 8906 section 5.2).

    Every current server answers a two-question query with FORMERR, and
    :mod:`namespy.server` is one of them -- but the refusal is policy, not syntax.
    A decoder that refused here could not inspect the odd message it is named for,
    and would be unable to read the very FORMERR reply this library sends back.
    """
    two = DnsQuestion(NAME, 1, 1).__bytes__() + DnsQuestion(NAME, 28, 1).__bytes__()
    header = struct.pack("!HBBHHHH", 1, 0, 0, 2, 0, 0, 0)
    packet, consumed = DnsPacket.parse(header + two)

    assert packet.QDCOUNT == 2
    assert len(packet.questions) == 2
    assert consumed == len(header + two)


def test_absurd_qdcount_cannot_spin() -> None:
    """A hostile count is bounded by the datagram, not by a special-case ceiling.

    Each question consumes at least three octets, so the read fails on the first
    missing octet rather than looping; the message is still rejected, which is what
    the old up-front ``QDCOUNT > 1`` check was really protecting.
    """
    header = struct.pack("!HBBHHHH", 1, 0, 0, 65535, 0, 0, 0)
    with pytest.raises(DnsPacketParseError):
        DnsPacket.parse(header)


def test_lenient_parse_keeps_a_truncated_answer() -> None:
    """TC=1 is a normal condition (RFC 1035 section 4.1.1) worth partial parsing.

    The header and question are all that is needed to retry over TCP, which is
    what RFC 7766 section 6 requires a resolver do.
    """
    answer = rr_wire(bytes(NAME), int(DnsRType.A), 1, 60, b"\x01\x02\x03\x04")
    payload = message(tc=True, answers=[answer])[:-2]
    with pytest.raises(DnsPacketParseError):
        DnsPacket.parse(payload)
    packet, _ = DnsPacket.parse(payload, strict=False)
    assert packet.TC
    assert len(packet.questions) == 1
    assert packet.answers == []


def test_query_and_response_classes_survive_round_trip() -> None:
    assert isinstance(
        DnsPacket.parse(bytes(Query(questions=[DnsQuestion(NAME, DnsQType.A)])))[0], Query
    )
    response = Response(ID=1, QR=DnsQR.RESPONSE, questions=[DnsQuestion(NAME, DnsQType.A)])
    assert isinstance(DnsPacket.parse(bytes(response))[0], Response)


def test_rdlength_recomputed_on_output() -> None:
    """A stale rdlength would desynchronise every section that follows it."""
    record = DnsRecord(NAME, DnsRType.A, DnsRClass.IN, 60, rdlength=999, rdata=b"\x01\x02\x03\x04")
    encoded = bytes(record)
    # Past the name: TYPE(2) + CLASS(2) + TTL(4), then RDLENGTH.
    assert struct.unpack_from("!H", encoded, len(bytes(NAME)) + 8)[0] == 4
    DnsPacket.parse(message(answers=[encoded]))


@pytest.mark.parametrize(
    ("given", "expected"),
    [(0xFFFFFFFF, 0x7FFFFFFF), (0x80000000, 0x7FFFFFFF), (3600, 3600), (-1, 0)],
)
def test_ttl_clamp(given: int, expected: int) -> None:
    """RFC 2181 section 8 caps a served TTL at 2147483647 seconds."""
    assert clamp_ttl(given) == expected


def test_question_equality_ignores_enum_identity() -> None:
    """1 == DnsQType.A, and a trailing root dot is the same name."""
    left = DnsQuestion("example.com", DnsQType.A, DnsRClass.IN)
    right = DnsQuestion(DomainName("example.com."), 1, 1)
    assert left == right
    assert len({left, right}) == 1


def test_unknown_opcode_degrades_to_int() -> None:
    """RFC 2929 section 3.1: an unassigned opcode is not a syntax error.

    A receiver answers NOTIMP rather than discarding the message, so the parser
    must keep the value rather than raise out of an enum lookup.
    """
    flags1 = 0b10000000 | (7 << 3)  # response, OPCODE 7 (unassigned)
    packet, _ = DnsPacket.parse(struct.pack("!HBBHHHH", 1, flags1, 0, 0, 0, 0, 0))
    assert int(packet.OPCODE) == 7


# ------------------------------------------------- codec registry and naming


def test_every_codec_the_library_ships_is_registered() -> None:
    """A missing registration is silent: the type just stays opaque."""
    registry = all_rdata_classes()
    for rtype in (
        DnsRType.A,
        DnsRType.AAAA,
        DnsRType.NS,
        DnsRType.CNAME,
        DnsRType.SOA,
        DnsRType.MX,
        DnsRType.TXT,
        DnsRType.SRV,
        DnsRType.PTR,
        DnsRType.DNAME,
    ):
        assert registry[int(rtype)].RType is rtype


def test_unknown_type_name_uses_the_rfc3597_mnemonic() -> None:
    """RFC 3597 section 5 gives ``TYPE<n>`` when there is no mnemonic."""
    assert type_name_of(int(DnsRType.A)) == "A"
    assert type_name_of(65280) == "TYPE65280"
    assert type_name_of(None) == "RDATA"


def test_constructor_rejects_bad_arguments_with_typeerror() -> None:
    """These were ``assert`` checks, so ``-O`` turned them into silent accepts."""
    with pytest.raises(TypeError):
        DnsPacket(answers=(DnsRecord(NAME, rdata=b"\x00" * 4),))
    with pytest.raises(TypeError):
        DnsPacket(questions=[], suffix="not bytes")


def test_parse_rejects_a_non_bytes_object_and_a_bad_offset() -> None:
    with pytest.raises(TypeError):
        DnsPacket.parse("not bytes")
    with pytest.raises(DnsPacketParseError):
        DnsPacket.parse(b"\x00" * 12, offset=99)


def test_sections_are_read_to_their_own_counts_in_order() -> None:
    """The original loop filled each section from "whatever remains".

    That accepted a message whose header promised fewer records than it carried,
    and left octets nobody owned when a section ran short.
    """
    qname = b"\x07example\x03com\x00"
    answer = rr_wire(qname, int(DnsRType.A), 1, 60, b"\x01\x02\x03\x04")
    authority = rr_wire(qname, int(DnsRType.NS), 1, 60, b"\x03ns1\xc0\x0c")
    additional = rr_wire(qname, int(DnsRType.A), 1, 60, b"\x05\x06\x07\x08")
    payload = (
        struct.pack("!HBBHHHH", 1, 0b10000000, 0x80, 1, 1, 1, 1)
        + qname
        + struct.pack("!HH", 1, 1)
        + answer
        + authority
        + additional
    )
    packet, consumed = DnsPacket.parse(payload)
    assert consumed == len(payload)
    assert [int(r.rtype) for r in packet.answers] == [int(DnsRType.A)]
    assert [int(r.rtype) for r in packet.nameservers] == [int(DnsRType.NS)]
    assert [int(r.rtype) for r in packet.additional_records] == [int(DnsRType.A)]
    assert str(packet.nameservers[0].rdata) == "ns1.example.com."


def test_count_shortfall_is_rejected_rather_than_tolerated() -> None:
    """A header promising two answers and carrying one is corrupt, not partial."""
    header = struct.pack("!HBBHHHH", 1, 0b10000000, 0x80, 1, 2, 0, 0)
    payload = header + b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    payload += rr_wire(b"\x07example\x03com\x00", 1, 1, 60, b"\x01\x02\x03\x04")
    with pytest.raises(DnsPacketParseError):
        DnsPacket.parse(payload)
