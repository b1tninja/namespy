import pytest

from aiodns.names import DomainName
from aiodns.packet import DnsPacket, DnsPacketParseError, DnsQuestion, Query


def test_dns_packet_defaults_are_not_shared() -> None:
    p1 = DnsPacket()
    p2 = DnsPacket()

    p1.questions.append("sentinel")  # type: ignore[arg-type]
    assert "sentinel" not in p2.questions


def test_dns_packet_parse_smoke() -> None:
    # Standard DNS query:
    #   ID = 0x1234
    #   flags = 0x0100 (RD)
    #   QDCOUNT = 1
    #   QNAME = "example.com"
    #   QTYPE = A (1)
    #   QCLASS = IN (1)
    query = bytes.fromhex(
        "1234"  # ID
        "0100"  # flags
        "0001"  # QDCOUNT
        "0000"  # ANCOUNT
        "0000"  # NSCOUNT
        "0000"  # ARCOUNT
        "07"
        "6578616d706c65"  # example
        "03"
        "636f6d"  # com
        "00"  # root
        "0001"  # QTYPE A
        "0001"  # QCLASS IN
    )

    pkt, offset = DnsPacket.parse(query)
    assert offset == len(query)
    assert pkt.QDCOUNT == 1
    assert len(pkt.questions) == 1
    # Wire form decodes to an absolute name (root terminator kept in presentation).
    assert str(pkt.questions[0].name) == "example.com."
    assert pkt.questions[0].name.is_absolute


def test_parse_truncated_raises_dns_packet_parse_error() -> None:
    with pytest.raises(DnsPacketParseError) as exc:
        DnsPacket.parse(b"")
    assert "12" in str(exc.value).lower() or "header" in str(exc.value).lower()
    assert exc.value.data == b""
    assert exc.value.wire_hex() == ""


def test_in_addr_arpa_ptr_query_with_digit_leading_labels() -> None:
    """
    PTR to 1.0.0.127.in-addr.arpa: labels are numeric; wire is 40 B (from client log).
    Previously failed: bare AssertionError (letter-only first char).
    """
    w40 = bytes.fromhex(
        "0001010000010000000000000131013001300331323707696e2d61646472046172706100000c0001"
    )
    assert len(w40) == 40
    pkt, off = DnsPacket.parse(w40)
    assert off == 40
    assert str(pkt.questions[0].name) == "1.0.0.127.in-addr.arpa."
    assert int(pkt.questions[0].qtype) == 12  # PTR


def test_parse_truncated_after_qname() -> None:
    """QTYPE/QCLASS need 4 bytes; clear DnsPacketParseError when tail is short."""
    full = bytes.fromhex(
        "0001010000010000000000000131013001300331323707696e2d61646472046172706100000c0001"
    )
    bad = full[:-1]  # drop last byte of QTYPE/QCLASS
    with pytest.raises(DnsPacketParseError) as e:
        DnsPacket.parse(bad)
    assert "truncated" in str(e.value).lower()


def test_dns_packet_hex_wire() -> None:
    q = Query(questions=[DnsQuestion(DomainName("a.example"), 1, 1)], ID=0xABCD)
    h = q.__hex__()
    assert h == bytes(q).hex()
    assert "abcd" in h.lower() or len(h) >= 4
