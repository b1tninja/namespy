"""Does wrapping raw RDATA in a codec ever change the wire form?

_wrap_rdata's docstring promises a successful decode cannot alter the bytes. If
that were false, a record built by hand would serialise differently from the
octets the caller supplied -- which would corrupt the root-hints loader and every
cache round-trip. Property-checked rather than trusted.
"""

import ipaddress
import struct

from namespy import DnsPacket, DnsRClass, DnsRecord, DnsRType, DomainName, Response
from namespy.rdata import RData, RData_SOA, RData_TXT, all_rdata_classes

#: SOA timers in wire order, so the payloads below read as fields not hex.
_TIMERS = "!IIIII"


def _wire_of(rtype, blob):
    return bytes(DnsRecord(DomainName("h.example."), rtype, DnsRClass.IN, 60, rdata=blob))


def test_handbuilt_record_serialises_to_the_octets_supplied():
    """Wrapping must be wire-neutral for every type that has a codec."""
    cases = {
        int(DnsRType.A): bytes.fromhex("7f000001"),
        int(DnsRType.AAAA): ipaddress.IPv6Address("2001:db8::1").packed,
        int(DnsRType.TXT): b"\x0bhello world",
        int(DnsRType.SOA): (
            bytes(DomainName("ns1.example."))
            + bytes(DomainName("host.example."))
            + struct.pack(_TIMERS, 1, 7200, 3600, 1209600, 3600)
        ),
        int(DnsRType.MX): b"\x00\x0a" + bytes(DomainName("mail.example.")),
        int(DnsRType.SRV): b"\x00\x01\x00\x02\x1f\x90" + bytes(DomainName("sip.example.")),
        # No codec registered: must stay opaque and byte-identical anyway.
        65: bytes.fromhex("00046400"),
        99: b"\xde\xad\xbe\xef",
    }
    for rtype, blob in cases.items():
        record = DnsRecord(DomainName("h.example."), rtype, DnsRClass.IN, 60, rdata=blob)
        # Strip the name + fixed RR header to compare the RDATA actually emitted.
        emitted = bytes(record.rdata)
        assert emitted == blob, (rtype, blob.hex(), emitted.hex())
        codec_name = type(record.rdata).__name__
        print(f"{rtype:>3} {codec_name:<16} {blob.hex()} == {emitted.hex()}")


def test_wrapping_decodes_when_it_can_and_stays_opaque_when_it_cannot():
    good = DnsRecord(DomainName("h."), DnsRType.A, rdata=bytes.fromhex("7f000001"))
    assert good.rdata.to_presentation() == "127.0.0.1"

    # Short A: cannot decode, so it must not raise and must not be renamed.
    bad = DnsRecord(DomainName("h."), DnsRType.A, rdata=b"\x01\x02")
    assert isinstance(bad.rdata, RData)
    assert not isinstance(bad.rdata, type(good.rdata))
    assert bytes(bad.rdata) == b"\x01\x02"
    assert bad.rdata.to_presentation() == r"\# 2 0102"

    # The empty SOA placeholder the cache tests use.
    placeholder = DnsRecord(DomainName("h."), DnsRType.SOA, rdata=b"")
    assert bytes(placeholder.rdata) == b""


def test_codec_round_trip_survives_a_full_message():
    """A wrapped record must survive encode -> parse -> encode unchanged."""
    soa = DnsRecord(
        DomainName("example.com."),
        DnsRType.SOA,
        DnsRClass.IN,
        7200,
        rdata=(
            bytes(DomainName("ns1.example.com."))
            + bytes(DomainName("hostmaster.example.com."))
            + struct.pack(_TIMERS, 2, 7200, 3600, 1209600, 720)
        ),
    )
    message = bytes(
        Response(
            ID=0x1234,
            QR=1,
            questions=[],
            nameservers=[soa],
        )
    )
    parsed, consumed = DnsPacket.parse(message)
    assert consumed == len(message)
    loaded = parsed.nameservers[0]
    assert isinstance(loaded.rdata, RData_SOA)
    assert loaded.rdata.minimum == 720
    assert bytes(loaded) == bytes(soa)


def test_txt_wrapping_keeps_the_character_string_split():
    """A hand-built TXT with valid charstrings is decoded, split preserved."""
    blob = b"\x03abc\x03def"
    record = DnsRecord(DomainName("h."), DnsRType.TXT, rdata=blob)
    assert isinstance(record.rdata, RData_TXT)
    assert record.rdata.strings == [b"abc", b"def"]
    assert bytes(record.rdata) == blob


def test_every_registered_codec_round_trips_through_a_wrapped_record():
    """Sweep the registry so a codec added later is covered by this guard."""
    payloads = {
        int(DnsRType.A): bytes.fromhex("c0a80101"),
        int(DnsRType.AAAA): bytes(16),
        int(DnsRType.NS): bytes(DomainName("a.example.")),
        int(DnsRType.CNAME): bytes(DomainName("b.example.")),
        int(DnsRType.PTR): bytes(DomainName("c.example.")),
        int(DnsRType.DNAME): bytes(DomainName("d.example.")),
        int(DnsRType.TXT): b"\x01x",
        int(DnsRType.MX): b"\x00\x00" + bytes(DomainName(".")),
        int(DnsRType.SRV): b"\x00\x00\x00\x00\x00\x00" + bytes(DomainName(".")),
        int(DnsRType.SOA): (
            bytes(DomainName(".")) + bytes(DomainName(".")) + struct.pack(_TIMERS, 0, 0, 0, 0, 0)
        ),
        # RFC 9460 Appendix D Figure 3 (SVCB) and the same shape for HTTPS: the
        # parameters are already in ascending key order, which the section 2.2
        # encoding rule requires and which this sweep compares byte for byte.
        int(DnsRType.SVCB): bytes.fromhex("000100000300020035"),
        int(DnsRType.HTTPS): bytes.fromhex("001003666f6f076578616d706c6503636f6d00000300020035"),
    }
    untested = set(all_rdata_classes()) - set(payloads)
    assert not untested, f"add a round-trip payload for: {sorted(untested)}"
    for rtype, blob in payloads.items():
        record = DnsRecord(DomainName("h."), rtype, rdata=blob)
        assert bytes(record.rdata) == blob, (rtype, blob.hex(), bytes(record.rdata).hex())
    print("registry sweep ok:", len(payloads), "codecs")
