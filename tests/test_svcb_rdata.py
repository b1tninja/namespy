"""SVCB and HTTPS RDATA: RFC 9460 Appendix D vectors, and what must be refused.

The vectors are copied from Appendix D of RFC 9460 -- the hex from the
``Hex encoding:`` lines, the presentation text from the ``Wire format`` lines of
Figures 1-9 -- because that appendix exists precisely so implementations can be
checked against one another. Each case is asserted in both directions: octets in,
octets out unchanged, and the RFC's own presentation text in, the RFC's own octets
out. The presentation half is the stronger one: it pins down escaping, the
``keyNNN`` fallback for unregistered keys, and the bracketless IPv6 list that
section 2.5 makes canonical.

The malformed cases at the bottom are the failures section 2.4.3 lists, seen from the
parser's side. The difference in consequence -- a *client* rejects the whole RRset, a
*server* only skips the record -- belongs to :func:`namespy.svcb.select_records`; this
layer reports and keeps the octets intact so the caller can still forward or log them.
"""

import struct

import pytest

from namespy.names import DomainName
from namespy.packet import DnsPacket
from namespy.rdata import RData_HTTPS, RData_SVCB
from namespy.svcb import SvcbCandidate, select_records
from namespy.wire import DnsPacketParseError

#: (RFC 9460 Appendix D presentation text, ``Hex encoding:`` octets)
APPENDIX_D = [
    pytest.param(
        "0 foo.example.com.",
        "000003666f6f076578616d706c6503636f6d00",
        id="D.2-fig1-aliasmode",
    ),
    pytest.param("1 .", "000100", id="D.3-fig2-service-not-available"),
    pytest.param(
        "16 foo.example.com. port=53",
        "001003666f6f076578616d706c6503636f6d00000300020035",
        id="D.4-fig3-port",
    ),
    pytest.param(
        "1 foo.example.com. key667=hello",
        "000103666f6f076578616d706c6503636f6d00029b000568656c6c6f",
        id="D.5-fig4-unregistered-key",
    ),
    pytest.param(
        '1 foo.example.com. key667="hello\\210qoo"',
        "000103666f6f076578616d706c6503636f6d00029b000968656c6c6fd2716f6f",
        id="D.5-fig5-unknown-octet-quoted",
    ),
    pytest.param(
        '1 foo.example.com. ipv6hint="2001:db8::1,2001:db8::53:1"',
        "000103666f6f076578616d706c6503636f6d00"
        "0006002020010db800000000000000000000000120010db8000000000000000000530001",
        id="D.6-fig6-ipv6hint-quoted",
    ),
    pytest.param(
        '1 example.com. ipv6hint="2001:db8:122:344::192.0.2.33"',
        "0001076578616d706c6503636f6d000006001020010db80122034400000000c0000221",
        id="D.6-fig7-embedded-ipv4",
    ),
    pytest.param(
        "16 foo.example.org. alpn=h2,h3-19 mandatory=ipv4hint,alpn ipv4hint=192.0.2.1",
        "001003666f6f076578616d706c65036f726700"
        "0000000400010004000100090268320568332d313900040004c0000201",
        id="D.7-fig8-mandatory",
    ),
    pytest.param(
        r'16 foo.example.org. alpn="f\\\\oo\\,bar,h2"',
        "001003666f6f076578616d706c65036f7267000001000c08665c6f6f2c626172026832",
        id="D.7-fig9-backslash-escaping",
    ),
    pytest.param(
        r"16 foo.example.org. alpn=f\\\092oo\092,bar,h2",
        "001003666f6f076578616d706c65036f7267000001000c08665c6f6f2c626172026832",
        id="D.7-fig9-digit-escaped-equivalent",
    ),
]


def message(answers: list[bytes]) -> bytes:
    """One question (``example.com/A``) plus raw RR octets; see test_packet_wire.py."""
    return b"".join(
        (
            struct.pack("!HBBHHHH", 1, 0x80, 0x80, 1, len(answers), 0, 0),
            b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1),
            *answers,
        )
    )


def vector(index: int) -> tuple[str, bytes]:
    """One Appendix D case as ``(presentation text, octets)``, by position.

    ``pytest.param`` hides its values behind ``.values``, which reads badly in a test
    that is not being parametrized over them -- the figures are referred to by number
    here (Figure 2 is ``vector(1)``), so they go through this instead.
    """
    presentation, hexstr = APPENDIX_D[index].values
    return str(presentation), bytes.fromhex(str(hexstr))


@pytest.mark.parametrize(("presentation", "hexstr"), APPENDIX_D)
def test_appendix_d_wire_vectors_round_trip(presentation: str, hexstr: str) -> None:
    """The RFC's octets decode, and encode back to the same octets.

    Output is canonical rather than a copy of the input in one respect: parameters
    come back in ascending SvcParamKey order, which section 2.2 requires on the wire.
    Every Appendix D vector is already sorted, so the bytes match exactly -- an
    unsorted record is the malformed case tested below.
    """
    blob = bytes.fromhex(hexstr)
    parsed = RData_SVCB.parse_from(blob, 0, len(blob))
    assert parsed.to_wire() == blob, presentation
    assert parsed.wire == blob, "the received octets must survive untouched"


@pytest.mark.parametrize(("presentation", "hexstr"), APPENDIX_D)
def test_appendix_d_presentation_vectors(presentation: str, hexstr: str) -> None:
    """The RFC's presentation text parses to the RFC's octets, and back.

    Figure 9 contributes two ids on purpose: section 2.5 calls the quoted and the
    digit-escaped spellings of a backslash equivalent, so both must reach one encoding.
    """
    blob = bytes.fromhex(hexstr)
    candidate = SvcbCandidate.from_presentation("example.com.", presentation)
    assert candidate.to_wire() == blob, presentation
    # Re-rendering what we decoded must parse again and mean the same thing, even
    # where the canonical rendering differs from the published text (key ordering).
    rendered = str(candidate)
    again = SvcbCandidate.from_presentation("example.com.", rendered)
    assert again.to_wire() == blob, rendered


def test_alias_and_service_modes_are_distinguishable() -> None:
    """SvcPriority 0 is the whole of the AliasMode/ServiceMode distinction (2.4)."""
    _, alias_blob = vector(0)
    _, service_blob = vector(2)
    alias = RData_SVCB.parse_from(alias_blob, 0, len(alias_blob))
    service = RData_SVCB.parse_from(service_blob, 0, len(service_blob))
    assert alias.is_alias
    assert alias.priority == 0
    assert not service.is_alias
    assert service.priority == 16


def test_root_target_name_stays_the_root() -> None:
    """Figure 2: a TargetName of ``.`` is kept literally, at both layers.

    Section 2.5 gives the root a different meaning per mode -- "service not
    available" in AliasMode, "use the owner name" in ServiceMode. That is the
    resolver's decision; the RDATA's job is not to make it early, because substituting
    the owner name here would erase the fact that the record was written with a root
    target, which is the one thing the two modes disagree about.
    """
    _, blob = vector(1)
    parsed = RData_SVCB.parse_from(blob, 0, len(blob))
    assert parsed.target == DomainName("")
    assert parsed.to_presentation() == "1 ."
    assert parsed.candidate("svc.example.com.").target == DomainName("")


@pytest.mark.parametrize(
    ("rdata", "reason"),
    [
        pytest.param(b"", "too short", id="empty"),
        pytest.param(b"\x00\x01", "too short", id="priority-only"),
        # RDLENGTH stops inside the TargetName: the first label promises 3 octets and
        # has 1. The message names the label rather than the field, because that is
        # the rule the name decoder broke; the offsets quoted in it are the record's.
        pytest.param(b"\x00\x00\x03\x00", "truncated label", id="name-overruns-rdlength"),
        # port=53 with the last octet of its value cut off. The parameters run to the
        # end of the RDLENGTH (2.2), so a value cannot spill past it.
        pytest.param(
            b"\x00\x01\x00\x00\x03\x00\x02\x00", "only 1 remain in the RDATA", id="value-truncated"
        ),
        # Two 'port' params. The rule that catches this is the duplicate one, not the
        # ordering one -- "exactly once" is a separate requirement (2.2).
        pytest.param(
            b"\x00\x01\x00\x00\x03\x00\x02\x00\x35\x00\x03\x00\x02\x00\x35",
            "duplicate",
            id="duplicate-key",
        ),
    ],
)
def test_malformed_rdata_is_refused(rdata: bytes, reason: str) -> None:
    """A record the standard calls malformed raises, and says which rule fired.

    The wording matters as much as the exception: section 2.4.3 splits these failures
    between "discard this RR" and "reject the RRset", and whoever reads the log needs
    to know which of the two the record tripped.
    """
    with pytest.raises(DnsPacketParseError, match=reason):
        RData_SVCB.parse_from(rdata, 0, len(rdata))


def test_unsorted_params_are_refused() -> None:
    """Section 2.2: SvcParams MUST be in ascending key order -- and it says so twice.

    A parser that accepted the unsorted form would silently disagree with every other
    implementation about whether two records are the same RR, which is the whole
    reason the ordering rule exists.
    """
    _, blob = vector(7)
    keys = list(RData_SVCB.parse_from(blob, 0, len(blob)).params)
    assert keys == sorted(keys)
    # 'port' (3) before 'alpn' (1) is descending.
    descending = b"\x00\x01\x00\x00\x03\x00\x02\x00\x35\x00\x01\x00\x03\x02h2"
    with pytest.raises(DnsPacketParseError, match="ascending"):
        RData_SVCB.parse_from(descending, 0, len(descending))


def test_target_name_is_expanded_on_output() -> None:
    """Section 2.2: the TargetName is sent uncompressed even if it arrived compressed.

    A compression pointer is a property of one packet, so re-emitting one would make
    the answer depend on where in the message the record happened to sit -- and would
    break the byte-for-byte comparison section 2.2's ordering rule assumes.
    """
    answer = (
        b"\xc0\x0c"  # owner: the question name, compressed
        b"\x00\x40\x00\x01\x00\x00\x01\x2c"  # SVCB, IN, TTL 300
        b"\x00\x04"  # RDLENGTH 4
        b"\x00\x01\xc0\x0c"  # priority 1, TargetName compressed to that same name
    )
    packet, _ = DnsPacket.parse(message([answer]))
    rdata = packet.answers[0].rdata
    assert isinstance(rdata, RData_SVCB)
    assert rdata.target == DomainName("example.com.")
    assert bytes(rdata) == bytes.fromhex("0001076578616d706c6503636f6d00")


def test_https_mandatory_keys_reach_the_client_test() -> None:
    """Section 8: an HTTPS RR carrying ``port`` is unusable to a client that lacks it.

    The RDATA class is what knows which mapping applies, so it is what supplies the
    automatically-mandatory keys; generic SVCB supplies none. Without that the two
    classes would decode identically and every client would look HTTPS-capable.
    """
    _, blob = vector(2)
    https = RData_HTTPS.parse_from(blob, 0, len(blob))
    generic = RData_SVCB.parse_from(blob, 0, len(blob))
    assert https.candidate("svc.example.com.").auto_mandatory == {3, 2}
    assert not generic.candidate("svc.example.com.").auto_mandatory

    blind = select_records(
        [https.candidate("svc.example.com.")], client_keys=("alpn",), shuffle=None
    )
    assert not blind.service
    assert "port" in blind.skipped[0].reasons[0]

    aware = select_records(
        [https.candidate("svc.example.com.")], client_keys=("alpn", "port"), shuffle=None
    )
    assert len(aware.service) == 1
    # Generic SVCB defines no mapping, so 'port' is merely optional there (section 8).
    assert len(select_records([generic.candidate("svc.example.com.")], client_keys=()).service)
