"""EDNS(0) on outbound queries: the OPT record, its fields, and the fallback.

RFC 6891 section 6.1.2 defines the OPT pseudo-record -- NAME the root, TYPE
41, CLASS the requestor's UDP payload size -- and section 6.1.3 lays its TTL
out as ``EXTENDED-RCODE | VERSION`` over ``FLAGS | Z``, with FLAGS in the
*low* 16 bits of the TTL (DO is the flags field's own bit 15, i.e. TTL bit
15 -- RFC 3225 section 3 draws it as the MSB of the third TTL octet).
Section 6.2.3 puts the floor on the advertised size ("Values lower than
512 MUST be treated as equal to 512"), and section 6.2.2 gives the requestor
its remedy when the far end cannot honor the record: "it MAY issue queries
without an OPT record".

Section 7 is what makes the remedy *triggerable* rather than speculative: a
responder that does not implement EDNS "MUST respond with a return code
(RCODE) of FORMERR ... and MUST NOT include an OPT record in the response",
so a FORMERR without OPT is the spec's own signal that a re-ask should be
unextended. BADVERS (section 6.1.3) is the version-level rejection; NOTIMP
is what ossified middleboxes answer instead of either. Section 6.2.1 adds
the one storage rule: "The OPT record MUST NOT be cached."

These tests drive :meth:`Resolver.query` with a recording transport, the
same seam the truncation tests use: what is under test is which bytes go
out, in what order, after which answer.
"""

import asyncio
import ipaddress

import pytest

from namespy.cache import MemoryDnsCache
from namespy.enums import DnsQR, DnsQType, DnsRClass, DnsResponseCode, DnsRType
from namespy.names import DomainName
from namespy.packet import DnsPacket, DnsQuestion, DnsRecord, Query, Response
from namespy.resolver import (
    Answer,
    RecursiveResolver,
    Resolver,
    Sname,
    _write_cache,
)

NS_NAME = DomainName("ns1.example.com.")
NS_IP = ipaddress.IPv4Address("198.51.100.53")
QNAME = DomainName("www.example.com.")
ANSWER_IP = ipaddress.IPv4Address("93.184.216.34")


class RecordingTransport:
    """Stands in for the datagram transport, keeping what was sent."""

    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append((bytes(data), addr))


def make_resolver(**attrs):
    """A bare ``Resolver`` driven without a socket (class-attribute knobs)."""
    resolver = Resolver()
    resolver.transport = RecordingTransport()
    resolver.queue = {}
    for name, value in attrs.items():
        setattr(resolver, name, value)
    return resolver


def ns_record():
    return DnsRecord(NS_NAME, DnsRType.NS, DnsRClass.IN, 0, rdata=NS_NAME)


def addr_record():
    return DnsRecord(NS_NAME, DnsRType.A, DnsRClass.IN, 0, rdata=NS_IP.packed)


def parse_sent(wire: bytes) -> DnsPacket:
    packet, consumed = DnsPacket.parse(wire)
    assert consumed == len(wire)
    return packet


# ------------------------------------------------------- the record on the wire


def test_query_advertises_edns() -> None:
    """One add_edns() call lifts the 512-octet ceiling of RFC 1035 section
    4.2.1: root name, type 41, CLASS the advertised size, empty RDATA."""
    query = Query(questions=[DnsQuestion(QNAME, DnsQType.A)]).add_edns(1232)
    packet = parse_sent(bytes(query))
    opt = packet.opt()
    assert opt is not None
    assert packet.requestor_payload_size == 1232
    assert packet.edns_version == 0
    assert int(opt.ttl) == 0  # query: no extended RCODE, no flags
    assert bytes(opt.rdata) == b""


def test_opt_is_eleven_octets_at_the_tail_of_the_message() -> None:
    """Byte-for-byte: NAME root | TYPE 41 | CLASS 1232 | TTL 0 | RDLENGTH 0."""
    wire = bytes(Query(questions=[DnsQuestion(QNAME, DnsQType.A)]).add_edns(1232))
    assert wire.endswith(b"\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00")


def test_add_edns_places_version_in_bits_16_to_23_and_flags_in_the_low_half() -> None:
    """RFC 6891 section 6.1.3/6.1.4 end to end: what the encoder writes, the
    decoder reads back. An earlier encoder put VERSION at bit 8 -- a TTL of
    ``1 << 8`` reads as plain Z there, so version negotiation vanished
    silently; pinning both halves is the whole point of this test."""
    query = Query(questions=[DnsQuestion(QNAME, DnsQType.A)])
    query.add_edns(512, version=2, flags=0x8000)
    opt = query.opt()
    assert opt is not None
    assert int(opt.ttl) == (2 << 16) | 0x8000
    packet = parse_sent(bytes(query))
    assert packet.edns_version == 2
    assert packet.ad  # DO is TTL bit 15 (RFC 3225 section 3)
    assert not packet.cd


def test_advertised_payload_floors_at_512() -> None:
    """RFC 6891 section 6.2.3: "Values lower than 512 MUST be treated as
    equal to 512" -- said of the receiver, but a requestor that advertises
    less is asking to be ignored; add_edns clamps instead."""
    packet = parse_sent(bytes(Query(questions=[DnsQuestion(QNAME, DnsQType.A)]).add_edns(64)))
    assert packet.requestor_payload_size == 512


def test_remove_edns_leaves_a_plain_rfc_1035_query() -> None:
    query = Query(questions=[DnsQuestion(QNAME, DnsQType.A)]).add_edns(1232)
    assert query.remove_edns() is True
    assert query.remove_edns() is False
    assert query.opt() is None
    assert int(query.ARCOUNT) == 0
    assert parse_sent(bytes(query)).opt() is None


def opt_wire(ttl: int = 0, payload: int = 1232, rcode: int = 0, *, flags: int | None = None):
    """An OPT record per RFC 6891 sections 6.1.2-6.1.3: EXTENDED-RCODE in
    the TTL's top octet, VERSION in octet 1, FLAGS (DO = TTL bit 8) in the
    low half. *ttl* is the raw TTL, or the VERSION when *flags* is given."""
    if flags is not None:
        ttl = (rcode << 24) | ((ttl & 0xFF) << 8) | (flags & 0xFFFF)
    else:
        ttl = (rcode << 24) | (ttl & 0x00FFFFFF)
    return DnsRecord(DomainName.root_label(), DnsRType.OPT, payload, ttl, rdata=b"")


def answer_for(query, *, rcode=0, additional=()):
    return Response(
        ID=query.ID,
        QR=DnsQR.RESPONSE,
        RCODE=rcode,
        questions=list(query.questions),
        answers=[DnsRecord(QNAME, DnsRType.A, DnsRClass.IN, 300, rdata=ANSWER_IP.packed)],
        additional_records=list(additional),
    )


def sent_queries(resolver):
    """Every query the resolver put on the wire, parsed back."""
    return [DnsPacket.parse(wire)[0] for wire, _addr in resolver.transport.sent]


def has_opt(packet) -> bool:
    return packet.opt() is not None


# ------------------------------------------------------- the OPT record sent


def test_query_carries_an_edns0_opt_record() -> None:
    wire = bytes(Query().add_edns(1232))
    parsed, _consumed = DnsPacket.parse(wire)
    opt = parsed.opt()
    assert opt is not None
    # RFC 6891 section 6.1.2: the owner name is the root and CLASS is the
    # requestor's UDP payload size.
    assert DomainName.root_label() == opt.name
    assert 1232 == int(opt.rclass)
    # version 0, no flags -> the whole TTL is zero (section 6.1.3)
    assert 0 == int(opt.ttl)
    assert b"" == opt.rdata.wire
    assert bytes(parsed) == wire  # parse/serialize round trip


def test_add_edns_replaces_rather_than_stacks() -> None:
    # RFC 6891 section 6.1.1: "At most one OPT RR MUST occur in a message";
    # a second advertisement must swap the first, not join it.
    query = Query().add_edns(1232).add_edns(512)
    assert 1 == len([r for r in query.additional_records if int(r.rtype) == 41])
    assert 512 == query.requestor_payload_size
    assert 1 == query.ARCOUNT


def test_payload_size_floor_is_512() -> None:
    # RFC 6891 section 6.2.3: "Values lower than 512 MUST be treated as
    # equal to 512" -- a smaller advertisement would truncate an answer the
    # responder was willing to send, so it is raised, not honored.
    assert 512 == Query().add_edns(64).requestor_payload_size
    assert 65535 == Query().add_edns(65535).requestor_payload_size


def test_remove_edns_leaves_an_unextended_query() -> None:
    query = Query().add_edns(1232)
    assert query.remove_edns() is True
    assert query.remove_edns() is False  # idempotent
    assert 0 == query.ARCOUNT
    parsed, _ = DnsPacket.parse(bytes(query))
    assert parsed.opt() is None


def test_extended_rcode_reads_the_upper_bits_from_opt_ttl() -> None:
    # RFC 6891 section 6.1.3: effective RCODE = EXTENDED-RCODE << 4 | header
    # RCODE, so SERVFAIL(2) with upper bits 1 gives 18 (YXRRSET).
    response = Response(
        ID=1,
        QR=DnsQR.RESPONSE,
        RCODE=2,
        additional_records=[opt_wire(rcode=1)],
    )
    parsed, _ = DnsPacket.parse(bytes(response))
    assert 18 == parsed.extended_rcode
    assert DnsResponseCode.SERVER_FAILURE == parsed.RCODE  # header field intact
    plain = Response(ID=1, QR=DnsQR.RESPONSE, RCODE=2)
    assert 2 == plain.extended_rcode  # no OPT -> header value, sections 6.1.3


def test_version_and_flags_round_trip() -> None:
    # Section 6.1.3 places VERSION in octet 1 of the TTL and FLAGS in the
    # low 16 bits -- FLAGS bit 15 (DO, RFC 3225) is therefore TTL bit 8, not
    # TTL bit 15, which is the top of Z.
    query = Query().add_edns(1232, version=2, flags=0x8000)
    parsed, _ = DnsPacket.parse(bytes(query))
    assert 2 == parsed.edns_version
    assert parsed.ad is True
    assert parsed.cd is False
    cd = Query().add_edns(1232, flags=0x4000)  # RFC 6955 section 4
    assert DnsPacket.parse(bytes(cd))[0].cd is True


def test_badvers_round_trips() -> None:
    # RFC 6891 section 6.1.3: a responder that dislikes our VERSION answers
    # RCODE=BADVERS (16) -- invisible in the 4-bit header, visible through
    # extended_rcode with the OPT the responder must include.
    response = Response(
        ID=1,
        QR=DnsQR.RESPONSE,
        RCODE=16,
        additional_records=[opt_wire(rcode=1)],
    )
    parsed, _ = DnsPacket.parse(bytes(response))
    assert 16 == parsed.extended_rcode
    # The wire form splits the effective code: the header carries only the
    # low nibble (RFC 6891 section 6.1.2 -- that is why 16 needs EDNS at
    # all); extended_rcode above is the value that survives reassembly.
    assert DnsResponseCode.NO_ERROR == parsed.RCODE
    assert 0 == parsed.edns_version


def test_an_extended_rcode_is_stamped_into_the_opt_that_carries_it() -> None:
    # The mirror of test_badvers_round_trips, where the OPT was stamped by hand.
    # Here nothing was: a packet holding the effective code in RCODE is what an
    # error assembled in memory looks like, and serialising it has to move the
    # upper eight bits into the OPT record -- otherwise only the header's low
    # nibble reaches the wire and RCODE 23 (EXPIRED) reads as 7 (FORMERR).
    response = Response(ID=1, QR=DnsQR.RESPONSE, RA=True, RCODE=23).add_edns(1232)
    parsed, _ = DnsPacket.parse(bytes(response))
    assert 23 == parsed.extended_rcode
    assert 7 == int(parsed.RCODE), "the header field keeps only the low nibble"
    assert 1232 == parsed.requestor_payload_size
    assert 0 == parsed.edns_version, "stamping must not disturb VERSION"


# --------------------------------------------------------------- cache safety


def test_opt_is_never_cached() -> None:
    # RFC 6891 section 6.2.1: "The OPT record MUST NOT be cached." _write_cache
    # stores answer and authority RRsets; OPT lives only in the additional
    # section, and a payload-size promise from one transaction must not be
    # served into the next (section 6.2.3 repeats the rule for the size).
    cache = MemoryDnsCache()
    sname = Sname(QNAME)
    query = Query(questions=[DnsQuestion(QNAME, DnsQType.A)])
    response = answer_for(query, additional=[opt_wire()])
    event = Answer(list(response.answers))
    _write_cache(cache, sname, event, response)
    stored = cache.get(QNAME, DnsQType.A, DnsRClass.IN)
    assert stored is not None
    assert all(int(r.rtype) != 41 for r in stored.records)


# ------------------------------------------------- section 7 fallback, live


async def start_query(resolver):
    """Begin a lookup; hand back the task, the query sent, and its future."""
    task = asyncio.get_running_loop().create_task(
        resolver.query([DnsQuestion(QNAME, DnsQType.A)], ns_record(), addr_record())
    )
    await asyncio.sleep(0)
    sent_query, future = next(iter(resolver.queue.values()))
    return task, sent_query, future


@pytest.mark.parametrize(
    ("rcode", "with_opt", "retries"),
    [
        # FORMERR with no OPT is section 7's signature of a non-EDNS server.
        (int(DnsResponseCode.FORMAT_ERROR), False, True),
        # FORMERR *with* OPT says "a problem with processing the OPT record
        # itself ... the response MUST include an OPT record" -- the server
        # speaks EDNS, so re-asking unextended would be nonsense.
        (int(DnsResponseCode.FORMAT_ERROR), True, False),
        # BADVERS rejects the VERSION, not the mechanism; unextended re-ask
        # is still section 6.2.2's only remedy.
        (16, True, True),
        # NOTIMP: not section 7's chosen signal, but what ossified
        # middleboxes answer; the retry costs one datagram.
        (int(DnsResponseCode.NOT_IMPLEMENTED), False, True),
        # SERVFAIL is nothing to do with EDNS.
        (int(DnsResponseCode.SERVER_FAILURE), False, False),
    ],
)
async def test_edns_rejection_triggers_exactly_the_documented_fallback(
    rcode, with_opt, retries
) -> None:
    resolver = make_resolver()
    task, first_query, future = await start_query(resolver)
    assert has_opt(first_query), "first attempt must advertise EDNS"

    additional = [opt_wire()] if with_opt else []
    future.set_result(answer_for(first_query, rcode=rcode, additional=additional))
    if retries:
        # The fallback re-arms a fresh future under the same pending key.
        for _ in range(10):
            await asyncio.sleep(0)
            if len(resolver.transport.sent) == 2:
                break
        second_query = sent_queries(resolver)[1]
        assert not has_opt(second_query), "the re-ask must be unextended"
        assert second_query.ID == first_query.ID  # same transaction identity
        future2 = resolver.queue[next(iter(resolver.queue))][1]
        future2.set_result(answer_for(second_query))
    result = await task
    assert (len(resolver.transport.sent) == 2) is retries
    assert result is not None


async def test_answer_on_the_first_attempt_sends_exactly_one_query() -> None:
    resolver = make_resolver()
    task, first_query, future = await start_query(resolver)
    future.set_result(answer_for(first_query))
    response = await task
    assert response is not None
    assert 1 == len(resolver.transport.sent)


async def test_edns_can_be_disabled_whole() -> None:
    # The constructor knob: an operator behind infrastructure that mishandles
    # OPT can return to the RFC 1035 section 4.2.1 regime explicitly.
    resolver = make_resolver(edns_payload_size=0)
    task, first_query, future = await start_query(resolver)
    assert not has_opt(first_query)
    future.set_result(answer_for(first_query))
    assert await task is not None


def test_recursive_resolver_plumbs_the_knob() -> None:
    assert 0 == RecursiveResolver(edns_payload_size=None).edns_payload_size
    assert 0 == RecursiveResolver(edns_payload_size=-5).edns_payload_size
    assert 4096 == RecursiveResolver(edns_payload_size=4096).edns_payload_size
