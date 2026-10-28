"""The datagram server: refusal paths, reply shape, and bounded egress.

``DnsServer`` is the only part of this library that listens, so these tests aim
at what an off-path sender can influence: a datagram that fails to parse must not
raise out of a protocol callback, a query that cannot be answered must be
*answered* (with an RCODE and the echoed question) rather than dropped, and the
number of upstream lookups triggered per inbound datagram must stay provably
below one.

The resolver is replaced with a stub for the refusal and reply-shape cases, and
driven through its real ``_send_for_entry`` seam for the one integration case, so
the server is not tested against a mock of itself.

.. rubric:: References

* RFC 1035 section 4.3 (server behaviour, including what to do with a bad query)
* RFC 5358 section 4 (BCP 140: an open recursion service must not be the default)
* RFC 5452 sections 4.2-4.3 and 9.1 (a client matches a reply on ID *and* the
  question section)
* RFC 5625 section 6.2 (do not listen where you do not control the clients) and
  section 6.3 (malformed traffic may be dropped); the bound on concurrent
  upstream work is a design decision, not a specification number
* RFC 6891 sections 6.1.1, 6.1.3, 6.2.4 and 7 (a response to an OPT query must
  carry an OPT of the responder's own; one OPT per message, and never a
  forwarded one; BADVERS for an unimplemented VERSION; no OPT for a requestor
  that did not ask)
"""

import asyncio
import ipaddress
import random

import pytest

from namespy.cache import MemoryDnsCache
from namespy.enums import (
    DnsOpCode,
    DnsQClass,
    DnsQR,
    DnsQType,
    DnsResponseCode,
    DnsRType,
)
from namespy.names import DomainName
from namespy.packet import OPT_RTYPE, DnsPacket, DnsQuestion, DnsRecord, Query, Response
from namespy.rdata import RData_A
from namespy.resolver import RecursiveResolver
from namespy.server import EDNS_VERSION_SUPPORTED, RESPONDER_PAYLOAD_SIZE, DnsServer

HOST = DomainName("www.example.com.")
HOST_IP = ipaddress.IPv4Address("93.184.216.34")
ADDR = ("127.0.0.1", 5353)


class FakeTransport:
    """Records what the server sends; exposes no socket, as a pipe transport would."""

    def __init__(self):
        self.sent = []

    def get_extra_info(self, name, default=None):
        return default

    def sendto(self, data, addr):
        self.sent.append((bytes(data), addr))

    @property
    def replies(self):
        return [DnsPacket.parse(data)[0] for data, _addr in self.sent]


def make_server(resolver=None, **kwargs):
    resolver = resolver if resolver is not None else RecursiveResolver(cache=MemoryDnsCache())
    server = DnsServer(resolver, **kwargs)
    transport = FakeTransport()
    server.connection_made(transport)
    return server, resolver, transport


def query_packet(name=HOST, qtype=DnsQType.A, packet_id=0xABCD):
    return Query(ID=packet_id, questions=[DnsQuestion(name, qtype, DnsQClass.IN)])


async def drain(server, timeout=1.0):
    """Await everything the server has spawned, so assertions see settled state."""
    tasks = list(server._tasks)
    if tasks:
        await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout)
    return tasks


def answered_response(packet):
    return Response(
        ID=packet.ID,
        QR=DnsQR.RESPONSE,
        RA=True,
        questions=list(packet.questions),
        answers=[
            DnsRecord(
                packet.questions[0].name,
                DnsRType.A,
                DnsQClass.IN,
                300,
                rdata=RData_A(HOST_IP),
            )
        ],
    )


# --------------------------------------------------------------- construction


def test_resolver_type_is_enforced():
    with pytest.raises(TypeError, match="RecursiveResolver"):
        DnsServer(object())


def test_connection_made_survives_a_transport_without_a_socket():
    """Path MTU discovery is Linux-only, so opening a transport must not need it."""
    server, _resolver, transport = make_server()
    assert server.transport is transport


def test_concurrency_floor_is_one():
    server, _resolver, _transport = make_server(max_concurrent_lookups=0)
    assert server.max_concurrent_lookups == 1


# ----------------------------------------------------------- inbound garbage


def test_truncated_datagram_replies_formerr_and_does_not_raise():
    """A parse failure escaping a protocol callback would kill the transport."""
    server, _resolver, transport = make_server()
    server.datagram_received(b"\x00\x01\x00", ADDR)

    assert transport.sent, "a malformed datagram must still get an answer"
    reply = transport.replies[0]
    assert reply.RCODE == DnsResponseCode.FORMAT_ERROR
    assert reply.QR == DnsQR.RESPONSE
    assert reply.QDCOUNT == 0, "nothing parsed, so there is nothing to echo"
    assert not server._tasks, "a datagram that never parsed must spawn no work"


def test_datagram_claiming_more_questions_than_it_has_is_refused():
    header = b"\x12\x34\x01\x00\x00\x05\x00\x00\x00\x00\x00\x00"
    server, _resolver, transport = make_server()
    server.datagram_received(header, ADDR)

    assert transport.replies[0].RCODE == DnsResponseCode.FORMAT_ERROR
    assert not server._tasks


def test_random_bytes_never_escape_as_an_exception():
    """Feed the callback directly: no octet sequence may raise out of it."""
    server, _resolver, _transport = make_server()
    rng = random.Random(20261027)
    for _ in range(400):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40)))
        server.datagram_received(blob, ADDR)


# ------------------------------------------------------------ refusal paths


async def test_incoming_response_is_ignored():
    server, _resolver, transport = make_server()
    packet = query_packet()
    packet.QR = DnsQR.RESPONSE

    await server.respond_to_packet(packet, ADDR)
    assert transport.sent == []


async def test_multiple_questions_are_refused_rather_than_partly_answered():
    """Answering one of N questions without saying which is worse than refusing."""
    server, _resolver, transport = make_server()
    packet = Query(
        ID=0x42,
        questions=[
            DnsQuestion(HOST, DnsQType.A, DnsQClass.IN),
            DnsQuestion(HOST, DnsQType.AAAA, DnsQClass.IN),
        ],
    )

    await server.respond_to_packet(packet, ADDR)
    reply = transport.replies[0]
    assert reply.RCODE == DnsResponseCode.FORMAT_ERROR
    assert reply.ID == 0x42
    assert reply.QDCOUNT == 2, "the question section must be echoed for matching"


async def test_unsupported_opcode_is_not_implemented_not_dropped():
    """RFC 2929 section 3.1: an unimplemented opcode gets NOTIMP, not silence."""
    server, _resolver, transport = make_server()
    packet = query_packet()
    packet.OPCODE = DnsOpCode.STATUS

    await server.respond_to_packet(packet, ADDR)
    assert transport.replies[0].RCODE == DnsResponseCode.NOT_IMPLEMENTED


async def test_resolution_failure_becomes_servfail():
    server, resolver, transport = make_server()

    async def no_answer(_packet):
        return None

    resolver.resolve = no_answer
    server.datagram_received(bytes(query_packet()), ADDR)
    await drain(server)

    assert transport.replies[0].RCODE == DnsResponseCode.SERVER_FAILURE


async def test_late_result_after_transport_change_stays_silent():
    server, resolver, transport = make_server()

    async def invalid_state(_packet):
        raise asyncio.InvalidStateError("transport closed mid-flight")

    resolver.resolve = invalid_state
    server.datagram_received(bytes(query_packet()), ADDR)
    await drain(server)

    assert transport.sent == []


# ---------------------------------------------------------------- happy path


async def test_answer_is_forwarded_with_the_query_id_and_question():
    server, resolver, transport = make_server()

    async def fake_resolve(packet):
        return answered_response(packet)

    resolver.resolve = fake_resolve
    server.datagram_received(bytes(query_packet()), ADDR)
    await drain(server)

    assert len(transport.sent) == 1
    data, addr = transport.sent[0]
    assert addr == ADDR
    reply = DnsPacket.parse(data)[0]
    assert reply.QR == DnsQR.RESPONSE
    assert reply.RA is True
    # RFC 5452 section 9.1: ID alone is 16 bits of matching; the echoed question
    # is what lets a client reject a forged reply that happened to guess the ID.
    assert reply.ID == 0xABCD
    assert reply.questions[0].name == HOST
    assert int(reply.questions[0].qtype) == int(DnsQType.A)
    assert bytes(reply.answers[0].rdata) == HOST_IP.packed


async def test_recursive_walk_result_is_relayed_end_to_end():
    """Drive the real resolver through its send seam, not a stub of resolve()."""
    resolver = RecursiveResolver(cache=MemoryDnsCache())
    server, _resolver, transport = make_server(resolver=resolver)

    async def authoritative(entry, questions):
        return Response(
            ID=0,
            QR=DnsQR.RESPONSE,
            AA=True,
            questions=list(questions),
            answers=[
                DnsRecord(questions[0].name, DnsRType.A, DnsQClass.IN, 60, rdata=RData_A(HOST_IP))
            ],
        )

    resolver._send_for_entry = authoritative
    server.datagram_received(bytes(query_packet()), ADDR)
    await drain(server)

    reply = transport.replies[0]
    assert reply.AA is True
    assert len(reply.answers) == 1
    # The trace lives on the resolver's response object, not on the wire: nothing
    # in RFC 1035 carries it, so the walk is observed on the resolver rather than
    # in the datagram that went out.
    assert resolver.last_trace is not None
    assert resolver.last_trace.events


# ------------------------------------------------------- EDNS(0) on the way out
#
# RFC 6891 section 6.1.1 obliges a responder to answer an OPT-bearing query
# with an OPT record of its own, section 7 forbids one for a query that had
# none, section 6.1.1 also says OPT "MUST NOT be cached, forwarded", section
# 6.1.1 demands FORMERR for a query carrying more than one, and section 6.1.3
# demands BADVERS for a VERSION the responder does not implement. Each of those
# sentences is a test below, plus the one case none of them covers: an extended
# RCODE that the client cannot be shown.


def opt_record(payload_size=1232, version=0, flags=0):
    """A bare OPT pseudo-record to stitch into a stub resolver's reply."""
    ttl = ((version & 0xFF) << 16) | (flags & 0xFFFF)
    return DnsRecord(DomainName("."), OPT_RTYPE, payload_size, ttl)


def stub_reply(packet, *, rcode=None, additional=()):
    """A relay-shaped answer, optionally carrying an upstream server's OPT."""
    return Response(
        ID=packet.ID,
        QR=DnsQR.RESPONSE,
        RA=True,
        RCODE=int(DnsResponseCode.NO_ERROR if rcode is None else rcode),
        questions=list(packet.questions),
        additional_records=list(additional),
    )


async def answer_with(resolver, reply_factory):
    async def stub(packet):
        return reply_factory(packet)

    resolver.resolve = stub


async def test_opt_in_the_query_buys_an_opt_of_our_own_in_the_reply() -> None:
    """Section 6.1.1's MUST, and the OPT is *ours*: 4096 was the client's
    number, the reply carries this host's reassembly limit (section 6.2.4)."""
    server, resolver, transport = make_server()
    await answer_with(resolver, stub_reply)

    query = query_packet().add_edns(4096)
    server.datagram_received(bytes(query), ADDR)
    await drain(server)

    reply = transport.replies[0]
    assert reply.opt() is not None, "an extended requestor must get an OPT back"
    assert RESPONDER_PAYLOAD_SIZE == reply.requestor_payload_size
    assert EDNS_VERSION_SUPPORTED == reply.edns_version
    assert 1 == sum(1 for r in reply.additional_records if int(r.rtype) == OPT_RTYPE)
    assert reply.questions[0].name == HOST  # the question is still first, section 6.1.1


async def test_unextended_query_is_answered_without_an_opt() -> None:
    """Section 7: no OPT in the request means the requestor "does not implement
    any part of this specification and ... the responder MUST NOT include an OPT
    record in its response"."""
    server, resolver, transport = make_server()
    await answer_with(resolver, stub_reply)

    server.datagram_received(bytes(query_packet()), ADDR)
    await drain(server)

    assert transport.replies[0].opt() is None


async def test_an_upstream_opt_is_never_forwarded_as_our_own() -> None:
    """The recursive walk hands back the authoritative server's message, OPT and
    all. Section 6.1.1: "OPT RRs MUST NOT be cached, forwarded" -- and its 512
    and its DO bit describe that server, not this one."""
    server, resolver, transport = make_server()
    upstream = opt_record(512, flags=0x8000)  # small stack, DO set
    await answer_with(resolver, lambda p: stub_reply(p, additional=[upstream]))

    server.datagram_received(bytes(query_packet().add_edns(1232)), ADDR)
    await drain(server)

    reply = transport.replies[0]
    assert RESPONDER_PAYLOAD_SIZE == reply.requestor_payload_size, "the 512 was theirs"
    assert not reply.ad, "a DO bit borrowed from an upstream answer claims nothing"
    assert 1 == sum(1 for r in reply.additional_records if int(r.rtype) == OPT_RTYPE)


async def test_a_query_with_two_opt_records_is_formerr_before_any_work() -> None:
    # Section 6.1.1: an OPT RR MUST be the only one in the message, and a query
    # with more than one MUST be answered FORMERR. Refused before the resolver
    # is consulted, so a hostile datagram cannot purchase a recursive walk.
    server, resolver, transport = make_server()
    looked_up = []

    async def stub(packet):
        looked_up.append(packet)
        return stub_reply(packet)

    resolver.resolve = stub

    # Both records go in through the constructor: `additional_records` hands
    # back a copy, so appending to it would emit octets ARCOUNT does not count.
    query = Query(
        ID=0xABCD,
        questions=[DnsQuestion(HOST, DnsQType.A, DnsQClass.IN)],
        additional_records=[opt_record(1232), opt_record(512)],
    )
    server.datagram_received(bytes(query), ADDR)
    await drain(server)

    reply = transport.replies[0]
    assert int(DnsResponseCode.FORMAT_ERROR) == int(reply.RCODE)
    assert [] == looked_up
    # The request was extended, so section 6.1.1's MUST still covers the error.
    assert reply.opt() is not None


async def test_an_unimplemented_edns_version_answers_badvers() -> None:
    # Section 6.1.3: a responder that does not implement the requested VERSION
    # MUST answer BADVERS, while the response OPT carries the highest level the
    # responder does implement -- which is the whole point of the exchange.
    server, resolver, transport = make_server()
    await answer_with(resolver, stub_reply)

    server.datagram_received(bytes(query_packet().add_edns(1232, version=1)), ADDR)
    await drain(server)

    reply = transport.replies[0]
    assert int(DnsResponseCode.BADVERS) == int(reply.extended_rcode)
    assert EDNS_VERSION_SUPPORTED == reply.edns_version
    assert 0 == int(reply.RCODE) & 0xF, "BADVERS is 16, so the header nibble stays clear"


async def test_an_extended_rcode_reaches_an_extended_client() -> None:
    # The upper eight bits only travel if the responder supplies the OPT that
    # holds them (section 6.1.3's EXTENDED-RCODE field).
    server, resolver, transport = make_server()
    await answer_with(resolver, lambda p: stub_reply(p, rcode=23))

    server.datagram_received(bytes(query_packet().add_edns(1232)), ADDR)
    await drain(server)

    assert 23 == int(transport.replies[0].extended_rcode)


async def test_an_extended_rcode_for_an_unextended_client_becomes_servfail() -> None:
    # No carrier, no message: section 7 forbids the OPT this client would need,
    # and masking 23 down to its low nibble would report FORMERR for an answer
    # that failed for an unrelated reason. SERVFAIL is the honest remainder.
    server, resolver, transport = make_server()
    await answer_with(resolver, lambda p: stub_reply(p, rcode=23, additional=[opt_record(4096)]))

    server.datagram_received(bytes(query_packet()), ADDR)
    await drain(server)

    reply = transport.replies[0]
    assert int(DnsResponseCode.SERVER_FAILURE) == int(reply.RCODE)
    assert reply.opt() is None


# ------------------------------------------------------- amplification defence


async def test_second_lookup_waits_for_a_slot():
    """Egress must be provably bounded relative to ingress.

    Two datagrams with a cap of one: only one upstream lookup may be in flight.
    That inequality is what stops the server being usable as an amplifier, so it
    is asserted rather than assumed.
    """
    server, resolver, transport = make_server(max_concurrent_lookups=1)
    gate = asyncio.Event()
    inflight = []

    async def slow(packet):
        inflight.append(1)
        await gate.wait()
        return answered_response(packet)

    resolver.resolve = slow
    server.datagram_received(bytes(query_packet()), ADDR)
    server.datagram_received(bytes(query_packet(packet_id=0x999)), ADDR)
    await asyncio.sleep(0.05)

    assert len(inflight) == 1, "a cap of one must not admit two"

    gate.set()
    await drain(server)
    assert len(inflight) == 2
    assert len(transport.sent) == 2


async def test_connection_lost_cancels_and_forgets_outstanding_work():
    server, resolver, _transport = make_server()

    async def hang(_packet):
        await asyncio.sleep(30)

    resolver.resolve = hang
    server.datagram_received(bytes(query_packet()), ADDR)
    tasks = list(server._tasks)
    assert len(tasks) == 1

    server.connection_lost(None)

    assert server._tasks == set(), "references must be dropped, not merely cancelled"
    # cancel() only marks the task; it unwinds when the loop next resumes it, so
    # the settled state has to be awaited rather than inspected immediately.
    results = await asyncio.gather(*tasks, return_exceptions=True)
    assert isinstance(results[0], asyncio.CancelledError)
