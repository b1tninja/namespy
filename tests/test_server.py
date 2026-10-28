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
* RFC 5452 section 5 (a client matches a reply on ID *and* the question section)
* RFC 5625 section 6.2 (rate-limit; cap concurrent upstream work)
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
from namespy.packet import DnsPacket, DnsQuestion, DnsRecord, Query, Response
from namespy.rdata import RData_A
from namespy.resolver import RecursiveResolver
from namespy.server import DnsServer

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
    # RFC 5452 section 5: ID alone is 16 bits of matching; the echoed question is
    # what lets a client reject a forged reply that happened to guess the ID.
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
