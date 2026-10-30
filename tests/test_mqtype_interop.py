"""The asker and the responder, on one wire.

Every test in :mod:`tests.test_resolver_mqtype` hands the client a response this project
wrote by hand, and every test in :mod:`tests.test_server` asks the server a question this
project wrote by hand. Neither suite proves the two agree: the QT list the client composes
is read back by the library that wrote it, and the combined Answer section the server
composes is parsed by the library that composed it. A byte-level disagreement between the
halves -- a QTx encoded in the wrong order, or an owner name the harvest's ownership rule
refuses -- would leave both suites green while every bundled lookup quietly fell back to
re-asking, which looks like correct behaviour from the outside and costs the whole point of
the extension.

So these tests put the real client and the real responder either side of a real datagram:
the client's own encoder writes the bytes, the server parses them and combines, and
``collect_bundle`` reads what comes back. Only the socket is missing, and that replacement
is deliberate rather than incidental -- see :class:`_Loopback` for what the client still has
to get right.

.. rubric:: References

* RFC 10029 section 3.2 (what the client owes the server on the way out), section 3.4 (what
  the server owes it on the way back) and section 3.5 (what the client concludes in between)
* RFC 5452 section 9.1 (a client matches a reply on the peer address, the ID *and* the
  question -- which the loopback still enforces, because it replaces the wire and not the
  checking)
"""

import asyncio
import ipaddress

from namespy.bundle import BundleState
from namespy.cache import MemoryDnsCache
from namespy.enums import DnsQClass, DnsQR, DnsQType, DnsRClass, DnsResponseCode, DnsRType
from namespy.names import DomainName
from namespy.packet import DnsQuestion, DnsRecord, Query, Response
from namespy.rdata import RData_A, RData_AAAA
from namespy.resolver import RecursiveResolver, Sbelt
from namespy.server import DnsServer

ROOT = DomainName(".")
QNAME = DomainName("www.example.com.")
NS_NAME = DomainName("ns.example.net.")
SERVER_IP = ipaddress.IPv4Address("127.0.0.53")
PEER = (SERVER_IP.exploded, 53)
CLIENT_ADDR = ("127.0.0.1", 5353)

A = int(DnsQType.A)
AAAA = int(DnsQType.AAAA)
HTTPS = int(DnsQType.HTTPS)

V4 = ipaddress.IPv4Address("93.184.216.34")
V6 = ipaddress.IPv6Address("2606:2800:220:1:248:1893:25c8:1946")
HTTPS_RDATA = b"\x00\x01\x00\x00\x01\x00\x03\x02h2"


def record(name, rtype, payload, ttl=300):
    return DnsRecord(name, rtype, DnsRClass.IN, ttl, rdata=payload)


class _ServerTransport:
    """Records what the server sends; exposes no socket, as a pipe transport would."""

    def __init__(self):
        self.sent = []

    def get_extra_info(self, name, default=None):
        return default

    def sendto(self, data, addr):
        self.sent.append((bytes(data), addr))


class _Loopback:
    """The client's UDP socket, replaced by a queue and a callback.

    Only the datagram is simulated. The client still encodes its own query, still registers
    it under the RFC 5452 section 9.1 key of peer address, ID and question, and still
    discards a reply that does not reproduce all three -- which is why the pump hands the
    bytes to ``Resolver.datagram_received`` under ``PEER``, the address the query went to,
    rather than under any plausible-looking tuple.
    """

    def __init__(self, outbox):
        self._outbox = outbox

    def get_extra_info(self, name, default=None):
        return default

    def sendto(self, data, addr):
        self._outbox.put_nowait(bytes(data))


def inner_reply(packet, *, rtype, payload):
    """What the server's own resolver would hand back for one question."""
    return Response(
        ID=packet.ID,
        QR=DnsQR.RESPONSE,
        AA=True,
        RA=True,
        questions=list(packet.questions),
        answers=[record(packet.questions[0].name, rtype, payload)],
    )


def upstream(replies, asked):
    """A stand-in for the server's recursive walk: one answer per QTYPE, no network.

    The substitution is narrow on purpose. These tests are about two EDNS options crossing
    one exchange; how the server found each RRset is what :mod:`tests.test_server` and
    :mod:`tests.test_resolve_steps` already hold.
    """

    async def resolve(packet):
        question = packet.questions[0]
        asked.append(int(question.qtype))
        build = replies.get(int(question.qtype))
        if build is None:
            return Response(
                ID=packet.ID,
                QR=DnsQR.RESPONSE,
                RA=True,
                RCODE=int(DnsResponseCode.SERVER_FAILURE),
                questions=list(packet.questions),
            )
        return build(packet)

    return resolve


def _seeded(cache):
    """A client whose entire world is the in-process server, addressed as the root."""
    client = RecursiveResolver(cache=cache)
    client.sbelt = Sbelt.from_response(
        Response(
            QR=DnsQR.RESPONSE,
            nameservers=[record(ROOT, DnsRType.NS, NS_NAME)],
            additional_records=[record(NS_NAME, DnsRType.A, SERVER_IP.packed)],
        )
    )
    return client


async def _pump(outbox, server, server_transport, client):
    """Carry every datagram the client sends into the server, and every reply back."""
    delivered = 0
    while True:
        data = await outbox.get()
        server.datagram_received(data, CLIENT_ADDR)
        while server._tasks:
            await asyncio.gather(*list(server._tasks), return_exceptions=True)
        while delivered < len(server_transport.sent):
            reply, _addr = server_transport.sent[delivered]
            delivered += 1
            client.datagram_received(reply, PEER)


def pair(replies, *, max_qtypes=None):
    """A client and a responder wired together, with the server's upstream stubbed.

    ``max_qtypes`` is not passed through when unset, and that is not an oversight: to
    :class:`~namespy.server.DnsServer` the value ``None`` means *unbounded*, while leaving it
    out means the §4 guideline of four. Forwarding ``None`` would quietly test a server
    configured to do more work than any default deployment does.
    """
    server_resolver = RecursiveResolver(cache=MemoryDnsCache())
    asked = []
    server_resolver.resolve = upstream(replies, asked)
    server = (
        DnsServer(server_resolver)
        if max_qtypes is None
        else DnsServer(server_resolver, max_qtypes=max_qtypes)
    )
    server_transport = _ServerTransport()
    server.connection_made(server_transport)
    return _seeded(MemoryDnsCache()), server, server_transport, asked


async def bundled_lookup(client, server, server_transport, extras, **kwargs):
    """Run one client lookup with the loopback running beside it."""
    outbox = asyncio.Queue()
    client.transport = _Loopback(outbox)
    client.queue = {}
    pump = asyncio.ensure_future(_pump(outbox, server, server_transport, client))
    packet = Query(questions=[DnsQuestion(QNAME, DnsQType.A, DnsQClass.IN)], RD=True)
    try:
        return await asyncio.wait_for(client.resolve_bundle(packet, extras, **kwargs), timeout=5.0)
    finally:
        pump.cancel()


ANSWERS = {
    A: lambda p: inner_reply(p, rtype=A, payload=RData_A(V4)),
    AAAA: lambda p: inner_reply(p, rtype=AAAA, payload=RData_AAAA(V6)),
    HTTPS: lambda p: inner_reply(p, rtype=HTTPS, payload=HTTPS_RDATA),
}


async def test_one_exchange_answers_all_three_types_over_a_real_wire():
    """The claim the feature rests on, in bytes rather than in objects.

    Everything the assertion looks at was produced by the code under test: the client
    encoded the MQTYPE-Query itself, the server parsed those bytes, combined, and encoded a
    MQTYPE-Response that the client then parsed. Had either half drifted on the QT list's
    encoding, the extras would come back :data:`~namespy.bundle.BundleState.NEEDED` and be
    re-asked -- a failure a caller could easily never notice, which is exactly why it is
    asserted here rather than inferred from the suites either side of it.
    """
    client, server, transport, asked = pair(ANSWERS)
    result = await bundled_lookup(client, server, transport, (AAAA, HTTPS))

    assert result.void is False
    assert result.supported is True, "the responder's option, read by the asker"
    assert result.still_needed == ()
    assert [entry.state for entry in result.types] == [
        BundleState.COMBINED,
        BundleState.COMBINED,
    ]
    assert asked[:1] == [A], "one primary lookup; the extras travelled with it"
    assert len(transport.sent) == 1, "one datagram back, which is the entire point"


async def test_each_combined_record_arrives_under_the_type_that_asked_for_it():
    """The harvest's ownership rule, applied to bytes the server chose rather than to
    records this test placed on a plate.

    :func:`~namespy.bundle.collect_bundle` filters the Answer section by type and by owner
    name, and the server is the one that assembled that section -- deciding which records to
    copy, in which order, and under whose name (RFC 10029 section 3.4 obliges it to
    deduplicate and to keep each RR in the section it would have appeared in). An owner name
    the server wrote differently from the one the client resolves against would make the
    harvest refuse a record that is plainly there, and the client would report NODATA for a
    type the server had just answered.
    """
    client, server, transport, _asked = pair(ANSWERS)
    result = await bundled_lookup(client, server, transport, (AAAA, HTTPS))

    primary = result.primary
    assert primary is not None
    assert sorted(int(r.rtype) for r in primary.answers) == sorted([A, AAAA, HTTPS])
    assert [int(r.rtype) for r in result.records_for(AAAA)] == [AAAA]
    assert [int(r.rtype) for r in result.records_for(HTTPS)] == [HTTPS]
    assert all(r.name == QNAME for r in result.records_for(AAAA)), "owned by the name asked"
    assert result.types[0].separate is False, "combined on the wire, and known to be"


async def test_a_server_that_combines_nothing_leaves_the_asking_to_the_client():
    """``max_qtypes=0`` across a real wire: support signalled, nothing folded in, and the
    whole of RFC 10029 section 3.5 carried out on bytes.

    The server answers the option with an empty list, which section 3.4 explicitly allows
    and section 3.5 obliges the client to read as "this much work was declined" rather than
    as any answer about the names. The client must therefore re-ask each type -- and the
    re-asks are what this test is really about: they go out over the same loopback, to the
    same responder, and have to come back as the right records under the right types.
    """
    client, server, transport, asked = pair(ANSWERS, max_qtypes=0)
    result = await bundled_lookup(client, server, transport, (AAAA, HTTPS))

    assert result.supported is True, "an empty list is support, not silence"
    assert [int(r.rtype) for r in result.primary.answers] == [A]
    assert result.still_needed == ()
    assert [entry.state for entry in result.types] == [
        BundleState.COMBINED,
        BundleState.COMBINED,
    ]
    assert all(entry.separate for entry in result.types), "fetched, not folded in"
    assert asked == [A, AAAA, HTTPS], "one bundled lookup and two standalone ones"
    assert len(transport.sent) == 3


async def test_a_partly_finished_bundle_finishes_over_the_same_wire():
    """The mixed case, which is the common one wherever an operator has put a limit in
    place: RFC 10029 section 3.4 lets the server stop combining when it runs out of
    allowance, and section 3.5 sends the client after whatever is left.

    Worth its own test rather than being folded into the two either side of it, because the
    result is a single bundle whose types have two different provenances. A client that
    treated the whole exchange as re-asked would query twice for AAAA; one that treated it
    as combined would never ask for HTTPS at all, and would report a name with an HTTPS
    record as though it had none.
    """
    client, server, transport, asked = pair(ANSWERS, max_qtypes=1)
    result = await bundled_lookup(client, server, transport, (AAAA, HTTPS))

    assert result.supported is True
    folded, fetched = result.types
    assert (folded.state, folded.separate) == (BundleState.COMBINED, False)
    assert (fetched.state, fetched.separate) == (BundleState.COMBINED, True)
    assert [int(r.rtype) for r in fetched.records] == [HTTPS]
    assert result.still_needed == (), "the work list is empty once the work is done"
    assert asked == [A, AAAA, HTTPS]
    assert len(transport.sent) == 2, "AAAA was not asked for twice"
