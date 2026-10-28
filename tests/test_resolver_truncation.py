"""Truncated UDP answers are retried over TCP, and are never cached.

RFC 1123 section 6.1.3.2 states one recommendation and one prohibition:

    If the Answer section of the response is truncated and if the requester
    supports TCP, it SHOULD try the query again using TCP.

    Truncated responses MUST NOT be saved (cached) and later used in such a way
    that the fact that they are truncated is lost.

RFC 1035 section 7.4 gives the reason for the prohibition: "When a response is
truncated, and a resolver doesn't know whether it has a complete set, it should
not cache a possibly partial set of RRs."  Once stored, a partial RRset is
indistinguishable from a complete one, so a single truncated answer would be
served to every later client as though it were the whole RRset.

Truncation is not a corner case for this library.  It does not yet advertise
EDNS(0), so replies are confined to 512 octets (RFC 1035 section 4.2.1) and a
root ``.`` NS answer carrying glue is already larger than that.

These tests drive :meth:`Resolver.query` with a recording transport and a stubbed
:meth:`Resolver._query_tcp`, because what is under test is the decision between
the two transports rather than either transport itself.
"""

import asyncio
import ipaddress

import pytest

from aiodns.cache import MemoryDnsCache
from aiodns.enums import DnsQR, DnsQType, DnsRClass, DnsRType
from aiodns.names import DomainName
from aiodns.packet import DnsQuestion, DnsRecord, Response
from aiodns.resolver import Answer, Resolver, Sname, _write_cache

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


def make_resolver():
    """A ``Resolver`` with just the attributes ``query`` needs to send UDP.

    ``Resolver`` declares its knobs as class attributes precisely so that it can
    be driven without a live transport, so no socket is opened here.
    """
    resolver = Resolver()
    resolver.transport = RecordingTransport()
    resolver.queue = {}
    return resolver


def ns_record():
    return DnsRecord(NS_NAME, DnsRType.NS, DnsRClass.IN, 0, rdata=NS_NAME)


def addr_record():
    return DnsRecord(NS_NAME, DnsRType.A, DnsRClass.IN, 0, rdata=NS_IP.packed)


def answer_for(query, *, tc=False):
    """A well-formed answer to *query*, optionally with the TC bit set."""
    return Response(
        ID=query.ID,
        QR=DnsQR.RESPONSE,
        TC=tc,
        RD=query.RD,
        RA=True,
        questions=list(query.questions),
        answers=[DnsRecord(QNAME, DnsRType.A, DnsRClass.IN, 300, rdata=ANSWER_IP.packed)],
    )


async def start_query(resolver):
    """Begin a lookup; hand back the task, the query sent, and its future."""
    task = asyncio.get_running_loop().create_task(
        resolver.query([DnsQuestion(QNAME, DnsQType.A)], ns_record(), addr_record())
    )
    await asyncio.sleep(0)
    sent_query, future = next(iter(resolver.queue.values()))
    return task, sent_query, future


class TcpStub:
    """Replaces ``_query_tcp``, recording calls and returning *result*."""

    def __init__(self, result):
        self.result = result
        self.calls = []

    async def __call__(self, host, wire, query_packet):
        self.calls.append((host, bytes(wire), query_packet))
        return self.result


# ------------------------------------------------------- transport failover


@pytest.mark.asyncio
async def test_truncated_udp_answer_is_retried_over_tcp():
    resolver = make_resolver()
    tcp = TcpStub("tcp-answer")
    resolver._query_tcp = tcp

    task, sent_query, future = await start_query(resolver)
    future.set_result(answer_for(sent_query, tc=True))

    assert await task == "tcp-answer"
    assert [host for host, _wire, _pkt in tcp.calls] == [NS_IP.exploded]


@pytest.mark.asyncio
async def test_tcp_retry_asks_the_same_question():
    """The retry must repeat the *same* query, not build a new one.

    A fresh transaction ID would be legal but wasteful; a fresh QNAME or QTYPE
    would quietly answer a different question than the one that was asked.
    """
    resolver = make_resolver()
    tcp = TcpStub("tcp-answer")
    resolver._query_tcp = tcp

    task, sent_query, future = await start_query(resolver)
    future.set_result(answer_for(sent_query, tc=True))
    await task

    _host, wire, query_packet = tcp.calls[0]
    assert len(wire) > 12, "TCP carries a length prefix plus the whole query"
    assert query_packet is sent_query
    assert query_packet.questions == sent_query.questions


@pytest.mark.asyncio
async def test_complete_udp_answer_does_not_touch_tcp():
    resolver = make_resolver()
    tcp = TcpStub("tcp-answer")
    resolver._query_tcp = tcp

    task, sent_query, future = await start_query(resolver)
    response = answer_for(sent_query, tc=False)
    future.set_result(response)

    assert await task is response
    assert tcp.calls == []


@pytest.mark.asyncio
async def test_truncated_answer_is_not_returned_when_tcp_fails():
    """Returning the partial answer would be worse than returning nothing.

    ``None`` makes the caller demote this nameserver and consult another; a
    truncated RRset would instead be taken for a complete answer and cached.
    """
    resolver = make_resolver()
    resolver._query_tcp = TcpStub(None)

    task, sent_query, future = await start_query(resolver)
    future.set_result(answer_for(sent_query, tc=True))

    assert await task is None


@pytest.mark.asyncio
async def test_udp_timeout_falls_back_to_tcp():
    resolver = make_resolver()
    resolver.query_timeout = 0.01
    tcp = TcpStub("tcp-answer")
    resolver._query_tcp = tcp

    task = asyncio.get_running_loop().create_task(
        resolver.query([DnsQuestion(QNAME, DnsQType.A)], ns_record(), addr_record())
    )
    await asyncio.sleep(0)

    assert await task == "tcp-answer"
    assert tcp.calls, "a UDP timeout must try TCP (RFC 1035 section 4.2.2)"


@pytest.mark.asyncio
async def test_timeout_releases_the_pending_slot():
    """A late datagram must neither fulfil an abandoned future nor leak the slot."""
    resolver = make_resolver()
    resolver.query_timeout = 0.01
    resolver._query_tcp = TcpStub(None)

    task = asyncio.get_running_loop().create_task(
        resolver.query([DnsQuestion(QNAME, DnsQType.A)], ns_record(), addr_record())
    )
    await asyncio.sleep(0)
    assert len(resolver.queue) == 1

    await task
    assert resolver.queue == {}


# ------------------------------------------------------------ cache hygiene


def sname():
    return Sname(QNAME, DnsQType.A, DnsRClass.IN)


def answer_records():
    return [DnsRecord(QNAME, DnsRType.A, DnsRClass.IN, 300, rdata=ANSWER_IP.packed)]


def stored(cache):
    return cache.get(QNAME, DnsQType.A, DnsRClass.IN)


def test_truncated_answer_is_not_cached():
    """RFC 1123 section 6.1.3.2: truncated responses MUST NOT be saved."""
    cache = MemoryDnsCache()
    response = Response(QR=DnsQR.RESPONSE, TC=True, answers=answer_records())

    _write_cache(cache, sname(), Answer(answer_records()), response)

    assert stored(cache) is None


def test_complete_answer_is_cached():
    """Control for the test above, so it cannot pass for the wrong reason."""
    cache = MemoryDnsCache()
    response = Response(QR=DnsQR.RESPONSE, TC=False, answers=answer_records())

    _write_cache(cache, sname(), Answer(answer_records()), response)

    hit = stored(cache)
    assert hit is not None
    assert len(hit.records) == 1


def test_truncated_tcp_answer_is_not_cached_either():
    """The guard is behind the transport, so it also covers TCP.

    RFC 7766 section 8 gives TCP a 65535-octet message field, which makes
    truncation unnecessary but not impossible from a misbehaving server.
    """
    cache = MemoryDnsCache()
    response = Response(
        QR=DnsQR.RESPONSE,
        TC=True,
        answers=answer_records(),
        additional_records=[],
    )

    _write_cache(cache, sname(), Answer(answer_records()), response)

    assert stored(cache) is None
