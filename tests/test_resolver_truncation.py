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

Truncation was the routine case while this library sent no EDNS(0): replies
were confined to 512 octets (RFC 1035 section 4.2.1) and a root ``.`` NS answer
carrying glue is already larger than that.  Outbound queries now advertise
EDNS(0), so the bit marks the servers that ignore EDNS, the middleboxes that
strip OPT, and answers genuinely larger than the advertised payload -- all
still reachable, none still the default.

These tests drive :meth:`Resolver.query` with a recording transport and a stubbed
:meth:`Resolver._query_tcp`, because what is under test is the decision between
the two transports rather than either transport itself.
"""

import asyncio
import ipaddress

import pytest

from namespy.cache import MemoryDnsCache
from namespy.enums import DnsQR, DnsQType, DnsRClass, DnsResponseCode, DnsRType
from namespy.names import DomainName
from namespy.packet import DnsQuestion, DnsRecord, Response
from namespy.resolver import Answer, Resolver, Sname, _write_cache

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


def answer_for(query, *, tc=False, rcode=0):
    """A well-formed answer to *query*, optionally with the TC bit set."""
    return Response(
        ID=query.ID,
        QR=DnsQR.RESPONSE,
        TC=tc,
        RCODE=rcode,
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
    # TcpStub replaces _query_tcp, whose contract is "the parsed Response that
    # TCP delivered" -- so the stand-in must be one, not a string marker.
    tcp_answer = Response(ID=0, QR=DnsQR.RESPONSE, RA=True)
    tcp = TcpStub(tcp_answer)
    resolver._query_tcp = tcp

    task, sent_query, future = await start_query(resolver)
    future.set_result(answer_for(sent_query, tc=True))

    assert await task is tcp_answer
    assert [host for host, _wire, _pkt in tcp.calls] == [NS_IP.exploded]


@pytest.mark.asyncio
async def test_tcp_retry_asks_the_same_question():
    """The retry must repeat the *same* query, not build a new one.

    A fresh transaction ID would be legal but wasteful; a fresh QNAME or QTYPE
    would quietly answer a different question than the one that was asked.
    """
    resolver = make_resolver()
    tcp = TcpStub(Response(ID=0, QR=DnsQR.RESPONSE, RA=True))
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
    tcp_answer = Response(ID=0, QR=DnsQR.RESPONSE, RA=True)
    tcp = TcpStub(tcp_answer)
    resolver._query_tcp = tcp

    task = asyncio.get_running_loop().create_task(
        resolver.query([DnsQuestion(QNAME, DnsQType.A)], ns_record(), addr_record())
    )
    await asyncio.sleep(0)

    assert await task is tcp_answer
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


# ------------------------------------------------- the attempt ceiling (RFC 9520 §3.1)


@pytest.mark.asyncio
async def test_silence_is_tried_once_per_transport_and_no_further():
    """RFC 9520 section 3.1: "A resolver MUST NOT retry a given query to a
    server address over a given DNS transport more than twice (i.e., three
    queries in total) before considering the server address unresponsive over
    that DNS transport for that query."

    Silence is what that ceiling exists for, and it is emphatically *not* what
    the two-attempt loop in :meth:`Resolver.query` was written for: the second
    pass through that loop is taken only when an answer actually said the OPT
    record was refused (RFC 6891 section 6.2.2's fallback), so a ``None`` result
    returns immediately rather than re-asking. What a server that never answers
    gets is one UDP datagram -- one retry, where the allowance is two -- plus
    the TCP attempt that :meth:`Resolver._await_udp` performs on timeout (RFC
    1035 section 4.2.2, RFC 1123 section 6.1.3.2), which §3.1 grants as a matter
    of course: "A resolver MAY retry a given query over a different DNS
    transport to the same server". Treating the address as unresponsive is the
    other half of the requirement, and it is why the failure cache is told about
    the zone rather than about this address.

    Nothing pinned this before: the tests either answered (one query, no
    ceiling reached) or refused EDNS (two queries, but a *spoken* refusal).
    """
    resolver = make_resolver()
    resolver.query_timeout = 0.01
    tcp = TcpStub(None)
    resolver._query_tcp = tcp

    response = await resolver.query([DnsQuestion(QNAME, DnsQType.A)], ns_record(), addr_record())

    assert response is None
    assert len(resolver.transport.sent) == 1, "silence must not buy a second UDP query"
    assert len(tcp.calls) == 1, "one UDP timeout is worth exactly one TCP attempt"


@pytest.mark.asyncio
async def test_edns_refusal_and_silence_do_not_combine_into_three_attempts():
    """The EDNS fallback and the timeout must not stack into a retry chain.

    A server that refuses OPT *and* then ignores the unextended re-ask is the
    worst case the send path can produce: the refusal spends the second UDP
    query, and that query's timeout spends the single TCP one. Two UDP queries
    to one address is still inside §3.1, because its ceiling is counted per
    transport ("more than twice ... over that DNS transport"), and section 2
    puts it plainly: "Nothing in this document prevents a resolver from retrying
    a query at a different server or the same server over a different DNS
    transport." What must not happen is a third UDP query or a second TCP one,
    and whichever attempt died, the pending slot has to be empty afterwards.
    """
    resolver = make_resolver()
    resolver.query_timeout = 0.01
    tcp = TcpStub(None)
    resolver._query_tcp = tcp

    task = asyncio.get_running_loop().create_task(
        resolver.query([DnsQuestion(QNAME, DnsQType.A)], ns_record(), addr_record())
    )
    await asyncio.sleep(0)
    first_query, future = next(iter(resolver.queue.values()))
    future.set_result(answer_for(first_query, rcode=int(DnsResponseCode.FORMAT_ERROR)))

    assert await task is None, "refusal then silence must end in nothing, not a retry chain"
    assert 2 == len(resolver.transport.sent), "one extended attempt, one unextended one"
    assert 1 == len(tcp.calls), "the unextended attempt's timeout is the only TCP attempt"
    assert resolver.queue == {}, "and no attempt may leave a pending slot behind"


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
