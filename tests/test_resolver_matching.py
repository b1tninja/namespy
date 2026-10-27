"""Response matching: which datagram is allowed to answer which question.

A resolver's cache is only as trustworthy as the check that ties a response to
the query it answers. RFC 5452 sections 5-6 is the normative text: a client must
validate the transaction ID *and* the question section, because the ID is only 16
bits and is otherwise the sole in-band discriminator. Keying on
``(server, ID)`` -- which is what this code used to do -- means any host that can
send a UDP datagram to our source port with a guessed ID can install an answer,
and RFC 1034 section 5.3.3's walk then follows wherever that answer points.

These tests drive :meth:`Resolver.datagram_received` with real serialized bytes
rather than hand-built packets, so the parser, the question echo and the matcher
are exercised together.

.. rubric:: References

* RFC 1034 section 5.3.3 (the delegations a poisoned answer can steer)
* RFC 1035 section 4.1, 4.1.1 (a response must carry the question section)
* RFC 5452 sections 5, 6 (validate ID and question before accepting)
"""

import asyncio
import ipaddress

import pytest

from aiodns.cache import MemoryDnsCache
from aiodns.names import DomainName
from aiodns.packet import DnsQuestion, DnsRecord, Query, Response
from aiodns.rdata import RData_A
from aiodns.resolver import RecursiveResolver, _is_expected_response, _pending_key

SERVER = ipaddress.IPv4Address("198.51.100.53")
SERVER_V6 = ipaddress.IPv6Address("2001:db8::53")
EVIL = ipaddress.IPv4Address("203.0.113.66")
QNAME = DomainName("www.example.com.")
OTHER = DomainName("evil.example.net.")
ANSWER_IP = ipaddress.IPv4Address("93.184.216.34")
BOGUS_IP = ipaddress.IPv4Address("203.0.113.99")

A_T, IN = 1, 1


def _query(name=QNAME, qtype=A_T, qid=0x1234):
    return Query(questions=[DnsQuestion(name, qtype, IN)], ID=qid, RD=False)


def _response(query, ip=ANSWER_IP, qid=None, name=None, include_question=True):
    """A response to *query*, echoing its question section by default."""
    return Response(
        ID=query.ID if qid is None else qid,
        QR=1,
        AA=True,
        questions=list(query.questions) if include_question else [],
        answers=[DnsRecord(name or QNAME, A_T, IN, 300, rdata=RData_A(ip))],
    )


@pytest.fixture
def resolver():
    return RecursiveResolver(cache=MemoryDnsCache())


def _register(resolver, query, queue=None):
    """Put a pending future in the queue exactly as ``query()`` would.

    Called from async tests only: a future needs a running loop to bind to, and
    nothing here awaits the future -- the assertions inspect ``done()`` and
    ``result()`` directly, since ``datagram_received`` fills it synchronously.
    """
    future = asyncio.get_running_loop().create_future()
    queue = resolver.queue if queue is None else queue
    server = SERVER_V6 if queue is resolver.queue_v6 else SERVER
    queue[_pending_key(server, query)] = (query, future)
    return future


# ------------------------------------------------------------------ key shape


def test_key_includes_the_question():
    """Two queries with the same ID but different names must not share a key."""
    first, second = _query(qid=0xABCD), _query(name=OTHER, qid=0xABCD)
    assert _pending_key(SERVER, first) != _pending_key(SERVER, second)


def test_key_is_case_insensitive_like_name_comparison():
    """A server that echoes the QNAME in different casing is still answering us."""
    upper = _query(name=DomainName("WWW.EXAMPLE.COM."))
    assert _pending_key(SERVER, upper) == _pending_key(SERVER, _query())


def test_missing_question_section_is_not_an_anonymous_key():
    """A question-less packet keys on ``None`` and so can never match a query."""
    bare = Response(ID=0x1234, QR=1, questions=[])
    assert _pending_key(SERVER, bare)[2:] == (None, None, None)
    assert _pending_key(SERVER, bare) != _pending_key(SERVER, _query())


def test_is_expected_response_rejects_a_query_bit():
    """A request that happens to reuse our ID is not an answer to it."""
    query = _query()
    impostor = Query(questions=list(query.questions), ID=query.ID)
    assert not _is_expected_response(query, impostor, SERVER)


# ------------------------------------------------------------- datagram paths


async def test_legitimate_response_completes_the_future(resolver):
    query = _query()
    future = _register(resolver, query)
    resolver.datagram_received(bytes(_response(query)), (SERVER.exploded, 53))
    assert future.done()
    assert future.result().answers[0].rdata.ip == ANSWER_IP
    assert resolver.queue == {}, "the slot must be consumed, not left to leak"


async def test_forged_response_with_wrong_qname_is_dropped(resolver):
    """The core defence: right ID, right server, wrong name must not be credited.

    The payload is well-formed and carries an answer, so a parser-level check
    would accept it. Only the question comparison catches it.
    """
    query = _query()
    future = _register(resolver, query)

    forged = _response(_query(name=OTHER), ip=BOGUS_IP, qid=query.ID)
    assert int(forged.ID) == int(query.ID), "a forgery must share the ID to tempt"
    resolver.datagram_received(bytes(forged), (SERVER.exploded, 53))

    assert not future.done()
    assert resolver.queue != {}, "the real query is still pending"


async def test_forged_response_from_another_source_is_dropped(resolver):
    """Right ID and question, but from a server we never asked."""
    query = _query()
    future = _register(resolver, query)
    resolver.datagram_received(bytes(_response(query)), (EVIL.exploded, 53))
    assert not future.done()
    assert resolver.queue != {}


async def test_response_without_question_section_is_dropped(resolver):
    """RFC 1035 section 4.1 requires the echo; without it nothing identifies us."""
    query = _query()
    future = _register(resolver, query)
    wire = bytes(_response(query, include_question=False))
    resolver.datagram_received(wire, (SERVER.exploded, 53))
    assert not future.done()


def test_unsolicited_response_is_ignored(resolver):
    """A response to a question nobody asked must not raise in the callback."""
    resolver.datagram_received(bytes(_response(_query())), (SERVER.exploded, 53))
    assert resolver.queue == {}


def test_malformed_datagram_does_not_raise(resolver):
    """A protocol callback that raises takes the transport down with it."""
    resolver.datagram_received(b"\x12\x34\x81\x80\x00\x01", (SERVER.exploded, 53))
    assert resolver.queue == {}


async def test_duplicate_response_delivers_once(resolver):
    """The second copy of an answer finds no slot and must not touch the future."""
    query = _query()
    future = _register(resolver, query)
    wire = bytes(_response(query))
    resolver.datagram_received(wire, (SERVER.exploded, 53))
    resolver.datagram_received(wire, (SERVER.exploded, 53))
    assert future.done()


async def test_v6_path_applies_the_same_rules(resolver):
    """The IPv6 shim used to match on ``(host, ID)`` alone; it must not drift."""
    query = _query()
    future = _register(resolver, query, resolver.queue_v6)

    forged = _response(_query(name=OTHER), ip=BOGUS_IP, qid=query.ID)
    resolver._datagram_received_v6(bytes(forged), (SERVER_V6.exploded, 53, 0, 0))
    assert not future.done()

    resolver._datagram_received_v6(bytes(_response(query)), (SERVER_V6.exploded, 53, 0, 0))
    assert future.done()


def test_exploded_and_compressed_v6_forms_are_the_same_key():
    """A regression guard for a bug that made every IPv6 answer miss.

    The send side formats its destination with ``.exploded``; the receive side
    sees whatever the OS reports, which Python renders compressed. Keying on raw
    text meant ``2001:db8:0:0:0:0:0:53`` never equalled ``2001:db8::53``, so an
    IPv6 query sat until it timed out no matter how promptly the answer arrived.
    """
    query = _query()
    assert str(SERVER_V6) != SERVER_V6.exploded, "the two forms must differ to matter"
    assert _pending_key(SERVER_V6, query) == _pending_key(SERVER_V6.exploded, query)


async def test_v6_answer_arriving_in_compressed_form_is_matched(resolver):
    """The realistic shape: registered exploded (as ``query()`` does), answered compressed."""
    query = _query()
    future = _register(resolver, query, resolver.queue_v6)
    resolver.queue_v6.clear()
    resolver.queue_v6[_pending_key(SERVER_V6.exploded, query)] = (query, future)

    resolver._datagram_received_v6(bytes(_response(query)), (str(SERVER_V6), 53, 0, 0))
    assert future.done(), "a differently-spelled but identical address must still match"


def test_generated_ids_are_well_spread():
    """``DnsPacket`` picks a fresh 16-bit ID per message, not a counter.

    RFC 5452 section 5 counts on the identifier being hard to guess, and the
    constructor takes it from :func:`secrets.randbits`. Birthday maths means a
    few hundred draws must collide occasionally, so the bar here is "spread over
    the space", not "all distinct".
    """
    ids = {int(Query(questions=[DnsQuestion(QNAME, A_T, IN)]).ID) for _ in range(256)}
    assert len(ids) > 200, "identifier clustering this bad would narrow a forgery"
