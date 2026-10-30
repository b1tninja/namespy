"""Asking with MQTYPE (RFC 10029): the option on the wire, and the answer in the cache.

``test_bundle.py`` pins how an answer is read. This file pins the parts that only exist
once the reading is wired into a resolver: the option leaving in a query, the walk
keeping it off the queries it does not belong to, a server that FORMERRs it, and the
cache entries a combined answer earns -- including the one it must never earn.

The seam is :meth:`Resolver.query`, stubbed where the walk is under test and left real
where the bytes are. ``test_resolver_truncation.py`` established the pattern: a
recording transport sees exactly what went out, which is the only way to test an EDNS
option that is invisible from the response side.

.. rubric:: References

* RFC 10029 section 3.1 (option 20 carries the QT list), section 3.2 (conforming
  requests), section 3.3 (what a server must refuse), section 3.4 (the response, and the
  rule that MQTYPE must not itself truncate), section 3.5 (the client's three readings,
  the FORMERR re-ask, and RFC 2181 section 5.4.1 ranking)
* RFC 6891 section 6.1.2 (unknown options ignored; an option lives in OPT and nowhere
  else), section 6.2.2 (the fallback to an unextended query), section 7 (FORMERR with an
  OPT for a bad option value, FORMERR without one for no EDNS at all)
* RFC 9156 section 3 step 2, for why a minimisation probe must not carry the list
* RFC 2308 section 5 and RFC 1123 section 6.1.3.2, the caching rules the harvested
  negatives are held to
"""

import asyncio
import ipaddress

import pytest

from namespy.bundle import BundledType, BundleResult, BundleState, collect_bundle
from namespy.cache import MemoryDnsCache, NegativeEntry, PositiveEntry
from namespy.edns import (
    MQTYPE_QUERY_OPTION_CODE,
    MQTYPE_RESPONSE_OPTION_CODE,
    EdnsOption,
)
from namespy.enums import DnsQR, DnsQType, DnsRClass, DnsResponseCode, DnsRType
from namespy.mqtype import mqtype_query_option, mqtype_response_option
from namespy.names import DomainName
from namespy.packet import OPT_RTYPE, DnsPacket, DnsQuestion, DnsRecord, Query, Response
from namespy.resolver import (
    Demote,
    Done,
    RecursiveResolver,
    Resolver,
    Sbelt,
    SendQuery,
    Slist,
    SlistEntry,
    Sname,
    resolve_steps,
)

ROOT = DomainName(".")
QNAME = DomainName("www.example.com.")
ZONE = DomainName("example.com.")
NS_NAME = DomainName("ns1.example.com.")
NS_IP = ipaddress.IPv4Address("192.0.2.53")
V4 = ipaddress.IPv4Address("93.184.216.34")
V6 = ipaddress.IPv6Address("2606:2800:220:1:248:1893:25c8:1946")

A = int(DnsQType.A)
AAAA = int(DnsQType.AAAA)
HTTPS = int(DnsQType.HTTPS)


def record(name, rtype, payload, ttl=300):
    return DnsRecord(name, rtype, DnsRClass.IN, ttl, rdata=payload)


def options_of(packet):
    """The EDNS options of a packet that came off the wire as bytes."""
    return packet.edns_options()


class RecordingTransport:
    """Keeps every datagram, so an EDNS option can be inspected as it left."""

    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append(bytes(data))


def bare_resolver(**kwargs):
    """A ``Resolver`` able to send UDP without a socket, plus its recording transport.

    ``Resolver`` declares its knobs as class attributes precisely so it can be driven
    like this (see ``test_resolver_truncation.py``); the overrides are the constructor
    arguments a real ``RecursiveResolver`` would have passed.
    """
    resolver = Resolver()
    resolver.transport = RecordingTransport()
    resolver.queue = {}
    for name, value in kwargs.items():
        setattr(resolver, name, value)
    return resolver


def ns_record():
    return DnsRecord(ZONE, DnsRType.NS, DnsRClass.IN, 0, rdata=NS_NAME)


def addr_record():
    return DnsRecord(NS_NAME, DnsRType.A, DnsRClass.IN, 0, rdata=NS_IP.packed)


# ------------------------------------------------------------------- the option on the wire


def parse_sent(packet_bytes):
    """Read a captured datagram back as the packet the resolver sent."""
    return DnsPacket.parse(packet_bytes)[0]


def sent_option(packet_bytes):
    """The MQTYPE-Query payload of a captured datagram, or ``None``."""
    options = parse_sent(packet_bytes).edns_options()
    return next((o.data for o in options if o.code == MQTYPE_QUERY_OPTION_CODE), None)


async def test_the_query_asks_for_the_types_it_was_given():
    """Section 3.1: OPTION-CODE 20, OPTION-DATA "a list of 2-octet values in network
    order". The option has to be in the bytes that leave, or nothing below this line
    means anything."""
    resolver = bare_resolver()
    task = asyncio.create_task(
        resolver.query(
            [DnsQuestion(QNAME, DnsQType.A)],
            ns_record(),
            addr_record(),
            extra_edns_options=(mqtype_query_option([AAAA, HTTPS], primary_qtype=A),),
        )
    )
    await asyncio.sleep(0)
    sent_query, future = next(iter(resolver.queue.values()))
    assert sent_option(resolver.transport.sent[0]) == bytes([0x00, 0x1C, 0x00, 0x41])
    assert sent_query.opt() is not None, "an option with no OPT to live in is no option"
    future.set_result(Response(ID=sent_query.ID, QR=DnsQR.RESPONSE, questions=[]))
    await task


async def settle(task, transport, expected_sends=2):
    """Let the query task run until it has re-sent, or finished, or clearly will not."""
    for _ in range(50):
        await asyncio.sleep(0)
        if task.done() or len(transport.sent) >= expected_sends:
            return


def formerr(*, with_opt):
    """A FORMERR, with and without an OPT -- RFC 6891 section 7's two different answers,
    which mean two different things and get two different remedies."""
    response = Response(ID=0, QR=DnsQR.RESPONSE, RCODE=DnsResponseCode.FORMAT_ERROR, questions=[])
    if with_opt:
        response.add_edns(1232)
    return response


async def bundled_query(resolver, *qtypes):
    """Start a query for A carrying a MQTYPE-Query for ``qtypes``, and hand back the task
    with the packet and future the resolver parked."""
    task = asyncio.create_task(
        resolver.query(
            [DnsQuestion(QNAME, DnsQType.A)],
            ns_record(),
            addr_record(),
            extra_edns_options=(mqtype_query_option(list(qtypes), primary_qtype=A),),
        )
    )
    await asyncio.sleep(0)
    return task, next(iter(resolver.queue.values()))


async def test_a_formerr_with_an_opt_loses_the_option_not_edns():
    """Section 3.5: "or if the server generates a FORMERR response, the client MUST issue
    additional standalone queries (that is, without using the MQTYPE-Query option)".

    The two FORMERRs are not interchangeable and this is where they part. A FORMERR that
    carries an OPT is section 7's complaint about the *contents* of the OPT, and the only
    thing this resolver puts in one beyond the record itself is the QT list -- so the
    option goes and EDNS stays, keeping the advertised payload size. Answering a
    complaint about one option by abandoning the whole mechanism is the wrong remedy, and
    the demotion a walk would otherwise reach for is worse: it turns a server that
    dislikes an extension into a name that does not resolve.
    """
    resolver = bare_resolver()
    task, (sent_query, future) = await bundled_query(resolver, AAAA)
    first = formerr(with_opt=True)
    first.ID = sent_query.ID
    future.set_result(first)
    await settle(task, resolver.transport)

    assert len(resolver.transport.sent) == 2, "it asked again"
    again = resolver.transport.sent[1]
    assert sent_option(again) is None, "and asked again without the option"
    assert parse_sent(again).opt() is not None, "but not without EDNS"

    _second_query, second_future = next(iter(resolver.queue.values()))
    second_future.set_result(Response(ID=sent_query.ID, QR=DnsQR.RESPONSE, questions=[]))
    assert await task is not None


async def test_a_formerr_without_an_opt_loses_edns_entirely():
    """The other FORMERR, kept straight: RFC 6891 section 7 says a non-EDNS responder
    "MUST respond with a return code (RCODE) of FORMERR to messages containing an OPT
    record ... and MUST NOT include an OPT record in the response". That is a refusal of
    the mechanism rather than of the QT list, so the remedy is section 6.2.2's unextended
    re-ask, which drops the option along with the OPT -- and it is why these two retries
    can never both be spent on one query."""
    resolver = bare_resolver()
    task, (sent_query, future) = await bundled_query(resolver, AAAA)
    first = formerr(with_opt=False)
    first.ID = sent_query.ID
    future.set_result(first)
    await settle(task, resolver.transport)

    again = resolver.transport.sent[1]
    assert parse_sent(again).opt() is None, "no OPT at all on the re-ask"
    assert sent_option(again) is None

    _second_query, second_future = next(iter(resolver.queue.values()))
    second_future.set_result(Response(ID=sent_query.ID, QR=DnsQR.RESPONSE, questions=[]))
    await task


async def test_an_answer_that_is_not_a_refusal_buys_no_retries():
    """The retries are for refusals. A NOERROR, a SERVFAIL, or a silence gets the one
    query the resolver has always sent: an optional extension must not add traffic to the
    ordinary path, and a spare attempt would be a second chance at a server that never
    objected to anything."""
    resolver = bare_resolver()
    task, (_sent_query, future) = await bundled_query(resolver, AAAA)
    future.set_result(Response(ID=0, QR=DnsQR.RESPONSE, questions=[]))
    await task
    assert len(resolver.transport.sent) == 1


async def test_no_edns_means_no_option_rather_than_a_loose_one():
    """An EDNS option is OPT RDATA (RFC 6891 section 6.1.2), so ``--no-edns`` has to take
    the bundle with it. Sending a QT list with no OPT would mean inventing a carrier for
    it; instead the query goes out exactly as it would have before the extension existed,
    and the bundle is reported unsupported, which is the truth."""
    resolver = bare_resolver(edns_payload_size=0)
    task, (_sent_query, future) = await bundled_query(resolver, AAAA)
    assert resolver.transport.sent, "the query still goes out"
    assert parse_sent(resolver.transport.sent[0]).opt() is None
    assert sent_option(resolver.transport.sent[0]) is None
    future.set_result(Response(ID=0, QR=DnsQR.RESPONSE, questions=[]))
    await task


# --------------------------------------------------- which queries in a walk carry it


def _root_seeded(sname):
    slist = Slist(sname)
    slist.zone = ROOT
    slist.match = 0
    slist.entries = [SlistEntry(ROOT, NS_NAME, [NS_IP])]
    return slist


def _run(gen, canned):
    """Drive a resolve_steps generator over canned replies, returning every event.

    The pattern is ``test_qname_min.py``'s: a SendQuery pauses the generator at
    ``send(response = ...)``, so the next resume must be the canned reply and never
    ``next()``, which would hand the loop ``None`` as a response.
    """
    events = [next(gen)]
    for response in canned:
        while not isinstance(events[-1], SendQuery):
            events.append(next(gen))
        events.append(gen.send(response))
    while True:
        try:
            events.append(next(gen))
        except StopIteration:
            return events


def _aa_answer(question_name, qtype=DnsQType.A):
    return Response(
        QR=DnsQR.RESPONSE,
        AA=True,
        questions=[DnsQuestion(question_name, qtype)],
        answers=[record(question_name, int(qtype), V4.packed)],
    )


def _referral(question_name, new_zone):
    return Response(
        QR=DnsQR.RESPONSE,
        AA=False,
        questions=[DnsQuestion(question_name, DnsQType.A)],
        nameservers=[DnsRecord(new_zone, DnsRType.NS, DnsRClass.IN, 0, rdata=NS_NAME)],
        additional_records=[DnsRecord(NS_NAME, DnsRType.A, DnsRClass.IN, 0, rdata=NS_IP.packed)],
    )


def test_the_real_question_carries_the_bundle():
    """The point of the exercise: the query for the caller's QNAME asks for the extras
    alongside it, so one descent answers for all of them."""
    sname = Sname(QNAME, DnsQType.A)
    events = _run(
        resolve_steps(sname, _root_seeded(sname), extra_qtypes=(AAAA, HTTPS)),
        [_aa_answer(QNAME)],
    )
    sent = [event for event in events if isinstance(event, SendQuery)]
    assert len(sent) == 1
    assert sent[0].extra_qtypes == (AAAA, HTTPS)


def test_an_ordinary_lookup_carries_nothing():
    """The default has to be the query this library has always sent. Every hop of an
    unbundled walk -- root, TLD, zone -- must go out clean, or the extension has become
    something that happens to everybody rather than something asked for."""
    sname = Sname(QNAME, DnsQType.A)
    events = _run(
        resolve_steps(sname, _root_seeded(sname)),
        [_referral(QNAME, ZONE), _aa_answer(QNAME)],
    )
    sent = [event for event in events if isinstance(event, SendQuery)]
    assert len(sent) == 2, "the referral and then the answer"
    assert all(event.extra_qtypes == () for event in sent)


def test_a_minimisation_probe_never_carries_it():
    """RFC 9156 section 3 step 2 makes a probe a query for a shorter *child* name.
    Bundling the extras into one would have a server combine RRsets for a name nobody
    asked about, and the harvest would then attribute them to the caller's QNAME."""
    sname = Sname(QNAME, DnsQType.A)
    events = _run(
        resolve_steps(sname, _root_seeded(sname), qname_min=True, extra_qtypes=(AAAA, HTTPS)),
        [
            _referral(DomainName("com"), DomainName("com")),
            _referral(DomainName("example.com"), ZONE),
            _aa_answer(QNAME),
        ],
    )
    sent = [event for event in events if isinstance(event, SendQuery)]
    probes = [event for event in sent if event.probe]
    assert probes, "the minimiser did probe"
    assert all(event.extra_qtypes == () for event in probes)
    real = [event for event in sent if not event.probe]
    assert real, "the walk reached the real question"
    assert all(event.extra_qtypes == (AAAA, HTTPS) for event in real)


# ------------------------------------------------------------- the bundle in a real lookup


class ZoneStub:
    """Answers from one authoritative server and remembers how each query asked.

    Stubs :meth:`Resolver.query` rather than the driver's ``_send_for_entry`` seam so
    that the option-building stays on the path under test: what this records is the QT
    list the walk decided to send with each question, which is the half only the walk
    controls.
    """

    def __init__(self, replies):
        self.replies = replies
        self.asked = []

    async def __call__(
        self, questions, nameserver_record, address_record, *, extra_edns_options=(), **kwargs
    ):
        question = questions[0]
        payload = next(
            (
                option.data
                for option in tuple(extra_edns_options)
                if option.code == MQTYPE_QUERY_OPTION_CODE
            ),
            None,
        )
        self.asked.append((int(question.qtype), payload))
        build = self.replies.get(int(question.qtype))
        return build(question) if build is not None else None


def bundled(question, *, answers=(), options=(), aa=True, soa=None, rcode=0):
    response = Response(
        QR=DnsQR.RESPONSE,
        AA=aa,
        RCODE=rcode,
        questions=[DnsQuestion(question.name, question.qtype, question.qclass)],
        answers=list(answers),
        nameservers=[soa] if soa is not None else [],
    )
    if options:
        response.add_edns(1232, options=list(options))
    return response


def zone(replies, failure_cache=None):
    """A resolver whose entire world is one authoritative server and one name."""
    cache = MemoryDnsCache()
    resolver = RecursiveResolver(cache=cache, failure_cache=failure_cache)
    resolver.sbelt = Sbelt.from_response(
        Response(
            QR=DnsQR.RESPONSE,
            nameservers=[DnsRecord(ROOT, DnsRType.NS, DnsRClass.IN, 0, rdata=NS_NAME)],
            additional_records=[
                DnsRecord(NS_NAME, DnsRType.A, DnsRClass.IN, 0, rdata=NS_IP.packed)
            ],
        )
    )
    stub = ZoneStub(replies)
    resolver.query = stub
    return resolver, stub, cache


def ask(*qtypes, ask_separately=True):
    return {
        "dns_packet": Query(questions=[DnsQuestion(QNAME, DnsQType.A)], RD=True),
        "extra_qtypes": list(qtypes),
        "ask_separately": ask_separately,
    }


ALL_THREE = {
    A: lambda q: bundled(
        q,
        answers=[
            record(QNAME, A, V4.packed),
            record(QNAME, AAAA, V6.packed),
            record(QNAME, HTTPS, b"\x00\x00\x00\x01"),
        ],
        options=[mqtype_response_option([AAAA, HTTPS])],
    )
}


async def test_one_walk_answers_what_used_to_take_three():
    """The roadmap row this round exists to close: with a server that combines, A, AAAA
    and HTTPS are settled by a single descent, and no second or third query leaves the
    building."""
    resolver, stub, _cache = zone(ALL_THREE)
    result = await resolver.resolve_bundle(**ask(AAAA, HTTPS))
    assert len(stub.asked) == 1, "one exchange, not three"
    assert stub.asked[0][1] == bytes([0x00, 0x1C, 0x00, 0x41]), "AAAA then HTTPS"
    assert result.supported is True
    assert result.combined == (AAAA, HTTPS)
    assert result.still_needed == ()
    assert result.state_of(AAAA) is BundleState.COMBINED
    assert [bytes(r.rdata) for r in result.records_for(HTTPS)] == [b"\x00\x00\x00\x01"]


async def test_what_arrives_in_the_shadow_of_an_answer_is_cached():
    """RFC 2181 section 5.4.1, cited by section 3.5: an authoritative answer received this
    way ranks the same as the primary's -- so it is cached, under the type it answers, and
    a later lookup for AAAA alone never touches the network. The name it is cached at is
    the one the walk ended at, which is where the records live."""
    resolver, _stub, cache = zone(ALL_THREE)
    await resolver.resolve_bundle(**ask(AAAA, HTTPS))
    entry = cache.get(QNAME, AAAA, DnsRClass.IN)
    assert isinstance(entry, PositiveEntry)
    assert entry.authoritative is True
    assert [int(r.rtype) for r in entry.records] == [AAAA]
    assert cache.get(QNAME, HTTPS, DnsRClass.IN) is not None


async def test_a_partial_bundle_is_finished_off_without_the_option():
    """Section 3.4 lets a server combine some types and omit the rest -- a size limit, a
    flag mismatch, plain unwillingness. What it does not do is answer for the omitted
    type, so the resolver owes it a query: section 3.5 asks for standalone ones, "(that
    is, without using the MQTYPE-Query option)". Watch the payload on the second call."""
    resolver, stub, _cache = zone(
        {
            A: lambda q: bundled(
                q,
                answers=[record(QNAME, A, V4.packed), record(QNAME, AAAA, V6.packed)],
                options=[mqtype_response_option([AAAA])],
            ),
            HTTPS: lambda q: bundled(q, answers=[record(QNAME, HTTPS, b"\x00\x00\x00\x01")]),
        }
    )
    result = await resolver.resolve_bundle(**ask(AAAA, HTTPS))
    assert result.combined == (AAAA,)
    assert result.state_of(AAAA) is BundleState.COMBINED
    assert result.state_of(HTTPS) is BundleState.COMBINED, "finished by the re-ask"
    assert result.still_needed == ()
    assert stub.asked[0] == (A, bytes([0x00, 0x1C, 0x00, 0x41]))
    assert stub.asked[1] == (HTTPS, None), "the re-ask carries no MQTYPE-Query"


async def test_a_server_that_has_never_heard_of_it_costs_what_it_always_costed():
    """The common case in the field, and the one that must not regress: no MQTYPE-Response
    means the primary answer is fine and every extra type still needs its own walk. Three
    questions in total, exactly as before the extension existed, plus a result that says
    which of them bought nothing."""
    resolver, stub, _cache = zone(
        {
            A: lambda q: bundled(q, answers=[record(QNAME, A, V4.packed)]),
            AAAA: lambda q: bundled(q, answers=[record(QNAME, AAAA, V6.packed)]),
            HTTPS: lambda q: bundled(q, answers=[record(QNAME, HTTPS, b"\x00\x00\x00\x01")]),
        }
    )
    result = await resolver.resolve_bundle(**ask(AAAA, HTTPS))
    assert result.supported is False
    assert result.void is False, "ignorance is not a protocol violation"
    assert result.primary is not None, "the answer the primary got still stands"
    assert [qtype for qtype, _payload in stub.asked] == [A, AAAA, HTTPS]
    assert all(payload is None for _q, payload in stub.asked[1:])


async def test_declining_to_finish_can_be_left_to_the_caller():
    """``ask_separately=False`` is the difference between being told to follow section 3.5
    and doing it: the work list comes back intact and the network stays quiet until
    somebody decides those types are wanted."""
    resolver, stub, _cache = zone({A: lambda q: bundled(q, answers=[record(QNAME, A, V4.packed)])})
    result = await resolver.resolve_bundle(**ask(AAAA, HTTPS, ask_separately=False))
    assert len(stub.asked) == 1
    assert result.still_needed == (AAAA, HTTPS)
    assert result.state_of(AAAA) is BundleState.NEEDED


# ---------------------------------------------------------------- what must not be cached


async def test_an_unlisted_type_is_not_cached_as_a_negative():
    """The one mistake this design exists to prevent, at the layer where it would do the
    damage. AAAA went unlisted -- four innocent reasons, none of them about the name --
    and a resolver that cached that silence as NODATA would hide the RRset for the length
    of the zone's MINIMUM while believing it had proof."""
    resolver, _stub, cache = zone(
        {
            A: lambda q: bundled(
                q,
                answers=[record(QNAME, A, V4.packed)],
                options=[mqtype_response_option([HTTPS])],
                soa=record(ZONE, DnsRType.SOA, b"", ttl=60),
            )
        }
    )
    result = await resolver.resolve_bundle(**ask(AAAA, HTTPS, ask_separately=False))
    assert result.state_of(AAAA) is BundleState.NEEDED
    assert cache.get(QNAME, AAAA, DnsRClass.IN) is None, "silence is not a verdict"
    assert isinstance(cache.get(QNAME, HTTPS, DnsRClass.IN), NegativeEntry)


async def test_an_authoritative_nodata_from_a_bundle_is_cached_like_any_other():
    """Listed, NOERROR, nothing in the Answer section, AA set: section 3.4 only lets a QTx
    be listed after its flags matched the primary's, so this is a real NODATA, and RFC
    2308 section 5's TTL rule applies to it the same way it does to one the resolver asked
    for by name."""
    resolver, _stub, cache = zone(
        {
            A: lambda q: bundled(
                q,
                answers=[record(QNAME, A, V4.packed)],
                options=[mqtype_response_option([AAAA])],
                soa=record(ZONE, DnsRType.SOA, b"", ttl=60),
            )
        }
    )
    await resolver.resolve_bundle(**ask(AAAA, ask_separately=False))
    entry = cache.get(QNAME, AAAA, DnsRClass.IN)
    assert isinstance(entry, NegativeEntry)
    assert int(entry.rcode) == int(DnsResponseCode.NO_ERROR)


async def test_a_negative_from_an_answer_that_claimed_no_authority_is_not_cached():
    """Ranking extras the same as the primary cuts both ways: a primary that is not
    authoritative cannot lend authority to a type it merely travelled with, and RFC 2308
    section 5 has no room for a negative nobody vouched for."""
    resolver, _stub, cache = zone(
        {
            A: lambda q: bundled(
                q,
                answers=[record(QNAME, A, V4.packed)],
                options=[mqtype_response_option([AAAA])],
                aa=False,
                soa=record(ZONE, DnsRType.SOA, b"", ttl=60),
            )
        }
    )
    await resolver.resolve_bundle(**ask(AAAA, ask_separately=False))
    assert cache.get(QNAME, AAAA, DnsRClass.IN) is None


# --------------------------------------------------------------------- when it goes wrong


def contradictory_response_option():
    """A MQTYPE-Response listing the same QTx twice.

    Built from octets rather than from :func:`~namespy.mqtype.mqtype_response_option`,
    which refuses to: this module's own send path will not produce a list its clients are
    told to discard. Only somebody else's server does, so that is what has to be forged
    here -- and the fact that the honest constructor cannot express it is the reason the
    reading layer still has to cope with it.
    """
    return EdnsOption(MQTYPE_RESPONSE_OPTION_CODE, bytes([0x00, 0x1C, 0x00, 0x1C]))


def doubled_response_options():
    """The other invalid shape: the option itself, twice."""
    single = bytes([0x00, 0x1C])
    return [
        EdnsOption(MQTYPE_RESPONSE_OPTION_CODE, single),
        EdnsOption(MQTYPE_RESPONSE_OPTION_CODE, single),
    ]


async def test_an_invalid_answer_is_discarded_before_it_reaches_the_cache():
    """Section 3.5's third reading, and the one with a trap in the implementation rather
    than in the reading: "the client MUST treat the answer as invalid (equivalent to
    FORMERR)".

    Equivalent to a FORMERR, so the walk treats it as one -- demote this server, ask
    another -- and the response is never classified, never used, and above all never
    cached. A discard performed *after* the cache write would be the most convincing kind
    of fake: the next lookup for this name would be answered from the cache by the very
    response this one was thrown away for, and the test that only checked the returned
    object would pass.

    With one server and no second opinion, the honest outcome is no primary answer at
    all. And because a zone this lookup watched fail is remembered as a failure (RFC 9520
    section 3.2), the extras' own queries are suppressed rather than sent into the same
    wall -- so the result says every type is still needed, which is the truth, and the
    network stays quiet. ``test_the_extras_are_asked_when_the_failure_cache_lets_them_be``
    is the same lookup with that cache switched off, showing the suppression is the cache
    and not a shortcut in the bundling code.
    """
    resolver, stub, cache = zone(
        {
            A: lambda q: bundled(
                q,
                answers=[record(QNAME, A, V4.packed)],
                options=doubled_response_options(),
            ),
            AAAA: lambda q: bundled(q, answers=[record(QNAME, AAAA, V6.packed)]),
            HTTPS: lambda q: bundled(q, answers=[record(QNAME, HTTPS, b"\x00\x00\x00\x01")]),
        }
    )
    result = await resolver.resolve_bundle(**ask(AAAA, HTTPS))
    assert cache.get(QNAME, A, DnsRClass.IN) is None, "discarded, so not remembered"
    assert result.primary is None, "and not quietly reused from somewhere else"
    assert result.supported is False
    assert len(stub.asked) == 1, "the one query that was, and then the suppression"
    assert result.still_needed == (AAAA, HTTPS)
    assert result.state_of(AAAA) is BundleState.NEEDED, "unfinished, and admitted"


async def test_the_extras_are_asked_when_the_failure_cache_lets_them_be():
    """The same broken server with ``failure_cache=False``: nothing now stops the
    re-asks, and each is a standalone query without the option -- which is what section
    3.5 asked for, and what the server answers perfectly well, because its defect was in
    the MQTYPE-Response and in nothing else.

    Worth having beside the test above because the pair says where each rule lives: the
    discarding is RFC 10029's, the silence is RFC 9520's, and neither is the bundling code
    quietly giving up on the types it was asked about.
    """
    resolver, stub, cache = zone(
        {
            A: lambda q: bundled(
                q,
                answers=[record(QNAME, A, V4.packed)],
                options=doubled_response_options(),
            ),
            AAAA: lambda q: bundled(q, answers=[record(QNAME, AAAA, V6.packed)]),
            HTTPS: lambda q: bundled(q, answers=[record(QNAME, HTTPS, b"\x00\x00\x00\x01")]),
        },
        failure_cache=False,
    )
    result = await resolver.resolve_bundle(**ask(AAAA, HTTPS))
    assert [qtype for qtype, _payload in stub.asked] == [A, AAAA, HTTPS]
    assert stub.asked[0][1] is not None, "the first asked with the option"
    assert all(payload is None for _q, payload in stub.asked[1:]), "nothing after it did"
    assert result.primary is None
    assert cache.get(QNAME, A, DnsRClass.IN) is None, "the discarded answer left nothing"
    assert result.state_of(AAAA) is BundleState.COMBINED, "the re-ask answered it"
    assert result.still_needed == ()


def test_the_neighbour_of_a_server_that_contradicts_itself_gets_asked():
    """The remedy worth having: another server of the same zone, asked the same question.
    This is a referral-shaped walk driven directly, because the rule now lives in the
    resolution loop rather than in the layer above it -- which is the only place it can
    run before the cache write."""
    sname = Sname(QNAME, DnsQType.A)
    slist = Slist(sname)
    slist.zone = ROOT
    slist.match = 0
    slist.entries = [
        SlistEntry(ROOT, DomainName("ns-broken.example."), [ipaddress.IPv4Address("192.0.2.1")]),
        SlistEntry(ROOT, DomainName("ns-good.example."), [ipaddress.IPv4Address("192.0.2.2")]),
    ]
    question = DnsQuestion(QNAME, DnsQType.A)
    broken = bundled(
        question,
        answers=[record(QNAME, A, V4.packed)],
        options=[contradictory_response_option()],
    )
    good = bundled(question, answers=[record(QNAME, A, ipaddress.IPv4Address("192.0.2.99").packed)])

    events = _run(resolve_steps(sname, slist, extra_qtypes=(AAAA,)), [broken, good])

    demotions = [event for event in events if isinstance(event, Demote)]
    assert [event.reason for event in demotions] == ["invalid MQTYPE-Response"]
    done = [event for event in events if isinstance(event, Done)]
    assert bytes(done[0].response.answers[0].rdata) == ipaddress.IPv4Address("192.0.2.99").packed


async def test_a_question_a_server_must_refuse_to_combine_is_not_asked():
    """Section 3.3 makes "An MQTYPE-Query option in a query where the primary question is
    a non-data RRTYPE (e.g., ANY, AXFR)" a FORMERR, and section 3.2 obliges a client not to
    build one. The refusal belongs at the caller's boundary -- by the time the walk notices
    it, the honest options are to send a broken query or to quietly ignore the request,
    and neither is good."""
    resolver, stub, _cache = zone({})
    packet = Query(questions=[DnsQuestion(QNAME, DnsQType.ANY)], RD=True)
    with pytest.raises(ValueError, match="not a data RRTYPE"):
        await resolver.resolve_bundle(packet, [AAAA])
    assert stub.asked == [], "refused before a byte left"


async def test_a_bundle_behind_a_duplicate_of_itself_is_refused():
    """Asking for AAAA behind a AAAA question duplicates the primary QTYPE -- the last of
    section 3.3's eight, and the one that is a pure waste of an exchange."""
    resolver, stub, _cache = zone({})
    with pytest.raises(ValueError, match="duplicates the primary"):
        await resolver.resolve_bundle(
            Query(questions=[DnsQuestion(QNAME, DnsQType.AAAA)], RD=True), [AAAA]
        )
    assert stub.asked == []


async def test_a_truncated_answer_caches_no_part_of_a_bundle():
    """RFC 1123 section 6.1.3.2: "Truncated responses MUST NOT be saved (cached)". A
    combination is where that rule matters most, because section 3.4 lets the server stop
    adding types the moment the answer grows too large -- an omitted RRset and a truncated
    one look identical once stored. The transport retries TCP and never hands back a TC
    answer, so this is the second line of defence, driven directly."""
    resolver, _stub, cache = zone({})
    answer = bundled(
        DnsQuestion(QNAME, DnsQType.A),
        answers=[record(QNAME, A, V4.packed), record(QNAME, AAAA, V6.packed)],
        options=[mqtype_response_option([AAAA])],
    )
    answer.TC = True
    bundle = collect_bundle(answer, primary_qtype=A, requested=(AAAA,), terminal_name=QNAME)
    assert bundle.state_of(AAAA) is BundleState.COMBINED, "readable, and still not storable"
    resolver._cache_bundle(answer, Sname(QNAME, DnsQType.A), bundle)
    assert cache.get(QNAME, AAAA, DnsRClass.IN) is None


async def test_the_trace_shows_the_walk_that_did_the_bundling():
    """The re-asks each build their own trace, and ``last_trace`` is what ``--trace``
    prints. Leaving it pointing at whichever standalone query finished last would show an
    operator the wrong descent for the lookup they asked about."""
    resolver, _stub, _cache = zone(
        {
            A: lambda q: bundled(q, answers=[record(QNAME, A, V4.packed)]),
            AAAA: lambda q: bundled(q, answers=[record(QNAME, AAAA, V6.packed)]),
        }
    )
    await resolver.resolve_bundle(**ask(AAAA, ask_separately=True))
    assert int(resolver.last_trace.sname.qtype) == A, "the primary's walk, not the re-ask's"


async def test_a_negative_without_a_proof_of_the_name_is_not_cached():
    """RFC 2308 section 5 again, from the other end: an authoritative NODATA still needs the
    zone SOA to say for how long. No SOA, no TTL, nothing to store -- and inventing a
    default is how a negative outlives the zone that denied it."""
    resolver, _stub, cache = zone(
        {
            A: lambda q: bundled(
                q,
                answers=[record(QNAME, A, V4.packed)],
                options=[mqtype_response_option([AAAA])],
            )
        }
    )
    await resolver.resolve_bundle(**ask(AAAA, ask_separately=False))
    assert cache.get(QNAME, AAAA, DnsRClass.IN) is None


async def test_a_zero_ttl_rrset_from_a_bundle_is_not_cached():
    """TTL zero means "do not keep this", and it means that of a harvested RRset as much as
    of one the resolver asked for by name. A bundle is a way of travelling, not a licence to
    outlive what the records said."""
    resolver, _stub, cache = zone(
        {
            A: lambda q: bundled(
                q,
                answers=[record(QNAME, A, V4.packed), record(QNAME, AAAA, V6.packed, ttl=0)],
                options=[mqtype_response_option([AAAA])],
            )
        }
    )
    result = await resolver.resolve_bundle(**ask(AAAA, ask_separately=False))
    assert result.state_of(AAAA) is BundleState.COMBINED, "the answer stands"
    assert cache.get(QNAME, AAAA, DnsRClass.IN) is None, "the storage does not"


async def test_an_opt_record_is_never_part_of_an_answer_being_cached():
    """RFC 6891 section 6.2.1: "The OPT record MUST NOT be cached, and MUST NOT be treated
    as a normal RRset while caching". OPT cannot be a QTx -- it is a Meta-RR, so section 3.3
    keeps it out of the list -- which makes this filter unreachable through the protocol and
    reachable only by a caller driving the cache write by hand. Kept for exactly that, and
    exercised the way :func:`_write_cache`'s copy of the rule is."""
    resolver, _stub, cache = zone({})
    opt = DnsRecord(DomainName("."), OPT_RTYPE, 0, 0, rdata=b"")
    bundle = BundleResult(
        supported=True,
        combined=(AAAA,),
        types=(BundledType(AAAA, BundleState.COMBINED, records=(opt,), authoritative=True),),
    )
    resolver._cache_bundle(
        bundled(DnsQuestion(QNAME, DnsQType.A)), Sname(QNAME, DnsQType.A), bundle
    )
    assert cache.get(QNAME, AAAA, DnsRClass.IN) is None


async def test_no_extras_is_an_ordinary_lookup_with_a_report_attached():
    """Called with an empty list, resolve_bundle must be resolve() -- not resolve() with a
    pile of NODATA verdicts for types nobody requested bolted on."""
    resolver, stub, cache = zone({A: lambda q: bundled(q, answers=[record(QNAME, A, V4.packed)])})
    result = await resolver.resolve_bundle(
        Query(questions=[DnsQuestion(QNAME, DnsQType.A)], RD=True), []
    )
    assert len(stub.asked) == 1
    assert result.supported is False
    assert result.types == ()
    assert result.still_needed == ()
    assert result.primary is not None
    assert cache.get(QNAME, A, DnsRClass.IN) is not None


async def test_the_standalone_re_asks_report_their_own_outcomes():
    """A type finished by its own query gets the same vocabulary as one finished by the
    bundle. Otherwise a caller could not tell "asked separately, does not exist" from
    "nobody ever asked" -- the same distinction section 3.5 insists on, one level up."""
    resolver, _stub, _cache = zone(
        {
            A: lambda q: bundled(q, answers=[record(QNAME, A, V4.packed)]),
            AAAA: lambda q: bundled(q, soa=record(ZONE, DnsRType.SOA, b"", ttl=60)),
            HTTPS: lambda q: bundled(
                q,
                soa=record(ZONE, DnsRType.SOA, b"", ttl=60),
                rcode=DnsResponseCode.NAME_ERROR,
            ),
        }
    )
    result = await resolver.resolve_bundle(**ask(AAAA, HTTPS))
    assert result.state_of(AAAA) is BundleState.NODATA
    assert result.state_of(HTTPS) is BundleState.NXDOMAIN
    assert result.still_needed == ()
    assert all(entry.answered for entry in result.types)
