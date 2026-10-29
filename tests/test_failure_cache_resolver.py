"""RFC 9520 negative caching, wired into the resolution loop.

``test_failure_cache.py`` exercises the cache on its own; these drive
``resolve_steps`` so the two halves are proved to meet. What is asserted is never
"the cache contains X" for its own sake but the two things an operator actually
gets: a failure a lookup hit is recorded in the *shape* RFC 9520 asks for, and a
remembered failure stops the *next* lookup before it reaches the network.

Spec anchors, quoted or paraphrased closely:

* RFC 9520 3.2: "When an incoming query matches a cached resolution failure, the
  resolver MUST NOT send any corresponding outgoing queries until after the cache
  entries expire."
* RFC 9520 3.3: a zone whose name servers are not answering is remembered as a
  zone, because "the resolver MUST limit queries to the non-responsive zone's
  parent zone" -- for the *next* lookup, which will be for a different name.
* RFC 9520 2.1/2.2: what counts as a failure is "no response" and a response code
  saying the server could not do its job; a server that answered properly is not
  a failure at all, and must not leave a dead-zone entry behind.
* RFC 9520 2.5: alias loops are among the failures worth remembering.
"""

import ipaddress

from namespy.cache import (
    FAILURE_INITIAL_TTL_S,
    FAILURE_MAX_TTL_S,
    FailureCache,
)
from namespy.enums import DnsQR, DnsQType, DnsRClass, DnsResponseCode, DnsRType
from namespy.names import DomainName
from namespy.packet import DnsQuestion, DnsRecord, Response
from namespy.resolver import (
    Done,
    Fail,
    RecursiveResolver,
    SendQuery,
    Slist,
    SlistEntry,
    Sname,
    resolve_steps,
)

ROOT_NS = DomainName("a.root-servers.net")
ROOT_IP = ipaddress.IPv4Address("198.41.0.4")
DEAD_ZONE = DomainName("dead.example")
DEAD_NS = DomainName("ns1.dead.example")
DEAD_IP = ipaddress.IPv4Address("198.51.100.1")
DEAD_NS2 = DomainName("ns2.dead.example")
DEAD_IP2 = ipaddress.IPv4Address("198.51.100.2")


def _seed_slist(sname, zone, entries, match=None):
    """A server list that starts at *zone*, skipping the walk down to it.

    Every test here is about what happens at one zone, and seeding the list
    directly keeps a test about a dead ``dead.example`` from depending on how the
    root happens to be configured.
    """
    slist = Slist(sname)
    slist.zone = zone
    slist.match = sname.match_count(zone) if match is None else match
    slist.entries = [SlistEntry(zone, ns, [addr]) for ns, addr in entries]
    return slist


def _response(qname, *, aa=True, rcode=DnsResponseCode.NO_ERROR, answers=(), nameservers=()):
    return Response(
        QR=DnsQR.RESPONSE,
        AA=aa,
        RCODE=rcode,
        questions=[DnsQuestion(qname, DnsQType.A)],
        answers=list(answers),
        nameservers=list(nameservers),
    )


def _answer_for(qname, addr):
    return _response(
        qname, answers=[DnsRecord(qname, DnsRType.A, DnsRClass.IN, 0, rdata=addr.packed)]
    )


def _cname_at(qname, target):
    return _response(
        qname, answers=[DnsRecord(qname, DnsRType.CNAME, DnsRClass.IN, 300, rdata=target)]
    )


def _drive(gen, responses):
    """Run *gen* to its terminal event, answering queries from *responses*.

    The last response repeats, which is how a one-server zone that never answers
    or a name that aliases forever is expressed: the same reply to every query.
    """
    events = []
    step = next(gen)
    index = 0
    while True:
        events.append(step)
        if isinstance(step, (Done, Fail)):
            return events
        reply = responses[min(index, len(responses) - 1)]
        if isinstance(step, SendQuery):
            index += 1
        step = gen.send(reply)


def _kinds(events):
    return [type(e).__name__ for e in events]


# ------------------------------------------------------- what gets recorded


def test_a_zone_that_never_answers_is_remembered_as_a_zone():
    """RFC 9520 3.3: the zone is the failure, not the name that happened to ask.

    A per-name entry here would satisfy the assertion "a failure was cached" and
    fail the requirement: the next query is for a different name in the same dead
    zone, and only a zone key stops that one too.
    """
    failures = FailureCache()
    sname = Sname(DomainName("a.dead.example"), DnsQType.A)
    slist = _seed_slist(sname, DEAD_ZONE, [(DEAD_NS, DEAD_IP)])

    events = _drive(resolve_steps(sname, slist, failures=failures), [None])

    assert _kinds(events) == ["SendQuery", "Demote", "Fail"]
    assert events[-1].reason == "no servers"
    entry = failures.lookup_zone(DEAD_ZONE)
    assert entry is not None
    assert entry.reason == "no response"
    assert failures.lookup_query(DomainName("a.dead.example"), DnsQType.A, DnsRClass.IN) is None


def test_a_servfail_zone_is_remembered_with_its_reason():
    """RFC 9520 §2.2: rcode 2 from every server is a failed lookup too.

    The reason string survives into the cache because it is what a trace and a log
    will show: "no response" and "rcode SERVER_FAILURE" send an operator to
    different problems, and both arrive at the same ``Fail("no servers")``.
    """
    failures = FailureCache()
    sname = Sname(DomainName("a.dead.example"), DnsQType.A)
    slist = _seed_slist(sname, DEAD_ZONE, [(DEAD_NS, DEAD_IP)])

    events = _drive(
        resolve_steps(sname, slist, failures=failures),
        [_response(sname.qname, aa=False, rcode=DnsResponseCode.SERVER_FAILURE)],
    )

    assert isinstance(events[-1], Fail)
    assert failures.lookup_zone(DEAD_ZONE).reason == "rcode " + DnsResponseCode.mnemonic(
        DnsResponseCode.SERVER_FAILURE
    )


def test_a_zone_that_answered_is_not_marked_dead():
    """The exclusion that keeps a working zone out of the failure cache.

    One server times out, its successor answers. The lookup never reached "no
    servers", and even if it had, this zone answered -- RFC 9520 3.3 is about a
    non-responsive zone, and half a functioning delegation is not one.
    """
    failures = FailureCache()
    qname = DomainName("a.dead.example")
    sname = Sname(qname, DnsQType.A)
    slist = _seed_slist(sname, DEAD_ZONE, [(DEAD_NS, DEAD_IP), (DEAD_NS2, DEAD_IP2)])

    events = _drive(
        resolve_steps(sname, slist, failures=failures),
        [None, _answer_for(qname, DEAD_IP2)],
    )

    assert _kinds(events) == ["SendQuery", "Demote", "SendQuery", "Answer", "Done"]
    assert len(failures) == 0


def test_an_unqueried_zone_is_never_marked_dead():
    """The guard against inventing an outage: ``.`` was never asked anything.

    With no servers at all -- no root hints -- the zone in scope is the root and
    the lookup fails immediately. Recording that as "the root is dead" would turn
    one misconfigured resolver into a five-minute blackout for every name it is
    asked about, so the narrow, per-name note is what gets written.
    """
    failures = FailureCache()
    sname = Sname(DomainName("example.com"), DnsQType.A)
    slist = Slist(sname)
    slist.zone = DomainName(".")
    slist.entries = []

    events = _drive(resolve_steps(sname, slist, failures=failures), [None])

    assert isinstance(events[-1], Fail)
    assert failures.lookup_zone(DomainName(".")) is None
    assert failures.lookup_query(DomainName("example.com"), DnsQType.A, DnsRClass.IN) is not None


def test_a_spent_hop_budget_is_remembered_for_the_name():
    """A hop budget spent mid-descent is this name's problem, not the zone's.

    The root referred us correctly -- it answered, and it was useful -- so the only
    honest note is against ``(qname, qtype, qclass)``.
    """
    failures = FailureCache()
    qname = DomainName("example.com")
    sname = Sname(qname, DnsQType.A)
    slist = _seed_slist(sname, DomainName("."), [(ROOT_NS, ROOT_IP)])
    referral = _response(
        qname,
        aa=False,
        nameservers=[
            DnsRecord(
                DomainName("com"),
                DnsRType.NS,
                DnsRClass.IN,
                0,
                rdata=DomainName("a.gtld-servers.net"),
            )
        ],
    )

    events = _drive(resolve_steps(sname, slist, failures=failures, max_hops=1), [referral])

    assert isinstance(events[-1], Fail)
    assert events[-1].reason == "max hops"
    assert failures.lookup_query(qname, DnsQType.A, DnsRClass.IN).reason == "max hops"
    assert failures.lookup_zone(DomainName(".")) is None


def test_an_alias_loop_is_remembered_for_the_name_asked_and_the_target():
    """RFC 9520 2.5, and the reason both keys are written.

    The loop is detected at the alias target, but a client re-asking the question
    it actually asked (``a.example.com``) is the repeat traffic RFC 9520 exists to
    suppress. Noting only the target would let that query re-walk the whole
    delegation before the cache stopped it one hop late.
    """
    failures = FailureCache()
    sname = Sname(DomainName("a.example.com"), DnsQType.A)
    slist = _seed_slist(sname, DomainName("example.com"), [(ROOT_NS, ROOT_IP)], match=2)
    round_trip = [
        _cname_at(DomainName("a.example.com"), DomainName("b.example.com")),
        _cname_at(DomainName("b.example.com"), DomainName("a.example.com")),
    ]

    events = _drive(resolve_steps(sname, slist, failures=failures), round_trip)

    assert isinstance(events[-1], Fail)
    assert "alias loop" in events[-1].reason
    for name in ("a.example.com", "b.example.com"):
        assert failures.lookup_query(DomainName(name), DnsQType.A, DnsRClass.IN) is not None
    # example.com answered every query; it is not a dead zone.
    assert failures.lookup_zone(DomainName("example.com")) is None


# ------------------------------------------------------ what suppression does


def test_the_next_name_in_a_dead_zone_asks_nothing():
    """RFC 9520 3.2, asserted the only way it can be: no ``SendQuery`` at all."""
    failures = FailureCache()
    failures.note_zone(DEAD_ZONE, "no response")
    sname = Sname(DomainName("b.dead.example"), DnsQType.A)
    slist = _seed_slist(sname, DEAD_ZONE, [(DEAD_NS, DEAD_IP)])

    events = _drive(resolve_steps(sname, slist, failures=failures), [None])

    assert _kinds(events) == ["Fail"]
    assert "cached failure for zone dead.example" in events[0].reason
    assert "no response" in events[0].reason
    assert failures.hits == 1


def test_a_dead_zone_does_not_reach_a_name_outside_it():
    """The scope of a zone entry is exactly its own subtree.

    ``other.example`` shares nothing with ``dead.example``; suppressing it would be
    the outage that 3.3's careful "parent zone" wording exists to avoid.
    """
    failures = FailureCache()
    failures.note_zone(DEAD_ZONE, "no response")
    other = DomainName("other.example")
    sname = Sname(DomainName("www.other.example"), DnsQType.A)
    slist = _seed_slist(sname, other, [(DomainName("ns.other.example"), DEAD_IP)])

    events = _drive(
        resolve_steps(sname, slist, failures=failures), [_answer_for(sname.qname, DEAD_IP)]
    )

    assert isinstance(events[0], SendQuery)
    assert _kinds(events)[-1] == "Done"


def test_a_zone_entry_suppresses_every_qtype_and_qclass_under_it():
    """3.2's "corresponding outgoing queries" is read broadly for a zone.

    The evidence is that the servers do not answer, which is a statement about the
    servers; the AAAA and MX queries beneath them will not be answered either, and
    each would otherwise be its own fresh failure to discover.
    """
    failures = FailureCache()
    failures.note_zone(DEAD_ZONE, "no response")
    for qtype in (DnsQType.AAAA, DnsQType.MX):
        sname = Sname(DomainName("b.dead.example"), qtype)
        slist = _seed_slist(sname, DEAD_ZONE, [(DEAD_NS, DEAD_IP)])
        events = _drive(resolve_steps(sname, slist, failures=failures), [None])
        assert _kinds(events) == ["Fail"], qtype


def test_a_query_entry_does_not_suppress_other_qtypes():
    """The mirror image: a per-name note is about one (name, type, class).

    A spent hop budget on the A query says nothing about whether MX will resolve,
    and suppressing it would be inventing an answer the resolver never sought.
    """
    failures = FailureCache()
    failures.note_query(DomainName("b.dead.example"), DnsQType.A, DnsRClass.IN, "max hops")
    sname = Sname(DomainName("b.dead.example"), DnsQType.MX)
    slist = _seed_slist(sname, DEAD_ZONE, [(DEAD_NS, DEAD_IP)])

    events = _drive(resolve_steps(sname, slist, failures=failures), [None])

    assert isinstance(events[0], SendQuery)


def test_suppressing_a_query_does_not_extend_the_failure():
    """The hazard the suppression path must not create.

    Re-noting on suppression would let a client polling a dead name push the expiry
    out on every poll, holding a recovered zone shut at the five-minute ceiling for
    as long as it kept asking. Suppression is a read.
    """
    clock = [1000.0]
    failures = FailureCache(time_fn=lambda: clock[0])
    sname_queried = Sname(DomainName("b.dead.example"), DnsQType.A)
    failures.note_query(sname_queried.qname, DnsQType.A, DnsRClass.IN, "no response")
    before = failures.lookup_query(sname_queried.qname, DnsQType.A, DnsRClass.IN)

    slist = _seed_slist(sname_queried, DEAD_ZONE, [(DEAD_NS, DEAD_IP)])
    _drive(resolve_steps(sname_queried, slist, failures=failures), [None])

    after = failures.lookup_query(sname_queried.qname, DnsQType.A, DnsRClass.IN)
    assert after.expires_at == before.expires_at
    assert after.strikes == 1


def test_a_repeated_failure_is_remembered_longer():
    """3.2's backoff, arriving through the resolver rather than by hand.

    Two full attempts, spaced past the first entry's expiry, must leave the second
    entry both counted and longer -- otherwise the cache is a fixed delay and the
    traffic it was meant to thin keeps arriving at the same rate.
    """
    clock = [1000.0]
    failures = FailureCache(time_fn=lambda: clock[0])
    qname = DomainName("a.dead.example")
    sname = Sname(qname, DnsQType.A)
    _drive(
        resolve_steps(
            sname, _seed_slist(sname, DEAD_ZONE, [(DEAD_NS, DEAD_IP)]), failures=failures
        ),
        [None],
    )
    first = failures.lookup_zone(DEAD_ZONE)

    clock[0] += first.ttl + 1
    again = Sname(qname, DnsQType.A)
    _drive(
        resolve_steps(
            again, _seed_slist(again, DEAD_ZONE, [(DEAD_NS, DEAD_IP)]), failures=failures
        ),
        [None],
    )

    second = failures.lookup_zone(DEAD_ZONE)
    assert second.strikes == 2
    assert second.ttl > first.ttl


# ------------------------------------------------------ the resolver's own wiring


def test_failure_cache_defaults_shared_and_switchable():
    """Three ways in, because there are three things a caller may want.

    A default cache (the point of the feature), an instance shared between
    resolvers (a worker pool should not each rediscover the same dead zone), and
    ``False`` for a resolver used to watch a zone fail -- where a resolver that has
    stopped asking is indistinguishable from one that is itself broken.
    """
    default = RecursiveResolver()
    shared = FailureCache()
    second = RecursiveResolver(failure_cache=shared)
    disabled = RecursiveResolver(failure_cache=False)

    assert isinstance(default.failure_cache, FailureCache)
    assert second.failure_cache is shared
    assert disabled.failure_cache is None


def test_recovery_resets_how_long_the_next_failure_is_kept():
    """Being slow to see recovery is only half the hazard; the other half is here.

    Four failures drive the note out to forty seconds. When the zone is heard from
    again, the count goes with the note -- otherwise a zone that flapped once meets
    every later outage near the ceiling, and a resolver that was quick to give up on
    it is now slow to notice it has broken again. RFC 9520 §3.3 warns that cached
    failures make a resolver slow to see recovery; an answer is the evidence that
    ends them, rather than a timer that happens to have run down.
    """
    clock = [1000.0]
    failures = FailureCache(time_fn=lambda: clock[0])
    last = None
    for strikes in (1, 2, 3, 4):
        sname = Sname(DomainName("a.dead.example"), DnsQType.A)
        _drive(
            resolve_steps(
                sname, _seed_slist(sname, DEAD_ZONE, [(DEAD_NS, DEAD_IP)]), failures=failures
            ),
            [None],
        )
        last = failures.lookup_zone(DEAD_ZONE)
        assert last.strikes == strikes
        clock[0] += FAILURE_MAX_TTL_S
    assert last.ttl == 40.0

    clock[0] += 41
    revived = Sname(DomainName("b.dead.example"), DnsQType.A)
    events = _drive(
        resolve_steps(
            revived,
            _seed_slist(revived, DEAD_ZONE, [(DEAD_NS, DEAD_IP)], match=3),
            failures=failures,
        ),
        [_answer_for(revived.qname, DEAD_IP)],
    )
    assert _kinds(events)[-1] == "Done"
    assert failures.lookup_zone(DEAD_ZONE) is None

    relapsed = Sname(DomainName("a.dead.example"), DnsQType.A)
    _drive(
        resolve_steps(
            relapsed, _seed_slist(relapsed, DEAD_ZONE, [(DEAD_NS, DEAD_IP)]), failures=failures
        ),
        [None],
    )
    assert failures.lookup_zone(DEAD_ZONE).strikes == 1
    assert failures.lookup_zone(DEAD_ZONE).ttl == FAILURE_INITIAL_TTL_S

    # The disabled path keeps asking, which is the whole reason it exists: the
    # generator is handed `None` and must not consult or write anything.
    sname = Sname(DomainName("a.dead.example"), DnsQType.A)
    slist = _seed_slist(sname, DEAD_ZONE, [(DEAD_NS, DEAD_IP)])
    events = _drive(resolve_steps(sname, slist, failures=None), [None])
    assert isinstance(events[0], SendQuery)
    assert _kinds(events)[-1] == "Fail"
