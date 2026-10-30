"""RFC 8020: a cached NXDOMAIN denies the subtree beneath it.

§2¶1: "When an iterative caching DNS resolver receives an NXDOMAIN response, it
SHOULD store it in its cache and then all names and resource record sets (RRsets)
at or below that node SHOULD be considered unreachable. Subsequent queries for
such names SHOULD elicit an NXDOMAIN response." §2¶7 gives the example: 'foo.example'
denied, then 'bar.foo.example' answered "without transmitting it to an
authoritative server".

Most of the assertions here are negative ones, and deliberately so. A cut that
fires produces a NXDOMAIN byte-for-byte like one that was fetched, so proving the
feature works means proving *no query left*; the risks worth pinning are the ones
where something must not cut -- NODATA, a sibling (§2¶8 says the first denial "won't
tell anything about" it), an expired entry, a cache too primitive to answer --
because each of those turns a correct answer into a denial of a name that exists.
"""

import ipaddress

import pytest

from namespy.cache import FailureCache, MemoryDnsCache, NegativeEntry, PositiveEntry
from namespy.enums import DnsQR, DnsQType, DnsRClass, DnsResponseCode, DnsRType
from namespy.names import DomainName
from namespy.packet import DnsQuestion, DnsRecord, Response
from namespy.resolver import (
    Fail,
    Nodata,
    Nxdomain,
    NxdomainCut,
    NxdomainPolicy,
    RecursiveResolver,
    SendQuery,
    Slist,
    SlistEntry,
    Sname,
    resolve_steps,
)
from namespy.trace import Trace

NOW = 1000.0
ROOT_NS = DomainName("a.root-servers.net.")
ROOT_IP = ipaddress.IPv4Address("198.41.0.4")


class _Clock:
    """Manually advanced, so expiry is a line in the test rather than a sleep."""

    def __init__(self, t=NOW):
        self.t = float(t)

    def __call__(self):
        return self.t


def _soa(zone, ttl=60, minimum=3600):
    """An SOA carrying real RDATA, because a denial without a proof is not cacheable.

    ``RData_SOA`` rather than hand-packed bytes: the sqlite backend serialises and
    re-parses this record, and several assertions below are about *which* zone's
    SOA came back -- that record is the only evidence in a cut's answer.
    """
    from namespy.rdata import RData_SOA

    return DnsRecord(
        DomainName(zone),
        DnsRType.SOA,
        DnsRClass.IN,
        ttl,
        rdata=RData_SOA(
            DomainName(f"ns1.{zone}"),
            DomainName(f"hostmaster.{zone}"),
            serial=1,
            refresh=7200,
            retry=3600,
            expire=1209600,
            minimum=minimum,
        ),
    )


def _deny(
    cache,
    name,
    qtype,
    soa_zone,
    clock,
    *,
    qclass=DnsRClass.IN,
    rcode=DnsResponseCode.NAME_ERROR,
    life=60,
):
    """Cache a denial for *name*, exactly as a terminal NXDOMAIN would write it."""
    cache.put(
        NegativeEntry(
            DomainName(name),
            qtype,
            qclass,
            rcode,
            _soa(soa_zone),
            clock.t + life,
        )
    )


def _seed_slist(sname, zone, ns_name=ROOT_NS, addr=ROOT_IP):
    slist = Slist(sname)
    slist.zone = zone
    slist.match = sname.match_count(zone)
    slist.entries = [SlistEntry(zone, ns_name, [addr])]
    return slist


def _response(
    qname, *, aa=False, rcode=DnsResponseCode.NO_ERROR, answers=(), nameservers=(), qtype=DnsQType.A
):
    return Response(
        QR=DnsQR.RESPONSE,
        AA=aa,
        RCODE=rcode,
        questions=[DnsQuestion(qname, qtype)],
        answers=list(answers),
        nameservers=list(nameservers),
    )


def _drive(generator, responses):
    """Run a resolve_steps generator, answering SendQuery from *responses*."""
    events = []
    pending = next(generator)
    events.append(pending)
    index = 0
    while True:
        try:
            if isinstance(pending, SendQuery) and index < len(responses):
                pending = generator.send(responses[index])
                index += 1
            else:
                pending = generator.send(None)
        except StopIteration:
            break
        events.append(pending)
    return events


def _kinds(events):
    return [type(event).__name__ for event in events]


def _walk(cache, name, qtype=DnsQType.AAAA, responses=(), **kwargs):
    """Resolve *name* against *cache* and return every event the walk yielded."""
    sname = Sname(DomainName(name), qtype)
    return _drive(
        resolve_steps(sname, _seed_slist(sname, DomainName(".")), cache, **kwargs),
        list(responses),
    )


def test_denial_above_the_name_ends_the_lookup_without_a_query():
    """The headline: a AAAA cut by an NXDOMAIN that arrived in answer to an A.

    Nothing on the wire distinguishes this from a fetched denial, which is why the
    assertion carrying the weight is the absence of a SendQuery -- RFC 8020 §2 is
    about not sending it, not about the rcode.
    """
    clock = _Clock()
    cache = MemoryDnsCache(time_fn=clock)
    _deny(cache, "foo.example.com.", DnsQType.A, "example.com.", clock)

    events = _walk(cache, "www.foo.example.com.", DnsQType.AAAA)

    assert _kinds(events) == ["NxdomainCut", "Nxdomain", "Done"]
    cut = events[0]
    assert cut.name == "www.foo.example.com."
    assert cut.denied_by == "foo.example.com."

    response = events[-1].response
    assert response.RCODE == DnsResponseCode.NAME_ERROR
    # The question section still names what was asked. Answering for one name
    # using evidence about another must not quietly rewrite the question.
    assert response.questions[0].name == DomainName("www.foo.example.com.")
    # The SOA in the authority section is the ancestor's proof, and is the only
    # part of the reply that says where the denial came from.
    assert response.nameservers[0].name == DomainName("example.com.")


def test_never_policy_walks_the_denied_subtree():
    """RFC 8020 is a SHOULD, and §2¶4 admits why: "The fact that a subtree does
    not exist is not forever".

    Off is the stance for watching a zone change: a name created under a denied
    node is invisible to the cut until the negative entry expires, so an operator
    confirming that a delegation appeared has to be allowed to ask again.
    """
    clock = _Clock()
    cache = MemoryDnsCache(time_fn=clock)
    _deny(cache, "foo.example.com.", DnsQType.A, "example.com.", clock)

    asked = DomainName("www.foo.example.com.")
    events = _walk(
        cache,
        asked,
        DnsQType.AAAA,
        [_response(asked)],
        nxdomain_cut=NxdomainPolicy.NEVER,
    )

    assert "NxdomainCut" not in _kinds(events)
    assert isinstance(events[0], SendQuery)


def test_nodata_above_the_name_does_not_cut():
    """A cached NODATA for ``foo`` says nothing about ``bar.foo``.

    Both negatives share one entry class, so this is where the difference is
    enforced rather than assumed.
    """
    clock = _Clock()
    cache = MemoryDnsCache(time_fn=clock)
    _deny(
        cache,
        "foo.example.com.",
        DnsQType.A,
        "example.com.",
        clock,
        rcode=DnsResponseCode.NO_ERROR,
    )

    asked = DomainName("www.foo.example.com.")
    events = _walk(cache, asked, DnsQType.AAAA, [_response(asked)])
    assert _kinds(events)[0] == "SendQuery"


def test_a_sibling_beside_the_denied_name_is_not_cut():
    """§2¶8, the boundary the optimisation has to respect.

    "If the first request is for 'bar.foo.example' and the second for
    'baz.foo.example', then the first NXDOMAIN response won't tell anything about
    'baz.foo.example'; therefore, the second query will be transmitted as it was
    before." A cut that reached sideways would deny names nobody ever denied.
    """
    clock = _Clock()
    cache = MemoryDnsCache(time_fn=clock)
    _deny(cache, "foo.example.com.", DnsQType.A, "example.com.", clock)

    asked = DomainName("bar.example.com.")
    events = _walk(cache, asked, DnsQType.A, [_response(asked)])
    assert _kinds(events)[0] == "SendQuery"


def test_expired_denial_stops_cutting():
    """The cut cannot outlive the answer it came from (RFC 2308 §3)."""
    clock = _Clock()
    cache = MemoryDnsCache(time_fn=clock)
    _deny(cache, "foo.example.com.", DnsQType.A, "example.com.", clock, life=60)
    assert _kinds(_walk(cache, "www.foo.example.com."))[0] == "NxdomainCut"

    clock.t += 61
    asked = DomainName("www.foo.example.com.")
    events = _walk(cache, asked, DnsQType.AAAA, [_response(asked)])
    assert _kinds(events)[0] == "SendQuery"


def test_the_cut_is_case_insensitive():
    """Same rule as the cache itself: RFC 1035 §3.1, case is not significant."""
    clock = _Clock()
    cache = MemoryDnsCache(time_fn=clock)
    _deny(cache, "FOO.example.com.", DnsQType.A, "example.com.", clock)

    events = _walk(cache, "www.Foo.EXAMPLE.com.", DnsQType.A)
    assert _kinds(events)[0] == "NxdomainCut"
    # Reported as the query spells it, not as the entry is stored. Both are the
    # same name -- §3.1 of RFC 1035 -- but a trace line whose two halves differ in
    # case reads like two names, and this line exists to be read.
    assert events[0].denied_by == "Foo.EXAMPLE.com."


def test_a_denial_at_the_name_itself_cuts_every_other_type():
    """§2¶1's "at", which is the half people skip.

    "all names and resource record sets (RRsets) at or below that node" -- the
    node is the denied name, so the denial covers every RRset at it, not only the
    types below it. RFC 2308 caches a negative per type, so the AAAA that follows
    an NXDOMAIN'd A is a fresh query under that spec and a re-proving of something
    the zone already proved. The cache cannot express the cut (get() is keyed on
    the type), which is why the walk includes the name itself rather than starting
    at the parent.
    """
    clock = _Clock()
    cache = MemoryDnsCache(time_fn=clock)
    _deny(cache, "gone.example.com.", DnsQType.A, "example.com.", clock)

    events = _walk(cache, "gone.example.com.", DnsQType.AAAA)
    assert _kinds(events) == ["NxdomainCut", "Nxdomain", "Done"]
    assert events[0].denied_by == "gone.example.com."


def test_closest_denial_answers_and_proves_it():
    """Closest-first, because a denial at ``com.`` proves less than one below it.

    Taking the outermost match would answer for a subtree using evidence about a
    smaller one, and would carry the wrong zone's SOA while doing it.
    """
    clock = _Clock()
    cache = MemoryDnsCache(time_fn=clock)
    _deny(cache, "com.", DnsQType.A, "com.", clock)
    _deny(cache, "foo.example.com.", DnsQType.A, "example.com.", clock)

    events = _walk(cache, "www.foo.example.com.")
    assert events[0].denied_by == "foo.example.com."
    assert events[-1].response.nameservers[0].name == DomainName("example.com.")

    # With only the zone-cut denial present, that is what answers -- the
    # behaviour is a walk, not a preference for the deepest entry it happens to
    # find first.
    clock2 = _Clock()
    cache2 = MemoryDnsCache(time_fn=clock2)
    _deny(cache2, "com.", DnsQType.A, "com.", clock2)
    events = _walk(cache2, "www.foo.example.com.")
    assert events[0].denied_by == "com."
    assert events[-1].response.nameservers[0].name == DomainName("com.")


def test_denial_reached_through_an_alias_cuts_at_the_end_of_the_chain():
    """RFC 8020 §2¶6: the name that does not exist is the last one in the chain.

    "Warning: if there is a chain of CNAME (or DNAME), the name that does not
    exist is the last of the chain ... and not the QNAME. The NXDOMAIN stored in
    the cache is for the denied name, not always for the QNAME." -- so the cut has
    to be consulted at every hop, not only at the origin. A resolver that checked
    once at the top would send a query for the alias target's subtree that its own
    cache already says cannot be answered.
    """
    clock = _Clock()
    cache = MemoryDnsCache(time_fn=clock)
    # The denial was left behind by some earlier lookup of a sibling, and it is
    # filed under AAAA while this query asks for A: two independent reasons a
    # plain get() would walk straight past it.
    _deny(cache, "web.example.net.", DnsQType.AAAA, "example.net.", clock)

    alias = DomainName("alias.example.com.")
    first = _response(
        alias,
        aa=True,
        answers=[
            DnsRecord(
                alias,
                DnsRType.CNAME,
                DnsRClass.IN,
                60,
                rdata=DomainName("web.example.net."),
            )
        ],
    )
    events = _walk(cache, alias, DnsQType.A, responses=[first])

    assert _kinds(events) == ["SendQuery", "Cname", "NxdomainCut", "Nxdomain", "Done"]
    assert events[1].target == DomainName("web.example.net.")
    assert events[2].denied_by == "web.example.net."
    assert events[-1].response.RCODE == DnsResponseCode.NAME_ERROR
    assert len([e for e in events if isinstance(e, SendQuery)]) == 1


def test_a_cached_denial_beats_a_failure_note():
    """Where RFC 8020 and RFC 9520 overlap, the proof wins.

    A failure note is a promise not to ask again; a cached NXDOMAIN is a denial
    somebody signed with their SOA. Both stop the query, but only one of them can
    answer the client, so the order here is not arbitrary -- the failure branch
    would return a SERVFAIL-ish refusal for a name the resolver actually knows
    does not exist.
    """
    clock = _Clock()
    cache = MemoryDnsCache(time_fn=clock)
    _deny(cache, "foo.example.com.", DnsQType.A, "example.com.", clock)
    failures = FailureCache(time_fn=clock)
    asked = DomainName("www.foo.example.com.")
    failures.note_query(asked, DnsQType.AAAA, DnsRClass.IN, "connection reset")

    events = _walk(cache, asked, DnsQType.AAAA, failures=failures)
    assert _kinds(events)[0] == "NxdomainCut"
    assert not any(isinstance(event, Fail) for event in events)


def test_validated_policy_is_refused_at_the_door():
    """RFC 8020 §2¶3 is a stance this package cannot honour, and says so.

    VALIDATED and NEVER emit the same packets while nothing validates, so a silent
    fallback would leave an operator believing DNSSEC proof was what stopped the
    cut. Refusing is the only honest option until there is validation -- and this
    test is the thing that has to change when it arrives.
    """
    with pytest.raises(ValueError, match="DNSSEC"):
        RecursiveResolver(nxdomain_cut=NxdomainPolicy.VALIDATED)


def test_policy_arrives_as_a_string_too():
    """Config files and CLI flags hand over text, like GluePolicy's."""
    resolver = RecursiveResolver(nxdomain_cut="never")
    assert resolver.nxdomain_cut is NxdomainPolicy.NEVER
    assert RecursiveResolver().nxdomain_cut is NxdomainPolicy.ALWAYS


def test_trace_names_both_halves_of_the_cut():
    """The packets of a cut and of a fetched denial are identical, so say it.

    Someone whose freshly created name is being denied reads this line, and the
    ancestor's SOA in the answer is the only hint the reply itself carries.
    """
    trace = Trace(Sname(DomainName("www.foo.example.com."), DnsQType.AAAA))
    trace.record(NxdomainCut("www.foo.example.com.", "foo.example.com."))
    trace.record(Nxdomain())

    diagram = trace.to_mermaid()
    assert "NXDOMAIN cut: www.foo.example.com. below foo.example.com." in diagram
    assert "NXDOMAIN" in diagram


def test_trace_still_separates_nodata_from_nxdomain():
    """Guard on the renderer's dispatch table.

    Both verdicts are one-word notes two branches apart, and a duplicated class
    name in that chain silently turns every NODATA into an NXDOMAIN -- which no
    number of resolver tests would catch.
    """
    trace = Trace(Sname(DomainName("example.com."), DnsQType.AAAA))
    trace.record(Nxdomain())
    assert "NXDOMAIN" in trace.to_mermaid()

    trace = Trace(Sname(DomainName("example.com."), DnsQType.AAAA))
    trace.record(Nodata(_soa("example.com.")))
    diagram = trace.to_mermaid()
    assert "NODATA" in diagram
    assert "NXDOMAIN" not in diagram


def _a(name):
    return DnsRecord(
        DomainName(name),
        DnsRType.A,
        DnsRClass.IN,
        60,
        rdata=ipaddress.IPv4Address("1.2.3.4").packed,
    )


def test_replacing_a_denial_with_an_answer_clears_the_index():
    """The one index mistake that would produce a wrong answer rather than a walk.

    The index maps a name to a *key*, and a name that was denied can be populated
    later: the zone adds an A record, the resolver caches it under the same
    ``(name, type, class)`` the denial occupied, and if the index still answered
    for that key the resolver would go on denying the subtree from an entry that no
    longer exists there.
    """
    clock = _Clock()
    cache = MemoryDnsCache(time_fn=clock)
    _deny(cache, "foo.example.com.", DnsQType.A, "example.com.", clock)
    cache.put(
        PositiveEntry(
            DomainName("foo.example.com."),
            DnsQType.A,
            DnsRClass.IN,
            [_a("foo.example.com.")],
            clock.t + 60,
        )
    )

    assert cache.nxdomain_at(DomainName("foo.example.com."), DnsRClass.IN) is None
    events = _walk(cache, "www.foo.example.com.", DnsQType.AAAA, [_response(DomainName("x"))])
    assert _kinds(events)[0] == "SendQuery"


def test_a_denial_become_nodata_clears_the_index():
    """Same shape, more likely: the name later exists but lacks the type.

    NODATA and NXDOMAIN share a key and a class, so the entry that replaces a
    denial can be a negative one that must not cut.
    """
    clock = _Clock()
    cache = MemoryDnsCache(time_fn=clock)
    _deny(cache, "foo.example.com.", DnsQType.A, "example.com.", clock)
    _deny(
        cache,
        "foo.example.com.",
        DnsQType.A,
        "example.com.",
        clock,
        rcode=DnsResponseCode.NO_ERROR,
    )

    assert cache.nxdomain_at(DomainName("foo.example.com."), DnsRClass.IN) is None


def test_eviction_clears_the_index():
    """A cut must not survive the entry that justified it, LRU or otherwise."""
    clock = _Clock()
    cache = MemoryDnsCache(max_entries=2, time_fn=clock)
    _deny(cache, "foo.example.com.", DnsQType.A, "example.com.", clock)
    for name in ("a.example.com.", "b.example.com."):
        cache.put(
            PositiveEntry(DomainName(name), DnsQType.A, DnsRClass.IN, [_a(name)], clock.t + 60)
        )

    assert len(cache) == 2
    assert cache.nxdomain_at(DomainName("foo.example.com."), DnsRClass.IN) is None


def test_prune_clears_the_index_and_a_new_denial_indexes_again():
    """Removal must not leave the name poisoned, or the next denial is invisible."""
    clock = _Clock()
    cache = MemoryDnsCache(time_fn=clock)
    _deny(cache, "foo.example.com.", DnsQType.A, "example.com.", clock, life=60)
    clock.t += 61
    assert cache.prune() == 1
    assert cache.nxdomain_at(DomainName("foo.example.com."), DnsRClass.IN) is None

    _deny(cache, "foo.example.com.", DnsQType.AAAA, "example.com.", clock)
    assert cache.nxdomain_at(DomainName("foo.example.com."), DnsRClass.IN) is not None


def test_a_dangling_pointer_costs_a_walk_not_a_lie():
    """The lookup re-checks what its index hands it.

    This reaches into the cache's innards on purpose: no public sequence produces a
    dangling pointer today, because every removal path clears the index. The point
    is that when someone adds a path that forgets to, the result is a wasted walk --
    not an NXDOMAIN invented from an entry that is gone.
    """
    clock = _Clock()
    cache = MemoryDnsCache(time_fn=clock)
    _deny(cache, "foo.example.com.", DnsQType.A, "example.com.", clock)
    key = next(iter(cache._nxdomain.values()))
    del cache._entries[key]

    assert cache.nxdomain_at(DomainName("foo.example.com."), DnsRClass.IN) is None
    assert key not in cache._nxdomain.values()
