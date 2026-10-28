"""QNAME minimisation in the resolution loop (RFC 9156).

The schedule arithmetic is pinned in ``test_minimis.py``; these tests pin
the *integration*: what each downline server is allowed to see, and the
rule that a probe response is never an answer about the original QNAME.
"""

import ipaddress

from namespy.cache import MemoryDnsCache
from namespy.enums import DnsQR, DnsQType, DnsRClass, DnsResponseCode, DnsRType
from namespy.names import DomainName
from namespy.packet import DnsQuestion, DnsRecord, Response
from namespy.resolver import (
    Answer,
    Demote,
    Done,
    Fail,
    Nodata,
    Nxdomain,
    Referral,
    SendQuery,
    Slist,
    SlistEntry,
    Sname,
    resolve_steps,
)

ROOT = DomainName(".")
GTLD = DomainName("a.gtld-servers.net")
NS1 = DomainName("ns1.example.com")


def _referral(question_name, new_zone, ns_targets, glue=()):
    ns_records = [DnsRecord(new_zone, DnsRType.NS, DnsRClass.IN, 0, rdata=t) for t in ns_targets]
    ar_records = [DnsRecord(t, DnsRType.A, DnsRClass.IN, 0, rdata=ip.packed) for t, ip in glue]
    return Response(
        QR=DnsQR.RESPONSE,
        AA=False,
        questions=[DnsQuestion(question_name, DnsQType.A)],
        nameservers=ns_records,
        additional_records=ar_records,
    )


def _aa_answer(qname, addr):
    return Response(
        QR=DnsQR.RESPONSE,
        AA=True,
        questions=[DnsQuestion(qname, DnsQType.A)],
        answers=[DnsRecord(qname, DnsRType.A, DnsRClass.IN, 60, rdata=addr.packed)],
    )


def _nodata(soa_owner):
    """Authoritative NODATA: the probe name exists and simply has no A record.

    The SOA carries empty rdata (the opaque fallback) -- the resolver only
    needs "the authority section holds SOA, not a deeper NS" to classify it,
    which is the RFC 2308 section 2.2.1 distinction.
    """
    return Response(
        QR=DnsQR.RESPONSE,
        AA=True,
        RCODE=DnsResponseCode.NO_ERROR,
        questions=[],
        nameservers=[DnsRecord(soa_owner, DnsRType.SOA, DnsRClass.IN, 60, rdata=b"")],
    )


def _root_seeded(sname):
    slist = Slist(sname)
    slist.zone = ROOT
    slist.match = 0
    slist.entries = [
        SlistEntry(ROOT, DomainName("a.root-servers.net"), [ipaddress.IPv4Address("198.41.0.4")])
    ]
    return slist


def _run(gen, canned):
    """Drive the generator over a list of canned replies; return every event.

    A ``SendQuery`` pauses the generator at ``send(response = ...)``: the next
    resume must be the canned reply, never ``next()`` -- which would hand the
    loop ``None`` as a response. So draining only happens between a response
    and the query it produced.
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


def test_probe_walk_exposes_only_zone_boundaries():
    """www.example.com.: the root sees only `com.`, the TLD only
    `example.com.`, the authoritative server the full QNAME
    (RFC 9156 section 2, section 3 steps 2-3)."""
    qname = DomainName("www.example.com")
    sname = Sname(qname, DnsQType.A)
    gen = resolve_steps(sname, _root_seeded(sname), qname_min=True)

    events = _run(
        gen,
        [
            _referral(
                DomainName("com"),
                DomainName("com"),
                [GTLD],
                glue=[(GTLD, ipaddress.IPv4Address("192.5.6.30"))],
            ),
            _referral(
                DomainName("example.com"),
                DomainName("example.com"),
                [NS1],
                glue=[(NS1, ipaddress.IPv4Address("93.184.216.34"))],
            ),
            _aa_answer(qname, ipaddress.IPv4Address("93.184.216.34")),
        ],
    )
    queries = [e for e in events if isinstance(e, SendQuery)]
    # rstrip: the harness Sname is unqualified, and the minimiser builds
    # probe names absolutely; presentation dots differ, the names do not.
    assert [str(q.questions[0].name).rstrip(".") for q in queries] == [
        "com",
        "example.com",
        "www.example.com",
    ]
    assert [q.probe for q in queries] == [True, True, False]
    # Every probe is QTYPE=A so referrals keep the classic shape
    # (RFC 9156 section 3 step 2); the real question keeps the real QTYPE.
    assert [q.questions[0].qtype for q in queries] == [DnsQType.A] * 3
    assert any(isinstance(e, Referral) for e in events)
    assert isinstance(events[-1], Done)


def test_probe_nodata_demotes_and_never_terminates():
    """ "com. has no A record" must never become the final NODATA for
    www.example.com. (RFC 9156 section 3 step 4: take the next name in
    Slist -- here, demote)."""
    qname = DomainName("www.example.com")
    sname = Sname(qname, DnsQType.A)
    slist = _root_seeded(sname)
    cache = MemoryDnsCache()
    events = _run(resolve_steps(sname, slist, cache, qname_min=True), [_nodata(ROOT)])

    assert not any(isinstance(e, (Answer, Nodata, Nxdomain, Done)) for e in events)
    demotes = [e for e in events if isinstance(e, Demote)]
    assert demotes
    assert "probe" in demotes[0].reason
    assert isinstance(events[-1], Fail)  # the single entry was demoted away
    # A probe says nothing about the QNAME; nothing may be cached under it.
    assert cache.get(qname, DnsQType.A, DnsRClass.IN) is None


def test_probe_budget_spends_one_slot_per_query_then_degrades_to_full_name():
    """A 20-label QNAME whose every probe is answered NODATA: each query
    spends one slot of the RFC 9156 section 2.3 schedule (1,1,1,1,2,2,3,3,3,3
    for the default 10/4) from the root baseline, because no referral ever
    deepens what the next server is known to be authoritative for. Once all
    ten slots are spent the resolver degrades to the original question and
    resolution completes -- section 2.3's MUST is a cap on probes, not a
    promise of an answer."""

    def at_depth(k):
        if k == 1:
            return "example"
        return ".".join([f"s{j}" for j in range(k - 1, 0, -1)] + ["example"])

    full = ".".join(f"s{j}" for j in range(19, 0, -1)) + ".example"
    sname = Sname(DomainName(full), DnsQType.A)
    slist = Slist(sname)
    slist.zone = ROOT
    slist.match = 0
    slist.entries = [
        SlistEntry(ROOT, DomainName(f"ns{j}.root"), [ipaddress.IPv4Address(f"10.0.0.{j}")])
        for j in range(1, 12)
    ]
    cache = MemoryDnsCache()

    events = _run(
        resolve_steps(sname, slist, cache, qname_min=True),
        [_nodata(ROOT)] * 10 + [_aa_answer(sname.qname, ipaddress.IPv4Address("192.0.2.7"))],
    )
    queries = [e for e in events if isinstance(e, SendQuery)]
    assert [str(q.questions[0].name).rstrip(".") for q in queries] == (
        [at_depth(1)] * 4 + [at_depth(2)] * 2 + [at_depth(3)] * 4 + [full]
    )
    assert [q.probe for q in queries] == [True] * 10 + [False]
    assert sum(isinstance(e, Demote) for e in events) == 10
    assert isinstance(events[-1], Done)
    # The full-name answer is the first statement about the QNAME, so it is
    # the first thing allowed into the cache under it.
    assert cache.get(sname.qname, DnsQType.A, DnsRClass.IN) is not None


def test_default_off_sends_the_full_question_everywhere_byte_identically():
    """qname_min left off: every server sees sname.questions, unmodified --
    the default path stays byte-identical to pre-minimisation namespy."""
    qname = DomainName("www.example.com.")
    sname = Sname(qname, DnsQType.A)
    gen = resolve_steps(sname, _root_seeded(sname))

    events = _run(
        gen,
        [
            _referral(
                qname, DomainName("com"), [GTLD], glue=[(GTLD, ipaddress.IPv4Address("192.5.6.30"))]
            ),
            _referral(qname, qname, [NS1], glue=[(NS1, ipaddress.IPv4Address("93.184.216.34"))]),
            _aa_answer(qname, ipaddress.IPv4Address("93.184.216.34")),
        ],
    )
    queries = [e for e in events if isinstance(e, SendQuery)]
    assert len(queries) == 3
    assert all(not q.probe for q in queries)
    expected = bytes(sname.questions[0])
    assert all(bytes(q.questions[0]) == expected for q in queries)
    assert isinstance(events[-1], Done)
