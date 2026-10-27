"""Alias handling: CNAME chains, DNAME redirection, and NODATA vs referral.

These cover behaviour that has no wire-level equivalent -- the resolver's
decisions about what a response *means* -- so they drive ``classify`` and
``resolve_steps`` directly with hand-built messages.

Spec anchors, all quoted or paraphrased closely:

* RFC 1034 5.3.3 step 4c: set SNAME to the CNAME's RDATA and go to step 2.
* RFC 1034 3.6.2: an alias must not map to itself, directly or indirectly.
* RFC 2308 2.2.1: a NODATA response is often mistaken for a referral; the
  authority section's content decides, not the AA bit alone.
* RFC 2308 3, 5: a negative answer needs an SOA to be cacheable, and its TTL is
  ``min(SOA.MINIMUM, SOA.TTL)``.
* RFC 6672 2.3, 3.1: a DNAME redirects names below its owner but never its owner,
  and a server synthesises a CNAME for the substitution.
"""

import ipaddress

from aiodns.enums import DnsQR, DnsQType, DnsRClass, DnsResponseCode, DnsRType
from aiodns.names import DomainName
from aiodns.packet import DnsQuestion, DnsRecord, Response
from aiodns.resolver import (
    MAX_ALIAS_HOPS,
    SendQuery,
    Slist,
    SlistEntry,
    Sname,
    classify,
    resolve_steps,
)

ROOT_NS = DomainName("a.root-servers.net")
ROOT_IP = ipaddress.IPv4Address("198.41.0.4")


def _seed_slist(zone, ns_name, addr, sname=None, match=0):
    slist = Slist(sname)
    slist.zone = zone
    slist.match = match
    slist.entries = [SlistEntry(zone, ns_name, [addr])]
    return slist


def _response(
    qname,
    qtype=DnsQType.A,
    *,
    aa=False,
    rcode=DnsResponseCode.NO_ERROR,
    answers=(),
    nameservers=(),
    additional=(),
):
    return Response(
        QR=DnsQR.RESPONSE,
        AA=aa,
        RCODE=rcode,
        questions=[DnsQuestion(qname, qtype)],
        answers=list(answers),
        nameservers=list(nameservers),
        additional_records=list(additional),
    )


def _record(name, rtype, rdata, ttl=300):
    return DnsRecord(name, rtype, DnsRClass.IN, ttl, rdata=rdata)


def _soa(zone, minimum=3600, ttl=3600):
    """An SOA carrying a real MINIMUM, as RFC 2308 section 4 requires readers to use."""
    from aiodns.rdata import RData_SOA

    rdata = RData_SOA(
        DomainName("ns1.example.com"),
        DomainName("hostmaster.example.com"),
        serial=1,
        refresh=7200,
        retry=3600,
        expire=1209600,
        minimum=minimum,
    )
    return DnsRecord(zone, DnsRType.SOA, DnsRClass.IN, ttl, rdata=rdata)


def _drive(generator, responses):
    """Run a ``resolve_steps`` generator, answering SendQuery from *responses*.

    Returns every event yielded, in order. Mirrors what
    ``RecursiveResolver._drive`` does, minus the sockets.
    """
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


# ------------------------------------------------------- CNAME, within a reply


def test_cname_without_target_answer_continues_the_lookup():
    """A lone CNAME must not end the lookup, and must not be an answer either.

    RFC 1034 5.3.3 step 4c re-anchors SNAME and returns to step 2. Treating this
    response as terminal is the bug that made every aliased name unresolvable, so
    the assertion worth pinning is the *absence* of Done and Demote.
    """
    sname = Sname(DomainName("www.example.com"), DnsQType.A)
    slist = _seed_slist(
        DomainName("example.com"), ROOT_NS, ROOT_IP, sname, match=sname.match_count("example.com")
    )
    cname = _record(DomainName("www.example.com"), DnsRType.CNAME, DomainName("web.example.net"))
    response = _response(sname.qname, aa=True, answers=[cname])

    events = list(classify(response, sname, slist, slist.best()))

    assert _kinds(events) == ["Cname"]
    assert events[0].target == DomainName("web.example.net")


def test_complete_cname_chain_returns_the_alias_with_the_answer():
    """RFC 1034 3.6.2: an aliased answer is returned *plus* the CNAME.

    A caller that saw only the A record could not distinguish an aliased name
    from a direct one, which matters for anything that has to report the
    canonical name.
    """
    sname = Sname(DomainName("www.example.com"), DnsQType.A)
    slist = _seed_slist(DomainName("example.com"), ROOT_NS, ROOT_IP, sname, match=2)
    cname = _record(DomainName("www.example.com"), DnsRType.CNAME, DomainName("web.example.net"))
    address = _record(
        DomainName("web.example.net"), DnsRType.A, ipaddress.IPv4Address("93.184.216.34").packed
    )
    response = _response(sname.qname, aa=True, answers=[cname, address])

    events = list(classify(response, sname, slist, slist.best()))

    # The Cname event is emitted for every redirection taken, even one that
    # completes inside this same response -- the trace has to show the hop.
    assert _kinds(events) == ["Cname", "Answer", "Done"]
    assert list(events[1].records) == [cname, address]


def test_direct_data_at_the_name_wins_over_a_redirection():
    """RFC 6672 2.3: when QTYPE matches data at the owner, the answer is sourced there."""
    sname = Sname(DomainName("www.example.com"), DnsQType.A)
    slist = _seed_slist(DomainName("example.com"), ROOT_NS, ROOT_IP, sname, match=2)
    address = _record(
        DomainName("www.example.com"), DnsRType.A, ipaddress.IPv4Address("1.2.3.4").packed
    )
    response = _response(sname.qname, aa=True, answers=[address])

    events = list(classify(response, sname, slist, slist.best()))

    assert _kinds(events) == ["Answer", "Done"]
    assert list(events[0].records) == [address]


def test_multi_hop_chain_inside_one_response():
    """A chain fully contained in one answer section is walked to its end."""
    sname = Sname(DomainName("a.example.com"), DnsQType.A)
    slist = _seed_slist(DomainName("example.com"), ROOT_NS, ROOT_IP, sname, match=2)
    answers = [
        _record(DomainName("a.example.com"), DnsRType.CNAME, DomainName("b.example.com")),
        _record(DomainName("b.example.com"), DnsRType.CNAME, DomainName("c.example.com")),
        _record(
            DomainName("c.example.com"),
            DnsRType.A,
            ipaddress.IPv4Address("5.6.7.8").packed,
        ),
    ]
    response = _response(sname.qname, aa=True, answers=answers)

    events = list(classify(response, sname, slist, slist.best()))

    assert _kinds(events) == ["Cname", "Cname", "Answer", "Done"]
    assert list(events[2].records) == answers


def test_alias_loop_inside_one_response_fails():
    """RFC 1034 3.6.2 forbids an alias mapping to itself, directly or indirectly.

    The point of this test is what the loop must *not* be: a loop reached the
    ``ANCOUNT > 0`` branch and was reported as NODATA, which RFC 2308 5 would
    then have cached against the zone SOA. A broken zone is a failure, not a
    negative answer.
    """
    sname = Sname(DomainName("a.example.com"), DnsQType.A)
    slist = _seed_slist(DomainName("example.com"), ROOT_NS, ROOT_IP, sname, match=2)
    answers = [
        _record(DomainName("a.example.com"), DnsRType.CNAME, DomainName("b.example.com")),
        _record(DomainName("b.example.com"), DnsRType.CNAME, DomainName("a.example.com")),
    ]
    response = _response(sname.qname, aa=True, answers=answers)

    events = list(classify(response, sname, slist, slist.best()))

    assert _kinds(events) == ["Cname", "Cname", "Fail"]
    assert "loop" in events[-1].reason


def test_self_alias_fails_instead_of_looking_like_nodata():
    """``a CNAME a`` is the degenerate loop, and must not be served as NODATA."""
    sname = Sname(DomainName("a.example.com"), DnsQType.A)
    slist = _seed_slist(DomainName("example.com"), ROOT_NS, ROOT_IP, sname, match=2)
    answers = [_record(DomainName("a.example.com"), DnsRType.CNAME, DomainName("a.example.com"))]
    response = _response(sname.qname, aa=True, answers=answers)

    events = list(classify(response, sname, slist, slist.best()))

    assert _kinds(events) == ["Cname", "Fail"]


# -------------------------------------------------------- DNAME (RFC 6672)


def test_dname_redirects_a_name_below_its_owner():
    """RFC 6672 2.2: the part of QNAME below the owner is prepended to the target.

    The DNAME is owned by an ancestor, not by QNAME, so a resolver that only
    looks at the QNAME's own records finds nothing and wrongly concludes NODATA.
    """
    sname = Sname(DomainName("foo.bar.example.com"), DnsQType.A)
    slist = _seed_slist(DomainName("example.com"), ROOT_NS, ROOT_IP, sname, match=3)
    answers = [_record(DomainName("bar.example.com"), DnsRType.DNAME, DomainName("baz.net"))]
    response = _response(sname.qname, aa=True, answers=answers)

    events = list(classify(response, sname, slist, slist.best()))

    assert _kinds(events) == ["Cname"]
    assert events[0].target == DomainName("foo.baz.net")


def test_dname_owner_itself_is_never_redirected():
    """RFC 6672 2.3: "the owner name of a DNAME RR is not redirected itself"."""
    sname = Sname(DomainName("bar.example.com"), DnsQType.A)
    slist = _seed_slist(DomainName("example.com"), ROOT_NS, ROOT_IP, sname, match=3)
    answers = [_record(DomainName("bar.example.com"), DnsRType.DNAME, DomainName("baz.net"))]
    response = _response(sname.qname, aa=True, answers=answers)

    events = list(classify(response, sname, slist, slist.best()))

    # No redirection, so the authority's empty answer for QTYPE=A is NODATA.
    assert "Cname" not in _kinds(events)
    assert _kinds(events) == ["Nodata", "Done"]


def test_dname_with_target_answered_in_the_same_response():
    """A DNAME plus the answer past it resolves in one round trip."""
    sname = Sname(DomainName("foo.bar.example.com"), DnsQType.A)
    slist = _seed_slist(DomainName("example.com"), ROOT_NS, ROOT_IP, sname, match=3)
    answers = [
        _record(DomainName("bar.example.com"), DnsRType.DNAME, DomainName("baz.net")),
        _record(DomainName("foo.baz.net"), DnsRType.A, ipaddress.IPv4Address("9.9.9.9").packed),
    ]
    response = _response(sname.qname, aa=True, answers=answers)

    events = list(classify(response, sname, slist, slist.best()))

    assert _kinds(events) == ["Cname", "Answer", "Done"]
    assert int(events[1].records[-1].rtype) == int(DnsRType.A)


def test_cname_at_the_dname_owner_wins_over_the_dname():
    """RFC 6672 2.3: data at the owner name is sourced from there, not redirected."""
    sname = Sname(DomainName("foo.bar.example.com"), DnsQType.A)
    slist = _seed_slist(DomainName("example.com"), ROOT_NS, ROOT_IP, sname, match=3)
    answers = [
        _record(DomainName("bar.example.com"), DnsRType.DNAME, DomainName("baz.net")),
        # A synthesised CNAME a server chose to include (RFC 6672 3.1).
        _record(DomainName("foo.bar.example.com"), DnsRType.CNAME, DomainName("other.test")),
        _record(DomainName("other.test"), DnsRType.A, ipaddress.IPv4Address("8.8.8.8").packed),
    ]
    response = _response(sname.qname, aa=True, answers=answers)

    events = list(classify(response, sname, slist, slist.best()))

    assert _kinds(events) == ["Cname", "Answer", "Done"]
    assert events[0].target == DomainName("other.test")


# -------------------------------------------- NODATA vs referral (RFC 2308)


def test_soa_and_ns_from_a_non_authoritative_server_is_nodata_not_a_referral():
    """RFC 2308 2.2.1: the authority section's *content* decides, not the AA bit.

    This is the shape RFC 2308 2.2.1 warns about -- a non-authoritative server
    relaying a NODATA that still carries the zone's NS records. Reading it as a
    referral would send the resolver in circles back to the same servers, because
    the NS set names the zone we are already querying.
    """
    sname = Sname(DomainName("www.example.com"), DnsQType.MX)
    slist = _seed_slist(DomainName("example.com"), ROOT_NS, ROOT_IP, sname, match=2)
    authority = [
        _soa(DomainName("example.com")),
        _record(DomainName("example.com"), DnsRType.NS, ROOT_NS),
    ]
    response = _response(sname.qname, DnsQType.MX, aa=False, nameservers=authority)

    events = list(classify(response, sname, slist, slist.best()))

    assert _kinds(events) == ["Nodata", "Done"]
    assert slist.zone == DomainName("example.com")


def test_a_referral_must_actually_get_closer():
    """RFC 1034 5.3.3 step 4b: only a *closer* zone counts as a referral."""
    sname = Sname(DomainName("host.sub.example.com"), DnsQType.A)
    slist = _seed_slist(DomainName("example.com"), ROOT_NS, ROOT_IP, sname, match=2)
    authority = [
        _record(DomainName("sub.example.com"), DnsRType.NS, DomainName("ns1.sub.example.com"))
    ]
    response = _response(sname.qname, aa=False, nameservers=authority)

    events = list(classify(response, sname, slist, slist.best()))

    assert _kinds(events) == ["Referral", "Demote"]
    assert slist.zone == DomainName("sub.example.com")
    assert slist.match == 3
    assert slist.entries[0].ns == DomainName("ns1.sub.example.com")
    # RFC 1035 section 6: ns1.sub.example.com is inside the zone it serves and
    # arrived without glue, so it is unreachable by construction. Demoting it now
    # is what stops the resolver sub-resolving it and descending into the same
    # zone again -- a descent that branches (A and AAAA) at every level.
    assert slist.entries[0].history["demoted"] is True
    assert "in-bailiwick" in slist.entries[0].history["lame"]


def test_in_bailiwick_nameserver_with_glue_is_not_demoted():
    """The lame rule keys on missing glue, not merely on being in-bailiwick.

    The identical delegation plus A glue at the target is perfectly usable, and
    demoting it would break ordinary zone delegation -- most zones do name their
    nameservers inside themselves.
    """
    sname = Sname(DomainName("host.sub.example.com"), DnsQType.A)
    slist = _seed_slist(DomainName("example.com"), ROOT_NS, ROOT_IP, sname, match=2)
    target = DomainName("ns1.sub.example.com")
    authority = [_record(DomainName("sub.example.com"), DnsRType.NS, target)]
    additional = [_record(target, DnsRType.A, ipaddress.IPv4Address("192.0.2.53").packed)]
    response = _response(sname.qname, aa=False, nameservers=authority, additional=additional)

    events = list(classify(response, sname, slist, slist.best()))

    assert _kinds(events) == ["Referral"]
    assert slist.entries[0].history["demoted"] is False
    assert slist.entries[0].addresses == [ipaddress.IPv4Address("192.0.2.53")]


def test_out_of_bailiwick_nameserver_without_glue_is_not_demoted():
    """A target outside the delegated zone may be resolved elsewhere (RFC 5625 2.6)."""
    sname = Sname(DomainName("host.sub.example.com"), DnsQType.A)
    slist = _seed_slist(DomainName("example.com"), ROOT_NS, ROOT_IP, sname, match=2)
    authority = [_record(DomainName("sub.example.com"), DnsRType.NS, DomainName("ns1.other.net"))]
    response = _response(sname.qname, aa=False, nameservers=authority)

    events = list(classify(response, sname, slist, slist.best()))

    assert _kinds(events) == ["Referral"]
    assert slist.entries[0].history["demoted"] is False
    assert slist.entries[0].addresses == []


def test_referral_glue_ignores_a_cname_at_the_target():
    """RFC 1034 5.4.1 permits an address record to be a CNAME, which is not glue.

    Accepting it would put a name where an address belongs.
    """
    sname = Sname(DomainName("host.sub.example.com"), DnsQType.A)
    slist = _seed_slist(DomainName("example.com"), ROOT_NS, ROOT_IP, sname, match=2)
    authority = [
        _record(DomainName("sub.example.com"), DnsRType.NS, DomainName("ns1.sub.example.com"))
    ]
    additional = [
        _record(DomainName("ns1.sub.example.com"), DnsRType.CNAME, DomainName("other.test")),
        _record(
            DomainName("ns1.sub.example.com"),
            DnsRType.A,
            ipaddress.IPv4Address("192.0.2.1").packed,
        ),
    ]
    response = _response(sname.qname, aa=False, nameservers=authority, additional=additional)

    list(classify(response, sname, slist, slist.best()))

    assert [str(a) for a in slist.entries[0].addresses] == ["192.0.2.1"]


def test_empty_authority_with_nothing_useful_demotes_the_server():
    """No answer, no SOA, no closer referral: the server told us nothing.

    RFC 2308 5 says such a response "SHOULD NOT be cached as there is no way to
    prevent the negative responses looping forever".
    """
    sname = Sname(DomainName("www.example.com"), DnsQType.A)
    slist = _seed_slist(DomainName("example.com"), ROOT_NS, ROOT_IP, sname, match=2)
    response = _response(sname.qname, aa=False)

    events = list(classify(response, sname, slist, slist.best()))

    assert _kinds(events) == ["Demote"]


def test_nxdomain_is_terminal():
    sname = Sname(DomainName("nx.example.com"), DnsQType.A)
    slist = _seed_slist(DomainName("example.com"), ROOT_NS, ROOT_IP, sname, match=2)
    response = _response(
        sname.qname,
        aa=True,
        rcode=DnsResponseCode.NAME_ERROR,
        nameservers=[_soa(DomainName("example.com"))],
    )

    events = list(classify(response, sname, slist, slist.best()))

    assert _kinds(events) == ["Nxdomain", "Done"]


# -------------------------------------------------- driver: chains across replies


def test_chain_across_two_responses_reanchors_and_asks_again():
    """RFC 1034 5.3.3 step 4c, end to end: the second query is for the target.

    This is the regression that mattered -- the chain used to stop at the CNAME
    and the name never resolved. Asserting on the *name queried* in the second
    request is what proves SNAME actually moved.
    """
    sname = Sname(DomainName("www.example.com"), DnsQType.A)
    slist = _seed_slist(DomainName("example.com"), ROOT_NS, ROOT_IP, sname, match=2)
    first = _response(
        sname.qname,
        aa=True,
        answers=[
            _record(DomainName("www.example.com"), DnsRType.CNAME, DomainName("web.example.net"))
        ],
    )
    second = _response(
        DomainName("web.example.net"),
        aa=True,
        answers=[
            _record(
                DomainName("web.example.net"),
                DnsRType.A,
                ipaddress.IPv4Address("93.184.216.34").packed,
            )
        ],
    )

    events = _drive(resolve_steps(sname, slist), [first, second])

    queries = [e.questions[0].name for e in events if isinstance(e, SendQuery)]
    assert queries == [DomainName("www.example.com"), DomainName("web.example.net")]
    assert _kinds(events)[-2:] == ["Answer", "Done"]
    assert sname.qname == DomainName("web.example.net")


def test_driver_fails_a_cross_response_alias_loop():
    """A loop spread over two responses must not burn the whole hop budget."""
    sname = Sname(DomainName("a.example.com"), DnsQType.A)
    slist = _seed_slist(DomainName("example.com"), ROOT_NS, ROOT_IP, sname, match=2)
    round_trip = [
        _response(
            DomainName("a.example.com"),
            aa=True,
            answers=[
                _record(DomainName("a.example.com"), DnsRType.CNAME, DomainName("b.example.com"))
            ],
        ),
        _response(
            DomainName("b.example.com"),
            aa=True,
            answers=[
                _record(DomainName("b.example.com"), DnsRType.CNAME, DomainName("a.example.com"))
            ],
        ),
    ]

    events = _drive(resolve_steps(sname, slist), round_trip * 4)

    assert _kinds(events)[-1] == "Fail"
    assert len([e for e in events if isinstance(e, SendQuery)]) == 2


def test_driver_bounds_a_long_alias_chain():
    """A pathological chain fails at the alias cap, not at MAX_HOPS."""
    sname = Sname(DomainName("host0.example.com"), DnsQType.A)
    slist = _seed_slist(DomainName("example.com"), ROOT_NS, ROOT_IP, sname, match=2)
    responses = [
        _response(
            DomainName(f"host{i}.example.com"),
            aa=True,
            answers=[
                _record(
                    DomainName(f"host{i}.example.com"),
                    DnsRType.CNAME,
                    DomainName(f"host{i + 1}.example.com"),
                )
            ],
        )
        for i in range(MAX_ALIAS_HOPS + 8)
    ]

    events = _drive(resolve_steps(sname, slist), responses)

    assert _kinds(events)[-1] == "Fail"
    assert "alias" in events[-1].reason
    assert len([e for e in events if isinstance(e, SendQuery)]) <= MAX_ALIAS_HOPS + 1


def test_reanchor_keeps_qtype_and_qclass():
    """An A query for an alias becomes an A query for the target, nothing else."""
    sname = Sname(DomainName("www.example.com"), DnsQType.A, DnsRClass.IN)
    sname.reanchor(DomainName("web.example.net"))
    assert sname.qname == DomainName("web.example.net")
    assert int(sname.qtype) == int(DnsQType.A)
    assert int(sname.qclass) == int(DnsRClass.IN)
    assert sname.questions[0].qtype == DnsQType.A
