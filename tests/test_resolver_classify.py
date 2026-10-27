import ipaddress

from aiodns.enums import DnsQR, DnsQType, DnsRClass, DnsResponseCode, DnsRType
from aiodns.names import DomainName
from aiodns.packet import DnsQuestion, DnsRecord, Response
from aiodns.resolver import (
    Answer,
    Cname,
    Demote,
    Done,
    Nodata,
    Nxdomain,
    Referral,
    Slist,
    SlistEntry,
    Sname,
    classify,
)


def _make_referral(qname, new_zone, ns_targets, glue=()):
    ns_records = [DnsRecord(new_zone, DnsRType.NS, DnsRClass.IN, 0, rdata=t) for t in ns_targets]
    ar_records = [DnsRecord(t, DnsRType.A, DnsRClass.IN, 0, rdata=ip.packed) for t, ip in glue]
    return Response(
        QR=DnsQR.RESPONSE,
        AA=False,
        questions=[DnsQuestion(qname, DnsQType.A)],
        nameservers=ns_records,
        additional_records=ar_records,
    )


def _make_answer(qname, addr):
    return Response(
        QR=DnsQR.RESPONSE,
        AA=True,
        questions=[DnsQuestion(qname, DnsQType.A)],
        answers=[DnsRecord(qname, DnsRType.A, DnsRClass.IN, 0, rdata=addr.packed)],
    )


def _seed_slist(zone, ns_name, addr, sname=None, match=0):
    slist = Slist(sname)
    slist.zone = zone
    slist.match = match
    slist.entries = [SlistEntry(zone, ns_name, [addr])]
    return slist


def test_classify_referral_better_extends_slist():
    sname = Sname(DomainName("example.com"), DnsQType.A)
    slist = _seed_slist(
        DomainName("."),
        DomainName("a.root-servers.net"),
        ipaddress.IPv4Address("198.41.0.4"),
        sname=sname,
        match=0,
    )
    entry = slist.best()

    referral = _make_referral(
        DomainName("example.com"),
        DomainName("com"),
        [DomainName("a.gtld-servers.net")],
        glue=[(DomainName("a.gtld-servers.net"), ipaddress.IPv4Address("192.5.6.30"))],
    )

    steps = list(classify(referral, sname, slist, entry))
    assert len(steps) == 1
    assert isinstance(steps[0], Referral)
    assert steps[0].match_before == 0
    assert steps[0].match_after == 1
    assert slist.zone == DomainName("com")
    assert slist.match == 1
    assert slist.entries
    assert slist.entries[0].zone == DomainName("com")


def test_classify_referral_not_closer_demotes():
    sname = Sname(DomainName("example.com"), DnsQType.A)
    slist = _seed_slist(
        DomainName("com"),
        DomainName("a.gtld-servers.net"),
        ipaddress.IPv4Address("192.5.6.30"),
        sname=sname,
        match=1,
    )
    entry = slist.best()

    sideways = _make_referral(
        DomainName("example.com"),
        DomainName("org"),
        [DomainName("a0.org.afilias-nst.info")],
        glue=[(DomainName("a0.org.afilias-nst.info"), ipaddress.IPv4Address("199.19.56.1"))],
    )

    steps = list(classify(sideways, sname, slist, entry))
    assert len(steps) == 1
    assert isinstance(steps[0], Demote)
    assert "not closer" in steps[0].reason
    assert slist.zone == DomainName("com")
    assert slist.match == 1


def test_classify_authoritative_answer():
    sname = Sname(DomainName("example.com"), DnsQType.A)
    slist = _seed_slist(
        DomainName("example.com"),
        DomainName("ns.example.com"),
        ipaddress.IPv4Address("1.2.3.4"),
        sname=sname,
        match=2,
    )
    entry = slist.best()

    answer = _make_answer(DomainName("example.com"), ipaddress.IPv4Address("93.184.216.34"))
    steps = list(classify(answer, sname, slist, entry))

    assert len(steps) == 2
    assert isinstance(steps[0], Answer)
    assert len(steps[0].records) == 1
    assert isinstance(steps[1], Done)
    assert steps[1].response is answer


def test_classify_nxdomain():
    sname = Sname(DomainName("nx.example.com"), DnsQType.A)
    slist = _seed_slist(
        DomainName("example.com"),
        DomainName("ns.example.com"),
        ipaddress.IPv4Address("1.2.3.4"),
        sname=sname,
        match=2,
    )
    entry = slist.best()

    response = Response(
        QR=DnsQR.RESPONSE,
        AA=True,
        RCODE=DnsResponseCode.NAME_ERROR,
        questions=[DnsQuestion(DomainName("nx.example.com"), DnsQType.A)],
    )

    steps = list(classify(response, sname, slist, entry))
    assert len(steps) == 2
    assert isinstance(steps[0], Nxdomain)
    assert isinstance(steps[1], Done)


def test_classify_nodata_with_soa():
    sname = Sname(DomainName("example.com"), DnsQType.MX)
    slist = _seed_slist(
        DomainName("example.com"),
        DomainName("ns.example.com"),
        ipaddress.IPv4Address("1.2.3.4"),
        sname=sname,
        match=2,
    )
    entry = slist.best()

    soa = DnsRecord(DomainName("example.com"), DnsRType.SOA, DnsRClass.IN, 0, rdata=b"")
    response = Response(
        QR=DnsQR.RESPONSE,
        AA=True,
        questions=[DnsQuestion(DomainName("example.com"), DnsQType.MX)],
        nameservers=[soa],
    )

    steps = list(classify(response, sname, slist, entry))
    assert len(steps) == 2
    assert isinstance(steps[0], Nodata)
    assert steps[0].soa is soa
    assert isinstance(steps[1], Done)


def test_classify_servfail_demotes():
    sname = Sname(DomainName("example.com"), DnsQType.A)
    slist = _seed_slist(
        DomainName("."),
        DomainName("a.root-servers.net"),
        ipaddress.IPv4Address("198.41.0.4"),
        sname=sname,
        match=0,
    )
    entry = slist.best()

    response = Response(
        QR=DnsQR.RESPONSE,
        RCODE=DnsResponseCode.SERVER_FAILURE,
        questions=[DnsQuestion(DomainName("example.com"), DnsQType.A)],
    )

    steps = list(classify(response, sname, slist, entry))
    assert len(steps) == 1
    assert isinstance(steps[0], Demote)
    assert "rcode" in steps[0].reason


def test_classify_no_response_demotes():
    sname = Sname(DomainName("example.com"), DnsQType.A)
    slist = _seed_slist(
        DomainName("."),
        DomainName("a.root-servers.net"),
        ipaddress.IPv4Address("198.41.0.4"),
        sname=sname,
        match=0,
    )
    entry = slist.best()

    steps = list(classify(None, sname, slist, entry))
    assert len(steps) == 1
    assert isinstance(steps[0], Demote)
    assert "no response" in steps[0].reason


def test_classify_unassigned_rcode_demotes_without_crashing():
    """A response code we have no member for must demote, not raise.

    Regression: this path used to read ``response.RCODE.name``, and RCODE is a
    plain ``int`` whenever the header held an unassigned value -- so the
    classifier died with ``AttributeError: 'int' object has no attribute
    'name'`` on a datagram, which is the opposite of what ``DnsResponseCode
    .parse`` exists to allow. Values 11-15 are unassigned today and RFC 6891
    section 6.1.3 makes the field 12 bits wide, so a server ahead of the
    registry is expected traffic (RFC 2929 section 3.1).
    """
    sname = Sname(DomainName("example.com"), DnsQType.A)
    slist = _seed_slist(
        DomainName("."),
        DomainName("a.root-servers.net"),
        ipaddress.IPv4Address("198.41.0.4"),
        sname=sname,
        match=0,
    )
    entry = slist.best()

    response = Response(
        QR=DnsQR.RESPONSE,
        RCODE=11,
        questions=[DnsQuestion(DomainName("example.com"), DnsQType.A)],
    )
    assert not isinstance(response.RCODE, DnsResponseCode)

    steps = list(classify(response, sname, slist, entry))
    assert len(steps) == 1
    assert isinstance(steps[0], Demote)
    assert steps[0].reason == "rcode RCODE11"


def test_classify_nodata_from_non_authoritative_server():
    """SOA and no NS in the authority section is NODATA even when AA is clear.

    RFC 2308 section 2.2.1 defines this as "type 2" NODATA and recommends
    authoritative servers emit it precisely because the alternative reads as a
    referral. The classifier here used to test ``AA`` before looking at the
    authority section at all, so a non-authoritative server's NODATA -- the shape
    most recursive resolvers actually see, since the answer usually arrives from a
    cached intermediary -- went down the referral path and the lookup demoted a
    perfectly good server.
    """
    sname = Sname(DomainName("example.com"), DnsQType.MX)
    slist = _seed_slist(
        DomainName("example.com"),
        DomainName("ns.example.com"),
        ipaddress.IPv4Address("1.2.3.4"),
        sname=sname,
        match=2,
    )
    entry = slist.best()

    soa = DnsRecord(DomainName("example.com"), DnsRType.SOA, DnsRClass.IN, 3600, rdata=b"")
    response = Response(
        QR=DnsQR.RESPONSE,
        AA=False,
        questions=[DnsQuestion(DomainName("example.com"), DnsQType.MX)],
        nameservers=[soa],
    )

    steps = list(classify(response, sname, slist, entry))
    assert [type(s).__name__ for s in steps] == ["Nodata", "Done"]
    assert steps[0].soa is soa
    assert not entry.history["demoted"]


def test_classify_cname_in_authoritative_answer():
    sname = Sname(DomainName("www.example.com"), DnsQType.A)
    slist = _seed_slist(
        DomainName("example.com"),
        DomainName("ns.example.com"),
        ipaddress.IPv4Address("1.2.3.4"),
        sname=sname,
        match=2,
    )
    entry = slist.best()

    cname = DnsRecord(
        DomainName("www.example.com"),
        DnsRType.CNAME,
        DnsRClass.IN,
        0,
        rdata=DomainName("example.com"),
    )
    a = DnsRecord(
        DomainName("example.com"),
        DnsRType.A,
        DnsRClass.IN,
        0,
        rdata=ipaddress.IPv4Address("93.184.216.34").packed,
    )
    response = Response(
        QR=DnsQR.RESPONSE,
        AA=True,
        questions=[DnsQuestion(DomainName("www.example.com"), DnsQType.A)],
        answers=[cname, a],
    )

    steps = list(classify(response, sname, slist, entry))
    kinds = [type(s).__name__ for s in steps]
    assert kinds == ["Cname", "Answer", "Done"]
    assert isinstance(steps[0], Cname)
