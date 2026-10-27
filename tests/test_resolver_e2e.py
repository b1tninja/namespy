"""End-to-end iterative resolution against canned responses, with no sockets.

The rest of the resolver suite tests ``classify`` and ``resolve_steps`` in
isolation. This drives the real :meth:`RecursiveResolver.resolve` through a
complete walk -- packaged root hints, a root referral, a ``.com`` referral with
glue, an authoritative answer -- by replacing only ``_send_for_entry``. That
keeps the generator, the Sbelt/Slist bookkeeping, glue extraction, caching, ID
propagation and trace building all on the path under test, which is what makes
it worth having alongside the unit tests.
"""

import ipaddress

import pytest

from aiodns.cache import MemoryDnsCache
from aiodns.names import DomainName
from aiodns.packet import DnsQuestion, DnsRecord, Query, Response
from aiodns.rdata import RData_A, RData_AAAA, RData_NS, RData_SOA
from aiodns.resolver import Demote, RecursiveResolver

GTLD = DomainName("a.gtld-servers.net.")
GTLD_IP = ipaddress.IPv4Address("192.5.6.4")
NS_EX = DomainName("ns1.example.com.")
NS_EX_IP = ipaddress.IPv4Address("198.51.100.10")
HOST = DomainName("www.example.com.")
HOST_IP = ipaddress.IPv4Address("93.184.216.34")
#: Never a legitimate destination in any test here, so its appearance in the
#: send log is unambiguous evidence that off-site data steered the walk.
EVIL_IP = ipaddress.IPv4Address("203.0.113.66")

A_T, NS_T, SOA_T, AAAA_T = 1, 2, 6, 28


def _referral(owner, target, glue_name=None, glue_ip=None):
    nameservers = [DnsRecord(owner, NS_T, 1, 172800, rdata=RData_NS(target))]
    additional = []
    if glue_ip is not None:
        rtype = A_T if glue_ip.version == 4 else AAAA_T
        codec = RData_A if glue_ip.version == 4 else RData_AAAA
        additional = [DnsRecord(glue_name, rtype, 1, 172800, rdata=codec(glue_ip))]
    return Response(
        ID=1,
        QR=1,
        questions=[DnsQuestion(HOST, A_T, 1)],
        nameservers=nameservers,
        additional_records=additional,
    )


def root_referral():
    return _referral(DomainName("com."), GTLD, GTLD, GTLD_IP)


def zone_referral():
    return _referral(DomainName("example.com."), NS_EX, NS_EX, NS_EX_IP)


def authoritative():
    soa = DnsRecord(
        DomainName("example.com."),
        SOA_T,
        1,
        900,
        rdata=RData_SOA(NS_EX, DomainName("hostmaster.example.com."), 1, 7200, 3600, 1209600, 3600),
    )
    return Response(
        ID=1,
        QR=1,
        AA=True,
        RA=True,
        questions=[DnsQuestion(HOST, A_T, 1)],
        answers=[DnsRecord(HOST, A_T, 1, 300, rdata=RData_A(HOST_IP))],
        nameservers=[soa],
    )


def _as_name(name):
    """Canonical lowercase absolute text, for use as a dict key."""
    if isinstance(name, DomainName):
        return name.canonical_text
    return DomainName(name).canonical_text


class FakeNetwork:
    """Stand in for ``_send_for_entry``, recording where each query went.

    Answers are chosen by question name first, then by destination address, then
    a fallback. Name-first matters because a sub-resolution (an NS target's own
    address) asks a *different* name, and a purely address-keyed fake would hand
    it the referral meant for the main query -- which would then be interpreted as
    an answer for the wrong name.

    Addresses are the keys that distinguish hops: a root server address means
    "return the .com referral", the gTLD address means "return the zone
    referral", and so on.
    """

    def __init__(self, by_address, default=None, by_name=None):
        self.by_address = by_address
        self.default = default
        self.by_name = {_as_name(name): handler for name, handler in (by_name or {}).items()}
        self.sent = []

    async def __call__(self, entry, questions):
        address = entry.addresses[0] if entry.addresses else None
        qname = questions[0].name
        self.sent.append((str(entry.ns), str(address)))
        return self.by_name.get(_as_name(qname), self.by_address.get(address, self.default))


@pytest.fixture
def resolver():
    return RecursiveResolver(cache=MemoryDnsCache())


def _wire(resolver, network):
    resolver._send_for_entry = network
    return resolver


async def test_full_iterative_walk(resolver):
    network = FakeNetwork({GTLD_IP: zone_referral(), NS_EX_IP: authoritative()}, root_referral())
    _wire(resolver, network)

    response = await resolver.resolve(Query(questions=[DnsQuestion(HOST, A_T, 1)], ID=0x1234))

    targets = [target for target, _ in network.sent]
    # Hints preserve the case they were written in; comparison is what is
    # case-insensitive (RFC 1035 section 3.1), so compare upper-cased here.
    assert targets[0].upper().endswith("ROOT-SERVERS.NET.")
    assert [t.lower() for t in targets[1:]] == [
        "a.gtld-servers.net.",
        "ns1.example.com.",
    ]
    assert response.AA is True
    assert len(response.answers) == 1
    assert bytes(response.answers[0].rdata) == HOST_IP.packed
    # RFC 5452 section 5: the reply must carry the query's identifier back.
    assert response.ID == 0x1234


async def test_packaged_root_hints_are_loaded(resolver):
    """Constructing a resolver must not need the network (RFC 8106 section 2)."""
    assert len(resolver.sbelt.entries) == 13
    assert all(
        entry.ns.is_subdomain_of(DomainName("root-servers.net."))
        for entry in resolver.sbelt.entries
    )
    # Both families, so an IPv6-only host can still start a walk.
    families = {address.version for entry in resolver.sbelt.entries for address in entry.addresses}
    assert families == {4, 6}


async def test_second_lookup_is_served_from_cache(resolver):
    network = FakeNetwork({GTLD_IP: zone_referral(), NS_EX_IP: authoritative()}, root_referral())
    _wire(resolver, network)

    await resolver.resolve(Query(questions=[DnsQuestion(HOST, A_T, 1)]))
    network.sent.clear()

    again = await resolver.resolve(Query(questions=[DnsQuestion(HOST, A_T, 1)]))
    assert network.sent == []
    assert bytes(again.answers[0].rdata) == HOST_IP.packed


async def test_glueless_referral_resolves_the_target(resolver):
    """An out-of-bailiwick NS with no glue is worth a sub-resolution.

    ``dns-sys.example.org.`` sits outside ``example.com.``, so its address is
    obtainable from elsewhere and RFC 5625 section 2.6 permits asking. The
    sub-resolution has no address yet, so it arrives with ``addresses`` empty and
    lands on the ``None`` key.
    """
    out_of_bailiwick = DomainName("dns-sys.example.org.")
    glueless = Response(
        ID=1,
        QR=1,
        questions=[DnsQuestion(HOST, A_T, 1)],
        nameservers=[
            DnsRecord(
                DomainName("example.com."),
                NS_T,
                1,
                172800,
                rdata=RData_NS(out_of_bailiwick),
            )
        ],
    )
    ns_answer = Response(
        ID=1,
        QR=1,
        questions=[DnsQuestion(out_of_bailiwick, A_T, 1)],
        answers=[DnsRecord(out_of_bailiwick, A_T, 1, 3600, rdata=RData_A(NS_EX_IP))],
    )
    network = FakeNetwork(
        {GTLD_IP: glueless, NS_EX_IP: authoritative()},
        root_referral(),
        by_name={out_of_bailiwick: ns_answer},
    )
    _wire(resolver, network)

    response = await resolver.resolve(Query(questions=[DnsQuestion(HOST, A_T, 1)]))
    assert response is not None
    assert bytes(response.answers[0].rdata) == HOST_IP.packed
    assert str(NS_EX_IP) in [address for _, address in network.sent]


async def test_in_bailiwick_glueless_is_lame_not_recursed(resolver):
    """A nameserver inside its own zone with no glue is lame, not retryable.

    RFC 1035 section 6: reaching it would require having reached it. Before this
    check the resolver sub-resolved the target, descended back into the same
    zone, and recursed -- two branches per level for A and AAAA -- instead of
    failing. The test would hang rather than merely fail if that regressed.
    """
    glueless = Response(
        ID=1,
        QR=1,
        questions=[DnsQuestion(HOST, A_T, 1)],
        nameservers=[DnsRecord(DomainName("example.com."), NS_T, 1, 172800, rdata=RData_NS(NS_EX))],
    )
    network = FakeNetwork({GTLD_IP: glueless, NS_EX_IP: authoritative()}, root_referral())
    _wire(resolver, network)

    response = await resolver.resolve(Query(questions=[DnsQuestion(HOST, A_T, 1)]))
    assert response is None
    assert str(NS_EX_IP) not in [address for _, address in network.sent]
    # Exactly one hop per zone: root, then .com -- no descent spiral.
    assert len(network.sent) == 2
    assert any(
        isinstance(event, Demote) and "in-bailiwick" in event.reason
        for event in resolver.last_trace.events
    )


async def test_off_site_answer_is_not_used_as_glue(resolver):
    """A sub-resolution answer for the wrong name must not redirect the walk.

    Same shape as the glueless test, but the address returned belongs to
    ``evil.example.`` -- if it were accepted, the next query would go to it.
    RFC 5625 section 2.5 requires data to be used only for the name asked.
    """
    out_of_bailiwick = DomainName("dns-sys.example.org.")
    glueless = Response(
        ID=1,
        QR=1,
        questions=[DnsQuestion(HOST, A_T, 1)],
        nameservers=[
            DnsRecord(
                DomainName("example.com."),
                NS_T,
                1,
                172800,
                rdata=RData_NS(out_of_bailiwick),
            )
        ],
    )
    bogus = Response(
        ID=1,
        QR=1,
        questions=[DnsQuestion(out_of_bailiwick, A_T, 1)],
        answers=[DnsRecord(DomainName("evil.example."), A_T, 1, 3600, rdata=RData_A(EVIL_IP))],
    )
    network = FakeNetwork(
        {GTLD_IP: glueless, NS_EX_IP: authoritative()},
        root_referral(),
        by_name={out_of_bailiwick: bogus},
    )
    _wire(resolver, network)

    await resolver.resolve(Query(questions=[DnsQuestion(HOST, A_T, 1)]))
    destinations = [address for _, address in network.sent]
    assert str(EVIL_IP) not in destinations


async def test_trace_is_attached_and_renders(resolver):
    network = FakeNetwork({GTLD_IP: zone_referral(), NS_EX_IP: authoritative()}, root_referral())
    _wire(resolver, network)

    response = await resolver.resolve(Query(questions=[DnsQuestion(HOST, A_T, 1)]))
    mermaid = response.trace.to_mermaid()
    assert mermaid.startswith("sequenceDiagram")
    # Participants are zones, not servers: the diagram tracks the descent.
    assert "participant Z0 as ." in mermaid
    assert "com." in mermaid
    assert "referral example.com." in mermaid
    assert "AA, 1 records" in mermaid


async def test_resolve_rejects_bad_input(resolver):
    with pytest.raises(TypeError, match="expects a DnsPacket"):
        await resolver.resolve("not a packet")
    with pytest.raises(ValueError, match="at least one question"):
        await resolver.resolve(Query(questions=[]))
    mixed = Query(
        questions=[
            DnsQuestion(HOST, A_T, 1),
            DnsQuestion(DomainName("other.example."), A_T, 1),
        ]
    )
    with pytest.raises(ValueError, match="must agree on name and class"):
        await resolver.resolve(mixed)
