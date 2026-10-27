import ipaddress

from aiodns.cache import MemoryDnsCache, NegativeEntry, PositiveEntry
from aiodns.enums import DnsQR, DnsQType, DnsRClass, DnsResponseCode, DnsRType
from aiodns.names import DomainName
from aiodns.packet import DnsQuestion, DnsRecord, Response
from aiodns.resolver import (
    Answer,
    Demote,
    Done,
    NeedAddress,
    Nxdomain,
    Referral,
    Resolver,
    Sbelt,
    SendQuery,
    Slist,
    SlistEntry,
    Sname,
    resolve_steps,
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


def _seed_slist(sname, zone, ns_name, addr):
    slist = Slist(sname)
    slist.zone = zone
    slist.match = sname.match_count(zone)
    slist.entries = [SlistEntry(zone, ns_name, [addr])]
    return slist


def test_resolve_steps_root_referral_then_authoritative_answer():
    sname = Sname(DomainName("example.com"), DnsQType.A)
    slist = _seed_slist(
        sname,
        DomainName("."),
        DomainName("a.root-servers.net"),
        ipaddress.IPv4Address("198.41.0.4"),
    )
    gen = resolve_steps(sname, slist)

    step = next(gen)
    assert isinstance(step, SendQuery)
    assert step.entry.zone == DomainName(".")

    referral = _make_referral(
        DomainName("example.com"),
        DomainName("com"),
        [DomainName("a.gtld-servers.net")],
        glue=[(DomainName("a.gtld-servers.net"), ipaddress.IPv4Address("192.5.6.30"))],
    )

    step = gen.send(referral)
    assert isinstance(step, Referral)
    assert step.match_after == 1

    step = next(gen)
    assert isinstance(step, SendQuery)
    assert step.entry.zone == DomainName("com")

    answer = _make_answer(DomainName("example.com"), ipaddress.IPv4Address("93.184.216.34"))

    step = gen.send(answer)
    assert isinstance(step, Answer)

    step = next(gen)
    assert isinstance(step, Done)
    assert step.response is answer


def test_resolve_steps_glueless_yields_need_address():
    sname = Sname(DomainName("example.org"), DnsQType.A)
    slist = Slist(sname)
    slist.zone = DomainName(".")
    slist.match = 0
    slist.entries = [SlistEntry(DomainName("."), DomainName("ns.glueless"), [])]

    gen = resolve_steps(sname, slist)

    step = next(gen)
    assert isinstance(step, NeedAddress)
    assert step.ns_name == DomainName("ns.glueless")

    step = gen.send([ipaddress.IPv4Address("203.0.113.1")])
    assert isinstance(step, SendQuery)
    assert step.entry.addresses[0] == ipaddress.IPv4Address("203.0.113.1")


def test_resolve_steps_two_hops_root_to_com_to_example():
    sname = Sname(DomainName("example.com"), DnsQType.A)
    slist = _seed_slist(
        sname,
        DomainName("."),
        DomainName("a.root-servers.net"),
        ipaddress.IPv4Address("198.41.0.4"),
    )
    gen = resolve_steps(sname, slist)

    step = next(gen)
    assert isinstance(step, SendQuery)
    referral_root = _make_referral(
        DomainName("example.com"),
        DomainName("com"),
        [DomainName("a.gtld-servers.net")],
        glue=[(DomainName("a.gtld-servers.net"), ipaddress.IPv4Address("192.5.6.30"))],
    )
    step = gen.send(referral_root)
    assert isinstance(step, Referral)

    step = next(gen)
    assert isinstance(step, SendQuery)
    referral_com = _make_referral(
        DomainName("example.com"),
        DomainName("example.com"),
        [DomainName("a.iana-servers.net")],
        glue=[(DomainName("a.iana-servers.net"), ipaddress.IPv4Address("199.43.135.53"))],
    )
    step = gen.send(referral_com)
    assert isinstance(step, Referral)
    assert step.match_after == 2

    step = next(gen)
    assert isinstance(step, SendQuery)
    final = _make_answer(DomainName("example.com"), ipaddress.IPv4Address("93.184.216.34"))
    step = gen.send(final)
    assert isinstance(step, Answer)
    step = next(gen)
    assert isinstance(step, Done)


def test_sbelt_copy_for_seeds_root_zone():
    sname = Sname(DomainName("example.com"), DnsQType.A)
    response = Response(
        QR=DnsQR.RESPONSE,
        AA=True,
        questions=[DnsQuestion(DomainName("."), DnsQType.NS)],
        nameservers=[
            DnsRecord(
                DomainName("."),
                DnsRType.NS,
                DnsRClass.IN,
                0,
                rdata=DomainName("a.root-servers.net"),
            ),
        ],
        additional_records=[
            DnsRecord(
                DomainName("a.root-servers.net"),
                DnsRType.A,
                DnsRClass.IN,
                0,
                rdata=ipaddress.IPv4Address("198.41.0.4").packed,
            ),
        ],
    )
    sbelt = Sbelt.from_response(response)
    slist = sbelt.copy_for(sname)
    assert slist.zone == DomainName(".")
    assert slist.match == 0
    assert len(slist.entries) == 1
    assert slist.entries[0].ns == DomainName("a.root-servers.net")
    assert slist.entries[0].addresses == [ipaddress.IPv4Address("198.41.0.4")]


def test_resolve_steps_glueless_subresolution_walks_to_authoritative_ns():
    # Reproduce the live `mitch.ns.cloudflare.com.` glueless walk that gets
    # stuck in production: wire-parsed names always carry the trailing root
    # terminator, so classify and slist.best must keep working when every
    # name in the response is absolute (FQDN) form.
    sname = Sname(DomainName("mitch.ns.cloudflare.com."), DnsQType.A)
    slist = _seed_slist(
        sname,
        DomainName("."),
        DomainName("a.root-servers.net."),
        ipaddress.IPv4Address("198.41.0.4"),
    )
    gen = resolve_steps(sname, slist)

    step = next(gen)
    assert isinstance(step, SendQuery)
    assert step.entry.zone == DomainName(".")

    referral_root = _make_referral(
        DomainName("mitch.ns.cloudflare.com."),
        DomainName("com."),
        [DomainName("a.gtld-servers.net.")],
        glue=[(DomainName("a.gtld-servers.net."), ipaddress.IPv4Address("192.5.6.30"))],
    )
    step = gen.send(referral_root)
    assert isinstance(step, Referral)
    assert step.match_after == 1

    step = next(gen)
    assert isinstance(step, SendQuery)
    assert step.entry.zone == DomainName("com.")

    referral_com = _make_referral(
        DomainName("mitch.ns.cloudflare.com."),
        DomainName("cloudflare.com."),
        [
            DomainName("ns3.cloudflare.com."),
            DomainName("ns4.cloudflare.com."),
        ],
        glue=[
            (DomainName("ns3.cloudflare.com."), ipaddress.IPv4Address("162.159.0.33")),
            (DomainName("ns4.cloudflare.com."), ipaddress.IPv4Address("162.159.1.33")),
        ],
    )
    step = gen.send(referral_com)
    assert isinstance(step, Referral)
    assert step.match_after == 2

    # The next step must be a SendQuery to one of the glued cloudflare NS —
    # if classify failed to attach glue (eg. via an `==` mismatch between
    # `ar.name` and `ns_target`), `entry.addresses` would be empty and the
    # generator would yield `NeedAddress`, sending us into an infinite
    # glueless loop instead of asking the authoritative server.
    step = next(gen)
    assert isinstance(step, SendQuery), f"expected SendQuery to a glued cloudflare NS, got {step!r}"
    assert step.entry.zone == DomainName("cloudflare.com.")
    assert step.entry.addresses, "glue should have been attached to the SLIST entry"
    assert step.entry.addresses[0] in (
        ipaddress.IPv4Address("162.159.0.33"),
        ipaddress.IPv4Address("162.159.1.33"),
    )


def test_resolve_steps_no_response_demotes_and_tries_next_entry():
    # When `_send_for_entry` reports no response (the per-query timeout in
    # `Resolver.query` hit, or the wire send failed), the driver feeds
    # `None` back into the generator. The resolver must demote the silent
    # server and immediately ask the next SLIST entry — without that, one
    # unreachable NS hangs the whole resolution until the global timeout.
    sname = Sname(DomainName("mitch.ns.cloudflare.com."), DnsQType.A)
    slist = Slist(sname)
    slist.zone = DomainName("cloudflare.com.")
    slist.match = sname.match_count(slist.zone)
    slist.entries = [
        SlistEntry(
            DomainName("cloudflare.com."),
            DomainName("ns3.cloudflare.com."),
            [ipaddress.IPv4Address("162.159.0.33")],
        ),
        SlistEntry(
            DomainName("cloudflare.com."),
            DomainName("ns4.cloudflare.com."),
            [ipaddress.IPv4Address("162.159.1.33")],
        ),
    ]

    gen = resolve_steps(sname, slist)

    first = next(gen)
    assert isinstance(first, SendQuery)
    first_ns = first.entry.ns

    demote = gen.send(None)
    assert isinstance(demote, Demote)
    assert demote.entry is first.entry
    assert demote.reason == "no response"

    nxt = next(gen)
    assert isinstance(nxt, SendQuery)
    assert nxt.entry.ns != first_ns


def test_resolve_steps_cache_short_circuits_to_answer():
    # A pre-populated cache hit must skip the network entirely: no
    # SendQuery is yielded, just Answer + Done with a synthesized response.
    sname = Sname(DomainName("example.com."), DnsQType.A)
    slist = _seed_slist(
        sname,
        DomainName("."),
        DomainName("a.root-servers.net."),
        ipaddress.IPv4Address("198.41.0.4"),
    )
    cache = MemoryDnsCache(time_fn=lambda: 1000.0)
    answer = DnsRecord(
        DomainName("example.com."),
        DnsRType.A,
        DnsRClass.IN,
        60,
        rdata=ipaddress.IPv4Address("93.184.216.34").packed,
    )
    cache.put(
        PositiveEntry(
            DomainName("example.com."),
            DnsQType.A,
            DnsRClass.IN,
            [answer],
            expires_at=1060.0,
            authoritative=True,
        )
    )

    gen = resolve_steps(sname, slist, cache)
    step = next(gen)
    assert isinstance(step, Answer)
    assert step.records[0].name == DomainName("example.com.")

    step = next(gen)
    assert isinstance(step, Done)
    assert step.response.AA is True
    assert step.response.ANCOUNT == 1


def test_resolve_steps_cache_short_circuits_to_nxdomain():
    sname = Sname(DomainName("nx.example.com."), DnsQType.A)
    slist = _seed_slist(
        sname,
        DomainName("."),
        DomainName("a.root-servers.net."),
        ipaddress.IPv4Address("198.41.0.4"),
    )
    cache = MemoryDnsCache(time_fn=lambda: 1000.0)
    soa = DnsRecord(
        DomainName("example.com."),
        DnsRType.SOA,
        DnsRClass.IN,
        60,
        rdata=b"",
    )
    cache.put(
        NegativeEntry(
            DomainName("nx.example.com."),
            DnsQType.A,
            DnsRClass.IN,
            DnsResponseCode.NAME_ERROR,
            soa,
            expires_at=1060.0,
        )
    )

    gen = resolve_steps(sname, slist, cache)
    step = next(gen)
    assert isinstance(step, Nxdomain)
    step = next(gen)
    assert isinstance(step, Done)
    assert DnsResponseCode.NAME_ERROR == step.response.RCODE


def test_resolve_steps_populates_cache_after_authoritative_answer():
    # An authoritative answer arriving from the network must be written
    # back to the cache so the next lookup short-circuits.
    sname = Sname(DomainName("example.com."), DnsQType.A)
    slist = _seed_slist(
        sname,
        DomainName("example.com."),
        DomainName("ns.example.com."),
        ipaddress.IPv4Address("1.2.3.4"),
    )
    cache = MemoryDnsCache(time_fn=lambda: 1000.0)
    gen = resolve_steps(sname, slist, cache)

    step = next(gen)
    assert isinstance(step, SendQuery)

    answer_record = DnsRecord(
        DomainName("example.com."),
        DnsRType.A,
        DnsRClass.IN,
        300,
        rdata=ipaddress.IPv4Address("93.184.216.34").packed,
    )
    response = Response(
        QR=DnsQR.RESPONSE,
        AA=True,
        questions=[DnsQuestion(DomainName("example.com."), DnsQType.A)],
        answers=[answer_record],
    )

    step = gen.send(response)
    assert isinstance(step, Answer)
    step = next(gen)
    assert isinstance(step, Done)

    hit = cache.get(DomainName("example.com."), DnsQType.A, DnsRClass.IN)
    assert isinstance(hit, PositiveEntry)
    assert hit.authoritative is True
    assert hit.expires_at == 1000.0 + 300


def test_resolver_dns_suffix_is_off_by_default():
    # The base resolver does not assume any DNS suffix unless one is configured.
    assert Resolver.dns_suffix is None


def test_resolver_dns_suffix_qualifies_relative_sname():
    # The resolver's job is to fill in the suffix for relative names.
    class _R(Resolver):
        dns_suffix = "corp.example.com"

    qualified = DomainName("host").qualify(dns_suffix=_R.dns_suffix)
    assert qualified.is_absolute
    assert str(qualified) == "host.corp.example.com."

    # A trailing root terminator on the SNAME prevents the suffix from being
    # assumed — the wire-form FQDN passes through unchanged.
    absolute = DomainName("host.")
    assert absolute.qualify(dns_suffix=_R.dns_suffix) is absolute
