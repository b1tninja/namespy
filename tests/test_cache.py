import ipaddress

import pytest

from namespy.cache import (
    DnsCache,
    MemoryDnsCache,
    NegativeEntry,
    PositiveEntry,
    SqliteDnsCache,
)
from namespy.enums import DnsRClass, DnsResponseCode, DnsRType
from namespy.names import DomainName
from namespy.packet import DnsRecord


class _Clock:
    """Manually-advanced clock for deterministic TTL testing."""

    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def _a_record(name="example.com.", ttl=300, ip="93.184.216.34"):
    return DnsRecord(
        DomainName(name),
        DnsRType.A,
        DnsRClass.IN,
        ttl,
        rdata=ipaddress.IPv4Address(ip).packed,
    )


@pytest.fixture(
    params=[
        pytest.param("memory", id="memory"),
        pytest.param("sqlite", id="sqlite"),
    ]
)
def make_cache(request):
    """Factory: ``make_cache(clock) -> DnsCache``.

    Parametrized so every cache test runs against both the in-memory and
    SQLite backings, ensuring the ABC contract holds for each.
    """
    kind = request.param

    def _factory(clock):
        if kind == "memory":
            return MemoryDnsCache(time_fn=clock)
        return SqliteDnsCache(":memory:", time_fn=clock)

    return _factory


def test_cache_is_dnscache(make_cache):
    cache = make_cache(_Clock())
    assert isinstance(cache, DnsCache)
    assert len(cache) == 0


def test_positive_entry_round_trip(make_cache):
    clock = _Clock()
    cache = make_cache(clock)
    rec = _a_record()
    cache.put(
        PositiveEntry(
            DomainName("example.com."),
            DnsRType.A,
            DnsRClass.IN,
            [rec],
            expires_at=clock.t + 300,
            authoritative=True,
        )
    )
    got = cache.get(DomainName("example.com."), DnsRType.A, DnsRClass.IN)
    assert isinstance(got, PositiveEntry)
    assert got.authoritative is True
    assert len(got.records) == 1
    assert got.records[0].name == DomainName("example.com.")
    assert got.records[0].rtype == DnsRType.A


def test_positive_entry_expires_on_read(make_cache):
    clock = _Clock()
    cache = make_cache(clock)
    cache.put(
        PositiveEntry(
            DomainName("example.com."),
            DnsRType.A,
            DnsRClass.IN,
            [_a_record()],
            expires_at=clock.t + 10,
        )
    )
    assert cache.get(DomainName("example.com."), DnsRType.A, DnsRClass.IN) is not None
    clock.t += 20
    assert cache.get(DomainName("example.com."), DnsRType.A, DnsRClass.IN) is None
    # Expired entry must be evicted on read so it does not linger.
    assert len(cache) == 0


def test_nxdomain_round_trip(make_cache):
    clock = _Clock()
    cache = make_cache(clock)
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
            DnsRType.A,
            DnsRClass.IN,
            DnsResponseCode.NAME_ERROR,
            soa,
            clock.t + 60,
        )
    )
    got = cache.get(DomainName("nx.example.com."), DnsRType.A, DnsRClass.IN)
    assert isinstance(got, NegativeEntry)
    assert got.rcode == DnsResponseCode.NAME_ERROR


def test_nodata_round_trip(make_cache):
    clock = _Clock()
    cache = make_cache(clock)
    soa = DnsRecord(
        DomainName("example.com."),
        DnsRType.SOA,
        DnsRClass.IN,
        60,
        rdata=b"",
    )
    cache.put(
        NegativeEntry(
            DomainName("example.com."),
            DnsRType.MX,
            DnsRClass.IN,
            DnsResponseCode.NO_ERROR,
            soa,
            clock.t + 60,
        )
    )
    got = cache.get(DomainName("example.com."), DnsRType.MX, DnsRClass.IN)
    assert isinstance(got, NegativeEntry)
    assert got.rcode == DnsResponseCode.NO_ERROR


def test_case_and_trailing_dot_collapse_to_one_key(make_cache):
    # RFC 1035 §3.1: case is not significant, and the wire form is always
    # absolute. The cache key must reflect that — different presentation
    # forms of the same wire name share a single entry.
    clock = _Clock()
    cache = make_cache(clock)
    cache.put(
        PositiveEntry(
            DomainName("Example.Com."),
            DnsRType.A,
            DnsRClass.IN,
            [_a_record()],
            clock.t + 300,
        )
    )
    got = cache.get(DomainName("example.com"), DnsRType.A, DnsRClass.IN)
    assert isinstance(got, PositiveEntry)


def test_prune_removes_expired(make_cache):
    clock = _Clock()
    cache = make_cache(clock)
    cache.put(
        PositiveEntry(
            DomainName("a.example."),
            DnsRType.A,
            DnsRClass.IN,
            [_a_record("a.example.")],
            clock.t + 1,
        )
    )
    cache.put(
        PositiveEntry(
            DomainName("b.example."),
            DnsRType.A,
            DnsRClass.IN,
            [_a_record("b.example.")],
            clock.t + 100,
        )
    )
    clock.t += 10
    n = cache.prune()
    assert n == 1
    assert len(cache) == 1
    assert cache.get(DomainName("b.example."), DnsRType.A, DnsRClass.IN) is not None


def test_memory_lru_evicts_oldest():
    clock = _Clock()
    cache = MemoryDnsCache(max_entries=2, time_fn=clock)
    cache.put(
        PositiveEntry(
            DomainName("a.example."),
            DnsRType.A,
            DnsRClass.IN,
            [_a_record("a.example.")],
            clock.t + 1000,
        )
    )
    cache.put(
        PositiveEntry(
            DomainName("b.example."),
            DnsRType.A,
            DnsRClass.IN,
            [_a_record("b.example.")],
            clock.t + 1000,
        )
    )
    cache.get(DomainName("a.example."), DnsRType.A, DnsRClass.IN)  # touch a
    cache.put(
        PositiveEntry(
            DomainName("c.example."),
            DnsRType.A,
            DnsRClass.IN,
            [_a_record("c.example.")],
            clock.t + 1000,
        )
    )
    assert cache.get(DomainName("b.example."), DnsRType.A, DnsRClass.IN) is None
    assert cache.get(DomainName("a.example."), DnsRType.A, DnsRClass.IN) is not None
    assert cache.get(DomainName("c.example."), DnsRType.A, DnsRClass.IN) is not None


def test_put_replaces_existing(make_cache):
    clock = _Clock()
    cache = make_cache(clock)
    cache.put(
        PositiveEntry(
            DomainName("example.com."),
            DnsRType.A,
            DnsRClass.IN,
            [_a_record(ip="1.1.1.1")],
            clock.t + 300,
        )
    )
    cache.put(
        PositiveEntry(
            DomainName("example.com."),
            DnsRType.A,
            DnsRClass.IN,
            [_a_record(ip="2.2.2.2")],
            clock.t + 300,
        )
    )
    assert len(cache) == 1
    got = cache.get(DomainName("example.com."), DnsRType.A, DnsRClass.IN)
    assert ipaddress.IPv4Address(bytes(got.records[0].rdata)) == ipaddress.IPv4Address("2.2.2.2")
