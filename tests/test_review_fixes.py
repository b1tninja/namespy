"""Guards for the fixes from the correctness review.

Each test locks one behaviour the audit found missing or fail-open, and cites
the same obligation the fix does:

* RFC 2181 section 8 -- a served TTL above 2147483647 becomes exactly that
* RFC 9267 section 5 -- RDATA is fully accounted for, in both directions
* RFC 1035 section 3.3.14 -- TXT carries at least one <character-string>
* RFC 1035 section 3.1 -- no wire form exists for an interior empty label
* RFC 5358 section 4.2 -- the attacker-controlled path stays quiet at default
* RFC 5625 section 6.2 -- an overloaded server drops rather than accumulates
"""

import asyncio
import ipaddress
import logging

import pytest

from namespy.cache import MemoryDnsCache
from namespy.enums import DnsRClass, DnsRType
from namespy.names import DomainName, DomainNameError, unescape_label
from namespy.packet import DnsPacket, DnsPacketParseError, DnsQuestion, DnsRecord, Query
from namespy.rdata import RData_NS, RData_TXT
from namespy.resolver import RecursiveResolver
from namespy.server import DnsServer

MAX_SERVABLE = 0x7FFFFFFF


# ---------------------------------------------------------------- TTL clamp


def test_record_ttl_is_clamped_not_masked() -> None:
    """RFC 2181 section 8: 0xFFFFFFFF becomes 2147483647, not a ~136y cache entry."""
    assert DnsRecord("a.example.", DnsRType.TXT, ttl=0xFFFFFFFF).ttl == MAX_SERVABLE
    assert DnsRecord("a.example.", DnsRType.TXT, ttl=-1).ttl == 0
    assert DnsRecord("a.example.", DnsRType.TXT, ttl=60).ttl == 60


# ------------------------------------------------- single-name trailing data


def _ns_record_wire(rdata: bytes, rdlength: int | None = None) -> bytes:
    rdlength = len(rdata) if rdlength is None else rdlength
    return (
        b"\x00\x00\x81\x80\x00\x00\x00\x01\x00\x00\x00\x00"
        b"\x02ns\x07example\x03com\x00"
        b"\x00\x02\x00\x01\x00\x00\x00\x40" + rdlength.to_bytes(2, "big") + rdata
    )


def test_ns_with_trailing_octet_is_refused() -> None:
    """NS/CNAME/PTR/DNAME must fail closed like MX/SRV/SOA already do."""
    rdata = b"\x03foo\x00\xff"  # a name plus one octet nothing accounts for
    with pytest.raises(DnsPacketParseError, match="trailing"):
        DnsPacket.parse(_ns_record_wire(rdata))


def test_ns_exact_rdata_still_accepted() -> None:
    packet, _ = DnsPacket.parse(_ns_record_wire(b"\x03foo\x00"))
    assert packet.answers[0].rdata == RData_NS(DomainName("foo."))


def test_txt_empty_rdata_is_refused() -> None:
    """RFC 1035 section 3.3.14 requires one or more character-strings."""
    with pytest.raises(DnsPacketParseError, match="character-string"):
        RData_TXT.parse_from(b"", 0, 0)


# ------------------------------------------------------------- name issues


def test_interior_empty_label_is_refused_not_erased() -> None:
    """ "a..b" is a distinct name with no wire form; it must not encode as "a.b"."""
    assert DomainName("a..b") != DomainName("a.b")
    with pytest.raises(DomainNameError, match="empty label"):
        bytes(DomainName("a..b"))


def test_non_ascii_digit_escape_does_not_raise_value_error() -> None:
    """A digit-like non-ASCII character must not enter the \\DDD decoder.

    The superscript-two character satisfies isdigit(), so a bare isdigit()
    test let it reach int() and escape as ValueError rather than the
    DomainNameError (or literal-octet path) callers are built for.
    """
    assert unescape_label("\u00b2") == b"\xb2"  # literal, latin-1 encodable
    assert unescape_label("\\\u00b2") == b"\xb2"  # backslash + non-ASCII digit
    assert unescape_label("\\127") == b"\x7f"  # the real escape still works


# ------------------------------------------------------------ offset metadata

MESSAGE = (
    b"\x12\x34\x81\x80\x00\x00\x00\x01\x00\x00\x00\x00"
    b"\x07example\x03com\x00"
    b"\x00\x01\x00\x01"
    b"\xc0\x0c"  # answer NAME: pointer to offset 12
    b"\x00\x01\x00\x01\x00\x00\x00\x40\x00\x04\x7f\x00\x00\x01"
)


def test_parsed_name_offset_is_where_the_name_starts() -> None:
    """The constructor documents `offset` as the name's start in `buffer`;
    a compression pointer used to overwrite it with where the record resumes."""
    name, end = DomainName.parse_from(MESSAGE, 29)
    assert name.offset == 29
    assert end == 31
    assert str(name) == "example.com."


# ------------------------------------------------------------ pending hygiene


async def test_cancellation_releases_the_pending_slot() -> None:
    """Abandoning the wait must not leave the (packet, future) entry behind."""
    resolver = RecursiveResolver(cache=MemoryDnsCache())
    query = Query(questions=[DnsQuestion(DomainName("example.com."), DnsRType.A)])
    key = ("198.51.100.53", query.ID, "example.com.", int(DnsRType.A), int(DnsRClass.IN))
    future: asyncio.Future = asyncio.get_running_loop().create_future()
    resolver.queue[key] = (query, future)

    waiter = asyncio.create_task(
        resolver._await_udp(future, key, query, ipaddress.IPv4Address("198.51.100.53"))
    )
    await asyncio.sleep(0)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    assert key not in resolver.queue


# ------------------------------------------------------------- log hygiene


def test_malformed_datagram_logs_at_debug(caplog) -> None:
    """The attacker-controlled path must not raise its own log level: one
    quiet line per datagram, everything available at debug."""
    resolver = RecursiveResolver(cache=MemoryDnsCache())
    with caplog.at_level(logging.DEBUG, logger="namespy.resolver"):
        resolver.datagram_received(b"\xff\xff\xff", ("198.51.100.53", 53))
    assert caplog.records, "the drop should still be visible at debug level"
    assert all(r.levelno <= logging.DEBUG for r in caplog.records)


# --------------------------------------------------------- server backpressure


async def test_server_drops_instead_of_spawning_without_bound() -> None:
    """The spawn itself must be bounded: an ingress flood may not mint one
    coroutine per datagram before any semaphore is consulted. A little
    queueing survives (the semaphore still orders lookups); unbounded does
    not."""
    resolver = RecursiveResolver(cache=MemoryDnsCache())
    server = DnsServer(resolver, max_concurrent_lookups=2)
    server.transport = type("T", (), {"sendto": staticmethod(lambda *_a: None)})()

    query = Query(questions=[DnsQuestion(DomainName("example.com."), DnsRType.A)])
    wire = bytes(query)
    for _ in range(10):
        server.datagram_received(wire, ("192.0.2.9", 40000))
    assert len(server._tasks) <= 4  # 2 slots + 2 queued, then dropped
    for task in list(server._tasks):
        task.cancel()
    await asyncio.gather(*server._tasks, return_exceptions=True)
