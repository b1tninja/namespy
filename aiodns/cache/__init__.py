"""DNS cache (RFC 1034 §7.4 / RFC 2308) package: abstract base + backings.

Per-RRset caching keyed on ``(qname, qtype, qclass)``. Entries carry their
own absolute expiry deadline in the cache's ``time_fn`` units (defaults
to wall-clock seconds). Concrete backings:

* :class:`MemoryDnsCache` — process-local dict with optional LRU bound.
* :class:`SqliteDnsCache` — SQLite, ephemeral or on-disk (see :mod:`aiodns.cache.sqlite`).

The :class:`aiodns.resolver.RecursiveResolver` consults the cache at the
top of each :func:`aiodns.resolver.resolve_steps` iteration before sending
any query, and writes back positive/negative results when an authoritative
response classifies as ``Answer`` / ``Nodata`` / ``Nxdomain``.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections import OrderedDict

from ..enums import DnsResponseCode
from ..names import DomainName


def _key(name, qtype, qclass):
    """Canonical cache key: ``(label_tuple, qtype_int, qclass_int)``.

    Names are case-folded and the trailing root terminator is stripped, so
    ``"example.com"`` and ``"EXAMPLE.com."`` collide on the same key (RFC
    1035 §3.1: case is not significant, and the wire form is always
    absolute). qtype/qclass are coerced to plain ints so callers may pass
    either an :class:`enum.IntEnum` or a raw integer.
    """
    if not isinstance(name, DomainName):
        name = DomainName(str(name))
    return (name._labels(), int(qtype), int(qclass))


class CacheEntry:
    """Base class for cache entries.

    Each entry is keyed on ``(name, qtype, qclass)`` and carries an absolute
    expiry deadline in the owning cache's ``time_fn`` units.
    """

    def __init__(self, name, qtype, qclass, expires_at):
        if not isinstance(name, DomainName):
            name = DomainName(str(name))
        self.name = name
        self.qtype = qtype
        self.qclass = qclass
        self.expires_at = float(expires_at)

    @property
    def key(self):
        return _key(self.name, self.qtype, self.qclass)

    def expired(self, now):
        return now >= self.expires_at


class PositiveEntry(CacheEntry):
    """Cached positive RRset (RFC 1034 §7.4)."""

    def __init__(self, name, qtype, qclass, records, expires_at, authoritative=False):
        super().__init__(name, qtype, qclass, expires_at)
        self.records = list(records)
        self.authoritative = bool(authoritative)

    def __repr__(self):
        return (
            f"<PositiveEntry {self.name}/{self.qtype} "
            f"n={len(self.records)} aa={self.authoritative}>"
        )


class NegativeEntry(CacheEntry):
    """Cached negative response (RFC 2308).

    ``rcode`` distinguishes NXDOMAIN (``DnsResponseCode.NAME_ERROR``) from
    NODATA (``DnsResponseCode.NO_ERROR`` with empty answer). ``soa`` is the
    record from the authority section that established the TTL ceiling
    (may be ``None`` if the upstream did not return one — the caller is
    expected to refuse to cache in that case).
    """

    def __init__(self, name, qtype, qclass, rcode, soa, expires_at):
        super().__init__(name, qtype, qclass, expires_at)
        try:
            rcode = DnsResponseCode(int(rcode))
        except ValueError:
            pass
        self.rcode = rcode
        self.soa = soa

    def __repr__(self):
        return f"<NegativeEntry {self.name}/{self.qtype} rcode={self.rcode}>"


class DnsCache(ABC):
    """Abstract per-RRset DNS cache.

    Concrete subclasses choose their storage and serialization. They are
    expected to evict expired entries on read; :meth:`prune` is an explicit
    sweep callers may invoke to reclaim space.
    """

    def __init__(self, time_fn=None):
        self.time_fn = time_fn or time.time

    @abstractmethod
    def get(self, name, qtype, qclass):
        """Return a non-expired :class:`CacheEntry` or ``None``."""

    @abstractmethod
    def put(self, entry):
        """Store ``entry``, replacing any existing entry under the same key."""

    @abstractmethod
    def __len__(self): ...

    def prune(self):
        """Sweep expired entries and return how many were removed."""
        return 0


class MemoryDnsCache(DnsCache):
    """Process-local dict-backed :class:`DnsCache`.

    With ``max_entries`` set, eviction is LRU (least-recently-*used*, where
    "use" is :meth:`get` or :meth:`put`).
    """

    def __init__(self, max_entries=None, time_fn=None):
        super().__init__(time_fn=time_fn)
        self._entries: OrderedDict = OrderedDict()
        self.max_entries = max_entries

    def get(self, name, qtype, qclass):
        key = _key(name, qtype, qclass)
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry.expired(self.time_fn()):
            del self._entries[key]
            return None
        self._entries.move_to_end(key)
        return entry

    def put(self, entry):
        key = entry.key
        if key in self._entries:
            del self._entries[key]
        self._entries[key] = entry
        if self.max_entries is not None:
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)

    def __len__(self):
        return len(self._entries)

    def prune(self):
        now = self.time_fn()
        keys = [k for k, e in self._entries.items() if e.expired(now)]
        for k in keys:
            del self._entries[k]
        return len(keys)


from .sqlite import SqliteDnsCache  # noqa: E402

__all__ = [
    "CacheEntry",
    "DnsCache",
    "MemoryDnsCache",
    "NegativeEntry",
    "PositiveEntry",
    "SqliteDnsCache",
]
