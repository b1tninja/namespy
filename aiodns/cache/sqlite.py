"""SQLite-backed :class:`~aiodns.cache.DnsCache`.

A single ``rrset_cache`` table keyed on ``(name, qtype, qclass)`` with an
``expires_at`` column for TTL eviction. Records are stored length-prefixed
(``!H`` + bytes from :meth:`DnsRecord.__bytes__`); negative entries store
just the SOA's wire form (or empty bytes if the response carried none).
"""

from __future__ import annotations

import sqlite3
import struct

from ..enums import DnsResponseCode
from ..names import DomainName
from ..packet import DnsRecord
from . import DnsCache, NegativeEntry, PositiveEntry

_KIND_POSITIVE = 0
_KIND_NXDOMAIN = 1
_KIND_NODATA = 2

_SCHEMA = """
CREATE TABLE IF NOT EXISTS rrset_cache (
    name        TEXT    NOT NULL,
    qtype       INTEGER NOT NULL,
    qclass      INTEGER NOT NULL,
    kind        INTEGER NOT NULL,
    rcode       INTEGER NOT NULL,
    expires_at  REAL    NOT NULL,
    authoritative INTEGER NOT NULL DEFAULT 0,
    payload     BLOB    NOT NULL,
    PRIMARY KEY (name, qtype, qclass)
);
CREATE INDEX IF NOT EXISTS idx_rrset_expires ON rrset_cache(expires_at);
"""


def _pack_records(records):
    """Pack a list of :class:`DnsRecord` as length-prefixed wire bytes."""
    parts = []
    for r in records:
        b = bytes(r)
        parts.append(struct.pack("!H", len(b)) + b)
    return b"".join(parts)


def _unpack_records(payload):
    records = []
    buf = bytes(payload)
    off = 0
    while off + 2 <= len(buf):
        (n,) = struct.unpack_from("!H", buf, off)
        off += 2
        chunk = buf[off : off + n]
        off += n
        rec, _ = DnsRecord.parse(chunk, 0)
        records.append(rec)
    return records


def _name_text(name):
    """Canonical text form of ``name`` for the SQLite key.

    Case-folded, escaped, root-terminated — :attr:`DomainName.canonical_text`
    is exactly the identity a cache key needs, so ``EXAMPLE.COM``,
    ``example.com`` and ``example.com.`` collapse to one row instead of
    fragmenting into three. Escaped form also means a label containing a dot
    cannot forge a second key.
    """
    if not isinstance(name, DomainName):
        name = DomainName(str(name))
    return name.canonical_text


class SqliteDnsCache(DnsCache):
    """SQLite-backed :class:`~aiodns.cache.DnsCache`.

    ``path`` is a filesystem path or ``":memory:"`` for an ephemeral DB.
    ``time_fn`` is the cache's clock (defaults to :func:`time.time`); the
    caller's ``expires_at`` values must be expressed in the same units.
    """

    def __init__(self, path=":memory:", time_fn=None):
        super().__init__(time_fn=time_fn)
        self._conn = sqlite3.connect(path)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass

    def get(self, name, qtype, qclass):
        key_name = _name_text(name)
        qt = int(qtype)
        qc = int(qclass)
        now = self.time_fn()
        row = self._conn.execute(
            "SELECT kind, rcode, expires_at, authoritative, payload "
            "FROM rrset_cache WHERE name=? AND qtype=? AND qclass=? LIMIT 1",
            (key_name, qt, qc),
        ).fetchone()
        if row is None:
            return None
        (kind, rcode, expires_at, authoritative, payload) = row
        if expires_at <= now:
            self._conn.execute(
                "DELETE FROM rrset_cache WHERE name=? AND qtype=? AND qclass=?",
                (key_name, qt, qc),
            )
            self._conn.commit()
            return None
        if kind == _KIND_POSITIVE:
            return PositiveEntry(
                name,
                qtype,
                qclass,
                _unpack_records(payload),
                expires_at,
                bool(authoritative),
            )
        soa = None
        if payload:
            try:
                soa, _ = DnsRecord.parse(bytes(payload), 0)
            except Exception:
                soa = None
        return NegativeEntry(name, qtype, qclass, rcode, soa, expires_at)

    def put(self, entry):
        key_name = _name_text(entry.name)
        qt = int(entry.qtype)
        qc = int(entry.qclass)
        if isinstance(entry, PositiveEntry):
            kind = _KIND_POSITIVE
            rcode = int(DnsResponseCode.no_error)
            authoritative = 1 if entry.authoritative else 0
            payload = _pack_records(entry.records)
        elif isinstance(entry, NegativeEntry):
            rcode_int = int(entry.rcode)
            kind = _KIND_NXDOMAIN if rcode_int == int(DnsResponseCode.name_error) else _KIND_NODATA
            rcode = rcode_int
            authoritative = 0
            payload = bytes(entry.soa) if entry.soa is not None else b""
        else:
            raise TypeError(f"unsupported cache entry: {type(entry).__name__}")
        self._conn.execute(
            "INSERT OR REPLACE INTO rrset_cache "
            "(name, qtype, qclass, kind, rcode, expires_at, authoritative, payload) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                key_name,
                qt,
                qc,
                kind,
                rcode,
                float(entry.expires_at),
                authoritative,
                payload,
            ),
        )
        self._conn.commit()

    def __len__(self):
        (n,) = self._conn.execute("SELECT COUNT(*) FROM rrset_cache").fetchone()
        return int(n)

    def prune(self):
        now = self.time_fn()
        cur = self._conn.execute(
            "DELETE FROM rrset_cache WHERE expires_at <= ?",
            (now,),
        )
        self._conn.commit()
        return cur.rowcount or 0
