"""SQLite-backed :class:`~namespy.cache.DnsCache`.

A single ``rrset_cache`` table keyed on ``(name, qtype, qclass)`` with an
``expires_at`` column for TTL eviction. Records are stored length-prefixed
(``!H`` + bytes from :meth:`DnsRecord.__bytes__`); negative entries store
just the SOA's wire form (or empty bytes if the response carried none).

Because :meth:`DnsRecord.__bytes__` emits pointer-free RDATA, a stored row can be
re-parsed in isolation: a record whose name arrived by compression pointer in the
original datagram is written with full labels, so the offset it once pointed to
does not have to exist for the row to decode.

Use it as a context manager, or call :meth:`close`; the connection is also
released on garbage collection, but only a deterministic close returns the file
descriptor when a long-running resolver drops a cache on reload.
"""

from __future__ import annotations

import logging
import sqlite3
import struct

from ..enums import DnsResponseCode
from ..names import DomainName
from ..packet import DnsRecord
from ..wire import DnsPacketParseError
from . import DnsCache, NegativeEntry, PositiveEntry

LOGGER = logging.getLogger(__name__)

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
    """SQLite-backed :class:`~namespy.cache.DnsCache`.

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
        """Close the connection, tolerating one that is already gone.

        Narrowed to :class:`sqlite3.Error` rather than bare :class:`Exception`:
        a double close is ordinary (an explicit call plus garbage collection),
        but an :class:`AttributeError` here is a bug and should not be hidden by
        a best-effort cleanup.
        """
        try:
            self._conn.close()
        except sqlite3.Error as exc:
            LOGGER.debug("sqlite_close_failed(err=%s)", exc)
        except AttributeError:
            # __init__ never finished, so there is nothing to close. Reached from
            # __del__ on an instance whose sqlite3.connect() call raised; raising
            # from a finalizer would only print "Exception ignored in __del__".
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def __del__(self):
        # A cache outliving its owner should still release the file handle:
        # sqlite3 only complains with a ResourceWarning at shutdown, which in a
        # long-running resolver means a descriptor leak that never surfaces as
        # an error. Callers that care about ordering should use the cache as a
        # context manager; this is the safety net for those that do not.
        self.close()

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
            except (DnsPacketParseError, struct.error, IndexError) as exc:
                # A row this parser cannot read means a truncated write or a DB
                # from an older build. Degrade to "negative entry without SOA",
                # which costs a re-query, rather than failing the lookup outright.
                LOGGER.debug("cache_soa_undecodable(err=%s)", exc)
                soa = None
        return NegativeEntry(name, qtype, qclass, rcode, soa, expires_at)

    def put(self, entry):
        key_name = _name_text(entry.name)
        qt = int(entry.qtype)
        qc = int(entry.qclass)
        if isinstance(entry, PositiveEntry):
            kind = _KIND_POSITIVE
            rcode = int(DnsResponseCode.NO_ERROR)
            authoritative = 1 if entry.authoritative else 0
            payload = _pack_records(entry.records)
        elif isinstance(entry, NegativeEntry):
            rcode_int = int(entry.rcode)
            kind = _KIND_NXDOMAIN if rcode_int == int(DnsResponseCode.NAME_ERROR) else _KIND_NODATA
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
