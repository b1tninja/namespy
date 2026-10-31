"""Cached denials that keep their proofs, and the adapters between a response and a proof set.

Three things meet here: the collector that pulls proof records out of a response
(`namespy.nsec.collect_proof_records`), the storage that has to hold them across a cache round trip
(`NegativeEntry.proofs`), and the SQLite migration that lets an on-disk database written before this
field still open. The RFCs behind them are RFC 8020 §2¶5 (a caching resolver MUST return the NSEC or
NSEC3 records that authenticated a cached denial when the query had DO set), RFC 4035 §3.1.1¶3 (a
signed RRset and its RRSIGs travel together), and RFC 4035 §3.2.1 (a recursive server's resolver side
MUST set DO, which is the plumbing that makes any of this arrive).

What is deliberately not asserted: that the resolver echoes these records today. It cannot know the
client's DO bit until that is plumbed through, and inventing an echo rule that ignores §3.2.1's strip
requirement would be worse than shipping none -- it would hand DNSSEC records to clients that never
asked for any.
"""

import sqlite3

import pytest

from namespy.cache import MemoryDnsCache, NegativeEntry
from namespy.cache.sqlite import SqliteDnsCache, _name_text
from namespy.dnssec import encode_base32hex, nsec3_hash
from namespy.enums import DnsRClass, DnsResponseCode, DnsRType
from namespy.names import DomainName
from namespy.nsec import closest_encloser_proof, collect_proof_records, proof_entries
from namespy.packet import DnsRecord
from namespy.rdata import RData_NSEC, RData_NSEC3, RData_RRSIG

ZONE = "example.com."
A = int(DnsRType.A)
NSEC = int(DnsRType.NSEC)
NSEC3 = int(DnsRType.NSEC3)
SALT = bytes.fromhex("1234")
NOW = 1000.0


def _record(name, rtype, rdata, ttl=300):
    return DnsRecord(DomainName(name), rtype, DnsRClass.IN, ttl, rdata=rdata)


def _rrsig(covered, owner, signer=ZONE):
    return RData_RRSIG(
        type_covered=covered,
        algorithm=13,
        labels=len([label for label in DomainName(owner).labels() if label]),
        original_ttl=300,
        expiration=2**31 - 1,
        inception=0,
        key_tag=1,
        signer_name=signer,
        signature=b"\x01" * 8,
    )


def _nsec(owner, nxt, types=(A,)):
    return _record(owner, DnsRType.NSEC, RData_NSEC(DomainName(nxt), list(types)))


def _nsec3(owner, nxt_digest, types=(A,), salt=SALT):
    return _record(owner, DnsRType.NSEC3, RData_NSEC3(1, 0, 0, salt, nxt_digest, list(types)))


def _digest(name, salt=SALT):
    return nsec3_hash(name, iterations=0, salt=salt)


def _soa(name=ZONE):
    from namespy.rdata import RData_SOA

    return _record(name, DnsRType.SOA, RData_SOA("ns." + name, "host." + name, serial=1))


# ------------------------------------------------------ collecting proofs out of a response


def test_a_signed_proof_comes_back_with_its_signature():
    """RFC 4035 §3.1.1¶3: a signed RRset and its RRSIGs are one bundle, not two candidates."""
    nsec = _nsec("a.example.com.", "z.example.com.")
    signature = _record("a.example.com.", DnsRType.RRSIG, _rrsig(NSEC, "a.example.com."))
    assert collect_proof_records([nsec, signature]) == (nsec, signature)


def test_an_unsigned_proof_is_dropped_rather_than_half_stored():
    """An unsigned NSEC cannot authenticate anything, and §2¶5 speaks only of signed zones.

    Storing it would let a resolver hand a client a "proof" the client would then have to discover is
    unsigned -- from the one server it treats as trusted. Dropping it costs only the echo.
    """
    assert collect_proof_records([_nsec("a.example.com.", "z.example.com.")]) == ()


def test_a_signature_over_another_type_does_not_pair():
    """Pairing is by owner name *and* Type Covered, so an A's RRSIG cannot dress up an NSEC."""
    nsec = _nsec("a.example.com.", "z.example.com.")
    wrong = _record("a.example.com.", DnsRType.RRSIG, _rrsig(A, "a.example.com."))
    assert collect_proof_records([nsec, wrong]) == ()


def test_pairing_ignores_the_signer_name():
    """The signer is the zone apex while the RRSIG's owner is the denied name.

    NSEC3 makes this unavoidable rather than merely likely: its owner is a base32hex hash resembling
    neither the query name nor the zone, so any pairing rule that consulted the signer would fail on
    exactly the records it exists to protect.
    """
    hashed = encode_base32hex(_digest("b.example.com."))
    owner = f"{hashed}.{ZONE}"
    nsec3 = _nsec3(owner, _digest("c.example.com."))
    signature = _record(owner, DnsRType.RRSIG, _rrsig(NSEC3, owner, signer="elsewhere.net."))
    assert collect_proof_records([nsec3, signature]) == (nsec3, signature)


def test_of_two_proofs_only_the_signed_one_survives():
    """One missing signature must not cost the whole bundle, nor lend its absence to the other."""
    signed = _nsec("a.example.com.", "m.example.com.")
    signed_sig = _record("a.example.com.", DnsRType.RRSIG, _rrsig(NSEC, "a.example.com."))
    unsigned = _nsec("m.example.com.", "z.example.com.")
    assert collect_proof_records([unsigned, signed, signed_sig]) == (signed, signed_sig)


def test_unrelated_records_are_not_collected():
    authority = [_soa(), _record("a.example.com.", DnsRType.MX, b"\x00\x0a\x00\x00")]
    assert collect_proof_records(authority) == ()


# ------------------------------------------------------------------ entries for the predicates


def test_proof_entries_carries_the_owner_name_that_rdata_lacks():
    """The owner is in the RR header, so an entry is a pair -- which is what nsec.py needs."""
    nsec = _nsec("a.example.com.", "z.example.com.")
    assert proof_entries([nsec]) == ((DomainName("a.example.com."), nsec.rdata),)
    assert proof_entries([nsec], rtype=NSEC3) == ()


def test_proof_entries_works_without_signatures_unlike_the_collector():
    """One answers "what does this assert", the other "what may I echo as authenticated"."""
    nsec = _nsec("a.example.com.", "z.example.com.")
    assert proof_entries([nsec])
    assert collect_proof_records([nsec]) == ()


def test_a_response_of_nsec3_records_feeds_the_encloser_algorithm():
    """The adapter's whole purpose: wire records in, a proof out."""
    names = [ZONE, "b.example.com.", "c.example.com."]
    digests = sorted(_digest(name) for name in names)
    records = []
    for index, digest in enumerate(digests):
        owner = f"{encode_base32hex(digest)}.{ZONE}"
        records.append(_nsec3(owner, digests[(index + 1) % len(digests)]))
    proof = closest_encloser_proof("x.b.example.com.", proof_entries(records, NSEC3), ZONE)
    assert proof.encloser == DomainName("b.example.com.")
    assert proof.next_closer == DomainName("x.b.example.com.")


# --------------------------------------------------------------------- proofs across the cache


def _denial(proofs=(), rcode=DnsResponseCode.NAME_ERROR, name="missing.example.com."):
    return NegativeEntry(name, A, int(DnsRClass.IN), rcode, _soa(), NOW + 300, proofs)


def _bundle():
    nsec = _nsec("a.example.com.", "z.example.com.")
    signature = _record("a.example.com.", DnsRType.RRSIG, _rrsig(NSEC, "a.example.com."))
    return (nsec, signature)


def test_the_memory_cut_carries_the_proofs_that_deny_the_descendant():
    """RFC 8020 §2¶5's data path: the descendant is answered from the ancestor's entry.

    ``nxdomain_at`` is the lookup that answers a name nobody queried, so proofs that survived
    ``get`` but not the cut index would be stored exactly where the requirement cannot use them.
    """
    cache = MemoryDnsCache(time_fn=lambda: NOW)
    proofs = _bundle()
    cache.put(_denial(proofs))
    assert cache.get("missing.example.com.", A, int(DnsRClass.IN)).proofs == proofs
    assert cache.nxdomain_at("missing.example.com.", int(DnsRClass.IN)).proofs == proofs


def test_a_denial_without_proofs_is_still_a_denial():
    """An unsigned zone, or a signed one answering a resolver that never asked. Empty is normal."""
    cache = MemoryDnsCache(time_fn=lambda: NOW)
    cache.put(_denial())
    assert cache.nxdomain_at("missing.example.com.", int(DnsRClass.IN)).proofs == ()


@pytest.fixture
def sqlite_cache(tmp_path):
    cache = SqliteDnsCache(str(tmp_path / "c.db"), time_fn=lambda: NOW)
    yield cache
    cache.close()


def test_the_sqlite_round_trip_preserves_the_bundle_wired(sqlite_cache):
    """Serialized records come back as the same octets, signatures included."""
    proofs = _bundle()
    sqlite_cache.put(_denial(proofs))
    for hit in (
        sqlite_cache.get("missing.example.com.", A, int(DnsRClass.IN)),
        sqlite_cache.nxdomain_at("missing.example.com.", int(DnsRClass.IN)),
    ):
        assert [bytes(r) for r in hit.proofs] == [bytes(r) for r in proofs]
        assert hit.proofs[0].rtype == DnsRType.NSEC


def test_a_nodata_denial_keeps_its_proofs_too(sqlite_cache):
    """§8.5's No Data proof is the same storage problem, one rcode away."""
    sqlite_cache.put(_denial(_bundle(), rcode=DnsResponseCode.NO_ERROR))
    hit = sqlite_cache.get("missing.example.com.", A, int(DnsRClass.IN))
    assert len(hit.proofs) == 2
    assert sqlite_cache.nxdomain_at("missing.example.com.", int(DnsRClass.IN)) is None


def test_an_empty_proofs_column_reads_back_empty(sqlite_cache):
    sqlite_cache.put(_denial())
    assert sqlite_cache.get("missing.example.com.", A, int(DnsRClass.IN)).proofs == ()


def test_a_database_written_before_this_field_still_opens(tmp_path):
    """The migration the schema text alone cannot perform.

    ``CREATE TABLE IF NOT EXISTS`` is a no-op against an existing file, so a database left by an
    older build has no ``proofs`` column and every read would raise OperationalError without the
    ALTER. Old rows read with no proofs -- which is the truth about them -- and new writes carry
    them, so upgrading costs nothing and loses nothing.
    """
    path = str(tmp_path / "old.db")
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE rrset_cache (
            name TEXT NOT NULL, qtype INTEGER NOT NULL, qclass INTEGER NOT NULL,
            kind INTEGER NOT NULL, rcode INTEGER NOT NULL, expires_at REAL NOT NULL,
            authoritative INTEGER NOT NULL DEFAULT 0, payload BLOB NOT NULL,
            PRIMARY KEY (name, qtype, qclass));
        """
    )
    # The key is whatever the backend's own canonical form is -- not a spelling this test guesses,
    # since a row under a name the cache would never look up would prove nothing about the upgrade.
    conn.execute(
        "INSERT INTO rrset_cache VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (_name_text(DomainName("missing.example.com.")), 1, 1, 1, 3, 9999999999.0, 0, b""),
    )
    conn.commit()
    conn.close()

    cache = SqliteDnsCache(path, time_fn=lambda: NOW)
    try:
        hit = cache.nxdomain_at("missing.example.com.", int(DnsRClass.IN))
        assert hit is not None
        assert hit.proofs == ()
        cache.put(_denial(_bundle()))
        assert len(cache.nxdomain_at("missing.example.com.", int(DnsRClass.IN)).proofs) == 2
    finally:
        cache.close()


def test_an_unreadable_proof_blob_costs_the_proofs_not_the_denial(sqlite_cache):
    """Same degradation as the SOA column: a truncated write must not delete a valid denial."""
    sqlite_cache.put(_denial(_bundle()))
    sqlite_cache._conn.execute(
        "UPDATE rrset_cache SET proofs=? WHERE name=?",
        (b"\xff\xff\x00\x00", _name_text(DomainName("missing.example.com."))),
    )
    sqlite_cache._conn.commit()
    hit = sqlite_cache.nxdomain_at("missing.example.com.", int(DnsRClass.IN))
    assert hit is not None
    assert hit.proofs == ()
    assert hit.rcode == DnsResponseCode.NAME_ERROR
