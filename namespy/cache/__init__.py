"""DNS cache (RFC 1034 §7.4 / RFC 2308) package: abstract base + backings.

Per-RRset caching keyed on ``(qname, qtype, qclass)``. Entries carry their
own absolute expiry deadline in the cache's ``time_fn`` units (defaults
to wall-clock seconds). Concrete backings:

* :class:`MemoryDnsCache` — process-local dict with optional LRU bound.
* :class:`SqliteDnsCache` — SQLite, ephemeral or on-disk (see :mod:`namespy.cache.sqlite`).

The :class:`namespy.resolver.RecursiveResolver` consults the cache at the
top of each :func:`namespy.resolver.resolve_steps` iteration before sending
any query, and writes back positive/negative results when an authoritative
response classifies as ``Answer`` / ``Nodata`` / ``Nxdomain``.

**A second cache, for a different kind of nothing** (RFC 9520 §3.2). The cache
above remembers answers -- including negative ones, which are statements a
server made. :class:`FailureCache` remembers the cases where nothing was said,
or where what was said was an admission of failure: a server that never
answered, a SERVFAIL, a zone whose every name server is down.

    RFC 9520 §3.2: "Resolvers MUST implement a cache for resolution failures.
    The purpose of this cache is to eliminate repeated upstream queries that
    cannot be resolved. When an incoming query matches a cached resolution
    failure, the resolver MUST NOT send any corresponding outgoing queries
    until after the cache entries expire."

Those two kinds of nothing are kept apart because they are believed differently
and expire on different clocks. ``NXDOMAIN`` is a statement whose authority
outlives the denial, so its TTL comes from the zone's SOA (RFC 2308 §5); a
timeout is the absence of a statement, which says nothing about the name and
everything about a momentary condition, so RFC 9520 bounds it in seconds and
minutes rather than in TTLs. Conflating them would let one dropped packet deny
a name for the length of a zone's MINIMUM field.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections import OrderedDict

from ..enums import DnsResponseCode
from ..names import DomainName

#: RFC 9520 §3.2: "Resolvers MUST cache resolution failures for at least 1
#: second." The floor no configuration may go below; :class:`FailureCache`
#: clamps every entry to it.
FAILURE_MIN_TTL_S = 1.0

#: RFC 9520 §3.2: "Consistent with [RFC2308], resolution failures MUST NOT be
#: cached for longer than 5 minutes." A ceiling rather than a default: the
#: failure may be one dropped packet, and a resolver that remembers it past the
#: outage has invented an outage of its own.
FAILURE_MAX_TTL_S = 300.0

#: RFC 9520 §3.2's own worked example: "the initial time for negatively caching
#: a resolution failure might be set to 5 seconds and increased after each retry
#: that results in another resolution failure, up to a configurable maximum, not
#: to exceed the 5-minute upper limit."
FAILURE_INITIAL_TTL_S = 5.0

#: RFC 9520 §3.2: "Resolvers SHOULD employ an exponential or linear backoff
#: algorithm to increase the cache duration for persistent resolution failures."
#: The factor by which an entry's duration grows each time the same failure is
#: re-encountered.
FAILURE_BACKOFF_FACTOR = 2.0

#: RFC 9520 §3.2: "resolvers SHOULD implement measures to mitigate resource
#: exhaustion attacks on the failed resolution cache. That is, the resolver
#: should limit the amount of memory and/or processing time devoted to this
#: cache." Anyone who can make a resolver fail can otherwise fill its memory
#: with failure records, so this bound is a constructor default rather than an
#: option, and eviction is least-recently-*used*.
FAILURE_CACHE_MAX_ENTRIES = 512


def _labels(name) -> tuple:
    """The case-folded label tuple a name is keyed by (see :func:`_key`)."""
    if not isinstance(name, DomainName):
        name = DomainName(str(name))
    return name._labels()


def _key(name, qtype, qclass):
    """Canonical cache key: ``(label_tuple, qtype_int, qclass_int)``.

    Names are case-folded and the trailing root terminator is stripped, so
    ``"example.com"`` and ``"EXAMPLE.com."`` collide on the same key (RFC
    1035 §3.1: case is not significant, and the wire form is always
    absolute). qtype/qclass are coerced to plain ints so callers may pass
    either an :class:`enum.IntEnum` or a raw integer.
    """
    return (_labels(name), int(qtype), int(qclass))


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

    ``proofs`` holds the NSEC or NSEC3 RRs that denied the name, each followed by the RRSIGs that
    cover it -- build it with :func:`namespy.nsec.collect_proof_records`, which enforces that pairing.
    It is what RFC 8020 §2¶5 turns the entry from a memory into evidence: "the iterative, caching
    resolver MUST return these NSEC or NSEC3 records in the response to the triggering query if the
    query had the DNSSEC OK (DO) bit set", and the records that prove a descendant's nonexistence are
    the same ones, which is precisely why they have to survive the cache round trip rather than be
    re-derived. Empty is legitimate -- an unsigned zone has none, and a signed zone's denial reaches
    a resolver that did not ask for DNSSEC data without them too -- and an empty value only costs the
    echo, never the denial itself.
    """

    def __init__(self, name, qtype, qclass, rcode, soa, expires_at, proofs=()):
        super().__init__(name, qtype, qclass, expires_at)
        try:
            rcode = DnsResponseCode(int(rcode))
        except ValueError:
            pass
        self.rcode = rcode
        self.soa = soa
        self.proofs = tuple(proofs)

    def __repr__(self):
        return (
            f"<NegativeEntry {self.name}/{self.qtype} rcode={self.rcode} proofs={len(self.proofs)}>"
        )


def _cut_key(name, qclass):
    """The ``(labels, qclass)`` half of :func:`_key`, for QTYPE-free lookups.

    Built by going through :func:`_key` rather than reimplementing the folding,
    so a change to how names are canonicalised cannot leave the RFC 8020 cut
    matching a name the cache itself would treat as distinct.
    """
    key = _key(name, 0, qclass)
    return (key[0], key[2])


def _is_nxdomain(entry):
    """True for a cache entry that denies the *existence* of its name.

    RFC 8020 §2 is about NXDOMAIN alone. A NODATA entry proves that one type is
    absent at one name and says nothing whatever about the names below it -- so
    the two share :class:`NegativeEntry`, and this is the test that must not be
    skipped just because the class does.
    """
    return isinstance(entry, NegativeEntry) and int(entry.rcode) == int(DnsResponseCode.NAME_ERROR)


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

    def nxdomain_at(self, name, qclass):  # noqa: ARG002 - the fallback ignores both
        """Return a cached NXDOMAIN recorded at exactly *name*, whatever was asked.

        RFC 8020 §2¶1 asks a resolver to treat "all names and resource record
        sets (RRsets) at or below that node" as unreachable once a name has been
        denied -- a statement about the *name*, made without regard to QTYPE.
        :meth:`get` cannot express it: a negative entry is keyed
        ``(name, qtype, class)``, so the NXDOMAIN that arrived in answer to an A
        is invisible to the AAAA that this cut is supposed to answer.
        That is the lookup this method provides, and the caller walks a name's
        ancestors with it, closest first, using
        :meth:`~namespy.names.DomainName.hierarchy`.

        Implementations return a :class:`NegativeEntry` whose rcode is
        ``NAME_ERROR`` and whose *soa* is the proof that denied the name -- the
        cut is answered with that SOA, so a caller that discards it loses the
        only evidence in the response.

        The base implementation returns ``None``, and that is the documented
        fallback rather than an unfilled stub. The cut is a SHOULD, so a backend
        that cannot answer this without scanning simply lets the resolver keep
        walking: the pre-RFC-8020 behaviour, still correct, only more chatty.
        """
        return None  # noqa: RET501 - explicit: "no cut available" is the contract


class MemoryDnsCache(DnsCache):
    """Process-local dict-backed :class:`DnsCache`.

    With ``max_entries`` set, eviction is LRU (least-recently-*used*, where
    "use" is :meth:`get` or :meth:`put`).
    """

    def __init__(self, max_entries=None, time_fn=None):
        super().__init__(time_fn=time_fn)
        self._entries: OrderedDict = OrderedDict()
        #: ``(labels, qclass)`` -> key of the newest cached NXDOMAIN at that name.
        #:
        #: An index rather than a scan, because the cut is consulted on every hop
        #: of every query: testing ancestors against ``_entries`` would cost
        #: O(cache size) per hop, which is dearer than the upstream query the cut
        #: exists to avoid.
        #:
        #: The index may legitimately *under*-report. A pointer is dropped when
        #: its entry is evicted or expires, and a second NXDOMAIN at the same name
        #: replaces the first; either way the next lookup finds nothing and the
        #: resolver walks, which is the pre-RFC-8020 behaviour. It cannot
        #: over-report, because :meth:`nxdomain_at` re-checks what it finds.
        self._nxdomain: dict = {}
        self.max_entries = max_entries

    def _unindex(self, key):
        """Drop the cut index entry if -- and only if -- ``key`` owns it."""
        index_key = (key[0], key[2])
        if self._nxdomain.get(index_key) == key:
            del self._nxdomain[index_key]

    def _forget(self, key):
        self._entries.pop(key, None)
        self._unindex(key)

    def get(self, name, qtype, qclass):
        key = _key(name, qtype, qclass)
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry.expired(self.time_fn()):
            self._forget(key)
            return None
        self._entries.move_to_end(key)
        return entry

    def nxdomain_at(self, name, qclass):
        key = self._nxdomain.get(_cut_key(name, qclass))
        if key is None:
            return None
        entry = self._entries.get(key)
        if entry is None or not _is_nxdomain(entry) or entry.expired(self.time_fn()):
            # Every removal path clears the index, so reaching here means a
            # pointer outlived its entry. The price is a walk -- never an answer
            # manufactured from a denial that has stopped existing.
            self._forget(key)
            return None
        self._entries.move_to_end(key)
        return entry

    def put(self, entry):
        key = entry.key
        self._forget(key)
        self._entries[key] = entry
        if _is_nxdomain(entry):
            self._nxdomain[(key[0], key[2])] = key
        if self.max_entries is not None:
            while len(self._entries) > self.max_entries:
                evicted, _ = self._entries.popitem(last=False)
                self._unindex(evicted)

    def __len__(self):
        return len(self._entries)

    def prune(self):
        now = self.time_fn()
        keys = [k for k, e in self._entries.items() if e.expired(now)]
        for k in keys:
            self._forget(k)
        return len(keys)


#: Key kinds for :class:`FailureCache`. A failure is not one thing, and RFC 9520
#: §3.2 says so outright: "The implementation might cache different resolution
#: failure conditions differently."
QUERY_FAILURE = "query"
ZONE_FAILURE = "zone"


class FailureEntry:
    """One remembered resolution failure (RFC 9520 §3.2).

    Deliberately *not* a :class:`CacheEntry`. Those are keyed on
    ``(name, qtype, qclass)`` and hold RRs; a failure has no RRset, and a
    zone-level failure is keyed on a zone cut -- a name no question was ever
    asked about. Forcing either into the RR-shaped base class would buy a shared
    :meth:`expired` at the price of describing what is stored incorrectly.

    *ttl* is kept alongside *expires_at* because RFC 9520 §3.2 wants repeat
    failures to back off, so the next duration is derived from this one: the
    entry has to remember how long it was given, not only when it ends.

    *strikes* counts how many times this exact failure has been re-encountered.
    It exists for the trace and the log: "dead for 5s" and "dead for 80s, strike
    5" are different diagnoses of the same network.
    """

    def __init__(self, key, reason, expires_at, ttl=FAILURE_INITIAL_TTL_S, strikes=1, zone=None):
        self.key = key
        self.reason = reason
        self.expires_at = float(expires_at)
        self.ttl = float(ttl)
        self.strikes = int(strikes)
        #: The zone cut this entry was keyed on, for :class:`ZONE_FAILURE`
        #: entries; ``None`` for query-keyed ones, whose name is ``key[1]``.
        self.zone = zone

    def expired(self, now):
        return now >= self.expires_at

    def __repr__(self):
        subject = self.zone if self.zone is not None else self.key[1]
        return (
            f"<FailureEntry {self.key[0]} {subject} ttl={self.ttl:g}s "
            f"strikes={self.strikes} {self.reason!r}>"
        )


class FailureCache:
    """RFC 9520 §3.2 "cache for resolution failures", keyed two ways.

    A failure is not an answer, so this is a separate store rather than another
    :class:`DnsCache` backing: :meth:`DnsCache.get` is spelled
    ``(name, qtype, qclass)``, and a zone's dead name servers are none of those
    three things.

    **What is keyed on what** -- §3.2 asks that this be written down:
    "Developers should document their implementation choices so that operators
    know what behaviors to expect when resolution failures are cached."

    * :meth:`note_query` stores ``(qname, qtype, qclass)``. This is the entry
      §3.2's suppression sentence is about: an incoming query matching it must
      not produce outgoing queries. It is also the only key that can record a
      failure that is a property of the *name* rather than of a server -- an
      alias loop (RFC 9520 §2.5), a delegation loop (§2.4, which presents here as
      the hop budget running out), or a lookup that simply ran out of servers.
    * :meth:`note_zone` stores a zone cut, recorded when every name server of
      that zone failed during one lookup. RFC 9520 §3.3 then asks for more than
      skipping the zone: "the resolver MUST limit queries to the non-responsive
      zone's parent zone (and to other ancestor zones) just as it would limit
      subsequent queries to the non-responsive zone." A name-keyed cache cannot
      express that, because the *next* lookup will be a different name beneath
      the same zone -- so :meth:`dead_zone_covering` answers "is this name
      underneath a zone we already know is down?" before anything is sent.
    * **Not** keyed on server address, which §3.2 also permits ("unresponsive
      servers might be cached only according to the server's IP address"). Inside
      one lookup the Slist already cycles through the remaining servers (RFC 1034
      §5.3.3 step 3), so an address key buys nothing there; across lookups it
      would let a single dropped datagram retire one of a zone's several healthy
      servers for minutes -- a self-inflicted outage traded for a saving the zone
      key already captures. The cost of the choice is that a dead address in a
      zone that still has live servers is re-probed once per lookup.

    **Durations.** Every entry is clamped into ``[FAILURE_MIN_TTL_S,
    FAILURE_MAX_TTL_S]`` -- at least a second (§3.2: "Resolvers MUST cache
    resolution failures for at least 1 second"), never past five minutes
    ("resolution failures MUST NOT be cached for longer than 5 minutes").
    Re-noticing a failure multiplies its duration by :attr:`backoff` (§3.2:
    "Resolvers SHOULD employ an exponential or linear backoff algorithm to
    increase the cache duration for persistent resolution failures"), up to the
    ceiling. :attr:`min_ttl` is operator-configurable, as §3.2's "The minimum
    cache duration SHOULD be configurable by the operator" asks; the ceiling is
    not, because the five-minute limit is a MUST and configurability a SHOULD,
    and the stronger of two requirements wins.

    **Bounds.** :attr:`max_entries` is always set (default
    :data:`FAILURE_CACHE_MAX_ENTRIES`) and eviction is least-recently-*used*, so
    the memory a §3.2 resource-exhaustion attempt can push into this cache is
    fixed in advance rather than proportional to the attack.

    **How a failure is forgotten.** Three ways, and the difference matters. An
    entry expires, which stops the suppression and leaves the strike count behind
    so the next failure is longer (:attr:`FAILURE_MAX_TTL_S` is only reachable
    through that memory). Eviction drops both, and the count restarts -- the price
    of a bound an attack cannot grow. Or the name resolves, and :meth:`forget`
    removes both: an answer is proof the outage has ended, and a stale count would
    make the next real failure open at the ceiling instead of the floor.
    """

    def __init__(
        self,
        initial_ttl: float = FAILURE_INITIAL_TTL_S,
        min_ttl: float = FAILURE_MIN_TTL_S,
        max_ttl: float = FAILURE_MAX_TTL_S,
        backoff: float = FAILURE_BACKOFF_FACTOR,
        max_entries: int = FAILURE_CACHE_MAX_ENTRIES,
        time_fn=None,
    ):
        """Build a failure cache. All durations are seconds.

        :param initial_ttl: how long the first sighting of a failure is
            remembered (RFC 9520 §3.2's example: 5 seconds).
        :param min_ttl: the floor an entry may never expire below. Clamped into
            the RFC's band, so an operator asking for "a second" and one asking
            for "an hour" both get something the five-minute ceiling allows.
        :param max_ttl: the ceiling repeat failures grow towards; may be lowered
            below five minutes, never raised above it.
        :param backoff: multiplier applied to an entry's duration each time the
            same failure is noticed again. ``1.0`` disables growth.
        :param max_entries: LRU bound on how many failures are remembered.
        """
        self.time_fn = time_fn or time.time
        # Both bounds are clamped before use, and in this order: min first, then
        # max forced to be at least min, so `min_ttl` can never end up above
        # `max_ttl` and hand back an entry with a negative lifetime.
        self.min_ttl = min(FAILURE_MAX_TTL_S, max(FAILURE_MIN_TTL_S, float(min_ttl)))
        self.max_ttl = min(FAILURE_MAX_TTL_S, max(self.min_ttl, float(max_ttl)))
        self.initial_ttl = min(self.max_ttl, max(self.min_ttl, float(initial_ttl)))
        self.backoff = max(1.0, float(backoff))
        self.max_entries = max(1, int(max_entries))
        self._entries: OrderedDict = OrderedDict()
        # Backoff state, kept apart from `_entries` on purpose. `_entries` answers
        # "until when must this not be asked about" and is swept the moment it
        # expires, so an outage that has ended stops costing a scan; the counts have
        # to outlive that window, because a cached failure is by definition not
        # re-queried while it is held -- the next encounter always comes after the
        # entry has gone. Fold the two together and every failure is a first failure
        # forever, which reduces §3.2's backoff to a fixed delay. Same bound and the
        # same eviction policy, so the memory an attacker can reach is unchanged.
        self._history: OrderedDict = OrderedDict()
        #: How many lookups this cache has suppressed. Observability for the one
        #: thing RFC 9520 is actually for: an operator who sees this climbing
        #: knows the upstream is still down without reading a trace.
        self.hits = 0

    def note_query(self, name, qtype, qclass, reason):
        """Remember that resolving ``(name, qtype, qclass)`` just failed."""
        return self._note((QUERY_FAILURE, _labels(name), int(qtype), int(qclass)), reason)

    def note_zone(self, zone, reason):
        """Remember that every name server of *zone* failed."""
        if not isinstance(zone, DomainName):
            zone = DomainName(str(zone))
        return self._note((ZONE_FAILURE, zone), reason, zone=zone)

    def match(self, name, qtype, qclass):
        """The cached failure that blocks this query, or ``None``.

        The query's own key is checked first: it is the specific evidence, and
        where both a zone and this name are remembered, the name is the thing
        that most recently failed.

        :attr:`hits` is counted here rather than in the lookup helpers, because a
        hit is only worth counting when it is the answer to a question a client
        actually asked -- the introspection helpers a test reaches for are not
        evidence that upstream traffic was saved.
        """
        hit = self._lookup((QUERY_FAILURE, _labels(name), int(qtype), int(qclass)))
        if hit is None:
            hit = self.dead_zone_covering(name)
        if hit is not None:
            self.hits += 1
        return hit

    def lookup_query(self, name, qtype, qclass):
        """A failure remembered for exactly this ``(name, qtype, qclass)``."""
        return self._lookup((QUERY_FAILURE, _labels(name), int(qtype), int(qclass)))

    def lookup_zone(self, zone):
        """A failure remembered for exactly this zone cut."""
        if not isinstance(zone, DomainName):
            zone = DomainName(str(zone))
        return self._lookup((ZONE_FAILURE, zone))

    def dead_zone_covering(self, name):
        """The deepest remembered dead zone *name* lies beneath, or ``None``.

        RFC 9520 §3.3's requirement to limit queries to a dead zone's *parent*
        is what this serves: a lookup for a new name beneath a dead zone would
        otherwise start at the root and re-ask every ancestor on its way down to
        the zone that is known not to answer.

        Deepest wins because it is the more precise claim: when both
        ``example.com`` and ``shop.example.com`` are remembered, the second says
        something narrower is broken, and failing the whole of ``example.com``
        because a sub-delegation is down would be its own kind of outage.

        The scan is linear in the number of live entries and bounded by
        :attr:`max_entries`; a lookup performs one, not one per label, which is
        why no index is worth building here. Names are compared over raw labels
        from the right, which is :meth:`DomainName.is_subdomain_of`'s rule (RFC
        1034 §3.1) restated against the same folded octets the keys use.
        """
        target = _labels(name)
        now = self.time_fn()
        best = None
        expired = []
        for key, entry in self._entries.items():
            if entry.expired(now):
                expired.append(key)
                continue
            if key[0] != ZONE_FAILURE:
                continue
            labels = key[1]._labels()
            if len(labels) > len(target):
                continue
            # `labels` empty means the root, which is an ancestor of every name;
            # the guard is needed because `target[-0:]` is the whole tuple rather
            # than the empty suffix, so the general form silently never matches.
            if labels and target[-len(labels) :] != labels:
                continue
            if best is None or len(labels) > len(best.zone._labels()):
                best = entry
        # Swept after the walk, because deleting mid-iteration over an
        # OrderedDict raises. An expired zone entry must stop suppressing
        # immediately: the five-minute ceiling exists so that a resolver which
        # remembered an outage too long can still notice it has ended.
        for key in expired:
            del self._entries[key]
        return best

    def _note(self, key, reason, *, zone=None):
        now = self.time_fn()
        # The duration comes from `_history`, not from a live entry, and that split
        # is what makes the backoff reachable at all. A cached failure suppresses
        # the query that would have re-encountered it, so the next sighting of the
        # same failure necessarily happens after this entry has expired and been
        # swept -- grow from live entries and every failure is a first failure,
        # forever, with the cache stuck at one fixed delay instead of the escalating
        # one §3.2 asks for.
        strikes, previous_ttl = self._history.get(key, (0, self.initial_ttl))
        strikes += 1
        ttl = self.initial_ttl if strikes == 1 else previous_ttl * self.backoff
        ttl = max(self.min_ttl, min(self.max_ttl, ttl))
        self._history[key] = (strikes, ttl)
        # Bounded on its own schedule: `_entries` is emptied as entries expire,
        # which is exactly when `_history` is still being consulted, so the two maps
        # are at their peaks at different moments and each needs the cap.
        self._history.move_to_end(key)
        while len(self._history) > self.max_entries:
            self._history.popitem(last=False)
        entry = FailureEntry(key, reason, now + ttl, ttl=ttl, strikes=strikes, zone=zone)
        self._entries[key] = entry
        # Re-inserting an existing key keeps its old LRU position in an
        # OrderedDict, and a failure that has just happened again is the last
        # thing here that should be evicted.
        self._entries.move_to_end(key)
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)
        return entry

    def forget(self, name, qtype, qclass):
        """Drop everything remembered about a query key; ``True`` if anything was.

        The recovery path. A lookup that *succeeds* is the evidence that a cached
        failure has expired rather than merely paused, so both the suppression and
        the strike count go: without this, a zone that flapped once would meet its
        next genuine outage already at the five-minute ceiling and would be slow to
        notice it the second time around.
        """
        return self._discard((QUERY_FAILURE, _labels(name), int(qtype), int(qclass)))

    def forget_zone(self, zone):
        """Drop a zone's failure and its strike count; ``True`` if anything was."""
        if not isinstance(zone, DomainName):
            zone = DomainName(str(zone))
        return self._discard((ZONE_FAILURE, zone))

    def _discard(self, key):
        # Both maps are popped unconditionally rather than joined with `or`: `or`
        # short-circuits, and an expired suppression is the common case here -- the
        # count outlives the entry it came from -- so a short-circuit would leave the
        # strike count behind to make the next failure long.
        history = self._history.pop(key, None)
        entry = self._entries.pop(key, None)
        return history is not None or entry is not None

    def _lookup(self, key):
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry.expired(self.time_fn()):
            # Swept, not merely ignored: a live entry is a promise not to query, and
            # one that has expired is nothing of the sort. The strike count stays in
            # `_history` -- this entry is gone, the experience is not.
            del self._entries[key]
            return None
        self._entries.move_to_end(key)
        return entry

    def clear(self):
        """Forget every remembered failure, counts included."""
        self._entries.clear()
        self._history.clear()

    def prune(self):
        """Sweep expired suppressions and return how many were removed.

        The strike counts deliberately survive this: they are the reason the next
        failure of the same thing is remembered longer, and a housekeeping call that
        quietly reset the backoff would undo §3.2's growth on every sweep.
        """
        now = self.time_fn()
        keys = [k for k, e in self._entries.items() if e.expired(now)]
        for k in keys:
            del self._entries[k]
        return len(keys)

    def __len__(self):
        return len(self._entries)

    def __repr__(self):
        return (
            f"<FailureCache n={len(self._entries)} remembered={len(self._history)} "
            f"hits={self.hits} bound={self.max_entries}>"
        )


from .sqlite import SqliteDnsCache  # noqa: E402

__all__ = [
    "FAILURE_BACKOFF_FACTOR",
    "FAILURE_CACHE_MAX_ENTRIES",
    "FAILURE_INITIAL_TTL_S",
    "FAILURE_MAX_TTL_S",
    "FAILURE_MIN_TTL_S",
    "QUERY_FAILURE",
    "ZONE_FAILURE",
    "CacheEntry",
    "DnsCache",
    "FailureCache",
    "FailureEntry",
    "MemoryDnsCache",
    "NegativeEntry",
    "PositiveEntry",
    "SqliteDnsCache",
]
