"""Tests for the RFC 9520 §3.2 resolution-failure cache.

The numbers these tests assert are the numbers the specification sets, not the
numbers this implementation chose: RFC 9520 §3.2 says "Resolvers MUST cache
resolution failures for at least 1 second" and that they "MUST NOT be cached for
longer than 5 minutes", so a test that let an entry die in 0.5s or live for six
minutes would be documenting a violation. Everything else -- the five-second
starting duration, the doubling, the entry bound -- is the configurable behaviour
§3.2 leaves open ("The minimum cache duration SHOULD be configurable by the
operator"), asserted here so that changing a default is a decision rather than an
accident.

The clock is injected rather than slept on: the floor is a second and the ceiling
is five minutes, and a suite that proved those two MUSTs by waiting would take
eleven minutes to prove them.
"""

import pytest

from namespy.cache import (
    FAILURE_MAX_TTL_S,
    FAILURE_MIN_TTL_S,
    QUERY_FAILURE,
    ZONE_FAILURE,
    FailureCache,
)
from namespy.names import DomainName


class Clock:
    """An injectable clock -- the whole point of ``time_fn`` on FailureCache."""

    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds
        return self.now


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def failures(clock):
    return FailureCache(time_fn=clock)


def test_first_failure_lasts_the_initial_duration(failures, clock):
    # RFC 9520 §3.2's worked example: "the resolver could cache that fact for
    # some short period (e.g. 5 seconds)".
    assert failures.lookup_query("dead.example", 1, 1) is None
    failures.note_query("dead.example", 1, 1, "no response")
    clock.advance(4.9)
    assert failures.lookup_query("dead.example", 1, 1) is not None
    clock.advance(0.1)
    assert failures.lookup_query("dead.example", 1, 1) is None


def test_failure_always_lives_at_least_one_second(clock):
    # "Resolvers MUST cache resolution failures for at least 1 second." A cache
    # configured to remember less is not allowed to forget sooner.
    failures = FailureCache(initial_ttl=0.01, time_fn=clock)
    failures.note_query("dead.example", 1, 1, "no response")
    clock.advance(FAILURE_MIN_TTL_S - 0.5)
    assert failures.lookup_query("dead.example", 1, 1) is not None
    clock.advance(0.5)
    assert failures.lookup_query("dead.example", 1, 1) is None


def test_failure_never_lives_past_five_minutes(failures, clock):
    # "... resolution failures MUST NOT be cached for longer than 5 minutes."
    # Backing off repeatedly must converge on the ceiling, not run away from it.
    for _ in range(12):
        entry = failures.note_query("dead.example", 1, 1, "no response")
        assert entry.ttl <= FAILURE_MAX_TTL_S
        clock.advance(entry.ttl)
    assert entry.ttl == FAILURE_MAX_TTL_S


def test_repeat_failure_backs_off_and_counts_strikes(failures, clock):
    # "Resolvers SHOULD employ an exponential or linear backoff algorithm to
    # increase the cache duration for persistent resolution failures."
    ttls, strikes = [], []
    for _ in range(4):
        entry = failures.note_query("dead.example", 1, 1, "no response")
        ttls.append(entry.ttl)
        strikes.append(entry.strikes)
        clock.advance(entry.ttl)
    assert ttls == [5.0, 10.0, 20.0, 40.0]
    assert strikes == [1, 2, 3, 4]


def test_repr_shows_the_strikes_that_explain_a_duration(failures):
    # "dead for 5s" and "dead for 80s, strike 5" are different diagnoses of the
    # same network, and the trace line is where an operator reads them.
    entry = failures.note_query("dead.example", 1, 1, "no response")
    assert "strikes=1" in repr(entry)
    assert repr(failures.note_zone("dead.example", "all servers failed")).startswith(
        "<FailureEntry zone dead.example"
    )


def test_backoff_can_be_disabled(clock):
    flat = FailureCache(backoff=1.0, time_fn=clock)
    assert flat.note_query("dead.example", 1, 1, "x").ttl == 5.0
    assert flat.note_query("dead.example", 1, 1, "x").ttl == 5.0


def test_operator_cannot_raise_the_ceiling_above_five_minutes(clock):
    # §3.2 makes the minimum configurable but the five-minute maximum a MUST, so
    # the MUST wins an argument with an operator's config file.
    failures = FailureCache(max_ttl=3600.0, time_fn=clock)
    assert failures.max_ttl == FAILURE_MAX_TTL_S
    assert failures.note_query("dead.example", 1, 1, "x").ttl <= FAILURE_MAX_TTL_S


def test_operator_can_lower_the_ceiling(clock):
    failures = FailureCache(max_ttl=10.0, backoff=2.0, time_fn=clock)
    for _ in range(6):
        entry = failures.note_query("dead.example", 1, 1, "x")
        clock.advance(entry.ttl)
    assert entry.ttl == 10.0


def test_inverted_bounds_cannot_produce_a_negative_lifetime(clock):
    # A config that asks for a minimum longer than the maximum is a mistake an
    # operator can actually make. It must degrade to the ceiling, not to an entry
    # that is born expired -- or, worse, one that never expires.
    failures = FailureCache(min_ttl=3600.0, max_ttl=10.0, time_fn=clock)
    assert failures.min_ttl == failures.max_ttl == FAILURE_MAX_TTL_S
    assert failures.note_query("dead.example", 1, 1, "x").ttl == FAILURE_MAX_TTL_S
    assert failures.lookup_query("dead.example", 1, 1) is not None


def test_zone_key_suppresses_a_different_name_beneath_it(failures):
    # RFC 9520 §3.3: "the resolver MUST limit queries to the non-responsive zone's
    # parent zone (and to other ancestor zones) just as it would limit subsequent
    # queries to the non-responsive zone." The next lookup is a *different name*
    # in the same zone, so only a zone-shaped key can honour that.
    failures.note_zone("dead.example", "all servers failed")
    assert failures.match("anything.dead.example", 1, 1) is not None
    assert failures.match("deep.inside.dead.example", 28, 1) is not None
    assert failures.match("dead.example", 1, 1) is not None


def test_zone_key_does_not_suppress_a_sibling(failures):
    # The comparison is label-wise, not string-wise: `notdead.example` merely
    # ends with the characters `dead.example` and must not be punished for it.
    failures.note_zone("dead.example", "all servers failed")
    assert failures.match("notdead.example", 1, 1) is None
    assert failures.match("other.example", 1, 1) is None
    assert failures.match("example", 1, 1) is None


def test_deeper_zone_is_the_one_that_counts(failures):
    # Both remembered: the narrower claim is the accurate one, so the parent's
    # entry must not be used to fail names outside the dead sub-delegation.
    failures.note_zone("dead.example", "all servers failed")
    failures.note_zone("shop.dead.example", "all servers failed")
    assert failures.match("a.shop.dead.example", 1, 1).zone == DomainName("shop.dead.example")
    assert failures.match("b.dead.example", 1, 1).zone == DomainName("dead.example")


def test_keys_are_case_insensitive(failures):
    # RFC 4343: name matching is case-insensitive, and a cache that forgot that
    # would answer `DEAD.example` with a fresh probe while `dead.example` is
    # still remembered as broken.
    failures.note_query("Dead.Example", 1, 1, "x")
    assert failures.match("DEAD.example", 1, 1) is not None
    failures.note_zone("Dead.Example", "x")
    assert failures.match("X.DEAD.EXAMPLE", 1, 1) is not None


def test_query_key_is_per_type_and_class(failures):
    # The key is (QNAME, QTYPE, QCLASS) because that is what §3.2's suppression
    # sentence is about: an incoming query that "corresponds to" the failed one.
    failures.note_query("dead.example", 1, 1, "x")
    assert failures.lookup_query("dead.example", 1, 1) is not None
    assert failures.lookup_query("dead.example", 28, 1) is None
    assert failures.lookup_query("dead.example", 1, 3) is None


def test_expired_zone_entry_stops_suppressing(failures, clock):
    failures.note_zone("dead.example", "all servers failed")
    clock.advance(FAILURE_MAX_TTL_S)
    assert failures.match("anything.dead.example", 1, 1) is None
    # Swept, not merely ignored: an outage that has ended must not keep costing a
    # scan over entries that can never match again.
    assert len(failures) == 0


def test_lru_bound_evicts_the_least_recently_used(clock):
    # RFC 9520 §3.2's resource-exhaustion concern, addressed: the memory an
    # attacker can push into this cache is fixed by configuration, not by the
    # volume of distinct garbage names they can invent.
    failures = FailureCache(max_entries=3, time_fn=clock)
    for name in ("a.example", "b.example", "c.example"):
        failures.note_query(name, 1, 1, "x")
    assert failures.match("a.example", 1, 1) is not None  # makes `a` recently used
    failures.note_query("d.example", 1, 1, "x")
    assert len(failures) == 3
    assert failures.lookup_query("a.example", 1, 1) is not None
    assert failures.lookup_query("b.example", 1, 1) is None


def test_a_repeated_failure_is_not_evicted_by_the_bound(clock):
    # Eviction that dropped the entries currently in use would defeat the cache:
    # re-noticing a failure has to make it the *least* evictable thing present.
    failures = FailureCache(max_entries=2, time_fn=clock)
    failures.note_query("dead.example", 1, 1, "x")
    failures.note_query("other.example", 1, 1, "y")
    failures.note_query("dead.example", 1, 1, "x")
    failures.note_query("third.example", 1, 1, "z")
    assert failures.lookup_query("dead.example", 1, 1).strikes == 2
    assert len(failures) == 2


def test_backoff_restarts_after_the_entry_was_evicted(clock):
    # A remembered duration is not a promise that the network stayed broken. If
    # the entry was evicted, the next failure starts short again -- asserted so
    # that nobody "fixes" this with a permanent per-name strike record, which
    # would be a cache with no expiry, the thing §3.2 forbids.
    failures = FailureCache(max_entries=1, time_fn=clock)
    assert failures.note_query("a.example", 1, 1, "x").ttl == 5.0
    assert failures.note_query("b.example", 1, 1, "x").ttl == 5.0
    assert failures.note_query("a.example", 1, 1, "x").ttl == 5.0


def test_hits_count_suppressed_lookups(failures):
    assert failures.hits == 0
    failures.note_query("dead.example", 1, 1, "x")
    failures.match("dead.example", 1, 1)
    failures.match("dead.example", 1, 1)
    assert failures.hits == 2


def test_prune_and_clear(failures, clock):
    failures.note_query("a.example", 1, 1, "x")
    failures.note_zone("b.example", "y")
    clock.advance(6.0)
    assert failures.prune() == 2
    assert len(failures) == 0
    failures.note_query("c.example", 1, 1, "z")
    failures.clear()
    assert len(failures) == 0


def test_query_key_wins_over_a_zone_key(failures):
    # Both apply; the specific evidence is reported, because a caller logging the
    # reason needs "alias loop" rather than "all servers failed" to be useful.
    failures.note_zone("dead.example", "all servers failed")
    failures.note_query("x.dead.example", 1, 1, "alias loop")
    hit = failures.match("x.dead.example", 1, 1)
    assert hit.key[0] == QUERY_FAILURE
    assert hit.reason == "alias loop"
    assert failures.match("y.dead.example", 1, 1).key[0] == ZONE_FAILURE


def test_names_are_accepted_as_strings_or_domain_names(failures):
    failures.note_query(DomainName("dead.example"), 1, 1, "x")
    assert failures.lookup_query("DEAD.EXAMPLE", 1, 1) is not None
    failures.note_zone(DomainName("gone.example"), "y")
    assert failures.dead_zone_covering("a.gone.example") is not None


def test_root_zone_entry_suppresses_everything(failures):
    # The degenerate case a zone key has to get right: `.` is the ancestor of
    # every name, so an entry for it fails the whole tree. That is correct, and
    # also why a caller must record a zone only when that zone's own servers --
    # not the root's -- were the thing that did not answer.
    failures.note_zone(".", "all servers failed")
    assert failures.match("anything.at.all", 1, 1) is not None
