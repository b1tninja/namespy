"""QNAME minimisation scheduling (RFC 9156) — the arithmetic only.

The schedule and the probe walk are pure functions over label counts, so
they can be pinned to the document's worked example without sockets, fake
zones, or an event loop. The resolver-side behaviour (which servers are
consulted, what counts as authority) is covered in
tests/test_resolver_minimis.py.
"""

from namespy.minimis import (
    MAX_MINIMISE_COUNT,
    MINIMISE_ONE_LAB,
    QnameMinimiser,
    label_schedule,
)
from namespy.names import DomainName


def test_rfc9156_worked_example():
    """RFC 9156 section 2.3 computes this exact schedule for 18 labels."""
    assert label_schedule(18) == [1, 1, 1, 1, 2, 2, 2, 2, 3, 3]


def test_schedule_sums_to_total_and_never_exceeds_the_budget():
    """section 2.3's MUST: bounded iterations, and every label gets exposed."""
    for total in range(0, 64):
        schedule = label_schedule(total)
        assert sum(schedule) == total, total
        assert len(schedule) <= MAX_MINIMISE_COUNT, total
        assert all(chunk > 0 for chunk in schedule), total


def test_short_names_probe_one_label_at_a_time():
    """Fewer labels than MINIMISE_ONE_LAB: the head rule covers everything."""
    for total in range(1, MINIMISE_ONE_LAB):
        assert label_schedule(total) == [1] * total


def test_root_and_empty_names_probe_nothing():
    assert label_schedule(0) == []


def test_probe_walk_strips_from_the_root_outward():
    """www.example.com from the root: com., then example.com., then the real
    question — section 2's "one label more than the zone we trust"."""
    qname = DomainName("www.example.com.")
    minimiser = QnameMinimiser(qname)

    first = minimiser.probe(0)  # root server: authoritative for nothing
    assert first == DomainName("com.")

    second = minimiser.probe(1)  # .com TLD servers
    assert second == DomainName("example.com.")

    third = minimiser.probe(2)  # example.com's own servers hold the answer
    assert third is None
    assert minimiser.probes_sent == 3


def test_single_label_qname_is_asked_as_is():
    """section 3: a one-label QNAME has no meaningful child; normal query."""
    minimiser = QnameMinimiser(DomainName("com."))
    assert minimiser.probe(0) is None
    assert minimiser.probes_sent == 1


def test_budget_exhaustion_degrades_to_the_original_question():
    """The MUST-cap of section 2.3 is a cap on *queries per request*."""
    labels = [f"l{i:02d}" for i in range(12)] + ["example", "com"]
    qname = DomainName(".".join(labels) + ".")
    minimiser = QnameMinimiser(qname)

    depth = 0
    answers = 0
    for _ in range(20):  # deliberately past the budget
        probe = minimiser.probe(depth)
        if probe is None:
            break
        answers += 1
        depth = len(probe.labels())  # pretend each probe came back with a
        # referral exactly at that zone — the pessimistic pace for the budget

    assert answers <= MAX_MINIMISE_COUNT
    assert minimiser.probes_sent <= MAX_MINIMISE_COUNT
    assert minimiser.probe(depth) is None  # stays None; budget stays spent


def test_full_authority_skips_the_schedule_entirely():
    """A server known authoritative for the full QNAME is asked the real
    question without burning a slot (section 3 step 3)."""
    minimiser = QnameMinimiser(DomainName("deep.sub.example.com."))
    assert minimiser.probe(4) is None
    assert minimiser.probes_sent == 0
