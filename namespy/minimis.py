"""QNAME minimisation scheduling (RFC 9156).

The privacy mechanism itself is simple: a server that is not known to be
authoritative for the original QNAME gets only "the QNAME that is the
original QNAME, stripped to just one label more than the longest matching
domain name for which the name server is known to be authoritative"
(RFC 9156 section 2). The interesting half is *how many* labels to expose
per probe, because one-label-per-query is an amplification vector -- a
127-label QNAME under a wildcard zone would otherwise cost a cold resolver
127 upstream queries (RFC 9156 section 2.3, which makes limiting them a
MUST).

This module owns the schedule; the resolver owns when to consult it. The
split exists so the schedule -- pure arithmetic on label counts -- can be
tested against the document's worked example without a network or a fake
zone, and so the resolver's descent loop keeps exactly one job.
"""

from __future__ import annotations

from .names import DomainName

#: RFC 9156 section 2.3: "a maximum number of QNAME minimisation iterations
#: MUST be selected (MAX_MINIMISE_COUNT); a RECOMMENDED value is 10."
MAX_MINIMISE_COUNT = 10

#: RFC 9156 section 2.3: "Optionally, a value for the number of queries that
#: should only have one label appended MAY be selected (MINIMISE_ONE_LAB);
#: a good value is 4." The first probes expose one label each because the
#: labels nearest the root are the ones most likely to be zone cuts -- the
#: privacy benefit is front-loaded there.
MINIMISE_ONE_LAB = 4


def label_schedule(
    total_labels: int,
    one_lab: int = MINIMISE_ONE_LAB,
    max_iterations: int = MAX_MINIMISE_COUNT,
) -> list[int]:
    """The per-probe label increments, per RFC 9156 section 2.3.

    The first ``one_lab`` probes add one label each. The remaining labels
    are "divided proportionally over the remaining iterations
    (MAX_MINIMISE_COUNT - MINIMISE_ONE_LAB)", and "the remainder of the
    division should be added to the last iterations".

    The document's worked example is the regression test: 18 labels with
    (10, 4) yields ``1,1,1,1,2,2,2,2,3,3`` -- ten probes, all 18 labels
    exposed, the widening deferred to the iterations furthest from the
    root where the labels are furthest from being zone cuts.

    Sums to *total_labels* and never exceeds *max_iterations* entries:
    slots that would receive zero labels are dropped rather than spent,
    which is what keeps short names from burning the whole budget.
    """
    total = max(0, int(total_labels))
    if total == 0:
        return []
    one = min(max(1, int(one_lab)), max_iterations, total)
    if total <= one:
        return [1] * total
    head = [1] * one
    rest = total - one
    slots = max_iterations - one
    share, remainder = divmod(rest, slots)
    # Lowest shares first: the remainder lands on the *last* iterations,
    # so the name widens gradually and the widest jumps happen only where
    # few zone cuts are expected.
    body = [share] * (slots - remainder) + [share + 1] * remainder
    return head + [chunk for chunk in body if chunk > 0]


class QnameMinimiser:
    """Per-resolution view of the section 2.3 schedule.

    The resolver tells the minimiser how many labels of the QNAME are
    already exposed -- how many labels the server we are about to query is
    known to be authoritative for -- and the minimiser answers with the
    next name to probe, or ``None`` to send the original question.

    ``None`` means "ask for the whole name now", which happens in exactly
    three situations, and each is the document saying so:

    * the server may already be authoritative for the full QNAME
      (section 3 step 3: "If CHILD is the same as QNAME ... resolve the
      original query as normal");
    * the probe the schedule would send is the full QNAME -- CHILD has
      caught up with QNAME, same rule, just reached by arithmetic;
    * the probe budget is spent. section 2.3's MUST is a cap on outgoing
      queries per request; once reached, degrading toward the classic
      full-name behaviour is the bounded answer, and the last query is
      then the one that ends the lookup rather than another probe.
    """

    def __init__(
        self,
        qname: DomainName,
        one_lab: int = MINIMISE_ONE_LAB,
        max_iterations: int = MAX_MINIMISE_COUNT,
    ) -> None:
        self._qname = qname
        self._all = qname.labels()
        self._schedule = label_schedule(len(self._all), one_lab, max_iterations)
        self._spent = 0

    @property
    def qname(self) -> DomainName:
        return self._qname

    @property
    def probes_sent(self) -> int:
        """How many schedule slots have been consumed (for trace output)."""
        return self._spent

    def probe(self, auth_labels: int) -> DomainName | None:
        """The next name to ask a server with *auth_labels* of authority.

        *auth_labels* is the number of labels of the QNAME that the server
        about to be queried is known to be authoritative for -- the zone-cut
        depth, counted from the root: root servers get 0, a TLD server for
        ``com.`` gets 1, and so on. The child is therefore the *suffix* of
        ``auth_labels + chunk`` labels -- ``DomainName.labels()`` is most
        significant first, so slicing off the front is what strips toward
        the root (RFC 9156 section 2: "stripped to just one label more than
        the longest matching domain name for which the name server is known
        to be authoritative").

        Returns ``None`` exactly when the caller must send the original
        question, per section 3 steps 2-3: either the server may already
        hold the answer (``auth_labels`` reaches the full QNAME), the
        computed child would *be* the full QNAME, or the probe budget is
        spent.
        """
        total = len(self._all)
        known = max(0, min(int(auth_labels), total))
        if known >= total:
            return None
        if self._spent >= len(self._schedule):
            return None
        chunk = self._schedule[self._spent]
        self._spent += 1
        depth = min(known + chunk, total)
        if depth >= total:
            # CHILD == QNAME: section 3 says resolve the original query as
            # normal. The slot was still spent -- this probe was scheduled,
            # it just turned out to need no minimisation.
            return None
        return DomainName.from_labels(self._all[total - depth :])
