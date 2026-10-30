"""MQTYPE on the asking side: what to send, and what the answer actually settled.

:mod:`namespy.mqtype` owns the two option records. This module owns the client's
decisions, which RFC 10029 spreads over three sections and which are awkward to test
while they are tangled into a resolution walk: whether a QT list may be sent at all,
which QTYPEs a returned answer covers, which ones the client still has to ask about,
and what the records for each of them are once they have been picked out of a message
whose sections now hold several types at once.

**Why a separate module rather than more functions in** :mod:`mqtype`. That module is
arithmetic over octets -- a QT list in, a QT list out -- and has no opinion about
messages. Reading a *combined answer* needs the Answer section, the owner names in it,
and the shared RCODE and flags, which is message-level work. The distinction is not
cosmetic: the whole danger of this extension is that one response now speaks for
several (QNAME, QCLASS, QTx) combinations, and the message is where that is either
honoured or got wrong.

**The danger, stated once.** Section 3.5 lists four innocent reasons a requested QTx
may be missing from MQTYPE-Response -- nothing in cache, flags or RCODE mismatched, an
unwilling server, a response too big -- and none of them is a negative answer about
the name:

    "The client MUST subsequently initiate separate standalone queries for all QTx
    values for which an answer is still required."

So a missing QTx is a work item, never NODATA, and this module keeps the two apart by
construction: :attr:`BundleState.NEEDED` carries no records and is not a verdict,
while :class:`BundleState.NODATA` and :class:`BundleState.NXDOMAIN` are reached only
through a QTx the server *did* list. A cache write driven by ``NEEDED`` would be the
bug this design exists to prevent.

**What "listed" is worth.** Section 3.4 obliges a server to merge a QTx only after
"the server MUST evaluate the resulting RCODE and other flags and check that they all
match the values generated from the primary query", and section 3.5 says the merged
answers "share the same RCODE and all other flags". A listed QTx with no records of
its type in the Answer section therefore means the RRset does not exist, and it may be
believed exactly as far as the primary's own NODATA could be -- which is why
:attr:`BundledType.authoritative` travels with it rather than being assumed.

.. rubric:: References

* RFC 10029 section 3.1 (the QT list; each value must be a data RRTYPE), section 3.2
  (a client MUST generate packets conforming to the section 3.3 parsing rules, and the
  choice of when to coalesce is implementation-specific), section 3.3 (the eight
  conditions a conforming server must refuse with FORMERR), section 3.4 (flag
  matching, and the "completely processed" meaning of a listed QTx), section 3.5
  (absent, present, and self-contradictory answers read three different ways; the
  standalone re-ask obligation), appendix A (the worked examples)
* RFC 6891 section 6.1.2 (any OPTION-CODE not understood MUST be ignored, which is
  what makes asking a server that has never heard of this extension free), section 7
  (a badly formatted option value is answered FORMERR)
* RFC 2181 section 5.4.1, cited by section 3.5 as the ranking rule for authoritative
  answers that arrive this way
"""

from dataclasses import dataclass, replace
from enum import Enum

from .enums import DnsResponseCode
from .mqtype import (
    mqtype_answered_qtypes,
    mqtype_query_option,
    mqtype_supported,
    qtypes_still_needed,
)
from .wire import DnsPacketParseError

__all__ = [
    "BundleResult",
    "BundleState",
    "BundledType",
    "bundle_is_void",
    "collect_bundle",
    "query_option_for",
]


class BundleState(Enum):
    """What a combined answer says about one requested QTYPE."""

    #: The server listed this QTx and the message carries records of its type.
    COMBINED = "combined"
    #: Listed, NOERROR, and no records: the RRset does not exist. Believable only as
    #: far as the primary's own NODATA is, which :attr:`BundledType.authoritative`
    #: records.
    NODATA = "nodata"
    #: Listed, and the shared RCODE is NXDOMAIN -- the name does not exist, and every
    #: listed QTYPE shares that verdict, because section 3.4 requires the flags to
    #: match before anything is merged.
    NXDOMAIN = "nxdomain"
    #: Not listed: section 3.5's four innocent reasons. Says nothing about the name,
    #: and means only that this type still needs its own query.
    NEEDED = "needed"


@dataclass(frozen=True)
class BundledType:
    """The outcome for one of the QTYPEs that rode along in the option."""

    qtype: int
    state: BundleState
    #: The records of this type that the combined answer carried, owned by the name the
    #: lookup ended at. Empty for every state but :attr:`BundleState.COMBINED`.
    records: tuple = ()
    #: Whether the answer that produced them claimed authority. Section 3.5 defers to
    #: RFC 2181 section 5.4.1 here: an authoritative answer received this way "MUST be
    #: ranked the same as the answer for the primary question" -- the same, which
    #: includes not being ranked *above* it when the primary was not authoritative.
    authoritative: bool = False
    #: The standalone :class:`~namespy.packet.Response` that answered this type, when
    #: the bundle did not. :func:`~namespy.mqtype.qtypes_still_needed` is a work list,
    #: and this is the work having been done.
    response: object = None
    #: Whether this outcome came from that standalone query rather than from the combined
    #: answer. §3.5 makes the re-ask part of the protocol, so both are answers -- but they
    #: are two different facts about the wire. Only a type inside the MQTYPE-Response was
    #: combined, and only its records are already visible in the packet the caller holds;
    #: a caller that renders the two alike tells a server it supports an extension it has
    #: never seen, and buries the records it had to go and fetch separately.
    separate: bool = False

    @property
    def answered(self) -> bool:
        """Whether anything is now known about this type, bundled or not."""
        return self.state is not BundleState.NEEDED or self.response is not None


@dataclass(frozen=True)
class BundleResult:
    """What one MQTYPE-Query exchange achieved.

    ``supported`` and ``still_needed`` are the two fields a caller acts on, and they
    are deliberately different things. A server that does not implement the extension
    is ``supported=False`` with every type still needed and ``void=False``, because its
    primary answer is perfectly good. A server that contradicted itself is
    ``void=True``, because that answer must be thrown away. Reading the two as one
    boolean is how a client keeps using an answer section 3.5 told it to discard.
    """

    #: Did the server claim support for the extension at all?
    supported: bool
    #: The answer to the primary question -- what
    #: :meth:`~namespy.resolver.RecursiveResolver.resolve` would have returned, or
    #: ``None`` when nothing answered it. :attr:`void` says whether it may be used.
    primary: object = None
    #: The requested QTYPEs the server fully combined, in the order they were asked.
    combined: tuple = ()
    #: The requested QTYPEs that need their own query. Not a negative answer.
    still_needed: tuple = ()
    #: One entry per requested QTYPE, in the order they were asked.
    types: tuple = ()
    #: True when the answer was self-contradictory and must not be used: "If the
    #: MQTYPE-Response option is present more than once or if a QTx value is duplicated
    #: (or duplicates the primary QTYPE field), the client MUST treat the answer as
    #: invalid (equivalent to FORMERR)" (section 3.5). It voids the primary answer too,
    #: which is why it is a flag on the result rather than a state on one type.
    void: bool = False
    #: Why :attr:`void` is set, for a log line or an error message.
    reason: str = ""
    #: QTYPEs the server listed that nobody asked for. Ignored -- section 3.5's list of
    #: invalid shapes does not include this, so the answer stands -- but reported,
    #: because a server inventing types is worth knowing about.
    unrequested: tuple = ()

    def state_of(self, qtype: int) -> BundleState | None:
        """The state of ``qtype``, or ``None`` if it was never asked for."""
        number = int(qtype)
        for entry in self.types:
            if entry.qtype == number:
                return entry.state
        return None

    def records_for(self, qtype: int) -> tuple:
        """The records harvested for ``qtype``; empty unless it was combined."""
        number = int(qtype)
        for entry in self.types:
            if entry.qtype == number:
                return entry.records
        return ()

    def with_primary(self, response) -> "BundleResult":
        """This result, attached to the answer for the primary question."""
        return replace(self, primary=response)

    def reasked(self, qtype: int, *, state: BundleState, records=(), response=None):
        """A copy of this result with the standalone outcome for ``qtype`` filled in.

        Section 3.5 makes the re-ask part of the protocol rather than an optimisation,
        so the result is not complete until every requested type says how it was
        answered -- bundled, or bought with its own query.
        """
        number = int(qtype)
        updated = tuple(
            replace(entry, state=state, records=tuple(records), response=response, separate=True)
            if entry.qtype == number
            else entry
            for entry in self.types
        )
        return replace(
            self,
            types=updated,
            still_needed=tuple(q for q in self.still_needed if q != number),
        )


def query_option_for(primary_qtype, extra_qtypes):
    """The MQTYPE-Query option for ``extra_qtypes``, or ``None`` when there are none.

    ``primary_qtype`` is passed through so section 3.3's last condition is checked
    where the request is built: "A duplicate QTx (or one duplicating the primary QTYPE
    field) in a query" is something a conforming server must refuse, and section 3.2
    obliges a client not to send it -- "DNS clients implementing this specification
    MUST generate packets that conform to the server request parsing rules described in
    Section 3.3".

    Raises :exc:`ValueError` for a list that could not be sent. That is the right
    behaviour at a caller's own API boundary and the wrong one at the transport, where
    an optional extension must never be the reason a name fails to resolve;
    :meth:`namespy.resolver.RecursiveResolver.resolve_bundle` validates up front and
    the send path falls back to a query without the option.
    """
    requested = tuple(int(qtype) for qtype in extra_qtypes)
    if not requested:
        return None
    return mqtype_query_option(requested, primary_qtype=primary_qtype)


def _options_of(response):
    """The EDNS options of *response*, or :const:`None` when they cannot be read.

    An unreadable option is not evidence that the answer is wrong. Section 3.5's
    discard rule is aimed at a *legible* MQTYPE-Response that contradicts itself; an
    unrelated malformed TLV in a stranger's OPT record is RFC 6891 section 7 material,
    and this module reads bundles rather than judging other people's options. So the
    bundle is reported as unsupported -- every type still needed, the primary answer
    untouched -- instead of raising out of a resolution walk.
    """
    try:
        return response.edns_options()
    except DnsPacketParseError:
        return None


def bundle_is_void(response, *, primary_qtype=None, requested=()) -> bool:
    """Whether *response* carries a MQTYPE-Response that contradicts itself.

    The narrow question a resolution loop needs, asked before it classifies or caches
    anything: section 3.5 says such an answer is "invalid (equivalent to FORMERR)", and
    an answer equivalent to a FORMERR must not be stored on its way to the bin. The
    loop does not need the per-type breakdown to know that, and :func:`collect_bundle`
    is the one implementation of the rule so the two cannot disagree about what
    "invalid" means.
    """
    return collect_bundle(response, primary_qtype=primary_qtype, requested=requested).void


def collect_bundle(response, *, primary_qtype=None, requested=(), terminal_name=None):
    """Read *response* as the answer to a MQTYPE-Query for ``requested``.

    Three readings, because section 3.5 commands three:

    * **no MQTYPE-Response** -- the server does not implement the extension. That is a
      normal outcome, not an error: "the client MUST treat the response as if this
      option is unsupported by the server and MUST process the primary response as if
      the MQTYPE-Query option had not been used". ``supported`` is False, nothing is
      ``void``, and every requested type comes back :attr:`BundleState.NEEDED`.
    * **a MQTYPE-Response** -- the server supports it. Each QTx it lists is
      :attr:`~BundleState.COMBINED`, :attr:`~BundleState.NODATA` or
      :attr:`~BundleState.NXDOMAIN` according to what the message holds; each QTx it
      omits is :attr:`~BundleState.NEEDED`, which is section 3.5's work list and not a
      verdict about the name.
    * **a self-contradictory MQTYPE-Response** -- the option twice, a repeated QTx, or
      one repeating the primary QTYPE. ``void`` is True with the reason in ``reason``,
      and the primary answer goes with it, because the sentence says "treat the answer
      as invalid (equivalent to FORMERR)" rather than "ignore the option".

    ``terminal_name`` is the name the lookup ended at, which is not always the name the
    caller asked about: the walk follows CNAMEs, and so do the extras, because
    :class:`~namespy.resolver.Sname` keeps its QTYPE through a re-anchor and the server
    answers a QTx at the target for the same reason it answers the primary there. The
    filter is what stops a bundle harvesting somebody else's RRset -- records owned by
    any other name in the answer section are not an answer for this one. Left ``None``,
    every owner is accepted, which is what the option-level tests want and a live
    lookup should not.
    """
    asked = tuple(int(qtype) for qtype in requested)
    if not asked:
        # Nothing was asked, so nothing can be reported. Answering "unsupported" keeps
        # a caller that forgot to pass a list from reading an empty result as a
        # negative answer for every type in the registry.
        return BundleResult(supported=False)

    options = _options_of(response)
    if options is None or not mqtype_supported(options):
        return BundleResult(
            supported=False,
            still_needed=asked,
            types=tuple(BundledType(qtype, BundleState.NEEDED) for qtype in asked),
        )

    try:
        listed = mqtype_answered_qtypes(options, primary_qtype=primary_qtype)
    except DnsPacketParseError as exc:
        needed = tuple(BundledType(qtype, BundleState.NEEDED) for qtype in asked)
        return BundleResult(
            supported=True, still_needed=asked, types=needed, void=True, reason=str(exc)
        )

    listed_set = {int(qtype) for qtype in listed}
    asked_set = set(asked)
    answers = tuple(getattr(response, "answers", ()) or ())
    authoritative = bool(getattr(response, "AA", False))
    nxdomain = int(getattr(response, "RCODE", 0)) == int(DnsResponseCode.NAME_ERROR)

    entries = []
    for qtype in asked:
        if qtype not in listed_set:
            # Absent, therefore unfinished. Deliberately before any look at the
            # sections: a record of this type in the answer is not evidence the server
            # combined it, and reading it as though it had would let one type's data
            # answer for another.
            entries.append(BundledType(qtype, BundleState.NEEDED))
            continue
        if nxdomain:
            # The name does not exist and every listed QTx shares that. Checked before
            # the records, because a server claiming NXDOMAIN while filling the Answer
            # section has contradicted section 3.5's own description of the message --
            # and the negative answer is the one with a proof attached to believe.
            entries.append(BundledType(qtype, BundleState.NXDOMAIN, authoritative=authoritative))
            continue
        records = tuple(
            record
            for record in answers
            if int(record.rtype) == qtype
            and (terminal_name is None or record.name == terminal_name)
        )
        if records:
            entries.append(
                BundledType(
                    qtype, BundleState.COMBINED, records=records, authoritative=authoritative
                )
            )
        else:
            entries.append(BundledType(qtype, BundleState.NODATA, authoritative=authoritative))

    return BundleResult(
        supported=True,
        combined=tuple(qtype for qtype in asked if qtype in listed_set),
        still_needed=qtypes_still_needed(asked, listed),
        types=tuple(entries),
        unrequested=tuple(sorted(q for q in listed_set if q not in asked_set)),
    )
