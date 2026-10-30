"""A UDP DNS server that answers by recursing with :class:`RecursiveResolver`.

Serving has a different risk profile from resolving. A resolver receives input
from servers it chose; a server receives input from anyone, and every unanswered
query it forwards is a candidate for a reflection/amplification attack. Three
consequences shape this module:

* **Never emit output the operator did not ask for.** The module previously built
  a fresh ``logging.Logger("server")`` and attached a module-global handler to it,
  so importing namespy and constructing a server produced output regardless of
  application configuration -- and an ``INFO`` line per query plus a ``print`` of
  every response turned a query flood into a log flood.
* **Bound the in-flight upstream lookups.** Each inbound datagram previously
  spawned ``asyncio.create_task`` with no reference kept, so the task could be
  garbage-collected mid-flight, and concurrency was whatever the sender chose.
* **Fail closed on malformed input.** A parse failure gets a ``FORMERR`` and a
  debug-level note rather than a traceback.

Serving also means *answering honestly about what this host supports*. A
responder that ignores OPT tells an EDNS requestor nothing about its reassembly
limit and hides the upper eight bits of any RCODE above 15, so
:meth:`DnsServer._apply_edns` builds the reply's OPT from this server's own
numbers -- and sends none at all to a requestor that never asked, which RFC
6891 section 7 makes the correct answer rather than an oversight.

Options inside that OPT are handled by the same rule, applied in two
directions. This server answers a query whose option it does not understand by
ignoring it -- "Any OPTION-CODE values not understood by a responder or
requestor MUST be ignored" (section 6.1.2) -- and answers one whose
option is *misformed* with FORMERR, because section 7 asks for exactly that and
insists the error response still carry an OPT, so a requestor can tell "this
server has EDNS and disliked what you sent" from "this server has no EDNS". The
one option it implements is NSID (RFC 5001): an identity string configured at
construction, returned only to a query that asked for it, never invented on its
own. Padding (RFC 7830) is deliberately *not* honoured here: section 4 says a
responder must pad when asked, section 6 says an implementation must not use
the option over an unencrypted transport, and this server's transport is plain
UDP -- the second MUST is the one that can be obeyed without lying about the
encryption, so padding is dropped and the reply stays its natural size.

MQTYPE (RFC 10029) is implemented in both directions: a malformed request is
refused and a well-formed one is *answered*. A query carrying a broken
MQTYPE-Query option -- an odd-length type list, a Meta RRTYPE inside it, a
repeated QTx, a second copy of the option -- gets FORMERR, because section 3.3
enumerates eight such conditions and requires that answer for each. A valid one
gets section 3.4's combination: the primary question is resolved first and its
RCODE and flags fixed at that moment, each extra QTx is resolved by its own
standalone query, and a result is merged only if it matches the primary on every
one of those values. What survives goes into the section it would have occupied
had it been asked alone (RFC 1035 section 4.1), deduplicated within that section
and deliberately not across sections. The reply carries a MQTYPE-Response option
listing exactly the QTx values folded in whole -- possibly an empty list, which
section 3.4 permits while still requiring the option, because the option's
presence is the entire message a client can read about support.

Three of section 3.4's sentences are load-bearing and easy to get backwards. The
option "MUST NOT itself trigger a truncated response", so a QTx that would push
the answer past what the client advertised is withdrawn and left off the list --
TC is never set on its account -- and processing stops there, which is also what
keeps section 4's amplification worry bounded: a client that asked for eight
types is refused the remaining seven without seven more outbound queries. A
primary answer that is already truncated gets no extra lookups at all, while
still getting the option. And the obligation to send it is not conditional on
success: a server that supports the extension must answer *every* valid query
with the option, including the SERVFAIL that a failed resolution produces, so
that path carries an empty list rather than silence.

.. rubric:: References

* RFC 1035 section 4.1.1 (header), section 4.3 (server behaviour)
* RFC 5001 section 2.2 (send NSID only when it was asked for, ignore any
  payload the requestor put in the request form of the option)
* RFC 5358 section 3 (why a recursing server is an amplification instrument),
  section 4 (BCP 140: give recursive service to intended clients only)
* RFC 5625 section 6.2 (do not listen on interfaces you do not control), section
  6.3 (intrinsically malformed traffic MAY be dropped rather than answered)
* RFC 6891 section 6.1.1 (one OPT per message, OPT is never forwarded, an OPT
  request must be answered with an OPT), section 6.1.2 (option format; unknown
  codes must be ignored), section 6.1.3 (BADVERS for a VERSION this server does
  not implement), section 7 (an OPT-free request must be answered without OPT;
  an option that is badly formatted or out of range must be answered FORMERR,
  with an OPT)
* RFC 7830 sections 4, 6 (a responder must pad when asked -- and must not use
  the option at all on an unencrypted transport, which plain UDP is)
* RFC 7873 section 5.2 (COOKIE lengths, and the FORMERR for an illegal one)
* RFC 8914 section 2 (an Extended DNS Error may ride in any response to a query
  that carried an OPT), section 3 (drop EDE options before other data when the
  response outgrows the requestor's payload size), sections 4.22-4.23 (the codes
  this server's own failures earn)
* RFC 10029 section 3.3 (the MQTYPE-Query conditions that oblige a FORMERR),
  section 3.4 (combining several QTYPEs into one answer: the flag-matching test,
  the per-section duplicate rule, and the rule that the option must never itself
  cause truncation), section 3.5 (how a client reads a QTx missing from the
  answer, which is what makes declining one quietly legitimate), section 4 (the
  operator-configurable limit on how many QTx values one query may ask for)
* RFC 6895 section 3.1 (the data/QTYPE/Meta split a QTx is validated against)
"""

import asyncio
import logging

from . import enable_path_mtu_discovery
from .edns import (
    COOKIE_OPTION_CODE,
    ERROR_OPTION_CODE,
    MQTYPE_QUERY_OPTION_CODE,
    NSID_OPTION_CODE,
    EdnsOption,
    cookie_length_valid,
    extended_dns_error_option,
    extended_error_option_valid,
    find_option,
    nsid_of,
)
from .enums import DnsOpCode, DnsQR, DnsResponseCode
from .mqtype import (
    MQTYPE_RECOMMENDED_QTX_LIMIT,
    mqtype_query_rejection,
    mqtype_response_option,
    qtypes_of,
)
from .packet import (
    OPT_RTYPE,
    DnsPacket,
    DnsPacketParseError,
    DnsQuestion,
    Query,
    Response,
)
from .resolver import EDNS_PAYLOAD_SIZE, RecursiveResolver

LOGGER = logging.getLogger(__name__)

#: EDNS(0) VERSION this server implements. RFC 6891 section 6.1.3: "If a
#: responder does not implement the VERSION level of the request, then it MUST
#: respond with RCODE=BADVERS", and "the VERSION of each response SHOULD be the
#: highest implementation level of the responder" -- which is this number.
EDNS_VERSION_SUPPORTED = 0

#: Largest RCODE expressible without an OPT record. RFC 6891 section 6.1.3
#: lays OPT's TTL out so that "EXTENDED-RCODE value 0 indicates that an
#: unextended RCODE is in use (values 0 through 15)"; above that, the upper
#: eight bits have nowhere to go unless OPT is present.
MAX_UNEXTENDED_RCODE = 0xF

#: Payload size advertised in this server's own OPT record. Section 6.2.4 makes
#: that field the *responder's* reassembly limit -- it is deliberately not a
#: copy of the requestor's -- and section 6.2.5 asks for a large starting point.
#: The same 1232-octet figure the resolver advertises outbound is reused here so
#: that one number describes this host's stack rather than two.
RESPONDER_PAYLOAD_SIZE = EDNS_PAYLOAD_SIZE

#: RFC 8914 section 4.22: "The requested operation or query is not supported."
EDE_NOT_SUPPORTED = 21

#: RFC 8914 section 4.23: "The resolver could not reach any of the authoritative
#: name servers (or they potentially refused to reply)." Which is precisely the
#: condition this server is in when its resolver hands back nothing.
EDE_NO_REACHABLE_AUTHORITY = 22

#: The Extended DNS Errors this server reports about *itself*.
#:
#: Only its own failures are listed, and that is the deliberate half of RFC 8914
#: section 3: relaying what an upstream server said is left to the forwarder --
#: "whether or not (and how) to pass along EDE information on to their original
#: client is implementation dependent" -- and this one keeps upstream explanations
#: in its log and in its failure cache rather than putting a stranger's words on the
#: wire as its own. Codes 0 through 24 belong to that registry; nothing here invents
#: one.
#:
#: The text is short on purpose (section 3: "implementers and operators creating EDE
#: options SHOULD avoid lengthy EXTRA-TEXT contents") and names this software, which
#: is the attribution the same paragraph asks for and none of the private information
#: section 2 warns against.
_OWN_FAILURE_ERRORS = {
    int(DnsResponseCode.SERVER_FAILURE): (
        EDE_NO_REACHABLE_AUTHORITY,
        b"namespy: no authoritative answer",
    ),
    int(DnsResponseCode.NOT_IMPLEMENTED): (
        EDE_NOT_SUPPORTED,
        b"namespy: only QUERY is supported",
    ),
}

#: How many upstream lookups one server instance allows at once. Bounded on
#: purpose: it is what makes this server's *egress* provably limited relative to
#: its ingress, which is the property an amplification defence needs (RFC 5358
#: section 3). No specification sets a number -- this one is a design decision.
MAX_CONCURRENT_LOOKUPS = 32

#: The three RR sections of a message, as the attribute that holds each one and
#: the header count that describes it, in the order RFC 1035 section 4.1 lays
#: them out. RFC 10029 section 3.4 is a rule *about sections* -- extra RRs go
#: "into the same sections in which they would have appeared in a standalone
#: query", and duplicates are removed within a section and not across them -- so
#: this is the one place that knows what a section is and how it is counted.
_SECTIONS = (
    ("answers", "ANCOUNT"),
    ("nameservers", "NSCOUNT"),
    ("additional_records", "ARCOUNT"),
)


class DnsServer(asyncio.Protocol):
    """Answer DNS queries over a datagram transport by recursing.

    :param resolver: the :class:`~namespy.resolver.RecursiveResolver` that does
        the work. It must already be bound to a transport, which is why resolver
        and server are connected to the event loop in that order.
    :param max_concurrent_lookups: cap on outstanding recursive lookups.
    """

    def __init__(
        self,
        resolver,
        max_concurrent_lookups: int = MAX_CONCURRENT_LOOKUPS,
        nsid=None,
        max_qtypes: int | None = MQTYPE_RECOMMENDED_QTX_LIMIT,
    ):
        """
        :param nsid: the RFC 5001 name-server identifier to advertise when a
            query asks for it — :class:`bytes`, or text to be encoded as UTF-8,
            or :const:`None` for a server that never sends the option.

            Opaque on the wire, and it should stay that way: RFC 5001 section 2
            wants it to identify "the instance of the name server", which is why
            a hostname or a rack name is the usual answer and why nothing here
            tries to parse it. Leaving it unset is the conservative default --
            section 2.2 forbids sending the option unasked, and a server with no
            identity to declare has nothing to leak about which machine in a
            anycast set answered.
        :param max_qtypes:
            how many MQTYPE QTx values one query may have processed (RFC 10029
            section 4: "Implementors SHOULD therefore allow operators to
            configure limits on the number of QTx values specified and/or the
            resulting response size"). The default is the document's own
            public-DNS figure, four; :const:`None` removes the limit, which is
            what the same paragraph advises for DNS-SD and private networks.
            Negative numbers are read as zero.

            Types past the limit are left out of the MQTYPE-Response list rather
            than refused. Exceeding an operator's limit is not one of section
            3.3's eight FORMERRs, and section 3.5 lists "the server was
            unwilling to process the request (for example, because a limit was
            exceeded)" as an ordinary reason for a QTx to be absent -- so a quiet
            omission is the answer the specification already has for this, and it
            costs no outbound lookups either.

            Zero is a configuration rather than a mistake, and it is the one that
            buys the support signal for nothing: a query is still answered, still
            carries a MQTYPE-Response, and the list in it is empty. Silence would
            be the other available message, and section 3.6 reads silence as "this
            server cannot combine", which is not true of a server that simply
            declined this much work.
        """
        if not isinstance(resolver, RecursiveResolver):
            raise TypeError(f"resolver must be a RecursiveResolver, got {type(resolver).__name__}")
        self.resolver = resolver
        self.log = LOGGER
        self.max_concurrent_lookups = max(1, int(max_concurrent_lookups))
        # Zero is allowed to mean zero -- it is a deployment choice, not a
        # mis-set knob, and the clamp is against negatives rather than against
        # the floor. A negative would slice the requested list from its wrong
        # end and hand back types the client never asked for.
        self.max_qtypes = None if max_qtypes is None else max(0, int(max_qtypes))
        if isinstance(nsid, str):
            nsid = nsid.encode("utf-8")
        self.nsid = None if nsid is None else bytes(nsid)
        # asyncio holds only a weak reference to a task, so a task created here
        # without being stored can be collected before it finishes.
        self._tasks: set[asyncio.Task] = set()
        self._slots = asyncio.Semaphore(self.max_concurrent_lookups)

    def connection_made(self, transport):
        self.transport = transport
        enable_path_mtu_discovery(transport, self.log)

    def connection_lost(self, _exc):
        # The task references matter as much as the cancellation: a task that is
        # merely cancelled can still be referenced forever, and every datagram
        # after a reconnect would add another.
        for task in list(self._tasks):
            task.cancel()
        self._tasks.clear()

    def _spawn(self, coro):
        """Create a task, keep a reference to it, retire it when it finishes."""
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    def _reply(
        self, response, addr, request=None, extended_errors=(), mqtype_answered=None
    ) -> None:
        if request is not None:
            self._apply_edns(request, response, extended_errors, mqtype_answered)
        wire = bytes(response)
        self.log.debug(
            "server_reply(dst=%s id=%#06x rcode=%s octets=%d)",
            addr[0],
            response.ID,
            response.RCODE,
            len(wire),
        )
        self.transport.sendto(wire, addr)

    def _error(self, dns_packet, addr, rcode: DnsResponseCode, mqtype_answered=None) -> None:
        """Reply with *rcode*, echoing the question so the client can match it.

        ``mqtype_answered`` is the list to put in a MQTYPE-Response option --
        empty on this path, but *present*, because RFC 10029 section 3.4 opens by
        obliging a supporting server to return the option in its response to a
        valid query and attaches no condition to that response being an error. A
        server that goes silent exactly when resolution fails is indistinguishable
        from one that never implemented the extension, which is the confusion the
        option exists to avoid.

        A client correlates a response with its query by ID *and* the echoed
        question (RFC 5452 sections 4.2-4.3 and 9.1), so an error response with an
        empty question section is one the client may discard. *dns_packet* is
        ``None`` when the datagram could not be parsed at all, and there is
        nothing to echo.

        An Extended DNS Error goes along when this server has something to say
        about the RCODE -- see :meth:`_own_failure_errors` for which ones do, and
        :meth:`_apply_edns` for why a client that never sent an OPT never sees it.
        """
        questions = list(dns_packet.questions) if dns_packet is not None else []
        self._reply(
            Response(
                ID=0 if dns_packet is None else dns_packet.ID,
                QR=DnsQR.RESPONSE,
                RCODE=rcode,
                questions=questions,
            ),
            addr,
            request=dns_packet,
            extended_errors=self._own_failure_errors(rcode),
            mqtype_answered=mqtype_answered,
        )

    @staticmethod
    def _own_failure_errors(rcode) -> tuple:
        """The EDE option this server sends with *rcode*, or an empty tuple.

        RFC 8914 section 2 lets the option accompany any response, and section 3
        refuses to bind codes to RCODEs ("This document does not allow or prohibit
        any particular extended error codes and information to be matched with any
        particular RCODEs"), so the pairing is the operator's to make. These two are
        the cases where the RCODE alone leaves the client guessing: SERVFAIL says
        "no answer" and not "nobody answered", and NOTIMP says "no" and not "to
        what". FORMERR, BADVERS and the rest already carry their own explanation in
        the code the client can read, so they get nothing.
        """
        explained = _OWN_FAILURE_ERRORS.get(int(rcode))
        if explained is None:
            return ()
        info_code, extra_text = explained
        return (extended_dns_error_option(info_code, extra_text),)

    @staticmethod
    def _opt_count(dns_packet) -> int:
        """How many OPT records a request carried (RFC 6891 section 6.1.1 allows one)."""
        return sum(1 for record in dns_packet.additional_records if int(record.rtype) == OPT_RTYPE)

    def _apply_edns(self, request, response, extended_errors=(), mqtype_answered=None) -> None:
        """Attach the OPT record this server is entitled -- or obliged -- to send.

        Two halves of RFC 6891 meet here. Section 6.1.1: "If an OPT record is
        present in a received request, compliant responders MUST include an OPT
        record in their respective responses." Section 7 is the mirror image:
        "Lack of presence of an OPT record in a request MUST be taken as an
        indication that the requestor does not implement any part of this
        specification and that the responder MUST NOT include an OPT record in
        its response." Answering an unextended client with OPT advertises a
        capability it never asked about; answering an extended client without it
        strands the extended RCODE in the header.

        Whatever OPT the recursive walk collected from an upstream server goes
        in the bin first. Section 6.1.1 says "OPT RRs MUST NOT be cached,
        forwarded, or stored in or loaded from master files", and the record the
        walk left behind carries *that server's* payload size and flags -- which
        this server would be misrepresenting as its own.
        """
        intended = int(response.extended_rcode)
        response.remove_edns()
        incoming = None if request is None else request.opt()
        if incoming is None:
            if intended > MAX_UNEXTENDED_RCODE:
                # Nothing can carry the upper eight bits: section 6.1.3 says
                # EXTENDED-RCODE 0 means "values 0 through 15", and section 7
                # forbids the only carrier this client will accept. Masking the
                # number instead (RCODE 23 would read as 7, FORMERR) would lie
                # about *why* the answer failed, so the client gets SERVFAIL --
                # the honest "there is no answer you can be given". That
                # substitution is a design decision, not a specification
                # instruction, and is logged because it is the one place an
                # answer changes on the way out.
                self.log.debug("server_unextended_rcode_downgrade(rcode=%s)", intended)
                response.RCODE = int(DnsResponseCode.SERVER_FAILURE)
            return

        def attach(options) -> None:
            """Put an OPT record on *response* carrying *options*.

            A closure because RFC 8914 section 3 can make this run twice: the
            explanation is dropped and the record rebuilt when keeping it would have
            pushed the answer past what the client said it could reassemble.
            """
            response.remove_edns()
            response.add_edns(
                RESPONDER_PAYLOAD_SIZE,
                version=EDNS_VERSION_SUPPORTED,
                options=options,
            )
            if intended > MAX_UNEXTENDED_RCODE:
                # Put the effective code back where the dropped OPT used to keep it.
                # Serialisation splits it again -- header nibble here, upper eight
                # in the record we just added (RFC 6891 section 6.1.3).
                response.RCODE = intended

        # The early return above cannot strand a MQTYPE-Response obligation: an
        # MQTYPE-Query option can only arrive inside an OPT record, so a requestor
        # that sent no OPT never asked, and RFC 6891 section 7's "no OPT in, no OPT
        # out" is the whole of what that client is owed.
        attach(self._reply_options(request, extended_errors, mqtype_answered))
        if extended_errors:
            self._keep_explanation_inside_advertised_size(
                request, response, attach, mqtype_answered
            )

    def _keep_explanation_inside_advertised_size(
        self, request, response, attach, mqtype_answered=None
    ) -> None:
        """Drop the EDE options if they made the response bigger than the client asked for.

        RFC 8914 section 3: "When the response grows beyond the requestor's UDP
        payload size [RFC6891], servers SHOULD truncate messages by dropping EDE
        options before dropping other data from packets." That ordering is the whole
        method: the explanation is the supplemental thing, so it is what goes, and
        what the client asked for is what survives.

        The same paragraph's "Implementations SHOULD set the truncation bit when
        dropping EDE options" is deliberately not followed, and the reason is which
        response this is. TC is a promise that a retry over TCP will find the rest of
        an answer, and on a response carrying nothing but its echoed question there is
        no rest to find -- setting it would buy a TCP handshake and the same SERVFAIL
        back. The log line is the honest record, and the RCODE already said there is
        no answer.
        """
        incoming = None if request is None else request.opt()
        if incoming is None:
            return
        # RFC 6891 section 6.2.3: "Values lower than 512 MUST be treated as equal to
        # 512", so a client advertising something tiny is still measured against the
        # floor it is owed rather than a limit that trims everything away.
        advertised = max(DnsPacket.EDNS_MINIMUM_PAYLOAD, int(incoming.rclass))
        size = len(bytes(response))
        if size <= advertised:
            return
        self.log.debug("server_edns_error_dropped(octets=%d advertised=%d)", size, advertised)
        # Rebuild with the explanation gone and everything else left alone --
        # including the MQTYPE-Response. RFC 8914 section 3 names the EDE option as
        # the thing to drop, and RFC 10029 section 3.4 makes its own option the one
        # that may not go: a reply that loses it says "this server does not
        # implement multiple QTYPEs", which is a statement no amount of re-asking
        # takes back from the client's side.
        attach(self._reply_options(request, mqtype_answered=mqtype_answered))

    def _reply_options(self, request, extended_errors=(), mqtype_answered=None) -> list:
        """The options this server puts in its own OPT for this request.

        NSID, and only when it was asked for. RFC 5001 section 2.2 is
        unambiguous in both directions: "A name server MUST NOT send an NSID
        option back to a resolver which did not request it", and "The name
        server MUST ignore any NSID payload data that might be present in the
        query message" -- so the *presence* of the option is the request, and
        whatever the client put in it is discarded rather than echoed. MQTYPE is
        asked for the same way and answered at the bottom of this docstring.

        Everything else the query carried is dropped on the floor, which is the
        documented treatment of an option a responder has no behaviour for
        ("Any OPTION-CODE values not understood by a responder or requestor MUST
        be ignored", RFC 6891 section 6.1.2). Padding is the interesting
        case, because here the code *is* understood and the answer is still no:
        RFC 7830 section 4 makes padding a MUST for a responder that is asked,
        while section 6 forbids the option outright on a transport that is not
        encrypted. This server's transport is plain UDP, so honouring section 4
        would mean obeying one MUST by breaking another; section 6 is the
        sentence that speaks to the situation this server is actually in, and it
        is the one kept. A future DNS-over-TLS front end is where padding belongs.

        An Extended DNS Error, when the caller has one to report, goes last. That
        position is RFC 8914 section 3's ordering made concrete: a server whose
        response has outgrown the requestor's payload size should drop EDE options
        "before dropping other data from packets", and an option already at the end of
        an OPT is the cheapest thing on the wire to give up -- which is how
        :meth:`_keep_explanation_inside_advertised_size` can remove it without
        disturbing anything else.

        A MQTYPE-Response, when ``mqtype_answered`` is not :const:`None`, goes
        immediately ahead of it for the mirror reason: RFC 10029 section 3.4 needs
        that option to survive precisely the response that got too big to carry
        something, and an option the size rule is not allowed to eat has to be
        somewhere the size rule is not looking. ``None`` means the query never
        asked, and sending the option unasked would be a claim about this server
        that no one requested.
        """
        options = []
        try:
            asked = nsid_of(request.edns_options()) if request is not None else None
        except DnsPacketParseError:
            # Already refused upstream by `_edns_options_or_error`, but the reply
            # to that refusal comes through here, and section 7 requires that
            # reply to carry an OPT -- so a second reading of the same broken
            # option has to answer "nothing asked for", not raise.
            asked = None
        if self.nsid is not None and asked is not None:
            options.append(EdnsOption(NSID_OPTION_CODE, self.nsid))
        if mqtype_answered is not None:
            # The empty list is the point of this branch as much as the filled one:
            # section 3.4 allows MQTYPE-Response to be empty while still requiring
            # "the option must still be returned", because presence is the whole of
            # what a client learns about support and absence is what a server that
            # never implemented the extension looks like.
            options.append(mqtype_response_option(mqtype_answered))
        options.extend(extended_errors)
        return options

    def _edns_options_or_error(self, dns_packet, addr) -> bool:
        """Whether ``dns_packet``'s options survive a first reading.

        RFC 6891 section 7: "If there is a problem with processing the OPT
        record itself, such as an option value that is badly formatted or that
        includes out-of-range values, a FORMERR MUST be returned. If this
        occurs, the response MUST include an OPT record." The second sentence is
        why this cannot be folded into the generic parse failure path -- that
        one answers with no OPT at all, which would tell the requestor this
        server has no EDNS rather than that it disliked the option it read.

        Two modelled options have a length to get wrong. COOKIE's rule is RFC 7873
        section 5.2.2's: "In summary, valid cookie lengths are 8 and 16 to 40
        inclusive", and nothing else. EDE's is only a floor -- RFC 8914 section 2
        makes the INFO-CODE the one part of the option that is always present, so
        fewer than two octets is a "badly formatted" option value in section 7's
        phrase -- while anything *longer* is somebody else's meaning and is left
        alone, because section 3's "Receivers MUST be able to accept EDE codes and
        EXTRA-TEXT in all messages" covers unassigned and private-use codes alike.
        NSID is opaque and any length is legal, and an unregistered code is not
        evaluated at all -- section 6.1.2's "MUST be ignored" covers its payload too,
        so refusing a private-code option for its contents would be inventing a rule.

        MQTYPE (RFC 10029) is judged by its own document's list rather than by a
        length, because its option carries a *list* and the ways to get a list wrong
        are not merely "short" and "long": section 3.3 enumerates eight of them and
        mandates FORMERR for each. All eight are checked by
        :func:`namespy.mqtype.mqtype_query_rejection`, shared with the sending side so
        the two can never disagree about what a valid option is. Worth knowing which
        conditions this path can actually reach: a message with QDCOUNT=0 is refused
        earlier for that reason alone (same RCODE), and a non-QUERY opcode earns
        NOTIMP before options are read -- RFC 2929 section 3.1's rule for an opcode a
        receiver does not implement, which outranks a complaint about its options.
        """
        try:
            options = dns_packet.edns_options()
        except DnsPacketParseError as exc:
            self.log.debug("server_bad_edns_option(src=%s err=%s)", addr[0], exc)
            self._error(dns_packet, addr, DnsResponseCode.FORMAT_ERROR)
            return False
        cookie = find_option(options, COOKIE_OPTION_CODE)
        if cookie is not None and not cookie_length_valid(len(cookie.data)):
            self.log.debug("server_bad_cookie_length(src=%s length=%s)", addr[0], len(cookie.data))
            self._error(dns_packet, addr, DnsResponseCode.FORMAT_ERROR)
            return False
        for option in options:
            # Every EDE option, not the first: RFC 8914 section 3 lets a sender put
            # more than one in a message, so a request that carries one good and one
            # unreadable has still shown that its OPT cannot be trusted.
            if option.code == ERROR_OPTION_CODE and not extended_error_option_valid(option):
                self.log.debug(
                    "server_bad_edns_error_length(src=%s length=%s)",
                    addr[0],
                    len(option.data),
                )
                self._error(dns_packet, addr, DnsResponseCode.FORMAT_ERROR)
                return False
        reason = mqtype_query_rejection(
            options,
            opcode=dns_packet.OPCODE,
            qdcount=dns_packet.QDCOUNT,
            primary_qtype=dns_packet.questions[0].qtype if dns_packet.questions else None,
        )
        if reason is not None:
            self.log.debug("server_bad_mqtype_query(src=%s reason=%s)", addr[0], reason)
            self._error(dns_packet, addr, DnsResponseCode.FORMAT_ERROR)
            return False
        return True

    # ------------------------------------------------------- MQTYPE (RFC 10029)

    @staticmethod
    def _mqtype_request(dns_packet):
        """The QTx list this query asked for, or ``None`` when it did not ask.

        ``None`` and an empty list are kept apart on purpose. Section 3.3 makes
        "an MQTYPE-Query option with an empty QT list" a FORMERR, so a *request*
        can never legitimately carry no types at all, while section 3.4 says the
        opposite of the answer: that list may be empty and the option must still be
        returned. One falsy value standing in for both would end up sending a
        client an option it never asked for.

        Nothing is validated here. :meth:`_edns_options_or_error` has already run
        section 3.3's eight conditions over the same option and refused the message
        if any of them held, which is what makes
        :func:`~namespy.mqtype.qtypes_of` safe to call without a handler -- and it
        is the reason those two calls cannot change places.
        """
        option = dns_packet.edns_option(MQTYPE_QUERY_OPTION_CODE)
        return None if option is None else qtypes_of(option)

    @staticmethod
    def _standalone_query(dns_packet, qtype: int):
        """A query for one QTx, as it would have looked having been the question.

        Deliberately minimal, and the reason is one line of the resolver rather
        than a paragraph of specification: :meth:`RecursiveResolver.resolve`
        rewrites the OPT of every message it sends with its own payload size and
        its own option list, so copying the client's OPT here would copy a thing
        that is about to be thrown away. It would also say things this server does
        not mean -- forwarding a COOKIE hands an upstream a token this server never
        issued (RFC 7873 section 5.2.1), and forwarding the MQTYPE-Query would ask
        that upstream to do the combining section 3.4 makes the responder's own
        job. Section 3.4 asks for "appropriate outbound queries", plural and
        standalone; this is one of them.
        """
        question = dns_packet.questions[0]
        return Query(
            ID=dns_packet.ID,
            RD=dns_packet.RD,
            questions=[DnsQuestion(question.name, qtype, question.qclass)],
        )

    @staticmethod
    def _recount(response) -> None:
        """Recompute the header's section counts from the sections themselves.

        The counts are stored and not derived: ``DnsPacket.__init__`` sets them from
        whatever lists it is handed, and ``__bytes__`` writes the stored figures
        alongside every record the lists hold. A merged answer whose ANCOUNT still
        says one is therefore a message that claims one record and carries two --
        which is a parse error on the way back in, and a lie on the way out.
        Anything that adds or withdraws records owes this call.
        """
        for section, count in _SECTIONS:
            setattr(response, count, len(getattr(response, section)))

    @staticmethod
    def _record_key(record):
        """What makes two RRs the same RR: everything about one except its TTL.

        Section 3.4 obliges a server to "detect duplicate RRs and keep only a single
        copy of each RR in its respective section", and the duplicates it worries
        about -- the CNAME both questions walked, the SOA neither answer needed --
        were read at different moments and may disagree about how long they stay
        true. RFC 2181 section 5.1 then decides which copy survives: an RRset is a
        set of RRs sharing name, type, class *and TTL*, so keeping both copies
        because their TTLs differ would emit an RRset that is not allowed to exist.
        The first copy wins, and the first copy is always the one the primary answer
        already had -- which is the answer whose RCODE and flags the whole response
        is now speaking with.
        """
        return (
            str(record.name).lower(),
            int(record.rtype),
            int(record.rclass),
            bytes(record.rdata),
        )

    @classmethod
    def _new_records(cls, response, other) -> dict:
        """RRs of *other* that *response* does not hold yet, grouped by section.

        Sections are compared with each other and never pooled, which is what the
        same section asks twice over: extra RRs go "into the same sections in which
        they would have appeared in a standalone query", and "RRs can be
        legitimately duplicated in different sections such as for the (SOA,
        TYPE12345) combination at a zone apex". An SOA in the Answer section for one
        QTx and the same SOA in the Authority section as another one's proof of
        nonexistence are two different statements about the name; pooling them
        would silently drop one.

        OPT is the one record that never crosses over. RFC 6891 section 6.1.1: "OPT
        RRs MUST NOT be cached, forwarded, or stored in or loaded from master
        files" -- and even if the walk's OPT had been worth forwarding, which its
        foreign payload size and flags prove it is not, a second OPT in the
        additional section would break that section's one-per-message rule.
        """
        fresh: dict[str, list] = {}
        for section, _count in _SECTIONS:
            held = {cls._record_key(record) for record in getattr(response, section)}
            wanted = []
            for record in getattr(other, section):
                key = cls._record_key(record)
                if int(record.rtype) == OPT_RTYPE or key in held:
                    continue
                held.add(key)
                wanted.append(record)
            fresh[section] = wanted
        return fresh

    @staticmethod
    def _flags_match(primary, other) -> bool:
        """Whether *other* may be folded into *primary* (RFC 10029 section 3.4).

        "For each individual combination, the server MUST evaluate the resulting
        RCODE and other flags and check that they all match the values generated
        from the primary query." Which flags counts is a judgement, and it is worth
        naming because the answer decides what gets thrown away:

        * RCODE, because an answer saying the name exists and one saying it does
          not cannot occupy one message -- section 3.4's own example is a NOERROR
          primary with a SERVFAIL combination;
        * AA, because authority is a claim about which server may make claims, and
          the section's other example -- an NS-plus-DS query at the parent side of a
          zone cut -- differs on this bit and nothing else;
        * AD, because "DNSSEC valid" is a promise the primary cannot make for an
          answer it did not resolve;
        * TC, because a truncated combination is not a complete RRset, and the
          complete RRset is the unit this section merges.

        RA and Z are left out deliberately. RA is this server's statement about
        itself and identical in everything it sends; Z must be zero in both. Either
        comparison could only reject a merge over a difference that says nothing
        about the answer.
        """
        return (
            int(primary.RCODE) == int(other.RCODE)
            and bool(primary.AA) == bool(other.AA)
            and bool(primary.TC) == bool(other.TC)
            and bool(primary.ad) == bool(other.ad)
        )

    def _prospective_size(self, request, response, answered) -> int:
        """How big *response* would be carrying this server's OPT and *answered*.

        The OPT has to be inside the measurement because the OPT is what carries the
        claim: an option costs four octets of header plus two per QTx, so sizing the
        message without it reports room that the thing being measured then eats. The
        option list comes from :meth:`_reply_options`, the same call that builds the
        real one, so NSID and anything else the reply will carry is paid for here
        rather than discovered by a client.

        The temporary record is put back afterwards, and that is not tidiness. The
        response may still hold the OPT the recursive walk collected, and for an
        RCODE above 15 that record is where the upper eight bits live:
        :meth:`_apply_edns` reads ``extended_rcode`` off the object it is handed a
        moment from now, so an OPT left behind here would quietly change which RCODE
        the client is finally told.
        """
        saved = list(response.additional_records), response.ARCOUNT
        try:
            response.add_edns(
                RESPONDER_PAYLOAD_SIZE,
                version=EDNS_VERSION_SUPPORTED,
                options=self._reply_options(request, mqtype_answered=answered),
            )
            return len(bytes(response))
        finally:
            response.additional_records, response.ARCOUNT = saved

    async def _combine_mqtype(self, request, response, requested) -> list[int]:
        """Fold the extra QTYPEs into *response*; report the ones that made it.

        RFC 10029 section 3.4, followed in the order the document gives its rules.
        *response* is modified in place and the returned list is what goes into the
        MQTYPE-Response option; a QTx joins that list only once its records are
        already in the message and the whole message still fits, which is the one
        ordering that cannot end up claiming a type it did not deliver.

        Running here rather than in :meth:`respond_to_packet` is what keeps the
        egress bound honest. The caller holds one slot of ``self._slots`` across the
        primary lookup and every combination, so a query for five types still has
        exactly one lookup outstanding upstream at any moment -- the ratio the
        amplification defence in RFC 5358 section 3 depends on is unchanged. The
        number of lookups per client does grow, and it is capped twice: by
        ``max_qtypes``, and by the size rule below that stops instead of continuing.
        That is the shape RFC 10029 section 4 asks an operator to be able to
        configure.

        Two kinds of stop run through this, and only one of them is a refusal. The
        size rule stops the loop because the next type cannot be delivered whole;
        ``max_qtypes`` stops it because an operator decided how much work a question
        may cost. A truncated primary is neither: section 3.4's "If this initial
        response results in truncation (TC=1), then the additional queries specified
        in the MQTYPE-Query option MUST NOT be processed" is an instruction about
        *this* exchange, because the full set can only be had over TCP, where this
        method runs again on the answer that arrives there and the option belongs with
        it. Returning the empty list -- rather than nothing -- is what keeps the
        support signal intact on all three paths.
        """
        if response.TC:
            # "If this initial response results in truncation (TC=1), then the
            # additional queries specified in the MQTYPE-Query option MUST NOT be
            # processed." Not one lookup is bought -- and the option still goes out,
            # because the same section opens by requiring it "even if that response
            # is truncated". TC says the answer continues over TCP; it does not say
            # this server implements nothing.
            self.log.debug("server_mqtype_primary_truncated(qtypes=%d)", len(requested))
            return []
        if self.max_qtypes is not None and len(requested) > self.max_qtypes:
            self.log.debug(
                "server_mqtype_over_limit(requested=%d limit=%d)",
                len(requested),
                self.max_qtypes,
            )
            requested = requested[: self.max_qtypes]
        incoming = request.opt()
        # RFC 6891 section 6.2.3, the same floor the EDE rule uses: "Values lower
        # than 512 MUST be treated as equal to 512", so a requestor advertising a
        # number designed to make the answer empty is owed the minimum instead -- and
        # a request with no OPT, which cannot have asked, sizes nothing at all.
        advertised = 0 if incoming is None else int(incoming.rclass)
        budget = max(DnsPacket.EDNS_MINIMUM_PAYLOAD, advertised)
        answered: list[int] = []
        for qtype in requested:
            combination = await self.resolver.resolve(self._standalone_query(request, qtype))
            if combination is None or not self._flags_match(response, combination):
                # Nothing to fold in, or a fold the section forbids: "the mismatching
                # additional response MUST NOT be included in the final combined
                # response, and its QTx value MUST NOT be included in the
                # MQTYPE-Response option's list". A lookup that returned no answer at
                # all mismatches by definition -- there are no flags to compare
                # against. The remaining types are still tried, because nothing here
                # says to stop; only the size rule below is allowed to.
                self.log.debug("server_mqtype_mismatch(qtype=%d)", qtype)
                continue
            saved = [list(getattr(response, section)) for section, _count in _SECTIONS]
            for section, records in self._new_records(response, combination).items():
                getattr(response, section).extend(records)
            self._recount(response)
            answered.append(qtype)
            if self._prospective_size(request, response, answered) <= budget:
                self.log.debug("server_mqtype_combined(qtype=%d)", qtype)
                continue
            # "the server MUST NOT include the respective QTx in the MQTYPE-Response
            # option's list and MAY stop processing further QTx combinations". Both
            # halves are kept in step: the records go back, the QTx goes unlisted, and
            # TC is left exactly as the primary answer set it, because "the handling
            # of an MQTYPE-Query option MUST NOT itself trigger a truncated
            # response". Stopping rather than trying the next type is the choice that
            # answers section 4's amplification concern instead of merely tolerating
            # it: a client that asked for eight types is refused the remaining seven
            # without seven queries being made on its behalf.
            answered.pop()
            for index, (section, _count) in enumerate(_SECTIONS):
                setattr(response, section, saved[index])
            self._recount(response)
            self.log.debug("server_mqtype_size_stop(qtype=%d budget=%d)", qtype, budget)
            break
        return answered

    async def respond_to_packet(self, dns_packet, addr):
        if DnsQR.QUERY != dns_packet.QR:
            self.log.debug("server_not_query(src=%s id=%#06x)", addr[0], dns_packet.ID)
            return

        if dns_packet.QDCOUNT != 1:
            # The resolver models one Sname at a time, and answering one of N
            # questions without saying which is worse than refusing.
            self._error(dns_packet, addr, DnsResponseCode.FORMAT_ERROR)
            return

        if DnsOpCode.QUERY != dns_packet.OPCODE:
            self.log.debug(
                "server_unsupported_opcode(src=%s opcode=%s)", addr[0], dns_packet.OPCODE
            )
            self._error(dns_packet, addr, DnsResponseCode.NOT_IMPLEMENTED)
            return

        if self._opt_count(dns_packet) > 1:
            # RFC 6891 section 6.1.1: "When an OPT RR is included within any
            # DNS message, it MUST be the only OPT RR in that message. If a
            # query message with more than one OPT RR is received, a FORMERR
            # (RCODE=1) MUST be returned." Checked before any upstream work so
            # one malformed datagram cannot buy any recursive lookups.
            self.log.debug("server_multiple_opt(src=%s:%s)", addr[0], addr[1])
            self._error(dns_packet, addr, DnsResponseCode.FORMAT_ERROR)
            return

        version = dns_packet.edns_version
        if version is not None and int(version) != EDNS_VERSION_SUPPORTED:
            # RFC 6891 section 6.1.3: "If a responder does not implement the
            # VERSION level of the request, then it MUST respond with
            # RCODE=BADVERS." The response's OPT carries version 0 -- "the
            # highest implementation level of the responder" -- which is what
            # tells the requestor how far down this server actually goes.
            self.log.debug("server_edns_version(src=%s:%s version=%s)", addr[0], addr[1], version)
            self._error(dns_packet, addr, DnsResponseCode.BADVERS)
            return

        if not self._edns_options_or_error(dns_packet, addr):
            # Options belong to the OPT, so they are judged with it: after the
            # version check, because options defined for a VERSION this server
            # does not implement cannot be interpreted at all, and before the
            # resolver is touched, because a datagram that cannot be answered
            # should not purchase a recursive walk. A request with no OPT has
            # no options to judge and passes straight through.
            return

        asked = self._mqtype_request(dns_packet)
        async with self._slots:
            try:
                response = await self.resolver.resolve(dns_packet)
            except asyncio.CancelledError:
                self.log.debug("server_cancelled(dst=%s)", addr[0])
                raise
            except asyncio.InvalidStateError:
                self.log.debug("server_late_result(dst=%s)", addr[0])
                return
            if response is None:
                # Section 3.4's first paragraph conditions nothing on the answer
                # being a good one: a server that supports multiple QTYPEs returns the
                # option in its response to a valid query. A resolution that produced
                # nothing therefore says so with an empty list, rather than with the
                # silence that means "this server never heard of MQTYPE".
                self._error(
                    dns_packet,
                    addr,
                    DnsResponseCode.SERVER_FAILURE,
                    mqtype_answered=None if asked is None else [],
                )
                return
            answered = None
            if asked is not None:
                try:
                    answered = await self._combine_mqtype(dns_packet, response, asked)
                except asyncio.InvalidStateError:
                    # The same race as above, one step later: the transport went away
                    # while extra types were being fetched, and an answer half-built
                    # for a client that has left is not worth finishing.
                    self.log.debug("server_late_result(dst=%s)", addr[0])
                    return
            self._reply(response, addr, request=dns_packet, mqtype_answered=answered)

    def datagram_received(self, data, addr):
        host, port = addr[0], addr[1]
        try:
            dns_packet, _offset = DnsPacket.parse(data)
        except DnsPacketParseError as exc:
            # Debug, not warning: this is the attacker-controlled path, and a
            # warning per datagram is a free log-flood primitive. The offset and
            # hex stay available to anyone who raises the level.
            self.log.debug(
                "server_parse_failed(src=%s:%s err=%s offset=%s octets=%d hex=%s)",
                host,
                port,
                exc,
                exc.offset,
                len(exc.data),
                exc.wire_hex(),
            )
            self._error(None, addr, DnsResponseCode.FORMAT_ERROR)
            return

        question = dns_packet.questions[0] if dns_packet.questions else None
        self.log.debug(
            "server_query(src=%s:%s id=%#06x q=%s)",
            host,
            port,
            dns_packet.ID,
            getattr(question, "name", "?"),
        )
        if len(self._tasks) >= 2 * self.max_concurrent_lookups:
            # Bound the *spawn*, not only the upstream lookup: taking the
            # semaphore inside the task meant every flooded datagram still
            # minted a coroutine, so ingress -- not the operator -- sized the
            # task set. The 2x margin keeps the semaphore meaningful (a few
            # lookups may wait their turn) while the backlog stays bounded;
            # past it, silent drop is the design's answer for overload -- the
            # same treatment RFC 5625 section 6.3 sanctions for intrinsically
            # malformed traffic: no response, no amplification, no log growth
            # at default level.
            self.log.debug("server_overload_drop(src=%s:%s)", host, port)
            return
        self._spawn(self.respond_to_packet(dns_packet, addr))
