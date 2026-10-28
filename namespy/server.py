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

.. rubric:: References

* RFC 1035 section 4.1.1 (header), section 4.3 (server behaviour)
* RFC 5358 section 3 (why a recursing server is an amplification instrument),
  section 4 (BCP 140: give recursive service to intended clients only)
* RFC 5625 section 6.2 (do not listen on interfaces you do not control), section
  6.3 (intrinsically malformed traffic MAY be dropped rather than answered)
* RFC 6891 section 6.1.1 (one OPT per message, OPT is never forwarded, an OPT
  request must be answered with an OPT), section 6.1.3 (BADVERS for a VERSION
  this server does not implement), section 7 (an OPT-free request must be
  answered without OPT)
"""

import asyncio
import logging

from . import enable_path_mtu_discovery
from .enums import DnsOpCode, DnsQR, DnsResponseCode
from .packet import OPT_RTYPE, DnsPacket, DnsPacketParseError, Response
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

#: How many upstream lookups one server instance allows at once. Bounded on
#: purpose: it is what makes this server's *egress* provably limited relative to
#: its ingress, which is the property an amplification defence needs (RFC 5358
#: section 3). No specification sets a number -- this one is a design decision.
MAX_CONCURRENT_LOOKUPS = 32


class DnsServer(asyncio.Protocol):
    """Answer DNS queries over a datagram transport by recursing.

    :param resolver: the :class:`~namespy.resolver.RecursiveResolver` that does
        the work. It must already be bound to a transport, which is why resolver
        and server are connected to the event loop in that order.
    :param max_concurrent_lookups: cap on outstanding recursive lookups.
    """

    def __init__(self, resolver, max_concurrent_lookups: int = MAX_CONCURRENT_LOOKUPS):
        if not isinstance(resolver, RecursiveResolver):
            raise TypeError(f"resolver must be a RecursiveResolver, got {type(resolver).__name__}")
        self.resolver = resolver
        self.log = LOGGER
        self.max_concurrent_lookups = max(1, int(max_concurrent_lookups))
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

    def _reply(self, response, addr, request=None) -> None:
        if request is not None:
            self._apply_edns(request, response)
        wire = bytes(response)
        self.log.debug(
            "server_reply(dst=%s id=%#06x rcode=%s octets=%d)",
            addr[0],
            response.ID,
            response.RCODE,
            len(wire),
        )
        self.transport.sendto(wire, addr)

    def _error(self, dns_packet, addr, rcode: DnsResponseCode) -> None:
        """Reply with *rcode*, echoing the question so the client can match it.

        A client correlates a response with its query by ID *and* the echoed
        question (RFC 5452 sections 4.2-4.3 and 9.1), so an error response with an
        empty question section is one the client may discard. *dns_packet* is
        ``None`` when the datagram could not be parsed at all, and there is
        nothing to echo.
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
        )

    @staticmethod
    def _opt_count(dns_packet) -> int:
        """How many OPT records a request carried (RFC 6891 section 6.1.1 allows one)."""
        return sum(1 for record in dns_packet.additional_records if int(record.rtype) == OPT_RTYPE)

    def _apply_edns(self, request, response) -> None:
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
        response.add_edns(RESPONDER_PAYLOAD_SIZE, version=EDNS_VERSION_SUPPORTED)
        if intended > MAX_UNEXTENDED_RCODE:
            # Put the effective code back where the dropped OPT used to keep it.
            # Serialisation splits it again -- header nibble here, upper eight
            # in the record we just added (RFC 6891 section 6.1.3).
            response.RCODE = intended

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
                self._error(dns_packet, addr, DnsResponseCode.SERVER_FAILURE)
                return
            self._reply(response, addr, request=dns_packet)

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
