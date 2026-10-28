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

.. rubric:: References

* RFC 1035 section 4.1.1 (header), section 4.3 (server behaviour)
* RFC 5358 section 3 (why a recursing server is an amplification instrument),
  section 4 (BCP 140: give recursive service to intended clients only)
* RFC 5625 section 6.2 (do not listen on interfaces you do not control), section
  6.3 (intrinsically malformed traffic MAY be dropped rather than answered)
"""

import asyncio
import logging

from . import enable_path_mtu_discovery
from .enums import DnsOpCode, DnsQR, DnsResponseCode
from .packet import DnsPacket, DnsPacketParseError, Response
from .resolver import RecursiveResolver

LOGGER = logging.getLogger(__name__)

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

    def _reply(self, response, addr) -> None:
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
        )

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
            self._reply(response, addr)

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
