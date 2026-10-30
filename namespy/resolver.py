"""Iterative resolution: RFC 1034 section 5.3.3, as a generator plus an async driver.

The module splits cleanly in two, and the split is the point:

* :func:`resolve_steps` is a *synchronous* generator that yields effect and
  trace events (``SendQuery``, ``NeedAddress``, ``Answer``, ``Demote``, ...) and
  receives back whatever the caller fetched. It never touches a socket, a clock,
  or the cache's clock, so the whole algorithm -- including the parts that took
  the longest to get right, like telling a referral from a NODATA and following
  an alias chain across responses -- is testable with a table of canned
  responses. See ``tests/test_resolve_steps.py`` and
  ``tests/test_resolver_alias.py``.
* :class:`Resolver` / :class:`RecursiveResolver` fulfil those effects over UDP
  and TCP and keep the safety-belt list of servers.

Constructing a resolver performs **no network I/O**: root hints come from the
``named.root`` shipped inside the package via :mod:`importlib.resources`. A
constructor that silently called ``urlretrieve`` (as this one did) broke every
offline test, hung on a network-less host with no timeout, and wrote a file into
the current working directory as a side effect of ``Resolver()``. Refreshing
hints from the network is now the explicit, awaited
:meth:`RecursiveResolver.refresh_root_hints`.

.. rubric:: References

* RFC 1034 section 5.3.2 (resolver state: Sname/Slist/Sbelt), section 5.3.3
  (the algorithm), section 3.6.2 (aliases must not loop), section 4.2.1 (glue
  RRs: only necessary for servers below the cut), section 4.2.2 (a zone's
  servers need not have names inside it)
* RFC 1035 section 4.3 (server behaviour), section 5.2 item 3 (delegations
  need their glue), RFC 1034 section 5.3.3 step 4c (CNAME in the answer)
* RFC 2308 section 5 (negative caching from SOA.MINIMUM)
* RFC 5452 section 9.1 (query matching rules), sections 5 and 7 (why a 16-bit ID
  alone is brute-forceable), section 9.2 (source-port randomness), section 6
  (accept only records inside the domain that was asked about -- the
  :class:`GluePolicy` default, and what ``PERMISSIVE`` deliberately switches off)
* RFC 6672 section 5.1 (DNAME plus CNAME makes alias loops easier to build)
* RFC 7766 section 6 (TCP for truncation and for AXFR)
* RFC 8106 section 2 (root hints: an initial address set is required)
* RFC 9156 (QNAME minimisation -- opt-in via ``qname_min``; see
  :mod:`namespy.minimis` for the probe schedule)
"""

import asyncio
import enum
import io
import ipaddress
import logging
import os
import random
import re
import secrets
import socket
import struct
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from importlib import resources
from socket import gaierror
from typing import NamedTuple

from . import enable_path_mtu_discovery
from .bundle import (
    BundledType,
    BundleResult,
    BundleState,
    bundle_is_void,
    collect_bundle,
    query_option_for,
)
from .cache import FailureCache, MemoryDnsCache, NegativeEntry, PositiveEntry
from .edns import (
    MQTYPE_QUERY_OPTION_CODE,
    extended_error_presentation,
    extended_errors_of,
    nsid_of,
    nsid_presentation,
)
from .enums import DnsQR, DnsQType, DnsRClass, DnsResponseCode, DnsRType, is_data_rrtype
from .minimis import QnameMinimiser
from .names import DomainName
from .packet import (
    OPT_RTYPE,
    DnsPacket,
    DnsPacketParseError,
    DnsQuestion,
    DnsRecord,
    Query,
    Response,
)
from .rdata import RData_A, RData_AAAA, type_name_of
from .trace import Trace

LOGGER = logging.getLogger(__name__)

# RFC 1034 §5.3.3 caps; these are the defaults, and RecursiveResolver takes each
# as a constructor argument so a caller can tighten them (a stub resolver serving
# a constrained client wants smaller, not larger).
MAX_HOPS = 32
MAX_DEPTH = 24

# Bound on CNAME/DNAME redirections followed for one lookup.
#
# No RFC states a number. RFC 1034 §3.6.2 only requires that alias loops not be
# followed forever ("a alias name must not map to itself, either directly or
# indirectly"), and RFC 6672 §5.1 notes that DNAME plus CNAME makes loops easier
# to construct than either type alone. Some bound is therefore mandatory; this
# is generous relative to real deployments, where chains of 2--3 are the norm,
# and it is deliberately smaller than MAX_HOPS so a pathological chain fails
# with a clear "alias" error rather than an opaque "max hops".
MAX_ALIAS_HOPS = 16

# Per-query timeout. RFC 1034 §5.3.3 step 3 says the resolver picks the
# "best" server, sends a query, and on timeout moves on to another entry —
# but the spec leaves the wait time to the implementation. A small budget
# is essential: without it, one unreachable anycast NS hangs the whole
# resolution (and any glueless sub-resolution rooted in it) until the
# caller's outer timeout fires. BIND uses 1.5--5 s initially; we pick 5 s.
QUERY_TIMEOUT_S = 5.0

#: EDNS(0) payload advertised on outbound queries (RFC 6891 section 6.2.3).
#: The document calls "between 1280 and 1410 bytes for IP (v4 or v6) over
#: Ethernet" reasonable; 1232 is 1280 -- IPv6's guaranteed minimum link MTU
#: (RFC 8200 section 5) -- minus the 40-octet IPv6 header and the 8-octet
#: UDP header, so an answer at the full advertised size fragments on
#: neither stack. 0 disables EDNS and returns every answer to the 512-octet
#: ceiling of RFC 1035 section 4.2.1.
EDNS_PAYLOAD_SIZE = 1232


class GluePolicy(enum.Enum):
    """How much of a referral's volunteered address data may be believed.

    RFC 5452 section 6 instructs a resolver to "take care to only accept data if
    it is known that the originator is authoritative for the QNAME or a parent of
    the QNAME", because a response "often contain[s] information that is not part
    of the zone for which we deem it authoritative". :attr:`STRICT` is that
    instruction executed: glue is believed only for a nameserver name inside the
    zone that answered, or inside the zone that referral delegated -- RFC 1034
    section 4.2.1 makes a parent responsible for exactly that glue, and for
    nothing else it volunteers.

    :attr:`PERMISSIVE` exists to measure the attack :attr:`STRICT` prevents. A
    researcher reproducing a cache-poisoning vector, or auditing what a parent
    zone actually volunteers about someone else's nameservers, needs the address
    to be *used*: without that it is discarded inside the classifier and the
    evidence never reaches a trace or a send log. It is a research instrument,
    not a compatibility knob -- believing an out-of-zone address hands the rest of
    the lookup, and the queries it sends, to the delegating server's choosing,
    which is the capability RFC 5452 section 6 exists to deny.

    Neither member relaxes three things, and each is a different reason:

    * the **lame check** (a below-cut nameserver with no glue, RFC 1034 section
      4.2.1) -- a reachability fact, not a trust judgement;
    * **response matching** (RFC 5452 section 9.1) -- the defense against an
      off-path forger, a different threat from a parent volunteering data;
    * the **cache** -- glue is recorded nowhere in it, so a permissive descent
      cannot persist a poisoning past the lookup that observed it.
    """

    #: RFC 5452 section 6 as written: in-bailiwick glue only. The default.
    STRICT = "strict"

    #: Believe any name-matching glue. Diagnostics only; see the class docstring.
    PERMISSIVE = "permissive"


class Resolver(asyncio.Protocol):
    """Send queries to authoritative servers and match the answers.

    The class attributes are the defaults; :class:`RecursiveResolver` overrides
    them from its constructor arguments, and a bare ``Resolver`` -- which tests
    and ad-hoc drivers instantiate without calling ``__init__`` -- therefore
    still has every knob defined.
    """

    #: The instance logger. Deliberately :func:`~logging.getLogger`, not a
    #: freshly-constructed ``logging.Logger``: constructing a Logger directly
    #: puts it outside the hierarchy, so it does not propagate, does not obey a
    #: level or handler the application set on the ``namespy`` logger, and -- with
    #: a module-global handler attached to each instance -- duplicates output.
    log = LOGGER

    #: Seconds to wait for one UDP answer before demoting the server.
    query_timeout = QUERY_TIMEOUT_S

    #: Hop, alias-chain and sub-resolution budgets (see module constants).
    max_hops = MAX_HOPS
    max_alias_hops = MAX_ALIAS_HOPS
    max_depth = MAX_DEPTH

    #: UDP payload advertised by the EDNS(0) OPT record on every outbound
    #: query (RFC 6891 section 6.2.3); ``0`` or ``None`` sends no OPT at all.
    edns_payload_size = EDNS_PAYLOAD_SIZE

    #: EDNS(0) options to attach to the OPT record of every outbound query --
    #: :class:`~namespy.edns.EdnsOption` instances, or ``(code, value)`` pairs.
    #: Asking for a Name Server Identifier (RFC 5001) is the intended use: an
    #: empty :attr:`~namespy.edns.OPTION_NSID` option asks every server to
    #: identify itself, and its answer is logged and recorded in
    #: :attr:`server_ids`. Section 6 of that RFC makes silence the normal
    #: outcome -- a server that does not implement the option simply omits it,
    #: so asking is free.
    edns_options = ()

    #: Which volunteered glue the classifier believes; see :class:`GluePolicy`.
    #: The safe member is also the class default, so a driver that never sets
    #: it -- and a test that builds a bare ``Resolver()`` -- filters strictly.
    glue_policy = GluePolicy.STRICT

    #: Optional DNS suffix the resolver assumes for *relative* names — those
    #: whose presentation form does not end in the root terminator (``.``).
    #: A trailing ``.`` on the SNAME prevents this suffix from being assumed
    #: (RFC 1035 §3.1's wire form is always absolute; the trailing dot in
    #: presentation form is a hint to the resolver, not a wire identity).
    #: Set to a ``str`` or :class:`~namespy.names.DomainName`; left ``None``,
    #: relative names are simply anchored at the root.
    dns_suffix = None

    async def query(
        self, questions, nameserver_record, address_record, *, extra_edns_options=(), **kwargs
    ):
        for label, value in (
            ("nameserver_record", nameserver_record),
            ("address_record", address_record),
        ):
            if value is not None and not isinstance(value, DnsRecord):
                raise TypeError(f"{label} must be a DnsRecord or None, got {type(value).__name__}")

        future = asyncio.get_running_loop().create_future()

        ip = _answer_address(address_record)
        if ip is None:
            raise ValueError(
                "address_record must carry valid A or AAAA RDATA, got "
                f"{type_name_of(address_record.rtype)} with "
                f"{len(bytes(address_record.rdata))} octet(s)"
            )
        dns_packet = Query(questions=questions, **kwargs)
        options = tuple(self.edns_options) + tuple(extra_edns_options)
        if self.edns_payload_size:
            # RFC 6891 and the practice behind DNS Flag Day: an EDNS-aware
            # requestor advertises OPT on *every* query rather than probing
            # selectively, so the responder never has to guess and the
            # 512-octet truncation regime becomes the fallback rather than
            # the default.
            dns_packet.add_edns(self._advertised_payload(ip), options=options)
        else:
            # No OPT record, so nothing can carry an option: RFC 10029 section 3.1's
            # QT list is OPT RDATA, not a section of its own. A bundle asked for under
            # --no-edns therefore degrades to the questions the caller would have sent
            # before this extension existed, and resolve_bundle reports it as
            # unsupported rather than silently reporting an empty combination.
            options = ()
        # RFC 7766 section 6 / RFC 5936: AXFR is a TCP-only operation, and a UDP
        # attempt would be answered with a truncated or refused reply rather
        # than a zone transfer.
        q0 = questions[0] if questions else None
        if q0 is not None and getattr(q0, "qtype", None) == DnsQType.AXFR:
            self.log.debug("resolver_force_tcp_axfr(dst=%s id=%s)", ip.exploded, dns_packet.ID)
            return await self._query_tcp(ip.exploded, bytes(dns_packet), dns_packet)

        key = _pending_key(ip.exploded, dns_packet)
        self.log.debug(
            "resolver_sendto(dst=%s id=%s q=%s %s %s)",
            ip.exploded,
            dns_packet.ID,
            getattr(q0, "name", ""),
            getattr(getattr(q0, "qtype", None), "name", getattr(q0, "qtype", "")),
            getattr(getattr(q0, "qclass", None), "name", getattr(q0, "qclass", "")),
        )
        if isinstance(ip, ipaddress.IPv6Address):
            # Use IPv6 glue when available.
            if hasattr(self, "_ensure_v6_transport"):
                try:
                    await self._ensure_v6_transport()
                except Exception as exc:
                    # IPv6 glue is an optimisation: without a v6 transport we
                    # simply cannot use a v6 address, and the caller falls back
                    # to the v4 ones. Worth a debug line, not an exception.
                    self.log.debug("resolver_v6_transport_unavailable(err=%s)", type(exc).__name__)
            transport_v6 = getattr(self, "transport_v6", None)
            queue_v6 = getattr(self, "queue_v6", None)
            if transport_v6 is None or queue_v6 is None:
                future.cancel()
                return None
            # On Windows, IPv6 sendto expects the full 4-tuple (host, port, flowinfo, scopeid).
            transport, queue, sendto_addr = transport_v6, queue_v6, (ip.exploded, 53, 0, 0)
        elif isinstance(ip, ipaddress.IPv4Address):
            transport, queue, sendto_addr = self.transport, self.queue, (ip.exploded, 53)
        else:
            future.cancel()
            return None

        # Three attempts at most, each taken for a different refusal, and each removing
        # one thing the server objected to.
        #
        # The first alternative is the RFC 6891 section 6.2.2 fallback -- "If a
        # requestor detects that the remote end does not support EDNS(0), it MAY issue
        # queries without an OPT record" -- taken only when the answer actually said so
        # (see _edns_rejected).
        #
        # The second is RFC 10029 section 3.5's: "In the above case, or if the server
        # generates a FORMERR response, the client MUST issue additional standalone
        # queries (that is, without using the MQTYPE-Query option) for all QTYPEs for
        # which an answer is still required". A server that FORMERRs a *well-formed*
        # MQTYPE-Query is in breach of RFC 6891 section 6.1.2 ("Any OPTION-CODE values
        # not understood by a responder or requestor MUST be ignored"), but what the
        # document prescribes is asking again without the option rather than punishing
        # the server -- and demotion is the alternative that turns an
        # extension-unfriendly server into a name that stops resolving.
        #
        # The two remedies are mutually exclusive, which is what makes three attempts
        # the worst case rather than a ladder to fall down. A FORMERR *without* an OPT
        # says "no EDNS here" and belongs to _edns_rejected, whose remedy (drop the OPT)
        # drops the option with it; a FORMERR *with* an OPT is section 7's complaint
        # about the contents of the OPT, and with a MQTYPE-Query in flight the option is
        # the thing that was added to it.
        #
        # The pending key cannot shift between attempts: it is built from the
        # transaction ID and the question, and neither retry touches either.
        bundle_in_flight = any(option.code == MQTYPE_QUERY_OPTION_CODE for option in options)
        for attempt in (1, 2, 3):
            if attempt > 1:
                future = asyncio.get_running_loop().create_future()
            queue[key] = (dns_packet, future)
            transport.sendto(bytes(dns_packet), sendto_addr)
            response = await self._await_udp(future, key, dns_packet, ip, queue=queue)
            if response is not None:
                self._note_server(ip, response)
            if response is None or attempt == 3:
                return response
            if self._edns_rejected(dns_packet, response):
                self.log.debug("resolver_edns_fallback(dst=%s id=%s)", ip.exploded, dns_packet.ID)
                dns_packet.remove_edns()
                bundle_in_flight = False
                continue
            if bundle_in_flight and int(response.extended_rcode) == int(
                DnsResponseCode.FORMAT_ERROR
            ):
                self.log.debug("resolver_mqtype_fallback(dst=%s id=%s)", ip.exploded, dns_packet.ID)
                # EDNS stays: the complaint was about the OPT's contents, and an
                # unextended re-ask would surrender the advertised payload size too.
                dns_packet.remove_edns()
                options = tuple(o for o in options if o.code != MQTYPE_QUERY_OPTION_CODE)
                dns_packet.add_edns(self._advertised_payload(ip), options=options)
                bundle_in_flight = False
                continue
            return response
        # Unreachable: attempt 3 always returns above, so the loop is exhaustive by
        # construction. Spelled out so the invariant survives a future edit that might
        # otherwise let a fall-through return a future that was never resolved.
        return None

    #: Cap on the per-server EDNS memos (advertised payload size, NSID). A
    #: resolver walking the delegation tree touches a lot of addresses, and
    #: these are convenience notes rather than state anything depends on: once
    #: a memo reaches a thousand servers, the oldest entries have long stopped
    #: describing a path anyone is still taking.
    _SERVER_MEMO_MAX = 1024

    def _advertised_payload(self, ip) -> int:
        """The UDP payload size to advertise to *ip* on this query.

        Starts from :attr:`edns_payload_size` and shrinks it to whatever this
        server has yet said it can receive -- RFC 6891 section 6.2.3 tells a
        requestor to use "their largest configured or implemented values ...
        in the absence of previous knowledge about the destination server",
        which is an instruction to use the smaller number once that knowledge
        exists, and section 6.2.4 treats a responder's advertised size as
        stable enough to be re-used across closely spaced transactions.
        Advertising more than the server will accept buys nothing: it invites
        IP fragmentation, which is the one failure mode section 6.2.3 warns
        "can cause fallback to occur".

        The floor of 512 is applied by :meth:`DnsPacket.add_edns`, so a server
        that advertises something absurd still gets a legal OPT record.
        """
        ours = int(self.edns_payload_size)
        if not ours:
            return 0
        known = getattr(self, "_payload_by_server", None)
        if not known:
            return ours
        theirs = known.get(str(ip))
        return ours if theirs is None else min(ours, theirs)

    def _note_server(self, ip, response) -> None:
        """Record what this answer says about the server that sent it.

        Two things are worth remembering, both learned from the OPT record of
        an extended answer and both keyed by the address we sent to:

        * its advertised UDP payload size (RFC 6891 section 6.2.4), which
          :meth:`_advertised_payload` will honour on the next query;
        * its Name Server Identifier, if we asked for one and it answered
          (RFC 5001 section 1) -- which is how a resolver tracking an anycast
          set or an overloaded pool learns *which* machine replied.

        An answer without an OPT record teaches nothing and changes nothing: a
        server that has fallen back to unextended DNS is still perfectly able
        to receive an EDNS query, and the next one simply re-advertises our
        full size.
        """
        advertised = response.requestor_payload_size
        if advertised is not None:
            # Section 6.2.3: "Values lower than 512 MUST be treated as equal
            # to 512." The responder's number is held to the same reading.
            memo = self._server_memo("_payload_by_server")
            if len(memo) >= self._SERVER_MEMO_MAX:
                memo.clear()
            memo[str(ip)] = max(DnsPacket.EDNS_MINIMUM_PAYLOAD, int(advertised))

        # A malformed option in a *response* is the server's problem, not
        # ours: NSID is what we asked for, so the answer is to ignore it and
        # carry on rather than to fail a lookup that has already succeeded.
        try:
            nsid = nsid_of(response.edns_options())
        except DnsPacketParseError:
            self.log.debug("resolver_nsid_unparsable(src=%s)", ip)
            return
        if nsid is None:
            return
        memo = self._server_memo("_server_ids")
        if len(memo) >= self._SERVER_MEMO_MAX:
            memo.clear()
        if memo.get(str(ip)) != nsid:
            self.log.info("resolver_server_id(dst=%s nsid=%s)", ip, nsid_presentation(nsid))
        memo[str(ip)] = nsid

    def _server_memo(self, attr: str) -> dict:
        """The per-server memo named *attr*, created on first use.

        Created lazily rather than in ``__init__`` because :class:`Resolver`
        is an :class:`asyncio.Protocol` that tests and callers construct
        without arguments, and because a memo defined as a *class* attribute
        would be a single dict shared by every resolver in the process -- one
        resolver would silently inherit what another had learned.
        """
        memo = getattr(self, attr, None)
        if memo is None:
            memo = self.__dict__[attr] = {}
        return memo

    @property
    def server_ids(self) -> dict:
        """Which server answered each way, keyed by the address queried.

        Populated only when NSID was asked for -- see :attr:`edns_options` --
        because a server that has not been invited to identify itself is
        entitled to stay anonymous (RFC 5001 section 2.2). Values are the raw
        octets; :func:`~namespy.edns.nsid_presentation` renders them in the
        hex form section 2.4 requires of any display. A copy is returned: what
        the resolver remembers is its own, and a caller that wants a running
        tally should keep one.
        """
        return dict(self._server_memo("_server_ids"))

    @property
    def server_payload_sizes(self) -> dict:
        """The UDP payload size each server last advertised (RFC 6891, 6.2.4).

        Read this to see what the network will actually carry: a server that
        answers with 512 gets 512 asked of it from here on, which is the
        difference between re-probing a path and learning about it once.
        """
        return dict(self._server_memo("_payload_by_server"))

    @staticmethod
    def _edns_rejected(dns_packet, response) -> bool:
        """True when *response* says the OPT sent in *dns_packet* was not honored.

        RFC 6891 section 7 gives a non-EDNS responder exactly one legal way
        to say so: "Responders that choose not to implement the protocol
        extensions defined in this document MUST respond with a return code
        (RCODE) of FORMERR to messages containing an OPT record in the
        additional section and MUST NOT include an OPT record in the
        response." A FORMERR that *does* carry an OPT is the other event
        section 7 defines -- "a problem with processing the OPT record
        itself ... the response MUST include an OPT record" -- and since the
        OPT built here is empty and machine-generated, treating that as
        non-support would paper over a real protocol event instead of
        reporting it.

        BADVERS (section 6.1.3) rejects the EDNS VERSION rather than the
        mechanism, and NOTIMP is what ossified middleboxes answer an OPT
        query with; both also force the unextended retry, which is the only
        remedy section 6.2.2 offers and is harmless when the answer was
        about something else -- the re-ask gets the same RCODE without EDNS.
        """
        if dns_packet.opt() is None:
            return False
        rcode = int(response.extended_rcode)
        if rcode in (int(DnsResponseCode.BADVERS), int(DnsResponseCode.NOT_IMPLEMENTED)):
            return True
        return rcode == int(DnsResponseCode.FORMAT_ERROR) and response.opt() is None

    async def _await_udp(self, future, key, dns_packet, ip, *, queue=None):
        """Await one UDP response, retrying over TCP when UDP could not carry it.

        Two outcomes force a TCP retry, and neither is a matter of taste:

        * **Timeout.** UDP may simply be blocked on the path, and RFC 1035
          section 4.2.2 makes TCP the fallback transport for exactly that case.
        * **``TC`` set.** RFC 1123 section 6.1.3.2: "If the Answer section of the
          response is truncated and if the requester supports TCP, it SHOULD try
          the query again using TCP."  Outbound queries advertise EDNS(0), so
          the 512-octet regime of RFC 1035 section 4.2.1 is no longer the
          default -- but truncation stays reachable: servers that ignore
          EDNS, middleboxes that strip OPT, and answers genuinely bigger than
          the advertised payload all still set the bit.

        A truncated response is never returned, even when the TCP retry also
        fails.  RFC 1123 section 6.1.3.2 forbids it outright -- "Truncated
        responses MUST NOT be saved (cached) and later used in such a way that the
        fact that they are truncated is lost" -- and RFC 1035 section 7.4 says a
        resolver which "doesn't know whether it has a complete set ... should not
        cache a possibly partial set of RRs".  Returning ``None`` makes the caller
        demote this nameserver and consult another, which is the right failure
        mode: a single partial answer would otherwise be cached and served to
        every later client as though it were complete.

        RFC 1035 section 4.3.1 does observe that a server should truncate "at the
        end of the response and work forward in the datagram", so a truncated
        response that still carries an authority section has a complete answer
        section.  Acting on that means trusting the server to implement
        truncation correctly in order to save one TCP exchange; the bit is taken
        at face value instead.

        The pending slot is released on timeout whether or not the retry then
        succeeds, so a late datagram cannot fulfil an abandoned future and the
        slot cannot leak.
        """
        pending = self.queue if queue is None else queue
        version = 6 if isinstance(ip, ipaddress.IPv6Address) else 4
        try:
            response = await asyncio.wait_for(future, timeout=self.query_timeout)
        except TimeoutError:
            pending.pop(key, None)
            self.log.debug(
                "resolver_timeout_udp(dst=%s id=%s ip_version=%d)",
                ip.exploded,
                dns_packet.ID,
                version,
            )
            return await self._query_tcp(ip.exploded, bytes(dns_packet), dns_packet)
        except asyncio.CancelledError:
            # The docstring above promised the slot cannot leak; timeout was
            # covered but cancellation was not, and cancellation is the common
            # case (caller timeout on the outer task, server reconnect, client
            # disconnect). An abandoned future with its key still in `pending`
            # grows the dict for the lifetime of the resolver.
            pending.pop(key, None)
            raise

        if response is not None and response.TC:
            self.log.debug(
                "resolver_truncated_udp(dst=%s id=%s ip_version=%d)",
                ip.exploded,
                dns_packet.ID,
                version,
            )
            return await self._query_tcp(ip.exploded, bytes(dns_packet), dns_packet)
        return response

    async def _query_tcp(self, host, wire, query_packet):
        """Query over TCP, with the 2-octet length prefix RFC 1035 section 4.2.2.

        TCP is reached from three places: a UDP attempt that timed out, a UDP
        response with ``TC`` set (see :meth:`_await_udp`), and zone transfers,
        which are TCP-only (RFC 5936). The timeouts are per-phase rather than one
        budget for the whole exchange, so a server that accepts the connection and
        then stalls cannot hold the lookup open for three times the query timeout.

        A response that arrives over TCP with ``TC`` still set is returned as it
        came. RFC 7766 section 8 gives TCP a 65535-octet message field, so
        truncation should not happen, but a server that sets the bit anyway is
        answered honestly rather than silently; :func:`_write_cache` refuses to
        cache it.

        The answer is checked against *query_packet* just as a UDP answer is.
        Point-to-point transport removes the off-path forgery threat that
        RFC 5452 addresses, but not the mundane ones: a middlebox, a stale
        pipelined response, or a server with a broken ID field can all hand back
        something that is not the answer to this question, and silently using it
        would be a wrong answer rather than a failure.
        """
        self.log.debug("resolver_tcp_try(dst=%s id=%s)", host, query_packet.ID)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 53), timeout=self.query_timeout
            )
        except Exception as e:
            self.log.debug(
                "resolver_tcp_connect_failed(dst=%s id=%s err=%s)",
                host,
                query_packet.ID,
                type(e).__name__,
            )
            return None
        try:
            writer.write(struct.pack("!H", len(wire)) + wire)
            await writer.drain()
            nbuf = await asyncio.wait_for(reader.readexactly(2), timeout=self.query_timeout)
            (n,) = struct.unpack("!H", nbuf)
            data = await asyncio.wait_for(reader.readexactly(n), timeout=self.query_timeout)
            (pkt, _off) = DnsPacket.parse(data)
            if int(pkt.ID) != int(query_packet.ID) or not _is_expected_response(
                query_packet, pkt, host
            ):
                self.log.warning("resolver_tcp_response_mismatch(dst=%s id=%s)", host, pkt.ID)
                return None
            self.log.debug(
                "resolver_tcp_ok(dst=%s id=%s rcvd_len=%d)", host, getattr(pkt, "ID", -1), len(data)
            )
            return pkt
        except Exception as e:
            self.log.debug(
                "resolver_tcp_failed(dst=%s id=%s err=%s)",
                host,
                query_packet.ID,
                type(e).__name__,
            )
            return None
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as exc:
                # The answer has already been read; a failure while tearing the
                # connection down (a server that RSTs instead of finishing the
                # close) must not turn a good response into an error.
                self.log.debug("resolver_tcp_close_failed(err=%s)", type(exc).__name__)


# RFC 1034 §5.3.2 resolver state.
#
# Sname  — the search name, plus QTYPE/QCLASS, plus a `.questions` list ready
#          to drop into a query.
# SlistEntry — one (zone, NS, addresses, history) row.
# Slist  — ordered candidate list for the current zone-cut.
# Sbelt  — safety-belt list seeded from named.root.


class Sname:
    def __init__(self, qname, qtype=DnsQType.A, qclass=DnsRClass.IN):
        if not isinstance(qname, DomainName):
            qname = DomainName(str(qname))
        try:
            qtype = DnsQType(qtype)
        except ValueError:
            pass
        try:
            qclass = DnsRClass(qclass)
        except ValueError:
            pass
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass
        self.questions = [DnsQuestion(qname, qtype, qclass)]

    @classmethod
    def from_question(cls, question):
        return cls(question.name, question.qtype, question.qclass)

    def reanchor(self, qname):
        """Re-root this search name at ``qname``, keeping QTYPE and QCLASS.

        This is RFC 1034 §5.3.3 step 4c: "if the answer contains a CNAME RR, set
        SNAME to the contents of the RDATA field of the displayed CNAME RR, and
        go to step 2". Mutating in place rather than building a new Sname keeps
        every holder of this object -- the driver, the trace, the caller --
        looking at the same search state, which is what the spec's "set SNAME"
        implies.

        QTYPE deliberately survives the redirect: an A query for an aliased name
        becomes an A query for the target, and only the target's RRset can end
        the lookup.
        """
        if not isinstance(qname, DomainName):
            qname = DomainName(str(qname))
        self.qname = qname
        self.questions = [DnsQuestion(qname, self.qtype, self.qclass)]
        return self

    def match_count(self, zone):
        """Number of labels this search name shares with ``zone``, from the root.

        Implements the §5.3.3 step 4b "closer" test that decides whether an
        authority section is a genuine referral.

        Compared over raw labels via :meth:`DomainName._labels` rather than by
        splitting presentation text on ``.``: an escaped label
        (``evil\\.example.com``, or any label containing a dot, which RFC 2181
        §11 permits) previously split into extra "labels" and inflated the count,
        which is exactly the value an attacker needs to make a bogus referral look
        closer than the current zone.
        """
        if not isinstance(zone, DomainName):
            zone = DomainName(str(zone))
        mine = self.qname._labels()
        theirs = zone._labels()
        shared = 0
        for left, right in zip(reversed(mine), reversed(theirs), strict=False):
            if left != right:
                break
            shared += 1
        return shared

    def __repr__(self):
        return f"<Sname {self.qname} {self.qtype} {self.qclass}>"


class SlistEntry:
    def __init__(self, zone, ns, addresses=None):
        self.zone = zone
        self.ns = ns
        self.addresses = list(addresses or [])
        self.history = {"sent": 0, "received": 0, "demoted": False}

    def __repr__(self):
        return (
            f"<SlistEntry zone={self.zone!r} ns={self.ns!r}"
            f" addrs={len(self.addresses)} demoted={self.history['demoted']}>"
        )


class Slist:
    def __init__(self, sname, entries=None):
        self.sname = sname
        self.entries = list(entries or [])
        self.zone = DomainName(".")
        self.match = 0

    def best(self):
        glued = next(
            (e for e in self.entries if not e.history["demoted"] and e.addresses),
            None,
        )
        if glued is not None:
            return glued
        return next(
            (e for e in self.entries if not e.history["demoted"]),
            None,
        )

    def demote(self, entry):
        if entry is not None:
            entry.history["demoted"] = True

    def __repr__(self):
        return f"<Slist zone={self.zone!r} match={self.match} entries={len(self.entries)}>"


class Sbelt(Slist):
    @classmethod
    def from_response(cls, response):
        sb = cls(sname=None)
        sb.zone = DomainName(".")
        sb.match = 0
        if response is None:
            return sb
        for ns in response.nameservers:
            if ns.rtype != DnsRType.NS:
                continue
            ns_target = ns.rdata
            addresses = []
            for ar in response.additional_records:
                if ar.name == ns_target and ar.rtype in (DnsRType.A, DnsRType.AAAA):
                    ip = _answer_address(ar)
                    if ip is not None:
                        addresses.append(ip)
            sb.entries.append(SlistEntry(DomainName("."), ns_target, addresses))
        return sb

    def copy_for(self, sname):
        s = Slist(sname)
        s.zone = DomainName(".")
        s.match = sname.match_count(s.zone) if sname is not None else 0
        s.entries = [self._copy_entry(e) for e in self.entries]
        random.shuffle(s.entries)
        return s

    @staticmethod
    def _copy_entry(entry):
        """Clone an entry, carrying the structural lame marker but not liveness.

        Two different things live in ``history``. ``lame`` is a property of the
        delegation itself -- an in-bailiwick nameserver with no glue is
        unreachable no matter how many times it is retried -- so it must survive,
        otherwise each copy restarts the descent the demotion exists to prevent.
        ``demoted`` from a timeout, by contrast, is an observation about one
        attempt; propagating it would let a single dropped packet retire a root
        server for the lifetime of the resolver, which is why real resolvers use
        backoff instead of permanent exclusion. RFC 1034 section 5.3.3 step 3
        is the ancestor of that: "cycle around all of the addresses for all of
        the servers with a timeout between each transmission", with SLIST
        entries carrying the timeout state.
        """
        clone = SlistEntry(entry.zone, entry.ns, list(entry.addresses))
        lame = entry.history.get("lame")
        if lame:
            clone.history["lame"] = lame
            clone.history["demoted"] = True
        return clone


# Effect / step / trace event types.
#
# A `resolve_steps` generator yields one of these each time it needs the
# driver to do something (SendQuery, NeedAddress) or just wants to record a
# decision (Referral, Answer, Nodata, …). The driver records every yield into
# a Trace, then either fulfills the effect or moves on.


@dataclass(frozen=True)
class SendQuery:
    """Ask the driver to send *questions* to *entry* and hand back the reply.

    The one effect that performs I/O. Corresponds to RFC 1034 section 5.3.3
    step 3 ("query a name server that is further authoritative"), and is also
    how a glueless NS gets its address resolved.
    """

    entry: SlistEntry
    questions: list
    #: True when *questions* is a QNAME-minimisation probe rather than the
    #: real question (RFC 9156 section 3 step 2). Trace rendering marks these
    #: so a reader can tell a probe from a resolution step.
    probe: bool = False
    #: Extra QTYPEs to ask for alongside *questions* in a MQTYPE-Query option
    #: (RFC 10029 section 3.1); empty is the ordinary single-type query.
    #:
    #: It rides on the effect rather than living on the resolver because the option
    #: belongs to one question and not to every query a lookup happens to send. A glue
    #: sub-resolution asks for a nameserver's address; bundling the user's HTTPS and
    #: AAAA into *that* would request another name's data under the wrong name, and a
    #: minimisation probe asks for a shorter child name whose answer says nothing about
    #: the extras' RRsets. Both build their own SendQuery, and neither passes this on.
    extra_qtypes: tuple = ()


@dataclass(frozen=True)
class NeedAddress:
    """The driver must resolve *ns_name* to an address before it can be queried.

    Raised for a glueless NS -- one whose name appears in the authority section
    but whose address did not. Glue is only mandatory for servers *below* the
    cut (RFC 1034 section 4.2.1), and a server outside it is legitimate, not
    lame (RFC 1034 section 4.2.2), so the address has to be chased elsewhere:
    RFC 1034 section 5.3.3 step 2, "the best is to start parallel resolver
    processes looking for the addresses while continuing onward".
    """

    ns_name: DomainName


@dataclass(frozen=True)
class Referral:
    """Slist descended from *old_zone* to *new_zone*.

    *match_before* and *match_after* are label counts matched before and after,
    which is how a trace shows progress. Equal counts mean a referral that did
    not advance, which the algorithm treats as a loop.
    """

    old_zone: DomainName
    new_zone: DomainName
    match_before: int
    match_after: int


@dataclass(frozen=True)
class Answer:
    """The answer section holds RRs of the requested type -- RFC 1034 section 5.3.3(a)."""

    #: Accepts any sequence, since callers naturally hold a list; the value is
    #: always stored as a tuple (see __post_init__), so declaring the narrow
    #: type would contradict the constructor.
    records: Sequence

    def __post_init__(self):
        # Freeze the sequence: these events are recorded in a Trace and read
        # back after the response that produced them is gone, so a caller
        # mutating the list it passed in must not rewrite history.
        object.__setattr__(self, "records", tuple(self.records))


@dataclass(frozen=True)
class Nodata:
    """The name exists but has no RR of the requested type.

    The SOA is carried because RFC 2308 section 5 makes it the source of the
    negative TTL, and because distinguishing this from a referral depends on
    the authority section holding SOA rather than NS (RFC 2308 section 2.2.1).
    """

    soa: object


@dataclass(frozen=True)
class Nxdomain:
    """The name does not exist -- RFC 1034 section 5.3.3(b), RFC 2308 section 3."""


@dataclass(frozen=True)
class Cname:
    """An alias was encountered; *target* must be re-anchored as the new SNAME.

    RFC 1034 section 5.3.3 requires the lookup to continue at the CNAME's
    target rather than returning it, and RFC 6672 section 2.3 adds the DNAME
    case where a synthesized name replaces the alias outright.
    """

    target: DomainName


@dataclass(frozen=True)
class Demote:
    """*entry* is being marked unusable, for *reason*.

    A demotion is a ranking change within the current Slist, not a deletion
    from the name space: RFC 1034 section 5.3.3 step 3 cycles "around all of
    the addresses for all of the servers", and step 4d removes a server from
    SLIST only for the current query, never from the cache.
    """

    entry: SlistEntry | None
    reason: str


@dataclass(frozen=True)
class VolunteeredGlue:
    """A responder offered address RDATA for *ns_name*, and the policy decided it.

    Emitted whenever a referral carries A/AAAA RDATA for a nameserver name the
    answering zone is not authoritative for. Under :attr:`GluePolicy.STRICT` (the
    default) it records what was **discarded**; under
    :attr:`GluePolicy.PERMISSIVE`, what was **used**. This is the research
    surface: the address a delegation volunteered is the datum a cache-poisoning
    analysis is about, and before this event existed the evidence was destroyed
    inside ``classify`` with only the bare fact of the discard left in
    ``entry.history``.

    Nothing is recorded here on clean traffic -- a zone that ships correct glue
    for its own nameservers produces no event at all, so a trace full of these is
    itself the measurement.

    *records* is the evidence as it arrived (an RR that does not decode to an
    address is still evidence that something was offered); *addresses* is what it
    decodes to, which is exactly where the next query would be sent.
    """

    ns_name: DomainName
    records: tuple
    addresses: tuple
    #: False when the policy refused the addresses, True when it believed them.
    used: bool
    reason: str

    def __post_init__(self):
        # Frozen like `Answer`: these are recorded in a Trace and read back long
        # after the response that produced them is gone.
        object.__setattr__(self, "records", tuple(self.records))
        object.__setattr__(self, "addresses", tuple(self.addresses))


@dataclass(frozen=True)
class Done:
    """Resolution finished; *response* is the answer to hand back."""

    response: object


@dataclass(frozen=True)
class Fail:
    """No answer can be produced; *reason* is for the trace and the log."""

    reason: str


def _answer_address(record):
    """The address in an ``A``/``AAAA`` answer, or ``None`` for anything else.

    Re-runs the codec over the record's wire octets rather than trusting
    ``record.rdata`` to already be an :class:`~namespy.rdata.RData_A`, because a
    caller may have built the record by hand with a bare :class:`bytes` or a
    :class:`~namespy.names.DomainName`. A malformed address yields "no address"
    here instead of raising inside a resolution loop: one bad glue record must
    not abort the lookup that happened to receive it.
    """
    rtype = int(record.rtype)
    if rtype not in (int(DnsRType.A), int(DnsRType.AAAA)):
        return None
    try:
        codec = RData_A if rtype == int(DnsRType.A) else RData_AAAA
        return codec(bytes(record.rdata)).ip
    except (DnsPacketParseError, ValueError):
        return None


def _canonical_address(host) -> str:
    """An address in the one text form both sides of a lookup can agree on.

    Needed because the two sides do not naturally produce the same string. On
    send we hold an :class:`ipaddress.IPv6Address` and tend to use ``.exploded``;
    what a socket reports as a sender comes from the OS and Python renders in
    *compressed* form. ``2001:db8:0:0:0:0:0:53`` and ``2001:db8::53`` are the same
    server and would never compare equal as text -- which silently made every
    IPv6 response miss its pending query, so an IPv6 lookup always timed out.
    IPv4 is unaffected, where the two forms coincide.

    Anything that does not parse as an address is returned unchanged, so a caller
    passing an already-canonical string, or a hostname, still gets a stable key.
    """
    text = str(host)
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def _pending_key(dst, packet):
    """The identity a response must match for us to accept it as *the* answer.

    Keyed on destination address, transaction ID, **and the question**, not just
    address and ID. RFC 5452 section 9.1 is the reason: it tells a client to
    match a response against source address, destination address, destination
    port, ID, QNAME, QCLASS and QTYPE before crediting it to a query. The ID on
    its own is 16 bits, and sections 5 and 7 of that document are the birthday
    arithmetic that makes it brute-forceable by an off-path sender, whereas a
    response must also reproduce the QNAME, QTYPE and QCLASS we asked about
    before it can be taken for an answer. That turns a 65k-guess problem into one
    that also requires knowing the name being resolved, and it is the difference
    between a resolver that can be poisoned by a stray or forged packet and one
    that cannot.

    The source and destination ports are not in the key because they are not free
    to vary here: the response arrives on the socket the query left from, so the
    transport already enforced RFC 5452 section 4.5 for us, and only the peer
    address is ours to check.

    The key is derived from whichever packet it is handed, so the same function
    serves both sides: the outgoing query registers under it, and an incoming
    response is looked up by it. A response that omits the question section
    entirely therefore never matches -- which is the intended strictness. RFC 1035
    section 4.1 says the question section "MUST be present in any DNS query or
    DNS response message", and RFC 5452 sections 4.2 and 9.1 tell a client to
    verify it rather than assume it.
    """
    question = packet.questions[0] if packet.questions else None
    address = _canonical_address(dst)
    if question is None:
        return (address, int(packet.ID), None, None, None)
    return (
        address,
        int(packet.ID),
        question.name,
        int(question.qtype),
        int(question.qclass),
    )


def _is_expected_response(query_packet, response_packet, dst) -> bool:
    """Whether *response_packet* may be credited to *query_packet*.

    Checks, in order of cost: the QR bit says this is a response and not some
    unrelated query that happens to share an ID; the question section is echoed
    faithfully. Both are required by RFC 1035 section 4.1.1 and both are named as
    client-side matching rules by RFC 5452 sections 4.2-4.3 and 9.1.
    """
    if DnsQR.RESPONSE != response_packet.QR:
        return False
    if not response_packet.questions:
        return False
    return _pending_key(dst, response_packet) == _pending_key(dst, query_packet)


def _records_by_owner(response):
    """Group a response's answer-section records by owner name.

    Keyed on :class:`~namespy.names.DomainName`, whose equality and hash are
    case-insensitive over raw labels, so ``WWW.Example.COM`` and
    ``www.example.com.`` land in the same bucket without normalising twice.
    """
    index = {}
    for record in response.answers:
        index.setdefault(record.name, []).append(record)
    return index


def _dname_expansion(qname, owner, target):
    """Apply a DNAME substitution to ``qname`` (RFC 6672 §2.2, §3.1).

    The part of the name *below* the DNAME's owner is prepended to the DNAME's
    target; the owner itself is never redirected (§2.3: "the owner name of a
    DNAME RR is not redirected itself"). So with
    ``bar.example.com. DNAME baz.net.``:

    * ``foo.bar.example.com.`` becomes ``foo.baz.net.``
    * ``bar.example.com.`` stays as it is -- and the caller must not call this
      for it.

    Rebuilt through :meth:`DomainName.from_labels`, so a label containing a dot
    cannot change the number of labels on the way through.
    """
    labels = list(qname.labels())
    owner_labels = owner.labels()
    below = labels[: len(labels) - len(owner_labels)]
    return DomainName.from_labels([*below, *target.labels()])


def _closest_dname(index, current):
    """The DNAME applying to ``current``: the most specific enclosing owner.

    A DNAME sits at the top of the subtree it redirects, so the record that
    applies to a name is almost never owned by that name. For
    ``foo.bar.example.com`` with ``bar.example.com. DNAME baz.net.``, the DNAME
    is at ``bar.example.com`` and nothing at all is at the QNAME unless the
    server also sent the synthesised CNAME of RFC 6672 §3.1. Looking only in the
    QNAME's own records therefore finds nothing, which is why this scans the
    owners actually present in the response.

    The closest encloser wins when several levels carry a DNAME, matching what a
    server would apply. Owners equal to ``current`` are excluded: RFC 6672 §2.3
    is explicit that "the owner name of a DNAME RR is not redirected itself", so
    a DNAME never fires for its own owner.
    """
    best_owner = None
    best_record = None
    for owner, records in index.items():
        if not current.is_subdomain_of(owner, include_self=False):
            continue
        record = next((r for r in records if int(r.rtype) == int(DnsRType.DNAME)), None)
        if record is None:
            continue
        if best_owner is None or len(owner.labels()) > len(best_owner.labels()):
            best_owner, best_record = owner, record
    return best_record, best_owner


class AliasWalk(NamedTuple):
    """Outcome of walking an answer section's alias chain.

    ``records``
        The final answer -- every alias traversed, followed by the RRset that
        matches QTYPE. RFC 1034 §3.6.2 requires the aliases to be returned with
        it: "the response to a query for a alias name includes the response to a
        query for the primary name, plus a CNAME RR at the original query name",
        and a caller that dropped them could not tell an aliased answer from a
        direct one.
    ``events``
        One :class:`Cname` per redirection taken, for the trace.
    ``continued_at``
        The name the walk stopped on when no QTYPE RRset was found, or ``None``
        when ``records`` is a complete answer. The driver re-anchors SNAME here
        and queries again (RFC 1034 §5.3.3 step 4c, "go to step 2").
    ``failure``
        A reason string when the chain is *broken* rather than merely unfinished
        -- a loop, or longer than :data:`MAX_ALIAS_HOPS`. These are not the same
        condition and must not be conflated: falling through with
        ``continued_at=None`` made a broken chain look like an empty answer, so a
        CNAME loop was classified as NODATA and passed on as a cacheable negative
        (RFC 2308 §5 would store it under the SOA's TTL) when the zone is simply
        broken. A resolver should fail here; Unbound answers SERVFAIL.
    """

    records: list | None
    events: list
    continued_at: DomainName | None = None
    failure: str | None = None


def _follow_aliases(response, sname, max_alias_hops: int = MAX_ALIAS_HOPS) -> AliasWalk:
    """Walk the CNAME/DNAME chain in a response's answer section.

    A DNAME is honoured even without the synthesised CNAME a server is supposed
    to include (RFC 6672 §3.1), because resolvers must cope with servers that
    omit it; where both are present the real CNAME wins, since it is what the
    server actually chose to answer with.
    """
    index = _records_by_owner(response)
    qtype = int(sname.qtype)
    any_type = qtype == int(DnsQType.ANY)

    current = sname.qname
    traversed: list[DomainName] = []
    events: list[Cname] = []
    seen = {current}

    while True:
        candidates = index.get(current, [])

        if any_type:
            # QTYPE=ANY is answered by whatever exists at the name; there is
            # nothing to match, so following an alias would be wrong.
            return AliasWalk(candidates or None, events)

        direct = [r for r in candidates if int(r.rtype) == qtype]
        if direct:
            # Data at this name wins over a redirection rooted here. That order
            # is mandated for DNAME (RFC 6672 §2.3: when QTYPE matches a type
            # owned by the DNAME's owner name, "the response is sourced from the
            # owner name"); for CNAME it is unreachable, since nothing may
            # coexist with a CNAME.
            return AliasWalk([*traversed, *direct], events)

        alias = next((r for r in candidates if int(r.rtype) == int(DnsRType.CNAME)), None)
        redirection = "cname"
        owner = current
        if alias is None:
            # No CNAME here. A DNAME may still redirect this name from further
            # up the tree, and it will be owned by an ancestor rather than by
            # `current`, so it cannot be found in `candidates`.
            alias, owner = _closest_dname(index, current)
            redirection = "dname"
        if alias is None:
            return AliasWalk(None, events, None if not traversed else current)

        target = alias.rdata
        if not isinstance(target, DomainName):
            # A hand-built record may hold raw octets; there is no name to follow.
            return AliasWalk(None, events)
        if redirection == "dname":
            target = _dname_expansion(current, owner, target)

        traversed.append(alias)
        events.append(Cname(target))
        if target in seen:
            # RFC 1034 §3.6.2 forbids an alias mapping to itself "either directly
            # or indirectly". This is a broken zone, not a negative answer: the
            # name exists, and data of QTYPE may well exist past the loop, so
            # reporting NODATA would cache a falsehood for the SOA's MINIMUM.
            return AliasWalk(None, events, failure=f"alias loop at {target}")
        seen.add(target)
        current = target

        if len(traversed) >= max_alias_hops:
            # Same reasoning: no answer of this shape deserves another query, and
            # returning `current` here would merely move the decision to the
            # driver's own counter instead of failing where the evidence is.
            return AliasWalk(None, events, failure=f"alias chain longer than {max_alias_hops}")


def _find_closer_delegation(response, sname, slist):
    """The authority section's referral, if it genuinely gets us closer.

    Returns ``(new_zone, ns_targets, match_after)`` or ``None``. RFC 1034
    §5.3.3 step 5 defines a referral as an authoritative-section NS set whose
    name is *closer* to SNAME than the zone we are already querying — "closer"
    being the label-count test of step 4b. Requiring the name to actually
    advance is what stops a server from bouncing a query back to itself, and it
    is the guard that makes a NODATA response with stray NS records
    unambiguous (RFC 2308 §2.2.1).
    """
    new_zone = None
    ns_targets = []
    for record in response.nameservers:
        if int(record.rtype) != int(DnsRType.NS):
            continue
        if new_zone is None:
            new_zone = record.name
        ns_targets.append(record.rdata)

    if new_zone is None:
        return None

    match_after = sname.match_count(new_zone)
    if match_after <= slist.match:
        return None
    return new_zone, ns_targets, match_after


def classify(
    response,
    sname,
    slist,
    entry,
    max_alias_hops: int = MAX_ALIAS_HOPS,
    glue_policy: GluePolicy = GluePolicy.STRICT,
):
    """Apply RFC 1034 §5.3.3 step 4 to a single response.

    Yields a sequence of trace events. Mutates `slist` for valid referrals
    (extends entries, advances zone/match). Each yielded `Demote` carries
    the entry the caller should mark demoted; each terminal `Done`
    completes the lookup.

    ``glue_policy`` decides only the credibility of address RDATA that a referral
    volunteers for a nameserver outside the answering zone -- see
    :class:`GluePolicy`. Either way a :class:`VolunteeredGlue` event is yielded
    after the `Referral`, because what a parent offered is worth recording even
    when it is refused.

    A trailing `Cname` with no `Done` after it is **not** an error and not a
    conclusion: it means SNAME must be re-anchored at that target and the lookup
    restarted from step 2 (RFC 1034 §5.3.3 step 4c). The driver in
    :func:`resolve_steps` owns that loop, because only it can bound the chain
    across successive responses; `classify` stays a pure per-response classifier
    so it remains directly testable.
    """
    if response is None:
        yield Demote(entry, "no response")
        return

    if DnsResponseCode.NAME_ERROR == response.RCODE:
        yield Nxdomain()
        yield Done(response)
        return

    if DnsResponseCode.NO_ERROR != response.RCODE:
        # Not response.RCODE.name: RCODE is a plain int whenever the header held
        # a value this enum has no member for, and .name on an int is an
        # AttributeError inside the classifier -- which, reached from a datagram,
        # would turn "unfamiliar RCODE" into a crash instead of a demotion.
        # RFC 2929 section 3.1 makes unassigned codes a routine occurrence, so
        # this is the normal path for a server ahead of the registry, not an edge.
        yield Demote(entry, "rcode " + DnsResponseCode.mnemonic(response.RCODE))
        return

    # Answer section: either a complete answer, or a chain parked on an alias
    # whose target still needs looking up (RFC 1034 §5.3.3 step 4c: "if the
    # answer contains a CNAME RR, set SNAME to the contents of the RDATA field
    # of the displayed CNAME RR, and go to step 2").
    walk = _follow_aliases(response, sname, max_alias_hops=max_alias_hops)
    yield from walk.events
    if walk.failure is not None:
        # A loop or an over-long chain is a broken zone, not a negative answer.
        # Letting this fall through reached the ANCOUNT > 0 branch below and
        # yielded Nodata, which RFC 2308 §5 would have cached against the SOA --
        # so one malformed alias set would hide a name for the length of the
        # zone's MINIMUM. Fail instead, and let the caller try another server.
        yield Fail(walk.failure)
        return
    if walk.records is not None:
        yield Answer(walk.records)
        yield Done(response)
        return
    if walk.continued_at is not None:
        # Neither terminal nor a Demote — the lookup is still alive and the
        # driver has a new SNAME to try. Ending the chain here is what made
        # every aliased name (www.cdn.example, most SMTP hosts) unresolvable.
        return

    if response.ANCOUNT == 0:
        soa = next(
            (r for r in response.nameservers if int(r.rtype) == int(DnsRType.SOA)),
            None,
        )
        if response.AA:
            # A server that claims authority for the zone of QNAME cannot
            # simultaneously be referring us onward, so an empty answer here is
            # NODATA no matter what else the authority section holds. RFC 2308
            # §2.2.1 decides the response type by the *content* of the authority
            # section rather than by AA, and §3 requires the zone SOA to be
            # present so the negative answer can be cached.
            yield Nodata(soa)
            yield Done(response)
            return

        delegation = _find_closer_delegation(response, sname, slist)
        if delegation is None:
            if soa is None:
                # Nothing to answer with, nowhere to go, and no TTL: RFC 2308 §5
                # says a negative answer without an SOA "SHOULD NOT be cached as
                # there is no way to prevent the negative responses looping
                # forever", so it is not trustworthy enough to return. Try
                # another server.
                has_ns = any(int(r.rtype) == int(DnsRType.NS) for r in response.nameservers)
                yield Demote(
                    entry,
                    "referral not closer" if has_ns else "no answer and no referral",
                )
                return
            # TYPE 2 NODATA (SOA present, no NS) from a non-authoritative
            # server. RFC 2308 §2.2.1 recommends authoritative servers send this
            # shape precisely because the alternative is so often misread as a
            # referral.
            yield Nodata(soa)
            yield Done(response)
            return

        new_zone, ns_targets, match_after = delegation
        old_zone = slist.zone
        match_before = slist.match

        new_entries = []
        glue_notes = []
        for ns_target in ns_targets:
            # RFC 5452 section 6: a response "often contain[s] information that
            # is not part of the zone for which we deem it authoritative", and
            # the remedy it prescribes is to "only accept data if it is known
            # that the originator is authoritative for the QNAME or a parent of
            # the QNAME". Here the originator serves ``old_zone``. The one name
            # space it may additionally speak for is ``new_zone``, because RFC
            # 1034 section 4.2.1 makes a parent responsible for the glue of
            # every nameserver below the cut.
            in_bailiwick = ns_target.is_subdomain_of(old_zone) or ns_target.is_subdomain_of(
                new_zone
            )
            addresses = []
            volunteered = []
            for ar in response.additional_records:
                # Glue must be for *this* target: RFC 1034 section 5.3.3 step
                # 4 caches "the NS delegation RRs and any address RRs *for the
                # servers*", which excludes every other owner name the extra
                # section may carry. An address lookup on an NS name can also
                # surface a CNAME, and a CNAME is not an address RR.
                if ar.name != ns_target:
                    continue
                if in_bailiwick:
                    ip = _answer_address(ar)
                    # _answer_address validates the family against the RR type, so a
                    # 16-octet "A" or a 4-octet "AAAA" contributes nothing rather
                    # than raising out of the resolution loop.
                    if ip is not None:
                        addresses.append(ip)
                    continue
                # ... and it must be *credible*, which is the question
                # :class:`GluePolicy` answers. Out-of-bailiwick data is not
                # believed by default: the delegating server is not authoritative
                # for this name, so the address it volunteered is exactly the
                # "data from an untrusted source" RFC 5452 section 6 warns about,
                # and accepting it lets any delegation point the rest of this
                # lookup -- and the queries it will send -- at an address of the
                # delegating server's choosing. The target name itself remains
                # perfectly usable (RFC 1034 section 4.2.2: a delegated server's
                # name need not lie inside the zone), so it is simply left without
                # an address, which sends resolve_steps into the NeedAddress
                # sub-resolution that asks the servers who *are* authoritative.
                #
                # Refusing it is not a reason to forget it: the RRs a parent
                # volunteers about someone else's nameservers are the measurement,
                # and GluePolicy.PERMISSIVE is the switch that turns this same list
                # into a next hop.
                volunteered.append(ar)
            entry = SlistEntry(new_zone, ns_target, addresses)
            new_entries.append(entry)
            if volunteered:
                believed = glue_policy is GluePolicy.PERMISSIVE
                offered = [
                    ip for ip in (_answer_address(ar) for ar in volunteered) if ip is not None
                ]
                if believed:
                    entry.addresses.extend(offered)
                entry.history["bailiwick"] = (
                    "out-of-bailiwick glue accepted (unverified)"
                    if believed
                    else "out-of-bailiwick glue discarded"
                )
                glue_notes.append(
                    VolunteeredGlue(
                        ns_name=ns_target,
                        records=tuple(volunteered),
                        addresses=tuple(offered),
                        used=believed,
                        reason=(
                            "believed under GluePolicy.PERMISSIVE"
                            if believed
                            else "not authoritative for this name (RFC 5452 section 6)"
                        ),
                    )
                )
            if not addresses and in_bailiwick:
                # RFC 1034 section 4.2.1: glue is "only necessary if the name
                # server's name is 'below' the cut", and RFC 1035 section 5.2
                # item 3 requires a zone to ship it. A below-cut target with
                # no glue is therefore a broken delegation -- *lame* -- because
                # reaching it would require having reached it. Demote it
                # immediately: sub-resolving would descend into the very zone
                # we are trying to reach, and with an A and an AAAA attempt per
                # level that is a 2x branching blowup rather than a lookup that
                # simply fails.
                entry.history["demoted"] = True
                entry.history["lame"] = "in-bailiwick without glue"
        random.shuffle(new_entries)

        slist.entries = new_entries
        slist.zone = new_zone
        slist.match = match_after

        yield Referral(old_zone, new_zone, match_before, match_after)
        # The glue notes come after the Referral, not before: the descent is the
        # event a reader follows, and these are the footnotes explaining what the
        # delegation volunteered on the way. resolve_steps lets them through even
        # during a QNAME-minimisation probe, for the same reason -- they are an
        # observation about a referral that was already accepted, never a
        # statement about the probe that must not be mistaken for one.
        yield from glue_notes
        for entry in new_entries:
            if entry.history.get("lame"):
                yield Demote(entry, entry.history["lame"])
        return

    # ANCOUNT > 0, yet nothing matched QTYPE and no alias chain led anywhere.
    if response.AA:
        # "Name exists, but no data of the requested type" (RFC 2308 §2.1): the
        # server answered authoritatively and the answer simply is not our type.
        yield Nodata(
            next(
                (r for r in response.nameservers if int(r.rtype) == int(DnsRType.SOA)),
                None,
            )
        )
        yield Done(response)
        return

    # A partial answer from an upstream cache. Take it as given rather than
    # second-guessing a server that never claimed authority for the zone.
    yield Answer(list(response.answers))
    yield Done(response)


def resolve_steps(
    sname,
    slist,
    cache=None,
    max_hops: int = MAX_HOPS,
    max_alias_hops: int = MAX_ALIAS_HOPS,
    qname_min: bool = False,
    glue_policy: GluePolicy = GluePolicy.STRICT,
    failures=None,
    extra_qtypes: tuple = (),
):
    """Drive resolution as a generator of effect/trace events.

    The generator is fully synchronous; it never touches sockets. The async
    driver `RecursiveResolver._drive` fulfills `SendQuery` / `NeedAddress`
    yields and feeds results back via `gen.send(...)`.

    If ``cache`` is provided (a :class:`namespy.cache.DnsCache`), every hop
    first consults it (RFC 1034 §5.3.3 step 1) and short-circuits with
    ``Answer``/``Done`` or ``Nxdomain``/``Nodata``/``Done`` on a hit. After
    a real authoritative response classifies as a terminal event, the
    result is written back to the cache.

    If ``failures`` is provided (a :class:`namespy.cache.FailureCache`), the
    same loop also refuses to *start* a query whose failure is already
    remembered, and records the failures it hits (RFC 9520 §3.2). Two shapes are
    recorded, because two things fail: a lookup that runs out of servers for a
    zone it had reached and never heard back from notes the **zone**, so the
    next lookup -- which will be for a different name under that zone, and would
    otherwise climb all the way back down -- is stopped at the top (§3.3: "the
    resolver MUST limit queries to the non-responsive zone's parent zone"); a
    lookup that ends because the *name* is unusable (an alias loop, a spent hop
    budget) notes the ``(qname, qtype, qclass)``. A zone that answered anything
    useful is never marked dead, which is what keeps a spent QNAME-minimisation
    probe walk -- servers answering too well, not too badly -- from poisoning a
    healthy delegation. Suppression never refreshes an entry: a client hammering
    a dead name must not be able to hold the failure open past the five-minute
    ceiling. Left ``None``, the generator behaves as it always has.

    ``qname_min`` enables QNAME minimisation (RFC 9156): servers not known
    to be authoritative for the full QNAME are probed with progressively
    deeper children -- see :mod:`namespy.minimis` for the schedule. The
    default ``False`` is deliberate: it changes the questions every
    downline server sees, and it earns its default in the field.

    ``glue_policy`` decides whether a referral's out-of-bailiwick address data
    may be used as glue (see :class:`GluePolicy`). It is a parameter of this
    function rather than ambient state because a single lookup can spawn
    sub-resolutions, and a policy that failed to reach them would quietly stop
    applying halfway down -- which in the permissive direction means the
    measurement records an adoption that did not happen.

    ``extra_qtypes`` asks each server that receives the *real* question to combine
    those QTYPEs into the same answer (RFC 10029; see :mod:`namespy.bundle`). The
    option goes out on full-QNAME queries and on nothing else: not on a
    QNAME-minimisation probe, which asks about a shorter name, and not on a glue
    sub-resolution, which asks about a nameserver's address rather than the caller's.
    A server that merely delegates does still see it, because there is no way to know
    from here which server is the zone's, and asking costs nothing that the protocol
    has not already made legal -- RFC 6891 section 6.1.2 says "Any OPTION-CODE values
    not understood by a responder or requestor MUST be ignored". Whatever a referral
    hop combines is not read: the caller harvests the bundle from the terminal answer,
    which is the only response in the walk that is an answer about those types at all.
    """
    # Alias state lives here, not in classify: a CNAME in one response can point
    # at a name that another response aliases again, so only the loop spanning
    # responses can tell a long chain from a loop. `seen` catches the two-name
    # ping-pong (a -> b -> a) that a hop counter alone would ride out for the
    # full budget.
    alias_hops = 0
    seen_names = {sname.qname}
    minimiser = QnameMinimiser(sname.qname) if qname_min else None
    # RFC 9520 §3.2 bookkeeping. `origin` is captured before the first re-anchor
    # so that a failure reached through an alias can be remembered against the
    # name the client actually asked about, not only the alias target it died on
    # -- without it, a repeat query for the original name re-walks the whole
    # delegation tree before the cache stops it one hop too late.
    origin = sname.qname
    #: Zones this lookup sent a query to, and zones that answered something
    #: usable. A zone is declared dead only when it is in the first set and not
    #: the second, which is RFC 9520 §2.1's "the servers are not answering" and
    #: not merely "this lookup stopped needing them".
    attempted = set()
    answered = set()
    #: Why each zone's candidate servers stopped being usable, in the order first
    #: seen, so a zone failure reads as a diagnosis ("no response; rcode
    #: SERVFAIL") rather than the bare fact that the list ran dry.
    demotions: dict = {}

    def _remember(reason):
        """Note that this name cannot be resolved right now (RFC 9520 §3.2)."""
        if failures is None:
            return
        failures.note_query(sname.qname, sname.qtype, sname.qclass, reason)
        if origin != sname.qname:
            failures.note_query(origin, sname.qtype, sname.qclass, reason)

    def _note_demotion(entry, reason):
        if entry is None:
            return
        reasons = demotions.setdefault(entry.zone, [])
        if reason not in reasons:
            reasons.append(reason)

    for _ in range(max_hops):
        if cache is not None:
            hit = cache.get(sname.qname, sname.qtype, sname.qclass)
            if hit is not None:
                if isinstance(hit, PositiveEntry):
                    yield Answer(hit.records)
                elif hit.rcode == DnsResponseCode.NAME_ERROR:
                    yield Nxdomain()
                else:
                    yield Nodata(hit.soa)
                yield Done(_synthesize_response(sname, hit))
                return
        if failures is not None:
            blocked = failures.match(sname.qname, sname.qtype, sname.qclass)
            if blocked is not None:
                # RFC 9520 §3.2: "When an incoming query matches a cached
                # resolution failure, the resolver MUST NOT send any
                # corresponding outgoing queries until after the cache entries
                # expire." Nothing above this line touched the network and, since
                # this returns, nothing below it will. The entry is deliberately
                # *not* re-noted here: a client hammering a dead name would
                # otherwise keep pushing its expiry out to the five-minute
                # ceiling and hold a recovered zone shut.
                yield Fail(_cached_failure_reason(blocked))
                return
        entry = slist.best()
        if entry is None:
            # Every candidate server has been demoted. RFC 9520 §2.1 names the
            # condition -- a zone's authoritative servers not answering, with
            # nothing left to try instead -- and §3.3 makes the remedy a
            # zone-shaped one, because the next lookup will be for a *different*
            # name under the same zone: "the resolver MUST limit queries to the
            # non-responsive zone's parent zone (and to other ancestor zones)
            # just as it would limit subsequent queries to the non-responsive
            # zone." Only a zone key can express that, so it is the zone that is
            # remembered, for as long as §3.2's backoff allows.
            #
            # Two exclusions, both to avoid inventing an outage:
            #   * a zone this lookup never queried (an empty Slist -- no root
            #     hints -- leaves `.` in scope, and poisoning the root turns a
            #     local misconfiguration into a five-minute blackout);
            #   * a zone that answered something usable along the way, which is
            #     the case a spent QNAME-minimisation probe walk produces: the
            #     servers answered, they simply were not referred onward.
            # In both, the narrower query-keyed note is still worth recording --
            # this exact name demonstrably did not resolve.
            reason = "; ".join(demotions.get(slist.zone, ())) or "no servers"
            if failures is not None and slist.zone in attempted and slist.zone not in answered:
                failures.note_zone(slist.zone, reason)
            elif failures is not None:
                _remember(reason)
            yield Fail("no servers")
            return
        if not entry.addresses:
            addrs = yield NeedAddress(entry.ns)
            if not addrs:
                _note_demotion(entry, "no address")
                yield Demote(entry, "no address")
                slist.demote(entry)
                continue
            entry.addresses.extend(addrs)
            continue
        probe = minimiser.probe(sname.match_count(entry.zone)) if minimiser is not None else None
        if probe is not None:
            # RFC 9156 section 3 step 2: the probe is a QTYPE=A query for
            # CHILD, which keeps any referral in the exact shape classify()
            # already parses. The original QTYPE travels only when the
            # minimiser returns None -- CHILD has reached QNAME, the zone
            # server is in hand, or the probe budget is spent (section 3
            # step 3: "resolve the original query as normal").
            questions = [DnsQuestion(probe, DnsQType.A, sname.qclass)]
            # And no bundle with it. A probe asks about a shorter name than the
            # extras were requested for, so a MQTYPE-Query here would have a server
            # combine RRsets for the *child* -- records for a name nobody asked
            # about, arriving under a question that is not the caller's.
            bundle = ()
        else:
            questions = sname.questions
            bundle = extra_qtypes
        attempted.add(entry.zone)
        response = yield SendQuery(entry, questions, probe=probe is not None, extra_qtypes=bundle)
        # Whatever this server offered as an explanation, kept for the reason
        # strings built below. It decides nothing in this loop -- see
        # :func:`_extended_error_note` for the sentence that forbids that.
        ede_note = _extended_error_note(response)
        if bundle and bundle_is_void(response, primary_qtype=int(sname.qtype), requested=bundle):
            # RFC 10029 section 3.5: an answer whose MQTYPE-Response arrives twice,
            # repeats a QTx, or repeats the primary QTYPE is "invalid (equivalent to
            # FORMERR)". Equivalent, so it is handled the way a FORMERR is handled: this
            # server drops out and the next one is asked.
            #
            # Where the check sits matters more than the rule. Before classify, and so
            # before the cache write below, an answer the client has been told to discard
            # is never stored -- and a later lookup that found it waiting in the cache
            # would make the discard a formality, which is exactly the bug this branch
            # replaced. Asking somewhere else is also the only remedy that can succeed:
            # the server that contradicted itself will contradict itself again.
            LOGGER.debug("resolver_mqtype_invalid(dst=%s)", entry.ns)
            _note_demotion(entry, "invalid MQTYPE-Response")
            yield Demote(entry, "invalid MQTYPE-Response")
            slist.demote(entry)
            continue
        terminal = False
        alias_target = None
        for step in classify(
            response,
            sname,
            slist,
            entry,
            max_alias_hops=max_alias_hops,
            glue_policy=glue_policy,
        ):
            if probe is not None and not isinstance(step, (Demote, Referral, VolunteeredGlue)):
                # A probe response is not a statement about the original
                # QNAME: "com. has no A record" must never become the final
                # NODATA for www.example.com. RFC 9156 section 3 step 4 is
                # the instruction -- take the next name in Slist -- which in
                # this codebase is a demote: the probed entry drops in rank,
                # the response is discarded, and nothing about a probe may
                # reach the cache keyed on the QNAME. Referrals (slist has
                # already descended inside classify) and the volunteered-glue
                # notes that annotate them fall through normally.
                #
                # The zone is recorded as having answered, and its demotion is
                # deliberately *not* recorded: a server that answered a probe
                # too well is not the "non-responsive zone" RFC 9520 section 3.3
                # is written about, and a finished probe walk across every
                # server of a healthy zone must not leave that zone marked dead.
                answered.add(entry.zone)
                yield Demote(entry, f"probe {probe} returned no referral")
                slist.demote(entry)
                break
            if not isinstance(step, (Demote, Fail)):
                # Anything a caller can act on is proof that this zone is
                # talking -- a referral, an answer, an alias, glue offered. That
                # proof outlives a later demotion of another server in the same
                # lookup, which is what keeps the exclusion above honest.
                answered.add(entry.zone)
            # Write to cache *before* yielding the terminal event so callers
            # (including tests) can observe a populated cache the moment the
            # Answer/Nxdomain/Nodata is visible — the generator pauses at
            # ``yield step`` and may never be resumed past Done.
            if cache is not None and isinstance(step, (Answer, Nodata, Nxdomain)):
                _write_cache(cache, sname, step, response)
            if failures is not None and isinstance(step, (Answer, Nodata, Nxdomain)):
                # Recovery, and it has to be explicit rather than left to the clock.
                # An answer is direct evidence that whatever was remembered about
                # this name is stale and that every zone which spoke during this
                # lookup is alive, so both the suppression and the strike counts go.
                # Leaving the counts behind would let a zone that flapped once meet
                # its next genuine outage already at the ceiling, which is the bad
                # trade: slow to notice the second failure of something that has
                # since recovered. RFC 9520 section 3.3's worry -- that cached
                # failures make a resolver slow to see recovery -- is answered here,
                # not by the five-minute ceiling alone.
                failures.forget(sname.qname, sname.qtype, sname.qclass)
                if origin != sname.qname:
                    failures.forget(origin, sname.qtype, sname.qclass)
                for zone in answered:
                    failures.forget_zone(zone)
            if isinstance(step, Fail):
                # Recorded, not yielded yet: `classify` fails for a reason that
                # belongs to the name rather than to a server -- an alias loop or
                # a chain past the budget, from `_follow_aliases` -- so this is
                # the query key's business, and RFC 9520 section 2.5 lists alias
                # loops among the failures worth remembering.
                _remember(step.reason)
            yield step
            if isinstance(step, (Done, Fail)):
                # Fail is terminal for the same reason Done is: classify emits it
                # when the response itself is unusable, and any Cname recorded a
                # moment earlier in the same response must not then be re-anchored
                # and queried again.
                terminal = True
                break
            if isinstance(step, Demote):
                # The server's own words ride along with the reason this demotion is
                # remembered for, so a zone declared dead reads as "rcode SERVFAIL;
                # EDE 22 (No Reachable Authority)" instead of repeating the RCODE the
                # trace already shows. RFC 9520 section 3.2 governs how long the entry
                # lives and says nothing about its text, so this is a pure gain in what
                # an operator learns about why the walk stopped.
                _note_demotion(step.entry, f"{step.reason}{ede_note}")
                slist.demote(step.entry)
            elif isinstance(step, Cname):
                # Recorded, not acted on yet: classify also emits Cname when a
                # chain completes inside one response, and that case must not
                # restart anything. Only a chain that stopped short of Done
                # leaves the lookup needing a new SNAME.
                alias_target = step.target
        if terminal:
            return
        if alias_target is None:
            continue
        if alias_target in seen_names:
            # RFC 1034 §3.6.2 forbids an alias resolving to itself "directly or
            # indirectly"; a server offering that is broken, and re-querying it
            # is how a resolver hangs rather than fails.
            _remember(f"alias loop at {alias_target}")
            yield Fail(f"alias loop at {alias_target}")
            return
        if alias_hops >= max_alias_hops:
            _remember(f"alias chain longer than {max_alias_hops}")
            yield Fail(f"alias chain longer than {max_alias_hops}")
            return
        seen_names.add(alias_target)
        alias_hops += 1
        sname.reanchor(alias_target)
        if minimiser is not None:
            # The QNAME changed, and RFC 9156 section 2's CHILD is defined
            # against the QNAME -- so the schedule restarts for the target.
            # A completed probe walk against the old name must not leave a
            # spent budget narrowing probes against the new one.
            minimiser = QnameMinimiser(sname.qname)
    _remember("max hops")
    yield Fail("max hops")


#: How many upstream EDEs a single failure reason will carry. RFC 8914 section 3
#: leaves the number of options in a message to the sender ("Senders MAY include
#: more than one EDE option"), and a reason that quotes twenty of them has stopped
#: reading as a reason.
_MAX_NOTED_ERRORS = 3


def _extended_error_note(response) -> str:
    """What the server said about why it failed, as a fragment of a reason string.

    Empty unless the response carried an ERROR option. Note what it is *not*: a
    code to branch on. RFC 8914 section 3 -- "Applications MUST continue to follow
    requirements from applicable specifications on how to process RCODEs no matter
    what EDE values are also received" -- is why this returns text, and section 6's
    "EDE content should be treated only as diagnostic information and MUST NOT
    alter DNS protocol processing" is why a malformed option, or a malformed OPT,
    is swallowed here rather than becoming a failure the client never saw.

    The words are somebody else's, so they arrive escaped and capped
    (:func:`~namespy.edns.extended_error_presentation`) and go only into a reason
    string that a trace or a log prints.
    """
    if response is None:
        return ""
    try:
        options = response.edns_options()
    except DnsPacketParseError:
        return ""
    errors = extended_errors_of(options)
    if not errors:
        return ""
    noted = "; ".join(
        f"EDE {extended_error_presentation(error)}" for error in errors[:_MAX_NOTED_ERRORS]
    )
    if len(errors) > _MAX_NOTED_ERRORS:
        noted += f" (+{len(errors) - _MAX_NOTED_ERRORS} more)"
    return "; " + noted


def _cached_failure_reason(entry) -> str:
    """Render a remembered failure as the reason a trace and a log can use.

    The two shapes read differently on purpose: a zone failure names the zone,
    because that -- not the QNAME in front of the operator -- is the thing that
    is not answering, and the strike count says whether this is a first
    one-second refusal or a name that has been refused for five minutes.
    """
    subject = f"zone {entry.zone}" if entry.zone is not None else "this name"
    return f"cached failure for {subject}: {entry.reason} (strike {entry.strikes})"


def _synthesize_response(sname, hit):
    """Build a synthetic :class:`Response` from a cache hit.

    The resolver's outer code expects a :class:`Response` from a successful
    resolution (it stamps the original packet's ``ID`` onto it); we manufacture
    one whose AN/NS sections reflect the cached entry.
    """
    questions = list(sname.questions)
    if isinstance(hit, PositiveEntry):
        return Response(
            QR=DnsQR.RESPONSE,
            AA=hit.authoritative,
            RCODE=DnsResponseCode.NO_ERROR,
            questions=questions,
            answers=list(hit.records),
        )
    rcode = hit.rcode if isinstance(hit.rcode, DnsResponseCode) else DnsResponseCode(int(hit.rcode))
    nameservers = [hit.soa] if hit.soa is not None else []
    return Response(
        QR=DnsQR.RESPONSE,
        AA=False,
        RCODE=rcode,
        questions=questions,
        nameservers=nameservers,
    )


def _negative_ttl_seconds(soa_record):
    """RFC 2308 §5: cap negative-cache TTL at ``min(SOA.MINIMUM, SOA.TTL)``.

    §3 puts the obligation on the authoritative server ("the TTL of this record
    is set from the minimum of the MINIMUM field of the SOA record and the TTL of
    the SOA itself"), but a cache must not be more generous than the spec allows,
    so the same clamp is applied here on the way in.

    Returns ``0`` when no SOA is present, which callers treat as "do not cache":
    §5 says negative responses without an SOA "SHOULD NOT be cached as there is
    no way to prevent the negative responses looping forever between a pair of
    servers even with a short TTL".
    """
    if soa_record is None:
        return 0
    ttl = int(getattr(soa_record, "ttl", 0) or 0)
    minimum = getattr(getattr(soa_record, "rdata", None), "minimum", None)
    if minimum is not None:
        return max(0, min(int(minimum), ttl))
    return max(0, ttl)


def _write_cache(cache, sname, terminal_event, response):
    """Populate ``cache`` from a terminal classify event.

    ``terminal_event`` is the most recent of (Answer, Nodata, Nxdomain)
    yielded for this response; ``response`` is the corresponding wire
    packet (used for the AA flag and to dig the SOA out of the authority
    section on NXDOMAIN).

    A truncated response is never stored. RFC 1123 section 6.1.3.2 states it as
    a prohibition -- "Truncated responses MUST NOT be saved (cached) and later
    used in such a way that the fact that they are truncated is lost" -- and
    RFC 1035 section 7.4 explains why: a partial RRset is indistinguishable from
    a complete one once stored, so caching one lets a single truncated answer
    masquerade as authority for the whole RRset. This is a second line of defence
    behind the TCP retry in :meth:`RecursiveResolver.query`, because TCP can also
    carry ``TC`` from a misbehaving server, and a caller that drives
    :func:`resolve_steps` directly has no transport layer to protect it.
    """
    if response is not None and getattr(response, "TC", False):
        return
    now = cache.time_fn()
    if isinstance(terminal_event, Answer):
        # RFC 6891 section 6.2.1: "The OPT record MUST NOT be cached, and
        # MUST NOT be treated as a normal RRset while caching." This resolver
        # never asks QTYPE=OPT, but resolve_steps is public and a diagnostic
        # caller can; the cache is where that has to bounce.
        records = [r for r in terminal_event.records if int(r.rtype) != OPT_RTYPE]
        if not records:
            return
        ttl = min(int(getattr(r, "ttl", 0) or 0) for r in records)
        if ttl <= 0:
            return
        cache.put(
            PositiveEntry(
                sname.qname,
                sname.qtype,
                sname.qclass,
                records,
                now + ttl,
                authoritative=bool(getattr(response, "AA", False)),
            )
        )
        return
    if isinstance(terminal_event, Nodata):
        ttl = _negative_ttl_seconds(terminal_event.soa)
        if ttl <= 0:
            return
        cache.put(
            NegativeEntry(
                sname.qname,
                sname.qtype,
                sname.qclass,
                DnsResponseCode.NO_ERROR,
                terminal_event.soa,
                now + ttl,
            )
        )
        return
    if isinstance(terminal_event, Nxdomain):
        soa = None
        if response is not None:
            soa = next(
                (r for r in response.nameservers if r.rtype == DnsRType.SOA),
                None,
            )
        ttl = _negative_ttl_seconds(soa)
        if ttl <= 0:
            return
        cache.put(
            NegativeEntry(
                sname.qname,
                sname.qtype,
                sname.qclass,
                DnsResponseCode.NAME_ERROR,
                soa,
                now + ttl,
            )
        )


class RecursiveResolver(Resolver):
    def error_received(self, exception):
        if isinstance(exception, gaierror):
            pass
        self.log.critical(exception)

    def record_reader(self, zone_file, source=None):
        """Read NS and address records from a root-hints style master file.

        Accepts a filesystem path, an :mod:`importlib.resources` traversable, or
        any readable file-like object -- the packaged hints are read through a
        traversable, fetched hints come from a string, and a user's own file comes
        as a path, and none of those three should need a temp file to reach here.

        Unrecognised lines are skipped with a warning naming the line number. The
        file is authoritative-server documentation rather than attacker input, but
        the two-line comment header in ``named.root`` is *not* unusual, and a
        previous version treated a blank line as an unrecognised entry and warned
        once per blank line.

        Deliberately unimplemented: ``$ORIGIN``/``$TTL`` directives and the
        owner-name inheritance rules of RFC 2308 section 2, because root hints use
        neither -- every line is fully qualified. Do not use this to load a real
        zone file.
        """
        source_name = source if source is not None else str(zone_file)
        lines = self._master_file_lines(zone_file)

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(";"):
                continue
            tokens = re.split(r"\s+", stripped)
            if len(tokens) == 5:
                (name, ttl, rclass, rtype, rdata) = tokens
                try:
                    rclass = DnsRClass[rclass]
                except KeyError:
                    self.log.warning(
                        "Unrecognized class %r on line %d of zone file: %s",
                        rclass,
                        i,
                        source_name,
                    )
                    continue
            elif len(tokens) == 4:
                (name, ttl, rtype, rdata) = tokens
                rclass = DnsRClass.IN  # hints are IN-class; RFC 8106 section 2
            else:
                self.log.warning("Unrecognized entry on line %d of zone file: %s", i, source_name)
                continue

            try:
                rtype = DnsRType[rtype]
                ttl = int(ttl)
            except (KeyError, ValueError):
                self.log.warning(
                    "Skipping line %d of %s: unrecognized type %r or TTL %r",
                    i,
                    source_name,
                    rtype,
                    ttl,
                )
                continue

            try:
                record_name = DomainName(name)
                if rtype == DnsRType.NS:
                    yield DnsRecord(record_name, rtype, rclass, ttl, rdata=DomainName(rdata))
                elif rtype == DnsRType.A:
                    yield DnsRecord(
                        record_name,
                        rtype,
                        rclass,
                        ttl,
                        rdata=RData_A(ipaddress.IPv4Address(rdata)),
                    )
                elif rtype == DnsRType.AAAA:
                    yield DnsRecord(
                        record_name,
                        rtype,
                        rclass,
                        ttl,
                        rdata=RData_AAAA(ipaddress.IPv6Address(rdata)),
                    )
                else:
                    self.log.debug(
                        "Skipping %s record for %s on line %d of %s",
                        rtype,
                        record_name,
                        i,
                        source_name,
                    )
            except (ValueError, TypeError) as exc:
                self.log.warning(
                    "Skipping malformed glue on line %d of %s: %s", i, source_name, exc
                )
                continue

    @staticmethod
    def _master_file_lines(zone_file):
        """Yield the text lines of a path, traversable, or readable object.

        Every branch that opens something closes it. The traversable branch used
        to be ``zone_file.open("r", encoding="utf-8").read()`` with no close at
        all, which leaked a descriptor on every hints load -- a ResourceWarning
        under CI, and a real leak for a resolver that refreshes its root hints in
        a long-lived process. An object handed in already open is *not* closed
        here: the caller opened it, so the caller keeps ownership.
        """
        if hasattr(zone_file, "read"):
            data = zone_file.read()
        elif hasattr(zone_file, "open"):  # importlib.resources.Traversable
            with zone_file.open("r", encoding="utf-8") as handle:
                data = handle.read()
        else:
            with open(zone_file, encoding="utf-8") as handle:
                data = handle.read()
        if isinstance(data, bytes):
            data = data.decode("utf-8", "replace")
        return iter(data.splitlines())

    #: Where the root server address set comes from (RFC 8106 section 2: a
    #: resolver needs an initial set of root server addresses, and the only
    #: questions are where it got them and how stale they are).
    ROOT_HINTS_URL = "https://www.internic.net/domain/named.root"

    def __init__(
        self,
        root_hints_path=None,
        dns_suffix=None,
        cache=None,
        failure_cache=None,
        max_hops: int = MAX_HOPS,
        max_depth: int = MAX_DEPTH,
        max_alias_hops: int = MAX_ALIAS_HOPS,
        query_timeout: float = QUERY_TIMEOUT_S,
        edns_payload_size: int | None = EDNS_PAYLOAD_SIZE,
        edns_options: Sequence = (),
        qname_min: bool = False,
        glue_policy: GluePolicy = GluePolicy.STRICT,
    ):
        """Build a resolver without touching the network.

        :param root_hints_path: a master-file path to read hints from. Left
            ``None``, the copy packaged inside Namespy is used, which is what makes
            ``RecursiveResolver()`` work offline, in a test, and on a host with no
            route to internic. A path that is given but does not exist is an
            error rather than a licence to fetch: silently downloading during
            ``__init__`` also wrote a file into the current working directory.
        :param query_timeout: seconds per UDP attempt (and per TCP phase).
        :param failure_cache: a :class:`~namespy.cache.FailureCache` holding the
            failures this resolver is not to ask about again (RFC 9520). Left
            ``None``, one is created for this resolver, which is what makes the
            second query for a dead name free rather than merely slow. Pass
            ``False`` to switch failure caching off entirely -- wanted when the
            resolver exists to *observe* a broken zone, because a resolver that
            has stopped asking is, from outside, indistinguishable from one that
            is itself broken. Pass an existing cache to share one across
            resolvers, or to choose the TTL bounds and capacity.
        :param edns_payload_size: UDP payload advertised by the EDNS(0) OPT
            record on every outbound query (RFC 6891 section 6.2.3). ``0`` or
            ``None`` sends no OPT at all -- the pre-EDNS behaviour, still
            occasionally wanted against ossified infrastructure, though the
            section 6.2.2 fallback already handles the servers that would
            otherwise need it.
        :param edns_options: EDNS(0) options to send on every outbound query,
            as :class:`~namespy.edns.EdnsOption` instances or ``(code, value)``
            pairs. Asking for a Name Server Identifier -- ``edns_options=(
            nsid_option(),)`` -- makes each server say which instance of itself
            answered, and its reply is logged at INFO and kept in
            :attr:`server_ids`. An empty tuple, the default, sends the same
            bare OPT record this resolver has always sent.
        :param qname_min: enable QNAME minimisation (RFC 9156): servers not
            known to be authoritative for the full QNAME are probed with
            progressively deeper children instead of being handed the whole
            name. Default ``False`` is deliberate -- it changes the question
            every downline server sees, so it earns its default in the field.
        :param glue_policy: whether address data that a referral volunteers for
            a nameserver outside the answering zone may be used as glue. The
            default, :attr:`GluePolicy.STRICT`, is RFC 5452 section 6: only glue
            inside the answering zone or below the cut it delegated is believed.
            :attr:`GluePolicy.PERMISSIVE` believes any name-matching address; it
            is a research instrument rather than a production setting, and
            :class:`GluePolicy` says what accepting costs and what it does not.
            Also accepted as the equivalent string, so a config file or CLI flag
            can hand it over directly.
        :raises ValueError: if *glue_policy* is not a :class:`GluePolicy` (or its
            name/value) -- a policy that silently failed to apply would be worse
            than one that was refused at the door.
        :raises FileNotFoundError: if *root_hints_path* is named but missing.
        """
        self.queue: dict[tuple, tuple] = {}
        self.queue_v6: dict[tuple, tuple] = {}
        self.transport_v6 = None
        self._v6_ready = None
        self.log = LOGGER
        self.max_hops = max(1, int(max_hops))
        self.max_depth = max(1, int(max_depth))
        self.max_alias_hops = max(1, int(max_alias_hops))
        self.query_timeout = max(0.05, float(query_timeout))
        self.edns_payload_size = 0 if edns_payload_size is None else max(0, int(edns_payload_size))
        # Frozen into a tuple: the value is read once per outbound query and a
        # caller who mutates the list they passed in would otherwise be
        # changing the wire format of queries already in flight.
        self.edns_options = tuple(edns_options)
        self.qname_min = bool(qname_min)
        # Coerce here, at the door: GluePolicy("permissive") and
        # GluePolicy.PERMISSIVE both arrive, and anything else raises now rather
        # than leaving a resolver that believes it has a policy.
        self.glue_policy = GluePolicy(glue_policy)
        if self.glue_policy is not GluePolicy.STRICT:
            # A warning, deliberately: this switch turns off a defense the RFC
            # specifies, so the log of any run that measured with it should say
            # so without anyone having to ask for -v.
            self.log.warning(
                "resolver_glue_policy=%s: out-of-bailiwick glue will be believed "
                "(RFC 5452 section 6 filtering disabled) -- diagnostics only",
                self.glue_policy.value,
            )
        self.root_hints = self.bootstrap(root_hints_path)
        self.sbelt = Sbelt.from_response(self.root_hints)
        self.last_trace = None
        self.cache = cache if cache is not None else MemoryDnsCache()
        # RFC 9520 §3.2. `False`, rather than `None`, switches this off, because
        # `None` already means "make me the default one" everywhere else in this
        # constructor -- and a resolver built to watch a zone fail has to be able
        # to keep asking it about the failure.
        if failure_cache is False:
            self.failure_cache = None
        elif failure_cache is None:
            self.failure_cache = FailureCache()
        else:
            self.failure_cache = failure_cache
        if dns_suffix is not None:
            self.dns_suffix = dns_suffix

    async def aclose(self):
        """Release every socket and pending query this resolver owns.

        asyncio hands a protocol its endpoint transport, and this class opens a
        second one privately, for AAAA glue (:meth:`_ensure_v6_transport`).
        Neither closes itself. An unclosed transport is an unclosed socket: it
        surfaces as a ``ResourceWarning`` when garbage-collected, and as a leaked
        descriptor in anything that builds resolvers in a loop -- a measurement
        harness, a server. This is why the class is an async context manager:
        :meth:`__aexit__` calls this method, so forgetting is not the default.

        Safe to call twice, and safe on a resolver that never connected --
        closing an already-closed transport is a no-op in asyncio, and the
        transports are read defensively because a protocol that never saw
        ``connection_made`` has none to read.

        Pending queries are *failed*, not cancelled. Cancelling the future would
        surface as ``CancelledError`` in whoever is awaiting it, and inside
        :func:`asyncio.wait_for` that makes the caller's own task look cancelled
        -- a wrong story about who is shutting down.
        """
        # Stop the background IPv6 bring-up first: it may be sitting inside
        # create_datagram_endpoint, and finishing a socket we are about to stop
        # using would only create one more thing to close.
        task, self._v6_ready = self._v6_ready, None
        if task is not None and not task.done():
            task.cancel()

        # Transports before the futures, and before the one ``await`` below: if a
        # cancellation reaches this coroutine while it is suspended, the sockets
        # are already gone.
        for transport in (getattr(self, "transport", None), self.transport_v6):
            if transport is not None:
                transport.close()
        self.transport = None
        self.transport_v6 = None

        for queue in (getattr(self, "queue", None), getattr(self, "queue_v6", None)):
            for _key, (_query, future) in list((queue or {}).items()):
                if future.done():
                    continue
                future.set_exception(RuntimeError("resolver closed"))
                # Reading the exception back is what keeps asyncio from logging
                # "Future exception was never retrieved" for every query that was
                # in flight when the caller stopped caring. The future's state --
                # and therefore what an awaiting caller sees -- is unchanged.
                future.exception()
            if queue is not None:
                queue.clear()

        if task is not None:
            # Let the cancellation land rather than leaving a task pending when
            # the loop stops. The handler swallows this one cancellation because
            # this method is the one that asked for it.
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def __aenter__(self):
        """Enter an ``async with`` block that guarantees :meth:`aclose`."""
        return self

    async def __aexit__(self, exc_type, exc, tb):
        """Close the resolver on the way out, including down the error path."""
        await self.aclose()
        # Do not swallow: an exception raised inside the block is the caller's
        # business, not this method's.

    def connection_made(self, transport):
        self.transport = transport
        enable_path_mtu_discovery(transport, self.log)
        # Start bringing up an IPv6 UDP transport in the background so AAAA glue
        # can be used when IPv4 anycast is unreachable.
        try:
            loop = asyncio.get_running_loop()
            if self._v6_ready is None:
                self._v6_ready = loop.create_task(self._ensure_v6_transport())
        except RuntimeError:
            # No running loop (should not happen in normal asyncio usage).
            pass

    async def _ensure_v6_transport(self):
        if self.transport_v6 is not None:
            return self.transport_v6

        parent = self

        class _V6Shim(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                parent.transport_v6 = transport

            def datagram_received(self, data, addr):
                parent._datagram_received_v6(data, addr)

            def error_received(self, exc):
                parent.error_received(exc)

        loop = asyncio.get_running_loop()
        try:
            transport, _proto = await loop.create_datagram_endpoint(
                lambda: _V6Shim(),
                local_addr=("::", 0),
                family=socket.AF_INET6,
            )
            self.transport_v6 = transport
            self.log.debug("resolver_v6_ready(sockname=%s)", transport.get_extra_info("sockname"))
            return transport
        except Exception as e:
            self.log.debug("resolver_v6_failed(err=%s)", type(e).__name__)
            self.transport_v6 = None
            return None

    def _datagram_received_v6(self, data, addr):
        try:
            dns_packet, _offset = DnsPacket.parse(data)
        except DnsPacketParseError:
            # Same policy as the IPv4 path: a malformed datagram is discarded
            # quietly at debug level, since an attacker who can send us garbage
            # should not be able to use our log as an amplifier.
            self.log.debug("resolver_v6_parse_failed(len=%d)", len(data))
            return

        host = addr[0]
        key = _pending_key(host, dns_packet)
        entry = self.queue_v6.get(key)
        if entry is None:
            self.log.debug("resolver_v6_unexpected_packet(src=%s id=%s)", host, dns_packet.ID)
            return

        query_packet, future = entry
        del self.queue_v6[key]
        if not _is_expected_response(query_packet, dns_packet, host):
            self.log.warning("resolver_v6_response_mismatch(src=%s id=%s)", host, dns_packet.ID)
            return
        if not future.done():
            future.set_result(dns_packet)

    def datagram_received(self, data, addr):
        try:
            (dns_packet, _offset) = DnsPacket.parse(data)
        except DnsPacketParseError as e:
            # Debug, not warning: this is the attacker-controlled path, and a
            # warning with a hex dump per datagram is a free log-flood
            # primitive. The v6 path and server.py already stay quiet; this
            # was the last loud one.
            self.log.debug(
                "resolver_parse_failed(err=%s offset=%s len=%d hex=%s)",
                e,
                e.offset,
                len(e.data),
                e.wire_hex(),
            )
            return

        self.log.debug("resolver_datagram_received(packet=%s, addr=%s)", dns_packet, addr)
        host = addr[0]
        entry = self.queue.get(_pending_key(host, dns_packet))
        if entry is None:
            # Nothing asked this server for this (name, type, class) under this
            # ID. Either it is late, duplicated, or forged; all three are handled
            # the same way -- discard.
            self.log.debug("resolver_unexpected_packet(src=%s id=%s)", host, dns_packet.ID)
            return

        query_packet, future = entry
        del self.queue[_pending_key(host, dns_packet)]
        if not _is_expected_response(query_packet, dns_packet, host):
            self.log.warning("resolver_response_mismatch(src=%s id=%s)", host, dns_packet.ID)
            return
        # The future may already be cancelled if the per-query timeout fired
        # before this late response arrived; ignore that race rather than
        # propagating InvalidStateError out of the protocol callback.
        if not future.done():
            future.set_result(dns_packet)

    @staticmethod
    def packaged_root_hints():
        """The ``named.root`` shipped inside the package, as a readable path.

        :mod:`importlib.resources` rather than ``os.path.dirname(__file__)`` so it
        also works when Namespy is installed as a zip or wheel, where there may be no
        directory on disk to name.
        """
        return resources.files("namespy").joinpath("named.root")

    def bootstrap(self, root_hints_path=None):
        """Build the root-hints ``Response`` from a master file, offline.

        The result is a synthetic ``Response`` whose authority section holds the
        root NS set and whose additional section holds the glue, because
        :class:`Sbelt` is built from responses and reusing that shape avoids a
        second, parallel representation of the same information.

        :raises FileNotFoundError: if *root_hints_path* is given and missing. The
            message names the packaged alternative so the fix is obvious.
        """
        if root_hints_path is None:
            source = self.packaged_root_hints()
            self.log.debug("root_hints_source(source=packaged)")
        else:
            if not os.path.isfile(root_hints_path):
                raise FileNotFoundError(
                    f"root hints file not found: {root_hints_path!r}. Omit "
                    f"root_hints_path to use the copy packaged with Namespy, or "
                    f"call refresh_root_hints() to fetch a current one."
                )
            source = root_hints_path
            self.log.debug("root_hints_source(source=%s)", root_hints_path)

        nameservers = []
        additional_records = []
        for record in self.record_reader(source):
            if record.rtype == DnsRType.NS:
                nameservers.append(record)
            if record.rtype in (DnsRType.A, DnsRType.AAAA):
                additional_records.append(record)

        if not nameservers:
            raise ValueError(f"root hints from {str(source)!r} contained no NS records")
        if not additional_records:
            # RFC 8106 section 2: hints without addresses are unusable -- the
            # resolver would have to resolve the root servers' own names, which is
            # the circular problem hints exist to avoid.
            raise ValueError(
                f"root hints from {str(source)!r} contained no glue addresses (RFC 8106 section 2)"
            )

        questions = [DnsQuestion(DomainName.root_label(), qtype=DnsQType.NS)]
        query = Query(QR=DnsQR.QUERY, RD=False, questions=questions)
        return Response(
            QR=DnsQR.RESPONSE,
            ID=query.ID,
            AA=True,
            RD=False,
            RA=False,
            questions=questions,
            nameservers=nameservers,
            additional_records=additional_records,
        )

    async def refresh_root_hints(self, url: str | None = None, timeout: float | None = None):
        """Fetch current root hints and replace the safety-belt list.

        Explicitly awaited, unlike the ``urlretrieve`` this replaces: root hints
        change rarely (RFC 8106 section 3 suggests a two-week refresh), so the
        caller decides when to pay for a fetch, and doing it inside ``__init__``
        made every resolver construction a network event.

        The fetched file is parsed and *validated* before :attr:`sbelt` is
        replaced, so a truncated or empty download cannot leave the resolver
        unable to start a lookup.

        :return: the synthetic hints ``Response`` now in use, or ``None`` if the
            fetch or parse failed, in which case the previous hints remain.
        """
        url = url or self.ROOT_HINTS_URL
        timeout = self.query_timeout if timeout is None else timeout
        try:
            text = await asyncio.wait_for(
                asyncio.to_thread(self._fetch_text, url, timeout), timeout + 1.0
            )
        except Exception as exc:
            self.log.warning("root_hints_fetch_failed(url=%s err=%s)", url, type(exc).__name__)
            return None

        try:
            response = self.bootstrap_from_text(text)
        except (ValueError, DnsPacketParseError) as exc:
            self.log.warning("root_hints_parse_failed(url=%s err=%s)", url, exc)
            return None

        self.root_hints = response
        self.sbelt = Sbelt.from_response(response)
        self.log.info(
            "root_hints_refreshed(url=%s ns=%d glue=%d)",
            url,
            len(response.nameservers),
            len(response.additional_records),
        )
        return response

    @staticmethod
    def _fetch_text(url: str, timeout: float) -> str:
        with urllib.request.urlopen(url, timeout=timeout) as handle:  # noqa: S310
            return handle.read().decode("utf-8", "replace")

    def bootstrap_from_text(self, text: str):
        """Same contract as :meth:`bootstrap`, from master-file text in memory."""
        nameservers = []
        additional_records = []
        for record in self.record_reader(io.StringIO(text), source="<fetched>"):
            if record.rtype == DnsRType.NS:
                nameservers.append(record)
            if record.rtype in (DnsRType.A, DnsRType.AAAA):
                additional_records.append(record)
        if not nameservers or not additional_records:
            raise ValueError("fetched root hints had no NS records or no glue addresses")

        questions = [DnsQuestion(DomainName.root_label(), qtype=DnsQType.NS)]
        return Response(
            QR=DnsQR.RESPONSE,
            ID=secrets.randbits(16),
            AA=True,
            RD=False,
            RA=False,
            questions=questions,
            nameservers=nameservers,
            additional_records=additional_records,
        )

    async def _send_for_entry(self, entry, questions, extra_qtypes=()):
        """Send the query to this entry, trying all known addresses."""
        if not entry.addresses:
            return None

        ns_record = DnsRecord(entry.zone, DnsRType.NS, DnsRClass.IN, 0, rdata=entry.ns)

        extra_options = ()
        if extra_qtypes:
            primary = getattr(questions[0], "qtype", None) if questions else None
            try:
                option = query_option_for(primary, extra_qtypes)
            except ValueError as exc:
                # An optional extension must never be the reason a name fails to
                # resolve. resolve_bundle validates the list where the caller can still
                # hear about it, so reaching here means somebody drove resolve_steps
                # directly with a list a conforming server is obliged to refuse --
                # section 3.3's FORMERRs. Send the query that list was meant to
                # accompany and say why the option is not in it.
                self.log.debug("resolver_mqtype_undone(dst=%s err=%s)", entry.ns, exc)
            else:
                extra_options = (option,) if option is not None else ()

        for address in list(entry.addresses):
            # Addresses arrive either as ipaddress objects (glue, root hints) or
            # as raw packed octets (a caller that seeded the belt by hand).
            packed = address.packed if hasattr(address, "packed") else bytes(address)
            if len(packed) not in (4, 16):
                continue

            addr_rtype = DnsRType.A if len(packed) == 4 else DnsRType.AAAA
            addr_record = DnsRecord(entry.ns, addr_rtype, DnsRClass.IN, 0, rdata=packed)
            try:
                response = await self.query(
                    questions,
                    ns_record,
                    addr_record,
                    RD=False,
                    extra_edns_options=extra_options,
                )
            except asyncio.InvalidStateError:
                response = None

            if response is not None:
                self._note_upstream_errors(response)
                return response

        return None

    def _note_upstream_errors(self, response) -> None:
        """Log any Extended DNS Error a server sent alongside its answer.

        DEBUG and nothing louder, which is this project's rule for text a stranger
        wrote. RFC 8914 section 6 calls the option "unauthenticated information"
        that "an attacker (e.g., a man in the middle (MITM) or malicious recursive
        server) could insert", and RFC 5358 section 4.2's reasoning is the same one
        the parser paths already follow: a warning per response is a free flood
        primitive. Escaping handles the octets, the level handles the volume.

        It lives here rather than in the resolution generator because this is where
        every response passes through, glue sub-resolutions included, and because
        the answer it is attached to may still be a perfectly good NOERROR --
        section 3 expects an EDE to be readable "in all messages, including those
        with a NOERROR RCODE", and a walk that logs only on failure would miss the
        Stale Answer and Cached Error codes entirely.
        """
        try:
            options = response.edns_options()
        except DnsPacketParseError:
            return
        for error in extended_errors_of(options):
            self.log.debug(
                "resolver_extended_error(rcode=%s ede=%s)",
                DnsResponseCode.mnemonic(response.extended_rcode),
                extended_error_presentation(error),
            )

    async def _drive(self, gen, trace, depth=0):
        """Pump the resolve_steps generator and fulfill its effects.

        *depth* bounds sub-resolutions (a glueless NS whose address must itself be
        looked up, which may in turn need glue). Returning ``None`` rather than
        raising is deliberate: the caller treats it as "no address found" and
        demotes the entry, so a deep chain degrades instead of aborting the
        lookup that triggered it.
        """
        if depth > self.max_depth:
            self.log.debug("resolver_depth_exceeded(depth=%d limit=%d)", depth, self.max_depth)
            return None
        sent = None
        while True:
            try:
                step = gen.send(sent)
            except StopIteration:
                return None
            trace.record(step)

            if isinstance(step, SendQuery):
                sent = await self._send_for_entry(step.entry, step.questions, step.extra_qtypes)
                continue
            if isinstance(step, NeedAddress):
                # RFC 1034 section 5.3.3 step 2: glue may be absent (a
                # "glueless" referral) for a server outside the new zone, which
                # is legitimate per section 4.2.2, and "the best is to start
                # parallel resolver processes looking for the addresses". Ask
                # for A *and* AAAA so a target reachable only over IPv6 is not
                # silently skipped, and read the payloads through the RDATA
                # codecs rather than assuming every answer is four octets.
                addrs = []
                for rtype in (DnsQType.A, DnsQType.AAAA):
                    child_sname = Sname(step.ns_name, rtype, DnsRClass.IN)
                    child_slist = self.sbelt.copy_for(child_sname)
                    child_trace = trace.child(child_sname)
                    # qname_min deliberately off here: the name being chased
                    # is an NS server's address, not the user's QNAME, so the
                    # privacy motivation of RFC 9156 section 1 does not apply
                    # and the extra probes would only slow glue resolution.
                    #
                    # glue_policy, by contrast, *is* inherited. This is where a
                    # refused address goes to be looked up properly, and a policy
                    # that stopped at the top of the descent would be a policy
                    # that silently changes meaning halfway down -- in the
                    # permissive direction, one that reports an adoption the
                    # sub-resolution never performed.
                    sub_gen = resolve_steps(
                        child_sname,
                        child_slist,
                        self.cache,
                        glue_policy=self.glue_policy,
                        failures=self.failure_cache,
                    )
                    sub_response = await self._drive(sub_gen, child_trace, depth + 1)
                    if not isinstance(sub_response, Response):
                        continue
                    for record in sub_response.answers:
                        # RFC 5452 section 6: only records in the domain that was
                        # asked about may be accepted, so an answer section that
                        # happens to carry some other name's address is refused
                        # here -- a server (or an attacker) must not be able to
                        # steer where the next query goes.
                        if record.name != step.ns_name:
                            continue
                        address = _answer_address(record)
                        if address is not None:
                            addrs.append(address)
                sent = addrs
                continue
            if isinstance(step, Done):
                return step.response
            if isinstance(step, Fail):
                return None
            sent = None

    async def resolve(self, dns_packet):
        """Resolve the first question of *dns_packet* iteratively.

        Validation here raises :class:`TypeError` / :class:`ValueError` rather
        than asserting: these guard a public API against caller mistakes, and an
        ``assert`` vanishes under ``python -O``, which would let a
        zero-question packet through to ``questions[0]`` and surface as an
        ``IndexError`` far from its cause.

        Multiple questions are accepted only when they share a name and class --
        :meth:`resolve_steps` tracks a single Sname, so silently resolving just
        the first of several unrelated questions would be a quiet wrong answer.
        """
        response, _sname = await self._walk(dns_packet)
        return response

    @staticmethod
    def _sole_question(dns_packet, method="resolve"):
        """Validate that *dns_packet* asks one (name, class), and return its question.

        The validation raises :class:`TypeError` / :class:`ValueError` rather than
        asserting: these guard a public API against caller mistakes, and an ``assert``
        vanishes under ``python -O``, which would let a zero-question packet through to
        ``questions[0]`` and surface as an ``IndexError`` far from its cause.

        Multiple questions are accepted only when they share a name and class --
        :func:`resolve_steps` tracks a single Sname, so silently resolving just the
        first of several unrelated questions would be a quiet wrong answer.
        """
        if not isinstance(dns_packet, DnsPacket):
            raise TypeError(f"{method}() expects a DnsPacket, got {type(dns_packet).__name__}")
        if not dns_packet.questions:
            raise ValueError(f"{method}() needs a packet with at least one question")

        first = dns_packet.questions[0]
        if len(dns_packet.questions) > 1 and any(
            question.name != first.name or question.qclass != first.qclass
            for question in dns_packet.questions[1:]
        ):
            raise ValueError(
                f"{method}() handles one (name, class) per call; multi-question "
                "packets must agree on name and class"
            )
        return first

    async def _walk(self, dns_packet, extra_qtypes=()):
        """Drive one walk from the roots; return ``(response, terminal sname)``.

        The SNAME comes back because it mutates on the way down. After a CNAME it holds
        the name the answer is really about, which is the name the extras' records are
        owned by and therefore the name a bundle must be harvested against -- asking
        AAAA for an aliased name gets the target's AAAA, exactly as asking A does.
        """
        question = self._sole_question(dns_packet)

        # Apply the resolver's DNS suffix. Names already terminated by a
        # trailing ``.`` pass through unchanged; relative names are promoted
        # to absolute by appending :attr:`dns_suffix` (or just the root).
        qname = question.name.qualify(dns_suffix=self.dns_suffix)
        sname = Sname(qname, question.qtype, question.qclass)
        self.last_trace = Trace(sname)
        slist = self.sbelt.copy_for(sname)
        gen = resolve_steps(
            sname,
            slist,
            self.cache,
            max_hops=self.max_hops,
            max_alias_hops=self.max_alias_hops,
            qname_min=self.qname_min,
            glue_policy=self.glue_policy,
            failures=self.failure_cache,
            extra_qtypes=tuple(extra_qtypes),
        )
        response = await self._drive(gen, self.last_trace)
        if isinstance(response, Response):
            response.ID = dns_packet.ID
            response.trace = self.last_trace
        return response, sname

    async def resolve_bundle(self, dns_packet, extra_qtypes=(), *, ask_separately=True):
        """Resolve one question and, in the same exchange, the QTYPEs in *extra_qtypes*.

        This is RFC 10029's asking side. The Question section still holds exactly one
        question -- QDCOUNT stays one, and RFC 9619's argument that it usually is one
        survives untouched -- while the extra types ride in a MQTYPE-Query option. One
        walk down the delegation tree then answers for all of them, which is the point:
        a resolver that asks A, AAAA and HTTPS separately walks the same servers the
        same way three times, and the walk is the expensive part.

        What comes back is a :class:`~namespy.bundle.BundleResult`, whose two most
        important fields are the ones most often conflated. A server that has never
        heard of the extension is ``supported=False`` with every extra type still needed
        and a primary answer in perfect health -- RFC 6891 section 6.1.2 requires that
        "Any OPTION-CODE values not understood by a responder or requestor MUST be
        ignored", so asking costs a few octets and nothing else. A server whose answer
        contradicts itself is ``void=True``, and its primary answer is not usable either.

        ``ask_separately`` carries out section 3.5's own instruction -- "The client MUST
        subsequently initiate separate standalone queries for all QTx values for which an
        answer is still required" -- by resolving each uncovered type with its own query,
        without the option. Pass ``False`` to keep the work list and decide later; nothing
        else about the result changes. A re-ask is an ordinary lookup and inherits the
        ordinary rules, so if this lookup left the name's zone remembered as a failure
        (RFC 9520 section 3.2) the re-ask is suppressed and the type stays on the work
        list: the result admitting it finished nothing, rather than a verdict nobody was
        allowed to earn.

        Raises :exc:`ValueError` for a list that could not be sent. Section 3.3 makes
        "An MQTYPE-Query option in a query where the primary question is a non-data
        RRTYPE (e.g., ANY, AXFR)" a FORMERR and section 3.2 obliges a client not to send
        one, so bundling behind an ANY is refused here rather than discovered by a server
        that is required to reject it.
        """
        question = self._sole_question(dns_packet, "resolve_bundle")
        asked = tuple(int(qtype) for qtype in extra_qtypes)
        if asked:
            if not is_data_rrtype(int(question.qtype)):
                raise ValueError(
                    f"cannot bundle a MQTYPE-Query behind a {question.qtype} question: "
                    "RFC 10029 section 3.3 obliges a server to answer FORMERR when the "
                    "primary question is not a data RRTYPE"
                )
            # Built and discarded for the sake of its validation: every section 3.3
            # condition on the list is checked here, at the boundary where the caller can
            # still be told, rather than at the socket where all that can be done about
            # it is to drop the option quietly.
            query_option_for(question.qtype, asked)

        response, sname = await self._walk(dns_packet, asked)
        # Held while the re-asks run, so the trace the caller sees is the descent that
        # did the bundling rather than whichever standalone query happened to be last.
        bundle_trace = self.last_trace
        if not asked:
            return BundleResult(supported=False, primary=response)

        if isinstance(response, Response):
            bundle = collect_bundle(
                response,
                primary_qtype=int(question.qtype),
                requested=asked,
                terminal_name=sname.qname,
            ).with_primary(response)
            # A self-contradictory answer does not get this far. :func:`resolve_steps`
            # reads one as the FORMERR section 3.5 says it is equivalent to, demotes that
            # server and asks another -- and that is the only place the rule can be
            # honoured, because an answer the client has been told to discard must not
            # already have been cached by the time somebody decides to discard it. What
            # is left to handle here is the ordinary pair of outcomes: it combined, or it
            # did not.
            self._cache_bundle(response, sname, bundle)
        else:
            # Nothing answered the primary. After a discarded answer this is the usual
            # shape -- one server, no second opinion, the walk out of candidates. The
            # extras are still owed their queries: section 3.5 asks for a standalone one
            # "for all QTx values for which an answer is still required". But a re-ask is
            # an ordinary lookup and inherits the ordinary rules, including RFC 9520
            # section 3.2: a zone this lookup just watched fail is remembered as dead, and
            # the re-ask is stopped before it sends. What comes back then says every type
            # is still needed, which is the truth, rather than a verdict nobody earned.
            bundle = BundleResult(
                supported=False,
                primary=response,
                still_needed=asked,
                types=tuple(BundledType(qtype, BundleState.NEEDED) for qtype in asked),
            )
        self.last_trace = bundle_trace
        if not ask_separately:
            return bundle

        for entry in bundle.types:
            if entry.state is not BundleState.NEEDED:
                continue
            # A standalone query, without the option -- section 3.5 is explicit: "that
            # is, without using the MQTYPE-Query option". It asks for the name the
            # *caller* asked about, not the name the bundle happened to end at: this
            # query has its own alias chain to walk, and starting it at the terminal name
            # would be re-using somebody else's route.
            single = Query(
                questions=[DnsQuestion(question.name, entry.qtype, question.qclass)], RD=True
            )
            answer, _terminal = await self._walk(single)
            if not isinstance(answer, Response):
                # Unfinished, so it stays NEEDED. A work list is allowed to say that: a
                # type nobody answered is not a type with no records.
                continue
            records = tuple(r for r in answer.answers if int(r.rtype) == entry.qtype)
            if int(answer.RCODE) == int(DnsResponseCode.NAME_ERROR):
                state = BundleState.NXDOMAIN
            elif records:
                state = BundleState.COMBINED
            else:
                state = BundleState.NODATA
            bundle = bundle.reasked(entry.qtype, state=state, records=records, response=answer)

        self.last_trace = bundle_trace
        return bundle

    def _cache_bundle(self, response, sname, bundle) -> None:
        """Store what a combined answer delivered for the extra QTYPEs.

        Section 3.5 is what licenses caching these at all: "any authoritative answers
        received MUST be ranked the same as the answer for the primary question" (RFC
        2181 section 5.4.1, cited there by name). The same, and not better -- so an
        extra's entry is authoritative exactly when the response claimed authority, and a
        NODATA learned this way is cached with the same SOA-derived ceiling RFC 2308
        section 5 imposes on the primary's own negative answer. Both rules are already
        :func:`_write_cache`'s for the primary; this extends the same treatment to the
        types that arrived in its shadow, keyed by the name the walk ended at, because
        that is the name the records are owned by and the name a later query for AAAA
        will arrive at by following the same CNAME.

        What is never cached here is :attr:`~namespy.bundle.BundleState.NEEDED`. A QTx
        the server did not list has section 3.5's four innocent reasons, none of which is
        "no such records", and storing a negative for it would hide a name for the length
        of the zone's MINIMUM on the strength of a server having said nothing at all.
        """
        cache = self.cache
        if cache is None or response.TC:
            # RFC 1123 section 6.1.3.2: "Truncated responses MUST NOT be saved (cached)".
            # A combination is the last place a partial RRset could hide, since section
            # 3.4 lets a server stop early precisely because the answer grew too large.
            return
        now = cache.time_fn()
        soa = next((r for r in response.nameservers if int(r.rtype) == int(DnsRType.SOA)), None)
        for entry in bundle.types:
            if entry.state is BundleState.COMBINED:
                records = tuple(r for r in entry.records if int(r.rtype) != OPT_RTYPE)
                if not records:
                    continue
                ttl = min(int(getattr(r, "ttl", 0) or 0) for r in records)
                if ttl <= 0:
                    continue
                cache.put(
                    PositiveEntry(
                        sname.qname,
                        entry.qtype,
                        sname.qclass,
                        records,
                        now + ttl,
                        authoritative=entry.authoritative,
                    )
                )
            elif entry.authoritative:
                # NODATA and NXDOMAIN, and only from a server that claimed authority --
                # the bar RFC 2308 section 2.2.1 sets for the primary's own negative.
                ttl = _negative_ttl_seconds(soa)
                if ttl <= 0:
                    continue
                rcode = (
                    DnsResponseCode.NAME_ERROR
                    if entry.state is BundleState.NXDOMAIN
                    else DnsResponseCode.NO_ERROR
                )
                cache.put(
                    NegativeEntry(sname.qname, entry.qtype, sname.qclass, rcode, soa, now + ttl)
                )
