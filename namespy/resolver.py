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
  (the algorithm), section 3.6.2 (aliases must not loop)
* RFC 1035 section 4.3 (server behaviour), section 5.4.1 (CNAME in the answer)
* RFC 2308 section 5 (negative caching from SOA.MINIMUM)
* RFC 5452 sections 5-6 (matching responses to queries; source-port randomness)
* RFC 6672 section 5.1 (DNAME plus CNAME makes alias loops easier to build)
* RFC 7766 section 6 (TCP for truncation and for AXFR)
* RFC 8106 section 2 (root hints: an initial address set is required)
* RFC 9156 (QNAME minimisation -- not implemented; see the note in resolve_steps)
"""

import asyncio
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
from .cache import MemoryDnsCache, NegativeEntry, PositiveEntry
from .enums import DnsQR, DnsQType, DnsRClass, DnsResponseCode, DnsRType
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

    #: Optional DNS suffix the resolver assumes for *relative* names — those
    #: whose presentation form does not end in the root terminator (``.``).
    #: A trailing ``.`` on the SNAME prevents this suffix from being assumed
    #: (RFC 1035 §3.1's wire form is always absolute; the trailing dot in
    #: presentation form is a hint to the resolver, not a wire identity).
    #: Set to a ``str`` or :class:`~namespy.names.DomainName`; left ``None``,
    #: relative names are simply anchored at the root.
    dns_suffix = None

    async def query(self, questions, nameserver_record, address_record, **kwargs):
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
        if self.edns_payload_size:
            # RFC 6891 and the practice behind DNS Flag Day: an EDNS-aware
            # requestor advertises OPT on *every* query rather than probing
            # selectively, so the responder never has to guess and the
            # 512-octet truncation regime becomes the fallback rather than
            # the default.
            dns_packet.add_edns(self.edns_payload_size)
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

        # Two attempts at most. The second exists only for the RFC 6891
        # section 6.2.2 fallback -- "If a requestor detects that the remote
        # end does not support EDNS(0), it MAY issue queries without an OPT
        # record" -- and is taken only when the first answer actually said so
        # (see _edns_rejected). The pending key cannot shift between
        # attempts: it is built from the transaction ID and the question,
        # and dropping the OPT record alters neither.
        for attempt in (1, 2):
            if attempt == 2:
                future = asyncio.get_running_loop().create_future()
                self.log.debug("resolver_edns_fallback(dst=%s id=%s)", ip.exploded, dns_packet.ID)
            queue[key] = (dns_packet, future)
            transport.sendto(bytes(dns_packet), sendto_addr)
            response = await self._await_udp(future, key, dns_packet, ip, queue=queue)
            if response is None or attempt == 2 or not self._edns_rejected(dns_packet, response):
                return response
            dns_packet.remove_edns()
        # Unreachable: attempt 2 always returns above, so the loop is
        # exhaustive by construction. Spelled out so the invariant survives a
        # future edit that might otherwise let a fall-through return a future
        # that was never resolved.
        return None

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

    @staticmethod
    def enumerate_nameserver_addresses(nameserver_records, additional_records):
        """Yield (NS record, address record) pairs, shuffled.

        The shuffle is not cosmetic. RFC 8106 section 2 and RFC 1034 section 5.3.3
        both assume a resolver will try *several* servers rather than the first one
        listed; without the shuffle, every resolver using this library hammers the
        same root server -- ``a.root-servers.net`` is first in ``named.root`` --
        which is both a self-inflicted denial-of-service risk and a way to make
        one server's outage look like global DNS failure.

        Non-NS nameserver records and non-address glue are skipped rather than
        raising: a response carries the additional section as a convenience, so it
        legitimately contains RRs that are not glue.
        """
        nameserver_records = list(nameserver_records)
        additional_records = list(additional_records)
        random.shuffle(nameserver_records)
        random.shuffle(additional_records)

        for nameserver_record in nameserver_records:
            if not isinstance(nameserver_record, DnsRecord):
                continue
            if nameserver_record.rtype != DnsRType.NS:
                continue
            for address_record in additional_records:
                if not isinstance(address_record, DnsRecord):
                    continue
                if address_record.name == nameserver_record.rdata and address_record.rtype in (
                    DnsRType.A,
                    DnsRType.AAAA,
                ):
                    yield (nameserver_record, address_record)


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
        backoff instead of permanent exclusion (RFC 1034 section 5.4.1).
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


@dataclass(frozen=True)
class NeedAddress:
    """The driver must resolve *ns_name* to an address before it can be queried.

    Raised for a glueless NS -- one whose name appears in the authority section
    but whose address did not (RFC 1034 section 3.6.4, RFC 5625 section 2.5).
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

    RFC 5625 section 2.6 forbids discarding a server on a single failure, so a
    demotion is a ranking change within the current Slist, not a deletion from
    the name space.
    """

    entry: SlistEntry | None
    reason: str


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
    address and ID. RFC 5452 sections 5 and 6 are the reason: the ID alone is 16
    bits, which an off-path sender can brute-force, whereas a response must also
    reproduce the QNAME, QTYPE and QCLASS we asked about before it can be taken
    for an answer. That turns a 65k-guess problem into one that also requires
    knowing the name being resolved, and it is the difference between a resolver
    that can be poisoned by a stray or forged packet and one that cannot.

    The key is derived from whichever packet it is handed, so the same function
    serves both sides: the outgoing query registers under it, and an incoming
    response is looked up by it. A response that omits the question section
    entirely therefore never matches -- which is the intended strictness. RFC 1035
    section 4.1 says the question section "MUST be present in any DNS query or
    DNS response message", and RFC 5452 section 5 tells a client to verify it
    rather than assume it.
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
    faithfully. Both are required by RFC 1035 section 4.1.1 and both are
    explicitly named as client-side validation by RFC 5452 section 5.
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


def classify(response, sname, slist, entry, max_alias_hops: int = MAX_ALIAS_HOPS):
    """Apply RFC 1034 §5.3.3 step 4 to a single response.

    Yields a sequence of trace events. Mutates `slist` for valid referrals
    (extends entries, advances zone/match). Each yielded `Demote` carries
    the entry the caller should mark demoted; each terminal `Done`
    completes the lookup.

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
        for ns_target in ns_targets:
            addresses = []
            for ar in response.additional_records:
                # Glue must be for *this* target; RFC 1034 §5.4.1 allows an
                # address record to be a CNAME, which is not glue at all.
                if ar.name != ns_target:
                    continue
                ip = _answer_address(ar)
                # _answer_address validates the family against the RR type, so a
                # 16-octet "A" or a 4-octet "AAAA" contributes nothing rather
                # than raising out of the resolution loop.
                if ip is not None:
                    addresses.append(ip)
            entry = SlistEntry(new_zone, ns_target, addresses)
            new_entries.append(entry)
            if not addresses and ns_target.is_subdomain_of(new_zone):
                # RFC 1035 section 6 / RFC 1034 section 5.4.1: a nameserver
                # inside the zone it is delegated to can only be reached via glue
                # supplied by the parent, because asking it for its own address
                # means already having reached it. Such a target is *lame*, so it
                # is demoted immediately: sub-resolving it would descend into the
                # very zone we are trying to reach, and with an A and an AAAA
                # attempt per level that is a 2x branching blowup rather than a
                # lookup that simply fails.
                entry.history["demoted"] = True
                entry.history["lame"] = "in-bailiwick without glue"
        random.shuffle(new_entries)

        slist.entries = new_entries
        slist.zone = new_zone
        slist.match = match_after

        yield Referral(old_zone, new_zone, match_before, match_after)
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
    """
    # Alias state lives here, not in classify: a CNAME in one response can point
    # at a name that another response aliases again, so only the loop spanning
    # responses can tell a long chain from a loop. `seen` catches the two-name
    # ping-pong (a -> b -> a) that a hop counter alone would ride out for the
    # full budget.
    alias_hops = 0
    seen_names = {sname.qname}

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
        entry = slist.best()
        if entry is None:
            yield Fail("no servers")
            return
        if not entry.addresses:
            addrs = yield NeedAddress(entry.ns)
            if not addrs:
                yield Demote(entry, "no address")
                slist.demote(entry)
                continue
            entry.addresses.extend(addrs)
            continue
        response = yield SendQuery(entry, sname.questions)
        terminal = False
        alias_target = None
        for step in classify(response, sname, slist, entry, max_alias_hops=max_alias_hops):
            # Write to cache *before* yielding the terminal event so callers
            # (including tests) can observe a populated cache the moment the
            # Answer/Nxdomain/Nodata is visible — the generator pauses at
            # ``yield step`` and may never be resumed past Done.
            if cache is not None and isinstance(step, (Answer, Nodata, Nxdomain)):
                _write_cache(cache, sname, step, response)
            yield step
            if isinstance(step, (Done, Fail)):
                # Fail is terminal for the same reason Done is: classify emits it
                # when the response itself is unusable, and any Cname recorded a
                # moment earlier in the same response must not then be re-anchored
                # and queried again.
                terminal = True
                break
            if isinstance(step, Demote):
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
            yield Fail(f"alias loop at {alias_target}")
            return
        if alias_hops >= max_alias_hops:
            yield Fail(f"alias chain longer than {max_alias_hops}")
            return
        seen_names.add(alias_target)
        alias_hops += 1
        sname.reanchor(alias_target)
    yield Fail("max hops")


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
        max_hops: int = MAX_HOPS,
        max_depth: int = MAX_DEPTH,
        max_alias_hops: int = MAX_ALIAS_HOPS,
        query_timeout: float = QUERY_TIMEOUT_S,
        edns_payload_size: int | None = EDNS_PAYLOAD_SIZE,
    ):
        """Build a resolver without touching the network.

        :param root_hints_path: a master-file path to read hints from. Left
            ``None``, the copy packaged inside Namespy is used, which is what makes
            ``RecursiveResolver()`` work offline, in a test, and on a host with no
            route to internic. A path that is given but does not exist is an
            error rather than a licence to fetch: silently downloading during
            ``__init__`` also wrote a file into the current working directory.
        :param query_timeout: seconds per UDP attempt (and per TCP phase).
        :param edns_payload_size: UDP payload advertised by the EDNS(0) OPT
            record on every outbound query (RFC 6891 section 6.2.3). ``0`` or
            ``None`` sends no OPT at all -- the pre-EDNS behaviour, still
            occasionally wanted against ossified infrastructure, though the
            section 6.2.2 fallback already handles the servers that would
            otherwise need it.
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
        self.root_hints = self.bootstrap(root_hints_path)
        self.sbelt = Sbelt.from_response(self.root_hints)
        self.last_trace = None
        self.cache = cache if cache is not None else MemoryDnsCache()
        if dns_suffix is not None:
            self.dns_suffix = dns_suffix

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

    async def _send_for_entry(self, entry, questions):
        """Send the query to this entry, trying all known addresses."""
        if not entry.addresses:
            return None

        ns_record = DnsRecord(entry.zone, DnsRType.NS, DnsRClass.IN, 0, rdata=entry.ns)

        for address in list(entry.addresses):
            # Addresses arrive either as ipaddress objects (glue, root hints) or
            # as raw packed octets (a caller that seeded the belt by hand).
            packed = address.packed if hasattr(address, "packed") else bytes(address)
            if len(packed) not in (4, 16):
                continue

            addr_rtype = DnsRType.A if len(packed) == 4 else DnsRType.AAAA
            addr_record = DnsRecord(entry.ns, addr_rtype, DnsRClass.IN, 0, rdata=packed)
            try:
                response = await self.query(questions, ns_record, addr_record, RD=False)
            except asyncio.InvalidStateError:
                response = None

            if response is not None:
                return response

        return None

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
                sent = await self._send_for_entry(step.entry, step.questions)
                continue
            if isinstance(step, NeedAddress):
                # RFC 1034 section 5.3.3 and RFC 5625 section 2.6: glue may be
                # absent (a "glueless" referral), in which case the NS target has
                # to be resolved in its own right. Ask for A *and* AAAA so a
                # target reachable only over IPv6 is not silently skipped, and
                # read the payloads through the RDATA codecs rather than assuming
                # every answer is four octets.
                addrs = []
                for rtype in (DnsQType.A, DnsQType.AAAA):
                    child_sname = Sname(step.ns_name, rtype, DnsRClass.IN)
                    child_slist = self.sbelt.copy_for(child_sname)
                    child_trace = trace.child(child_sname)
                    sub_gen = resolve_steps(child_sname, child_slist, self.cache)
                    sub_response = await self._drive(sub_gen, child_trace, depth + 1)
                    if not isinstance(sub_response, Response):
                        continue
                    for record in sub_response.answers:
                        # RFC 5625 section 2.5: only accept data for the name
                        # actually asked about. A server (or an attacker) that
                        # answers with some other name's address must not be able
                        # to steer where we send the next query.
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
        if not isinstance(dns_packet, DnsPacket):
            raise TypeError(f"resolve() expects a DnsPacket, got {type(dns_packet).__name__}")
        if not dns_packet.questions:
            raise ValueError("resolve() needs a packet with at least one question")

        first = dns_packet.questions[0]
        if len(dns_packet.questions) > 1 and any(
            question.name != first.name or question.qclass != first.qclass
            for question in dns_packet.questions[1:]
        ):
            raise ValueError(
                "resolve() handles one (name, class) per call; multi-question "
                "packets must agree on name and class"
            )

        # Apply the resolver's DNS suffix. Names already terminated by a
        # trailing ``.`` pass through unchanged; relative names are promoted
        # to absolute by appending :attr:`dns_suffix` (or just the root).
        question = dns_packet.questions[0]
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
        )
        response = await self._drive(gen, self.last_trace)
        if isinstance(response, Response):
            response.ID = dns_packet.ID
            response.trace = self.last_trace
        return response
