import asyncio
import ipaddress
import logging
import os
import random
import re
import socket
import struct
import urllib.request
from socket import gaierror
from typing import NamedTuple

from . import IP_MTU_DISCOVER, IP_PMTUDISC_DO, console
from .cache import MemoryDnsCache, NegativeEntry, PositiveEntry
from .enums import DnsQR, DnsQType, DnsRClass, DnsResponseCode, DnsRType
from .names import DomainName
from .packet import DnsPacket, DnsPacketParseError, DnsQuestion, DnsRecord, Query, Response
from .trace import Trace

# RFC 1034 §5.3.3 caps; tunable knobs in this module.
MAX_HOPS = 32
MAX_DEPTH = 24

# Bound on CNAME/DNAME redirections followed for one lookup.
#
# No RFC states a number. RFC 1034 §3.6.2 only requires that alias loops not be
# followed forever ("a alias name must not map to itself, either directly or
# indirectly"), and RFC 6672 §5.1 notes that DNAME plus CNAME makes loops easier
# to construct than either type alone. Some bound is therefore mandatory; this
# is generous relative to real deployments, where chains of 2–3 are the norm,
# and it is deliberately smaller than MAX_HOPS so a pathological chain fails
# with a clear "alias" error rather than an opaque "max hops".
MAX_ALIAS_HOPS = 16

# Per-query timeout. RFC 1034 §5.3.3 step 3 says the resolver picks the
# "best" server, sends a query, and on timeout moves on to another entry —
# but the spec leaves the wait time to the implementation. A small budget
# is essential: without it, one unreachable anycast NS hangs the whole
# resolution (and any glueless sub-resolution rooted in it) until the
# caller's outer timeout fires. BIND uses 1.5–5 s initially; we pick 5 s.
QUERY_TIMEOUT_S = 5.0


class Resolver(asyncio.Protocol):
    #: Optional DNS suffix the resolver assumes for *relative* names — those
    #: whose presentation form does not end in the root terminator (``.``).
    #: A trailing ``.`` on the SNAME prevents this suffix from being assumed
    #: (RFC 1035 §3.1's wire form is always absolute; the trailing dot in
    #: presentation form is a hint to the resolver, not a wire identity).
    #: Set to a ``str`` or :class:`~aiodns.names.DomainName`; left ``None``,
    #: relative names are simply anchored at the root.
    dns_suffix = None

    async def query(self, questions, nameserver_record, address_record, **kwargs):
        if nameserver_record:
            assert isinstance(nameserver_record, DnsRecord)
        if address_record:
            assert isinstance(address_record, DnsRecord)

        future = asyncio.get_running_loop().create_future()

        ip = ipaddress.ip_address(bytes(address_record.rdata))
        dns_packet = Query(questions=questions, **kwargs)
        # RFC 5936: AXFR uses TCP.
        try:
            q0 = questions[0] if questions else None
            if q0 is not None and getattr(q0, "qtype", None) == DnsQType.AXFR:
                self.log.debug("resolver_force_tcp_axfr(dst=%s id=%s)", ip.exploded, dns_packet.ID)
                return await self._query_tcp(ip.exploded, bytes(dns_packet), dns_packet.ID)
        except Exception:
            pass
        key = (ip.exploded, dns_packet.ID)
        try:
            q0 = questions[0] if questions else None
            self.log.debug(
                "resolver_sendto(dst=%s id=%s q=%s %s %s)",
                ip.exploded,
                dns_packet.ID,
                getattr(q0, "name", ""),
                getattr(getattr(q0, "qtype", None), "name", getattr(q0, "qtype", "")),
                getattr(getattr(q0, "qclass", None), "name", getattr(q0, "qclass", "")),
            )
        except Exception:
            pass
        if isinstance(ip, ipaddress.IPv6Address):
            # Use IPv6 glue when available.
            if hasattr(self, "_ensure_v6_transport"):
                try:
                    await self._ensure_v6_transport()
                except Exception:
                    pass
            transport_v6 = getattr(self, "transport_v6", None)
            queue_v6 = getattr(self, "queue_v6", None)
            if transport_v6 is None or queue_v6 is None:
                future.cancel()
                return None

            queue_v6[key] = (dns_packet, future)
            # On Windows, IPv6 sendto expects the full 4-tuple (host, port, flowinfo, scopeid).
            transport_v6.sendto(bytes(dns_packet), (ip.exploded, 53, 0, 0))
            try:
                return await asyncio.wait_for(future, timeout=QUERY_TIMEOUT_S)
            except TimeoutError:
                queue_v6.pop(key, None)
                self.log.debug(
                    "resolver_timeout_udp(dst=%s id=%s ip_version=6)", ip.exploded, dns_packet.ID
                )
                return None

        if not isinstance(ip, ipaddress.IPv4Address):
            future.cancel()
            return None

        self.queue[key] = (dns_packet, future)
        self.transport.sendto(bytes(dns_packet), (ip.exploded, 53))
        try:
            return await asyncio.wait_for(future, timeout=QUERY_TIMEOUT_S)
        except TimeoutError:
            # Drop the queue slot so a late response doesn't try to fulfil
            # a cancelled future (and so the slot doesn't leak); the caller
            # treats ``None`` as "no response" and demotes the entry.
            self.queue.pop(key, None)
            self.log.debug(
                "resolver_timeout_udp(dst=%s id=%s ip_version=4)", ip.exploded, dns_packet.ID
            )
            # UDP may be blocked; try TCP (RFC 1035).
            tcp = await self._query_tcp(ip.exploded, bytes(dns_packet), dns_packet.ID)
            return tcp

    async def _query_tcp(self, host, wire, qid):
        self.log.debug("resolver_tcp_try(dst=%s id=%s)", host, qid)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 53), timeout=QUERY_TIMEOUT_S
            )
        except Exception as e:
            self.log.debug(
                "resolver_tcp_connect_failed(dst=%s id=%s err=%s)", host, qid, type(e).__name__
            )
            return None
        try:
            writer.write(struct.pack("!H", len(wire)) + wire)
            await writer.drain()
            nbuf = await asyncio.wait_for(reader.readexactly(2), timeout=QUERY_TIMEOUT_S)
            (n,) = struct.unpack("!H", nbuf)
            data = await asyncio.wait_for(reader.readexactly(n), timeout=QUERY_TIMEOUT_S)
            (pkt, _off) = DnsPacket.parse(data)
            self.log.debug(
                "resolver_tcp_ok(dst=%s id=%s rcvd_len=%d)", host, getattr(pkt, "ID", -1), len(data)
            )
            return pkt
        except Exception as e:
            self.log.debug("resolver_tcp_failed(dst=%s id=%s err=%s)", host, qid, type(e).__name__)
            return None
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    @staticmethod
    def enumerate_nameserver_addresses(nameserver_records, additional_records):
        nameserver_records = list(nameserver_records)
        additional_records = list(additional_records)
        random.shuffle(nameserver_records)
        random.shuffle(additional_records)

        for nameserver_record in nameserver_records:
            assert isinstance(nameserver_record, DnsRecord)
            if nameserver_record.rtype == DnsRType.NS:
                for address_record in additional_records:
                    assert isinstance(address_record, DnsRecord)
                    if address_record.name == nameserver_record.rdata and address_record.rtype in [
                        DnsRType.A,
                        DnsRType.AAAA,
                    ]:
                        yield (nameserver_record, address_record)


class Forwarder(asyncio.Protocol):
    def __init__(self, nameservers=None):
        if nameservers is None:
            nameservers = ["8.8.8.8", "8.8.4.4", "4.2.2.2", "1.1.1.1"]


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
        return "<Sname %s %s %s>" % (self.qname, self.qtype, self.qclass)


class SlistEntry:
    def __init__(self, zone, ns, addresses=None):
        self.zone = zone
        self.ns = ns
        self.addresses = list(addresses or [])
        self.history = {"sent": 0, "received": 0, "demoted": False}

    def __repr__(self):
        return "<SlistEntry zone=%r ns=%r addrs=%d demoted=%s>" % (
            self.zone,
            self.ns,
            len(self.addresses),
            self.history["demoted"],
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
        return "<Slist zone=%r match=%d entries=%d>" % (
            self.zone,
            self.match,
            len(self.entries),
        )


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
                    ip = ipaddress.ip_address(bytes(ar.rdata))
                    addresses.append(ip)
            sb.entries.append(SlistEntry(DomainName("."), ns_target, addresses))
        return sb

    def copy_for(self, sname):
        s = Slist(sname)
        s.zone = DomainName(".")
        s.match = sname.match_count(s.zone) if sname is not None else 0
        s.entries = [SlistEntry(e.zone, e.ns, list(e.addresses)) for e in self.entries]
        random.shuffle(s.entries)
        return s


# Effect / step / trace event types.
#
# A `resolve_steps` generator yields one of these each time it needs the
# driver to do something (SendQuery, NeedAddress) or just wants to record a
# decision (Referral, Answer, Nodata, …). The driver records every yield into
# a Trace, then either fulfills the effect or moves on.


class SendQuery:
    def __init__(self, entry, questions):
        self.entry = entry
        self.questions = questions

    def __repr__(self):
        return "<SendQuery to=%r q=%r>" % (self.entry.ns, self.questions)


class NeedAddress:
    def __init__(self, ns_name):
        self.ns_name = ns_name

    def __repr__(self):
        return "<NeedAddress %r>" % (self.ns_name,)


class Referral:
    def __init__(self, old_zone, new_zone, match_before, match_after):
        self.old_zone = old_zone
        self.new_zone = new_zone
        self.match_before = match_before
        self.match_after = match_after

    def __repr__(self):
        return "<Referral %r->%r match %d->%d>" % (
            self.old_zone,
            self.new_zone,
            self.match_before,
            self.match_after,
        )


class Answer:
    def __init__(self, records):
        self.records = list(records)

    def __repr__(self):
        return "<Answer %d>" % len(self.records)


class Nodata:
    def __init__(self, soa):
        self.soa = soa

    def __repr__(self):
        return "<Nodata soa=%r>" % (self.soa,)


class Nxdomain:
    def __repr__(self):
        return "<Nxdomain>"


class Cname:
    def __init__(self, target):
        self.target = target

    def __repr__(self):
        return "<Cname %r>" % (self.target,)


class Demote:
    def __init__(self, entry, reason):
        self.entry = entry
        self.reason = reason

    def __repr__(self):
        ns = self.entry.ns if self.entry is not None else None
        return "<Demote %r %s>" % (ns, self.reason)


class Done:
    def __init__(self, response):
        self.response = response

    def __repr__(self):
        return "<Done>"


class Fail:
    def __init__(self, reason):
        self.reason = reason

    def __repr__(self):
        return "<Fail %s>" % self.reason


def _records_by_owner(response):
    """Group a response's answer-section records by owner name.

    Keyed on :class:`~aiodns.names.DomainName`, whose equality and hash are
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


def _follow_aliases(response, sname) -> AliasWalk:
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
    traversed = []
    events = []
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

        if len(traversed) >= MAX_ALIAS_HOPS:
            # Same reasoning: no answer of this shape deserves another query, and
            # returning `current` here would merely move the decision to the
            # driver's own counter instead of failing where the evidence is.
            return AliasWalk(None, events, failure=f"alias chain longer than {MAX_ALIAS_HOPS}")


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


def classify(response, sname, slist, entry):
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

    if response.RCODE == DnsResponseCode.name_error:
        yield Nxdomain()
        yield Done(response)
        return

    if response.RCODE != DnsResponseCode.no_error:
        yield Demote(entry, "rcode " + response.RCODE.name)
        return

    # Answer section: either a complete answer, or a chain parked on an alias
    # whose target still needs looking up (RFC 1034 §5.3.3 step 4c: "if the
    # answer contains a CNAME RR, set SNAME to the contents of the RDATA field
    # of the displayed CNAME RR, and go to step 2").
    walk = _follow_aliases(response, sname)
    for event in walk.events:
        yield event
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
                if int(ar.rtype) == int(DnsRType.A):
                    ip = ipaddress.ip_address(bytes(ar.rdata))
                    if isinstance(ip, ipaddress.IPv4Address):
                        addresses.append(ip)
                elif int(ar.rtype) == int(DnsRType.AAAA):
                    ip = ipaddress.ip_address(bytes(ar.rdata))
                    if isinstance(ip, ipaddress.IPv6Address):
                        addresses.append(ip)
            new_entries.append(SlistEntry(new_zone, ns_target, addresses))
        random.shuffle(new_entries)

        slist.entries = new_entries
        slist.zone = new_zone
        slist.match = match_after

        yield Referral(old_zone, new_zone, match_before, match_after)
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


def resolve_steps(sname, slist, cache=None):
    """Drive resolution as a generator of effect/trace events.

    The generator is fully synchronous; it never touches sockets. The async
    driver `RecursiveResolver._drive` fulfills `SendQuery` / `NeedAddress`
    yields and feeds results back via `gen.send(...)`.

    If ``cache`` is provided (a :class:`aiodns.cache.DnsCache`), every hop
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

    for _ in range(MAX_HOPS):
        if cache is not None:
            hit = cache.get(sname.qname, sname.qtype, sname.qclass)
            if hit is not None:
                if isinstance(hit, PositiveEntry):
                    yield Answer(hit.records)
                elif hit.rcode == DnsResponseCode.name_error:
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
        for step in classify(response, sname, slist, entry):
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
        if alias_hops >= MAX_ALIAS_HOPS:
            yield Fail(f"alias chain longer than {MAX_ALIAS_HOPS}")
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
            QR=DnsQR.response,
            AA=hit.authoritative,
            RCODE=DnsResponseCode.no_error,
            questions=questions,
            answers=list(hit.records),
        )
    rcode = hit.rcode if isinstance(hit.rcode, DnsResponseCode) else DnsResponseCode(int(hit.rcode))
    nameservers = [hit.soa] if hit.soa is not None else []
    return Response(
        QR=DnsQR.response,
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
    """
    now = cache.time_fn()
    if isinstance(terminal_event, Answer):
        records = list(terminal_event.records)
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
                DnsResponseCode.no_error,
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
                DnsResponseCode.name_error,
                soa,
                now + ttl,
            )
        )


class RecursiveResolver(Resolver):
    def error_received(self, exception):
        if isinstance(exception, gaierror):
            pass
        self.log.critical(exception)

    def record_reader(self, zone_file):
        with open(zone_file, "r") as root_hints_file:
            for i, line in enumerate(root_hints_file):
                if not line or line[0] == ";":
                    continue
                tokens = re.split(r"\s+", line.rstrip())
                if len(tokens) == 5:
                    (name, ttl, rclass, rtype, rdata) = tokens
                    rclass = DnsRClass[rclass]
                elif len(tokens) == 4:
                    (name, ttl, rtype, rdata) = tokens
                    rclass = DnsRClass.IN  # lets just assume
                else:
                    logging.warning("Unrecognized entry on line %d of zone file: %s", i, zone_file)
                    continue

                try:
                    rtype = DnsRType[rtype]
                    ttl = int(ttl)
                except ValueError:
                    self.log.critical("Malformed glue records.")
                    continue

                name = DomainName(name)
                if rtype == DnsRType.SOA:
                    pass
                if rtype == DnsRType.NS:
                    record = DnsRecord(name, rtype, rclass, ttl, rdata=DomainName(rdata))
                elif rtype == DnsRType.A:
                    record = DnsRecord(
                        name, rtype, rclass, ttl, rdata=ipaddress.IPv4Address(rdata).packed
                    )
                elif rtype == DnsRType.AAAA:
                    record = DnsRecord(
                        name, rtype, rclass, ttl, rdata=ipaddress.IPv6Address(rdata).packed
                    )
                else:
                    logging.warning(
                        "Skipping %s record for %s from zone: %s", rtype, name, zone_file
                    )
                    continue

                yield record

    def __init__(self, root_hints_path="named.root", dns_suffix=None, cache=None):
        self.queue = {}
        self.queue_v6 = {}
        self.transport_v6 = None
        self._v6_ready = None
        self.log = logging.Logger("resolver")
        self.log.addHandler(console)
        self.root_hints = self.bootstrap(root_hints_path)
        self.sbelt = Sbelt.from_response(self.root_hints)
        self.last_trace = None
        self.cache = cache if cache is not None else MemoryDnsCache()
        if dns_suffix is not None:
            self.dns_suffix = dns_suffix

    def connection_made(self, transport):
        self.transport = transport
        sock = transport.get_extra_info("socket")
        sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
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
            try:
                self.log.debug(
                    "resolver_v6_ready(sockname=%s)", transport.get_extra_info("sockname")
                )
            except Exception:
                pass
            return transport
        except Exception as e:
            self.log.debug("resolver_v6_failed(err=%s)", type(e).__name__)
            self.transport_v6 = None
            return None

    def _datagram_received_v6(self, data, addr):
        try:
            (dns_packet, offset) = DnsPacket.parse(data)
        except DnsPacketParseError:
            return

        host = addr[0]
        key = (str(host), dns_packet.ID)
        if key in self.queue_v6:
            (_query_packet, future) = self.queue_v6[key]
            del self.queue_v6[key]
            if not future.done():
                future.set_result(dns_packet)
        else:
            pass

    def datagram_received(self, data, addr):
        try:
            (dns_packet, offset) = DnsPacket.parse(data)
        except DnsPacketParseError as e:
            self.log.warning(
                "parse failed in resolver: err=%s offset=%s len=%d hex=%s",
                e,
                e.offset,
                len(e.data),
                e.wire_hex(),
            )
        else:
            self.log.debug("resolver_datagram_recieved(%s, %s)" % (dns_packet, addr))
            (host, port) = addr
            key = (str(host), dns_packet.ID)
            if key in self.queue:
                (query_packet, future) = self.queue[key]
                del self.queue[key]
                # The future may already be cancelled if the per-query
                # timeout fired before this late response arrived; ignore
                # that race rather than propagating InvalidStateError out
                # of the protocol callback.
                if not future.done():
                    future.set_result(dns_packet)
            else:
                self.log.debug("resolver_unexpected_packet(src=%s id=%s)", host, dns_packet.ID)

    def bootstrap(self, root_hints_path):
        questions = [DnsQuestion(DomainName.root_label(), qtype=DnsQType.NS)]

        try:
            if not os.path.isfile(root_hints_path):
                urllib.request.urlretrieve(
                    "http://www.internic.net/domain/named.root", root_hints_path
                )
                self.log.info("Attempting to retrieve root hints from internic.")
            else:
                self.log.debug("Found root hints, %s" % os.path.basename(root_hints_path))

        except IOError:
            self.log.critical("Unable to retrieve root hints.")
            return None

        else:
            nameservers = []
            additional_records = []
            for record in self.record_reader(root_hints_path):
                if record.rtype == DnsRType.NS:
                    nameservers.append(record)
                if record.rtype == DnsRType.A or record.rtype == DnsRType.AAAA:
                    additional_records.append(record)

            query = Query(QR=DnsQR.query, RD=False, questions=questions)
            response = Response(
                QR=DnsQR.response,
                ID=query.ID,
                AA=True,
                RD=False,
                RA=False,
                questions=questions,
                nameservers=nameservers,
                additional_records=additional_records,
            )

        return response

    async def _send_for_entry(self, entry, questions):
        """Send the query to this entry, trying all known addresses."""
        if not entry.addresses:
            return None

        ns_record = DnsRecord(entry.zone, DnsRType.NS, DnsRClass.IN, 0, rdata=entry.ns)

        for address in list(entry.addresses):
            if hasattr(address, "packed"):
                packed = address.packed
            else:
                packed = bytes(address)
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
        """Pump the resolve_steps generator and fulfill its effects."""
        if depth > MAX_DEPTH:
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
                child_sname = Sname(step.ns_name, DnsQType.A, DnsRClass.IN)
                child_slist = self.sbelt.copy_for(child_sname)
                child_trace = trace.child(child_sname)
                sub_gen = resolve_steps(child_sname, child_slist, self.cache)
                sub_response = await self._drive(sub_gen, child_trace, depth + 1)
                addrs = []
                if isinstance(sub_response, Response):
                    for r in sub_response.answers:
                        if r.rtype == DnsRType.A:
                            ip = ipaddress.ip_address(bytes(r.rdata))
                            if isinstance(ip, ipaddress.IPv4Address):
                                addrs.append(ip)
                sent = addrs
                continue
            if isinstance(step, Done):
                return step.response
            if isinstance(step, Fail):
                return None
            sent = None

    async def resolve(self, dns_packet):
        assert isinstance(dns_packet, DnsPacket)
        assert dns_packet.QDCOUNT > 0

        if dns_packet.QDCOUNT > 1:
            assert all(q.name == dns_packet.questions[0].name for q in dns_packet.questions[1:])
            assert all(q.qclass == dns_packet.questions[0].qclass for q in dns_packet.questions[1:])

        # Apply the resolver's DNS suffix. Names already terminated by a
        # trailing ``.`` pass through unchanged; relative names are promoted
        # to absolute by appending :attr:`dns_suffix` (or just the root).
        question = dns_packet.questions[0]
        qname = question.name.qualify(dns_suffix=self.dns_suffix)
        sname = Sname(qname, question.qtype, question.qclass)
        self.last_trace = Trace(sname)
        slist = self.sbelt.copy_for(sname)
        gen = resolve_steps(sname, slist, self.cache)
        response = await self._drive(gen, self.last_trace)
        if isinstance(response, Response):
            response.ID = dns_packet.ID
            response.trace = self.last_trace
        return response
