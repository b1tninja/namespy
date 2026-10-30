#!/usr/bin/env python3
# setcap cap_net_bind_service=+ep /usr/bin/python3.4  # for binding :53 on Linux

import argparse
import asyncio
import logging
import sys
import time
import traceback

from .bundle import BundleResult, BundleState
from .edns import (
    extended_error_presentation,
    extended_errors_of,
    nsid_option,
    nsid_presentation,
)
from .enums import (
    DnsOpCode,
    DnsQClass,
    DnsQR,
    DnsQType,
    DnsRClass,
    DnsResponseCode,
    is_data_rrtype,
)
from .names import DomainName
from .packet import OPT_RTYPE, DnsPacket, DnsPacketParseError, DnsQuestion, Query
from .rdata import generic_presentation, type_name_of
from .resolver import EDNS_PAYLOAD_SIZE, GluePolicy, RecursiveResolver
from .server import MQTYPE_RECOMMENDED_QTX_LIMIT, DnsServer

LOCAL_DNS: tuple[str, int] = ("127.0.0.1", 53)
EXAMPLE_NAME = "example.org"
LOOKUP_TIMEOUT_S = 120.0

#: QTYPE and QCLASS are each 16 bits (RFC 1035 sections 4.1.3, 6).
MAX_WIRE_FIELD = 0xFFFF


class _LocalDnsResponseWaiter(asyncio.DatagramProtocol):
    """Wait for a single UDP datagram, then close the client transport."""

    def __init__(self, on_packet: asyncio.Future) -> None:
        self._on_packet = on_packet
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if not self._on_packet.done():
            self._on_packet.set_result((data, addr))
        if self.transport is not None:
            self.transport.close()

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        if not self._on_packet.done():
            self._on_packet.set_exception(exc)


async def _lookup_example_org_via_local_server(loop: asyncio.AbstractEventLoop) -> None:
    future: asyncio.Future = loop.create_future()
    client_transport, _ = await loop.create_datagram_endpoint(
        lambda: _LocalDnsResponseWaiter(future),
        local_addr=("0.0.0.0", 0),
    )
    try:
        query = Query(questions=[DnsQuestion(DomainName(EXAMPLE_NAME), 1, 1)], RD=True)
        client_transport.sendto(bytes(query), LOCAL_DNS)
        data, raddr = await asyncio.wait_for(future, timeout=LOOKUP_TIMEOUT_S)
    except TimeoutError:
        logging.error(
            "Timed out after %s s waiting for %s A from local DnsServer %s (resolver may be WIP).",
            LOOKUP_TIMEOUT_S,
            EXAMPLE_NAME,
            LOCAL_DNS,
        )
    except Exception:
        logging.exception("UDP client error while waiting for %s", EXAMPLE_NAME)
    else:
        try:
            pkt, _off = DnsPacket.parse(data)
        except Exception:
            logging.exception("Failed to parse DNS response from %s", raddr)
        else:
            logging.info("example.org lookup via local DnsServer %s -> %s", LOCAL_DNS, pkt)
    finally:
        client_transport.close()


def _dump_last_resolution_md(resolver_protocol, path="last_resolution.md") -> None:
    trace = getattr(resolver_protocol, "last_trace", None)
    if trace is None:
        return
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("# Last resolution trace\n\n")
            f.write("```mermaid\n")
            f.write(trace.to_mermaid())
            f.write("\n```\n")
        logging.info("Wrote %s", path)
    except OSError:
        logging.exception("Failed to write %s", path)


# Dig-style CLI.


def _parse_qtype(token):
    """Resolve a record type given as a mnemonic or a number.

    A number with no mnemonic is *accepted*. Refusing it would mean the CLI
    cannot ask for a type until this library happens to list it, which is the
    opposite of what RFC 3597 section 3 requires of a receiver: unknown types are
    legitimate wire values, and a freshly assigned one should be queryable on the
    day it is registered, not after Namespy catches up.
    """
    s = str(token).upper()
    try:
        return DnsQType[s]
    except KeyError:
        pass
    return _parse_field(s, token, DnsQType, "record type")


def _parse_qclass(token):
    """Resolve a record class, mnemonic or number (see :func:`_parse_qtype`).

    Both paths return :class:`~namespy.enums.DnsQClass`, the space of the question
    section's QCLASS field. Reaching for :class:`~namespy.enums.DnsRClass` on the
    mnemonic path made the return type depend on how the user spelled the same
    value -- ``IN`` yielding one enum and ``1`` the other -- which is invisible
    while comparing by value and surprising the moment anything keys on type.
    """
    s = str(token).upper()
    try:
        return DnsQClass[s]
    except KeyError:
        pass
    return _parse_field(s, token, DnsQClass, "record class")


def _parse_field(text, token, enum, label):
    """Coerce a 16-bit protocol field, keeping an unregistered value as an int.

    The range check is the only hard limit: QTYPE and QCLASS are each 16 bits on
    the wire (RFC 1035 sections 4.1.3, 6), so anything larger cannot be sent and
    failing here beats emitting a truncated field later.
    """
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"unknown {label}: {token}") from None
    if not 0 <= value <= MAX_WIRE_FIELD:
        raise argparse.ArgumentTypeError(
            f"{label} {token} is outside the 16-bit range 0-{MAX_WIRE_FIELD}"
        )
    return enum.parse(value)


def _format_rdata(record):
    r"""Render one record's RDATA for the dig-style answer.

    Goes through the codec's :meth:`~namespy.rdata.RData.to_presentation` so that
    every type renders the way the wire format describes it: an address as an
    address, a name absolutely qualified, and an unknown type as RFC 3597
    section 5 ``\# <len> <hex>``. The alternative was decoding bytes as ASCII,
    which turned a binary RDATA into mojibake on the terminal -- and which a
    `ZONEMD` or `CSYNC` record hits routinely now that unknown types parse.

    ``record.rdata`` is always an :class:`~namespy.rdata.RData`, so there is no
    raw-bytes case to special-case here; the fallback exists only because
    ``__slots__`` lets a caller assign one in after construction.
    """
    rdata = record.rdata
    if hasattr(rdata, "to_presentation"):
        return rdata.to_presentation()
    return generic_presentation(bytes(rdata))


def _format_record_row(r):
    # Class and type are separate constant spaces: 1 means A in one and IN in
    # the other, so each must be resolved through its own enum -- otherwise the
    # class column silently prints a record-type mnemonic.
    class_col = DnsRClass.mnemonic(r.rclass)
    return f"{r.name}\t{r.ttl}\t{class_col}\t{type_name_of(r.rtype)}\t{_format_rdata(r)}"


def _format_response(response, args, elapsed_ms, bundle=None):
    """Render *response* as a dig-style answer.

    Follows dig's section layout so existing muscle memory and log scrapers
    still work, with two deliberate additions: the EDNS(0) pseudo-section, since
    an OPT record is otherwise invisible while being exactly what determines the
    effective RCODE (RFC 6891 sections 6.1.2-6.1.3); and ``ad``/``cd`` flags,
    which live only in OPT and are the first thing an operator wants to see when
    comparing against a validating resolver.

    *bundle* adds a third pseudo-section, and is ``None`` unless ``--mqtype`` was
    given: with no bundle asked for there is nothing to account for, and the
    output of an ordinary lookup stays byte for byte what it was.
    """
    lines = []
    lines.append(
        f"; <<>> namespy <<>> {args.name} {type_name_of(args.type)} {DnsQClass.mnemonic(args.qclass)}"
    )
    if response is None:
        lines.append(";; no response")
        return "\n".join(lines)

    flags = []
    if DnsQR.RESPONSE == response.QR:
        flags.append("qr")
    if response.AA:
        flags.append("aa")
    if response.TC:
        flags.append("tc")
    if response.RD:
        flags.append("rd")
    if response.RA:
        flags.append("ra")
    if response.ad:
        flags.append("ad")
    if response.cd:
        flags.append("cd")

    lines.append(";; Got answer:")
    lines.append(
        f";; ->>HEADER<<- opcode: {DnsOpCode.mnemonic(response.OPCODE)}, "
        f"status: {DnsResponseCode.mnemonic(response.extended_rcode)}, "
        f"id: {response.ID}"
    )
    lines.append(
        f";; flags: {' '.join(flags)}; QUERY: {response.QDCOUNT}, "
        f"ANSWER: {len(response.answers)}, AUTHORITY: {len(response.nameservers)}, "
        f"ADDITIONAL: {len(response.additional_records)}"
    )
    lines.append("")

    if response.opt() is not None:
        record = response.opt()
        lines.append(";; OPT PSEUDOSECTION:")
        lines.append(
            f"; EDNS: version: 0, flags: {'; '.join(_opt_flags(response))}; udpsize: {int(record.rclass)}"
        )
        # One line per Extended DNS Error, in the order they arrived. They belong in
        # this pseudo-section because they *are* OPT RDATA, and because RFC 8914
        # section 3 refuses to tie them to any RCODE -- "Receivers MUST be able to
        # accept EDE codes and EXTRA-TEXT in all messages, including those with a
        # NOERROR RCODE" -- so printing them only under a failure status would hide
        # the Stale Answer and Cached Error codes, which are the interesting ones.
        for error in _response_errors(response):
            lines.append(f"; EDE: {extended_error_presentation(error)}")
        lines.append("")

    if response.questions:
        lines.append(";; QUESTION SECTION:")
        for q in response.questions:
            lines.append(f";{q.name}\t\t{DnsQClass.mnemonic(q.qclass)}\t{type_name_of(q.qtype)}")
        lines.append("")

    for label, section in (
        ("ANSWER", response.answers),
        ("AUTHORITY", response.nameservers),
        ("ADDITIONAL", [r for r in response.additional_records if int(r.rtype) != OPT_RTYPE]),
    ):
        # OPT is deliberately excluded from the ADDITIONAL listing above, while
        # still counted in the ARCOUNT figure: it is a transport pseudo-record
        # with no zone meaning, already fully described by the pseudo-section, and
        # printing it as a row invites someone to read its CLASS field -- the
        # sender's UDP payload size -- as a record class.
        if section:
            lines.append(f";; {label} SECTION:")
            for r in section:
                lines.append(_format_record_row(r))
            lines.append("")

    if bundle is not None:
        lines.append(_format_bundle(bundle))
        lines.append("")

    lines.append(f";; Query time: {int(elapsed_ms)} msec")
    lines.append(f";; MSG SIZE  rcvd: {len(bytes(response))}")
    return "\n".join(lines)


def _opt_flags(response):
    """The EDNS(0) flag mnemonics set in a response, in dig's order."""
    out = []
    if response.ad:
        out.append("ad")
    if response.cd:
        out.append("cd")
    return out


def _response_errors(response):
    """The Extended DNS Errors a response carries -- and never an exception.

    A malformed option inside somebody's OPT is not worth losing an answer over:
    RFC 8914 section 6 says EDE "MUST NOT alter DNS protocol processing", and a
    printer that raises would be altering it. So the bad case prints nothing and the
    good case prints what the server chose to say, escaped and capped by
    :func:`~namespy.edns.extended_error_presentation` because those octets came from
    a stranger.
    """
    try:
        return extended_errors_of(response.edns_options())
    except DnsPacketParseError:
        return ()


def _format_short(response, bundle=None):
    """RDATA and nothing else -- plus the RDATA of anything else that was asked for.

    ``--short`` keeps stdout parseable, which is why the bundle's commentary stays in the
    report. But a caller who asked for AAAA beside A and got only the A lines would read
    that as an empty set, and the empty set is the one thing this interface must never
    imply about a type the answer did not speak for (RFC 10029 section 3.5). So the extra
    records print, and the unanswered types print nothing at all: no line is their honest
    short form, and the ledger of why is what the non-short mode is for.
    """
    if response is None and bundle is None:
        return ""
    answers = [] if response is None else list(response.answers)
    lines = [_format_rdata(r) for r in answers]
    if bundle is not None:
        # Only the records of a separate lookup are new to the reader. A combined type's
        # records are Answer rows of the response just printed -- section 3.4 puts them
        # there -- so appending them again would show the same line twice, and filtering on
        # provenance rather than on identity is what keeps the two cases apart when a
        # re-asked type happens to return records equal to ones already in the packet.
        lines.extend(
            _format_rdata(r) for entry in bundle.types if entry.separate for r in entry.records
        )
    return "\n".join(lines)


def _normalize_dig_plus_args(argv):
    """Translate dig-style `+option` tokens to `--option` so argparse can read them."""
    out = []
    for tok in argv:
        if tok.startswith("+") and len(tok) > 1:
            out.append("--" + tok[1:])
        else:
            out.append(tok)
    return out


def build_parser():
    # prog is namespy, matching the console-script name, because that is what a
    # user actually typed when they see this text; the import name stays namespy
    # for compatibility, so the examples show both entry points.
    p = argparse.ArgumentParser(
        prog="namespy",
        description="Namespy: a dig-style CLI for the recursive resolver, plus a demo server mode.",
        epilog="Examples:\n"
        "  namespy example.com\n"
        "  namespy example.com MX\n"
        "  namespy +short example.com\n"
        "  namespy +trace example.com A\n"
        "  namespy --serve\n"
        "  python -m namespy example.com   (same thing, without installing)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("name", nargs="?", help="domain name to resolve (presentation form)")
    p.add_argument(
        "type",
        nargs="?",
        type=_parse_qtype,
        default=DnsQType.A,
        help="record type (A, AAAA, NS, MX, TXT, CNAME, SOA, ANY, ...). Default: A",
    )
    p.add_argument(
        "qclass",
        nargs="?",
        type=_parse_qclass,
        default=DnsQClass.IN,
        metavar="class",
        help="record class (IN, CH, HS). Default: IN",
    )
    p.add_argument(
        "--serve",
        action="store_true",
        help="run the demo server (binds 127.0.0.1:53) instead of doing a one-shot lookup",
    )
    p.add_argument(
        "--short",
        action="store_true",
        help="dig +short style: print only RDATA, one record per line",
    )
    p.add_argument(
        "--trace", action="store_true", help="write the resolution trace to last_resolution.md"
    )
    p.add_argument(
        "--trace-file",
        default="last_resolution.md",
        help="path for --trace output (default: last_resolution.md)",
    )
    p.add_argument(
        "--root-hints",
        default=None,
        help="path to a root hints zone file (default: the copy packaged "
        "with Namespy; refresh it with refresh_root_hints())",
    )
    p.add_argument(
        "--dns-suffix",
        default=None,
        help="DNS suffix the resolver assumes for relative names "
        "(names without a trailing root terminator). A "
        "trailing '.' on the supplied name disables suffix "
        "application.",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=LOOKUP_TIMEOUT_S,
        help="overall lookup timeout in seconds (default: %(default)s)",
    )
    p.add_argument(
        "--no-edns",
        action="store_true",
        help="do not advertise EDNS(0) on outbound queries; caps answers at "
        "512 octets and forces TCP for anything larger (RFC 6891)",
    )
    p.add_argument(
        "--nsid",
        action="store_true",
        help="ask every server to identify itself (RFC 5001 NSID); each answer "
        "that carries an identifier is printed as ';; NSID <addr> <hex>'. "
        "Silence is normal -- a server that does not implement the option, or "
        "declines to say, simply omits it",
    )
    p.add_argument(
        "--advertise-nsid",
        default=None,
        metavar="NSID",
        help="with --serve: the identifier (RFC 5001) to send back to a client "
        "that asks for one. Never sent unasked, so this advertises nothing to "
        "a server nobody is probing -- it is how an anycast instance says "
        "which machine it is",
    )
    p.add_argument(
        "--max-qtypes",
        dest="max_qtypes",
        type=int,
        default=MQTYPE_RECOMMENDED_QTX_LIMIT,
        metavar="N",
        help="with --serve: how many extra QTYPEs (RFC 10029) one query may have "
        "combined into its answer -- the limit section 4 asks operators to keep, and "
        "the figure it calls appropriate for public DNS. Zero supports the option "
        "without ever buying a second lookup: the MQTYPE-Response still goes out, "
        "empty, which is what 'this is understood and nothing was combined' sounds "
        "like, and silence is what 'not implemented' sounds like",
    )
    p.add_argument(
        "--qname-min",
        action="store_true",
        help="QNAME minimisation: downline servers get progressively deeper "
        "children instead of the full name (RFC 9156); more queries, less "
        "exposure -- --trace marks the probes",
    )
    p.add_argument(
        "--mqtype",
        action="append",
        type=_parse_qtype,
        metavar="TYPE",
        help="ask for one more record type inside the same walk with an MQTYPE-Query EDNS "
        "option (RFC 10029); repeatable. 'namespy example.org A --mqtype AAAA --mqtype "
        "HTTPS' is one descent from the root instead of three. A server that does not "
        "implement it answers the primary question as usual and the extras are then "
        "looked up separately, so this can only ever save round trips, never cost an "
        "answer. The primary type must be a data type (section 3.3): a bundle cannot "
        "ride behind ANY.",
    )
    p.add_argument(
        "--no-failure-cache",
        dest="no_failure_cache",
        action="store_true",
        help="do not remember resolution failures (RFC 9520 off): keep asking a "
        "zone that has stopped answering, once per query, for as long as it stays "
        "dead. The default refuses a repeat query for up to five minutes so a dead "
        "zone does not cost a fresh walk from the root each time -- right for "
        "serving, wrong for watching a zone fail, and wrong for anything that "
        "needs to see the retries",
    )
    p.add_argument(
        "--allow-out-of-bailiwick-glue",
        dest="allow_out_of_bailiwick_glue",
        action="store_true",
        help="DIAGNOSTICS ONLY: believe glue for a nameserver outside the zone "
        "that referred us, instead of refusing it (RFC 5452 section 6 off). "
        "Emits a warning at startup and a --trace line per address believed; "
        "an answer obtained this way may have been steered by whoever "
        "delegated. Never for a lookup you care about.",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="enable INFO-level logging")
    p.add_argument("--debug", action="store_true", help="enable DEBUG-level logging")
    return p


def _failure_cache(args):
    """``False`` if asked not to remember failures, else ``None`` for the default.

    The distinction matters: to the resolver, ``None`` means "own me a cache" and
    ``False`` means "do not remember anything" (RFC 9520 section 3.2 off).
    """
    return False if args.no_failure_cache else None


def _glue_policy(args) -> GluePolicy:
    """Translate the diagnostics flag into a policy -- and say so out loud.

    The banner goes to stderr rather than only into the log because what this
    switch produces is an answer that may have been steered by whoever delegated,
    and an answer printed with no such warning beside it is an answer somebody
    will quote. Stderr keeps that from disturbing a script parsing stdout: the
    bytes on stdout are the same either way, and ``2>/dev/null`` is the deliberate
    way to have it quiet.
    """
    if not getattr(args, "allow_out_of_bailiwick_glue", False):
        return GluePolicy.STRICT
    print(
        "namespy: out-of-bailiwick glue will be BELIEVED (RFC 5452 section 6 "
        "filtering off) -- diagnostics only, never for a lookup you rely on",
        file=sys.stderr,
    )
    return GluePolicy.PERMISSIVE


def _outbound_options(args) -> tuple:
    """The EDNS(0) options to put on every query this run sends.

    One option is selectable from the command line, and asking for it is free:
    RFC 6891 section 6.1.2 requires that "any OPTION-CODE values not understood
    by a responder or requestor MUST be ignored", so a server that never
    implemented NSID answers a query carrying it exactly as it would have
    answered one without it. So this flag cannot lose you an answer; the worst it
    can do is teach you nothing.
    """
    return (nsid_option(),) if getattr(args, "nsid", False) else ()


def _bundle_qtypes(args) -> tuple:
    """The types ``--mqtype`` asked for, minus any run in which they cannot travel.

    Two conditions make the flag a no-op before it reaches the resolver, and both are
    announced rather than left to the user's imagination. ``--no-edns`` removes the only
    carriage an EDNS(0) option has: RFC 10029 section 3.3 puts the list in an MQTYPE-Query
    option, which lives in an OPT record. A non-data primary -- ANY, AXFR, a SIG(0)
    pseudo-type -- is the case a server is *required* to answer FORMERR once a bundle
    rides with it (section 3.3 again), so refusing here saves an exchange that was over
    before it started, and points at what a bundle is for instead of rediscovering the
    rule off a stranger's error code.

    What is wrong with the list itself -- a repeat, a Meta-RR posing as a data type, a value
    no 16-bit field can hold -- stays the resolver's business:
    :func:`~namespy.bundle.query_option_for` is where those section 3.3 limits live, and
    :func:`cli_query` turns its ``ValueError`` into a message.
    """
    asked = tuple(int(qtype) for qtype in getattr(args, "mqtype", None) or ())
    if not asked:
        return ()
    if not is_data_rrtype(int(args.type)):
        print(
            f";; --mqtype ignored: a bundle behind a {type_name_of(args.type)} question must "
            "be answered FORMERR (RFC 10029 section 3.3). Ask for a data type instead.",
            file=sys.stderr,
        )
        return ()
    if getattr(args, "no_edns", False):
        print(
            ";; --mqtype ignored: EDNS(0) is off, and an MQTYPE-Query option has no other "
            "way to travel (RFC 10029 section 3.3). Drop --no-edns to bundle.",
            file=sys.stderr,
        )
        return ()
    return asked


def _format_bundle(bundle) -> str:
    """What the bundle makes of each type ``--mqtype`` asked for, as comment lines.

    Not where the records are: a server that combined them put those RRsets "into the same
    sections in which they would have appeared in a standalone query" -- RFC 10029 section
    3.4 -- which for a data answer means the Answer section the block above has already
    printed. What that section cannot show is the mapping, namely which record answered which
    of several questions, and which questions this answer leaves open. The latter is written
    as unanswered and never as empty: section 3.5 gives four reasons a requested QTx may be
    absent from the MQTYPE-Response, of which "the server was unwilling to process the
    request" and "the response size limit would be exceeded" are two, so a line reading "0
    records" would state a verdict the protocol refuses to license -- and caching that verdict
    is the exact failure this whole feature has to get wrong before it breaks the DNS.

    Each line also says how the type was answered, and on today's Internet that is the more
    informative half. The overwhelmingly common case is a server that has never seen option
    20: its reply leaves every requested type to a query of its own. Call those "combined"
    and this tool tells a lie about a stranger's capabilities -- and hides the records, which
    are not in the packet the Answer section above was drawn from, and which the user
    therefore asked for and did not receive.
    """
    lines = ["", ";; MQTYPE SECTION:"]
    if bundle.void:
        lines.append(f";; answer void and re-asked without the bundle: {bundle.reason}")
    elif not bundle.supported:
        lines.append(";; no MQTYPE-Response option: no server combined these types")
    for entry in bundle.types:
        name = type_name_of(entry.qtype)
        if entry.state is BundleState.NEEDED:
            lines.append(f";;\t{name}: not answered; nothing is known about it either way")
            continue
        origin = "asked separately" if entry.separate else "combined here"
        if entry.state is BundleState.COMBINED:
            verdict = f"{len(entry.records)} record(s)"
        elif entry.state is BundleState.NODATA:
            verdict = "NODATA: this name exists and has no records of this type"
        else:
            verdict = "NXDOMAIN: this name does not exist"
        lines.append(f";;\t{name}: {origin}: {verdict}")
        # A separate query's records are printed, because otherwise the line above would
        # promise an answer and the reader would find no trace of it. They are prefixed with
        # ';' the way the QUESTION section's rows are, because they are answers the caller
        # asked for that this response never carried: setting them out as Answer rows would
        # report that the server combined them, which is precisely what the exchange
        # established it had not done.
        if entry.separate:
            lines.extend(f";{_format_record_row(r)}" for r in entry.records)
    return "\n".join(lines)


def _report_server_ids(resolver) -> None:
    """Print the identifiers the servers handed back, one line each.

    Hex, two digits per octet, because RFC 5001 section 2.4 requires a user
    interface to "read and write the contents of the NSID option as a sequence
    of hexadecimal digits" -- the payload is opaque, and any prettier rendering
    would be an interpretation nobody authorised.

    Stderr, not stdout: ``--short`` promises RDATA and nothing else, and server
    metadata arriving between records would break a script parsing an answer.
    Saying so once when nothing came back is deliberate -- silence from this
    function is indistinguishable from a flag that never took effect.
    """
    identities = resolver.server_ids
    if not identities:
        print(";; no server identified itself (RFC 5001 NSID)", file=sys.stderr)
        return
    for address in sorted(identities):
        print(f";; NSID {address} {nsid_presentation(identities[address])}", file=sys.stderr)


async def cli_query(args) -> int:
    loop = asyncio.get_running_loop()
    qname = DomainName(args.name)
    # Decided before the resolver is built, because it decides what the resolver sends on
    # every hop rather than on one: an empty tuple here means the walk below never carries
    # an MQTYPE-Query option and no server is asked to do anything new.
    asked = _bundle_qtypes(args)

    _transport, resolver_protocol = await loop.create_datagram_endpoint(
        lambda: RecursiveResolver(
            root_hints_path=args.root_hints,
            dns_suffix=args.dns_suffix,
            edns_payload_size=0 if args.no_edns else EDNS_PAYLOAD_SIZE,
            edns_options=_outbound_options(args),
            qname_min=args.qname_min,
            glue_policy=_glue_policy(args),
            failure_cache=_failure_cache(args),
        ),
        local_addr=("0.0.0.0", 0),
    )
    try:
        question = DnsQuestion(qname, args.type, args.qclass)
        query = Query(questions=[question], RD=True)
        start = time.monotonic()
        try:
            if asked:
                bundle = await asyncio.wait_for(
                    resolver_protocol.resolve_bundle(query, asked),
                    timeout=args.timeout,
                )
            else:
                # An ordinary lookup goes through the ordinary door. resolve_bundle() with
                # an empty list is defined to be this same walk, but routing every lookup
                # through it would quietly make the new method part of what a Resolver has
                # to provide -- including the ones this project did not write.
                answer = await asyncio.wait_for(
                    resolver_protocol.resolve(query),
                    timeout=args.timeout,
                )
                bundle = BundleResult(supported=False, primary=answer)
        except TimeoutError:
            print(f";; query timed out after {args.timeout:.1f} s", file=sys.stderr)
            return 2
        except ValueError as exc:
            # A list RFC 10029 section 3.3 will not carry: a repeat of the primary's own
            # type, a Meta-RR posing as a data type, a value no 16-bit field can hold.
            # Usage errors are said, not raised -- the walk that would have followed is not
            # worth starting, and a traceback is not what a rejected argument means.
            print(f";; --mqtype: {exc}", file=sys.stderr)
            return 2
        elapsed_ms = (time.monotonic() - start) * 1000.0
        response = bundle.primary

        if bundle.void:
            # Loudly, and on stderr where it cannot corrupt an answer: a server that
            # answered a bundle invalidly has been told to stop by section 3.5, and the
            # operator is the only one who can tell the rest of the world about it.
            print(f";; warning: {bundle.reason}", file=sys.stderr)

        if args.short:
            text = _format_short(response, bundle if asked else None)
            if text:
                print(text)
        else:
            print(_format_response(response, args, elapsed_ms, bundle if asked else None))

        if args.trace:
            _dump_last_resolution_md(resolver_protocol, path=args.trace_file)

        if args.nsid:
            _report_server_ids(resolver_protocol)

        return 0 if response is not None else 2
    finally:
        _transport.close()
        # The endpoint transport is only half of it. The resolver opened a second
        # socket for AAAA glue, and that one belongs to nobody but itself.
        await resolver_protocol.aclose()


async def serve(args) -> int:
    resolver_protocol = None
    _resolver_transport = None
    _server_transport = None
    try:
        loop = asyncio.get_running_loop()

        _resolver_transport, resolver_protocol = await loop.create_datagram_endpoint(
            lambda: RecursiveResolver(
                root_hints_path=args.root_hints,
                dns_suffix=args.dns_suffix,
                edns_payload_size=0 if args.no_edns else EDNS_PAYLOAD_SIZE,
                edns_options=_outbound_options(args),
                qname_min=args.qname_min,
                glue_policy=_glue_policy(args),
                failure_cache=_failure_cache(args),
            ),
            local_addr=("0.0.0.0", 0),
        )
        logging.debug(
            "%s bound to: %s", resolver_protocol, _resolver_transport.get_extra_info("sockname")
        )

        _server_transport, _server_protocol = await loop.create_datagram_endpoint(
            lambda: DnsServer(
                resolver_protocol, nsid=args.advertise_nsid, max_qtypes=args.max_qtypes
            ),
            local_addr=("127.0.0.1", 53),
        )
        logging.debug(
            "%s bound to: %s", _server_protocol, _server_transport.get_extra_info("sockname")
        )

    except BaseException:
        traceback.print_exc()
        return 1
    else:
        logging.info(
            "Startup successful. Querying %s (A) through DnsServer %s ...", EXAMPLE_NAME, LOCAL_DNS
        )
        await _lookup_example_org_via_local_server(loop)
        if resolver_protocol is not None and args.trace:
            _dump_last_resolution_md(resolver_protocol, path=args.trace_file)
        logging.info("Press Ctrl+C to stop.")
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            return 0
        return 0
    finally:
        # This mode runs until someone stops it, which is exactly when an
        # unclosed socket stops being a detail: the two endpoint transports, plus
        # the resolver's private IPv6 one. Every way out of here -- bind failure,
        # Ctrl+C, something unexpected -- lets all three go.
        for transport in (_resolver_transport, _server_transport):
            if transport is not None:
                transport.close()
        if resolver_protocol is not None:
            await resolver_protocol.aclose()


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    argv = _normalize_dig_plus_args(argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    level = logging.WARNING
    if args.verbose:
        level = logging.INFO
    if args.debug:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")

    if args.serve:
        return asyncio.run(serve(args))
    if args.name is None:
        parser.error("name is required (or use --serve to run the demo server)")
    return asyncio.run(cli_query(args))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logging.info("Shutting down.")
        sys.exit(130)
