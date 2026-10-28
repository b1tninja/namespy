#!/usr/bin/env python3
# setcap cap_net_bind_service=+ep /usr/bin/python3.4  # for binding :53 on Linux

import argparse
import asyncio
import logging
import sys
import time
import traceback

from .enums import (
    DnsOpCode,
    DnsQClass,
    DnsQR,
    DnsQType,
    DnsRClass,
    DnsResponseCode,
)
from .names import DomainName
from .packet import OPT_RTYPE, DnsPacket, DnsQuestion, Query
from .rdata import generic_presentation, type_name_of
from .resolver import RecursiveResolver
from .server import DnsServer

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
    day it is registered, not after DNSpy catches up.
    """
    s = str(token).upper()
    try:
        return DnsQType[s]
    except KeyError:
        pass
    return _parse_field(s, token, DnsQType, "record type")


def _parse_qclass(token):
    """Resolve a record class, mnemonic or number (see :func:`_parse_qtype`).

    Both paths return :class:`~aiodns.enums.DnsQClass`, the space of the question
    section's QCLASS field. Reaching for :class:`~aiodns.enums.DnsRClass` on the
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

    Goes through the codec's :meth:`~aiodns.rdata.RData.to_presentation` so that
    every type renders the way the wire format describes it: an address as an
    address, a name absolutely qualified, and an unknown type as RFC 3597
    section 5 ``\# <len> <hex>``. The alternative was decoding bytes as ASCII,
    which turned a binary RDATA into mojibake on the terminal -- and which a
    `ZONEMD` or `CSYNC` record hits routinely now that unknown types parse.

    ``record.rdata`` is always an :class:`~aiodns.rdata.RData`, so there is no
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


def _format_response(response, args, elapsed_ms):
    """Render *response* as a dig-style answer.

    Follows dig's section layout so existing muscle memory and log scrapers
    still work, with two deliberate additions: the EDNS(0) pseudo-section, since
    an OPT record is otherwise invisible while being exactly what determines the
    effective RCODE (RFC 6891 sections 6.1.2-6.1.3); and ``ad``/``cd`` flags,
    which live only in OPT and are the first thing an operator wants to see when
    comparing against a validating resolver.
    """
    lines = []
    lines.append(
        f"; <<>> dnspy <<>> {args.name} {type_name_of(args.type)} {DnsQClass.mnemonic(args.qclass)}"
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


def _format_short(response):
    if response is None:
        return ""
    return "\n".join(_format_rdata(r) for r in response.answers)


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
    # prog is dnspy, matching the console-script name, because that is what a
    # user actually typed when they see this text; the import name stays aiodns
    # for compatibility, so the examples show both entry points.
    p = argparse.ArgumentParser(
        prog="dnspy",
        description="DNSpy: a dig-style CLI for the recursive resolver, plus a demo server mode.",
        epilog="Examples:\n"
        "  dnspy example.com\n"
        "  dnspy example.com MX\n"
        "  dnspy +short example.com\n"
        "  dnspy +trace example.com A\n"
        "  dnspy --serve\n"
        "  python -m aiodns example.com   (same thing, without installing)",
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
        "with DNSpy; refresh it with refresh_root_hints())",
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
    p.add_argument("-v", "--verbose", action="store_true", help="enable INFO-level logging")
    p.add_argument("--debug", action="store_true", help="enable DEBUG-level logging")
    return p


async def cli_query(args) -> int:
    loop = asyncio.get_running_loop()
    qname = DomainName(args.name)

    _transport, resolver_protocol = await loop.create_datagram_endpoint(
        lambda: RecursiveResolver(
            root_hints_path=args.root_hints,
            dns_suffix=args.dns_suffix,
        ),
        local_addr=("0.0.0.0", 0),
    )
    try:
        question = DnsQuestion(qname, args.type, args.qclass)
        query = Query(questions=[question], RD=True)
        start = time.monotonic()
        try:
            response = await asyncio.wait_for(
                resolver_protocol.resolve(query),
                timeout=args.timeout,
            )
        except TimeoutError:
            print(f";; query timed out after {args.timeout:.1f} s", file=sys.stderr)
            return 2
        elapsed_ms = (time.monotonic() - start) * 1000.0

        if args.short:
            text = _format_short(response)
            if text:
                print(text)
        else:
            print(_format_response(response, args, elapsed_ms))

        if args.trace:
            _dump_last_resolution_md(resolver_protocol, path=args.trace_file)

        return 0 if response is not None else 2
    finally:
        _transport.close()


async def serve(args) -> int:
    resolver_protocol = None
    try:
        loop = asyncio.get_running_loop()

        _resolver_transport, resolver_protocol = await loop.create_datagram_endpoint(
            lambda: RecursiveResolver(
                root_hints_path=args.root_hints,
                dns_suffix=args.dns_suffix,
            ),
            local_addr=("0.0.0.0", 0),
        )
        logging.debug(
            "%s bound to: %s", resolver_protocol, _resolver_transport.get_extra_info("sockname")
        )

        _server_transport, _server_protocol = await loop.create_datagram_endpoint(
            lambda: DnsServer(resolver_protocol),
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
