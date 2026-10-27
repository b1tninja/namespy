#!/usr/bin/env python3
# setcap cap_net_bind_service=+ep /usr/bin/python3.4  # for binding :53 on Linux

import argparse
import asyncio
import ipaddress
import logging
import sys
import time
import traceback

from .enums import DnsQType, DnsRClass, DnsRType
from .names import DomainName
from .packet import DnsPacket, DnsQuestion, Query
from .resolver import RecursiveResolver
from .server import DnsServer

LOCAL_DNS: tuple[str, int] = ("127.0.0.1", 53)
EXAMPLE_NAME = "example.org"
LOOKUP_TIMEOUT_S = 120.0


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
    s = str(token).upper()
    try:
        return DnsQType[s]
    except KeyError:
        pass
    try:
        return DnsQType(int(s))
    except (ValueError, KeyError):
        raise argparse.ArgumentTypeError("unknown record type: %s" % token) from None


def _parse_qclass(token):
    s = str(token).upper()
    try:
        return DnsRClass[s]
    except KeyError:
        pass
    try:
        return DnsRClass(int(s))
    except (ValueError, KeyError):
        raise argparse.ArgumentTypeError("unknown record class: %s" % token) from None


def _format_rdata(record):
    rdata = record.rdata
    rtype = record.rtype
    if hasattr(rdata, "ip"):
        return rdata.ip.compressed
    if isinstance(rdata, (bytes, bytearray)):
        b = bytes(rdata)
        if rtype == DnsRType.A and len(b) == 4:
            return ipaddress.IPv4Address(b).compressed
        if rtype == DnsRType.AAAA and len(b) == 16:
            return ipaddress.IPv6Address(b).compressed
        try:
            return b.decode("ascii")
        except UnicodeDecodeError:
            return b.hex()
    return str(rdata)


def _format_record_row(r):
    rclass = r.rclass.name if hasattr(r.rclass, "name") else str(r.rclass)
    rtype = r.rtype.name if hasattr(r.rtype, "name") else str(r.rtype)
    return "%s\t%d\t%s\t%s\t%s" % (r.name, r.ttl, rclass, rtype, _format_rdata(r))


def _format_response(response, args, elapsed_ms):
    """Render `Response` as a dig-style answer."""
    lines = []
    qtype_name = args.type.name if hasattr(args.type, "name") else str(args.type)
    qclass_name = args.qclass.name if hasattr(args.qclass, "name") else str(args.qclass)
    lines.append("; <<>> aiodns <<>> %s %s %s" % (args.name, qtype_name, qclass_name))
    if response is None:
        lines.append(";; no response")
        return "\n".join(lines)

    flags = []
    if response.QR == 1:
        flags.append("qr")
    if response.AA:
        flags.append("aa")
    if response.TC:
        flags.append("tc")
    if response.RD:
        flags.append("rd")
    if response.RA:
        flags.append("ra")

    lines.append(";; Got answer:")
    lines.append(
        ";; ->>HEADER<<- opcode: %s, status: %s, id: %d"
        % (
            response.OPCODE.name,
            response.RCODE.name,
            response.ID,
        )
    )
    lines.append(
        ";; flags: %s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d"
        % (
            " ".join(flags),
            response.QDCOUNT,
            response.ANCOUNT,
            response.NSCOUNT,
            response.ARCOUNT,
        )
    )
    lines.append("")

    if response.questions:
        lines.append(";; QUESTION SECTION:")
        for q in response.questions:
            qclass = q.qclass.name if hasattr(q.qclass, "name") else str(q.qclass)
            qtype = q.qtype.name if hasattr(q.qtype, "name") else str(q.qtype)
            lines.append(";%s\t\t%s\t%s" % (q.name, qclass, qtype))
        lines.append("")

    for label, section in (
        ("ANSWER", response.answers),
        ("AUTHORITY", response.nameservers),
        ("ADDITIONAL", response.additional_records),
    ):
        if section:
            lines.append(";; %s SECTION:" % label)
            for r in section:
                lines.append(_format_record_row(r))
            lines.append("")

    lines.append(";; Query time: %d msec" % int(elapsed_ms))
    lines.append(";; MSG SIZE  rcvd: %d" % len(bytes(response)))
    return "\n".join(lines)


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
    p = argparse.ArgumentParser(
        prog="aiodns",
        description="DNSpy: a dig-style CLI for the recursive resolver, plus a demo server mode.",
        epilog="Examples:\n"
        "  python -m aiodns example.com\n"
        "  python -m aiodns example.com MX\n"
        "  python -m aiodns +short example.com\n"
        "  python -m aiodns +trace example.com A\n"
        "  python -m aiodns --serve",
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
        default=DnsRClass.IN,
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
        default="named.root",
        help="path to the root hints zone file (default: named.root)",
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
            print(";; query timed out after %.1f s" % args.timeout, file=sys.stderr)
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
