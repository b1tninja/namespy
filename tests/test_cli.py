"""The dig-style CLI: argument handling, rendering, and exit codes.

Nothing here touches the network. ``cli_query`` and ``serve`` build their
endpoints through ``loop.create_datagram_endpoint``, which is patched to hand
back the protocol the factory would have produced -- a real
:class:`~namespy.resolver.RecursiveResolver`, since constructing one reads the
packaged root hints and does no I/O -- with its ``resolve`` replaced. That keeps
the tests honest about the wiring while leaving resolver behaviour to
:mod:`tests.test_resolve_steps`.

Exit codes are the interface a script consumes: ``0`` answered, ``2`` no answer,
``1`` could not start.
"""

import argparse
import asyncio
import logging

import pytest

from namespy import __main__ as cli
from namespy.__main__ import (
    _dump_last_resolution_md,
    _format_rdata,
    _format_record_row,
    _format_response,
    _format_short,
    _normalize_dig_plus_args,
    _parse_qclass,
    _parse_qtype,
    build_parser,
)
from namespy.enums import DnsQClass, DnsQType, DnsRClass, DnsRType
from namespy.names import DomainName
from namespy.packet import DnsQuestion, DnsRecord, Response
from namespy.rdata import RData, RData_A, RData_NS, RData_TXT
from namespy.resolver import Done, Sname
from namespy.trace import Trace


def _args(argv):
    """Parse *argv* the way ``main`` does, so ``+short`` means what it means there."""
    return build_parser().parse_args(_normalize_dig_plus_args(argv))


class _FakeTransport:
    """Reports being closed and owns no socket."""

    def __init__(self):
        self.closed = False

    def get_extra_info(self, key, default=None):
        return ("127.0.0.1", 5353) if key == "sockname" else default

    def close(self):
        self.closed = True


def _stub_endpoints(monkeypatch, resolve):
    """Route the CLI's endpoint creation to *resolve*, bypassing real sockets.

    Patched on the running loop instance rather than on its class, so a bug here
    cannot leak into another test that expects a real socket.
    """
    made = []

    async def fake_endpoint(factory, **_kwargs):
        protocol = factory()
        protocol.resolve = resolve
        transport = _FakeTransport()
        made.append((transport, protocol))
        return transport, protocol

    monkeypatch.setattr(
        asyncio.get_running_loop(), "create_datagram_endpoint", fake_endpoint, raising=False
    )
    return made


# ----------------------------------------------------------------- argument parsing


def test_qtype_accepts_mnemonic_and_number():
    assert _parse_qtype("A") is DnsQType.A
    assert _parse_qtype("aaaa") is DnsQType.AAAA
    assert _parse_qtype("255") is DnsQType.ANY


def test_qtype_accepts_a_number_with_no_mnemonic():
    # An unassigned type is still a legal thing to ask for (RFC 3597 section 3),
    # so the CLI must not gate questions on what this library happens to list.
    assert _parse_qtype("99") == 99
    assert _parse_qclass("65535") == 65535


@pytest.mark.parametrize("token", ["65536", "-1", "999999"])
def test_field_value_outside_the_wire_range_is_refused(token):
    # QTYPE/QCLASS are 16 bits; a larger value cannot be serialised, so it is
    # rejected here rather than silently truncated when the query is built.
    with pytest.raises(argparse.ArgumentTypeError, match="16-bit range"):
        _parse_qtype(token)
    with pytest.raises(argparse.ArgumentTypeError, match="16-bit range"):
        _parse_qclass(token)


def test_qclass_accepts_mnemonic_and_number():
    # Both spellings must land in the same constant space, or the return type
    # depends on how the user happened to write it.
    assert _parse_qclass("IN") is DnsQClass.IN
    assert _parse_qclass("1") is DnsQClass.IN
    assert _parse_qclass("3") is DnsQClass.CH
    assert _parse_qclass("255") is DnsQClass.ANY


def test_qtype_accepts_lowercase_mnemonic():
    # dig accepts either case, and so must this; the tables are uppercase.
    assert _parse_qtype("a") is DnsQType.A
    assert _parse_qclass("in") is DnsQClass.IN


@pytest.mark.parametrize("token", ["BOGUS", "TYPE1", "", "A B"])
def test_qtype_rejects_unknown(token):
    # A number is a value; a non-number that is not a mnemonic is a mistake, and
    # silently defaulting to A would ask a different question than was typed.
    with pytest.raises(argparse.ArgumentTypeError, match="unknown record type"):
        _parse_qtype(token)


def test_qclass_rejects_unknown():
    with pytest.raises(argparse.ArgumentTypeError, match="unknown record class"):
        _parse_qclass("NONSENSE")


def test_plus_tokens_become_long_options():
    assert _normalize_dig_plus_args(["+short", "example.com", "A"]) == [
        "--short",
        "example.com",
        "A",
    ]
    # A lone "+" is not an option; -v is already a real flag and passes through.
    assert _normalize_dig_plus_args(["+", "-v"]) == ["+", "-v"]


def test_parser_defaults():
    args = _args(["example.com"])
    assert args.name == "example.com"
    assert args.type is DnsQType.A
    assert args.qclass is DnsQClass.IN
    assert args.short is False
    assert args.serve is False


def test_parser_positional_order_matches_dig():
    args = _args(["example.com", "MX", "CH"])
    assert args.type is DnsQType.MX
    assert args.qclass is DnsQClass.CH


def test_parser_accepts_dig_style_flags():
    args = _args(["+short", "+trace", "example.org", "TXT"])
    assert args.short is True
    assert args.trace is True
    assert args.type is DnsQType.TXT


def test_missing_name_is_a_usage_error():
    with pytest.raises(SystemExit) as excinfo:
        cli.main([])
    assert excinfo.value.code == 2


# ------------------------------------------------------------------------ rendering


def test_rdata_renders_through_the_codec():
    assert _format_rdata(DnsRecord("h.", DnsRType.A, rdata=RData_A("10.0.0.1"))) == "10.0.0.1"
    assert (
        _format_rdata(DnsRecord("h.", DnsRType.NS, rdata=RData_NS("ns1.example.")))
        == "ns1.example."
    )
    txt = RData_TXT(["v=spf1 -all"])
    assert _format_rdata(DnsRecord("h.", DnsRType.TXT, rdata=txt)) == '"v=spf1 -all"'


def test_rdata_falls_back_to_rfc3597_for_unknown_types():
    # No ASCII decoding: 0xDE 0xAD is not text, and rendering it as such is how
    # binary RDATA used to reach the terminal as mojibake.
    record = DnsRecord("h", 65534, rdlength=4, rdata=RData(b"\xde\xad\xbe\xef"))
    assert _format_rdata(record) == r"\# 4 deadbeef"


def test_rdata_renders_raw_addresses_without_a_codec():
    v4 = DnsRecord("h", DnsRType.A, rdata=bytes.fromhex("7f000001"))
    v6 = DnsRecord("h", DnsRType.AAAA, rdata=bytes.fromhex("20010db8" + "00" * 12))
    assert _format_rdata(v4) == "127.0.0.1"
    assert _format_rdata(v6) == "2001:db8::"


def test_record_row_resolves_class_in_its_own_space():
    # Class 1 is IN while type 1 is A; reading the class column through the type
    # enum would print "A" where dig prints "IN".
    row = _format_record_row(DnsRecord("h.example.", DnsRType.A, DnsRClass.IN, 300, rdata=b""))
    assert row.split("\t") == ["h.example.", "300", "IN", "A", r"\# 0"]


def test_record_row_does_not_invent_a_root_terminator():
    # Every name in a message on the wire is absolute, so real rows always carry
    # the trailing dot. A record built with a relative name must still print as
    # relative: RFC 1035 section 5.1 makes an unterminated name mean "append the
    # $ORIGIN", and silently adding the dot here would misreport a relative name
    # as a fully-qualified one.
    relative = _format_record_row(DnsRecord("h.example", DnsRType.A, rdata=b"")).split("\t")[0]
    absolute = _format_record_row(DnsRecord("h.example.", DnsRType.A, rdata=b"")).split("\t")[0]
    assert relative == "h.example"
    assert absolute == "h.example."


def test_record_row_uses_class_mnemonic_for_unknown_classes():
    row = _format_record_row(DnsRecord("h", DnsRType.A, 65535, 0, rdata=b""))
    assert "CLASS65535" in row


def _response_with_opt():
    # OPT's TTL is EXTENDED-RCODE (8) | FLAGS (16) | reserved (8), so this says
    # "extended rcode 1" (BADVERS) with AD set -- a response no 4-bit header
    # could express on its own.
    opt = DnsRecord(
        DomainName.root_label(),
        DnsRType.OPT,
        1232,
        (0x01 << 24) | (1 << 15),
        rdata=b"",
    )
    return Response(
        ID=0x1234,
        QR=1,
        RD=True,
        RA=True,
        questions=[DnsQuestion(DomainName("example.com"), DnsQType.A, DnsRClass.IN)],
        answers=[DnsRecord("example.com", DnsRType.A, rdata=RData_A("93.184.216.34"))],
        additional_records=[opt],
    )


def test_response_renders_dig_sections():
    text = _format_response(_response_with_opt(), _args(["example.com"]), 12.9)
    assert "; <<>> namespy <<>> example.com A IN" in text
    assert ";; ->>HEADER<<- opcode: QUERY, status: BADVERS, id: 4660" in text
    assert "qr rd ra ad" in text
    assert ";; OPT PSEUDOSECTION:" in text
    assert "udpsize: 1232" in text
    assert ";; ANSWER SECTION:" in text
    assert "93.184.216.34" in text
    assert ";; Query time: 12 msec" in text
    assert ";; MSG SIZE  rcvd:" in text


def test_extended_rcode_is_not_truncated_to_the_header_field():
    response = _response_with_opt()
    assert response.extended_rcode == 16
    assert "status: 16" not in _format_response(response, _args(["example.com"]), 1)


def test_no_response_renders_as_dig_does():
    text = _format_response(None, _args(["example.com"]), 5)
    assert "example.com" in text
    assert ";; no response" in text


def test_short_format_is_rdata_only():
    assert _format_short(_response_with_opt()) == "93.184.216.34"
    assert _format_short(None) == ""


# ------------------------------------------------------------------- trace dumping


class _WithTrace:
    last_trace = Trace(DomainName("example.com"))


def test_trace_is_written_as_mermaid(tmp_path):
    path = tmp_path / "trace.md"
    _dump_last_resolution_md(_WithTrace(), path=str(path))
    body = path.read_text(encoding="utf-8")
    assert "```mermaid" in body
    assert "sequenceDiagram" in body


def test_trace_dump_without_a_trace_writes_nothing(tmp_path):
    path = tmp_path / "absent.md"
    _dump_last_resolution_md(object(), path=str(path))
    assert not path.exists()


def test_unwritable_trace_path_is_reported_not_raised(caplog):
    with caplog.at_level(logging.ERROR):
        _dump_last_resolution_md(_WithTrace(), path="/nonexistent-dir-xyz/out.md")
    assert any("Failed to write" in record.message for record in caplog.records)


# --------------------------------------------------------------------- command paths


async def _answered(_query):
    return _response_with_opt()


async def _nothing(_query):
    return None


async def test_cli_query_prints_answer_and_exits_zero(monkeypatch, capsys):
    made = _stub_endpoints(monkeypatch, _answered)
    assert await cli.cli_query(_args(["example.com"])) == 0
    assert ";; ANSWER SECTION:" in capsys.readouterr().out
    assert made, "the CLI never created its endpoint"
    assert made[0][1].resolve is _answered


async def test_cli_query_short_flag_prints_only_rdata(monkeypatch, capsys):
    _stub_endpoints(monkeypatch, _answered)
    assert await cli.cli_query(_args(["+short", "example.com"])) == 0
    assert capsys.readouterr().out.strip() == "93.184.216.34"


async def test_cli_query_reports_no_answer_as_two(monkeypatch, capsys):
    _stub_endpoints(monkeypatch, _nothing)
    assert await cli.cli_query(_args(["example.com"])) == 2
    assert ";; no response" in capsys.readouterr().out


async def test_cli_query_timeout_is_two_and_goes_to_stderr(monkeypatch, capsys):
    async def never_answers(_query):
        await asyncio.sleep(5)

    _stub_endpoints(monkeypatch, never_answers)
    args = _args(["example.com"])
    args.timeout = 0.01
    assert await cli.cli_query(args) == 2
    captured = capsys.readouterr()
    assert "timed out" in captured.err
    assert captured.out == ""


async def test_cli_query_closes_the_transport_it_opened(monkeypatch):
    made = _stub_endpoints(monkeypatch, _answered)
    await cli.cli_query(_args(["example.com"]))
    assert made[0][0].closed is True


async def test_cli_query_writes_the_trace_file(monkeypatch, tmp_path):
    # The real resolve() records the walk on the protocol before returning, which
    # is the only thing --trace has to write. The stub has to do the same, or this
    # test would pass while asserting nothing about the wiring it claims to cover.
    async def resolving(_query):
        response = await _answered(_query)
        trace = Trace(Sname(DomainName("example.com"), DnsQType.A, DnsRClass.IN))
        trace.record(Done(response))
        made[0][1].last_trace = trace
        return response

    made = _stub_endpoints(monkeypatch, resolving)
    target = tmp_path / "walk.md"
    args = _args(["+trace", "example.com"])
    args.trace_file = str(target)
    assert await cli.cli_query(args) == 0

    body = target.read_text(encoding="utf-8")
    assert "```mermaid" in body
    assert "sequenceDiagram" in body
    assert "done" in body


async def test_trace_flag_is_silent_without_tracing(monkeypatch, tmp_path):
    # --trace is opt-in: a plain lookup must not leave a file behind in the
    # caller's working directory.
    _stub_endpoints(monkeypatch, _answered)
    target = tmp_path / "should-not-exist.md"
    args = _args(["example.com"])
    args.trace_file = str(target)
    await cli.cli_query(args)
    assert not target.exists()


async def test_serve_reports_a_bind_failure_as_one(monkeypatch, capsys):
    async def refusing_endpoint(factory, **_kwargs):
        raise OSError(13, "permission denied")

    monkeypatch.setattr(
        asyncio.get_running_loop(), "create_datagram_endpoint", refusing_endpoint, raising=False
    )
    assert await cli.serve(_args(["--serve"])) == 1
    assert "permission denied" in capsys.readouterr().err


async def test_serve_runs_until_cancelled(monkeypatch, caplog):
    async def idle_endpoint(factory, **_kwargs):
        return _FakeTransport(), factory()

    async def skip_demo(_loop):
        return None

    monkeypatch.setattr(
        asyncio.get_running_loop(), "create_datagram_endpoint", idle_endpoint, raising=False
    )
    monkeypatch.setattr(cli, "_lookup_example_org_via_local_server", skip_demo)

    with caplog.at_level(logging.INFO):
        task = asyncio.ensure_future(cli.serve(_args(["--serve"])))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        task.cancel()
        assert await task == 0
    assert any("Press Ctrl+C" in record.message for record in caplog.records)


def test_main_routes_serve_to_the_server(monkeypatch):
    seen = {}

    async def fake_serve(args):
        seen["args"] = args
        return 7

    monkeypatch.setattr(cli, "serve", fake_serve)
    assert cli.main(["--serve"]) == 7
    assert seen["args"].serve is True


def test_main_routes_a_name_to_a_lookup(monkeypatch):
    seen = {}

    async def fake_cli_query(args):
        seen["args"] = args
        return 0

    monkeypatch.setattr(cli, "cli_query", fake_cli_query)
    assert cli.main(["example.com", "MX"]) == 0
    assert seen["args"].type.name == "MX"


@pytest.mark.parametrize(
    ("argv", "expected"),
    [([], logging.WARNING), (["-v"], logging.INFO), (["--debug"], logging.DEBUG)],
)
def test_main_sets_log_level_from_flags(monkeypatch, argv, expected):
    configured = {}

    def capture(**kwargs):
        configured.update(kwargs)

    async def fake_serve(_args):
        return 0

    monkeypatch.setattr(cli.logging, "basicConfig", capture)
    monkeypatch.setattr(cli, "serve", fake_serve)
    cli.main(["--serve", *argv])
    assert configured["level"] == expected
