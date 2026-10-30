"""The dig-style CLI: argument handling, rendering, and exit codes.

Nothing here touches the network. ``cli_query`` and ``serve`` build their
endpoints through ``loop.create_datagram_endpoint``, which is patched to hand
back the protocol the factory would have produced -- a real
:class:`~namespy.resolver.RecursiveResolver`, since constructing one reads the
packaged root hints and does no I/O -- with its ``resolve`` (and, for the
``--mqtype`` tests, its ``resolve_bundle``) replaced. That keeps the tests honest
about the wiring while leaving resolver behaviour to :mod:`tests.test_resolve_steps`.

Exit codes are the interface a script consumes: ``0`` answered, ``2`` no answer,
``1`` could not start.
"""

import argparse
import asyncio
import logging

import pytest

from namespy import __main__ as cli
from namespy.__main__ import (
    _bundle_qtypes,
    _dump_last_resolution_md,
    _format_bundle,
    _format_rdata,
    _format_record_row,
    _format_response,
    _format_short,
    _normalize_dig_plus_args,
    _parse_qclass,
    _parse_qtype,
    _report_server_ids,
    build_parser,
)
from namespy.bundle import BundledType, BundleResult, BundleState
from namespy.cache import FailureCache
from namespy.edns import extended_dns_error_option, nsid_option, serialize_options
from namespy.enums import DnsQClass, DnsQType, DnsRClass, DnsRType
from namespy.names import DomainName
from namespy.packet import DnsQuestion, DnsRecord, Response
from namespy.rdata import RData, RData_A, RData_AAAA, RData_NS, RData_TXT
from namespy.resolver import Done, GluePolicy, Sname
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


def _stub_endpoints(monkeypatch, resolve, resolve_bundle=None):
    """Route the CLI's endpoint creation to *resolve*, bypassing real sockets.

    Patched on the running loop instance rather than on its class, so a bug here
    cannot leak into another test that expects a real socket.

    *resolve_bundle* is patched only when a test asks for it, which is what keeps
    ``test_cli_query_prints_answer_and_exits_zero``'s assertion meaningful: a plain
    lookup must go through ``resolve``, not through the bundling door with an empty
    list -- otherwise merely having this feature in the tree would make the method
    mandatory for any resolver object, ours or anybody else's.
    """
    made = []

    async def fake_endpoint(factory, **_kwargs):
        protocol = factory()
        protocol.resolve = resolve
        if resolve_bundle is not None:
            protocol.resolve_bundle = resolve_bundle
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
    # OPT's TTL is EXTENDED-RCODE | VERSION over FLAGS | Z, so this says
    # "extended rcode 1" (BADVERS), version 0, with AD set -- a response no
    # 4-bit header could express on its own.
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


def _explained(*errors):
    """A perfectly good NOERROR answer whose OPT carries *errors* -- INFO-CODE and
    EXTRA-TEXT pairs -- so the printer is tested against a response that has not failed."""
    response = Response(
        ID=0x1234,
        QR=1,
        questions=[DnsQuestion(DomainName("example.com."), DnsQType.A)],
        answers=[DnsRecord("example.com.", DnsRType.A, rdata=RData_A("93.184.216.34"))],
    )
    response.add_edns(
        1232, options=[extended_dns_error_option(code, text) for code, text in errors]
    )
    return response


def test_an_explanation_is_printed_where_the_option_lives():
    """An Extended DNS Error is OPT RDATA, so dig's own layout puts its report beside
    the payload size rather than in a section of its own -- and this prints it under the
    pseudo-section because that is where a reader looking for EDNS matters will look."""
    text = _format_response(_explained((22, b"no reachable authority")), _args(["example.com"]), 3)

    assert "; EDNS: version: 0" in text
    assert "; EDE: 22 (No Reachable Authority): no reachable authority" in text


def test_an_explanation_is_printed_under_a_code_that_is_not_a_failure():
    """RFC 8914 section 3: "Receivers MUST be able to accept EDE codes and EXTRA-TEXT in
    all messages, including those with a NOERROR RCODE". The codes that make that sentence
    matter are 3 and 4, which travel with answers a resolver is perfectly entitled to use,
    so a printer that keyed on the status line would hide exactly the two codes worth
    reading -- a stale answer looks like a fresh one otherwise."""
    text = _format_response(_explained((3, b"")), _args(["example.com"]), 3)

    assert "status: NO_ERROR" in text
    assert "; EDE: 3 (Stale Answer)" in text


def test_more_than_one_explanation_is_printed_in_the_order_it_arrived():
    """Section 3: "Senders MAY include more than one EDE option and receivers MUST be
    able to accept (but not necessarily process or act on) multiple EDE options in a DNS
    message." Nothing ranks them for us and nothing licenses dropping one, so the printer
    keeps the sender's order and prints every option it was given."""
    text = _format_response(_explained((22, b""), (23, b"ns1: timeout")), _args(["example.com"]), 3)

    first, second = text.index("; EDE: 22"), text.index("; EDE: 23")
    assert first < second
    assert "; EDE: 23 (Network Error): ns1: timeout" in text


def test_an_unsafe_explanation_is_printed_escaped(capsys):
    """Section 6: the option is "unauthenticated information, unless secured by a form of
    secured DNS transaction", and "An attacker (e.g., a man in the middle (MITM) or
    malicious recursive server) could insert an extended error response into untrusted
    data" -- a sentence a program that writes to a terminal takes literally. The code is
    printed as the number it provably is; the text arrives escaped."""
    print(_format_response(_explained((22, b"\x1b[2Jcleared")), _args(["example.com"]), 3))

    out = capsys.readouterr().out
    assert "\\x1b[2Jcleared" in out, "shown as the octets they are"
    assert "\x1b" not in out, "never handed to the terminal to obey"


def test_a_malformed_explanation_costs_the_answer_nothing():
    """The printer's share of section 6's "MUST NOT alter DNS protocol processing": an OPT
    whose option length runs past the packet is a defect four octets wide, and the answer
    riding beside it is still an answer. It is not half-printed either -- a line that
    started with "; EDE:" and then stopped would report a code nobody sent."""
    response = _explained((22, b""))
    response.opt().rdata = b"\x00\x0f\x00\x0a\x00\x01"

    text = _format_response(response, _args(["example.com"]), 3)

    assert "93.184.216.34" in text
    assert "; EDE:" not in text


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


def test_the_diagnostics_glue_flag_defaults_to_off():
    """Nobody gets a resolver that believes volunteered glue by accident."""
    assert _args(["example.com"]).allow_out_of_bailiwick_glue is False


async def test_the_diagnostics_glue_flag_reaches_the_resolver(monkeypatch, capsys):
    """Parsed is not the same as wired: the policy has to arrive on the resolver.

    The flag's entire meaning is a resolver that adopts volunteered glue, so a
    regression here would be a measurement run that filtered as usual and reported
    exposure numbers it never measured. The banner is asserted in the same breath
    because an answer printed beside no such warning is an answer somebody will
    quote as though it were a normal lookup.
    """
    made = _stub_endpoints(monkeypatch, _answered)

    assert await cli.cli_query(_args(["--allow-out-of-bailiwick-glue", "example.com"])) == 0

    assert made[0][1].glue_policy is GluePolicy.PERMISSIVE
    assert "BELIEVED" in capsys.readouterr().err


async def test_a_plain_lookup_filters_glue_and_says_nothing_about_it(monkeypatch, capsys):
    """The default run must stay byte-for-byte boring -- stdout included."""
    made = _stub_endpoints(monkeypatch, _answered)

    assert await cli.cli_query(_args(["example.com"])) == 0

    assert made[0][1].glue_policy is GluePolicy.STRICT
    assert "BELIEVED" not in capsys.readouterr().err


def test_failure_caching_defaults_to_on():
    """RFC 9520 suppression is what a plain run does; switching it off is opt-in."""
    assert _args(["example.com"]).no_failure_cache is False


async def test_the_no_failure_cache_switch_reaches_the_resolver(monkeypatch):
    """A resolver built to watch a zone fail must be one that keeps asking it.

    The switch means "remember nothing", which the resolver spells ``False``;
    anything else in that slot means "own me a cache". A wiring mistake is
    therefore invisible from the command line -- the lookup behaves exactly as it
    did before the flag existed, and the operator concludes the zone is still
    refusing to answer when it is their own resolver that stopped asking.
    """
    made = _stub_endpoints(monkeypatch, _answered)
    assert await cli.cli_query(_args(["--no-failure-cache", "example.com"])) == 0
    assert made[0][1].failure_cache is None

    made = _stub_endpoints(monkeypatch, _answered)
    assert await cli.cli_query(_args(["example.com"])) == 0
    assert isinstance(made[0][1].failure_cache, FailureCache)


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


async def test_serve_closes_every_socket_on_the_way_out(monkeypatch):
    """Server mode runs until someone stops it, which is when leaks start to matter.

    Two endpoints are opened here, and the resolver keeps a third socket of its
    own. Nothing in asyncio closes any of them, so the ``finally`` in ``serve`` is
    the only thing standing between a demo server and a descriptor leak -- and the
    path exercised is the ordinary Ctrl+C one, not an exceptional one.
    """
    made = []

    async def idle_endpoint(factory, **_kwargs):
        transport = _FakeTransport()
        made.append(transport)
        return transport, factory()

    async def skip_demo(_loop):
        return None

    monkeypatch.setattr(
        asyncio.get_running_loop(), "create_datagram_endpoint", idle_endpoint, raising=False
    )
    monkeypatch.setattr(cli, "_lookup_example_org_via_local_server", skip_demo)

    task = asyncio.ensure_future(cli.serve(_args(["--serve"])))
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    task.cancel()
    assert await task == 0

    assert len(made) == 2, "resolver endpoint plus the server's own socket"
    assert [transport.closed for transport in made] == [True, True]


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


# ------------------------------------------------ asking servers to identify themselves
#
# RFC 5001 section 2.1 makes the request an NSID option carrying no payload,
# section 6.1 guarantees that a server which does not implement it "will provide a
# meaningless answer" rather than a broken one, and section 2.4 settles what a user
# interface may do with what comes back: it "MUST read and write the contents of the
# NSID option as a sequence of hexadecimal digits, two digits per payload octet".
# So the flag costs nothing on the way out and cannot lose an answer; the report on
# the way in is hex, on stderr, because stdout is the answer and ``--short``
# promises RDATA and nothing beside it.


def test_nothing_is_asked_of_the_servers_unless_the_operator_asks():
    assert () == cli._outbound_options(_args(["example.com"]))
    assert () == cli._outbound_options(_args(["--serve"]))


def test_the_nsid_flag_is_the_empty_option_rfc_5001_asks_for():
    assert (nsid_option(),) == cli._outbound_options(_args(["--nsid", "example.com"]))
    assert (nsid_option(),) == cli._outbound_options(_args(["--nsid", "--serve"]))


class _ServersThatAnswered:
    """Just the part of a resolver the report reads: who said what."""

    def __init__(self, identities):
        self.server_ids = identities


def test_server_identifiers_are_reported_as_hex(capsys):
    _report_server_ids(_ServersThatAnswered({"198.51.100.53": b"ns-a", "2001:db8::1": b"\x00\x01"}))

    err = capsys.readouterr().err
    assert ";; NSID 198.51.100.53 6e732d61\n" in err
    assert ";; NSID 2001:db8::1 0001\n" in err
    assert "ns-a" not in err, "section 2.4: two hex digits per octet, never the bytes"


def test_an_identifier_request_met_with_silence_says_so(capsys):
    """Silence here is the ordinary outcome -- section 6.1 expects it from every
    server that has not implemented the option -- so it cannot also be what a flag
    that never took effect looks like."""
    _report_server_ids(_ServersThatAnswered({}))
    assert "no server identified itself" in capsys.readouterr().err


async def test_the_nsid_flag_reaches_the_resolver_a_query_builds(monkeypatch, capsys):
    """Parsed is not wired. The endpoint factory hands back the real
    ``RecursiveResolver``, so this is the attribute an actual lookup would carry
    into every one of its queries."""
    made = _stub_endpoints(monkeypatch, _answered)

    assert await cli.cli_query(_args(["--nsid", "example.com"])) == 0

    assert (nsid_option(),) == made[0][1].edns_options
    assert "no server identified itself" in capsys.readouterr().err


async def test_a_plain_lookup_asks_nothing_and_reports_nothing(monkeypatch, capsys):
    """The default run must stay byte-for-byte boring, stderr included."""
    made = _stub_endpoints(monkeypatch, _answered)

    assert await cli.cli_query(_args(["example.com"])) == 0

    assert () == made[0][1].edns_options
    assert "NSID" not in capsys.readouterr().err


def _reply_naming_itself():
    """A response whose OPT carries an NSID payload, as an answering server sends."""
    return Response(
        ID=0x1234,
        QR=1,
        questions=[DnsQuestion(DomainName("example.com."), DnsQType.A)],
        additional_records=[
            DnsRecord(
                DomainName.root_label(),
                DnsRType.OPT,
                1232,
                0,
                rdata=serialize_options([nsid_option(b"ns-a")]),
            )
        ],
    )


async def test_an_identifier_a_server_handed_back_is_printed_by_the_lookup(monkeypatch, capsys):
    """The two ends of the feature in one run: the memo the resolver fills from an
    answer is the one the CLI reports, keyed by the address that answered."""

    async def answered_by_a_talking_server(_query):
        # Stand in for the reply path, which records the answer per server before
        # the CLI is ever handed it; the stubbed resolve skips that step.
        made[0][1]._note_server("198.51.100.53", _reply_naming_itself())
        return _response_with_opt()

    made = _stub_endpoints(monkeypatch, answered_by_a_talking_server)

    assert await cli.cli_query(_args(["--nsid", "example.com"])) == 0

    err = capsys.readouterr().err
    assert ";; NSID 198.51.100.53 6e732d61" in err


async def test_the_advertised_identifier_reaches_the_server_a_serve_builds(monkeypatch):
    """The server is the one that decides whether to answer a request -- RFC 5001
    section 2.2 forbids sending the identifier unasked -- so this is where the flag
    has to land."""
    made = []

    async def idle_endpoint(factory, **_kwargs):
        protocol = factory()
        made.append(protocol)
        return _FakeTransport(), protocol

    async def skip_demo(_loop):
        return None

    monkeypatch.setattr(
        asyncio.get_running_loop(), "create_datagram_endpoint", idle_endpoint, raising=False
    )
    monkeypatch.setattr(cli, "_lookup_example_org_via_local_server", skip_demo)

    task = asyncio.ensure_future(cli.serve(_args(["--serve", "--advertise-nsid", "ns-a"])))
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    task.cancel()
    assert await task == 0

    assert b"ns-a" == made[-1].nsid, "the resolver endpoint is created before the server's"


async def test_the_operational_qtype_limit_reaches_the_server_a_serve_builds(monkeypatch):
    """RFC 10029 section 4 asks implementors to let operators configure how many QTx
    values are processed, and ``DnsServer.max_qtypes`` is where that sentence lands --
    so a ``--serve`` that cannot say it is a server whose only answer is the default.

    The second round pins the default itself: a server started with no opinion still
    combines up to the four the document calls appropriate for public DNS, because the
    flag's absence means "no opinion", not "no combining".
    """
    made = []

    async def idle_endpoint(factory, **_kwargs):
        protocol = factory()
        made.append(protocol)
        return _FakeTransport(), protocol

    async def skip_demo(_loop):
        return None

    monkeypatch.setattr(
        asyncio.get_running_loop(), "create_datagram_endpoint", idle_endpoint, raising=False
    )
    monkeypatch.setattr(cli, "_lookup_example_org_via_local_server", skip_demo)

    for argv, limit in ((["--serve", "--max-qtypes", "2"], 2), (["--serve"], 4)):
        made.clear()
        task = asyncio.ensure_future(cli.serve(_args(argv)))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        task.cancel()
        assert await task == 0
        assert limit == made[-1].max_qtypes, "the resolver endpoint is created before the server's"


# ------------------------------------------------------------------------ --mqtype

AAAA_ROW = DnsRecord(
    "example.com", DnsRType.AAAA, rdata=RData_AAAA("2606:2800:220:1:248:1893:25c8:1946")
)
TXT_ROW = DnsRecord("example.com", DnsRType.TXT, rdata=RData_TXT(["bundled"]))


def _bundled(*argv):
    """The types ``--mqtype`` in *argv* actually asks the resolver for."""
    return _bundle_qtypes(_args(list(argv)))


def test_mqtype_is_repeatable_and_keeps_the_order_typed():
    """One flag, one type -- and the order survives, because it is the order the option
    carries on the wire and the order the report repeats. A parser that sorted or setified
    the list would be changing the bytes without asking."""
    args = _args(["example.org", "A", "--mqtype", "AAAA", "--mqtype", "HTTPS"])
    assert [int(q) for q in args.mqtype] == [int(DnsQType.AAAA), int(DnsQType.HTTPS)]


def test_a_plain_lookup_asks_for_no_bundle_at_all():
    """The default must be that nothing new is sent. Every server on the Internet receives
    the queries this tool sends, and an off-by-default is the only courteous setting for an
    extension they have not all seen."""
    assert _bundled("example.org") == ()


def test_a_bundle_cannot_ride_behind_a_question_with_no_answer_of_its_own(capsys):
    """RFC 10029 section 3.3 obliges a server to answer FORMERR when the primary question
    is not a data RRTYPE, so this exchange is finished before it starts. Refusing it here
    costs nothing and says what a bundle is for; sending it collects a stranger's error code
    and teaches the user nothing they could act on."""
    assert _bundled("example.org", "ANY", "--mqtype", "AAAA") == ()
    assert "section 3.3" in capsys.readouterr().err


def test_no_edns_leaves_the_list_nowhere_to_go(capsys):
    """An MQTYPE-Query is an EDNS(0) option: with --no-edns there is no OPT record to carry
    it (section 3.3). A flag that silently does nothing is worse than one refused out loud,
    because the user would conclude the servers do not support the extension."""
    assert _bundled("--no-edns", "example.org", "--mqtype", "AAAA") == ()
    assert "--mqtype ignored" in capsys.readouterr().err


def test_a_report_says_which_question_each_answer_belongs_to():
    """The records themselves are already in the Answer section -- section 3.1 put them
    there -- so the block's whole job is the mapping, which is the one thing a reader cannot
    recover from the packet: several RRsets travelling together, and no field saying which
    of them answered which question."""
    bundle = BundleResult(
        supported=True,
        primary=_response_with_opt(),
        combined=(int(DnsQType.AAAA),),
        types=(
            BundledType(
                int(DnsQType.AAAA), BundleState.COMBINED, records=(AAAA_ROW,), authoritative=True
            ),
        ),
    )
    text = _format_bundle(bundle)
    assert "AAAA" in text
    assert "1 record" in text


def test_an_unanswered_type_is_reported_as_unanswered_and_never_as_empty():
    """The interface's share of section 3.5, which lists four reasons a requested QTx may be
    absent from the MQTYPE-Response -- cache misses, flag mismatches, a server unwilling to
    do the work, a size limit -- and not one of them is "the name has no such records". "0
    records" would be a negative answer this protocol refuses to give, and the mistake a user
    would then make, believing the name has no AAAA, is the one this feature exists not to
    make."""
    bundle = BundleResult(
        supported=False,
        primary=_response_with_opt(),
        still_needed=(int(DnsQType.AAAA),),
        types=(BundledType(int(DnsQType.AAAA), BundleState.NEEDED),),
    )
    text = _format_bundle(bundle)
    assert "not answered" in text
    assert "0 record" not in text
    assert "NODATA" not in text, "unasked-for is not the same as not-there"


def test_a_void_answer_is_read_aloud_not_quietly_replaced():
    """Section 3.5 tells the client to throw the answer away, which the resolver does; it
    does not tell the operator that a server on the path broke the rules, and nobody else
    is going to say so. A server doing this is a server to report."""
    bundle = BundleResult(
        supported=True,
        primary=_response_with_opt(),
        void=True,
        reason="MQTYPE-Response option appeared twice",
    )
    assert "twice" in _format_bundle(bundle)


def test_short_output_prints_a_bundled_record_exactly_once():
    """A combined record is one of the Answer rows, so --short would print it twice if the
    harvest were appended blindly; a record from a separate lookup is genuinely new, and
    dropping it would leave the user holding one type out of the two they asked for."""
    response = _response_with_opt()
    response.answers.append(AAAA_ROW)
    from_bundle = BundleResult(
        supported=True,
        primary=response,
        types=(
            BundledType(
                int(DnsQType.AAAA), BundleState.COMBINED, records=(AAAA_ROW,), authoritative=True
            ),
        ),
    )
    assert _format_short(response, from_bundle).splitlines() == [
        "93.184.216.34",
        "2606:2800:220:1:248:1893:25c8:1946",
    ]

    from_elsewhere = BundleResult(
        supported=False,
        primary=response,
        types=(
            BundledType(
                int(DnsQType.TXT),
                BundleState.COMBINED,
                records=(TXT_ROW,),
                authoritative=True,
                response=object(),
                separate=True,
            ),
        ),
    )
    text = _format_short(response, from_elsewhere)
    assert text.count("2606:2800:220:1:248:1893:25c8:1946") == 1, "the Answer row, once"
    assert '"bundled"' in text, "and the record only a separate lookup found"


def test_an_answer_bought_separately_is_not_reported_as_combined():
    """What every lookup against today's authoritative servers actually looks like, and the
    rendering has to survive it: the server never saw option 20, so nothing was combined,
    and the AAAA and HTTPS the user asked for arrived in replies of their own -- absent from
    the Answer section this output has already printed. Call that "combined" and the tool
    invents support a stranger never offered; leave the records out and it looks as though
    the flag fetched nothing at all.

    (This is a bug this test was written to fix: the first version printed "combined: 2
    record(s) in the answer above" over an Answer section holding two A records.)
    """
    bundle = BundleResult(
        supported=False,
        primary=_response_with_opt(),
        types=(
            BundledType(
                int(DnsQType.AAAA),
                BundleState.COMBINED,
                records=(AAAA_ROW,),
                authoritative=True,
                response=object(),
                separate=True,
            ),
        ),
    )
    text = _format_bundle(bundle)
    assert "asked separately" in text
    assert "combined here" not in text, "the header says nobody combined; so must the rows"
    assert "2606:2800:220:1:248:1893:25c8:1946" in text, "and shown, not just counted"


async def test_the_bundle_flag_reaches_the_walk_that_sends_it(monkeypatch, capsys):
    """The one assertion that proves the flag is wired to something: the types typed are
    the types handed to the resolver, and the report appears in the answer."""
    seen = []

    async def bundled(_query, extra_qtypes):
        seen.append(tuple(extra_qtypes))
        return BundleResult(supported=True, primary=_response_with_opt())

    _stub_endpoints(monkeypatch, _answered, resolve_bundle=bundled)
    assert await cli.cli_query(_args(["example.org", "A", "--mqtype", "AAAA"])) == 0
    assert seen == [(int(DnsQType.AAAA),)]
    assert ";; MQTYPE SECTION:" in capsys.readouterr().out


async def test_a_list_the_protocol_will_not_carry_is_a_usage_error_not_a_crash(monkeypatch, capsys):
    """A repeat, a Meta-RR, a value outside the 16-bit field: the section 3.3 limits live in
    the resolver, and what
    reaches the user is the sentence, not the traceback -- the walk that would have followed
    is not worth starting, and an unhandled exception is not what a rejected argument means."""

    async def refused(_query, _extra_qtypes):
        raise ValueError("MQTYPE-Query repeats a QTx: 1")

    _stub_endpoints(monkeypatch, _answered, resolve_bundle=refused)
    assert await cli.cli_query(_args(["example.org", "A", "--mqtype", "AAAA"])) == 2
    assert "repeats a QTx" in capsys.readouterr().err


async def test_an_ordinary_lookup_keeps_the_output_it_always_had(monkeypatch, capsys):
    """No --mqtype, no mention of one. A feature nobody asked for must not change what a
    script parsing this output has been parsing all along."""
    _stub_endpoints(monkeypatch, _answered)
    assert await cli.cli_query(_args(["example.org"])) == 0
    assert "MQTYPE SECTION" not in capsys.readouterr().out
