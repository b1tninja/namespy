# namespy

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![CI](https://github.com/b1tninja/namespy/actions/workflows/ci.yml/badge.svg)
![Security](https://github.com/b1tninja/namespy/actions/workflows/security.yml/badge.svg)
<!-- PyPI badges go live with the first release; publishing is wired and the
     name is registered to this repo's trusted publisher at that moment. Until
     then a shields.io pypi badge would render "no version" on the landing page.
     Uncomment at the tag:
[![PyPI - Version](https://img.shields.io/pypi/v/namespy.svg)](https://pypi.org/project/namespy/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/namespy.svg)](https://pypi.org/project/namespy/)
-->

An asyncio DNS library: a wire codec that survives malformed input, an iterative
resolver that follows RFC 1034 section 5.3.3 literally, and a `dig`-flavoured
inspector. No runtime dependencies.

- **Python:** 3.12+ · **one name everywhere:** `pip install namespy`,
  `import namespy`, `namespy example.com`
- **Naming:** it used to be `aiodns` on import and `dnspy` on the command line.
  Both collided with unrelated projects — [`aiodns`](https://pypi.org/project/aiodns/)
  is an established asyncio resolver, and `dnspy` is an FQDN-manipulation library
  — so installing this would have shadowed one of them. One string now covers the
  distribution, the import and the console script, which is the only arrangement
  that cannot surprise anyone.
- **Status:** the codec, resolver and CLI are tested and usable, EDNS(0)
  included; there is no DNSSEC validation — see
  [What it does not do](#what-it-does-not-do)
- **Spec anchors:** [`docs/roadmap.md`](docs/roadmap.md) is the completeness
  matrix — every protocol obligation this code could take on, with an honest
  status and the test that pins it, and the roadmap the gaps consolidate
  into. [`docs/rfc-map.md`](docs/rfc-map.md) is the deep RFC 1034 §5.3.3
  walkthrough behind the resolver

## Install

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

Not published to PyPI yet, so install from the repository.

## Try it

```bash
namespy example.com                  # dig-style answer
namespy example.com AAAA
namespy example.com A --mqtype AAAA --mqtype HTTPS   # one walk, three types (RFC 10029)
namespy --short example.com MX       # or: namespy +short example.com MX
namespy example.com --trace          # write the resolution walk to last_resolution.md
namespy --serve                      # demo server on 127.0.0.1:53
```

`python -m namespy` does the same without installing the console script, and
`namespy --help` lists the rest (`--no-edns`, `--nsid`, `--mqtype`, `--root-hints`,
`--dns-suffix`, `--timeout`, `--trace-file`, `--qname-min`,
`--allow-out-of-bailiwick-glue`, `--no-failure-cache`, `-v`, `--debug`).

`--trace` output is a Mermaid `sequenceDiagram`, so GitHub renders it directly —
useful for seeing exactly where a zone cut was crossed and which NS forced a
glueless sub-resolution.

`--serve` binds loopback on purpose. It is a codec exercise, not a name server;
exposing a recursive resolver to a network you do not control turns it into an
amplification instrument (RFC 5358, RFC 9085). See [`SECURITY.md`](SECURITY.md).

Root hints ship inside the package and load through `importlib.resources`, so a
fresh checkout resolves from the root servers with no setup and no network access
at construction time. `await resolver.refresh_root_hints()` fetches a current
copy from [Internic](https://www.internic.net/domain/named.root) if you want one;
nothing else in the library contacts that URL.

## Use it as a library

`RecursiveResolver` is an `asyncio.Protocol`: it owns a datagram endpoint and you
await `resolve()`.

```python
import asyncio
from namespy import DnsQType, DnsQuestion, DomainName, Query, RecursiveResolver


async def main():
    loop = asyncio.get_running_loop()
    transport, resolver = await loop.create_datagram_endpoint(
        RecursiveResolver,
        local_addr=("0.0.0.0", 0),  # ephemeral source port, RFC 5452 section 9.2
    )
    try:
        query = Query(questions=[DnsQuestion(DomainName("example.com."), DnsQType.A)])
        response = await asyncio.wait_for(resolver.resolve(query), timeout=10)
        for record in response.answers:
            print(record.name, record.rtype, record.ttl, record.rdata)
        print(resolver.last_trace.to_mermaid())
    finally:
        # Both halves: the socket asyncio handed you, and the private IPv6 socket
        # the resolver opened for itself to fetch AAAA glue.
        transport.close()
        await resolver.aclose()


asyncio.run(main())
```

One walk can answer more than one type. `resolve_bundle` asks for the extras in an
MQTYPE-Query option (RFC 10029), and what a server did not combine comes back as work
rather than as a verdict:

```python
bundle = await resolver.resolve_bundle(query, (DnsQType.AAAA, DnsQType.HTTPS))
for entry in bundle.types:
    print(entry.qtype, entry.state.value, len(entry.records))
print(bundle.still_needed)  # empty unless a type stayed unanswered
```

An answer that contradicts itself (§3.5: a duplicated QTx, the option twice) voids the
bundle *and* the primary answer, is reported in `bundle.void` and `bundle.reason`, and is
never cached — silence about a type, on the other hand, only means nobody answered it.

The pieces are useful apart from the resolver. Decoding a capture needs neither a
resolver nor an event loop:

```python
from namespy import DnsPacket
from namespy.rdata import RData_SOA

packet, consumed = DnsPacket.parse(raw_datagram)
print(packet.ID, packet.RCODE, packet.extended_rcode, packet.TC, len(packet.answers))

soa = RData_SOA("ns1.example.com", "hostmaster.example.com", 2026102701, 7200, 3600, 1209600, 3600)
bytes(soa)  # pointer-free, so it is storable anywhere
RData_SOA.serial_ahead(1, 0xFFFFFFFF)  # True — RFC 1982 serial arithmetic
```

Anything the codec does not know about stays readable rather than raising: an
`HTTPS` (65) or `ZONEMD` (63) record decodes to an opaque `RData` and renders in
RFC 3597 section 5 form, `\# 24 00046400...`, which is what RFC 3597 section 3
asks a receiver to do with a type it has never heard of.

## What it does not do

Listing these is more useful than a promise of completeness, because three of
them change the security properties of anything built on top.

- **No DNSSEC validation.** The `AD` bit is read and exposed, but nothing
  verifies an RRSIG and there is no trust anchor (RFC 4033/4034/4035). Answers
  are unauthenticated: anyone who can deliver a well-formed response that matches
  the question — same source address, same ID, echoed question — is believed.
  `DNSKEY` and `DS` do decode now, key tag and DS digest included
  (`namespy/dnssec.py`; RFC 4034 §2, §5, Appendix B) — that is the half needing no
  cryptographic dependency. What is missing is RRSIG and the proof records
  (`NSEC`/`NSEC3`), the canonical-RRset rule they depend on, and the verification
  itself.
- **EDNS(0) options are partial: NSID, Extended DNS Errors and MQTYPE are put to
  use.**
  Outbound queries advertise a 1232-octet UDP payload (RFC 6891 §6.1.2, disable with
  `--no-edns` or the constructor knob), arriving OPT records yield `extended_rcode`,
  `ad`, `cd` and `requestor_payload_size`, and a FORMERR/BADVERS/NOTIMP answer
  *without* an OPT alongside it triggers the §6.2.2 unextended re-ask. Option TLVs
  (§6.1.2) are carried in both directions: `--nsid` asks each server the walk touches
  who it is and prints the answers as hex (RFC 5001 §2.4), and what a server advertises
  becomes the ceiling on the next query sent to it (§6.2.3, §6.2.4). Extended DNS Errors
  (RFC 8914) go both ways as well — the bundled server explains a failure it caused
  (22 behind a SERVFAIL that ran out of authoritative servers, 21 behind a NOTIMP), and
  a code that arrives is printed as `; EDE:` on any rcode (§3 requires a receiver to
  accept them beside a NOERROR too) and folded into the reason a cached failure
  remembers. It is never *acted on*: §6 says the content "MUST NOT alter DNS protocol
  processing" and calls it unauthenticated, so an attacker who can deliver a response
  can deliver an explanation with it. An upstream code is not forwarded to this
  resolver's own client, which §3 leaves to the implementation and this implementation
  declines. COOKIE (RFC 7873) and
  Padding (RFC 7830) encode and decode but are not yet *used*: there is no server-side
  cookie state to validate a reply against — the server only refuses a COOKIE whose
  length is impossible (§5.2.2) — and RFC 7830 §6 forbids padding over plaintext UDP,
  which is all this code sends today. MQTYPE (RFC 10029) is answered and, since this round,
  asked as well: both
  option codes compose and parse (`namespy/mqtype.py`), the bundled server refuses every
  malformed MQTYPE-Query §3.3 lists, and given a well-formed one it combines the extra
  QTYPEs into the answer and returns the §3.4 MQTYPE-Response naming exactly the
  types it folded in whole. An empty list beside a failure says "supported, nothing
  combined";
  silence stays the way a server that never heard of the extension looks, so a reply to
  every valid query carries the option even when it holds nothing. §4's operator knob is
  the server's `max_qtypes` — `--max-qtypes` on the demo server, four by default, which
  is the figure §4 calls appropriate for public DNS — and zero is the setting that
  answers the option without ever buying the extra lookups. A response that cannot carry
  one more type stops combining rather than truncating: §3.4's rule that a listed QTx is
  present in full outranks the wish to answer everything at once. Asking is `--mqtype TYPE`
  (repeatable), or `RecursiveResolver.resolve_bundle(packet, (AAAA, HTTPS))` from code: one
  descent answers all three, `namespy/bundle.py` reads what came back, and any type the
  answer did not combine gets its own query (§3.5) rather than a negative — §3.5's four
  reasons for leaving a QTx out are all about the server and none of them is "this name has
  no such records". A server that has never seen option 20 costs time and no answer; a
  server that answers a bundle invalidly has the whole reply discarded before any of it can
  reach the cache. The
  demo server answers an extended query
  with an OPT of its own — never a forwarded one, always its own payload size, and its
  identifier only if it was given one with `--advertise-nsid` and only if the
  query asked — and keeps §7's silence for a query that had none. Truncation is fully
  handled: a `TC` answer is re-asked over TCP instead of being believed
  (RFC 1123 §6.1.3.2).
- **No IDN or punycode.** Labels are octets end to end, which is what RFC 2181
  §11 requires of a implementation, but it means RFC 5890 A-labels must be
  encoded by the caller.
- **QNAME minimisation is opt-in** (`--qname-min`, `qname_min=True`). By
  default the full QNAME goes to every server on the way down, leaking the
  whole name to the root and TLD servers (RFC 9156 §4.1); with it on, each
  server sees only the labels the previous referral proved relevant, at the
  cost of more queries. `--trace` marks the probe queries, and budget
  exhaustion degrades back to full names rather than failing.
- **Failure caching is coarse, on purpose** (`FailureCache`, RFC 9520 §3.2). A name
  that just failed — or any name under a zone whose servers just stopped answering
  (§3.3) — is answered `SERVFAIL` for one second to five minutes without a query
  leaving the process, and a successful lookup clears what was remembered about the
  name and about every zone that spoke during it. What is *not* cached is an
  unresponsive server *address*, which §3.2 permits: within a lookup the Slist
  already cycles a zone's remaining servers, and across lookups an address key would
  retire one of a zone's several healthy servers for minutes over a single dropped
  datagram. `--no-failure-cache` (`failure_cache=False`) turns it off, which is what
  a resolver built to watch a zone fail needs — one that has stopped asking is, from
  outside, indistinguishable from one that is itself broken.
- **Bailiwick is enforced on glue only, and it is now observable.** A referral's
  address records are accepted for a nameserver name inside the answering zone or
  inside the zone it delegates (RFC 5452 §6, RFC 1034 §4.2.1); anything else is
  discarded and that server's address is resolved from its own authority instead.
  What a delegation volunteered used to vanish inside the classifier; it is now a
  `VolunteeredGlue` trace event, refused or believed. `GluePolicy.PERMISSIVE`
  (`--allow-out-of-bailiwick-glue`) makes the refused addresses take effect, which
  is how you measure the exposure rather than merely assert it — diagnostics only,
  and it says so at startup. Answers and negative assertions are still stored for
  the queried name only, so there is nothing else for a referral to smuggle.
- **Not a name server.** No zone storage, no serving of a zone, no AXFR/IXFR. The
  bundled `DnsServer` answers from the resolver for loopback testing.
- **UDP, with TCP only for truncation.** No DNS over TLS (RFC 7858), HTTPS
  (RFC 8484) or QUIC (RFC 9250), and no mDNS/DNS-SD (RFC 6762, RFC 6763).

Of these, the DNSSEC and EDNS entries are the ones worth re-reading before
you depend on this for anything that needs authenticity. The full
obligation-level picture, gap by gap, is
[`docs/roadmap.md`](docs/roadmap.md).

## Development

See [`CONTRIBUTING.md`](CONTRIBUTING.md). The short version — all four must pass.
The two pytest runs happen on Linux and Windows alike, because a socket option
that exists only on Linux is exactly the kind of bug a Linux-only CI never sees;
lint, typing and the distribution checks run once on Linux.

```bash
pytest -q --cov                          # coverage floor enforced by pyproject
python -O -m pytest -q                   # assertions stripped
ruff check . && ruff format --check .
mypy namespy
```

The second line is the one that matters most here: `python -O` strips `assert`,
and a parser whose bounds checks were `assert` stops being a parser under
production flags. The `--cov` on the first is not decoration either — pytest
reads `fail_under` through pytest-cov, and pytest-cov only runs when asked, so
`pytest -q` alone passes whatever it covers. Suite and policy details are in
`SECURITY.md`.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
