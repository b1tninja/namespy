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
namespy --short example.com MX       # or: namespy +short example.com MX
namespy example.com --trace          # write the resolution walk to last_resolution.md
namespy --serve                      # demo server on 127.0.0.1:53
```

`python -m namespy` does the same without installing the console script, and
`namespy --help` lists the rest (`--no-edns`, `--root-hints`, `--dns-suffix`,
`--timeout`, `--trace-file`, `-v`, `--debug`).

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
- **EDNS(0) is sent and understood, minimally.** Outbound queries advertise a
  1232-octet UDP payload (RFC 6891 §6.1.2, disable with `--no-edns` or the
  constructor knob), arriving OPT records yield `extended_rcode`, `ad`, `cd`
  and `requestor_payload_size`, and a FORMERR/BADVERS/NOTIMP answer triggers
  the §6.2.2 unextended re-ask. What is missing is *options*: no NSID,
  COOKIE or per-server payload adaptation yet, and the demo server does not
  echo OPT in its own responses (roadmap P1). Truncation is fully handled:
  a `TC` answer is re-asked over TCP instead of being believed
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
- **Bailiwick is enforced on glue only.** A referral's address records are accepted
  for a nameserver name inside the answering zone or inside the zone it delegates
  (RFC 5452 §6, RFC 1034 §4.2.1); anything else is discarded and that server's
  address is resolved from its own authority instead. Answers and negative
  assertions are stored for the queried name only — no other section is cached, so
  there is nothing else for a referral to smuggle.
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
pytest -q                              # coverage floor enforced by pyproject
python -O -m pytest -q                 # assertions stripped
ruff check . && ruff format --check .
mypy namespy
```

The second line is the one that matters most here: `python -O` strips `assert`,
and a parser whose bounds checks were `assert` stops being a parser under
production flags. Suite and policy details are in `SECURITY.md`.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
