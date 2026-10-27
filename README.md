# aiodns (DNSpy)

An **asyncio-based DNS library and example server** from the DNSpy project: packet encode/decode, `DomainName` handling, and a work-in-progress recursive resolver wired through UDP `asyncio` protocols.

- **Python:** 3.12+ (see [`pyproject.toml`](pyproject.toml))
- **Style:** Ruff (lint + format), pytest for tests
- **Status:** experimental; the recursive resolver path is still rough, but the core parsing and the demo server are useful for learning and local experimentation

## References

- [RFC 1034](https://www.ietf.org/rfc/rfc1034.txt) — Domain names: concepts and facilities  
- [RFC 1035](https://www.ietf.org/rfc/rfc1035.txt) — Domain names: implementation and specification

## What’s in the box

| Area | Notes |
|------|--------|
| `aiodns/packet.py` | DNS message layout: questions, resource records, `Query` / `Response` |
| `aiodns/names.py` | `DomainName` wire encoding and parsing |
| `aiodns/resolver.py` | `RecursiveResolver` and related resolver logic (WIP) |
| `aiodns/server.py` | `DnsServer` datagram handler that forwards to the resolver |
| `aiodns/__main__.py` | Example: bind resolver + listener, run until Ctrl+C |

**Not supported (yet):** IDN / Punycode (`xn--` labels), full EDNS(0) behavior, and production-grade error handling. Treat this as a **lab** codebase, not a public resolver you expose to the internet.

## Install

From the repository root, using a virtual environment is recommended:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

The package metadata name is `aiodns-dnspy` (see `pyproject.toml`) to avoid clashing with other projects named `aiodns` on PyPI. The import name remains `aiodns`.

## Run the example server

The example binds:

- a **recursive resolver** UDP socket on `0.0.0.0:0` (ephemeral port), and  
- a **DNS listener** on `127.0.0.1:53`.

**Port 53** is a privileged port on many systems. On Windows you may need an elevated shell, or change the listen address/port in `aiodns/__main__.py` for local dev (e.g. `127.0.0.1`, high port like `5353`).

```powershell
python -m aiodns
```

On success you should see a log line about startup; the process then **runs until you press Ctrl+C**.

Root hints come from `named.root` **shipped inside the package** and loaded with
`importlib.resources`, so a fresh install resolves from the root servers with no
setup and no network fetch at construction time. To use your own copy, pass
`root_hints_path=` to `RecursiveResolver`; to pull a current version from
[Internic](https://www.internic.net/domain/named.root), `await
resolver.refresh_root_hints()`. Nothing reaches the network unless you await
that call — an earlier revision called `urlretrieve` inside `__init__`, with no
timeout, which made constructing a resolver an unbounded blocking operation.

## Tracing

`RecursiveResolver` records every iterative-resolution step into a `Trace`
(see [`aiodns/trace.py`](aiodns/trace.py)). The trace is exposed both on the
resolver (`resolver.last_trace`) and on the response object
(`response.trace`). Render any trace as a Mermaid `sequenceDiagram` with
`Trace.to_mermaid()`.

When you run `python -m aiodns` and the demo lookup completes, the most
recent trace is written to `last_resolution.md` in the current working
directory — open it in any Mermaid-aware viewer to see the zone-cut walk
and any glueless sub-resolutions.

For the RFC 1034 mapping that drives the resolver code, see
[`resolution.MD`](resolution.MD).

## Develop

```powershell
python -m ruff check .
python -m ruff format .
python -m pytest
python -m compileall aiodns
```

## Layout

```
aiodns/          # Library package
tests/           # Pytest
pyproject.toml   # Project metadata, Ruff, pytest
```

## History

This tree started as early Python 3 + asyncio code and was **modernized** (event-loop usage, packaging, tests, and bug fixes) while keeping the same general module layout. Older “WIP / master branch” notes in the previous README are superseded by the process above: check `git` history and this file for the current state.
