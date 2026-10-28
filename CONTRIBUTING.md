# Contributing

## Getting set up

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Python 3.12 or newer. The library itself has **no runtime dependencies** — keep it
that way unless there is a strong argument, because a DNS stack that pulls in half
of PyPI is a DNS stack nobody will embed.

Check everything the way CI does:

```bash
pytest                                   # coverage floor enforced by pyproject
python -O -m pytest                      # assertions stripped — see below
ruff check . && ruff format --check .
mypy aiodns                              # blocking in CI; tightens per module
python -m build && python tools/check_dist.py dist/
```

## Two rules that are not negotiable

### 1. No `assert` on anything that came off the wire

`assert` disappears from the bytecode under `python -O` and `PYTHONOPTIMIZE`. In a
parser, that means the bounds check you wrote is not executed in somebody's
production environment. On a wire path, raise
`aiodns.wire.DnsPacketParseError` (or `DnsNameParseError`) with the datagram and
the offset:

```python
assert offset < len(buffer)  # ✗ stripped by -O
if offset >= len(buffer):  # ✓
    raise DnsPacketParseError("...", data=buffer, offset=offset)
```

`assert` remains correct for internal invariants and in tests — that is what
`S101` is ignored for in `pyproject.toml`.

Because this cannot be caught by reading diffs reliably, CI runs the **entire
suite under `python -O`**. A test that only passes with assertions enabled is a
test of a check that does not exist.

### 2. Protocol behaviour cites its source

Any line that implements, deviates from, or deliberately violates a specification
says so in the docstring or comment, in the form `RFC 9267 section 5`. Not the
title, the section. `docs/rfc-map.md` is the index: spec obligation → code
location → test. If you change behaviour that a document describes, update that
row in the same commit.

The reason is concrete. Reading a function that rejects a `10` two-bit label prefix
and wondering whether it is over-strict costs twenty minutes with the RFC and
indefinitely without it; the citation turns it into a two-minute check.

## Conventions worth knowing before you write code

**Tests assert `actual == expected`.** Ruff's `SIM300` wants the constant on the
left and reads an enum member as a constant, so it is ignored for `tests/*`.
Reordering them makes every failure message read backwards.

**Unknown protocol values stay `int`.** `DnsRType.parse(65)` returns an enum
member when the registry knows the value and a plain `int` when it does not, per
RFC 3597 section 3. Never reach for `.value` on something that came from `parse`;
use `int(...)` or `type_name_of(...)`. This is what the crash-on-`HTTPS`-record bug
was.

**RDATA serialises uncompressed.** `RData.to_wire()` must not emit a compression
pointer, because `cache/sqlite.py` stores `bytes(record)` and re-parses it in a
buffer where the original name offsets do not exist. A pointer there silently
resurrects a different name. The octets as received remain on `.wire` for dumps.

**Adding an RR type** takes three edits: a member in `enums.py`, a codec class in
`rdata.py` (registering itself via `RType`, so `__init_subclass__` picks it up),
and a test that round-trips it plus one that feeds it truncated. The opaque
fallback means forgetting the codec is not fatal — but it is silently lossy for
presentation, so add the codec.

## Committing

Direct commits to `master` are fine; this is a small repo and pull-request theatre
would slow it down. Write the commit body the way `git log` is written here: the
first line says *what* in the imperative, the body says *why* — including, for
fixes, the symptom someone would have observed. A commit that only says "fix bug"
is unsearchable the next time the same area needs work.

`CHANGELOG.md` follows Keep a Changelog; add a line under `Unreleased` when a
change is visible to a user of the library. Pure test or doc churn does not need
an entry.

## Running things

```bash
dnspy example.com                  # one-shot lookup via the packaged resolver
dnspy example.com --trace          # per-step RFC 1034 section 5.3.3 trace
dnspy --serve                      # loopback demo server, 127.0.0.1:53
```

`--serve` binds loopback on purpose. Do not turn it into something that listens
on a routable address — see `SECURITY.md`.
