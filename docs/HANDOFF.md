# Working handoff — library modernisation

A running document, not project documentation. Delete it when the remaining
phases below land. It exists so the work survives an interrupted session.

**Start here every time:**

```powershell
cd D:\code\DNSpy
git --no-pager log --oneline -8   # what has already landed
git status --short                # must be clean; if not, finish or commit it
```

## Status at time of writing

| | |
|---|---|
| Branch | `master`, pushed and in sync with `origin/master` |
| Commits in this effort | 10 (`fe1741e` … `3676c06`) |
| Suite | 265 passed, 0 failed, ~0.7s |
| Coverage | 81.2% (floor 80 in `pyproject.toml`) |
| Lint | `ruff check` clean over E,W,F,I,B,N,UP,SIM,C4,PT,RUF,S,RET,ARG; `ruff format --check` clean |
| Types | `mypy` advisory, 12 errors in 4 files (listed under "left to do") |
| CI | **none yet** — `.github/workflows` does not exist |
| License | **declared but absent** — `pyproject.toml` says Apache-2.0, there is no LICENSE file |

## Commands

```powershell
cd D:\code\DNSpy
.venv\Scripts\python.exe -m pip install -e ".[dev]"      # venv already exists
.venv\Scripts\python.exe -m pytest -q                    # suite
.venv\Scripts\python.exe -m pytest -q --cov=aiodns --cov-report=term
.venv\Scripts\python.exe -O -m pytest -q                 # see "the -O rule"
.venv\Scripts\python.exe -m ruff check .
.venv\Scripts\python.exe -m ruff format .
.venv\Scripts\python.exe -m mypy aiodns                  # advisory, not gating
.venv\Scripts\python.exe -m build                        # sdist + wheel
```

### Environment gotchas (each one cost time already)

- **PowerShell aborts on stderr.** `git push` and `git commit` write progress to
  stderr, which PowerShell surfaces as a NativeCommandError and which stops the
  pipeline *after* the command has actually succeeded — so it looks like a
  failure and the state has already changed. Wrap anything that writes stderr:
  `cmd /c "git push origin master > %TEMP%\out.txt 2>&1"`, then read the file.
  Never conclude a git operation failed from PowerShell's output alone; check
  `git rev-parse --short HEAD origin/master`.
- **Install with quotes**: `pip install -e ".[dev]"`. Unquoted, PowerShell eats
  the brackets.
- **`cmd /c` for redirection** when capturing tool output; `%TEMP%` expands
  there reliably, `$env:TEMP` interpolation inside a quoted string does not.
- **`Get-Content` misreads these files; it is not corruption.** Windows
  PowerShell 5.1 decodes BOM-less UTF-8 as ANSI, so an em-dash or an arrow in a
  comment renders as a three-character garble starting with an a-circumflex. The
  files are valid UTF-8 with no BOM. Confirm before "fixing":
  `pathlib.Path(p).read_text(encoding="utf-8")` succeeds, and at the byte level an
  em-dash is the sequence E2 80 94 rather than C3 A2. Editing against the console
  rendering is how mojibake gets *introduced* — this doc deliberately avoids
  quoting the garbled form, because doing so would make it trip its own test.
- **Never use `Set-Content` on source files** — it re-encodes and has already
  produced mojibake here. Use the file editor.

## Rules that must survive further edits

These are the decisions the code is built on. Reversing one silently undoes a
fix that has an RFC behind it.

1. **No `assert` on anything that came off the wire.** All validation raises
   `DnsPacketParseError` (defined once in `aiodns/wire.py`). The original bug set
   was that every bounds check was an `assert`, so `python -O` deleted the
   parser's entire defence. This is why `-O` is part of the definition of done:
   `pytest -O` must stay green.
2. **Serialization is canonical and compression-free.** `to_wire()` re-encodes
   full labels, never a pointer, because `cache/sqlite.py` stores `bytes(record)`
   and re-parses it standalone, where the original offsets no longer exist.
   Received octets stay available as `.wire` for hex dumps only.
3. **Unknown is not an error.** An unregistered RR type, class, or RCODE becomes
   a plain `int` (via `parse()` fallbacks) and opaque `RData`, never an exception
   — RFC 3597 §3. This is what stopped a single `HTTPS` record (type 65) from
   killing the listener.
4. **RDATA reads are bounded by RDLENGTH**, always passed down as `length`.
   Never slice twice (`data[o:][:n]` silently short-reads — that was a bug).
5. **Name comparison is case-insensitive and terminator-insensitive**, labels are
   arbitrary octets (RFC 2181 §11); LDH/hostname rules are an opt-in check
   (`is_hostname`), never a parse-time rejection, because `_dmarc`, `_svc._https`
   and `*` are all legal.
6. **Comments cite the section that obliges the code.** When changing behaviour,
   update or remove the citation; a stale RFC reference is worse than none.
7. **Coverage floor ratchets with the tests, never ahead of them** — a gate that
   fails on arrival gets ignored, and an ignored gate protects nothing.
8. **Lint exemptions stay scoped, never global.** Naming exceptions are
   per-file to `packet.py`/`rdata.py` because those identifiers mirror the wire
   format (`ID/QR/OPCODE/AA/TC/RD/RA/Z/RCODE/QDCOUNT`, `RData_SOA`). Adding a
   repo-wide ignore to make a new finding go away defeats the point of having
   enabled the rule.


## What is done

Everything since `3527bda` (the last pre-existing commit) — list them with
`git --no-pager log --oneline 3527bda..HEAD`, since this document adds one more.
All on `master` and pushed. Grouped below by the problem they solved rather than
by commit, because several spanned layers.

### Wire parsing is now a hostile-input boundary (`names.py`, `wire.py`, `packet.py`)

Original defects, all confirmed by reading the pre-change source and now
regression-tested in `tests/test_names_wire.py` / `tests/test_packet_wire.py`:

- The compression-pointer test was `if buffer[offset] & 0b11000000:`, which is
  literally the "broken implementation" example in **RFC 9267 §2**. Octets
  `0x40`–`0xBF` were misread as pointers. Now `(o & 0xC0) == 0xC0`, with the
  reserved `10`/`01` two-bit prefixes rejected.
- Pointers that point at pointers were rejected (`assert buffer[offset] < 64`
  after following a pointer), although a chain is legal wire form
  (**RFC 1035 §4.1.4**). Chains now follow, with a visited-set plus a strictly-
  decreasing-target rule so expansion cannot loop, and a total expanded-name
  limit of 255 octets *counting label-length octets*.
- Every bounds check was an `assert`; all are now `DnsPacketParseError`.
- Labels are arbitrary octets (**RFC 2181 §11**); the old LDH asserts rejected
  `_dmarc`, `_svc._https` and `*`. Presentation escaping is round-trip safe, and
  hostname rules moved to an opt-in `is_hostname`.
- `DnsPacketParseError` is defined once, in `wire.py`, and re-exported from
  `packet.py` — it used to exist twice, so a failure raised as one class escaped
  the `except` in `server.py` and `resolver.py`.
- `RDLENGTH` is checked against the message before slicing; the old
  `data[offset:][:rdlength]` double-slice short-reads instead of failing.

### Unknown RR types no longer crash (`rdata.py`, `enums.py`)

`DnsRType` stopped at 32769 and omitted **62 CSYNC, 63 ZONEMD, 64 SVCB,
65 HTTPS**, and the record parser reached for `rtype.value` on a plain `int` — so
one `HTTPS` record raised `AttributeError` inside a protocol callback, which
`server.py` did not catch. Now: codecs self-register via `__init_subclass__`,
anything unregistered becomes opaque `RData` with RFC 3597 §5 `\#` presentation,
and the enum tables carry the modern types plus extended RCODEs, pinned by
invariant tests in `tests/test_enums.py` (including QTYPE ⊇ RTYPE, which is what
stops the two tables drifting apart).

`SOA` was unserializable — `__init__` never set `.blob`, so `bytes(record)`
raised on any NODATA/NXDOMAIN answer — and had no `MINIMUM` field, which is the
negative-cache TTL **RFC 2308 §5.1** requires. Both fixed; serial comparison is
now RFC 1982 wrap-around arithmetic (`serial_ahead`), because a naive `>` breaks
when a zone crosses 2**31.

### Resolution semantics (`resolver.py`)

- `classify()` branched on `AA` first, so a non-AA `ANCOUNT==0, NSCOUNT>0` answer
  took the referral path. NODATA is now decided by SOA-vs-NS in the authority
  section regardless of `AA` (**RFC 2308 §2.2.1**).
- CNAME chains are followed by re-anchoring SNAME at the target with a chain
  limit, and DNAME redirection is synthesised (**RFC 1034 §5.3.3(b)**,
  **RFC 6672 §2.3**). Previously a CNAME only produced a trace event and the
  lookup terminated. Helpers `DomainName.from_labels` / `is_subdomain_of` exist
  because that synthesis needs raw-label composition. Tests:
  `tests/test_resolver_alias.py`.
- Responses are matched on the echoed question (QNAME/QTYPE/QCLASS) and source
  port, not just `(source_ip, query_ID)` — the old key made poisoning trivial for
  an off-path sender (**RFC 5452 §5**–**§6**). Tests:
  `tests/test_resolver_matching.py`.
- `ID` comes from `secrets.randbits`, not `random.getrandbits` (Mersenne Twister
  state is recoverable from observed outputs).
- Blocking `urllib.request.urlretrieve` of InterNIC `named.root` removed from
  `__init__`; hints load from the packaged file via `importlib.resources` with a
  timeout-bounded `urlopen` only when explicitly refreshed. `MAX_HOPS`,
  `MAX_DEPTH`, and per-attempt timeouts are constructor arguments now.

### Repo and packaging

Installable (`[build-system]` + hatchling, dynamic version read from the
package), `py.typed` shipped, console script `dnspy`, coverage floor 80 wired to
`--cov-fail-under`, mypy configured but advisory. Generated and legacy files
untracked (`last_resolution.md` ×2, the 2014-era `dns.sql`/`database.png` moved
to `docs/legacy/`), `.gitignore` reconciled with what is actually tracked.
`docs/rfc-map.md` maps each spec obligation to the module and test that
implements it — that file is the fastest way into this codebase.

### Where the coverage actually sits

| Module | Cover | Note |
|---|---|---|
| `wire.py` | 100% | |
| `server.py` | 98% | was 0% before this effort |
| `enums.py` | 98% | |
| `packet.py` | 95% | |
| `cache/*` | 89% | |
| `names.py` | 88% | escaping/presentation branches |
| `trace.py` | 86% | |
| `rdata.py` | 85% | defensive branches for malformed RDATA |
| `__main__.py` | 84% | |
| `resolver.py` | **67%** | the real sockets: `123-202`, `221-266`, `1632-1654`; root-hints fetch `1575-1619` |

## What is left, in priority order

1. **LICENSE — do this first.** `pyproject.toml` declares
   `license = "Apache-2.0"` and there is **no license file on disk**, no README
   mention, and `gh api repos/b1tninja/DNSpy` returns `license: null`. A declared
   license nobody granted is worse than an absent one. Write the Apache-2.0 text,
   make sure both sdist and wheel carry it (`license-files`), add a README
   section. While there: the keyword `dnssec-adjacent` reads as a capability
   claim and DNSSEC is not implemented — drop or rename it.

2. **CI — nothing exists.** `.github/workflows` is absent, so every guarantee
   above (265 tests, the `-O` rule, the 80% floor, `named.root` inside the wheel)
   currently survives only because someone remembers to run it. `ci.yml` on
   push/PR, matrix `{3.12, 3.13} × {ubuntu, windows}` — the Windows leg matters
   specifically because `IP_MTU_DISCOVER`/`IP_PMTUDISC_DO` are Linux-only and the
   `getattr`-based guard in `aiodns/__init__.py` is the only thing keeping the
   listener from dying there. Steps: `ruff check`, `ruff format --check`,
   `compileall`, `pytest` (coverage gate is already in `pyproject.toml`), then
   `pip install .` and assert `aiodns/named.root` is importable from the
   *installed* package. That last step is not decoration: hatchling derives
   default excludes from `.gitignore`, which ignores a working-tree
   `named.root`, so the `artifacts` line in `pyproject.toml` is the only thing
   shipping it — and only a build assertion notices if someone deletes it.
   `mypy` with `continue-on-error: true` while it stays advisory. Then
   dependabot (pip + actions), `dependency-review`, CodeQL, branch protection.

3. **Fuzzing — a promise not kept.** `hypothesis` is in the dev extras and **no
   test imports it**. The property worth buying, given where the effort went: for
   arbitrary bytes, `DnsPacket.parse(data)` and `DomainName.parse_from(data, off)`
   must either return or raise `DnsPacketParseError` — *never* another exception
   type. That one invariant is what keeps a `datagram_received` callback alive,
   and it is exactly the class of bug the hand-written corpus tests cannot
   exhaust. Plus round-trip: `parse(bytes(record)) == record` for generated
   records.

4. **TC → TCP retry.** Precisely described in `docs/rfc-map.md` §11 — the
   transport already exists, the third trigger (retry the same server because the
   answer came back truncated) does not. RFC 1035 §4.3.1, RFC 7766 §6.

5. **EDNS(0) is decoded but never sent.** `DnsPacket` has `opt()`,
   `extended_rcode`, `ad`, `cd`, `requestor_payload_size`, and the CLI renders the
   OPT pseudo-section the way `dig` does. Outbound queries carry no OPT, so the
   receive ceiling is still 512 octets and RCODEs are still 4-bit. Needs: an OPT
   with a UDP payload size on outbound queries, the §6.2.5 fallback when a server
   answers without OPT, and `server.py` answering EDNS-aware.

6. **Docs that are still missing outright:** `SECURITY.md` (the parser is the
   attack surface; state the no-open-resolver position; point at RFC 5358/BCP 140
   and RFC 5625), `CONTRIBUTING.md` (must state rules 1, 2 and 7 above or they
   will be reverted by the next contributor), `CHANGELOG.md`, issue/PR templates,
   and repo metadata via `gh repo edit` — description is set but `homepage` is
   null and `topics` is empty. Re-read `README.md` against the code rather than
   trusting it: the last false statement found in this repo was caught by exactly
   that check (commit `3676c06`).

7. **mypy — 12 errors, advisory, 4 files.** With the fix shape:
   - `enums.py` `call-arg`/`attr-defined` ×4: `_TypeMixin` precedes `IntEnum` in
     the MRO, so mypy cannot see `name` or the enum constructor through it.
     Type the mixin against `enum.IntEnum` (or use a `Protocol`) rather than
     ignoring.
   - `enums.py` `misc` ×4: a subclass overrides `_prefix`, declared `Final` in
     the base. Either drop `Final` or give each enum its own private name.
   - `names.py:170` `has-type`: inference cycle inside `__init__` — annotate the
     attribute explicitly.
   - `rdata.py:278` `assignment`: `RData_AAAA._ADDRESS_TYPE` narrows the base's
     `type[IPv4Address]`. Annotate the base as `ClassVar[type[ipaddress._BaseAddress]]`.
   - `resolver.py:919`, `1024` `arg-type`: `Answer(...)` is declared to take a
     `tuple` and is handed a `list` — widen the dataclass to `Sequence` or pass
     `tuple(...)`. Worth checking which is intended rather than coercing.

8. **`resolver.py` at 67%.** The uncovered lines are the real sockets — UDP
   `123-202`, TCP `221-266`, send `1632-1654` — plus the root-hints fetch
   `1575-1619`. These need a loopback tier (bind an ephemeral in-process UDP/TCP
   responder), not more unit tests. No marker set exists for that yet; add
   `markers = ["network: touches a real socket"]` and keep genuine internet tests
   opt-in so CI stays hermetic and cannot flake.

9. **Later, all spec-driven and none urgent:** serve-stale (RFC 8767), QNAME
   minimisation (RFC 9156), out-of-bailiwick NS checks (RFC 5625 §2.5, other
   direction), DNSSEC validation (RFC 4033/4034/4035).

## Suggested next session

1 → 2 → 3 is the sequence: a license before anyone is told the code is reusable,
CI so the existing 265 tests actually protect something overnight, then the fuzz
property that locks in the parser work. Then the two open correctness gaps (4, 5),
then the docs, then the type and coverage tail.

## Decisions already taken (do not relitigate)

- Commit directly to `master`; **no pull requests** — it is the owner's repo and
  nobody else uses it.
  nobody else uses it.
- License is **Apache-2.0**; **no PyPI publish** yet, so release automation stays
  tag-gated and dormant.
- The import name stays **`aiodns`** for now (the PyPI collision with the well-known
  `aiodns` is accepted; a `dnspy` alias was discussed and deliberately deferred).
