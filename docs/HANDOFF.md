# Working handoff — publish & post-publish work

A running document, not project documentation. It exists so the work survives
an interrupted session, and it is current as of the commit that last touched
it — check `git log --oneline -5 -- docs/HANDOFF.md` against `HEAD` if in
doubt.

**Start here every time:**

```powershell
cd D:\code\namespy
git --no-pager log --oneline -8   # what has already landed
git status --short                # must be clean; if not, finish or commit it
gh run list -L 5                  # what CI thinks about it
```

## Status

| | |
|---|---|
| Branch | `master`, pushed, in sync with `origin/master`, **branch-protected** (10 required checks, strict) |
| Suite | 415 passed, 0 failed; clean under `python -O` too (the pytest "assertions stripped" notice there is pytest talking about itself, not this code) |
| Coverage | floor 80 enforced in `pyproject.toml` |
| Features | codec, resolver, CLI, truncation/TCP, **EDNS(0) incl. §6.2.2 fallback** (`--no-edns` to disable) and **EDNS options** — NSID (`--nsid` / `--advertise-nsid`), COOKIE, Padding, per-server payload sizes; `tests/test_edns.py` pins it |
| Planning | [`docs/roadmap.md`](roadmap.md) is the completeness matrix and the roadmap — update the row in the same commit as any behaviour change it describes |
| Lint / types | `ruff check` + `ruff format --check` clean; `mypy namespy` exits 0 |
| CI | `ci.yml` (lint, 3.12/3.13 × Ubuntu/Windows, `-O` run, distribution audit), `security.yml` (CodeQL security-extended, dependency-review, pip-audit), `socket.yml` (Socket.dev firewall on installs) — all green on `master` |
| Release | `release.yml` wired end-to-end: tag → build → attest → trusted-publish to PyPI → GitHub Release. **One manual step away — see checklist below.** |
| License | Apache-2.0, `LICENSE` in tree, PEP 639 string metadata |
| PyPI name | `namespy` confirmed unregistered (HTTP 404 on pypi.org and test.pypi.org, 2026-10-28) — register it via Trusted Publisher, not by hand-uploading a wheel |

## The only remaining blocker: first release (manual, ~5 minutes)

GitHub side is done (the `pypi` environment exists, `release.yml` names it).
On python.org — needs a browser session with the PyPI account that will own
the project:

1. PyPI → Account settings → **Publish a project via Trusted Publishing**:
   project name `namespy`, repository `b1tninja/namespy`, workflow name
   `release.yml`, environment `pypi`. Do **not** upload a file first — the
   point is Trusted Publishing; no token exists or is stored anywhere.
2. Then locally: bump `namespy/__init__.py` `__version__` (it is the single
   source — hatchling reads it, and `release.yml` refuses a tag that
   disagrees with it), commit, `git tag v0.1.0`, `git push origin master v0.1.0`.
3. Watch `gh run list`; verify with `pip index versions namespy` and
   `gh attestation verify` against a downloaded artifact.
4. Uncomment the PyPI badges in `README.md`, flip `CHANGELOG.md` Unreleased →
   `## [0.1.0] - YYYY-MM-DD`, update the `SECURITY.md` "never been published"
   wording. Those edits are one commit.

Rehearsal without PyPI: `gh workflow run release.yml -f version=0.1.0` runs
build+attest+audit only (publish will fail on the missing trusted publisher,
which is the correct failure). **Done 2026-10-28, run 40640446010: build job
green (version gate, build, dist audit, SLSA attest, digest, artifact),
publish failed with PyPI's textbook `invalid-publisher: valid token, but no
corresponding publisher` — proof the OIDC half works and only the python.org
form above is missing.** TestPyPI has no trusted publishing; a dry run
there needs an API token in a separate environment — only worth it if step 1
is somehow blocked.

## Commands

```powershell
cd D:\code\namespy
.venv\Scripts\python.exe -m pip install -e ".[dev]"      # venv already exists
.venv\Scripts\python.exe -m pytest -q                    # suite
.venv\Scripts\python.exe -O -m pytest -q                 # see "the -O rule"
.venv\Scripts\python.exe -m ruff check .
.venv\Scripts\python.exe -m ruff format .
.venv\Scripts\python.exe -m mypy namespy                 # gating in CI
.venv\Scripts\python.exe -m build                        # sdist + wheel
.venv\Scripts\python.exe tools\check_dist.py dist\       # what must be inside them
```

.venv\Scripts\python.exe tools\check_dist.py dist\       # what must be inside them
```

### Environment gotchas (each one cost time already)

- **PowerShell aborts on stderr.** `git push` and `git commit` write progress
  to stderr, which PowerShell surfaces as a NativeCommandError and which
  stops the pipeline *after* the command has actually succeeded. Wrap
  anything that writes stderr: `cmd /c "git push origin master > %TEMP%\o.txt
  2>&1"`, then read the file. Never conclude a git operation failed from
  PowerShell's output alone; verify with `git ls-remote origin refs/heads/master`.
- **Never put a mutating git command and a git read in the same parallel
  tool batch.** Concurrent invocations in one batch race each other: a
  parallel `git status` refreshes the index (that is the phantom
  `index.lock`), and a parallel `git log`/`ls-remote` reads a half-moved
  HEAD and reports commits that just landed as still "modified" or absent.
  The commits are fine — verify sequentially after the chain finishes.
  Run `add && commit && push` as one chained `cmd /c` line and nothing
  else in the same batch.
- **Install with quotes**: `pip install -e ".[dev]"`. Unquoted, PowerShell
  eats the brackets.
- **`Get-Content` misreads UTF-8; it is not corruption.** Windows PowerShell
  5.1 decodes BOM-less UTF-8 as ANSI, so an em-dash renders as mojibake. The
  files are valid UTF-8; editing against the console rendering is how
  mojibake gets *introduced*. **Never use `Set-Content` on source files** —
  it re-encodes and has already produced mojibake here. Use the file editor.

## Rules that must survive further edits

1. **No `assert` on anything that came off the wire.** All validation raises
   `DnsPacketParseError` (defined once in `namespy/wire.py`). `pytest -O`
   must stay green — it is part of the definition of done, not a bonus.
2. **Serialization is canonical and compression-free.** `to_wire()` re-encodes
   full labels, never a pointer, because `cache/sqlite.py` stores
   `bytes(record)` and re-parses it standalone. Received octets stay on
   `.wire` for dumps.
3. **Unknown is not an error.** Unregistered types/classes/RCODEs pass
   through as data (RFC 3597 section 3); never reach for `.value` on the
   result of `parse()`.
4. **RDATA is accounted for inside RDLENGTH in both directions** — overrun
   *and* under-run fail closed (RFC 9267 section 5). The trailing-octet fix
   in `RData_SingleName.parse_from` is the template.
5. **Served TTLs clamp at 2147483647** (RFC 2181 section 8) — `clamp_ttl` is
   called from `DnsRecord.__init__`; do not reintroduce a raw `int(ttl)`.
6. **Attacker-controlled paths log at DEBUG, never louder** (RFC 5358
   section 4.2 rationale). v4, v6 and server now agree; keep them agreed.
7. **Names are octet strings** (RFC 2181 section 11): no LDH screening in the
   parser, comparison is ASCII-folded octets, an interior empty label has no
   wire form and must raise at encode time rather than silently rename.
8. **Protocol behaviour cites its source** — `RFC 9267 section 5` style, in
   code and in `docs/rfc-map.md` (obligation → code → test). Update the row
   in the same commit as the behaviour. Re-check any citation you touch
   against the live document (rfclib / rfc-editor) before editing it.
9. **Coverage floor is a ratchet**: raise it with tests, never ahead of them.

## Known gaps (deliberate, documented in README/CHANGELOG)

- ~~EDNS(0) on outbound queries~~ — shipped (f15b751), and so are its option
  TLVs and the per-server payload sizes that travel with them. The roadmap's P1
  is now RFC 9520: caching a resolution failure, so a dead zone stops being
  re-queried by every name beneath it. See the P1 row of
  [`docs/roadmap.md`](roadmap.md).
- QNAME minimisation: shipped opt-in (`qname_min` / `--qname-min`); the
  default-off is deliberate. serve-stale (RFC 8767), DNSSEC validation
  (RFC 4033/4034/4035), IDN/punycode (RFC 5891), DoT/DoH (RFC 7858/8484)
  remain open.
- ~~Out-of-bailiwick glue filtering~~ — shipped: `classify` takes a referral's
  address records only for a nameserver name inside the zone that answered or
  inside the zone that referral delegates (RFC 5452 section 6 with RFC 1034
  section 4.2.1); anything else is discarded and that server's address comes from
  the `NeedAddress` sub-resolution instead. The lame check for an in-bailiwick NS
  with no glue was already in place.
- `SqliteDnsCache` does synchronous disk I/O on the event loop (latency, not
  correctness); a live-network test tier would lift `resolver.py` coverage.

## Next task: EDNS option TLV + per-server payload adaptation (roadmap P1, highest priority)

QNAME minimisation shipped opt-in this round: probe walk + descent
integration (`resolve_steps` takes `qname_min`), probe-aware handling of
terminal classifications (a probe's NODATA/NXDOMAIN demotes and continues
per RFC 9156 section 3 step 4 instead of answering for the original QNAME),
budget degradation to full names, `--qname-min` CLI, probes marked in
`--trace`, CNAME chasing deliberately full-name. Patterns to reuse for the
rest of this section: `test_qname_min.py` for fake-server descent tests.

The remaining work, in `docs/roadmap.md` order:

1. **Wildcard synthesis** (RFC 4592 section 2.2) — names carry
   `is_wildcard` already; the closest-encloser proof and synthesized-TTL
   rule are missing, and until then answers from `*.example` zones are not
   RFC-identical.

Shipped this round: EDNS option TLVs, and the payload sizes they travel with.
`namespy/edns.py` owns the code/length/value records and the three option codes
worth an opinion: NSID (RFC 5001), COOKIE (RFC 7873), Padding (RFC 7830).
Requestor side, `add_edns(options=...)` writes them into OPT RDATA and
`--nsid` asks every server the walk touches who it is, printed as hex per
section 2.4. Resolver side, `_server_ids` records what each server answered and
`_payload_by_server` what it advertised, and `_advertised_payload` offers a
server the smaller of our default and the size it asked to be offered (RFC 6891
sections 6.2.3/6.2.4, floored at 512 — a responder may ignore a smaller CLASS,
so going below the historic default buys nothing). Server side,
`--advertise-nsid` gives the demo server an identifier, `_reply_options` hands it
out only to a query that asked with a zero-length NSID option (RFC 5001 section
2.2), and `_edns_options_or_error` answers a misformed option with FORMERR *plus*
an OPT — a FORMERR with no OPT is what section 6.2.2 reads as "no EDNS here",
which must not be confused with "EDNS here, bad option". Two decisions are
deliberate: a code nobody here models is ignored rather than refused (RFC 6891
section 6.1.2), while a misformed one is a wire-format error in either direction
— the parser raises instead of truncating, and on the query side that raise is
what becomes the FORMERR; and padding is never emitted over plaintext UDP at all
(RFC 7830 section 6), which is why the server declines a padding request rather
than honouring section 4. Patterns to reuse: `test_edns.py` for TLV and resolver
plumbing, `test_server.py`'s `make_server`/`answer_with`/`extended_query` for
responder-side tests.

Shipped since the last handoff: the bailiwick filter for out-of-zone glue
(RFC 5452 section 6). A referral's address records now reach an `SlistEntry` only
if their owner is the answering zone or a subdomain of it, or lies under the zone
the referral delegates — RFC 1034 section 4.2.1 makes a parent responsible for
below-cut glue and nothing else it volunteers is credible. Discarded glue leaves
the nameserver as a name that still needs an address, which the `NeedAddress`
sub-resolution obtains from the servers that are authoritative for it (RFC 1034
section 4.2.2). The filter lives in `classify`, so every consumer of a referral
inherits it. Tests: `test_resolver_classify.py` (discard / keep-below-cut /
not-lame-without-glue / per-nameserver), and the two-hop descent in
`test_resolve_steps.py` now walks the sub-resolution instead of believing the
volunteered address.

Definition of done for any of these: focused tests + full suite green under
`-O`; roadmap row flipped in the same commit; README/CHANGELOG updated if
the gap list changes; ratchet coverage if it moved.
