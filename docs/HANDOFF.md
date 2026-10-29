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
| Suite | 675 passed, 0 failed; clean under `python -O` too (the pytest "assertions stripped" notice there is pytest talking about itself, not this code) |
| Coverage | 87.2% measured with `pytest -q --cov`; floor 80 lives in `pyproject.toml`, and CI passes `--cov` now — before this round it did not, so the floor was never read there |
| Features | codec, resolver, CLI, truncation/TCP, **EDNS(0) incl. §6.2.2 fallback** (`--no-edns` to disable), **EDNS options** — NSID (`--nsid` / `--advertise-nsid`), COOKIE, Padding, per-server payload sizes (`tests/test_edns.py`) — and **Extended DNS Errors** (RFC 8914) composed by the server and consumed by the resolver and the CLI (`tests/test_edns_error.py`), and **SVCB/HTTPS RDATA** (RFC 9460) decoded into `SvcParams` with `alpn`/`dohpath`, `keyNNNNN` for unregistered keys and §2.4 selection (`namespy/svcb.py`; `tests/test_svcb_rdata.py`, `tests/test_svcb_wire.py`, `tests/test_svcb_presentation.py`) |
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
   **against the body of the document — not a section index, and not your
   memory of the wording.** Pull the text (`get_rfc`, the RFC-Editor mirror
   this machine keeps under `D:\code\rfclibrary\data\mirror\rfc\`, or
   rfc-editor.org) and find the sentence you quote *inside* the section you
   name. A section number can be exactly right while the words inside the
   quotation marks are a paraphrase: that is how RFC 6891's "MUST be ignored"
   shipped here as "MUST be silently ignored", and how RFC 7873 §5.2.2's
   "valid cookie lengths are 8 and 16 to 40 inclusive" circulated in wording
   the RFC does not use. Wrapped lines defeat naive greps — search for a
   fragment that survives the wrap ("valid cookie lengths"), never the whole
   sentence, and confirm the surrounding heading is the one you cited.
9. **Coverage floor is a ratchet**: raise it with tests, never ahead of them — and it
   is only ever *read* when something passes `--cov`, so check the flag is present
   before believing the gate fired.

## Known gaps (deliberate, documented in README/CHANGELOG)

- ~~EDNS(0) on outbound queries~~ — shipped (f15b751), and so are its option
  TLVs, the per-server payload sizes that travel with them, and Extended DNS Errors
  (RFC 8914) in both directions. RFC 9520 shipped too:
  `FailureCache` remembers a failed lookup — including a zone whose servers stopped
  answering — and sends nothing upstream while the entry lives. Dead addresses are
  deliberately not remembered; `--no-failure-cache` turns the whole thing off. See
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

## Latest round: Extended DNS Errors (RFC 8914)

Shipped: the `ERROR` option (code 15) is written *and* read. `ExtendedDNSError` in
`namespy/edns.py` holds the INFO-CODE plus the raw EXTRA-TEXT octets and infers nothing
from either — §3 forbids reading a meaning into a code, §6 forbids the option changing
anything. `.option` turns one into a TLV; `extended_errors_of` returns a response's whole
list in wire order and raises nothing, because a malformed option is something a
*receiver* skips (`extended_error_option_valid`) while the server answers one with FORMERR
under RFC 6891 §7 — same octets, opposite directions, and that asymmetry is the point.
`namespy/server.py` sends exactly two codes: 22 (`_own_failure_errors`) for a walk that
ran out of authoritative servers, 21 for a non-QUERY opcode, each with EXTRA-TEXT naming
this software; `_apply_edns` drops explanations before anything the client asked for when
the reply would overflow its advertised size (§3's order), decorates nothing for
BADVERS/FORMERR, and says nothing at all to a requestor that sent no OPT. On the way in,
`resolver._extended_error_note` folds up to three codes into the reason a `FailureCache`
entry remembers and `_note_upstream_errors` logs at DEBUG; `__main__._response_errors`
prints `; EDE: 22 (No Reachable Authority): text` under any rcode, control octets escaped,
because §6's MITM sentence describes the field a terminal is about to be handed.
Patterns worth reusing: `test_cli.py`'s `_explained(*errors)` builds a NOERROR answer that
carries options — the only sane way to pin §3's "accept them in all messages" without a
network — and `test_failure_cache_resolver.py`'s `_drive` return value pins what a
received code *changed* (the remembered reason) beside what it did not (nothing else).
Absent on purpose: no propagation of an upstream code to this resolver's own client (§3
permits either answer, and the failure path returns `None` rather than a message to
decorate), and no invented name for a code the registry does not carry — it prints as its
number. Worth knowing: every §2/§3/§6 quotation in the EDE code was re-checked against the
RFC body this round, and three that had crept in as paraphrases were replaced — the rule 8
failure mode is alive, so re-check a quote rather than trusting the section number beside
it. Shipped since that was written: SVCB and HTTPS (9460) — `namespy/svcb.py` with the
key registry, `SvcParams`, `SvcbCandidate` and `select_records`, plus `RData_SVCB` and
`RData_HTTPS` in `rdata.py`, with Appendix D of the RFC as the test oracle. Two things
worth knowing before touching either file. First, a malformed `HTTPS` RDATA now fails the
whole message parse, as a malformed `A` or `SOA` always has: the codec is registered, so
"opaque fallback" applies only to types with no codec (RFC 3597 §3), and refusing to guess
where the next record starts is RFC 9267 §5 rather than a local preference. Second,
`namespy/svcb.py` measured 70% under `pytest --cov` while the note in `pyproject.toml`
expects 89% or better, because much of its presentation layer was exercised only by
doctests and CI runs `pytest -q --cov` without `--doctest-modules`. Writing those examples
into `tests/` is what found the two bugs fixed in the same commit: `_PARSABLE_KEYS` was a
set of key *names* while `SvcParams.from_wire` and `to_wire` compare key *numbers*, so no
registered key ever matched and every one was treated as uninterpretable — a one-octet
`port` therefore decoded as a well-formed record that merely has no `port`, which changes
how a client connects instead of losing the record, because §2.2's third malformed
condition was never reached — and `SvcParams._unknown` came from how an object was built
rather than from what it stores, so a hand-built `SvcParams` could not say which of its
keys have no value definition. `SvcParams._unknown` is now derived from the stored keys,
which is also what keeps `ech` (registered at 5, no value definition) opaque in both
directions: `test_ech_is_conveyed_but_stays_opaque`'s `unknown_keys == (5,)` on a
hand-built `SvcParams` is the pin. What is
still doctest-only is `zone_file_warnings` (svcb.py:1325–1368), which leaves the module at
88% — chase that by moving those examples into `tests/`, not by writing weaker tests.
What remains in `docs/roadmap.md`, in order: MQTYPE (10029),
then wildcard synthesis (4592 §2.2).

Housekeeping that turned out to be a real fix: the coverage floor had never been *read*
by CI. `[tool.coverage.report] fail_under` is a pytest-cov input, and pytest-cov measures
only when `--cov` is passed — the Test step ran plain `pytest -q`, so it exited 0 whatever
the tests covered, while README, CONTRIBUTING and the pyproject comment all said the floor
was "enforced by pyproject". The step now runs `python -m pytest -q --cov`, the three docs
say so, and the comment's stale module figures (measured before this round's tests
landed) are
replaced with today's. The floor itself stays at 80: 87.2% is one platform's number, and
rule 9 says a raise waits for a measurement, not a guess — the next one should come from a
CI run.

## Previous round: RFC 9520 failure caching (`FailureCache`)

Shipped: a resolution failure is remembered and acted on. `FailureCache` in
`namespy/cache/__init__.py` is consulted by `resolve_steps` before any query leaves
the process and recorded at each place a lookup dies. `RecursiveResolver` owns one
(`failure_cache=`,
`--no-failure-cache` on the command line). A zone whose servers stopped answering is
keyed on the zone — that is what makes the next name beneath it cost nothing, and
what §3.3's parent-throttling means in this codebase — while an alias loop or a spent
hop budget is keyed on `(QNAME, QTYPE, QCLASS)`. Patterns worth reusing:
`test_failure_cache_resolver.py`'s `_drive(gen, responses)` for asserting the
*absence* of a query — it returns every event the generator yielded, so "nothing
left the process" is the absence of a `SendQuery` in that list — and
`FailureCache(time_fn=...)` for TTL behaviour without sleeping. That closes the last
P1 item in `docs/roadmap.md`, its RFC 9520 §3.1 row included: that ceiling is counted
per transport ("A resolver MUST NOT retry a given query to a server address over a
given DNS transport more than twice"), so a silent server costing one UDP datagram and
one TCP attempt is conforming — it just had never been pinned. `test_silence_is_tried_once_per_transport_and_no_further`
and `test_edns_refusal_and_silence_do_not_combine_into_three_attempts` in
`test_resolver_truncation.py` do that now. What remains in the roadmap is P2 and below.

## Earlier round: EDNS option TLV + per-server payload adaptation

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
