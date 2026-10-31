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
| Suite | 919 passed, 0 failed; clean under `python -O` too (the pytest "assertions stripped" notice there is pytest talking about itself, not this code) |
| Coverage | 89% measured with `pytest -q --cov` (it drifts by a few hundredths between runs, since some transport-retry branches depend on timing); floor 80 lives in `pyproject.toml`, and CI passes `--cov` now — before this round it did not, so the floor was never read there |
| Features | codec, resolver, CLI, truncation/TCP, **EDNS(0) incl. §6.2.2 fallback** (`--no-edns` to disable), **EDNS options** — NSID (`--nsid` / `--advertise-nsid`), COOKIE, Padding, per-server payload sizes (`tests/test_edns.py`) — and **Extended DNS Errors** (RFC 8914) composed by the server and consumed by the resolver and the CLI (`tests/test_edns_error.py`), and **SVCB/HTTPS RDATA** (RFC 9460) decoded into `SvcParams` with `alpn`/`dohpath`, `keyNNNNN` for unregistered keys and §2.4 selection (`namespy/svcb.py`; `tests/test_svcb_rdata.py`, `tests/test_svcb_wire.py`, `tests/test_svcb_presentation.py`), and **MQTYPE** (RFC 10029) in both roles — both options composed and parsed, §3.3's refusals enforced on send and on receive, §3.4's combination merging the extra QTYPEs into one reply and returning the MQTYPE-Response (`namespy/mqtype.py`, `namespy/server.py`; `tests/test_mqtype.py`, `tests/test_server.py`), **and** asked, read and re-asked by the resolver, so one walk answers A + AAAA + HTTPS (`namespy/bundle.py`, `RecursiveResolver.resolve_bundle`, CLI `--mqtype`; `tests/test_bundle.py`, `tests/test_resolver_mqtype.py`), and **the NXDOMAIN cut** (RFC 8020) — `NxdomainPolicy` (`ALWAYS`/`NEVER`/`VALIDATED`) over the QTYPE-free `DnsCache.nxdomain_at()` in both backends, consulted at every hop, with `--no-nxdomain-cut` on the CLI and `NXDOMAIN cut:` in both the trace and the answer (`tests/test_nxdomain_cut.py`, plus the new rows in `tests/test_cache.py`), and the **first leg of DNSSEC** (RFC 4034) — `DNSKEY` and `DS` codecs plus the key tag and DS-digest arithmetic in `namespy/dnssec.py`, with no new dependency: the digests are `hashlib`, and the two published vectors in the RFC are the tests (`tests/test_dnssec_codecs.py`), and **the DNSSEC proof records** (RFC 4034 §3–§4, RFC 5155 §3–§4) — `RRSIG`, `NSEC`, `NSEC3` and `NSEC3PARAM` codecs with type bit maps, the NSEC3 hash and §10.3's iteration ceiling, again with no new dependency (`tests/test_dnssec_proofs.py`) |
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

## Latest round: the NXDOMAIN cut (RFC 8020)

Shipped: §2's SHOULD, as a policy. A NXDOMAIN in the cache now denies the names at and below it,
so the lookup RFC 2308 would send upstream is answered from the denial the zone already made.

**Why the change is in the cache and not the resolver.** §2¶1's claim is about *names* — "all
names and resource record sets (RRsets) at or below that node SHOULD be considered unreachable" —
while a negative entry is
keyed `(name, qtype, class)`. The NXDOMAIN that arrived in answer to an A was therefore invisible
to the AAAA this cut exists to serve, and no amount of resolver-side cleverness fixes a key that
cannot be named. So `DnsCache.nxdomain_at(name, qclass)` is the QTYPE-free lookup `get()` cannot
be: SQLite does it as one read on the primary key's leftmost column, memory keeps an index
maintained on every removal path. The index is not micro-optimisation — the cut is consulted on
every hop of every query, so scanning the cache per hop would cost more than the traffic saved.
The base implementation returns `None` rather than raising: the cut is a SHOULD, so a backend that
cannot answer keeps walking, which *is* the pre-8020 behaviour.

**Two things the tests caught by failing, both mine.** First draft walked only the *ancestors* of
the queried name, which misses the "at" in §2¶1's "at or below that node" — the node is the denied
name, so its other RRsets are covered too — and a AAAA for a name whose A was denied still went
out; the walk now includes the name itself. Second, the alias case (§2¶6: the denied name is the
**last** one in the chain, "and not the QNAME") only
worked once the cut moved inside the per-hop loop rather than being checked once at the origin.

**Policy shape, and where it deliberately differs from `GluePolicy`.** Three stances because RFC
8020 names three: `ALWAYS` (§2¶1's SHOULD, default), `NEVER` (§2 is a SHOULD, and §2¶4 concedes
"The fact that a subtree does not exist is not forever" — this is the watch-a-zone-change switch,
sibling of `--no-failure-cache`), and `VALIDATED` (§2¶3's MAY, cut only on a DNSSEC-validated
denial). `VALIDATED` refuses to construct and says DNSSEC in the message, because it and `NEVER`
emit identical packets while nothing validates; a silent fallback would let an operator believe
proofs were what stopped the cut. `test_validated_policy_is_refused_at_the_door` is the thing that
must change when validation lands. Unlike permissive glue, `NEVER` logs rather than warning on
stderr: it gives up an efficiency, not a defense, and cannot hand a lookup to anyone.

**Visibility, which is the half of the glue precedent worth copying.** A cut's answer is
indistinguishable on the wire from a denial fetched for the name itself — the reply carries the
*ancestor's* SOA beside a question naming the deeper name — so `NxdomainCut` renders as
`NXDOMAIN cut: www.foo.example below foo.example` in the trace and as a `;;` line in the answer.
Both halves are reported in the case the *query* used, not as the cached entry is stored: two names
differing only in case read like two names, and this line exists to be read by whoever just
created the name being denied.

**Overlap with RFC 9520, decided rather than discovered.** The cut is consulted *before* the
failure note, because a cached denial is a proof with an SOA behind it while a failure note is only
a promise not to ask again — and only the first of the two can answer the client.

**Verified**: 870 passed (+37), `ruff check namespy tests` clean, `ruff format --check` clean,
`mypy namespy` exits 0. `docs/roadmap.md` gained its 8020 §2 row; `docs/rfc-map.md` §10 the
code-mapping row.

**Next**: the DNSSEC record codecs (§2¶5's NSEC/NSEC3 echo is one of them), the thing
`VALIDATED` is waiting on. Checking
the RFC while writing this turned up the one obligation here that is *not* shipped: §2¶5 says a
resolver "MUST return these NSEC or NSEC3 records in the response to the triggering query if the
query had the DNSSEC OK (DO) bit set". It is unreachable rather than missing — there are no proof
records to return until the codec exists — but it is the reason the roadmap row is scoped to
§2¶1–¶4 and §2¶6–¶8 rather than to the section. §5¶1 is the known cost of the whole feature, and
the RFC's own answer to it ("This document assumes that such a setup is rare and does not need to
be supported") is why `NEVER` exists rather than a per-zone exception.

### Follow-up: the first DNSSEC leg (RFC 4034 §2, §5, App. B)

`namespy/dnssec.py` (new) plus `RData_DNSKEY` / `RData_DS` in `namespy/rdata.py`, registered on
48 and 43. Chosen because it is the part of DNSSEC with no dependency in it: the public key is
opaque (§2.1.4 defers its format to documents this package does not implement), the key tag is a
16-bit checksum, and the DS digest is `hashlib` over "owner name | DNSKEY RDATA" (§5.1.4). The
dependency decision — RSA/ECDSA/EdDSA for verification — is still ahead of it, untouched.

**The vectors are the RFC's, which is the whole reason to trust the arithmetic.** §5.4 prints a
DNSKEY *and its DS*: key tag **60485**, SHA-1 digest **2BB183AF5F22588179A53B0A98631FAD1A292118**.
Both come out of this code unchanged, in one test, validating the §2.1 layout, §5.1.4's bare
concatenation, and §6.2's downcasing at once. Where no vector exists — the key tag has none for
arbitrary RDATA — the test transcribes Appendix B's C reference a second time and compares.

**Two verified errata change numbers here, and both are pinned.** 4552 rewrites Appendix B's
prose about carries: accumulate at 32-bit precision keeping the carries, fold once, drop only the
carry that the fold itself produces — and the erratum adds that this is "often the same as
reduction modulo 65535, **but not always**", so the shortcut is not used and
`test_key_tag_is_not_reduction_modulo_65535` carries the smallest input where they differ. 193
fixes §B.1's parenthetical for algorithm 1 (RSA/MD5) to "3rd to last and 2nd to last" octets,
which is what its own normative phrase meant; the vector is built so the two readings differ.

**Two things the tests caught before commit, both worth repeating.** The constructors took
`bytes(public_key)` — so the RFC's own Base64 text raised `TypeError: string argument without an
encoding`, and the example that documents the format could not be parsed by the code that
implements it; `key_material()` / `digest_material()` now take octets *or* the master-file text
each field's presentation form specifies (§2.2, §5.3). And `DigestType(15)` raised "not a valid
DigestType", which sends a reader to look for a typo in their zone file when the truth is that
this package has no hasher for 15 — `ds_digest` now refuses by number and names what it does
support. Note the direction the asymmetry runs: **reading is more forgiving than writing**. A DS
with an unknown digest type parses, round-trips and prints; a DNSKEY with Protocol 4 is kept and
reported by `may_verify_rrsets` rather than dropped at parse time, because §2.1.2 puts that
judgement at verification and an operator needs to see which rule the zone broke.

**The repo's own sweep did its job.** `test_rdata_wrapping.py` asserts every registered codec has
a round-trip payload, and it failed the moment the two were added — the new types had to be given
payloads there, which also means they are now covered by the message-level encode/parse/encode
comparison alongside A, SOA and SVCB.

**Next**: RRSIG and NSEC/NSEC3 (4034 §3–§4, 5155), then the canonical-RRset rule of §6.2 — where
erratum 1062 matters, since 4034's list of types whose RDATA names get downcased is incomplete and
RFC 3597 §7 carries the real set — then the wildcard reconstruction from RRSIG's Labels field
(§3.1.3), and only then the verification dependency decision. `NxdomainPolicy.VALIDATED` and
RFC 8020 §2¶5's MUST both clear on the proof-record codecs.

### Follow-up: the DNSSEC proof records (RFC 4034 §3–§4, RFC 5155 §3–§4, §10.3)

`RData_RRSIG` (46), `RData_NSEC` (47), `RData_NSEC3` (50) and `RData_NSEC3PARAM` (51) in
`namespy/rdata.py`, with what they share moved to `namespy/dnssec.py`: the type bit map
encoder/decoder (§4.1.2, reused unchanged by §3.1.8), the NSEC3 hash (§5), base32hex
(§3.3), and §10.3's iteration ceiling as a predicate. Chosen because the codecs are what
everything else in DNSSEC waits on and because, like the first leg, none of it needs a
dependency: SHA-1 is `hashlib`, the bitmap is arithmetic, and a signature is opaque octets.

**Appendix A of RFC 5155 is a test suite the authors wrote on purpose** — "They can also be
used as test vectors for the hash algorithm" — and its twelve hashes are what the new
`test_dnssec_proofs.py` is built on. They cover three traps at once. The alphabet:
**verified erratum 3544** corrects §3.3's "base32" to base32hex, and RFC 4648 §7 warns the two
are not the same encoding; `base64.b32encode` would have produced labels that exist in no
zone. The recursion: §3.1.3's *iterations* is "the number of additional times", so the name is
hashed once regardless and twelve means thirteen invocations — the off-by-one yields a hash
that matches nothing, silently. And the canonical input: §6.2 item 4 keeps the `*` label, which
is why `*.w.example.` has its own hash and why `canonical_owner_octets` is now shared with the
DS digest instead of being named for it.

**`within_validity` is the one rule in `RRSIG` that is not just unpacking.** §3.1.5¶2 allows an
Expiration numerically below its Inception and mandates RFC 1982 arithmetic for these fields, so
the comparison goes through `RData_SOA.serial_ahead` — the same serial arithmetic the repo
already trusted for SOA updates. An integer `inception <= now <= expiration` would have been the
obvious implementation and would have been wrong for signatures that straddle the 2106 wrap.

**The sweep earned its keep again.** Registering four codecs made `test_rdata_wrapping.py`
demand a payload for each, and writing the RRSIG one surfaced a header format of `!HBBIIHI`
where `!HBBIIIH` is correct: the same 18 octets, with the Key Tag read into the Inception Time
and the last field taken from wherever the name started. Nothing else in the suite would have
noticed until a resolver cached a signature that printed a 1970 expiry.

**Not claimed, in order of what now unblocks what.** The §6.2 canonical-RRset rule and the
Labels-field wildcard reconstruction (§3.1.3) are verification-side and were absent at the time of
writing — both have since shipped; see the next section. What the two errata on that rule turned
out to mean is recorded there, because my first account of it ("RFC 3597 §7 carries the real set")
was wrong. Proof *checking* is absent: `NSEC3` exposes
`hash_owner()` for a name, but deciding whether a name falls between this record and
`next_hashed_owner` is §7/§8 work, where **errata 3441 and 4622** both change what a server must
include for empty non-terminals and NSEC3 owner names. RFC 8020 §2¶5's MUST still cannot be
met, and the reason is now specific: the proof records decode, but `DnsCache` stores only the
SOA of a negative answer, so there is nothing to echo when DO is set — storing them is that
row's remaining scope. `NxdomainPolicy.VALIDATED` therefore still refuses to construct, and its
test is still the marker that has to change when validation lands.

**Verified**: 978 passed (+59), `ruff check .` and `ruff format --check .` clean,
`mypy namespy` exits 0, and `python -O -m pytest -q` passes, so none of the new reasoning rests
on an `assert`. Roadmap §6 gained its proof-record row, §10's 8020 row now names the reason
§2¶5 is still open, and `docs/rfc-map.md` §10 maps the new symbols.

**Next**: canonical RRset ordering, then NSEC/NSEC3 proof construction, then the cache change
that lets a denial carry its proofs — and only after those, the dependency decision for
signature verification, which is the one choice here that cannot be undone quietly.

### Follow-up: choosing the cryptographic dependency (and bounding it)

The open decision on the roadmap — "the one choice here that cannot be undone quietly" — is
taken: **`cryptography`, behind a capability-named `crypto` extra**, with `namespy/crypto.py` as
the only module permitted to find it. Verification is still not implemented; what landed is the
boundary and the policy it has to satisfy, so the choice can be reviewed before it is load-bearing.

**Why the extra is called `crypto` and not `dnssec`.** Renaming a published extra breaks every
downstream that installed the old name, and DNSSEC is not the only thing that will ever want
arithmetic here — a TLSA association check (RFC 6698) or any future signature work lands in the
same place. Naming the boundary after its first customer guarantees a breaking change later.

**What the research turned up, so it is not redone.** RFC 9904 Table 2 (Nov 2025) sets "Implement
for DNSSEC Validation" to MUST for 5, 7, 8, 10 and 13 — including the two SHA-1-based RSA numbers
RFC 9905 deprecated *for signing*. A validator still has to verify them, because the zones signed
with them are still out there. That fact alone eliminates every EdDSA-only or modern-only
candidate, and it is why `IMPLEMENT_FOR_VALIDATION` and `SIGNATURE_ALGORITHMS` are two tables with
a test checking they agree: the policy is the RFC's, the capability is the library's, and a gap
between them is something to report to the user rather than a zone to fail on silently.

- **`cryptography` (chosen).** 50.0.2 at this writing; Python Cryptographic Authority under the
  PSF, published security policy with a 48-hour acknowledgement and support for "the main branch
  as well as the most recent release". Covers the whole MUST set plus Ed25519/Ed448. abi3 wheels
  for Windows, macOS, manylinux and musllinux across five architectures, with trusted publishing
  and provenance attestation on every file; Rust (≥1.83) is needed only to compile from source,
  and the floor version installed from a wheel on Windows/3.13 with no toolchain at all.
  Its advisory history is honest reading: of ~19 advisories, three are "Vulnerable OpenSSL
  included in cryptography wheels" — the recurring cost of statically linking OpenSSL, whose fix
  is to upgrade, which is why the floor sits at a current release. One High (Feb 2026) is missing
  subgroup validation for **SECT** curves: unreachable from DNSSEC, since algorithms 13 and 14
  name P-256 and P-384 (prime-order, cofactor 1) — but the reason our layer, not the library,
  decides which curve an algorithm number may mean. None of them touch verification itself.
- **`python-ecdsa` (rejected).** Its own PyPI page says "this library should not be used in
  production settings", it has no RSA — so it cannot do 5, 7, 8 or 10 — and its releases carry no
  provenance. Not close.
- **`pycryptodome` (rejected, with less margin).** Capable and self-contained (own C code, NIST +
  Wycheproof vectors, blinded constant-time paths, Ed448 present), but single-maintainer and
  without the governance or provenance posture above. The fallback if `cryptography` ever stops
  working on a target platform.
- **`PyNaCl` (rejected on scope).** libsodium has no RSA and no NIST P-256, so the MUST set is
  unreachable. Its PyPI page would not load during this pass (bot-blocked), so this rests on
  libsodium's documented feature set rather than a quotation.
- **Pure Python (rejected).** For RSA the exponentiation is the easy part; the hazard is PKCS#1
  v1.5 `DigestInfo` parsing, where the historical forgery bugs live, and RFC 3110 §3¶7 states the
  padding rule in a way that invites a lenient reader ("the FF octet MUST be repeated the maximum
  number of times such that the value being exponentiated is one octet shorter than n"). Writing
  that check by hand is the wrong trade against a promise that was always about *weight*, not about
  never having a dependency.

**The cost, measured here.** A floor constrains other people's environments: this dev box already
had `ubi-reader`, which caps `cryptography<47`, so it and `namespy[crypto]` cannot coexist. That
is the price of demanding a supported line, and still cheaper than no floor — which lets pip
install a release that stopped receiving security fixes. There is no ceiling for the same reason:
a cap in an optional extra of a library protects nobody and guarantees resolver conflicts.

**Homework the verification leg inherits**, all of it encoding rather than arithmetic: RFC 6605 §4
gives ECDSA signatures as fixed-width r‖s, not DER, so `decode_dss_signature` /
`encode_dss_signature` is the bridge (exercised by the new test); a DNSKEY holds an uncompressed
point with the `0x04` tag removed, and `from_encoded_point` is the constructor to use because it
refuses an off-curve point with `ValueError("Invalid EC key")` — asserted, not assumed; RFC 8080 §4
stores EdDSA keys and signatures as raw octets; RFC 3110 §3¶10 permits leading zero bytes in an RSA
signature field, so the codec must not require it to be exactly the key length; and §2's "1 or 3
octets" exponent length plus its prohibition on leading zero octets is still unenforced in
`RData_DNSKEY`, with one verified erratum on RFC 3110 §3 to read first.

**Two bugs the first push found, neither of which this machine could see.** The first was mine in
the test: a plain `from cryptography.exceptions import ...` sat *above* `pytest.importorskip`, so
an install without the extra raised ModuleNotFoundError instead of skipping — all four Test jobs
red while the Crypto job was green. A developer box that has installed the extra cannot
reproduce that, which is the whole argument for the matrix, and the guard is now a call to
`_needs_backend()` that asks the probe rather than an import that duplicates its question.

The second was in the probe, and only surfaced because uninstalling the library left an empty
`cryptography/` directory behind: Python imports that as a **namespace package** — successfully,
with no `__file__` — so `backend()` reported a present backend that had nothing in it. That is the
worst of the two answers, because it sends a caller past the boundary and into an AttributeError
inside verification instead of the `MissingCryptoError` it is built to handle. The probe now
treats a namespace package as absent (`namespy/crypto.py`, with a test that reproduces the
leftover directory). Working out why that test fails when the library *is* installed taught me the
other half of the rule: an empty directory yields only a namespace *portion*, and the finder
prefers a real package from anywhere else on `sys.path`, so the shadow cannot win — the test skips
with that reason stated rather than passing by luck in whichever configuration it landed in.

Both configurations are now exercised on purpose: absent locally and in the four Test jobs (989
passed, 2 skipped), present in the Crypto job (12 passed, 1 skipped).

**Verified**: `ruff check .` and `ruff format --check .` clean, `mypy namespy` exits 0, and the
claim that `import namespy` pulls in no third-party module is now proven in a subprocess — the
only place it can actually be checked.

### Follow-up: the canonical RRset (RFC 4034 §6.2-§6.3, §3.1.3, §3.1.8.1; RFC 3597 §7)

The last DNSSEC work that needs neither a dependency nor a trust anchor: the byte string a
signature is checked against. `canonical_rrset_bytes` / `rrsig_signed_data` and friends in
`namespy/dnssec.py`, `canonical_wire()` on `RData` and each name-bearing codec,
`signed_data_prefix()` on `RData_RRSIG`. `test_dnssec_canonical.py` is 25-odd tests over it.

**I had the downcasing rule wrong last round, and the correction is the interesting part.** I wrote
that RFC 4034 §6.2 item 3's list is incomplete "and RFC 3597 §7 carries the real one". Reading both
sections against their errata says otherwise: **erratum 1062** is raised against 4034 and
**erratum 1063** against 3597, each quoting the other's list, and neither supplies a replacement —
so the two documents disagree in *both* directions and the working answer is the union (3597 §7¶4's
pre-2003 types plus RRSIG and NSEC, which only 4034 names). Two consequences worth knowing before
touching this code: NSEC3 has no embedded domain name to downcase at all (its hashed owner name is
opaque octets, which is what I had imagined wrongly), and RFC 3597 §7¶5 says types defined *after*
it never downcase embedded names — so HTTPS/SVCB keep the case of their target-name, RFC 9460 being
silent on canonical form. A test pins that, because "it has a name in it, downcase it" is the
natural instinct and it is wrong for the newer half of the registry.

**Three traps this section closed.** (1) §3.1.8.1¶5 repeats owner/type/class/TTL/RDLENGTH *inside
every RR* of the signed string; a test measures the ten-octet delta between a one-record and a
two-record set so a future "optimisation" cannot quietly hoist it. (2) §6.3¶2 makes duplicate RDATA
a protocol error an implementation MUST treat as one, allowing leniency only if all but one copy is
dropped — `DuplicateRecordError` by default, `tolerate_duplicates=True` for the other reading.
(3) Canonicalisation is per-codec, not a `lower()` over the RDATA: an MX preference of `0x4142` is
inside the A-Z byte range, so the shortcut corrupts a number while appearing to canonicalise.

**Where a type is listed but we have no codec** (NAPTR, RP, AFSDB, the 1990s remainder),
`canonical_rdata_octets` raises `CanonicalizationError` naming the type instead of hashing raw
octets: guessing where names sit produces a byte string that fails *valid* signatures, and a false
authentication failure is the one outcome a validator must not manufacture.

**Verified**: 1017 passed (+27), `ruff check .` and `ruff format --check .` clean, `mypy namespy`
exits 0, `python -O -m pytest -q` clean. Roadmap §6 gained the canonicalisation row and the
validation row now names precisely what is left.

**Next**, in the order that unblocks the most: RFC 3110 §2's DNSKEY RSA packing (the 1-or-3-octet
exponent length and the leading-zero prohibition) together with **erratum 2811**, which corrects §3
to say RSA signature RDATA **MUST** be zero-padded to the modulus length — the backend will not
infer that padding, so the codec has to; then NSEC/NSEC3 proof checking (§7/§8, errata 3441 and
4622); then the `DnsCache` change that lets a cached denial carry its proofs, which is all that
stands between us and RFC 8020 §2¶5's MUST; then the verification calls through
`namespy[crypto]`, at which point `NxdomainPolicy.VALIDATED` finally has something to mean.

### Follow-up: RSA keys and signature width (RFC 3110 §2-§3, RFC 5702 §2, erratum 2811)

Reading RFC 3110 to write this down removed a stated blocker: §2's DNSKEY public key is integer
packing, not cryptography, so `unpack_rsa_public_key` / `pack_rsa_public_key` in `namespy/dnssec.py`
plus `RData_DNSKEY.rsa_public_key()` and `.require_rsa_key()` give us RSA key material on a default
install. ECDSA and EdDSA key material still waits on `namespy[crypto]`. 16 tests in
`test_dnssec_rsa.py`, none of which need a backend.

**The leading-zero rule is arithmetic, not tidiness.** §2¶3 prohibits leading zero octets in the
exponent and modulus; the reason they must be enforced rather than tolerated is that `key_tag` sums
the RDATA octets, so one extra zero produces a different tag and a DS matching nothing — a correct
key that cannot be used. The same reasoning settled a question the RFC leaves implicit: is the
3-octet length form allowed for a 3-byte exponent? §2¶3's "is represented as one octet if it is in
the range of 1 to 255" reads as prescriptive, and the key-tag consequence confirms it, so
`unpack_rsa_public_key` refuses the long form when the short one was required. I came in intending
to enforce "an empty exponent MUST be an error" from memory; searched the corpus, no such sentence
exists in any RFC, so the code derives that refusal from §2¶2's figure and its docstring says the
rule is read off the layout rather than quoted.

**`MIN_RSA_KEY_BITS` was one constant too few.** RFC 3110 §3¶9 and RFC 5702 §2.1¶2 set the modulus
floor at 512 bits (algorithms 5, 7, 8); **RFC 5702 §2.2¶2 sets 1024 for RSA/SHA-512**. The existing
constant and its test predated that reading, so a validator using it accepted a 512-bit SHA-512 key
RFC 5702 forbids — and because a zone can hold keys of several algorithms, the weakest is what an
attacker forges against. Now `RSA_MIN_KEY_BITS_BY_ALGORITHM` / `minimum_rsa_key_bits()` carry it and
`require_rsa_key()` applies the algorithm's own floor.

**Algorithm 1 is not this format.** RFC 3110 §2's two notes moved RSA/SHA-1 onto number 5 precisely
to separate it from RFC 2537's RSA/MD5, whose RDATA begins with a key-length header; parsing that
with this reader yields a confident wrong key rather than an error. `RSA_ALGORITHMS` is derived from
`SIGNATURE_ALGORITHMS` (`primitive is RSA`) so the two tables cannot drift.

**Erratum 2811 decided a design question that looked arbitrary.** §3¶10 published: "Leading zero
bytes are permitted in the RSA/SHA1 algorithm signature." Verified technical erratum: MUST be added,
so the signature is exactly ⌈bits(n)/8⌉ octets (PKCS #1's `I2OSP(s, k)`). Hence
`rsa_signature_octets` pads short signatures rather than rejecting them — those records exist, and a
backend handed a short one fails in the same shape as a forgery — and refuses a signature wider than
the modulus, since no reduction mod n can produce one.

**Also found for the verification leg: RFC 5702 §8.2's downgrade defence is void** (verified erratum
7090): the claimed protection rests on a signer-side requirement with no validator-side counterpart,
and RFC 6840 §5.11 says explicitly that a validator need not check that every algorithm is present.
So the future "pick an RRSIG from the set" step must choose safely among what arrived instead of
demanding a set shape.

**Verified**: 1033 passed (+16), `ruff check .` / `ruff format --check .` clean, `mypy namespy`
exits 0.

**Next**: NSEC/NSEC3 proof checking (§7/§8, errata 3441 and 4622), then the `DnsCache` change that
lets a cached denial carry its proofs (all that stands between us and RFC 8020 §2¶5's MUST), then
ECDSA/EdDSA key and signature encodings (RFC 6605 §4, RFC 8080 §3 — r‖s, not DER) and the
verification calls through `namespy[crypto]`, at which point `NxdomainPolicy.VALIDATED` acquires
meaning.

### Follow-up: the denial-of-existence proof rules (RFC 4034 §6.1, RFC 4035 §5.4, RFC 4592 §3.3.1, RFC 5155 §6-§9)

New module `namespy/nsec.py`, 26 tests in `test_nsec_proofs.py`. It decides what a set of NSEC or
NSEC3 records *asserts* about a name; it authenticates nothing, exactly as the canonicalisation work
doesn't, so the verification leg still owns the question of whether the records are genuine.

**The most valuable thing here is the error split.** `IncompleteProofError` means the proof records
were not in the response — RFC 4035 §5.4¶6 obliges a resolver to ask again (truncation is why they go
missing, and the third NSEC3 record is the usual casualty), so the caller's move is TCP retry.
`ContradictoryProofError` means the records cannot all be true, where the move is bogus. One error
type for both produces either a retry loop against a correctly-answering server or a forged denial
accepted because retrying eventually looked better.

**Three traps, all now pinned by tests:**

1. *The span wraps.* A zone's last NSEC points at the apex (§4.1.1¶1) and its last NSEC3 at the
   first hash (§7.1¶19), so the second endpoint sorts before the first. The obvious `start < key <
   end` makes that record cover nothing, and every name after the final owner reports unproven —
   i.e. real NXDOMAINs become bogus. Both `name_between` and `hash_between` carry the branch, and
   the one-name zone (equal endpoints) falls out of the same expression.
2. *Some bitmap bits must not be read.* RFC 4035 §5.4¶7 forbids reading the NSEC and RRSIG bits — a
   validated NSEC already proves both exist at its owner, so a signer that omitted them from the
   bitmap must not have it disprove the record carrying it. RFC 5155 §7.1¶5 gives the same reasoning
   for the NSEC3 bit. `test_the_nsec_and_rrsig_bits_are_never_read` and
   `test_nsec3_denies_a_type_at_a_matching_name_only` hold the line; §8.5¶2's empty-bitmap ENT case
   is tested next to them.
3. *§8.3's flag has to survive the step up.* The encloser is found because its child was covered, so
   clearing the flag on a matching parent — the intuitive tidy-up — destroys the proof. Implemented
   literally, in the RFC's own bullet order, and the bogus branch (§8.3¶10: matching while the flag
   is clear means the name exists) is distinguished from incomplete.

Also enforced: §8.3¶12's proper-zone test on the encloser's record (a DNAME, or NS without SOA, means
this server is not authoritative below the name it denies); §8.4's wildcard half, which is what stops
"no such name here" being read as "no answer was due" when `*.example.com.` exists — with RFC 4592
§3.3.1¶4 making that one name to test rather than a wildcard hunt, and §3.3.1¶6-¶7 the reason there
is no fallback to a nearer wildcard; and §8.1/§8.2 filters, including refusing a record set that
mixes algorithm/iterations/salt, since hashes computed under different parameters are incomparable
and a mixed set lets a matching record be paired with an incomparable covering one.

Opt-Out is handled as an assertion problem rather than a flag: `nsec3_proves_nothing` says a covering
Opt-Out record asserts nothing about what it covers (§6¶3 — reading it as a denial is the attack), and
`ClosestEncloserProof.via_opt_out` exists so the resolver can obey RFC 5155 §9.2¶1's AD-bit
prohibition when it gets there.

**My own arithmetic error, caught by the tests:** I asserted `*.example.` sorts between `a.example.`
and `z.example.`. The asterisk is 0x2A, below every letter, so it sorts between the apex and
`a.example.` — the test failed, the span logic was right, and the corrected test now documents where
the label actually falls (the same lesson RFC 4034 §6.1¶4's vector teaches with \001 and \200).

**Not claimed**: §8.5 as amended by **erratum 3441** (No Data for an empty non-terminal under an
Opt-Out span must carry the closest *provable* encloser proof) and §8.6-§8.9 (DS no-data, wildcard
no-data, wildcard answers, referrals to unsigned subzones). Nothing is wired to a `DnsPacket` yet.
Note also **erratum 4622** on the *server* side (§7.2.8): as published its second condition can never
hold, because the NSEC3 type exists at its own owner name — relevant when we have to *accept* such
NXDOMAIN answers.

**Verified**: 1059 passed (+26), `ruff check .` / `ruff format --check .` clean, `mypy namespy`
exits 0, `python -O -m pytest -q` clean.

**Next**, in the order that unblocks most: the `DnsCache` change that lets a cached negative answer
carry its proof records — that is what connects this module to a real response, and it is also all
that stands between us and RFC 8020 §2¶5's MUST; then the response-level validators (§8.5 with
erratum 3441, §8.6-§8.9) and `NxdomainPolicy.VALIDATED`; then ECDSA/EdDSA key and signature
encodings (RFC 6605 §4, RFC 8080 §3) and the verification calls through `namespy[crypto]`.

## Previous round: MQTYPE (RFC 10029)

Shipped: the wire form of both options in both directions, the server's half of using them
(§3.4's combination), and now the client's half too — `RecursiveResolver.resolve_bundle`
asks, `namespy.bundle` reads, and `--mqtype` puts both on the command line, so an
A + AAAA + HTTPS lookup is one descent instead of three.
`namespy/mqtype.py` composes MQTYPE-Query (20) and MQTYPE-Response (21), parses either,
and holds the §3.3 rules on the way out as well as the way in — §3.2 makes a client
responsible for "packets that conform to the server request parsing rules described in
Section 3.3", so one `_offence()` serves both ends and they cannot drift apart about what
is valid. Two codes rather than one code plus a flag, because the directions are not
symmetric: §3.3 refuses an inbound MQTYPE-Response outright, while §3.5 makes the
*absence* of one the way a server says it does not support the extension — so an inbound
response option is a FORMERR and an empty outbound one is a legal "supported, but there
was nothing to combine" (Appendix A.3's DS-plus-NS figure is exactly that case). Things
worth knowing before editing:

- `mqtype_supported()` never raises and `mqtype_answered_qtypes()` does, on purpose. A
  second option, a repeated QTx, or a QTx equal to the primary QTYPE means "treat the
  answer as invalid (equivalent to FORMERR)" (§3.5), which is a *different* instruction
  from "unsupported"; one boolean covering both would keep using an answer the client was
  told to discard.
- Whether a number may be a QTx is RFC 6895 §3.1's partition, not a range check, which is
  why `enums.rrtype_class()` is new: `OPT` (41) is a Meta-RR numbered *inside* the data
  band, 128–255 is a gap the allocation policy never gave to data, and an unassigned 300
  is a perfectly good QTx (refusing it would repeat RFC 3597 §3's mistake). `NXTYPE` (40)
  and `OPT` (41) are the trap a `<= 55` test walks straight into.
- `qtypes_still_needed()` is a work list, not a negative answer. A missing QTx has four
  innocent reasons — §3.5's own list — and none of them is NXDOMAIN or NODATA, so no
  caller may cache a negative from it.
- The combine loop runs inside the egress slot the primary lookup took, so what RFC 10029
  §4 says about amplification stays true of this server: one client, one outstanding
  upstream query at a time, whatever it asked for. `_standalone_query` sets
  `edns_override=True` because the copy of the requestor's OPT is what carries the copy of
  its payload size — and it drops the MQTYPE-Query on the way, because a query that echoes
  a QTx at the responder is a second question, not the same one asked twice.
- Three stops, three meanings, one list. The size rule withdraws a QTx it cannot deliver
  whole — measured by `_prospective_size`, which pays for the option's own octets before
  naming a type — and the records go back the way they came; `max_qtypes` shortens the
  work list because an operator decided a question may not cost that many lookups; a `TC`
  primary forbids the extra queries outright, since the complete answer can only arrive
  over TCP, where the loop runs again and the option travels with the answer that reaches
  the requestor. All three return `answered` as far as it got. RFC 8914 §3's
  drop-EDE-first rule rebuilds an oversized reply *around* the MQTYPE-Response: the
  explanation is the one option a size rule is allowed to eat.
- `_record_key` is RFC 2181 §5's identity plus the section, deliberately. TTL is not part
  of what makes a record the same record, and a NODATA answer legitimately carries one SOA
  twice — once in the Answer section denying the type, once in the Authority section
  proving the name exists. Keying without the section quietly "fixes" that.
- `namespy/bundle.py` reads and never sends; the resolver walks and never interprets. That
  split is what keeps a cached lie out of the design: the reader decides what an answer says
  about each requested QTYPE (`BundleState`), and the resolver decides what may be stored,
  which is only what the answer vouched for. An unlisted type is `NEEDED`, §3.5's four
  innocent reasons being the reason it is a work list rather than a verdict, and
  `resolve_bundle` re-asks it (§3.5: "The client MUST subsequently initiate separate
  standalone queries") unless the caller passes `ask_separately=False`.
- `supported` and `void` stay two fields, and the void is handled in `resolve_steps` *before*
  classification reaches the cache. A duplicated QTx or a second MQTYPE-Response is
  "equivalent to FORMERR" (§3.5) and discards the primary answer with it, so a client that
  cached the primary on its way to rejecting the bundle would be storing an answer it has just
  been told to throw away; `test_an_invalid_answer_is_discarded_before_it_reaches_the_cache`
  is the pin. Unsupported is the opposite case — the answer is good and is used as-is.
- The option is threaded through the walk rather than attached to one query, and the lookups
  that merely support the walk are kept out of it. A QNAME minimisation probe sets
  `bundle = ()` explicitly: it asks about a shorter name than the extras were requested for,
  so §3.4's per-combination flags would be the probe's and a server would be invited to
  combine RRsets for a name nobody asked about (`test_a_minimisation_probe_never_carries_it`).
  Glue sub-resolution needs no such guard — the list travels only in the one walk that was
  handed it, so every other walk starts empty by construction.
- `BundledType.separate` says whether a type's answer arrived in the combined reply or in a
  query of its own, and only `reasked()` ever sets it. It looks redundant next to `response`,
  which a re-ask fills in at the same moment, and it is not: `--mqtype` against today's
  authoritative servers takes the re-ask path *every time*, and the first version of the CLI
  report printed "combined: 2 record(s) in the answer above" over an Answer section holding
  two A records. Where an answer came from is a fact about the exchange, not something a
  renderer should infer from a record being present — `test_an_answer_bought_separately_is_not_reported_as_combined`
  is the pin, and `_format_short` filters on the same field rather than on record identity.
- The UDP fallback is three tiers in RFC 6891 §6.2.2's own order: FORMERR whose reply carries
  an OPT loses the MQTYPE-Query and nothing else; FORMERR with no OPT loses EDNS entirely;
  both re-run the walk. A server that has never seen option 20 therefore costs one more
  exchange, never an answer — which is the same promise `--nsid` makes.

§4's four-QTx guideline is exported as `MQTYPE_RECOMMENDED_QTX_LIMIT`, which is the default
of `DnsServer(max_qtypes=...)` and the default of the CLI's `--max-qtypes` — one constant, so
the two cannot drift
about what an undecided operator gets. An operator may raise it, or pass `None` to leave
the list bounded only by what an EDNS option can hold at all: §3.1 gives OPTION-LENGTH no
count field of its own, so it is RFC 6891's 16-bit option length (which `EdnsOption`
enforces) and the advertised UDP payload that cap the list, not any number RFC 10029
states. Zero is worth naming because it is not a smaller version of the same
refusal: it answers the option and combines nothing, which is a server declining this
much work, while silence is a server that cannot do the extension at all. Passing the
flag is what keeps the CLI honest here — an absent `--max-qtypes` wired through as
`None` would have quietly meant *unlimited*, which is the opposite of the conservative
default §4 asks for.

The asking side is deliberately not held to that number. §4's guideline is advice about how
much work to take on, `query_option_for` enforces only what §3.3 makes mandatory, and a server
that thinks a list is too long already has a legal way to say so: leave the tail out (§3.5's
"the server was unwilling to process the request (for example, because a limit was exceeded)"),
which the client reads as work left over and re-asks. So five `--mqtype` flags may return four
combined and one fetched separately; what they can never do is turn that omission into a
negative answer about the name.

`tests/test_mqtype.py` (44 tests, Appendix A's three figures as the oracle), sixteen
tests in `tests/test_server.py` — the refusals, the combination rules down to the bytes of
the option on the wire, the operator's limit at both ends of its range, and one test that
holds the EDE and MQTYPE size rules in the same packet — and 22 in `tests/test_enums.py`
pinning every boundary of the §3.1 table. `mqtype.py` is at 100% coverage. On the asking
side, `tests/test_bundle.py` (28) covers the reader — §3.5's outcomes, every invalid shape,
the ownership rules a harvest is held to — and `tests/test_resolver_mqtype.py` (28) covers
what a walk does with it: the option on the real question and never on a minimisation probe,
the three fallbacks, the cache rules including the one that must never fire, and demotion
when a server on the path contradicts itself. Twelve more in `tests/test_cli.py` hold the
flag and its rendering. `bundle.py` is at 100% coverage too.

### Follow-up: the two halves, on one wire

The asking side shipped with every test on one side of the exchange writing the bytes the
other side read — which proves nothing about whether the two agree. `tests/test_mqtype_interop.py`
now runs a real `RecursiveResolver` against a real `DnsServer`:

- The splice is at the **transport**, not at `query()`. `_Loopback` replaces the client's
  socket with a queue; a pump task hands the bytes to `DnsServer.datagram_received` and feeds
  the reply back through `Resolver.datagram_received` under the *peer address the query went
  to*. That last part is not a detail: `_pending_key` implements RFC 5452 §9.1 (address + ID +
  question), so the client's matching discipline is still under test with the wire simulated.
  Splicing at `query()` instead would have had the test build the packet itself, which means
  re-implementing the encoder it is supposed to be proving.
- The server's upstream is stubbed at `resolver.resolve` (the same seam `test_server.py`
  uses) and the client's whole world is one seeded root, so a bundled lookup is one datagram
  and a declined one is three — which is what the tests count.
- **It caught a real defect immediately.** Ten fixtures used `b"\x00\x00\x00\x01"` as HTTPS
  RDATA: priority 0, target `.`, one stray octet — malformed under RFC 9460 §2.2, which is why
  the client was discarding an otherwise perfect reply. They survived because those records
  never went through the wire codec. The lesson is general: a hand-built `DnsRecord` is not a
  parsed one, and any fixture that claims to hold RDATA should be able to survive
  `bytes(record)` and come back.

`--trace` gained the visibility the CLI report already had. `SendQuery.extra_qtypes` was
already on the effect, and the re-ask traces already existed — they were just thrown away when
`resolve_bundle` restored the bundling descent, so the file showed one descent for a run that
had sent three. Bundling hops now render as `(mqtype +2)` and each re-ask is a child trace
(`_walk(..., trace=)`, the same mechanism glue sub-resolution uses). Note the contract the test
pins: **the child's title is set by `_walk`, not by the caller**, because qualification happens
inside the walk — a child titled from the caller's relative name would disagree with the
query on the wire.

Also fixed here: `docs/rfc-map.md` still claimed EDNS(0) was decoded but never sent, and its
code-mapping table had no row for any of the last four features. When a feature lands, its row
belongs in that table in the same commit — that document is where a contributor looks to find
out whether a rule is deliberately absent.

## Earlier round: Extended DNS Errors (RFC 8914)

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
What remains in `docs/roadmap.md`, in order: wildcard synthesis (4592 §2.2) is now at the
head of the queue -- MQTYPE's asking side, which used to lead it, shipped in the round above.

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

## An earlier round: RFC 9520 failure caching (`FailureCache`)

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

## Earliest round: EDNS option TLV + per-server payload adaptation

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
ved.
