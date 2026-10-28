# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project intends [semantic versioning](https://semver.org/spec/v2.0.0.html), though
nothing has been tagged or published yet, so `master` is the only version.

## [Unreleased]

### Added

- Security CI (`.github/workflows/security.yml`): CodeQL with `security-extended`
  (weekly and on change), `dependency-review` on every pull request, and
  `pip-audit` over the resolved dev environment. `socket.yml` screens every
  dependency install through the Socket.dev firewall. `master` is protected:
  all checks must pass, strictly, before anything lands.
- Release path completed (`.github/workflows/release.yml`): SLSA build
  provenance via `actions/attest`, PyPI attestations via trusted publishing,
  a `pypi` deployment environment scoping who can mint an upload credential,
  a GitHub Release created only after PyPI accepted the artifacts, and a
  `workflow_dispatch` rehearsal path that no longer trips its own tag check.
- `tests/test_review_fixes.py` — locks every finding from the correctness
  review (TTL clamp, trailing-RDATA refusal, empty-label refusal, cancellation
  pending-slot release, log-level discipline, server spawn bound).

### Changed

- **Record TTLs are now clamped to 2147483647 (RFC 2181 section 8).** The
  clamp existed as `clamp_ttl()` but was never called: a hostile or buggy
  server offering `0xFFFFFFFF` produced a cache entry that never expired,
  which is a poisoning half-win that lasts forever.
- **NS/CNAME/PTR/DNAME RDATA with trailing octets is refused.** Only the
  overrun direction was checked, so `RDLENGTH = name + garbage` half-parsed;
  MX, SRV and SOA already failed closed, and RFC 9267 section 5 says the
  whole declared length must be accounted for.
- **TXT with an empty RDLENGTH is refused** (RFC 1035 section 3.3.14: one or
  more `<character-string>`).
- **Interior empty labels are no longer silently erased.** `DomainName("a..b")`
  used to encode as `a.b`, collapsing two distinct names onto one wire form;
  the encoder now refuses, which is honest because no wire form for an
  interior empty label exists.
- **Compression pointer octets no longer count against the 255-octet name
  budget** — RFC 1035 section 3.1 bounds the expanded name, not the encoding;
  the old accounting rejected valid wide names carried on pointers.
- **Wire-parsed names carry their correct start offset** in `.offset` (it
  held the post-pointer resume point, or `None`).
- Non-ASCII digit-like characters in presentation names no longer raise
  `ValueError` from the `\DDD` escape decoder.
- Resolver IPv4 malformed-datagram logging dropped to `DEBUG`; the IPv6 path
  and the server already stayed quiet, and a `WARNING` + hex dump per spoofed
  datagram is a free log-flood primitive.
- **Cancelling an awaited UDP query releases its pending slot.** The timeout
  path popped it; cancellation — the common case on caller timeouts and
  reconnects — did not, growing the pending dict for the resolver's lifetime.
- **The server bounds task creation, not just concurrent lookups.** Under a
  datagram flood it previously minted one coroutine per packet before any
  semaphore; excess traffic is now dropped silently per RFC 5625 section 6.2.

### Added earlier in this effort

- `LICENSE` — Apache-2.0. The repository previously had none, which meant
  "all rights reserved" by default and no one could lawfully use the code.
- GitHub Actions CI: lint, a 3.12/3.13 × Ubuntu/Windows test matrix, a run of the
  whole suite under `python -O`, and a distribution-audit job
  (`.github/workflows/ci.yml`). Dependabot for pip and Actions.
- A release workflow gated on `v*` tags, using OIDC trusted publishing. Dormant
  until the PyPI project and its `pypi` environment exist; see the comments.
- `tools/check_dist.py` — asserts a built wheel *and* sdist contain
  `namespy/named.root`, `namespy/py.typed` and the license text, and that generated
  files have not leaked in.
- `SECURITY.md`, `CONTRIBUTING.md`, `docs/rfc-map.md` (spec obligation → code →
  test), `docs/HANDOFF.md`, `docs/legacy/`.
- Tests: `test_names_wire.py`, `test_packet_wire.py`, `test_resolver_matching.py`,
  `test_resolver_alias.py`, `test_server.py`, `test_cli.py`, `test_enums.py`.
  Coverage went from unmeasured to 80%+ with an enforced floor; `server.py` was
  previously untested entirely.
- `RData_DNAME`, and CNAME/DNAME chain following in the resolver.
- `DomainName.from_labels()`, `DomainName.is_subdomain_of()`,
  `DomainName.is_hostname`, `DomainName.is_wildcard`, `RData_SOA.serial_ahead()`,
  `RData_TXT.from_text()` / `.text`, `RData_MX.is_null_mx`.
- `namespy/py.typed`, a `namespy` console script, and `[project.urls]`.
- `TC` now triggers a TCP retry. A UDP response with the truncation bit set, or a
  UDP attempt that times out, is re-asked over TCP to the same server
  (RFC 1123 section 6.1.3.2, RFC 7766 section 6). A truncated UDP answer is never
  returned, and no truncated response is ever cached — a partial RRset is
  indistinguishable from a complete one once stored (RFC 1035 section 7.4).

### Changed

- **Wire parsing no longer uses `assert` for bounds checks.** Everything on a
  network path raises `DnsPacketParseError`. The previous behaviour was that
  `python -O` removed every length check in `names.py`, `packet.py` and
  `rdata.py`.
- Compression pointers are validated the way RFC 9267 section 2 requires: the
  2-bit test is `(offset & 0xC0) == 0xC0` rather than `offset & 0b11000000`,
  reserved types `10`/`01` are rejected, targets must strictly decrease, and
  expanded names are capped at 255 octets counting label-length octets.
  Pointer-to-pointer chains — valid wire form that used to raise — now parse.
- RDATA is parsed inside its declared RDLENGTH (RFC 9267 section 5) instead of
  being sliced twice, which silently accepted a short RDATA and walked into the
  next record.
- Unknown RR types and classes decode to opaque `RData` per RFC 3597 section 3
  instead of raising `AttributeError` from a protocol callback. `DnsRType` gained
  `SVCB` (64), `HTTPS` (65), `CSYNC` (62), `ZONEMD` (63) and others;
  `DnsResponseCode` gained the EDNS(0) extended values.
- Responses are matched on source address + transaction ID + **question section**
  (RFC 5452 sections 5–6), not address + ID alone. A reply that omits the question
  section is no longer accepted.
- A non-authoritative `ANCOUNT == 0` response with NS records in the authority
  section is no longer classified as a referral when the authority section holds
  an SOA — the NODATA/NXDOMAIN distinction RFC 2308 section 2.2.1 requires.
- `RData_SOA` is serialisable (it previously raised `AttributeError` on `bytes()`,
  so any response containing an SOA could not be re-emitted), parses `MINIMUM`
  (RFC 2308 section 5), and compares serials with RFC 1982 wrap-around arithmetic.
- Name labels follow RFC 2181 section 11: any octet string is storable, with LDH
  checking moved to the opt-in `is_hostname`. `_dmarc.example.com`,
  `_smtp._tcp.example.org` (BCP 222) and `*.example.com` (RFC 4592) now parse.
- TTLs are clamped to 2147483647 when served (RFC 2181 section 8).
- The resolver no longer performs blocking network I/O in `__init__`. Root hints
  come from the packaged `named.root` via `importlib.resources`; refreshing is an
  awaited `refresh_root_hints()` call.
- `MAX_HOPS`, `MAX_DEPTH` and the query timeout became constructor arguments rather
  than module constants.
- `logging.Logger("resolver")` became `getLogger(__name__)`; malformed-datagram
  logging dropped to `DEBUG` so a garbage spray cannot use the log as an
  amplifier (RFC 5358 section 4.2). The per-datagram `print()` is gone.
- The Linux-only `IP_MTU_DISCOVER` setsockopt is platform-guarded; it previously
  raised inside `connection_made` on Windows.
- Protocol constants renamed to PEP 8 member names (`DnsQR.RESPONSE`,
  `DnsResponseCode.NO_ERROR`) so the tables read consistently; the wire mnemonics
  are preserved where RFC 1035 section 4.1.1 names the field itself.
- `record.rdata` is now always an `RData`. Hand-built records used to store the
  raw `bytes` the caller passed while parsed records held an `RData`, so
  `print(record.rdata)` showed a Python bytes literal on one path and RFC 3597
  section 5 form on the other, and consumers needed `isinstance` branches. The
  constructor now offers the octets to the registered codec and falls back to the
  opaque form when they do not decode, so `DnsRecord(name, DnsRType.SOA,
  rdata=b"")` still works and wrapping never changes the wire form — asserted for
  every registered codec by `tests/test_rdata_wrapping.py`.
- Package metadata: explicit `[build-system]` (hatchling), version `0.1.0` read
  from `namespy.__version__`, declared license, classifiers, coverage and lint
  configuration, `mypy` clean on `namespy`.

### Removed

- `namespy/dns.py` (empty), `Forwarder` (a constructor that did nothing), the
  unreachable `self.resolver.db` references, and the committed `dns.sql` /
  `database.png` scratch — legacy SQL notes moved to `docs/legacy/`.
- Tracked generated files: `last_resolution.md` (in two places), `.cursor/plans/`.
  `.gitignore` now matches what is actually tracked.

### Known gaps

Tracked honestly rather than as a promise — full list with reasons in
[`docs/HANDOFF.md`](docs/HANDOFF.md):

- No EDNS(0) on outbound queries (RFC 6891), so answers are effectively capped at
  512 octets — which is why truncation is routine rather than exotic. A truncated
  answer now retries over TCP (RFC 7766 section 6) instead of being trusted.
- No DNSSEC validation, no QNAME minimisation (RFC 9156), no serve-stale
  (RFC 8767), no IDN/punycode (RFC 5891 / RFC 3492), no DoT/DoH (RFC 7858 /
  RFC 8484).
- No bailiwick filtering of glue and additional-section records (RFC 5625
  section 2.5).
