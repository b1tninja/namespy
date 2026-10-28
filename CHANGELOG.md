# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project intends [semantic versioning](https://semver.org/spec/v2.0.0.html), though
nothing has been tagged or published yet, so `master` is the only version.

## [Unreleased]

### Added

- QNAME minimisation (RFC 9156), opt-in: `RecursiveResolver(qname_min=True)`
  or `namespy --qname-min`. Servers not known to be authoritative for the
  full name receive progressively deeper children — the section 2.3 probe
  schedule is pinned by `test_minimis.py`, the descent integration by
  `test_qname_min.py`. Terminal *probe* responses demote and continue
  (section 3 step 4) instead of answering for the original QNAME; budget
  exhaustion degrades to full-name queries; `--trace` marks probes. Off by
  default because it changes wire behaviour toward every downline server;
  CNAME chasing deliberately keeps full names.
- `RecursiveResolver.aclose()`, plus `async with` support, releases every socket
  a resolver owns: the endpoint transport asyncio attached, the private IPv6
  socket it opens for AAAA glue, and a bring-up task still in flight. Fails are
  completed with `RuntimeError` rather than cancelled, so a caller's
  `asyncio.wait_for` reports that *this* resolver closed instead of appearing to
  have been cancelled from outside. Both CLI modes use it, and the library
  example in the README now shows it next to `transport.close()`. Pinned by
  `test_resolver_lifecycle.py`.
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

- **Out-of-bailiwick glue is no longer believed (RFC 5452 section 6).** A
  referral's address records are accepted only for a nameserver name inside the
  zone that answered, or inside the zone that referral delegated -- RFC 1034
  section 4.2.1 makes a parent responsible for exactly that glue, and nothing
  else it volunteers is credible. Before this, any A/AAAA in the additional
  section was used, so a delegation could aim the rest of a lookup, and the
  queries sent while performing it, at an address of its own choosing. A
  discarded address leaves the nameserver as a name that needs resolving, which
  the existing `NeedAddress` sub-resolution satisfies from the servers that are
  authoritative for it (RFC 1034 section 4.2.2). Pinned by
  `test_resolver_classify.py`; the two-hop descent in `test_resolve_steps.py`
  now walks that sub-resolution instead of believing the volunteered address.
- Every RFC citation in the tree was re-checked against the published texts.
  The corrections were mostly to section numbers that do not exist or say
  something else: response matching is RFC 5452 section 9.1 (not 5), ID and
  source-port randomisation is section 9.2, in-domain acceptance is section 6,
  and RFC 5625 -- DNS Proxy Implementation Guidelines -- has no section 2.5 at
  all; its packet-filtering advice is section 6.3.
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

- EDNS(0) on the wire (RFC 6891, full implementation at `HEAD`): OPT on
  every outbound query (§6.1.2) advertising a 1232-octet payload with the
  512 floor enforced (§6.2.3), the EXTENDED-RCODE | VERSION | FLAGS TTL
  layout and 12-bit RCODE reassembly (§6.1.3), the §7 FORMERR-without-OPT
  signature plus BADVERS/NOTIMP driving exactly one unextended re-ask
  (§6.2.2), and an OPT that is never cached (§6.2.1). `--no-edns` or
  `edns_payload_size=0` opts out entirely. Remaining EDNS work (options
  TLV, per-server payload adaptation, responder-side echo) is roadmap P1
  in [`docs/roadmap.md`](docs/roadmap.md).
- `docs/roadmap.md` — the specification-completeness matrix: every
  obligation the code could take on, status, and the test that pins it,
  consolidating into a prioritised roadmap. README links it as the
  project's planning document.
- `tests/test_edns.py` (17 tests) — the OPT on the wire, TTL bit layout
  against RFC diagrams, fallback matrix, cache exclusion, knob plumbing.

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

- `RecursiveResolver.enumerate_nameserver_addresses()`, an undocumented public
  static helper with no callers and no tests. It paired every NS in a referral
  with any address record in the additional section that shared its name, with
  no zone context and therefore no way to apply the bailiwick rule above -- in
  other words, a ready-made way to reintroduce the bug that was just fixed.
  `classify()` is where a referral is consumed and it performs the check; a
  caller that needs the shuffled-server behaviour is served by `Slist`, which
  already shuffles its candidates (RFC 8106 section 2).
- `namespy/dns.py` (empty), `Forwarder` (a constructor that did nothing), the
  unreachable `self.resolver.db` references, and the committed `dns.sql` /
  `database.png` scratch — legacy SQL notes moved to `docs/legacy/`.
- Tracked generated files: `last_resolution.md` (in two places), `.cursor/plans/`.
  `.gitignore` now matches what is actually tracked.

### Known gaps

Tracked honestly rather than as a promise — full list with reasons in
[`docs/HANDOFF.md`](docs/HANDOFF.md):

- EDNS(0) *options* are not implemented: OPT RDATA is written empty and read
  opaquely, so no NSID (RFC 5001), COOKIE (RFC 7873) or per-server payload
  adaptation (RFC 6891 section 6.2.3), and the bundled server does not echo
  OPT in its responses (section 6.2.4). The core record, the 1232-octet
  advertisement and the section 6.2.2 fallback do ship.
- No DNSSEC validation, no serve-stale (RFC 8767), no IDN/punycode
  (RFC 5891 / RFC 3492), no DoT/DoH (RFC 7858 / RFC 8484). QNAME
  minimisation (RFC 9156) ships opt-in — see *Added*.
