# Specification completeness — and the roadmap it implies

This is the project's north star: every protocol obligation namespy could
plausibly take on, with an honest status against the code and tests at
`HEAD`. It is deliberately blunt about gaps — three of them change the
security properties of anything built on top, and pretending otherwise would
make this document useless as a planning tool.

**The honesty rule:** ✅ requires a named test, and a row may only say ✅
when that test would fail if the behaviour regressed. Reading code and
agreeing is not enough; that is how "EDNS is decoded but not sent" nearly
became "EDNS is done".

Legend: ✅ implemented and pinned by tests · 🟡 partial (what is missing is
stated) · ⬜ not implemented · ▫️ deliberate non-goal.

When you change behaviour that a row describes, update the row in the same
commit — the same rule [`CONTRIBUTING.md`](../CONTRIBUTING.md) states for
code citations. [`rfc-map.md`](rfc-map.md) remains the deep RFC 1034 §5.3.3
walkthrough; this document is the cross-specification survey.

## 1. Wire format and message parsing

Spec anchors: RFC 1035, RFC 2181, RFC 9267, RFC 3597, RFC 4343, RFC 3688.

| Obligation | Spec | Status | Where |
|---|---|---|---|
| Header fields, all 12 octets, both flag halves | 1035 §4.1.1 | ✅ | `test_packet_wire.py` |
| Question section on queries *and* responses | 1035 §4.1.2 | ✅ | `test_packet_wire.py`, `test_resolver_matching.py` |
| RR wire form: TYPE/CLASS/TTL/RDLENGTH/RDATA | 1035 §3.2.1, §4.1.3 | ✅ | `test_packet_wire.py`, `test_rdata_wrapping.py` |
| Name wire form; compression pointers *and* pointer-to-pointer chains on decode | 1035 §3.3, §4.1.4 | ✅ | `test_names_wire.py` |
| Pointer strictness: `(offset & 0xC0) == 0xC0`, reserved label types rejected, targets strictly decrease, 255-octet expanded cap | 9267 §2–§4 | ✅ | `test_packet_wire.py` |
| RDATA accounted inside RDLENGTH in **both** directions (overrun *and* under-run) | 9267 §5 | ✅ | `test_review_fixes.py`, `test_fuzz_wire.py` |
| Canonical, compression-free serialisation (the sqlite cache re-parses standalone) | design contract | ✅ | `test_rdata_wrapping.py` |
| Unknown TYPE/CLASS pass through opaquely; `\# len hex` presentation | 3597 §3, §5 | ✅ | `test_enums.py`, `test_packet_wire.py` |
| Labels are octet strings: `_dmarc`, `_smtp._tcp`, any 0–255 octets | 2181 §11, BCP 222 | ✅ | `test_names.py` |
| Name comparison is case-insensitive octet folding | 1035 §2.4.4, 4343 §2.1 | ✅ | `test_names.py` |
| Length limits: 255-octet names, 63-octet labels | 1035 §2.3.4, 2181 §2 | ✅ | `test_names_wire.py` |
| Served TTLs clamped to 2³¹−1 — an unclamped `0xFFFFFFFF` is a forever cache entry | 2181 §8, 3688 §1 | ✅ | `test_review_fixes.py` |

## 2. Transport and truncation

| Obligation | Spec | Status | Where |
|---|---|---|---|
| UDP query/response correlated by source + ID + echoed question | 5452 §5 | ✅ | `test_resolver_matching.py` |
| `TC=1` re-asked over TCP; a truncated answer is never returned and never cached | 1123 §6.1.3.2, 1035 §7.4, 7766 §6 | ✅ | `test_resolver_truncation.py` |
| UDP timeout re-asks over TCP | 1035 §4.2.2, 7766 §6 | ✅ | `test_resolver_truncation.py` |
| TCP framing: 2-octet length prefix, same query re-sent verbatim | 7766 §3.1, §6 | ✅ | `test_resolver_truncation.py` |
| DNS over TLS / HTTPS / QUIC | 7858, 8484, 9250 | ⬜ | roadmap P4 |

## 3. EDNS(0) — RFC 6891

Shipped at `HEAD`; every row below is driven by `tests/test_edns.py`.

| Obligation | Spec | Status | Where |
|---|---|---|---|
| OPT on outbound queries: NAME=root, TYPE 41, CLASS = advertised payload (default 1232) | §6.1.2 | ✅ | `test_query_advertises_edns`, `test_query_carries_an_edns0_opt_record` |
| OPT TTL layout: EXTENDED-RCODE \| VERSION \| FLAGS, empty RDATA — eleven octets | §6.1.3 | ✅ | `test_add_edns_places_version_in_bits_16_to_23_and_flags_in_the_low_half`, `test_opt_is_eleven_octets_at_the_tail_of_the_message` |
| Extended RCODE: effective = `(OPT upper << 4) \| header`; 16 = BADVERS survives reassembly | §6.1.3 | ✅ | `test_extended_rcode_reads_the_upper_bits_from_opt_ttl`, `test_badvers_round_trips` |
| FLAGS/DO placement encoded and exposed (no DNSSEC consumer yet — see §8) | §6.1.4 | ✅ | `test_version_and_flags_round_trip` |
| Advertised payload below 512 treated as 512 | §6.2.3 | ✅ | `test_advertised_payload_floors_at_512` |
| FORMERR with no OPT in the response → the §7 signature of a non-EDNS server → unextended re-ask | §7 | ✅ | `test_edns_rejection_triggers_exactly_the_documented_fallback` |
| BADVERS and NOTIMP also force the unextended re-ask; FORMERR *with* OPT does not | §6.2.2, §7 | ✅ | same matrix test, five parametrised cases |
| OPT is never cached | §6.2.1 | ✅ | `test_opt_is_never_cached` |
| OPT replaces rather than stacks; removable; whole feature disableable (constructor knob + `--no-edns`) | design | ✅ | `test_add_edns_replaces_rather_than_stacks`, `test_edns_can_be_disabled_whole` |
| EDNS **options** (option-code/length TLVs): NSID (5001), COOKIE (7873), Padding (7830) | §6.1.2, 5001, 7873, 7830 | ⬜ | roadmap P1 — OPT RDATA is written empty and read opaquely |
| Per-server payload adaptation to the responder's advertised CLASS | §6.2.3 (SHOULD) | ⬜ | roadmap P1 — advertised size is static today |
| Responder-side duties: OPT in every response of an EDNS-aware server | §6.2.4 | ⬜ | roadmap P1 — the demo server ignores OPT; loopback-only, see §8 |

## 4. Resolution — RFC 1034 §5.3.3

The algorithm itself is the deep dive in [`rfc-map.md`](rfc-map.md); here it
is one row per obligation.

| Obligation | Spec | Status | Where |
|---|---|---|---|
| Iterate from the roots; never send RD=1 | §5.3.3, §4.3.1 | ✅ | `test_resolve_steps.py`, `test_resolver_e2e.py` |
| SLIST selection, demotion on failure, retry without discarding the server | §5.3.3(d), 5625 §2.6 | ✅ | `test_resolve_steps.py` |
| Referral following, including glueless NS sub-resolution | §3.6.3–§3.6.4 | ✅ | `test_resolve_steps.py` |
| CNAME chasing with a hop bound | §5.3.3(c) | ✅ | `test_resolver_alias.py` |
| DNAME substitution and restart at the zone cut — the non-CNAME alias | 6672 §5 | ✅ | `test_resolver_alias.py` |
| NXDOMAIN vs NODATA distinguished by authority content | 2308 §2.2.1 | ✅ | `test_resolver_classify.py` |
| Negative answers cached at `min(SOA.MINIMUM, SOA TTL)` | 2308 §5 | ✅ | `test_cache.py`, `test_resolve_steps.py` |
| CNAME-chain and alias-expansion bounds | 1034 §3.6.2 | ✅ | `test_resolver_alias.py` |
| Wildcard matching and synthesis of the closest encloser | 4592 §2.1–§2.2 | ⬜ | roadmap P2 — names carry an `is_wildcard` flag; no synthesis |
| QNAME minimisation | 9156 §4 | ◐ | `namespy/minimis.py` lands the §2.3 schedule + probe walk (`test_minimis.py`); descent-loop integration is the remaining half — roadmap P2 |
| Serve-stale on upstream failure | 8767 | ⬜ | roadmap P3 |

## 5. Cache poisoning resistance — RFC 5452, RFC 5625

| Obligation | Spec | Status | Where |
|---|---|---|---|
| Response accepted only on matching source address, transaction ID **and** echoed question | 5452 §5–§6 | ✅ | `test_resolver_matching.py` |
| Randomised transaction IDs, ephemeral source port | 5452 §5 | ✅ | constructor path, `test_resolver_matching.py` |
| Refusal of a reply that omits the question section | 1035 §4.1 | ✅ | `test_resolver_matching.py` |
| In-bailiwick glueless NS refused as lame | 5625 §2.5 | ✅ | `test_resolve_steps.py` |
| Out-of-bailiwick glue and extra-section records filtered | 5625 §2.5 | ⬜ | roadmap P1 — the reverse case of the row above; a server can still plant address records above its zone cut |
| 0x20 QNAME-case encoding as extra entropy | 6841 | ⬜ | roadmap P3 — marginal over port+ID+question without DNSSEC |

## 6. DNSSEC — RFC 4033/4034/4035

| Obligation | Spec | Status | Where |
|---|---|---|---|
| `AD` and `CD` bits decoded and exposed, never asserted | 6891 §6.1.4, 4035 §2 | ✅ | `test_edns.py`, `test_packet_wire.py` |
| RRSIG and the DNSSEC record codecs | 4034 §3 | ⬜ | roadmap P3 |
| Validation pipeline: trust anchor → DS → DNSKEY → RRSIG, NSEC/NSEC3 proof | 4033 §3, 4035 §2, 5155 | ⬜ | roadmap P3 — the single largest gap; everything today is unauthenticated |

## 7. Names beyond ASCII

| Obligation | Spec | Status | Where |
|---|---|---|---|
| Octet-transparent storage (A-labels pass through untouched) | 2181 §11, 5890 §2.3 | ✅ | `test_names.py` |
| A-label encode/decode, punycode, validity checkpoints | 5891, 3492 | ⬜ | roadmap P2 — callers must pre-encode today |

## 8. The bundled server

`namespy --serve` is a codec exercise bound to loopback; the obligations it
takes on are the ones that keep it from becoming a weapon.

| Obligation | Spec | Status | Where |
|---|---|---|---|
| Loopback bind only; documented why an open resolver is an amplification instrument | 5358, 9085 | ✅ | `test_server.py`, `SECURITY.md` |
| Malformed datagrams dropped at `DEBUG`, never logged louder | 5358 §4.2 rationale | ✅ | `test_review_fixes.py` |
| Concurrent lookups and task creation bounded; excess dropped silently | 5625 §6.2 | ✅ | `test_server.py`, `test_review_fixes.py` |
| QDCOUNT ≠ 1 → FORMERR; unsupported OPCODE → NOTIMP, question echoed | 1035 §4.1, 5452 §5 | ✅ | `test_server.py` |
| OPT echoed in responses; EDNS-aware responder | 6891 §6.2.4 | ⬜ | roadmap P1 — pairs with the §3 responder row |
| Rate limiting, RRL, cache sharing | 5358 §3, 9085 §4 | ▫️ | non-goal — it is a test fixture, not a service; `SECURITY.md` says so |

## 9. Packaging and process

| Obligation | Reference | Status | Where |
|---|---|---|---|
| Typed distribution: `py.typed`, sdist+wheel audited, zero runtime dependencies | — | ✅ | `tools/check_dist.py` in CI |
| Suite green under `python -O` (no `assert` on wire paths, ever) | project rule 1 | ✅ | CI job, `CONTRIBUTING.md` |
| Trusted publishing with provenance; no stored credentials | — | ✅ | `release.yml` |
| Every RFC citation live-checked against the document itself | project rule 10 | ✅ | review practice, `docs/HANDOFF.md` |

---

## The roadmap, consolidated

Priority is ordered by what changes the security or correctness properties
of code built on namespy, not by implementation cost.

| # | Item | Spec | Why it ranks here | Cost |
|---|---|---|---|---|
| **P1** | Bailiwick filter for out-of-zone glue | 5625 §2.5 | a hostile delegation can still plant addresses above its zone cut — the *remaining half* of a defence the code already claims | small |
| **P1** | EDNS options TLV parse/emit, then per-server payload adaptation | 6891 §6.1.2/§6.2.3, 5001 | unlocks NSID for debugging; shrinks the truncation/TCP detour that dominates big answers | small–medium |
| **P1** | Server echoes OPT; EDNS-aware responses | 6891 §6.2.4 | makes the demo server honest about what it claims on the wire | small |
| **P2** | QNAME minimisation (integration) | 9156 | privacy: today the full name leaks to root and TLD servers; schedule module done, loop integration is the rest | medium |
| **P2** | IDNA/punycode | 5891/3492 | correctness for internationalised names; currently the caller's job | medium |
| **P2** | Wildcard synthesis | 4592 | needed before results can claim RFC-identical semantics for `*.example` zones | medium |
| **P3** | DNSSEC validation (4033/4034/4035, 5155) | — | the largest trust gap and the largest project: trust anchors, crypto (a dependency decision against the zero-dependency promise), proof checking | large |
| **P3** | Serve-stale | 8767 | availability win; depends on cache bookkeeping DNSSEC also wants | medium |
| **P3** | 0x20 encoding | 6841 | marginal over port+ID+question without DNSSEC; deliberately late | small |
| **P4** | DoT / DoH / DoQ | 7858/8484/9250 | transport security matters, but each is a new subsystem with its own failure modes | large |
| — | Rate limiting / RRL for the server | 5358/9085 | ▫️ non-goal: loopback fixture, not a service | — |

The three P1 items are small, self-contained, and each closes an obligation
the surrounding code already cites — which makes them the natural next
release.
