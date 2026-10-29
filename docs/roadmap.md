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
| UDP query/response correlated by source + ID + echoed question | 5452 §9.1 | ✅ | `test_resolver_matching.py` |
| `TC=1` re-asked over TCP; a truncated answer is never returned and never cached | 1123 §6.1.3.2, 1035 §7.4, 7766 §6 | ✅ | `test_resolver_truncation.py` |
| UDP timeout re-asks over TCP | 1035 §4.2.2, 7766 §6 | ✅ | `test_resolver_truncation.py` |
| TCP framing: 2-octet length prefix, same query re-sent verbatim | 7766 §3.1, §6 | ✅ | `test_resolver_truncation.py` |
| DNS over TLS / HTTPS / QUIC | 7858, 8484, 9250 | ⬜ | roadmap P4 |

## 3. EDNS(0) — RFC 6891

Shipped at `HEAD`; the rows below are driven by `tests/test_edns.py`, the
responder's own duties by `tests/test_server.py`, and what the CLI does with an
identifier by `tests/test_cli.py`.

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
| EDNS **options** (option-code/length/value TLVs) inside OPT RDATA, written and read in the order they were given | §6.1.2 | ✅ | `test_options_survive_the_wire_in_the_order_they_were_given`, `test_the_option_helpers_describe_the_codes_they_invent` (`test_edns.py`) |
| An option code this code does not model is carried and ignored, never refused; a *misformed* one raises rather than being silently truncated | §6.1.2 | ✅ | `test_an_unregistered_option_is_carried_rather_than_rejected`, `test_a_half_written_option_raises_instead_of_stopping_early` (`test_edns.py`), `test_an_option_this_server_does_not_know_is_ignored_not_refused` (`test_server.py`) |
| A misformed option in a *query* → FORMERR, and that answer still carries an OPT — a server that implements EDNS and found the request malformed must not look like one that does not implement it | §6.1.2, §7 | ✅ | `test_a_misformed_option_is_formerr_and_still_carries_an_opt` (`test_server.py`) |
| NSID: asked for with a zero-length option, answered only when asked, ignored if a requestor hands one in | 5001 §2.1, §2.2 | ✅ | `test_nsid_of_separates_being_asked_from_being_ignored` (`test_edns.py`), `test_an_identifier_goes_only_to_a_query_that_asked_for_it`, `test_a_server_with_no_identity_never_sends_the_option`, `test_an_identifier_written_by_the_requestor_is_ignored` (`test_server.py`), `test_the_nsid_flag_is_the_empty_option_rfc_5001_asks_for` (`test_cli.py`) |
| Identifiers presented as two hex digits per octet, never as the raw bytes | 5001 §2.4 | ✅ | `test_an_identifier_is_printed_as_hex_because_it_is_opaque` (`test_edns.py`), `test_server_identifiers_are_reported_as_hex`, `test_an_identifier_a_server_handed_back_is_printed_by_the_lookup`, `test_an_identifier_request_met_with_silence_says_so` (`test_cli.py`) |
| COOKIE: 8 octets, or 16 through 40, are the only lengths the rules allow; anything else is out of range, and in a query it is FORMERR | 7873 §5.2.1, §5.2.2 | ✅ | `test_cookie_lengths_outside_the_table_are_out_of_range` (`test_edns.py`), `test_a_cookie_of_an_undreamt_of_length_is_refused_before_the_walk` (`test_server.py`) — a *server's* cookie is still not validated or switched: that needs per-client state this code keeps nowhere |
| Padding is understood but never emitted, in either role, because every transport here is plaintext UDP | 7830 §4, §6 | ✅ | `test_padding_asked_for_over_plain_udp_is_not_honoured` (`test_server.py`) |
| Per-server payload adaptation to the responder's advertised CLASS, floored at 512 | §6.2.3 (SHOULD), §6.2.4 | ✅ | `test_a_server_that_advertises_less_becomes_the_ceiling`, `test_the_resolver_remembers_who_answered_and_for_how_much`, `test_configured_options_go_out_on_every_query` (`test_edns.py`) |
| Extended RCODE on the way out: an effective code above 15 is split — low nibble in the header, upper eight stamped into the OPT TTL | §6.1.3 | ✅ | `test_an_extended_rcode_is_stamped_into_the_opt_that_carries_it` (the hand-stamped wire case stays pinned by `test_badvers_round_trips`) |
| Responder-side duties: OPT in the response to an OPT query, carrying *this* server's payload size | §6.1.1, §6.2.4 | ✅ | `test_opt_in_the_query_buys_an_opt_of_our_own_in_the_reply`, `test_an_upstream_opt_is_never_forwarded_as_our_own` (`test_server.py`) |
| No OPT for a requestor that did not ask; an extended RCODE it cannot be shown becomes SERVFAIL | §7 | ✅ | `test_unextended_query_is_answered_without_an_opt`, `test_an_extended_rcode_for_an_unextended_client_becomes_servfail` (whose upstream OPT is the "does not extend" half) |
| More than one OPT in a query → FORMERR before any resolution; a VERSION we do not implement → BADVERS with version 0 | §6.1.1, §6.1.3 | ✅ | `test_a_query_with_two_opt_records_is_formerr_before_any_work`, `test_an_unimplemented_edns_version_answers_badvers` |

## 4. Resolution — RFC 1034 §5.3.3

The algorithm itself is the deep dive in [`rfc-map.md`](rfc-map.md); here it
is one row per obligation.

| Obligation | Spec | Status | Where |
|---|---|---|---|
| Iterate from the roots; never send RD=1 | §5.3.3, §4.3.1 | ✅ | `test_resolve_steps.py`, `test_resolver_e2e.py` |
| SLIST selection, demotion on failure, retry without discarding the server | §5.3.3(d) | ✅ | `test_resolve_steps.py` |
| Referral following, including glueless NS sub-resolution | §3.6.3–§3.6.4 | ✅ | `test_resolve_steps.py` |
| CNAME chasing with a hop bound | §5.3.3(c) | ✅ | `test_resolver_alias.py` |
| DNAME substitution and restart at the zone cut — the non-CNAME alias | 6672 §5 | ✅ | `test_resolver_alias.py` |
| NXDOMAIN vs NODATA distinguished by authority content | 2308 §2.2.1 | ✅ | `test_resolver_classify.py` |
| Negative answers cached at `min(SOA.MINIMUM, SOA TTL)` | 2308 §5 | ✅ | `test_cache.py`, `test_resolve_steps.py` |
| CNAME-chain and alias-expansion bounds | 1034 §3.6.2 | ✅ | `test_resolver_alias.py` |
| Wildcard matching and synthesis of the closest encloser | 4592 §2.1–§2.2 | ⬜ | roadmap P2 — names carry an `is_wildcard` flag; no synthesis |
| QNAME minimisation | 9156 §4 | ✅ | opt-in `qname_min` / `--qname-min`: §2.3 probe schedule (`test_minimis.py`) + descent integration with probe-aware demotion and budget degradation (`test_qname_min.py`); off by default |
| Serve-stale on upstream failure | 8767 | ⬜ | roadmap P3 |

## 5. Cache poisoning resistance — RFC 5452, RFC 5625

| Obligation | Spec | Status | Where |
|---|---|---|---|
| Response accepted only on matching source address, transaction ID **and** echoed question | 5452 §4.2–§4.3, §9.1 | ✅ | `test_resolver_matching.py` |
| Randomised transaction IDs, ephemeral source port | 5452 §9.2 | ✅ | constructor path, `test_resolver_matching.py` |
| Refusal of a reply that omits the question section | 1035 §4.1 | ✅ | `test_resolver_matching.py` |
| In-bailiwick glueless NS refused as lame | §4.2.1 | ✅ | `test_resolve_steps.py` |
| Out-of-bailiwick glue and extra-section records filtered | 5452 §6 | ✅ | `test_resolver_classify.py`, `test_glue_policy.py` — glue is accepted only for a name inside the answering zone or the zone it delegates; anything else is discarded and the server's address is obtained by sub-resolution instead. The discarded address is now a `VolunteeredGlue` trace event, and `GluePolicy.PERMISSIVE` lets it be believed so the exposure can be measured rather than only asserted |
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
| Concurrent lookups and task creation bounded; excess dropped silently | 5358 §4 (the bound itself is a design decision) | ✅ | `test_server.py`, `test_review_fixes.py` |
| QDCOUNT ≠ 1 → FORMERR; unsupported OPCODE → NOTIMP, question echoed | 1035 §4.1, 5452 §9.1 | ✅ | `test_server.py` |
| OPT echoed in responses; EDNS-aware responder | 6891 §6.1.1, §6.2.4, §7 | ✅ | `test_server.py` (the EDNS section) — see §3 for the four obligations it pins |
| Extended RCODE above 15 with no OPT to carry it becomes SERVFAIL rather than a masked code | 6891 §6.1.3, §7 | ✅ | `test_an_extended_rcode_for_an_unextended_client_becomes_servfail` |
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
| ~~P1~~ | ~~Bailiwick filter for out-of-zone glue~~ shipped | 5452 §6 | ✅ `classify` now accepts glue only for a name inside the answering zone or the zone it delegates | — |
| ~~P1~~ | ~~EDNS options TLV parse/emit, then per-server payload adaptation~~ shipped | 6891 §6.1.2/§6.2.3, 5001, 7873, 7830 | ✅ options ride in OPT RDATA both ways; NSID is asked for, answered only on request and printed as hex; COOKIE and Padding carry their length rules; each responder's advertised size now caps what we offer it | — |
| ~~P1~~ | ~~Server echoes OPT; EDNS-aware responses~~ shipped | 6891 §6.1.1/§6.2.4/§7 | ✅ the demo server now answers extended queries with its own OPT, refuses a second OPT with FORMERR, answers an unknown VERSION with BADVERS, and keeps §7 silence for unextended requestors | — |
| **P2** | ~~QNAME minimisation~~ shipped opt-in | 9156 | ✅ probe walk + descent integration; flipping the default is a field-behaviour decision, not a code one | — |
| **P2** | IDNA/punycode | 5891/3492 | correctness for internationalised names; currently the caller's job | medium |
| **P2** | Wildcard synthesis | 4592 | needed before results can claim RFC-identical semantics for `*.example` zones | medium |
| **P3** | DNSSEC validation (4033/4034/4035, 5155) | — | the largest trust gap and the largest project: trust anchors, crypto (a dependency decision against the zero-dependency promise), proof checking | large |
| **P3** | Serve-stale | 8767 | availability win; depends on cache bookkeeping DNSSEC also wants | medium |
| **P3** | 0x20 encoding | 6841 | marginal over port+ID+question without DNSSEC; deliberately late | small |
| **P4** | DoT / DoH / DoQ | 7858/8484/9250 | transport security matters, but each is a new subsystem with its own failure modes | large |
| — | Rate limiting / RRL for the server | 5358/9085 | ▫️ non-goal: loopback fixture, not a service | — |

All three original P1 items have shipped. What remains begins at P2: IDNA for
internationalised names, wildcard synthesis before answers can claim
RFC-identical semantics, and DNSSEC, which is both the largest trust gap and by
far the largest project.
