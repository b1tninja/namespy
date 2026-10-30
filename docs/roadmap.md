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
| SVCB/HTTPS `SvcParams` on the wire: ascending keys, no duplicates, reserved key 0 refused, `SvcParamValue` lengths kept inside RDLENGTH, and every registered key's value held to its own section | 9460 §2.2, §2.2.1, §2.2.2 | ✅ | `test_descending_key_order_is_refused`, `test_a_repeated_key_is_refused`, `test_the_reserved_invalid_key_is_refused_in_position`, `test_a_value_claiming_more_octets_than_remain_is_refused`, `test_a_value_that_disagrees_with_its_key_is_malformed`, `test_a_registered_key_is_not_reported_as_unknown` (`test_svcb_wire.py`) |
| SVCB presentation format in both directions: decimal escapes and quoting, comma-separated value lists, `keyNNNNN` for a key with no registered name | 9460 §2.1, §2.1.1, Appendix A.1 | ✅ | `test_encoding_escapes_in_decimal`, `test_quoting_groups_octets_that_would_end_the_token`, `test_appendix_a1_worked_example`, `test_unregistered_keys_use_the_keynnnnn_form`, `test_generated_spelling_reparses_to_the_same_wire_value` (`test_svcb_presentation.py`) |

## 2. Transport and truncation

| Obligation | Spec | Status | Where |
|---|---|---|---|
| UDP query/response correlated by source + ID + echoed question | 5452 §9.1 | ✅ | `test_resolver_matching.py` |
| `TC=1` re-asked over TCP; a truncated answer is never returned and never cached | 1123 §6.1.3.2, 1035 §7.4, 7766 §6 | ✅ | `test_resolver_truncation.py` |
| UDP timeout re-asks over TCP | 1035 §4.2.2, 7766 §6 | ✅ | `test_resolver_truncation.py` |
| TCP framing: 2-octet length prefix, same query re-sent verbatim | 7766 §3.1, §6 | ✅ | `test_resolver_truncation.py` |
| DNS over TLS / HTTPS / QUIC / CoAP, as the transport for a *forwarded* query | 7858, 8484, 9250, 9953 | ⬜ | roadmap P4 — these are stub-to-resolver protocols, and there is no forwarding mode here to put them behind; the row that fits this resolver is the next one |
| Opportunistic encryption of the recursive-to-authoritative leg: probe SVCB at `_dns.<NS-name>`, remember the answer by server address, fall back to Do53 on any failure | 9539 §4, 9460, 9461 | ⬜ | roadmap P4 — Experimental and optional by design. The SVCB codecs it was gated on have landed; what is left is the `_dns.<name>` probe itself, the answer store keyed by server address, and the Do53 fallback |
| SVCB / HTTPS RDATA codecs (SvcParams, `alpn`, `dohpath`) rather than an RFC 3597 blob | 9460 | ✅ | `namespy/svcb.py` holds the registry, `SvcParams`, `SvcbCandidate` and `select_records` (§2.4 client behaviour); `RData_SVCB`/`RData_HTTPS` are registered in `rdata.py`; Appendix D is the test oracle in `test_svcb_rdata.py`, and the two §2.1/§2.2 format obligations it rests on are the last two rows of §1 |
| TCP connection reuse, with the `edns-tcp-keepalive` idle timeout that authorises it | 7828, 9210 | ⬜ | roadmap P3 — `_query_tcp` opens a connection, uses it once and closes it |
| Both address families kept in play so one family's outage cannot partition the answer | 10001 §4.2 | 🟡 | an SLIST queries whatever addresses the glue happened to carry; there is no family-aware selection or fallback policy |

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
| COOKIE: 8 octets, or 16 through 40, are the only lengths the rules allow; anything else is out of range, and in a query it is FORMERR | 7873 §4, §5.2.2 | ✅ | `test_cookie_lengths_outside_the_table_are_out_of_range` (`test_edns.py`), `test_a_cookie_of_an_undreamt_of_length_is_refused_before_the_walk` (`test_server.py`) — a *server's* cookie is still not validated or switched: that needs per-client state this code keeps nowhere |
| Padding is understood but never emitted, in either role, because every transport here is plaintext UDP | 7830 §4, §6 | ✅ | `test_padding_asked_for_over_plain_udp_is_not_honoured` (`test_server.py`) |
| Per-server payload adaptation to the responder's advertised CLASS, floored at 512 | §6.2.3 (SHOULD), §6.2.4 | ✅ | `test_a_server_that_advertises_less_becomes_the_ceiling`, `test_the_resolver_remembers_who_answered_and_for_how_much`, `test_configured_options_go_out_on_every_query` (`test_edns.py`) |
| Extended RCODE on the way out: an effective code above 15 is split — low nibble in the header, upper eight stamped into the OPT TTL | §6.1.3 | ✅ | `test_an_extended_rcode_is_stamped_into_the_opt_that_carries_it` (the hand-stamped wire case stays pinned by `test_badvers_round_trips`) |
| Responder-side duties: OPT in the response to an OPT query, carrying *this* server's payload size | §6.1.1, §6.2.4 | ✅ | `test_opt_in_the_query_buys_an_opt_of_our_own_in_the_reply`, `test_an_upstream_opt_is_never_forwarded_as_our_own` (`test_server.py`) |
| No OPT for a requestor that did not ask; an extended RCODE it cannot be shown becomes SERVFAIL | §7 | ✅ | `test_unextended_query_is_answered_without_an_opt`, `test_an_extended_rcode_for_an_unextended_client_becomes_servfail` (whose upstream OPT is the "does not extend" half) |
| More than one OPT in a query → FORMERR before any resolution; a VERSION we do not implement → BADVERS with version 0 | §6.1.1, §6.1.3 | ✅ | `test_a_query_with_two_opt_records_is_formerr_before_any_work`, `test_an_unimplemented_edns_version_answers_badvers` |
| Extended DNS Errors on the way out: the reason behind a failure this server caused, as an `ERROR` option — 22 for a walk that ran out of authoritative servers, 21 for a non-QUERY opcode — with EXTRA-TEXT short enough to obey §3's "SHOULD avoid lengthy EXTRA-TEXT contents" and naming this software rather than anything §2's private-information caution warns against | 8914 §2, §3, §4.22, §4.23 | ✅ | `test_a_failure_that_needs_explaining_explains_itself`, `test_a_refusal_explains_what_was_refused` (`test_server.py`), `test_the_codes_this_project_sends_are_its_own_two`, `test_the_payload_is_the_info_code_then_the_text` (`test_edns_error.py`) |
| An explanation goes only to a requestor that speaks EDNS, is never echoed out of a query, never decorates a rejection that already explains itself (BADVERS, FORMERR), and is the first thing dropped when the reply would exceed what the client advertised | §3, §6.1.1, 6891 §6.2.3 | ✅ | `test_an_unextended_client_is_told_nothing_extra`, `test_an_extended_error_in_a_query_is_neither_answered_nor_echoed`, `test_a_rejection_that_already_explains_itself_gets_no_extended_error`, `test_an_explanation_is_dropped_before_anything_the_client_asked_for` (`test_server.py`) |
| On the way in, a received code is diagnosis and nothing else: it joins the reason a dead zone is remembered for and the debug log, decides nothing about how the RCODE is processed, and a malformed option is swallowed rather than raised | §3, §6 | ✅ | `test_an_upstream_explanation_rides_into_the_remembered_failure`, `test_an_explanation_changes_what_is_remembered_and_nothing_else`, `test_a_malformed_explanation_is_swallowed_and_the_walk_continues`, `test_a_malformed_explanation_on_an_answer_is_still_not_a_failure`, `test_an_upstream_explanation_is_logged_at_debug_and_nowhere_louder` (`test_failure_cache_resolver.py`) |
| EXTRA-TEXT is somebody else's octets: escaped and capped wherever it is rendered, printed on any RCODE rather than only under a failure (§3: receivers MUST accept codes and EXTRA-TEXT "in all messages, including those with a NOERROR RCODE"), more than one code accepted and kept three deep at most, and a code outside the registry printed as its number rather than a name IANA has not given it | §3, §4, §6 | ✅ | `test_an_unsafe_explanation_is_printed_escaped`, `test_an_explanation_is_printed_under_a_code_that_is_not_a_failure`, `test_more_than_one_explanation_is_printed_in_the_order_it_arrived` (`test_cli.py`), `test_somebody_elses_text_cannot_write_on_the_terminal`, `test_a_code_with_no_entry_prints_as_its_number` (`test_edns_error.py`), `test_someone_elses_words_cannot_write_into_the_reason`, `test_a_flood_of_explanations_is_remembered_three_deep`, `test_a_code_this_registry_does_not_know_is_still_remembered` (`test_failure_cache_resolver.py`) |
| Multiple QTYPEs: MQTYPE-Query (20) composed, MQTYPE-Response (21) read, every §3.3 malformed condition refused on both ends, a valid query answered with §3.4's combined reply and option, and a client that asks — one walk answering A + AAAA + HTTPS, re-asking what the answer left out (§3.5) | 10029 §3.2–§3.5 | ✅ | `namespy.mqtype`, `namespy/bundle.py`, `namespy/server.py`, `namespy/resolver.py`, `tests/test_mqtype.py`, `tests/test_bundle.py`, `tests/test_resolver_mqtype.py`, the MQTYPE tests in `test_server.py` and `test_cli.py` |
| EDNS Client Subnet | 7871, 7872 | ▫️ | non-goal: option 8 is unknown here and so ignored, exactly as §6.1.2 requires of an option a responder does not understand — which is also the privacy-preserving answer for a resolver that does not implement it |
| Padding *policy* — how much to add, and how often to change it | 8467 | ▫️ | non-goal while every transport is plaintext (7830 §6); it becomes a real question the day the P4 transports exist |

## 4. Resolution — RFC 1034 §5.3.3

The algorithm itself is the deep dive in [`rfc-map.md`](rfc-map.md); here it
is one row per obligation.

| Obligation | Spec | Status | Where |
|---|---|---|---|
| Iterate from the roots; never send RD=1 | §5.3.3, §4.3.1 | ✅ | `test_resolve_steps.py`, `test_resolver_e2e.py` |
| SLIST selection, demotion on failure, retry without discarding the server | §5.3.3(d) | ✅ | `test_resolve_steps.py` |
| Referral following, including glueless NS sub-resolution | §3.6.3–§3.6.4 | ✅ | `test_resolve_steps.py` |
| Glue a referral did not carry is obtained by sub-resolution, never guessed at — which is also the only answer available when an authority withholds it for size and sets `TC` | 9471, 1034 §3.6.3 | ✅ | `test_resolve_steps.py` (the glueless case) — 9471's obligation is the *authority's*; see §8 for the row this server owes |
| CNAME chasing with a hop bound | §5.3.3(c) | ✅ | `test_resolver_alias.py` |
| DNAME substitution and restart at the zone cut — the non-CNAME alias | 6672 §5 | ✅ | `test_resolver_alias.py` |
| NXDOMAIN vs NODATA distinguished by authority content | 2308 §2.2.1 | ✅ | `test_resolver_classify.py` |
| Negative answers cached at `min(SOA.MINIMUM, SOA TTL)` | 2308 §5 | ✅ | `test_cache.py`, `test_resolve_steps.py` |
| A cached NXDOMAIN denies the names at and below it, whatever the later query's QTYPE | 8020 §2¶1–§2¶4, §2¶6–§2¶8 | ✅ | `NxdomainPolicy` (`ALWAYS`/`NEVER`/`VALIDATED`, the last refused until DNSSEC exists per §2¶3) over the QTYPE-free `DnsCache.nxdomain_at()`, consulted at every hop. `test_nxdomain_cut.py` pins "denies" as the absence of a `SendQuery`, that NODATA never cuts, that the closest denial is the one that answers and carries its own SOA, and that a denial reached through an alias cuts at the end of the chain (§2¶6). §2¶5's MUST — echo the NSEC/NSEC3 proofs when DO is set — is unreachable until the DNSSEC codecs exist, so it is not claimed here; see roadmap P3 |
| CNAME-chain and alias-expansion bounds | 1034 §3.6.2 | ✅ | `test_resolver_alias.py` |
| Wildcard matching and synthesis of the closest encloser | 4592 §2.1–§2.2 | ⬜ | roadmap P2 — names carry an `is_wildcard` flag; no synthesis |
| QNAME minimisation | 9156 §4 | ✅ | opt-in `qname_min` / `--qname-min`: §2.3 probe schedule (`test_minimis.py`) + descent integration with probe-aware demotion and budget degradation (`test_qname_min.py`); off by default |
| Serve-stale on upstream failure | 8767 | ⬜ | roadmap P3 |
| Never more than two retries to one server address over one transport before treating that address as unresponsive | 9520 §3.1 | ✅ | the UDP loop in `query()` asks at most twice, and the second time only when an answer refused the OPT record; the timeout path adds one TCP attempt, which §3.1 allows as a different transport. `test_silence_is_tried_once_per_transport_and_no_further` pins a silent server at one UDP query and one TCP attempt, `test_edns_refusal_and_silence_do_not_combine_into_three_attempts` that the two paths do not stack into a retry chain, `test_answer_on_the_first_attempt_sends_exactly_one_query` the happy path, `test_edns_rejection_triggers_exactly_the_documented_fallback` the refusal |
| A resolution failure cached for at least a second and never more than five minutes, so a repeat lookup of a dead zone sends nothing upstream until the entry expires | 9520 §3.2 | ✅ | `FailureCache`; `test_failure_cache.py` for the band, the backoff and the LRU bound, `test_failure_cache_resolver.py` for the resolver half — `test_the_next_name_in_a_dead_zone_asks_nothing` pins "sends nothing" as the absence of a `SendQuery`, and `test_suppressing_a_query_does_not_extend_the_failure` that suppression is a read rather than a re-note. Implementation choices (what is keyed, what is not, how long each lasts) are documented on the class, as §3.2 asks |
| Queries to a non-responsive zone's parent limited as hard as queries to that zone | 9520 §3.3 | ✅ | The zone is the key, not the name: `test_a_zone_that_never_answers_is_remembered_as_a_zone` records a dead zone, and `test_the_next_name_in_a_dead_zone_asks_nothing` stops a *different* name beneath it from re-walking the tree to its parent. `test_a_zone_that_answered_is_not_marked_dead` and `test_an_unqueried_zone_is_never_marked_dead` hold the exclusions, and `test_a_dead_zone_does_not_reach_a_name_outside_it` the scope |

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
| The umbrella to validate against, and the algorithm to validate with | 9364, 9904, 9905, 9906 | ⬜ | roadmap P3 — 9364 is the BCP that says a validator must validate, and 9904 is where the algorithm set is actually maintained; 9905 deprecates RSASHA1 and RSASHA1-NSEC3-SHA1 and 9906 ECC-GOST, both updating 4034/5155, so the table in those documents cannot be copied as-is |
| Negative answers reused for names below an NSEC's cover, within its TTL | 8198, 9077 | ⬜ | roadmap P3 — nothing synthesises anything yet (see §4), so there is no proof to use aggressively |
| A trust anchor acquired and maintained rather than embedded forever | 8509, 9535 | ⬜ | roadmap P3 — the root is the sentinel of 8509's own design; a validator that cannot roll it fails on the next KSK ceremony |
| What to set `AD` to when the client asked for validation and no trust anchor is configured | 8145 | ⬜ | roadmap P3 — today `AD` is only ever read, never asserted, which is the honest answer; a validator has to make the opposite choice and 8145 is what governs it |
| New DNSSEC record types: the compact NSEC3 digest formats are themselves RRs | 9824 | ⬜ | roadmap P3 — `rdata.py`'s registry will answer "unknown type" for them, which is conforming but means a compactly-signed zone cannot be validated at all |

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
| A referral carries *every* in-bailiwick nameserver address it can, and says so with `TC` when it cannot | 9471 §3 | ⬜ | the fixture answers from a zone it was handed and sets no `TC` on a referral it has trimmed; 9471 is what a real authority is measured by, so a server that grows past loopback owes this |
| Rate limiting, RRL, cache sharing | 5358 §3, 9085 §4 | ▫️ | non-goal — it is a test fixture, not a service; `SECURITY.md` says so |
| Zone transfer over TLS | 9103 | ▫️ | non-goal — the fixture serves a hand-built zone over loopback UDP and has nothing to transfer |
| NOTIFY for generalized zones | 9859 | ▫️ | non-goal — nothing is dynamic here, which is what that document exists to make safe |

## 9. Packaging and process

| Obligation | Reference | Status | Where |
|---|---|---|---|
| Typed distribution: `py.typed`, sdist+wheel audited, zero runtime dependencies | — | ✅ | `tools/check_dist.py` in CI |
| Suite green under `python -O` (no `assert` on wire paths, ever) | project rule 1 | ✅ | CI job, `CONTRIBUTING.md` |
| Trusted publishing with provenance; no stored credentials | — | ✅ | `release.yml` |
| Protocol behaviour cites its source, by section rather than by title | [CONTRIBUTING.md](../CONTRIBUTING.md) rule 2 | ✅ | every module docstring and wire-path comment; `docs/rfc-map.md` is the index |
| Every RFC citation checked against the document itself | review practice, no gate | 🟡 | [`HANDOFF.md`](HANDOFF.md) rule 8 says to re-check any citation you touch against the live document. Two audit rounds found mistakes in prose that had already been reviewed: the first turned up eight anchors pointing at the wrong section; the second found a citation to a section that does not exist (RFC 6891 has no §6.3 — the "never cached, forwarded, or stored" rule is §6.1.1), a §6.2.2/§7 attribution swap, and sentences held in quotation marks that the documents do not contain. A third pass, over prose the second pass had itself just touched, found the same defect again: RFC 7873 §5.2.2 says "valid cookie lengths are 8 and 16 to 40 inclusive" and RFC 6891 §6.1.2 says "MUST be ignored" — the section numbers had been right the whole time while the words inside the quotation marks were paraphrase. A check like that cannot be satisfied from an index or from a diff, so this row stays 🟡 until a tool finds each quoted sentence inside the body of the document it cites |

---

## The roadmap, consolidated

Priority is ordered by what changes the security or correctness properties
of code built on namespy, not by implementation cost.

| # | Item | Spec | Why it ranks here | Cost |
|---|---|---|---|---|
| ~~P1~~ | ~~Negative caching of resolution failures: remember a dead zone, send nothing upstream while the entry lives, and throttle queries to the parent of a zone whose servers all failed~~ shipped | 9520 §3.2, §3.3 | ✅ `FailureCache` in `namespy/cache/__init__.py`, consulted and recorded by `resolve_steps` and owned by `RecursiveResolver`. Dead *addresses* are deliberately not remembered — the Slist already cycles a zone's remaining servers inside one lookup, and an address key across lookups would retire one healthy server of a zone for minutes over a single dropped datagram; the class docstring records that choice and its cost. On by default; `failure_cache=False` / `--no-failure-cache` turns it off | — |
| ~~P1~~ | ~~Bailiwick filter for out-of-zone glue~~ shipped | 5452 §6 | ✅ `classify` now accepts glue only for a name inside the answering zone or the zone it delegates | — |
| ~~P1~~ | ~~EDNS options TLV parse/emit, then per-server payload adaptation~~ shipped | 6891 §6.1.2/§6.2.3, 5001, 7873, 7830 | ✅ options ride in OPT RDATA both ways; NSID is asked for, answered only on request and printed as hex; COOKIE and Padding carry their length rules; each responder's advertised size now caps what we offer it | — |
| ~~P1~~ | ~~Server echoes OPT; EDNS-aware responses~~ shipped | 6891 §6.1.1/§6.2.4/§7 | ✅ the demo server now answers extended queries with its own OPT, refuses a second OPT with FORMERR, answers an unknown VERSION with BADVERS, and keeps §7 silence for unextended requestors | — |
| **P2** | ~~QNAME minimisation~~ shipped opt-in | 9156 | ✅ probe walk + descent integration; flipping the default is a field-behaviour decision, not a code one | — |
| ~~P2~~ | ~~SVCB / HTTPS RDATA codecs~~ shipped, so an `HTTPS` RR arrives as parameters rather than an RFC 3597 blob | 9460, 9461 | ✅ every encrypted-transport and discovery idea in this table can now begin by reading parameters instead of a hex string; §8's automatically mandatory keys travel with each record, so a client supporting neither `port` nor `no-default-alpn` is told to ignore an `HTTPS` RR that offers them — the part a hand-rolled implementation gets wrong | — |
| ~~P2~~ | ~~Extended DNS Errors: compose and consume the `ERROR` option~~ shipped | 8914 | ✅ an unexplained SERVFAIL now says which server stopped answering and which zone could not be reached, and a resolver that receives one keeps the sender's words in the failure it remembers and in the debug log. What the code deliberately does *not* buy: influence over resolution — section 6 forbids it — nor propagation of an upstream code to this resolver's own client, which would mean synthesising a response the failure path never builds | — |
| ~~P2~~ | ~~Multiple QTYPEs (MQTYPE) — wire form, the responder's half and the asker's half~~ shipped | 10029 | ✅ both options compose, §3.3's eight refusals are enforced on the way out as well as the way in, the three §3.5 outcomes are kept apart rather than collapsed, and a valid MQTYPE-Query gets §3.4's combined answer and MQTYPE-Response from inside the one egress slot the primary lookup holds — with `--max-qtypes` putting §4's knob in the operator's hands, zero meaning support without the extra lookups. On the asking side, `resolve_bundle` and `--mqtype` now send one query where A + AAAA + HTTPS needed three walks of the same tree: §3.5's silence is read as ignorance and re-asked, §3.5's invalid answer is dropped before it can be cached, and RFC 6891 §6.2.2's fallback turns a server that dislikes the option into one ordinary lookup's worth of extra time | — |
| **P3** | IDNA/punycode | 5891/3492 | correctness for internationalised names; currently the caller's job | medium |
| **P3** | Wildcard synthesis | 4592 | needed before results can claim RFC-identical semantics for `*.example` zones | medium |
| **P3** | DNSSEC validation (4033/4034/4035, 5155) | — | the largest trust gap and the largest project: trust anchors, crypto (a dependency decision against the zero-dependency promise), proof checking; the algorithm set is 9904's, with 9905/9906 having removed entries from 4034/5155 | large |
| **P3** | Serve-stale | 8767 | availability win; the staleness bookkeeping it needs is a sibling of what `FailureCache` already keeps, which is why it sat behind the RFC 9520 item and is now unblocked | medium |
| **P3** | TCP connection reuse with `edns-tcp-keepalive` | 7828, 9210 | every truncated answer currently pays a fresh three-way handshake, and 7828 is what lets a connection be kept honestly rather than by guesswork | small |
| **P3** | 0x20 encoding | 6841 | marginal over port+ID+question without DNSSEC; deliberately late | small |
| **P4** | Opportunistic encryption of the leg to the authority servers | 9539, 9460/9461 | the encrypted transport this resolver can actually use — 7858/8484/9250/9953 are stub-to-resolver protocols and have nothing to attach to here; 9539 is Experimental and optional, so this ranks where it does on reach rather than on requirement | large |
| — | Rate limiting / RRL for the server | 5358/9085 | ▫️ non-goal: loopback fixture, not a service | — |

Every P1 is now shipped: bailiwick, EDNS options and OPT echo outright, QNAME
minimisation opt-in, and RFC 9520's failure cache last — the item that had
replaced the others at the top, because it was the one whose absence was visible
to people who had never run this code. It is about how much traffic a resolver
sends other people's nameservers: before it, every lookup that walked into a dead
zone started the hammering again from zero, and the next name beneath that zone
re-asked its parent as though nothing had happened. All three of that RFC's rows
are ✅, §3.1's retry ceiling included: the ceiling is per transport, so a silent
server costing one UDP query and one TCP attempt is what the text allows, and
`test_silence_is_tried_once_per_transport_and_no_further` is what keeps this
project from talking itself out of that reading later.

Everything below changes the answers this resolver gives or the transports it can
use: the SVCB codec has landed, so the cheap correctness items still open are IDNA and
wildcard synthesis, then DNSSEC, which remains both the largest trust gap and by
far the largest project.
