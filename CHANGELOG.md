# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project intends [semantic versioning](https://semver.org/spec/v2.0.0.html), though
nothing has been tagged or published yet, so `master` is the only version.

## [Unreleased]

### Added

- The response-level validators (RFC 5155 §8.5-§8.9, RFC 4035 §5.4) — the shapes a signed
  response can take, each with the records it owes and the split between *absent* and
  *contradictory*. `nsec3_proves_no_data` is §8.5 **as corrected by verified erratum 3441**,
  which is what makes it branch at all: as published it demanded a matching NSEC3
  unconditionally, and an Opt-Out chain holds no record at an insecure delegation (§6¶1),
  so the amended text accepts a closest *provable* encloser proof whose next closer is
  covered by an Opt-Out span — and only that. `nsec3_proves_no_ds` (§8.6) is the same shape
  reading the DS bit, the most load-bearing denial in the protocol because it is what tells
  a validator to stop below an unsigned child; §6¶4 is why its matching branch accepts an
  Opt-Out record while §6¶3 is why a covering one asserts nothing.
  `nsec3_proves_wildcard_no_data` (§8.7) rests on the wildcard's *existence* — matched, not
  covered, which is the difference between a No Data answer and the Name Error its records
  would otherwise describe. `nsec3_proves_wildcard_answer` (§8.8) takes the synthesising
  name the caller read from the covering RRSIG's Labels field and demands the span over the
  "next closer", which is RFC 4592 §3.3.1's "no search for an alternate" made verifiable.
  `nsec3_proves_unsigned_delegation` (§8.9) validates a referral into an unsigned zone, and
  its SOA-bit check is the parent test: a record that matches the delegation name while
  listing SOA is the child's own, quoted as the parent's word. `nsec_proves_no_data`,
  `nsec_proves_nxdomain_response` and `nsec_proves_wildcard_answer` assemble the thinner RFC
  4035 §5.4 text into the same shapes, with the §5.4¶3 Labels equality for callers holding
  the covering RRSIG and the CNAME-bit check RFC 5155 §8.5¶1 spells out and RFC 4035 leaves
  to the reader. Every entry point filters through `usable_nsec3` first, every result names
  the records a proof rests on and flags whether it runs through an Opt-Out span — the AD
  prohibition of RFC 5155 §9.2¶1, pre-computed and waiting for a header that can model the
  bit — and every failure is an `IncompleteProofError` (§5.4¶6: ask again) or a
  `ContradictoryProofError` (no retry will help). Nothing here verifies a signature yet;
  the shapes are what a response owes before its RRSIGs are read at all.
  `tests/test_nsec_responses.py` (44 tests), including the two findings of writing it:
  under NSEC the wildcard of an encloser can never be *missing* — `*.encloser` sorts
  directly above the encloser, inside the encloser's own span, so both proof halves ride
  on one record — which is a geometric fact NSEC3's hashed order does not have; and the
  erratum's asserting-span refusal is a contradiction rather than an incomplete proof,
  because a record asserting QNAME's absence while the response asserts its presence is
  two claims that cannot both stand.

- Extended DNS Errors (RFC 8914) — the `ERROR` option, EDNS option code 15, is composed
  *and* consumed. `ExtendedDNSError` in `namespy.edns` holds an INFO-CODE and the
  EXTRA-TEXT that followed it and interprets neither: §2 says the text "is intended for
  human consumption (not automated parsing)", so `extra_text` keeps exactly the octets the
  option carried — a trailing NUL survives, because §2 also says text "may be null
  terminated but MUST NOT be assumed to be", and only `.text` drops one, for display —
  while `.option` writes the INFO-CODE-then-text payload §2's figure describes. Receiving
  is deliberately broad, because §3 is emphatic: "Receivers MUST be able to accept EDE
  codes and EXTRA-TEXT in all messages, including those with a NOERROR RCODE but need not
  act on them", and its next sentence lets a sender include *more than one* option. So
  `extended_errors_of` returns all of them in wire order and raises nothing — not even for
  an option too short to hold a code, which is a wire-format error on the way *in*
  (RFC 6891 §7's badly-formatted option, answered FORMERR) and merely skipped by a
  *receiver*. That asymmetry is §6: EDE "MUST NOT alter DNS protocol processing", so a
  four-octet defect must not cost the answer riding beside it.
- Explaining a failure, on the way out (RFC 8914 §2, §3, §4.22, §4.23): the demo server
  puts the reason behind a failure it caused into an `ERROR` option instead of handing
  over a bare rcode. A walk that ran out of authoritative servers answers SERVFAIL with
  22 (§4.23, "The resolver could not reach any of the authoritative name servers") and a
  non-QUERY opcode answers NOTIMP with 21 (§4.22, "The requested operation or query is not
  supported"), each with EXTRA-TEXT short enough to obey §3's "SHOULD avoid lengthy
  EXTRA-TEXT contents" and naming this software rather than anything §2's
  private-information caution warns against. Four limits are deliberate: the option goes
  only to a requestor that sent an OPT (§7), it is never echoed out of a query (§6.1.1
  forbids forwarding what arrived), it never decorates a rejection that already explains
  itself (BADVERS and FORMERR carry their own reason), and it is the first thing dropped
  when the reply would overflow what the client advertised — §3 prescribes that order:
  "servers SHOULD truncate messages by dropping EDE options before dropping other data".
- Consuming one, on the way in (§3, §6): a received code is diagnosis and nothing else.
  It joins the reason a dead zone is remembered for — three codes at most, because §3
  leaves the count to the sender and a reason quoting twenty has stopped being a reason —
  and it reaches the debug log, where RFC 5358 §4.2's reasoning and §6's "unauthenticated
  information" agree that somebody else's octets are logged at DEBUG and nowhere louder.
  Nothing branches on an INFO-CODE. The CLI prints each one on its own `; EDE:` line
  beside the EDNS one, on *any* rcode rather than only under a failure (§3's codes 3 and 4
  travel with answers a resolver may legitimately use), with control characters escaped
  and the text capped on screen — §6's MITM sentence describes a text field that this
  program is about to hand to a terminal. What it does *not* do is forward an upstream
  code to this resolver's own client: §3 calls that "implementation dependent", and the
  failure path returns `None` rather than a message, so propagation would mean
  synthesising a response nothing here builds. `tests/test_edns_error.py` (21 tests),
  plus the EDE sections of `test_server.py`, `test_failure_cache_resolver.py` and
  `test_cli.py`, pin all of it.
- Resolution failures are cached now (RFC 9520 §3.2, §3.3) — `FailureCache` and
  `FailureEntry` in `namespy.cache`, consulted by `resolve_steps` before it sends
  anything and owned by `RecursiveResolver` (`failure_cache=`: pass a cache to share
  one between resolvers, leave it out for a default one, pass `False` to switch it
  off — `False` rather than `None` because `None` means "give me the default"
  everywhere else in that constructor, and a resolver built to *watch* a zone fail
  has to keep asking it). A lookup that dies because a zone's servers never answered
  records the **zone**, not the name that happened to ask, because the next query
  will be for a different name under that zone: §3.3 asks that a non-responsive
  zone's parent be limited "just as it would limit subsequent queries to the
  non-responsive zone", and only a zone key can express that. A suppressed lookup
  ends without a `Response` — which the server already answers SERVFAIL — with no
  packet leaving the process. Failures that are properties of a name are keyed on
  `(QNAME, QTYPE, QCLASS)` instead: an alias loop (§2.5), a spent hop budget, or a
  lookup that had no server to ask at all. Two exclusions keep the cache from
  inventing outages — a zone this lookup never queried, and one that answered
  something usable along the way, which is what a finished QNAME-minimisation probe
  walk looks like. Entries live between one second and five minutes (§3.2's band;
  the floor is configurable, the ceiling is a MUST so it is not), double per repeat
  failure, and are LRU-bounded so the memory §3.2's resource-exhaustion concern
  fears is fixed by configuration rather than by how many garbage names someone can
  invent. Suppression does not extend an entry, or a client hammering a dead name
  would hold a recovered zone shut at the ceiling; a lookup that *succeeds* clears
  what was remembered about that name and about every zone that spoke during it,
  which is how recovery gets noticed rather than waited for. What is *not* cached is
  an unresponsive server address, which §3.2 permits: inside one lookup the Slist
  already cycles a zone's remaining servers, and across lookups an address key would
  retire one of a zone's several healthy servers for minutes over a single dropped
  datagram. `--no-failure-cache` is the way out from the command line.
- EDNS(0) *options* — the code/length/value records that live inside OPT RDATA
  (RFC 6891 §6.1.2), which until now was written empty and read as an opaque
  blob. `namespy.edns` carries them; a query can now hold NSID (RFC 5001),
  COOKIE (RFC 7873) and Padding (RFC 7830), and `--nsid` asks every server the
  walk touches to say who it is. What comes back is printed as hex, because
  §2.4 of RFC 5001 asks for two digits per octet — an identifier is meant to be
  pasted into a report, not recognised on sight — and a query that was asked to
  identify servers but was met with silence says so, since RFC 6891 §6.1.2
  requires that an option code a responder does not understand be ignored, and a
  server that never implemented the option is exactly that responder. A
  server answers NSID only when the question was actually put to it
  (§2.2), ignores an identifier a requestor tries to hand it (also §2.2), and
  `--advertise-nsid` is what gives the demo server one to answer with. Each
  responder's advertised payload size is now remembered and applied as the
  ceiling on the next query sent to *that* server (RFC 6891 §6.2.3, §6.2.4):
  the number is what governs how big a reply it may send without fragmenting
  the datagram, so offering it more than it asked for bought nothing but a
  possible fragment. Padding round-trips and names the block it pads, but is
  never applied to a query on plain UDP — RFC 7830 §6 forbids it there, and
  there is no encrypted transport in this codebase to apply it over. A
  misformed option in a *query* is answered FORMERR, and that answer carries an
  OPT: §7 requires it, because "the response MUST include an OPT record" when the
  failure was in the OPT itself — "to allow the requestor to distinguish between
  servers that do not implement EDNS and format errors within EDNS". A server
  that does implement EDNS and found the request malformed must not look like one
  that does not. A cookie option of 9 octets is refused the same way, and so is
  one of 41: RFC 7873 §5.2.2 says "valid cookie lengths are 8 and 16 to 40
  inclusive", so 9 through 15 cannot be a client cookie plus a server cookie of
  any legal size — accepting
  one would be validating a nonce the requestor cannot reproduce. An option code
  this code does not model is ignored instead (§6.1.2), because an experimental
  code is somebody's deployment choice rather than a defect. A misformed one is
  not forgiven in either direction: a declared length that runs past the end of
  the RDATA raises instead of being quietly truncated, which is what lets the
  server turn it into the FORMERR above.
  Pinned by `tests/test_edns.py`, the EDNS section of `tests/test_server.py`,
  and the NSID tests in `tests/test_cli.py`.
- The demo server is now an EDNS(0) responder (RFC 6891 §6.1.1, §6.1.3, §6.2.4,
  §7). A query that carried an OPT gets one back carrying *this* server's
  payload size — never the one the recursive walk collected, since §6.1.1
  forbids forwarding OPT and its CLASS and FLAGS describe somebody else's
  stack; a query that carried none gets none, which is what §7 requires of a
  responder talking to a requestor that announced no EDNS at all. A query with
  two OPT records is answered FORMERR before the resolver is touched, and a
  VERSION this server does not implement is answered BADVERS with `version=0`
  in the OPT — the number that tells the requestor how far down to go. Pinned
  by the EDNS section of `tests/test_server.py`.
- Serialising an effective RCODE above 15 now puts the upper eight bits in the
  OPT record that carries them. A `Response` built in memory holds the whole
  code in `RCODE`, and the wire writer shifted it by 4 — the shift in the
  *effective*-RCODE formula, a different quantity — so it landed in VERSION
  instead of EXTENDED-RCODE and `RCODE=23` (EXPIRED) reached the wire as 7
  (FORMERR). `test_an_extended_rcode_is_stamped_into_the_opt_that_carries_it`
  pins it; the hand-stamped wire-in direction was already pinned by
  `test_badvers_round_trips`.

- QNAME minimisation (RFC 9156), opt-in: `RecursiveResolver(qname_min=True)`
  or `namespy --qname-min`. Servers not known to be authoritative for the
  full name receive progressively deeper children — the section 2.3 probe
  schedule is pinned by `test_minimis.py`, the descent integration by
  `test_qname_min.py`. Terminal *probe* responses demote and continue
  (section 3 step 4) instead of answering for the original QNAME; budget
  exhaustion degrades to full-name queries; `--trace` marks probes. Off by
  default because it changes wire behaviour toward every downline server;
  CNAME chasing deliberately keeps full names.
- Out-of-bailiwick glue is now a *policy* rather than only a behavior, so the
  exposure it prevents can be measured. `GluePolicy` (`STRICT` default,
  `PERMISSIVE`) is accepted by `RecursiveResolver`, `resolve_steps` and
  `classify`; `namespy --allow-out-of-bailiwick-glue` reaches it from the CLI and
  prints a warning on stderr, since an answer obtained this way may have been
  steered by whoever delegated. Either way a referral's volunteered address is now
  a `VolunteeredGlue` trace event — previously the address was discarded inside
  `classify` and left no mark, so the interesting population (who volunteers glue
  for someone else's nameservers, and what would happen if it were believed) was
  exactly the part that could not be observed. `--trace` renders each one as
  believed or discarded, and the policy is inherited by the glueless
  sub-resolution so it cannot loosen halfway down a descent. Pinned by
  `test_glue_policy.py`, with the end-to-end difference in destination shown by
  `test_resolver_e2e.py`.
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
- SVCB and HTTPS (RFC 9460) — types 64 and 65 stop being an RFC 3597 hex blob.
  `RData_SVCB`/`RData_HTTPS` in `namespy.rdata` carry the priority, the TargetName
  and a `SvcParams` object; `namespy.svcb` is the module behind them. Encoding
  obeys §2.2's "SvcParamKeys SHALL appear in increasing numeric order" — the
  parameters are stored by key number and written in sorted order, so a record
  built in the wrong order still leaves this program canonical, while *receiving*
  out-of-order or duplicated parameters is refused as a wire error rather than
  quietly normalised. Unknown keys are kept, not dropped: §2.1.1 does not make an
  unrecognised SvcParam a wire error at all — it matters only when it is
  mandatory, and then the whole record is ignored — so nothing here edits one
  away, and `keyNNNNN` (§2.1) round-trips so a generated zone file says what it
  meant.
  `select_records()` implements the §2.4 client behaviour — AliasMode wins over
  every ServiceMode record in the RRset, records that fail a test cost only
  themselves unless `strict=True` takes §2.4.3's option of rejecting the RRset,
  and each discarded record arrives in `skipped` with the reasons that removed it.
  §8's automatically mandatory keys are the part most likely to be got wrong: an
  `HTTPS` mapping mandates `port` and `no-default-alpn` without saying so in the
  RDATA, so `SvcbCandidate` carries them separately from any explicit `mandatory`
  parameter and a client that supports neither is told, correctly, to ignore the
  record. RFC 9460 Appendix D is the test oracle: `tests/test_svcb_rdata.py` (30
  tests) walks every figure through both wire decoding and presentation parsing.
  `tests/test_svcb_wire.py` (46) works the framing one level below that — a partial
  parameter header, a `SvcParamValue` length that overruns the RDATA, keys out of
  order, an uninterpretable key followed by a readable one — and holds every
  registered key's value to its own section, which is where §2.2's third malformed
  condition bites: a key that was not recognised as registered would let a corrupt
  `port` through as a record that merely has no `port`, silently changing how the
  client connects instead of losing the record. `tests/test_svcb_presentation.py`
  (101) covers §2.1's encoding rules in both directions — charstring escaping,
  value-list splitting and joining, the `keyNNNNN` spelling, and the rejections.
- MQTYPE (RFC 10029) — asking several QTYPEs in one exchange without touching the
  Question section, so QDCOUNT stays one and RFC 9619's "QDCOUNT Is (Usually) One"
  argument survives untouched; the extra types ride in EDNS options 20 and 21 (§5).
  `namespy.mqtype` builds and reads both, and the asymmetry between them is the
  design rather than an accident: §3.3 makes an inbound MQTYPE-Response a FORMERR on
  its own, and §3.5 makes the *absence* of a MQTYPE-Response the way a server says it
  does not support the extension, so the two directions could not share one code with
  a flag inside it. Hence two constructors instead of one taking a flag, because only
  one of the two lists may be empty: §3.3 requires FORMERR for "an MQTYPE-Query option
  with an empty QT list" while §3.4 says the opposite of the answer — "it is possible
  for the resulting MQTYPE-Response option to contain an empty list, but as described
  above, the option must still be returned". Presence is the support signal and
  contents is what was combined, and Appendix A.3's DS-plus-NS figure is precisely
  that empty case. `mqtype_query_rejection()` holds all eight §3.3 conditions and the
  constructors refuse the same list on the sending side, because §3.2 obliges a client
  to "generate packets that conform to the server request parsing rules described in
  Section 3.3" — one shared validator, so the two ends can never drift apart about what
  is valid. Validity turns on RFC 6895 §3.1's data/QTYPE/Meta partition, which is why
  `enums.rrtype_class()` exists: a range check cannot do it, because `OPT` (41) is a
  Meta-RR numbered inside the data band while 128–255 is a gap the policy never
  allocated to data, and an unassigned number above the gap (300) is a perfectly good
  QTx — refusing it would be RFC 3597 §3's error. Reading an answer is three outcomes
  rather than two, because §3.5 commands three different things: absent means
  "unsupported", so keep the primary answer and re-ask the rest; present means use it;
  present-but-self-contradictory (the option twice, or a QTx repeated, or one
  repeating the primary QTYPE) means "treat the answer as invalid (equivalent to
  FORMERR)". Collapsing the third into the first is the dangerous mistake, since it
  keeps using an answer the client was told to discard — so
  `mqtype_supported()` and `mqtype_answered_qtypes()` are separate, the first never
  raising and the second raising for exactly those contradictions.
  `qtypes_still_needed()` is the work list §3.5 demands and pointedly not a negative
  answer: a missing QTx has four innocent reasons (nothing cached, flags or rcode
  mismatched, unwilling server, response too big), none of which is NXDOMAIN or NODATA.
  §4's "a limit of four QTx values would be appropriate" is offered as
  `MQTYPE_RECOMMENDED_QTX_LIMIT`, which is what both the server's `max_qtypes` and the
  demo server's `--max-qtypes` default to — one constant, so an undecided library and an
  undecided command line cannot disagree about what they got. The knob is a real dial
  because §4's paragraph is a policy rather than a cap: `None` leaves only the ceiling an
  EDNS option has in any case — §3.1 gives OPTION-LENGTH no count field of its own, so
  the list is bounded by RFC 6891's 16-bit option length, which `EdnsOption` already
  enforces, and by the UDP payload the query advertises, which runs out far sooner —
  and zero answers the option while buying none of the lookups, which is
  a refusal of *this much work* and sounds nothing like the silence that means the
  extension is absent. The demo server enforces §3.3 (malformed → FORMERR, with
  an OPT per RFC 6891 §7) and, given a well-formed query, combines: each QTx is resolved
  through the same semaphore slot as the primary lookup, so one client stays one
  exchange however many types it asked for (§4's amplification argument), and the answer
  grows by whatever the primary response does not already hold. §3.4's rules are each a
  separate guard. A record already present is not added twice, where "present" is RFC
  2181 §5's identity — name, type, class, RDATA, TTL excluded — which is why an SOA that
  appears in both the Answer (NODATA) and the Authority (proof of absence) sections
  stays two records. A QTx whose answer disagrees with the primary on rcode, `aa`, `tc`
  or `ad` is left out, because those are one bit per message and the option may not name
  a type whose records are absent. A response that would grow past what the client
  advertised stops combining instead of setting `TC`, since a listed QTx is promised in
  full and §3.5's recovery from a missing one is to re-ask, not to be told the answer was
  cut. A `TC` primary stops the loop on its own — the full set can only arrive over TCP,
  and the option belongs with the answer that reaches it — and every one of those stops
  still returns the option, empty if nothing was folded in, because §3.4 makes presence
  the support signal and §3.5 makes absence the signal to retry type by type. Where RFC
  8914 §3's "drop EDE options first" would have taken the reply's explanation with it,
  the explanation is what goes and the MQTYPE-Response stays. `tests/test_mqtype.py`
  (44) uses Appendix A's three figures as the oracle and covers every §3.3 condition and
  each §3.5 outcome; sixteen in `tests/test_server.py` hold the server to both halves of
  its posture — the refusals and the combination rules down to the octet, and the exact
  reach of the operator's limit, zero and unbounded included; and 22 in
  `tests/test_enums.py` pin every boundary of the §3.1 allocation table.
- MQTYPE on the asking side (RFC 10029 §3.2, §3.5) — `namespy.bundle` reads a combined
  answer, `RecursiveResolver.resolve_bundle(packet, (AAAA, HTTPS))` walks once, and
  `--mqtype TYPE` (repeatable) puts it on the command line. The reader is a module of its own
  because the failure this feature invites is a cached lie, and it is a failure about
  *absence*: §3.5 gives four reasons a requested QTx can be missing from the MQTYPE-Response —
  nothing in cache, flags that did not match, a server unwilling to do the work, a size limit
  — and not one of them is "this name has no records of that type". So an unlisted type comes
  back as `BundleState.NEEDED`, a work list rather than a verdict, and only the types the
  answer vouched for reach the cache. §3.5's "The client MUST subsequently initiate separate
  standalone queries for all QTx values for which an answer is still required" is what
  `resolve_bundle` does by default; `ask_separately=False` hands that decision to a caller who
  knows whether it wants an AAAA at all. `supported` and `void` are two fields instead of one
  boolean because the two cases want opposite things: a server that never implemented the
  extension answers the primary question perfectly well, and §3.5 says to process it "as if the
  MQTYPE-Query option had not been used", while a server that duplicated a QTx or sent the
  option twice has produced an answer §3.5 makes equivalent to FORMERR — which voids the
  harvest *and* the primary, so the void is caught in `resolve_steps` before classification,
  since anywhere later the bad answer has already been cached on its way to being rejected.
  §3.5's ranking rule (RFC 2181 §5.4.1) cuts both ways: an authoritative NODATA for a listed
  QTx is a negative and caches like any other under RFC 2308 §5, and one that nobody vouched
  for caches as nothing at all. Each entry also carries where its answer came from —
  `BundledType.separate` — because a combined type and a re-asked one are otherwise the same
  state with records attached, and only the first was combined by anybody.
- The list travels with the walk, not with one query. An MQTYPE-Query option rides every send
  of the descent it belongs to and none of the lookups that merely support it: a QNAME
  minimisation probe asks the child so that a server can answer NOERROR rather than name the
  zone, while §3.4 evaluates each (QNAME, QCLASS, QTx) combination against the flags of *the
  query that asked* — so a probe carrying the list invites a server to attribute the parent's
  RRsets to the child's name. Glue sub-resolution is excluded for the same reason: it asks
  about a nameserver's name at somebody else's request, and its answer is not this bundle's.
  §3.3's refusals are refused before they are sent — a repeated QTx, one that is a Meta-RR
  rather than a data type, a bundle behind a non-data primary such as ANY, which §3.3 makes a
  FORMERR rather than a difference of opinion — and a server that rejects the option is
  stepped down
  the way RFC 6891 §6.2.2 steps anything else down: drop the option if a reply comes back
  FORMERR carrying an OPT, drop EDNS entirely if it comes back FORMERR without one.
  `tests/test_bundle.py` (28), `tests/test_resolver_mqtype.py` (28) and twelve in
  `tests/test_cli.py` hold the reader, the threading, the three fallbacks and the rendering;
  `bundle.py` is at 100% coverage. And because each of those suites only ever talked to a
  response this project wrote by hand, `tests/test_mqtype_interop.py` (4) wires the real
  client to the real responder over a real datagram — the client encodes, the server parses,
  combines, and answers, and the client's harvester reads the result — for the combined,
  declined, and partly-completed cases. It found the malformed fixtures below on the first run.
- A bundled hop is now visible in `--trace`. `SendQuery` has carried `extra_qtypes` since the
  option shipped, but `to_mermaid()` only ever marked probes, so `last_resolution.md` showed a
  line-for-line identical diagram whether a descent had bundled three types into one query or
  fetched each with its own — and it still would, because the fallback answers every type
  either way and only the trace can tell. Each bundling hop now reads `example.com. A
  (mqtype +2)`, counted rather than named because this module dispatches on class names
  precisely so it never has to import the resolver. The standalone re-asks, which had been
  invisible — each built a trace that `resolve_bundle` then discarded when it restored the
  bundling descent — are attached as child traces and render as their own diagrams, so the
  file says what was asked and how many times. A lookup that did not bundle renders exactly as
  before, marker absent, which is what the existing mermaid tests pin.
- The NXDOMAIN cut (RFC 8020 §2) — a NXDOMAIN already in the cache now denies the names at and
  below it, so a lookup that RFC 2308 would send upstream is answered from the denial the zone
  already made. §2¶1's claim is about *names* — "all names and resource record sets (RRsets) at
  or below that node SHOULD be considered unreachable" — while a negative entry is keyed
  `(name, qtype, class)`, so the
  NXDOMAIN that arrived in answer to an A was invisible to the AAAA this cut is meant to serve.
  That is why the change is in the cache layer and not the resolver: `DnsCache.nxdomain_at(name,
  qclass)` is the QTYPE-free lookup `get()` cannot be. Its SQLite form is one read on the primary
  key's leftmost column; its in-memory form is an index maintained on every removal path, because
  the cut is consulted on every hop of every query and a scan of the cache per hop would cost
  more than the traffic the cut saves. The base implementation returns `None` rather than raising:
  the cut is a SHOULD, so a backend that cannot answer it keeps walking, which is the behaviour
  from before it existed. Two consequences of §2 that tests caught by failing — and were right to:
  the *name itself* is cut for every other type, since §2¶1 says "at or below that node" and the
  node is the denied name — re-proving a nonexistence the zone already stated is not what RFC 8020
  asks for; and the cut
  must be consulted at *every* hop, because §2¶6 makes the denied name the last one in an alias
  chain, so a resolver that checked only at the origin would walk straight into a subtree its own
  cache says is unreachable. `NxdomainPolicy` decides all this and sits beside `GluePolicy`
  deliberately: `ALWAYS` is the §2 SHOULD, and `NEVER` exists for the reason §2¶4 gives — "The
  fact that a subtree does not exist is not forever" — so a name created under a denied node is
  invisible until the negative entry expires, which is wrong for serving and exactly right for
  watching a zone change, the same split `--no-failure-cache` draws. Unlike permissive glue it
  gives up an efficiency rather than a defense, so it logs instead of warning on stderr.
  `VALIDATED` is §2¶3's MAY — cut only when the NXDOMAIN was DNSSEC-validated — and is refused at
  the door with a message naming DNSSEC, because it and `NEVER` emit identical packets while
  nothing here validates, and a silent fallback would let an operator believe proofs were what
  stopped the cut; the test that pins the refusal is the one that has to change when validation
  arrives. A cut's answer is indistinguishable on the wire from a denial fetched for the name
  asked about — the reply carries the *ancestor's* SOA beside a question naming the deeper name —
  so `--trace` gains `NXDOMAIN cut: www.foo.example below foo.example` and the answer a matching
  `;;` line, both naming the ancestor, and both halves reported in the case the query used because
  a line whose two names differ only in case reads like two names. A cached denial is consulted
  before the RFC 9520 failure note where the two overlap, since one is a proof with an SOA behind
  it and the other only a promise not to ask again.
- The first leg of DNSSEC (RFC 4034 §2, §5, Appendix B) — `DNSKEY` and `DS` stop being RFC 3597
  hex blobs. `namespy/dnssec.py` holds the arithmetic and `RData_DNSKEY` / `RData_DS` in
  `namespy/rdata.py` are the codecs, registered on type numbers 48 and 43 like every other
  type this package understands. The point of doing these two first is that they need no
  dependency: a DNSKEY carries a public key it never interprets (§2.1.4 defers the format to
  documents this package does not implement), a DS carries a hash it never checks, the key tag
  is a 16-bit checksum, and the digest is one `hashlib` call over "DNSKEY owner name | DNSKEY
  RDATA" (§5.1.4). Signature verification — RSA, ECDSA, EdDSA — is where the dependency
  decision actually lives, and it is still ahead.
- Both published vectors in RFC 4034 are the tests, so nothing here is a number this code
  computed and then agreed with: §5.4's DNSKEY yields key tag **60485** and SHA-1 digest
  **2BB183AF5F22588179A53B0A98631FAD1A292118** exactly as printed. A checksum with no other
  vector is cross-checked against a second, independent transcription of Appendix B's reference
  C code over odd and even lengths.
- Two verified errata change the answer and are pinned by name. **4552** corrects Appendix B's
  prose ("ignoring any carry bits") to what the C actually does — accumulate at 32-bit
  precision, fold once, discard only the carry that fold produces — and warns the result is
  "often the same as reduction modulo 65535, but not always"; `test_key_tag_is_not_reduction_modulo_65535`
  uses the smallest input where they differ, because a shortcut that agrees on
  most keys and disagrees on some lands its disagreement on a delegation. **193** corrects
  §B.1's parenthetical for algorithm 1 from "4th to last and 3rd to last" octets to "3rd to last
  and 2nd to last", which is what its own normative phrase always meant; the vector there is
  built so the two readings give different numbers.
- Digest types are the ones this package can actually produce — SHA-1 (§A.2), SHA-256
  (RFC 4509 §2), SHA-384 (RFC 6605 §2) — and minting any other refuses *by number* rather than
  approximating it. Reading is deliberately more forgiving than writing: a DS with an unknown
  digest type parses, round-trips and prints, because refusing to parse a delegation would turn
  this resolver's ignorance into SERVFAIL for someone else's zone. Same asymmetry in `DNSKEY`:
  a key with the wrong Protocol or a missing Zone Flag is kept and reported
  (`may_verify_rrsets`), not dropped at parse time, because §2.1.2 puts that judgement at
  verification and an operator needs to see which rule the zone broke.
- The second leg of DNSSEC (RFC 4034 §3–§4, RFC 5155) — the proof records decode.
  `RData_RRSIG`, `RData_NSEC`, `RData_NSEC3` and `RData_NSEC3PARAM` in `namespy/rdata.py`,
  on shared ground in `namespy/dnssec.py`: `encode_type_bitmap`/`decode_type_bitmap`
  (§4.1.2's window blocks, whose ordering and trailing-zero MUSTs leave exactly one legal
  encoding per set of types, so equality on rebuilt bytes is sound), `nsec3_hash` (§5's
  `IH(salt, x, k)` recursion), `encode_base32hex`/`decode_base32hex`, and
  `iterations_within_limit` (§10.3's ceiling table). Still no new dependency: the NSEC3 hash
  is `hashlib.sha1`, the algorithm §11 registers, and the bitmap is arithmetic.
  **Verified erratum 3544** is why the base32 helper is not `base64.b32encode`. RFC 5155 §3.3
  prints "base32" where RFC 4648 §7 base32hex is meant — the two alphabets share no character
  below `K`, so a hash written the other way produces a label that exists in no zone, and the
  failure would read as a zone with no NSEC3 chain rather than as an encoding bug. All twelve
  of Appendix A's hashes reproduce exactly (`test_nsec3_hash_reproduces_the_published_vectors`),
  which pins the recursion at the same time — §3.1.3's *iterations* counts additional hashes,
  so `iterations: 12` is thirteen invocations, one short of what a careless reading gives —
  plus §6.2 item 4's rule that a wildcard hashes with its `*` label intact
  (`*.w.example.` has its own entry) and the entry whose first label is itself a hash.
  `RData_RRSIG` computes nothing but does enforce §3.1.5: `within_validity` compares the two
  time fields with RFC 1982 serial arithmetic, reusing what `RData_SOA.serial_ahead` already
  had for SOA serials, because §3.1.5¶2 states that an Expiration numerically *below* its
  Inception is legal and "all comparisons involving these fields MUST use Serial number
  arithmetic" — `test_rrsig_validity_survives_the_32_bit_wrap` holds that, since a plain
  integer comparison would quietly reject live signatures for half of 2105–2106.
  Reading stays forgiving and writing stays strict, as with `DNSKEY`/`DS`: an NSEC3 with hash
  algorithm 2 parses, round-trips and prints, but `hash_owner()` refuses rather than inventing
  a hash function, and a Hash Length of 7 for SHA-1 is rejected on receipt even though §3.1.6's
  field permits it, because a truncated hash is a proof that proves nothing.
  **The repo's own sweep caught a live bug**: `test_rdata_wrapping.py` demands a payload per
  registered codec, and writing one exposed an RRSIG header format spelled `!HBBIIHI` where
  `!HBBIIIH` is right — same 18 octets, and it read the Key Tag into the Inception Time. The
  field-order test now says so in its docstring.
- The cryptographic dependency decision, taken and bounded rather than deferred: a
  `crypto` extra in `pyproject.toml` pointing at `cryptography>=50.0.2`, and
  `namespy/crypto.py` as the one module allowed to find it. Named for the capability and
  not for DNSSEC on purpose — a feature-named extra has to be renamed the first time
  anything else needs arithmetic, and renaming a published extra breaks everyone who
  installed it. `import namespy` still imports no third-party module at all, which a test
  now proves in a fresh interpreter rather than asserting about.
  What the probe carries is the *policy*, not the arithmetic. `IMPLEMENT_FOR_VALIDATION` is
  RFC 9904 Table 2's "Implement for DNSSEC Validation" column — including the pair that
  surprises, RSASHA1 (5) and RSASHA1-NSEC3-SHA1 (7), which RFC 9905 deprecated for *signing*
  while Table 2 keeps them MUST for *validation*, because a resolver that refuses them cannot
  read the zones still signed with them. `SIGNATURE_ALGORITHMS` pairs each number with its
  primitive and digest per RFC 3110 / RFC 5702 / RFC 6605 / RFC 8080, and a test asserts the
  two tables agree: every MUST number has a primitive, and no MUST NOT number sneaks in.
  `require_backend("verify an RRSIG")` refuses with the exact extra to install, because
  "no crypto" is a line an operator reads in a log; `MissingCryptoError` is a `RuntimeError`
  and not an `ImportError` so the resolver can treat it as a policy refusal — answer
  unauthenticated and say why — rather than a broken install.
  `MAX_RSA_KEY_BITS` is 4096 (RFC 3110 §2) and marked as not-yet-enforced on purpose: the
  backend documents "denial of service via parsing untrusted key material" as outside what it
  treats as a security issue, which is a reasonable line for a general-purpose library and
  precisely the reason a resolver reading DNSKEYs off the wire needs its own. The marker test
  moves when the enforcement lands, the way `NxdomainPolicy.VALIDATED` marks validation.
  **Why this library, in short:** it is the only candidate that covers the whole MUST set in
  one dependency, is governed by the Python Cryptographic Authority with a published security
  policy (48-hour acknowledgement; security support for "the main branch as well as the most
  recent release"), ships abi3 wheels for Windows/macOS/manylinux/musllinux across five
  architectures with build provenance attested on every file, and documents the three
  integration points DNSSEC needs — `decode_dss_signature` for the fixed-width r‖s that RFC
  6605 §4 uses instead of DER, `from_encoded_point` for the tag-stripped point a DNSKEY
  carries, and raw-byte Ed25519/Ed448 loading per RFC 8080. All three are now exercised by a
  test in the new CI job, including that an off-curve point is refused rather than trusted.
  `python-ecdsa` was rejected on its own instruction ("should not be used in production
  settings") and for having no RSA at all — which leaves it unable to do 5, 7, 8 or 10;
  `pycryptodome` is capable and self-contained but is a single-maintainer project without the
  provenance posture; `PyNaCl` has no RSA and no NIST P-256, so it cannot cover the MUST set
  either. Implementing verification in pure Python was considered for the RSA numbers and
  rejected: the hazard there is not the modular arithmetic but the PKCS#1 v1.5
  `DigestInfo` parsing, which is where the historical forgery bugs live.
- The canonical RRset — the exact octets a DNSSEC signature covers (RFC 4034 §6.2, §6.3,
  §3.1.3, §3.1.8.1; RFC 3597 §7). `canonical_rdata_octets`, `canonical_rr_bytes`,
  `canonical_rrset_bytes`, `canonical_rrset_rdatas`, `rrsig_signed_data`, `signed_owner_name` and
  `rrsig_label_count` in `namespy/dnssec.py`, with `canonical_wire()` on `RData` and on every
  codec that carries a domain name and `signed_data_prefix()` on `RData_RRSIG`. This is the last
  piece of DNSSEC that needs no dependency and no trust anchor: it produces the byte string a
  signature is checked against and verifies nothing itself.
  §3.1.8.1¶5 is the sentence most likely to be read carelessly — `RR(i) = owner | type | class |
  TTL | RDATA length | RDATA` repeats the owner, type and class **inside every record**, rather
  than stating them once for the set — so the test counts the ten-octet difference between a
  one-record and a two-record set instead of trusting that the shapes look right.
  **Which types downcase the names inside their RDATA turned out to be a two-document question,
  and my earlier note about it was wrong.** RFC 4034 §6.2 item 3 and RFC 3597 §7¶4 each carry a
  verified erratum for omitting entries the other has — **1062** against 4034, **1063** against
  3597 — and the union is what implementations settle on: §7¶4's pre-2003 types plus RRSIG and
  NSEC, which RFC 4034 adds by name. RFC 3597 §7 is therefore not "the full set", and NSEC3 has no
  embedded domain name to downcase in the first place (its hashed owner name is opaque octets).
  More consequentially, §7¶5 says that for any type defined *after* RFC 3597 "the canonical form is
  such that no downcasing of embedded domain names takes place" — so HTTPS and SVCB keep the case
  of their target-name even though it is a domain name (RFC 9460 says nothing about canonical
  form, so §7¶5 governs), and `test_a_type_after_rfc_3597_keeps_the_case_of_its_embedded_name`
  pins that against the "downcase anything with a name in it" instinct. The list is built from the
  type registry rather than typed-out numbers, and asserted as mnemonics, so it reads against the
  RFC's sentence and cannot gain a digit quietly.
  Two rules that look cosmetic are not. §6.3¶1 orders RDATA as "a left-justified unsigned octet
  sequence in which the absence of an octet sorts before a zero octet", which is plain bytes
  comparison — what it rules out is a length-aware or numeric comparator, and a different order is
  a different signature. §6.3¶2 makes a duplicate record "a protocol error" that MUST be treated as
  one, permitting leniency only on condition that all but one copy be dropped: both readings are
  honoured, `DuplicateRecordError` by default and `tolerate_duplicates=True` doing the drop,
  because sorting two identical members produces a string no signer made.
  `canonical_wire()` is per-codec rather than one `bytes(...).lower()` on the whole record: an MX
  preference or an SRV port of `0x4142` is inside the A-Z byte range, and lowering it would corrupt
  the number while "canonicalising" — `test_canonicalisation_leaves_numeric_fields_alone` exists to
  keep anyone from taking the shortcut. A type that item 3 lists but this package has no codec for
  raises `CanonicalizationError` instead of hashing raw octets, because guessing where names sit
  makes a *valid* signature fail, which is indistinguishable from an attack.
  `signed_owner_name` does the §3.1.3 wildcard reconstruction (`www.example.com.` with Labels 2 is
  signed as `*.example.com.`), refuses a Labels value larger than the owner has labels rather than
  clamping it, and keeps the `*` in the hashed name as §3.1.3¶4 requires.
- RSA public keys in DNSKEY, and the width of an RSA signature (RFC 3110 §2-§3, RFC 5702 §2).
  `pack_rsa_public_key`, `unpack_rsa_public_key`, `rsa_signature_octets`, `RsaPublicKey` and
  `MalformedRsaKeyError` in `namespy/dnssec.py`; `RData_DNSKEY.key_algorithm_is_rsa`,
  `rsa_public_key()` and `require_rsa_key()` in `namespy/rdata.py`;
  `RSA_ALGORITHMS`, `RSA_MIN_KEY_BITS_BY_ALGORITHM` and `minimum_rsa_key_bits()` in
  `namespy/crypto.py`. Reading RFC 3110 turned up no reason to wait for the backend: §2 is integer
  packing, so the key material is now decodable on a default install while ECDSA and EdDSA still
  wait on `namespy[crypto]`.
  **The RFC's "leading zero octets are prohibited in the exponent and modulus" (§2¶3) is not
  tidiness — it is key-tag arithmetic.** A key tag sums the RDATA octets, so the same modulus and
  exponent written with a leading zero produce a different tag and therefore a DS that matches
  nothing: every bit correct, the key unusable. The same reasoning makes §2¶3's
  "is represented as" prescriptive about the 1-or-3-octet exponent length field, so
  `unpack_rsa_public_key` refuses a 3-byte exponent written in the long form rather than forgiving
  the second encoding. Both directions are tested, including the rare 256-octet exponent that
  reaches the 3-octet form at all.
  **`MIN_RSA_KEY_BITS` was not enough on its own, and the gap is a downgrade surface.** RFC 3110
  §3¶9 and RFC 5702 §2.1¶2 set the modulus floor at 512 bits for algorithms 5, 7 and 8, but
  **RFC 5702 §2.2¶2 sets it at 1024 for RSA/SHA-512**: one constant accepts a 512-bit RSA/SHA-512
  key that RFC 5702 forbids. Since a zone may hold keys of several algorithms and a validator picks
  one, the weakest key is what an attacker aims at, so the floor is now per-algorithm and
  `require_rsa_key()` looks it up. `MIN_RSA_KEY_BITS` remains as the general floor with a pointer
  to the function.
  Algorithm 1 (RSA/MD5) is deliberately *not* read with this format. RFC 3110 §2's notes moved
  RSA/SHA-1 onto number 5 specifically to separate it from RFC 2537's RSA/MD5 keys, whose RDATA
  begins with a key-length header that this parser would take for an exponent length and return a
  plausible wrong key. `RSA_ALGORITHMS` is derived from the existing algorithm table rather than
  written out again, so the two cannot drift.
  **Erratum 2811 is why `rsa_signature_octets` pads instead of rejecting.** RFC 3110 §3¶10 as
  published said "leading zero bytes are permitted" in an RSA signature; the verified technical
  erratum changes it to "MUST be added ... so that the signature size in bytes is equal to the size
  of n", citing PKCS #1's `I2OSP(s, k)`. Records written against the published wording exist, and
  a backend handed a short signature fails in the same shape as a forgery, so a short signature is
  padded and a signature *wider* than the modulus is refused — that one cannot come from a
  reduction mod n, so trimming would be guessing.
  Parsing behaviour is unchanged: a DNSKEY holding unreadable RSA octets still parses, still
  computes its key tag, and refuses only when `rsa_public_key()` is asked, which keeps RFC 4034
  §2.1.2's "judged at verification time" and keeps an operator's ability to say which rule a zone
  broke.
- Cached denials now keep their proof records. `NegativeEntry` gained a `proofs` field — the
  NSEC/NSEC3 RRs that denied the name, each followed by the RRSIGs covering it — stored by both
  backends and readable from both lookups, including `nxdomain_at`, the one that answers a name
  nobody queried. `namespy.nsec.collect_proof_records(records)` builds the bundle, and
  `namespy.nsec.proof_entries(records, rtype)` adapts wire records into the `(owner, rdata)` pairs
  the proof predicates take, so `closest_encloser_proof` can now be fed straight from a response or
  from the cache.
  **The bundle is defined by RFC 4035 §3.1.1¶3, not by convenience**: "When placing a signed RRset
  in the Authority section, the name server MUST also place its RRSIG RRs in the Authority
  section." A collector that returned bare NSEC records would let a resolver hand a client an
  authenticated-looking denial from the one server the client trusts, so a proof with no covering
  RRSIG is dropped rather than half-stored. Pairing is by owner name and Type Covered — never by
  Signer's Name, which is the zone apex and in an NSEC3 response resembles neither the denied name
  nor anything else. That distinction is a test of its own, because pairing on the signer is the
  natural implementation and it fails exactly where proofs matter.
  `proof_entries` deliberately does *not* require signatures, and the difference from the collector
  is documented on both: one answers "what does this set assert", which a diagnosis needs even for
  records it will not trust; the other answers "what may be echoed as authenticated".
  SQLite needed a column, and a column needs a migration that schema text cannot do: `CREATE TABLE
  IF NOT EXISTS` is a no-op against a file that already exists, so an on-disk database from an older
  build has no `proofs` column and every read would raise `OperationalError`. `_add_proofs_column`
  checks `PRAGMA table_info` and ALTERs once; old rows read back with no proofs, which is the truth
  about them, and new writes carry them. An unreadable proofs blob costs the proofs and not the
  denial — the same degradation `_decode_soa` already applies, for the same reason: deleting the
  entry would turn a missing signature bundle into a re-query storm.
  **What is not claimed, in one sentence because it is the interesting part: the resolver still does
  not echo these records, because it never sets the DO bit and so is never sent them.** RFC 4035
  §3.2.1 is blunt that "the resolver side of a security-aware recursive name server MUST set the DO
  bit when sending requests, regardless of the state of the DO bit in the initiating request", and
  that the name-server side MUST strip DNSSEC RRs when the client did not ask but MUST NOT strip
  types the query explicitly requested. Honouring that pair needs the client's DO state carried
  into the resolver and an OPT record built with DO on outbound queries — done in the entry below,
  which turns RFC 8020 §2¶5's MUST from storable into satisfiable. Proofs that do arrive
  — from a caller that queried DNSSEC types explicitly — are collected, cached and reachable today.
- Outbound DO, and the DO/AD confusion that was hiding behind a property name.
  `RecursiveResolver(dnssec_ok=True)` sets EDNS(0)'s DNSSEC OK bit on every query (new
  `namespy.packet.EDNS_DO_BIT` / `EDNS_CD_BIT` constants, used by the readers), which is what makes
  the proofs above arrive at all — an authoritative server sends NSEC/NSEC3 records to a resolver
  that asks for them, and RFC 4035 §3.2.1 is explicit that "the resolver side of a security-aware
  recursive name server MUST set the DO bit when sending requests, regardless of the state of the DO
  bit in the initiating request". Off by default and deliberately so: that MUST binds the recursive
  *name server* serving DNSSEC-aware clients, and this package is a resolver library until a caller
  makes it one; the option costs octets per query and can force a TCP re-ask, so it is an operator's
  decision rather than a default. The EDNS fallback path drops DO along with the OPT record it is
  re-asking without, so a server that rejected EDNS is not asked for DNSSEC data a second time.
  **`DnsMessage.ad` was reading OPT FLAGS bit 15, which is DO, not Authentic Data.** AD is header
  bit 5 (RFC 6895) and asserts "this responder validated the answer"; DO is a *request* — "please
  include DNSSEC records" — and an authoritative server echoes it back in its response OPT whether or
  not anything was authenticated. The property is now `DnsMessage.dnssec_ok`, and the consequence is
  user-visible: `namespy lookup` printed `ad` in the header flag list from that bit, so **every
  response from a DNSSEC-aware server claimed "authenticated data" to a CLI that had not verified a
  single signature.** The header flags list no longer prints it, and `_opt_flags` now reports the
  bit where it belongs and by its right name — `flags: do` on the EDNS line, as dig does.
  The header's own AD and CD bits are not modelled by this package's wire format yet, so there is
  currently no correct source for an `ad` flag at all; printing nothing is the honest answer until
  they are, which is now a roadmap item — and a prerequisite for RFC 5155 §9.2's AD prohibition,
  which cannot be obeyed by a resolver that cannot set the bit.
- The serving rule that makes the request worth making: the proof echo a DO=1 client is owed, and the
  strip a DO=0 client is owed. `namespy.dnssec.DNSSEC_SECURITY_TYPES` (RRSIG, DNSKEY, NSEC, NSEC3,
  NSEC3PARAM) is the set RFC 4035 §3.2.1¶1 makes conditional on the client, and
  `DnsServer._strip_dnssec` withdraws it from every section of a reply — recomputing the header
  counts, which are stored rather than derived, so an answer that drops two RRSIGs while still
  claiming four records is a message lying about its own length. `_synthesize_response` attaches a
  cached denial's stored proofs to its answer, which is what makes RFC 8020 §2¶5's MUST satisfiable
  rather than merely storable: "the iterative, caching resolver MUST return these NSEC or NSEC3
  records in the response to the triggering query if the query had the DNSSEC OK (DO) bit set". The
  guard deciding whether to strip exists in exactly one place — `_reply`, just before `_apply_edns` —
  so the resolver assembles the full answer, the cache never loses evidence, and no policy is split
  across two components. Three readings the spec leaves open are recorded in the code and tested:
  **QTYPE=\* is not an explicit request for RRSIG** (§3.2.1's exception covers types a query
  "explicitly requested", and RFC 3225 §2¶5 makes client willingness binary — otherwise one wildcard
  type defeats the strip, to the benefit of nobody, since §2¶3's resolvers that fail on DNSSEC records
  are precisely the ones that send ANY); **a QTx in RFC 10029's list counts as explicitly requested**,
  because a client that named RRSIG among the types it wanted asked for that type, whichever option
  carried it; and **DS is not in the set**, on the reading that it is data rather than decoration.
  That last choice has an operational consequence — a DO=1 walk can now carry a DS in a referral on to
  a DO=0 client, which §3.1.4's referral rule arguably wants and RFC 3225 §2¶3 would rather avoid —
  so it is filed as an open question on the roadmap instead of being presented as settled.
  `namespy lookup --dnssec` puts the whole path within reach of a user: DO outbound, signatures and
  proofs printed, and a `namespy serve --dnssec` operator gets both halves of §3.2.1. A known gap: the
  SOA that rides along with an echoed denial is unsigned, because an RRSIG over the SOA is not a proof
  of anything and was never stored with the proofs. `tests/test_dnssec_serving.py`, 12 tests over the
  echo, the strip, both exceptions, and the funnel.
- Authenticated denial of existence: the NSEC and NSEC3 proof rules, in a new module
  `namespy/nsec.py` (RFC 4034 §6.1, RFC 4035 §5.4, RFC 4592 §3.3.1, RFC 5155 §6-§9).
  `name_order_key`, `canonical_name_before`, `sort_canonical`, `name_between`, `hash_between`,
  the NSEC predicates (`nsec_matches`, `nsec_proves_nxdomain`, `nsec_proves_no_type`,
  `nsec_proves_no_wildcard`, `nsec_owner_is_explicit`, `find_nsec_matching`,
  `find_nsec_covering`), the NSEC3 predicates (`nsec3_owner_digest`, `nsec3_matches`,
  `nsec3_covers`, `nsec3_proves_nothing`, `nsec3_proves_no_type`, the two finders, `usable_nsec3`,
  `nsec3_record_is_from_proper_zone`), the §8.3 algorithm as `closest_encloser_proof` returning a
  `ClosestEncloserProof`, `wildcard_at`, and §8.4's full Name Error check as
  `nsec3_proves_nxdomain` returning an `Nsec3NxdomainProof`. Like the canonicalisation work, this
  authenticates nothing: it reports what a set of records asserts, and verifying those records
  remains the verification leg's job.
  **Two error types, because the two situations ask the resolver for opposite things.** An
  `IncompleteProofError` means the records were not in the response, which RFC 4035 §5.4¶6 says a
  resolver MUST act on by asking again — typically over TCP, since truncation is what drops proof
  records, and the third record of an NSEC3 denial is the one usually lost. A
  `ContradictoryProofError` means the records cannot all be true, where retrying is pointless and
  the answer is bogus. Collapsing the two is how a resolver ends up either hammering a server that
  is correctly refusing it, or accepting a forged denial because it retried its way to something
  that looked better.
  **The span has to wrap, and the naive reading of a zone's last record silently breaks it.** The
  last NSEC points back at the apex (RFC 4034 §4.1.1¶1) and the last NSEC3 back at the first hash
  (RFC 5155 §7.1¶19), so its second endpoint sorts *before* its first. Compare them the obvious way
  and that record appears to cover nothing: every name after the zone's final owner — which is what
  a passer-by probes, since it is where the chain ends — comes back unproven, and a legitimate
  NXDOMAIN is reported as bogus. `name_between` and `hash_between` both carry the wrap branch, and
  the single-owner-name case (endpoints equal, span covering everything else) falls out of the same
  expression rather than needing its own rule.
  Two bitmap rules are MUST-NOT-reads that implementations commonly get wrong in the permissive
  direction: RFC 4035
  §5.4¶7 requires ignoring the NSEC and RRSIG bits in an NSEC RR, because a validated NSEC already
  proves both exist at its owner name — so a signer that left them out of the bitmap must not be
  able to have it disprove the record carrying it; and RFC 5155 §7.1¶5 means a signed zone never
  lists NSEC3 in its own Type Bit Maps, so the same reasoning excludes that bit. §8.5¶2's related
  case — an empty non-terminal's record has an *empty* bitmap and correctly denies everything — is
  tested as well.
  **`closest_encloser_proof` implements RFC 5155 §8.3's algorithm literally, including an
  asymmetry that is easy to "simplify" into a bug.** The flag means "the name one label longer is
  covered", it is cleared only when a name has no matching record, and it survives the step up to
  the parent — which is the whole point, since the encloser is found by inheriting the flag its
  child raised. A name that matches while the flag is clear is *bogus* (§8.3¶10), not merely
  unhelpful: the server is denying a name it has just proven exists. §8.3¶12's proper-zone test is
  applied to the encloser's record — a DNAME there, or an NS without an SOA, means this server is
  not authoritative below the name it is denying, so the proof denies nothing however well signed.
  §8.4 then requires the wildcard at the encloser to be covered as well, which is the half that
  stops a server denying `hostile.example.com.` on the strength of having no such name while a
  `*.example.com.` answers for it. RFC 4592 §3.3.1¶4 is what makes that a single name to test
  rather than a wildcard search, and §3.3.1¶6-¶7 the reason no "closest wildcard" fallback exists.
  `usable_nsec3` applies §8.1 (ignore unknown hash algorithms) and §8.2¶1 (ignore Flags other than
  zero or one) as filters, then refuses mixed algorithm/iterations/salt sets under §8.2¶2's MAY:
  hashes from different parameters are not comparable, so a mixed set lets a server pair a matching
  record with a covering record computed differently and produce two proofs that together prove
  nothing. Opt-Out spans get `nsec3_proves_nothing` (§6¶3 — an Opt-Out record asserts nothing about
  what it covers, and reading it as a denial is the attack rather than an optimisation) and
  `ClosestEncloserProof.via_opt_out`, which is how the resolver will know not to set AD when
  RFC 5155 §9.2¶1 forbids it.
  **Not claimed.** §8.5's amended text from **erratum 3441** (a No Data response caused by an empty
  non-terminal under an Opt-Out span must carry the closest provable encloser proof) belongs with
  the No-Data validators, and §8.6-§8.9 (DS no-data, wildcard no-data, wildcard answers, referrals
  to unsigned subzones) are not implemented yet; neither is any of this wired to a `DnsPacket`,
  which needs the cache to hold proof records alongside a negative answer.


### Fixed

- **The name round-trip fuzzer could raise instead of skipping.**
  `test_names_survive_encode_parse_and_back` assumed the 255-octet limit away *after*
  encoding — `assume(len(bytes(name)) <= MAX_NAME_OCTETS)` — and the encoding is exactly
  what raises `DomainNameError` once the budget is blown, so the assumption guarded
  nothing and a stored six-label counterexample (39-to-40 octet labels) turned every
  local run red while CI's fresh `.hypothesis/` database and lower example count stayed
  green. The bound is now computed from the label octets before `from_labels` can raise,
  and the same ordering mistake in the unregistered-types property (the 0xFFFF record
  budget) is fixed the same way.

- **Ten test fixtures held an HTTPS record that cannot be parsed.** The octets
  `b"\x00\x00\x00\x01"` were used as HTTPS RDATA across `test_bundle.py` and
  `test_resolver_mqtype.py`: priority 0, target `.`, then one stray octet — and RFC 9460
  §2.2's first malformed condition is that "the end of the RDATA occurs within a SvcParam",
  which is exactly what a lone trailing octet is. Nothing noticed because no test round-tripped
  those records through the wire codec; the first thing that did was the new client-to-server
  interop test, and what it caught was the *client* discarding a complete, correct reply
  because the record inside it was malformed. They now carry a real minimal record (priority 1,
  target `.`, `alpn=h2`).
- **`docs/rfc-map.md` said EDNS(0) was decoded but not sent.** Outbound OPT has been sent for
  several rounds — advertised payload, `extended_rcode`, `ad`/`cd`, the §6.2.2 unextended
  re-ask, and NSID, EDE and MQTYPE options in use — while §11 still told a reader that outbound
  queries carried no OPT and that the payload ceiling was therefore 512 octets and the RCODEs
  still 4 bits. The bullet now describes what is actually partial about it (which options are
  put on the wire, and why COOKIE and Padding are not), and §10 gained the code-mapping rows
  those features never got: option TLVs and per-server payload sizes, Extended DNS Errors,
  MQTYPE in both directions, SVCB parameters, and the QNAME minimisation schedule.

### Changed

- **The coverage floor was not enforced anywhere.** `fail_under` in `pyproject.toml` is
  read by pytest through pytest-cov, and pytest-cov measures only when `--cov` is passed;
  the Test job ran plain `pytest -q`, so it exited 0 whatever the tests covered while the
  README, CONTRIBUTING and the comment above that floor all said it was enforced by
  pyproject. The step now runs `python -m pytest -q --cov`, and all three say so too.
  Verified in both directions: one test file exits 1 with "Required test coverage of 80.0%
  not reached", the whole suite exits 0 at 87.2%. The floor itself stays at 80 rather than
  moving to meet that figure — 87.2% was measured on one platform and one Python, CI gates
  on two of each, and a floor raised on a guess protects nothing.
- **`--trace` rendered every failure twice.** The `Fail` branch appended its note
  twice, so a reader counted one dead end as two. Fixed as part of giving glue
  observation somewhere to appear; `test_trace_mermaid.py` now pins the count.
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

- EDNS(0) *options* are implemented and several are put to use: NSID (RFC 5001) in
  both directions, per-server payload adaptation (RFC 6891 §6.2.3, §6.2.4), Extended DNS
  Errors (RFC 8914) composed and consumed, MQTYPE (RFC 10029) in both directions — the
  bundled server combines the QTYPEs a query names and reports which ones it folded in
  (§3.3–§3.4), and the resolver asks for them, reads what came back, and re-asks what did
  not (§3.2, §3.5) — and the bundled server answers an extended query with an OPT of its
  own (§6.1.1, §6.2.4).
  Still unused on purpose: COOKIE has no server-side state to validate a reply against,
  and Padding is never emitted because RFC 7830 §6 withdraws it from plaintext UDP, which
  is every transport here. No client subnet option (RFC 7871) and no transport keepalive
  (RFC 7828) — see `docs/roadmap.md`. Asking with MQTYPE is opt-in (`--mqtype`,
  `resolve_bundle`), so a lookup that did not ask for it still sends nothing a legacy
  server has never seen.
- No DNSSEC validation, no serve-stale (RFC 8767), no IDN/punycode
  (RFC 5891 / RFC 3492), no DoT/DoH (RFC 7858 / RFC 8484). QNAME
  minimisation (RFC 9156) ships opt-in — see *Added*.
