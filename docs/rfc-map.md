# Recursive Resolution: RFC 1034 mapped onto DNSpy

This document is the contributor reference for changes to
[`aiodns/resolver.py`](aiodns/resolver.py). It summarizes the parts of
[RFC 1034](https://www.ietf.org/rfc/rfc1034.txt) that drive resolution
decisions and points at the symbols in our code that implement each.

## 1. Recursive vs iterative service (RFC 1034 §4.3.1)

DNS messages carry two flag bits relevant to recursion:

- **RD** (Recursion Desired) — set by the *client* when it wants the
  server to chase referrals on its behalf.
- **RA** (Recursion Available) — set by the *server* when it is willing
  to provide that service.

`RecursiveResolver` accepts client queries with `RD=1` and answers
them by performing iterative resolution **upstream**: it sends its own
queries with `RD=0` to authoritative servers and follows referrals
itself. The `SendQuery` effect builds queries via
`Resolver.query(..., RD=False)`.

## 2. Resolver state (RFC 1034 §5.3.2)

| Spec field | Meaning | DNSpy symbol |
|---|---|---|
| SNAME  | The name we're searching for | `Sname.qname` |
| STYPE  | QTYPE of the search | `Sname.qtype` |
| SCLASS | QCLASS | `Sname.qclass` |
| SLIST  | Best-known nameservers for the current zone-cut | `Slist` |
| SBELT  | Safety-belt servers from configuration | `Sbelt` (built from `named.root` in `RecursiveResolver.bootstrap`) |
| CACHE  | RRs from previous responses | `DnsCache` (`MemoryDnsCache`, `SqliteDnsCache`), consulted at step 1 and written by `cache.put` |

Each `SlistEntry` is a `(zone, ns, addresses, history)` row representing
one nameserver candidate.

## 3. The four-step algorithm (§5.3.3)

```mermaid
flowchart TD
    Start[resolve SNAME, STYPE] --> Cache{Step 1: cache hit?}
    Cache -- yes --> ReturnCache[return cached RRs]
    Cache -- no --> Pick[Step 2: pick best server in SLIST]
    Pick --> Send[Step 3: send query]
    Send --> Analyze{Step 4: analyze response}
    Analyze -- "answer (4a)" --> Done[return]
    Analyze -- "better delegation (4b)" --> Pick
    Analyze -- "CNAME (4c)" --> Rename[SNAME = canonical] --> Cache
    Analyze -- "SERVFAIL/bizarre (4d)" --> Demote[demote server] --> Send
```

In DNSpy:

- **Step 1** (cache lookup): consulted at the top of every iteration of
  `resolve_steps`, so a re-anchored alias target gets a cache check too rather
  than only the original QNAME. A hit yields `Answer`/`Nxdomain`/`Nodata` plus
  `Done(_synthesize_response(...))` and returns without touching the network;
  a miss falls through to step 2. Writes happen through `cache.put` when a
  response is classified. See
  [`aiodns/cache/__init__.py`](aiodns/cache/__init__.py) for `DnsCache`, its
  in-memory and SQLite backends, and how negative entries take their TTL from
  the SOA (RFC 2308 §5).
- **Step 2** (pick best server): `Slist.best()` returns the first
  non-demoted entry. If that entry has no addresses, the generator
  yields `NeedAddress(ns)` and the driver runs a *nested* `resolve_steps`
  to discover them (see §7).
- **Step 3** (send): the generator yields `SendQuery(entry, questions)`;
  the async driver fulfills it with `Resolver.query(...)` and feeds the
  response back via `gen.send(response)`.
- **Step 4** (analyze): `classify(response, sname, slist, entry)` is a
  small pure generator that yields one of:
  - `Answer(records)` + `Done(response)` — final answer (4a),
  - `Referral(old_zone, new_zone, match_before, match_after)` — valid
    "closer" delegation (4b), after extending `Slist`,
  - `Cname(target)` — one redirection taken; if no `Done` follows, the driver
    re-anchors SNAME and restarts at step 2 (4c, see §6),
  - `Demote(entry, reason)` — SERVFAIL / bogus / not-closer (4d),
  - `Fail(reason)` — a broken alias chain or exhausted hops, which is
    deliberately *not* a cacheable negative.

## 4. Match count and "closer" delegations (§5.3.3 step 4b)

A referral is only progress if the new zone has *strictly more* labels
in common with SNAME (counted from the root) than the previous zone:

- SNAME = `example.org`, current zone = `.` (match 0).
- Referral to `org.` (match 1) — accepted.
- Referral to `example.org.` (match 2) — accepted.
- Referral back to `.` or to `com.` (match 0) — rejected, server demoted.

`Sname.match_count(zone)` does the counting; `classify()` enforces the
inequality before extending `Slist`.

## 5. Negative responses (§4.3.4)

NXDOMAIN and NODATA both carry the SOA in the **authority** section of
the wire response, *not* the answer section. Our classifier mirrors
that:

- `RCODE == NAME_ERROR` → NXDOMAIN. Yields `Nxdomain()` then `Done(response)`.
- Any other non-`NO_ERROR` RCODE → `Demote(entry, "rcode <mnemonic>")`, and
  the lookup tries another server. The mnemonic comes from
  `DnsResponseCode.mnemonic()` because RCODE is a plain `int` for values the
  enum has no member for (11-15 are unassigned; §6.1.3 of RFC 6891 makes the
  field 12 bits wide).
- `ANCOUNT == 0` → the **content of the authority section** decides, per
  RFC 2308 §2.2.1, which classifies by SOA-versus-NS presence rather than by
  the `AA` bit:
  - `AA=1`: a server claiming authority cannot simultaneously be referring us
    onward, so an empty answer is NODATA whatever else is there.
  - `AA=0` with SOA and no NS: "type 2" NODATA — a shape RFC 2308 §2.2.1
    recommends precisely because the alternative is so often misread as a
    referral.
  - `AA=0` with NS RRs *closer* than the current zone: a referral (§5.3.3 4b).
  - `AA=0` with neither: `Demote`, because a negative answer with no SOA has no
    TTL and RFC 2308 §5 says it "SHOULD NOT be cached as there is no way to
    prevent the negative responses looping forever".

The SOA (if present) is read straight out of `response.nameservers`; it is
never re-queried. Do **not** synthesize an extra SOA query — the SOA is already
in the response we just received, and a second query would race against it.

Classifying on `AA` *before* inspecting the authority section was an earlier
bug: the non-authoritative NODATA above is the common case for a recursive
resolver, and it was being sent down the referral path, which demoted a
perfectly healthy server.

## 6. Alias chasing (§5.3.3 step 4c, RFC 6672)

An answer that contains a CNAME whose target is not itself answered is **not
a conclusion**: §5.3.3 step 4c says "if the answer contains a CNAME RR, set
SNAME to the contents of the RDATA field of the displayed CNAME RR, and go to
step 2". So the lookup restarts with QNAME re-anchored at the target, QTYPE
unchanged — an A query for an aliased name becomes an A query for the target,
and only the target's RRset can end it.

Two pieces, deliberately split:

- `_follow_aliases(response, sname)` walks the chain *inside one response* and
  returns an `AliasWalk`: resolved records, the trace `Cname` events, either a
  `continued_at` target that needs another query, or a `failure`.
- `resolve_steps` owns the loop *across responses*, because only it can count
  hops over several round trips. It re-anchors `sname` and re-enters at step 2,
  bounded by `max_alias_hops` (`MAX_ALIAS_HOPS` by default, configurable per
  `Resolver`).

A trailing `Cname` with no `Done` is therefore the normal signal for "keep
going", not an error — `classify` stays a pure per-response classifier so it
remains directly testable, and the driver owns the state.

A chain that loops or exceeds the hop cap yields `Fail`, **not** NODATA:
RFC 2308 §5 would have us cache a NODATA against the zone SOA, so one malformed
alias set would hide a live name for the length of the zone's MINIMUM.

DNAME (RFC 6672) is handled in the same walk: a DNAME at or above QNAME
redirects the whole subtree, and the synthesized name is QNAME's labels below
the owner prepended to the DNAME's target (§2.3). The owner itself is never
redirected — §2.3 says "the owner name of a DNAME RR is not redirected itself"
— so the enclosing-owner scan uses the strict subdomain test
(`is_subdomain_of(owner, include_self=False)`).

## 7. Glueless delegation (§5.3.3 step 2 priorities)

A referral can list NS names without addresses (no glue in the
additional section). We then need the address before we can query the
delegated zone. The generator yields `NeedAddress(ns_name)`; the driver
runs a nested `resolve_steps` for `ns_name A` (capped at `MAX_DEPTH`)
and feeds the resulting addresses back via `gen.send(addresses)`. The
nested resolution gets its own `Trace` child and renders as a separate
Mermaid `sequenceDiagram` block under the parent.

## 8. Server-side reply shape (§4.3.2 a/b/c)

Knowing what an authoritative server emits helps interpret what we
receive on the client side:

- **a**: matched node — copy matching RRs into answer; CNAME causes
  rename. `AA=1`.
- **b**: encountered an NS cut — copy NS RRs into authority, addresses
  into additional ("glue if needed"). `AA=0` (referral).
- **c**: no match — return NXDOMAIN (authoritative name error).

Mapping to our classifier:

| Server emits | Classifier branch |
|---|---|
| `AA=1`, `ANCOUNT > 0` | answer (4a, a) — after any CNAME/DNAME walk |
| Alias whose target is unanswered | re-anchor SNAME, go to step 2 (4c) |
| `AA=0`, `ANCOUNT = 0`, NS closer than current zone | referral (4b, b) |
| `ANCOUNT = 0`, SOA in authority | NODATA (§4.3.4; RFC 2308 §2.2.1) |
| `RCODE = NAME_ERROR` | NXDOMAIN (4d, c) |
| other `RCODE`, or no SOA to time a negative by | demote (4d) |

## 9. Architecture: generator of effects

```mermaid
flowchart LR
    Resolve[resolve dns_packet] --> Drive[_drive async]
    Drive -->|"next(gen)"| Gen[resolve_steps generator]
    Gen -->|"yield SendQuery"| Drive
    Drive -->|"await self.query"| Net[(UDP)]
    Net -->|"Response"| Drive
    Drive -->|"gen.send Response"| Gen
    Gen -->|"yield NeedAddress(ns)"| Drive
    Drive -->|"_drive child gen"| Gen
    Gen -->|"yield Done"| Drive --> Resolve
```

The resolver becomes pure logic that yields effect objects describing
what to do next; the async driver fulfills them. The yield stream **is**
the trace (plus nested child streams for sub-resolves). Tests drive the
generator synchronously with `gen.send(canned_response)` — no sockets.

## 10. Code mapping

| Concept | File / symbol |
|---|---|
| SBELT root hints | `RecursiveResolver.bootstrap()` -> `RecursiveResolver.sbelt` |
| SLIST construction | `Sbelt.copy_for(sname)` |
| Server selection (§5.3.3 step 2) | `Slist.best()` |
| Send (§5.3.3 step 3) | `SendQuery` effect, `Resolver.query()` |
| Analyze (§5.3.3 step 4) | `classify(response, sname, slist, entry)` |
| Match count (§5.3.3 step 4b) | `Sname.match_count(zone)` |
| Glueless NS resolution | `NeedAddress` effect + `_drive` recursion |
| Negative responses (§4.3.4) | `Nodata`, `Nxdomain` events |
| Truncation → TCP retry (RFC 1123 §6.1.3.2) | `Resolver._await_udp()` → `Resolver._query_tcp()` |
| No-cache-on-truncation (RFC 1035 §7.4) | `_write_cache()` early return |
| Trace tree | [`aiodns/trace.py`](aiodns/trace.py) `Trace` |
| Mermaid output | `Trace.to_mermaid()` |

## 11. Known gaps

Deliberately unimplemented, each with the spec that would drive it:

- **EDNS(0) is decoded but not sent.** `DnsPacket` reads an OPT record and
  exposes `extended_rcode`, `ad`, `cd` and `requestor_payload_size`
  (RFC 6891 §6.1.2-6.1.3), but outbound queries carry no OPT. That leaves the
  UDP payload ceiling at 512 octets (§6.2.3) and caps us at the 4-bit RCODEs.
  Truncation is a direct consequence of that ceiling, and is now handled: a
  `TC` answer is re-asked over TCP rather than believed (RFC 1123 §6.1.3.2).
- **QNAME minimisation** (RFC 9156) is not done: the full QNAME goes to every
  server on the way down. See the note in `resolve_steps`.
- **No DNSSEC validation.** The `AD` bit is surfaced but not verified; nothing
  in `RDATA` speaks RRSIG/DNSKEY (RFC 4033/4034/4035), and there is no trust
  anchor.
- **Out-of-bailiwick referral names.** `classify` already marks a referral lame
  when an *in*-bailiwick NS arrives without glue (RFC 5625 §2.5); it does not
  yet check the reverse case, where the authority section's NS names sit outside
  the new zone and no glue was offered either.
- **No IDN/punycode.** Labels are octets, end to end (RFC 2181 §11). A caller
  wanting RFC 5890-style A-labels must encode before calling.

Closed since this document was first written, and now covered by tests:
the cache (step 1), CNAME/DNAME chasing (step 4c), and IPv6 glue with a real
v6 transport.
