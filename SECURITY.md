# Security Policy

This is a DNS **library**: a wire codec, an iterative resolver, and a demo
server. Its threat model is therefore mostly the one described in RFC 5625
(DNS Message Implementation Requirements) and RFC 9267 (DNS Transfer
Compression Considered Harmful), which is unusually concrete about what a parser
must survive.

## Reporting a vulnerability

Email the maintainer, or open a [private security advisory][advisory] on GitHub
rather than a public issue. There is no NDA and no embargo period imposed — the
expectation is simply that a fix exists before details are public.

[advisory]: https://github.com/b1tninja/DNSpy/security/advisories/new

## Supported versions

| Version | Supported |
| ------- | --------- |
| `master` | ✅ |
| Anything reachable by tag | ✅ until superseded |
| Anything else | ❌ — there are no backport branches |

This project has never been published to PyPI, so `master` is the only real
support surface.

## Attack surface, and what is actually done about it

### Parsing untrusted messages — the primary surface

Everything that arrives from a socket is attacker-chosen bytes. The rules below
are enforced by the test suite, and `tools/` and CI keep them enforced:

- **No `assert` on wire data, anywhere.** An `assert` compiled out by `python -O`
  or `PYTHONOPTIMIZE` is not a check. Every bounds test in `names.py`,
  `packet.py` and `rdata.py` raises `DnsPacketParseError` instead, and CI runs
  the whole suite under `python -O` so the policy fails loudly if a future commit
  quietly reintroduces the pattern.
- **Compression pointers are bounded, not merely tracked.** RFC 9267 section 2
  describes both the loop and the "broken implementation" that tests
  `offset & 0b11000000` instead of `(offset & 0xC0) == 0xC0` — the earlier
  revision of this code had the broken test, which meant octets `0x40`–`0xBF`
  were misread as pointers. Pointer targets must strictly decrease, reserved
  2-bit label types `10`/`01` are rejected, and an expanded name may not exceed
  255 octets counting label-length octets (RFC 9267 section 4).
- **RDATA is read inside its declared length.** RFC 9267 section 5: reading past
  RDLENGTH walks into the next record. Slicing that yields a *short* result
  rather than failing is treated as a bug, which is why `rdata_octets()` exists.
- **Unknown RR types and classes are data, not errors.** RFC 3597 section 3
  requires them to pass through opaquely. An `HTTPS` (65) or `CSYNC` (62) record
  used to raise `AttributeError` inside a protocol callback, which took down the
  listener; they now decode to an opaque `RData` blob.
- **Malformed input is discarded, not escalated.** A parse failure logs at
  `DEBUG`, never at `WARNING` with the datagram attached, so an attacker spraying
  garbage cannot use this library's log as an amplifier (RFC 5358 section 4.2).

### Accepting a response — cache poisoning

A reply is only credited to a query if it comes from **the same address we sent
it to**, carries the **same transaction ID**, and **echoes the question section**
(QNAME, QTYPE, QCLASS) faithfully — see `_pending_key` /
`_is_expected_response` in `resolver.py`. That is RFC 5452 sections 5 and 6:
the ID is 16 bits and brute-forceable alone, but a forger must also reproduce the
name being resolved. A response with no question section never matches, which is
deliberate — RFC 1035 section 4.1 makes the question section mandatory in
responses.

Query IDs come from `random.getrandbits`, and outgoing sockets bind to port `0`
so the OS chooses an ephemeral source port; both are required by RFC 5452
section 5 and neither is optional.

**Not implemented, and you should know before relying on it:**

- **No DNSSEC validation** (RFC 4033/4034/4035). Answers are unauthenticated. A
  network-position attacker who can deliver a well-formed, question-matching
  response to the right port still wins; nothing here checks an RRSIG.
- **No response rate limiting.** This library is a client. If you embed it in
  something that answers on behalf of others, RFC 5358 becomes your obligation.
- **No EDNS(0) on outbound queries** yet, so answers are capped at 512 octets and
  extended RCODEs are not requested (RFC 6891). The decoder *can* read an OPT
  record if one arrives.
- **No bailiwick enforcement** on glue and extra-section records (RFC 5625
  section 2.5). Names below a zone cut can be filled in by the server that
  supplied them.

### The bundled server and CLI demo

`aiodns.server.Server` and `dnspy --serve` exist to exercise the codec against a
loopback peer. **They are not a name server product and must not be exposed to a
network you do not control.** An unauthorised recursive resolver on a reachable
address is an amplification and cache-poisoning instrument; RFC 5358 and RFC 9085
are the documents that explain why, and BCP 140 covers the operational side. The
CLI binds `127.0.0.1:53`; anything broader is a deliberate edit you are making,
and should come with an ACL, a rate limit, and a version-caching plan.

### Outbound fetching

The resolver ships with packaged root hints and does **not** fetch them at
runtime. Refreshing them is an explicit call (`Resolver.refresh_root_hints`), it
updates in-memory state only — the packaged file is never overwritten — and a
failed or truncated download leaves the existing hint set untouched rather than
replacing it with something unusable, which is the failure mode that makes a
resolver appear broken for days.

## Non-security notes that look like security notes

- `random` is used for transaction IDs and nothing cryptographic. DNS's ID is not
  a secret in the authenticated sense; if you need authentication, you need
  DNSSEC or a transport that provides it (RFC 7858, RFC 8484, RFC 9157).
- The `sqlite` cache stores what it was given, with no integrity check on load.
  Treat the database file as part of the trust boundary: if an attacker can write
  it, they can inject answers.
