# Legacy design artifacts

Nothing here is used by the current code. It is kept because it explains a
design decision, not because it is runnable.

`schema.sql` and `database-schema.png` are a mysqldump and an ER diagram of an
earlier MySQL-backed design: tables `blob`, `blacklist`, `packet`, `name`,
`resource_record`, `packet_question`, `query`, `packet_record`. That model was a
*passive capture log* — store every packet seen, normalise names and RRs into
rows, keep raw payloads content-addressed by SHA-1 in `blob`, and hold a
`blacklist` of addresses to ignore.

What replaced it is :mod:`namespy.cache`: a small positive/negative RR cache with
two interchangeable backends, `MemoryCache` and `SqliteCache`
(:mod:`namespy.cache.memory`, :mod:`namespy.cache.sqlite`). The difference is the
point of keeping these files around. The old schema modelled *observed traffic*;
the current one models *cached answers with TTLs*, because RFC 1034 section 4.5.4
and RFC 2181 sections 5-8 make caching a time-bounded, authority-aware
operation, whereas logging is append-only and eternal. Storing a packet is not
the same job as holding an RRset until its TTL expires, and conflating them is
why the old tables never fit.

Two details still worth knowing if the topic comes up:

* `blob` keyed raw RDATA by SHA-1, which is a reasonable content-addressing
  trick and remains the natural way to deduplicate RDATA if storage ever becomes
  a problem again.
* `blacklist` used `VARBINARY(16)`, which is wide enough for IPv6 — a hint that
  the old code was written after IPv6 was already in view, and a reminder that a
  DNS cache key must never assume four-octet addresses.

Read them as history. Do not import them, and do not treat them as a target.
