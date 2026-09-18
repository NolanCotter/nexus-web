# 010 — Federated Records Wire Convention (v1 backend dogfood)

- Status: **accepted** — resolver lane; companion to `009-signed-fetch-path.md`.
  DHT milestone gate #2 (federated backend dogfooded). NXP/0.1 untouched:
  same verbs, framing, limits, and response shape.
- Owner: `crates/resolver` — `FederatedBackend` + the test-only record server
  in `tests/federated.rs`.

## Convention

Federated resolution is **pull-only and DNS-like**. For a valid site name
`name`, `FederatedBackend::fetch` sends, over nexus-transport TCP framing:

```text
NXP/0.1 RECORDS <name> @<name>\n
```

- `<name>` (site field): the name being resolved — lowercase rule shared with
  every NXP request.
- `@<name>` (path field): the **endpoint-record namespace** for that name —
  the exact record path the resolver core keys on
  (`signed.record.path == "@name"`, identical to the `MemoryBackend::fetch`
  filter). The `@` prefix disambiguates endpoint records from content records
  served at content paths (the `server` crate serves `RECORDS example home`
  for pages).

Response (framing and body shape identical to every NXP response):

```text
NXP/0.1 200 <len>\n<JSON array of SignedRecord>
```

- Each envelope: `path == "@<name>"`, `content_hash` = JSON of an
  `EndpointRecord` (or a `Revocation` — tombstones ride the same envelope),
  per the v0 convention `CachingResolver::resolve` already consumes.
- `NXP/0.1 404 <len>\n` = authoritative "no records for this name" (negative
  answer, not a failure).
- Any other code, an undecodable body, or a transport error = the backend
  records a failure and returns nothing.

## Deviation from the stock parser (documented, deliberate — closed 2026-09-18)

`nexus_protocol::is_valid_path` validates *content* paths and rejects `@`, so
`parse_records_request` admits exactly `@<site>` (and the encoder builds it)
while `parse_request` (FETCH) never does. Stock servers serve the endpoint
plane from `endpoints/<name>.json` via `SiteStore::insert_endpoint_records`.
Rationale: the RECORDS verb, frame shape, size limits, and JSON response body
are reused exactly — nothing new on the wire. The `@` is the record-namespace
marker, not a protocol change; name bytes still pass `is_valid_site`, so the
line carries no injection characters. A server answering `400` is treated as
a transport failure.

## Security model

Servers are availability points, never authorities. The backend never
verifies: every envelope is admitted (or dropped) through the identical core
path as `MemoryBackend` — signature + site match + expiry + strictly-advancing
seq against the out-of-band trust anchor. A malicious server can withhold data
(404/empty) or serve forged, expired, stale, or foreign-key records; all fail
verification and are never admitted. Multiple endpoints are queried in order
and aggregated; the core's merge rule (newest verified wins) reconciles them —
a poisoned or unreachable endpoint cannot veto a valid answer.

## Gaps

- No client-side caching/TTL of fetched records (the warm-table fast path
  already bypasses backends; see 009).
- ~~No negative cache for authoritative 404s~~ DONE 2026-09-18:
  `Backend::fetch_authoritative` + TTL negative cache on misses
  (failures/forgeries never cached); no refresh without a cold miss.
- No publish path: NXP/0.1 has no push verb, so records are signed and
  published out-of-band at the resolver (DNS model).