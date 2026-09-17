# 009 — Signed Fetch Path (M3): seq, revocation, pinning, rotation

- Status: **accepted** — resolver lane M3; companion to `006-decentralized-resolution.md`
  (which planned `seq` as the first multi-source upgrade).
- Owner: resolution lane — `crates/resolver` + `crates/browser`. Wire protocol (NXP/0.1) untouched.

## Decisions

1. **Monotonic `seq` on `EndpointRecord`, newest verified wins.** `seq` is a
   *per-name* high-water mark shared by every accepted key of the name.
   Admission requires `record.seq > high_water(name)`; any lower-or-equal
   record is a stale replay and is dropped, whatever key signed it. This
   deviates from 006's "per (site, kind)" draft deliberately: a per-name
   sequence makes rotation a continuation (new key signs `high_water + 1`)
   and routing unambiguous — highest live, non-tombstoned `seq` wins, and
   `Route.pinned_site_id` follows the winner. Canonical bytes become
   `site \0 transport \0 host \0 port \0 seq \0 expires`; `#[serde(default)]`
   keeps pre-M3 envelopes decodeable (as seq 0 → immediately stale).

2. **Revocation tombstones.** `Revocation { site, max_seq, expires, sig }` is
   a signed record; once verified it installs a *permanent* tombstone:
   endpoint records of `site` with `seq <= max_seq` are suppressed at
   admit-time and filtered from `route()`. A key can only tombstone records
   it could have signed (no privilege escalation). Revocations ride the same
   `SignedRecord` envelope as endpoint records (JSON in `content_hash`,
   path `@name`), so backends deliver them identically.

3. **Key rotation and delegation wired into admission.** `RecordStore::rotate`
   applies `RotationLog` entries as cutovers (old key removed, its records
   tombstoned to the high-water mark, new key continues the sequence; chains
   apply topologically). `RecordStore::delegate` fully verifies
   `Delegation` (ed25519 signature against an accepted key, expiry,
   `path_prefix` covers the `@name` record path) before adding the delegate
   key to the accepted set.

4. **Browser pinning, fail closed.** `Route.pinned_site_id` threads through
   the browser: `navigate_with_records(resolver, site, path, &[SignedRecord])`
   fetches, then requires at least one record signed by the pinned key that
   names the path and matches the fetched page's canonical BLAKE3 content id.
   `navigate(...)` supplies no records, so any pinned route is refused.

## Gaps (explicit)

1. **Server does not serve signed records yet.** The browser API takes
   records explicitly rather than faking a wire fetch; the server/protocol
   lane must add a records endpoint, and the browser should then fetch
   records from the same host before trusting content.
2. **Warm-path cache bypass.** `CachingResolver` serves the petname table
   without re-consulting backends; revocation via a backend takes effect on
   the next cold resolve, and `revoke_record` invalidates the table
   explicitly. Cache-coherence (TTL / high-water summaries) is future work.
3. **RotationLog has no signed carrier** — `rotate()` is out-of-band policy
   today; a signed envelope carrying rotation entries is future work.
4. **Revocation authority** is limited to the target site's own key; a
   rotated-in key cannot tombstone the retired key's records (pre-sign the
   revocation while the old key is live).
5. **Delegation prefix matching** is a plain `starts_with` on the `@name`
   record path (`@` covers all names, `@alice` exactly one) — a hierarchical
   namespaced compare is future work.