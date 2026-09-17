# Task K: Security model — proposal (archived subagent report)

> Source: Security Engineer (background research crew).
> Status: proposal, not yet fully implemented. This doc records both the
> recommendations and, honestly, where v0 code does and does not meet them.

## Ground rules (adopted)

- **Never claim security because Rust.** `unsafe_code = "forbid"` is a floor.
- **Total parsing:** no panics on untrusted input; no `unwrap`/`expect`/
  indexing in decode paths.
- **Fail closed:** unknown versions, malformed lengths, oversize claims ->
  reject and close. Never best-effort parse.
- **Zero ambient authority:** webvm/renderer get only explicitly granted caps.
- **Untrusted-by-default:** lengths are advisory, names are strings not
  paths, network bytes are data, not instructions.

## Trust domains (most -> least trusted)

1. Chrome core (browser orchestration, identity keys, storage root).
2. Signed content pipeline (protocol/resolver/content/storage code trusted,
   inputs adversarial).
3. Untrusted execution (page markup, future site code): hostile payloads.
4. Network: hostile + active MITM.

Rule: domain 3 reaches domain 1 only through the capability API, as typed,
logged, revocable grants.

## Per-subsystem rules vs v0 reality

| Area | Rule | v0 status |
|---|---|---|
| Protocol framing | length capped before allocation; fixed widths; depth budget; fuzz | DONE in code (MAX_LINE/MAX_BODY, no varints, no recursion, trailing-garbage rejected, 11 parser tests). Fuzz NOT yet set up |
| Transport | authenticated handshake, one suite, deadlines, conn caps | PARTIAL: timeouts + line/body caps exist; NO encryption/auth yet (loopback demo only). Tracked as M1 gate |
| Identity | ed25519 only, OS RNG, 0600 key files, domain-separated sigs, verify-against-resolved-key | PARTIAL: ed25519 + canonical bytes + expiry exist with tests; domain-separation tag + key-file hygiene NOT yet implemented |
| Resolver | resolver never authenticates; client verifies owner sig + content hash; monotonic versions defeat rollback | NOT yet: LocalResolver has no signed bindings; `pinned_site_id` field exists but is unenforced. M3 work |
| Content | hash verified before parse/render; full 256-bit hashes; decompression caps; manifest/subresource caps | PARTIAL: full BLAKE3 IDs, verify-on-read in storage, page size/component/depth caps exist. No compression support at all (nothing to bomb — yet) |
| Storage | keys computed from hashes, never from names; 0700 root; no symlinks; atomic writes; quotas | MOSTLY DONE: hex-validated IDs, traversal rejected + tested, temp+rename writes. Dir perms/quota eviction NOT enforced |
| Server | loopback default; per-peer limits; slowloris resistance; never forward arbitrary URLs | PARTIAL: binds 127.0.0.1 by default, one-thread-per-conn (no cap — DoS note accepted for demo). No rate limits yet |
| webvm/renderer | separate OS process, ~5-import host ABI by copy, per-origin caps, memory cap, watchdog | STUB: Broker enforces deny-by-default + quotas with audit log and tests, but executes nothing and is in-process. Process isolation is M6 work |
| Browser | origin = identity (not address); grant table single choke point, revoked on navigation; chrome-drawn identity display | PARTIAL: origin model is petname+endpoint (pre-identity); history stack exists; no permission UI yet |
| Hygiene | cargo audit, pinned crypto, panic-freedom in decode paths | NOT yet: audit/fuzz not in CI. Release `panic=abort` not set |

## Ranked risks (abridged)

1. webvm/renderer escape -> host compromise (no exec yet, so latent).
2. Transport without peer auth (accepted for loopback demo; gate before any LAN use).
3. Parser panics on hostile frames (mitigated by total-parse code + tests; needs fuzz).
4. Key file mishandling (no key files written yet; rule must land with M3).
5. Version rollback (needs monotonic binding versions in M3).
6. Disk exhaustion via cache (no quotas yet; demo-scale only).
7. Resolver eclipse (no P2P yet; client-side verification is the planned fix).
8. Phishing via identity confusion (no identity UI yet).
9. Dependency CVEs (no audit in CI yet).

## M0/M1 gates (from report, adopted as checklist)

M0 demo: loopback-only bind; capped fail-closed parser; signed sample
manifest verified before render; 0700 storage root plan; timeouts
everywhere; CI with fmt + tests (+ clippy blocked locally, runs in CI).
M1: authenticated handshake; signed bindings + rollback rejection;
per-peer limits; grant table with expiry + revocation; storage quotas;
key rotation path. Explicit M1 non-goals: revocation infrastructure,
encrypted-at-rest cache, multi-suite negotiation, anonymous browsing.

## Recommended next security increments

1. `cargo-fuzz` target for `parse_request`/`split_response` + name validation.
2. `cargo audit` (or `cargo deny`) in CI.
3. Domain-separation prefix in `ResourceRecord::canonical_bytes` (wire-breaking
   change — do BEFORE any real deployment; current canonical form has no tag).
4. Enforce `pinned_site_id` in the browser fetch path (M3).
5. Cap server connection count + add per-connection read deadlines.
