# SHIP_LOG

Legitimate engineering increments only. One line per coherent change.

- [x] #1 bootstrap Rust workspace (10 crates) + README/LICENSE/gitignore
- [x] #2 Nix dev shell (flake.nix) + rust-toolchain pin
- [x] #3 NXP/0.1 protocol codec + limits + tests
- [x] #4 TCP transport framing + timeouts + tests
- [x] #5 Ed25519 site identity + signed records + expiry
- [x] #6 LocalResolver petname table + validation
- [x] #7 Typed page model + validation + BLAKE3 content IDs
- [x] #8 CAS stores (memory + filesystem, verify-on-read)
- [x] #9 Reference server (SiteStore + NXP handler + CLI)
- [x] #10 Terminal renderer (pure function + snapshots)
- [x] #11 WebVM capability broker (deny-by-default)
- [x] #12 CLI browser (resolve->fetch->parse->render + history)
- [x] #13 example site (home/about JSON, validated)
- [x] #14 architecture/protocol/identity/resolution docs + ADRs 001-005
- [x] #15 end-to-end integration test (server<->browser over TCP)
- [x] #16 CI (fmt+clippy+test) + GitHub push
- [x] #17 crypto identity research proposal archived (docs/research/)
- [x] #18 replication primitive: NXPACK1 pack export/import with verify-on-import (crates/storage, ADR 008)
- [x] #19 unified `nexus` CLI (browse <site[/path]> + interactive back/forward/reload/history)
- [x] #20 storage hardening: 0700/0600 perms, quota+eviction, corruption tests
- [x] #21 server conn caps (503), slowloris deadlines, EOF→Truncated mapping
- [x] #22 demo/e2e.sh smoke test + verified README quickstart
- [x] #23 richer terminal renderer (wrap, link index, placeholders) + showcase page
- [x] #24 cargo-fuzz skeleton + deterministic adversarial corpus (protocol/content)
- [x] #25 Resource envelope over Page (ADR 007): identity+version+references
- [x] #26 workspace audit: poison-proof locks, rustdoc, validation dedup, dep hygiene
- [x] #27 NXPACK1 merged (see #18); ADR renumbered to 008
- [x] #28 identity v1 domain-separated signatures, 0600 key files, rotation chains
- [x] #29 pinned Nix toolchain (1.98.1), hermetic `nix flake check`, CI audit step
- [x] #30 clippy `-D warnings` green under pinned toolchain (8 findings fixed)
- [x] #31 offline-first browser cache with stale fallback (Milestone G)
- [x] #32 resolver M3: seq, revocation tombstones, pin enforcement, rotation (ADR 009)
- [x] #33 security batteries: 237-input parser totality, traversal, 64-byte sig flips, resolver/store behavior (168 green)
- [x] #34 RECORDS verb + server record signing (--key) + wire-verified browser fetch (--pin); M3 gap 1 closed
- [x] #35 verified sessions: ClientSession pinning + `nexus browse --pin` interactive verified nav
- [x] #36 background record refresh: re-signer thread + --resign-interval, no restart
- [x] #37 full-screen TUI browser (`nexus-tui`): testable state machine + ratatui shell, verified-fetch aware
- [x] #38 verified offline cache: pinned chains cached + re-verified stale serve (`--pin` works offline)
- [x] #39 LIST verb + `nexus sync` site mirroring (verified with --pin)
- [x] #40 demo covers signed flow: keyed server, pin accept/refuse, verified sync
- [x] #41 cache GC: orphan/tmp reaping + `nexus cache-gc` (foreign files untouched)
- [x] #42 TUI polish: history persistence, find-in-page, help overlay
- [x] #43 cross-session `nexus history` shared with the TUI log
- [x] #44 federated resolver backend over RECORDS (DHT gate 2 dogfood, ADR 010)
- [x] #45 stock server serves @name endpoint plane + federated dogfood test
- [x] #46 DHT spike: Kademlia sim + sybil measurements → NO-GO per gates (`experiment/dht-kademlia`, path is federated→gossip)
- [x] #47 authoritative negative caching with TTL (failures/forgeries never cached)
- [x] #48 offline cache inside interactive sessions (TUI + browse go stale/verified-stale)
- [x] #49 sneakernet: NXPACK site export (`nexus export`) + server `--pack` import
- [x] #50 conditional FETCH: content-id preconditions + 304, cache revalidation
- [x] #51 canonical content IDs unified (lowercase-only everywhere; uppercase aliases rejected)
- [x] #52 endpoint failover across route endpoints (statuses never mask)
- [x] #53 adversarial corpus for LIST/RECORDS-@/if_id + fuzz seeds
- Next: DHT past gates, WebVM execution.

## Notes (wave 2, 2026-09-17)
- `cargo test --workspace`: 141+ passed, 0 failed. `cargo fmt --check`: clean.
- `cargo clippy --workspace --all-targets -- -D warnings`: green under
  `nix develop` (pinned 1.98.1). System clippy still mismatched — use nix.
- `nix flake check`: all checks passed (verified locally).
- Lanes work in `wave2/*` branches + `/tmp/opencode` worktrees; main only
  takes reviewed merges. Research drafts live on `experiment/*` branches.
