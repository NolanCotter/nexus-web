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
- Next: records endpoint on server (M3 gap 1), TUI browser, DHT past gates.

## Notes (wave 2, 2026-09-17)
- `cargo test --workspace`: 141+ passed, 0 failed. `cargo fmt --check`: clean.
- `cargo clippy --workspace --all-targets -- -D warnings`: green under
  `nix develop` (pinned 1.98.1). System clippy still mismatched — use nix.
- `nix flake check`: all checks passed (verified locally).
- Lanes work in `wave2/*` branches + `/tmp/opencode` worktrees; main only
  takes reviewed merges. Research drafts live on `experiment/*` branches.
