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
- Next: wire signatures into fetch (M3), TUI browser, DHT experiment branch.

## Notes
- `cargo fmt --all` clean; `cargo test --workspace` green (53 tests).
- `cargo clippy` blocked on this machine: system clippy 0.1.97 vs rustc 1.96.1
  (E0514 incompatible crate artifacts). CI runs clippy with a matched toolchain;
  use `nix develop` (pinned toolchain) locally until the system set is aligned.
