# Fuzzing setup (nix lane notes, 2026-09-17)

## Decision: no duplicate skeleton on this branch

A complete `cargo-fuzz` workspace already exists on the
`wave2/fuzzing` lane: `fuzz/Cargo.toml` (standalone `[workspace]`,
`nexus-web-fuzz`, **not** a root-workspace member so
`cargo test --workspace` is unaffected) with three targets —
`fuzz_targets/parse_request.rs`, `split_response.rs`, `page_from_json.rs`
— plus a deterministic adversarial corpus (`fuzz/corpus/`).
Re-scaffolding it here would guarantee merge conflicts, so this lane
contributes the **reproducible runner** (toolchain + docs), not a second
copy. If `wave2/fuzzing` is ever dropped, recreate with:

```sh
cargo fuzz init   # then keep fuzz/ OUT of root workspace members
```

and one target per total-parse entry point
(`parse_request`, `split_response`/`parse_response_header`,
`Page::from_json`). Contract under test: **Err-never-panic** on any input
(see `docs/research/task-k-security.md`: "Total parsing").

## Prerequisites

- `cargo-fuzz` binary: system `cargo-fuzz 0.12.0` (`~/.cargo/bin`) and
  nixpkgs `cargo-fuzz` (in this branch's `nix develop` inputs) both present.
- Building/running fuzz targets fetches `libfuzzer-sys` from crates.io and
  needs clang + (for `cargo fuzz run`) a nightly toolchain for sanitizer
  flags. The pinned `1.98.1` stable toolchain builds and tests the workspace;
  fuzzing itself is a nightly activity. None of this works in the
  `nix flake check` sandbox (no network) — use `nix develop` (networked).

## Commands (from a checkout carrying `fuzz/`)

```sh
nix develop --command bash -c 'cargo fuzz list'
nix develop --command bash -c 'cargo fuzz run parse_request -- -max_total_time=60'
nix develop --command bash -c 'cargo fuzz run split_response -- -max_total_time=60'
nix develop --command bash -c 'cargo fuzz run page_from_json -- -max_total_time=60'
```

Seed with the checked-in corpus: `cargo fuzz run <target> fuzz/corpus/<target>/`.
Minimize new findings into `fuzz/corpus/<target>/` before committing.

## CI (future, not this lane)

Fuzz is **not** in CI yet (matches task-k-security hygiene row:
"audit/fuzz not in CI"). Recommended increment: short nightly
`cargo fuzz run <each target> -- -max_total_time=120` job, allowed to fail
open (`continue-on-error: true`) until corpus + targets are stable, then
enforce. Short smoke (`-runs=1000` per target) may join per-PR CI once
deterministic.
