# Fuzzing (NXP/0.1 parsers + `Page::from_json`)

Text protocol NXP/0.1 is frozen — fuzzing guards the parsers, it never changes
the wire format. Contract under test: **Err-never-panic** on any input.

## Layout (standard `cargo-fuzz`, standalone workspace)

- `fuzz/Cargo.toml` — own `[workspace]`, NOT a member of the root workspace,
  so `cargo test --workspace` / `cargo build --workspace` are unaffected.
- `fuzz/fuzz_targets/parse_request.rs` — `nexus_protocol::parse_request`
  (+ lossy-UTF8 path).
- `fuzz/fuzz_targets/split_response.rs` — `nexus_protocol::split_response`
  + `parse_response_header`.
- `fuzz/fuzz_targets/page_from_json.rs` — `nexus_content::Page::from_json`.
- `fuzz/corpus/<target>/` — AFL-style seed inputs (checked in).
- Deterministic fallback (runs on stable, no nightly):
  `crates/protocol/tests/adversarial.rs`, `crates/content/tests/adversarial.rs`.

## Prerequisites

`cargo-fuzz` needs a **nightly** toolchain (`-Zsanitizer=address`).
The stock dev shell is stable-only, so install/use nightly once:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz          # once; provides `cargo fuzz`
cargo fuzz --version              # expect cargo-fuzz 0.12.x
```

## Run

From the repo root:

```sh
cargo fuzz list
cargo fuzz run parse_request   -- -max_total_time=60 -print_final_stats=1
cargo fuzz run split_response  -- -max_total_time=60 -print_final_stats=1
cargo fuzz run page_from_json  -- -max_total_time=60 -print_final_stats=1
```

Artifacts / new corpus land in `fuzz/artifacts/<target>/` and
`fuzz/corpus/<target>/` (both gitignored except the checked-in seeds).
Minimize and check in any interesting new seed:

```sh
cargo fuzz cmin parse_request
```

## Stable fallback (always green, no nightly)

```sh
cargo test --workspace
cargo test -p nexus-protocol --test adversarial
cargo test -p nexus-content  --test adversarial
```

## Status (2026-09-17, wave2/fuzzing)

- `cargo-fuzz 0.12.0` installs cleanly.
- `cargo fuzz build parse_request` on the stable-only shell fails as expected:
  `error: the option 'Z' is only accepted on the nightly compiler`
  (full output in the lane report). No fuzzer crashes observed because no
  libFuzzer run was possible without nightly — the deterministic adversarial
  suites above are the committed safety net until a nightly run lands.
- Triage rule: any libFuzzer crash → minimize, add the input to
  `crates/*/tests/adversarial.rs` + `fuzz/corpus/<target>/`, fix, re-run.
## Nix runner (2026-09-17, wave2/nix)

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
