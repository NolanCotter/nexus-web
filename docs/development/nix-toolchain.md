# Nix toolchain + reproducibility notes (wave2/nix, 2026-09-17)

## Canonical path: `nix develop`

NixOS env has **no rustup** (`rustup: command not found`), nix 2.34.8.
The system nix-profile toolchain is **mismatched** and must not be used:

- `rustc 1.96.1 (31fca3adb 2026-06-26)`, `cargo 1.96.2`
- `cargo clippy --version` reports `0.1.97`, but the driver is
  `rustc 1.97.1 (8bab26f4f 2026-07-14)` — mixed nix-profile generations.
- Symptom after `cargo clean`: `cargo clippy` fails with
  `error[E0514]: found crate 'thiserror' compiled by an incompatible
  version of rustc ... please recompile that crate using this compiler
  (rustc 1.97.1 ...)`. The driver and rustc disagree, so no rebuild fixes it.

`nix develop` provides a **matched** toolchain (verified 2026-09-17):

- `rustc 1.98.1 (48a229cea 2026-09-01)`, `cargo 1.98.1`
- `clippy 0.1.98 (48a229ceae 2026-09-01)`, `rustfmt 1.9.0-stable`

Always run cargo commands inside `nix develop`:

```sh
nix develop --command cargo test --workspace
nix develop --command cargo clippy --workspace --all-targets -- -D warnings
nix develop --command cargo fmt --all -- --check
```

## Pinning

- `flake.nix` pins `rustVersion = "1.98.1"` via
  `pkgs.rust-bin.stable.${rustVersion}` (was `stable.latest`, which floats).
- `rust-toolchain.toml` pins `channel = "1.98.1"` (was `"stable"`).
  Inert without rustup, but governs CI's `dtolnay/rust-toolchain` action,
  which is pinned to `toolchain: 1.98.1` for the same reason.
- `flake.lock` is committed. Bump the pin in all three places at once.

## `nix flake check` scope (sandbox has no network)

`nix flake check` builds `checks.*` derivations in a sandbox **without
crates.io access**. The old `checks.build`
(`cargo test --workspace --offline || cargo test --workspace`) failed there:

```text
error: failed to get `ed25519-dalek` as a dependency of package
`nexus-identity v0.1.0 ...`
Caused by: ... [6] Could not resolve hostname (Could not resolve host:
index.crates.io)
```

So `checks.*` is intentionally hermetic now:

- `checks.fmt` — `cargo fmt --all -- --check` (no deps, sandbox-safe).
- `checks.toolchain` — asserts `rustc --version` matches the pin and
  records rustc/cargo/clippy versions.

Full `cargo test --workspace` coverage lives in `nix develop`
(62 passed, 0 failed, verified 2026-09-17 both `--offline` and online)
and in GitHub CI (networked).

## Clippy status (resolved 2026-09-17, lead integration)

`cargo clippy --workspace --all-targets -- -D warnings` inside
`nix develop` (matched 1.98.1/0.1.98) failed on **real lints**,
not version skew (fixed — see below):

```text
error: struct `MemoryBackend` has a public `len` method, but no `is_empty` method
   --> crates/resolver/src/backend.rs:182:5
    = help: ... clippy::len-without-is_empty ... `-D clippy::len-without-is-empty`
    = help: to override `-D warnings` add `#[allow(clippy::len_without_is_empty)]`
error: could not compile `nexus-resolver` (lib) due to 1 previous error
```

Fixed during lead integration (all green, exit 0): `MemoryBackend::is_empty`
for the `len-without-is-empty` lint above, `single_match` collapses in the
adversarial suites, `map_or(true, …)` → `is_some_and` negation (keeps MSRV
1.75; `is_none_or` needs 1.82), `repeat().take()` → `vec![x; n]`, `format!`
without args → string literal, never-loop `loop` → single `match`,
`incoming()` + `if let Ok` → `.flatten()`. CI keeps `-D warnings` strict.

## `cargo audit` status

- `cargo-audit 0.22.1` (nixpkgs) run 2026-09-17:
  `Scanning Cargo.lock for vulnerabilities (65 crate dependencies)`,
  exit 0, **no findings**.
- CI runs `cargo audit` as an **advisory** step (`continue-on-error: true`)
  so a future RUSTSEC disclosure can't brick unrelated PRs; check the step
  output and file the fix promptly.
- `nix develop` also ships `cargo-audit` and `cargo-fuzz`.
