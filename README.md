# Nexus — experimental alternative web architecture

> Nexus is an experimental alternative web architecture built from first principles.

This repository is a research prototype. It is **not** production-ready.
We do **not** claim it is secure, decentralized, scalable, or revolutionary —
those properties must be demonstrated, not asserted.

## Goal

Design and implement a fundamentally different way for humans to identify,
discover, retrieve, render, interact with, and publish information over a
network — without cloning HTTP/DNS/HTML/URLs/browser architecture.

Current model under exploration:

```text
IDENTITY
   ↓
RESOURCE
   ↓
CONTENT
   ↓
CAPABILITIES
   ↓
REPLICATION
```

## Status

M0 skeleton + M1 first network slice (see `docs/`).

- `NXP/0.1`: minimal text request/response prototype over TCP (`crates/protocol`, `crates/transport`)
- Local petname resolver (`crates/resolver`)
- Ed25519 site identity + signed records (`crates/identity`)
- Content-addressed JSON page model (`crates/content`, `crates/storage`)
- Example server + CLI browser (`crates/server`, `crates/browser`)
- Capability-gated sandbox stub (`crates/webvm`)
- Terminal renderer (`crates/renderer`)

## Quickstart

From the repo root. Prereqs: a Rust stable toolchain
(`rust-toolchain.toml` pins `stable` + `rustfmt`, `clippy`, `rust-src`;
verified with `cargo 1.96.2`, plain `cargo` works, `nix develop` optional)
and `python3` (used by the demo script to pick a free port).

Build:

```bash
cargo build -p nexus-server -p nexus-browser
```

End-to-end demo — serves `sites/example`, fetches `home` + `about`,
checks a missing page 404s; exits nonzero on any surprise:

```bash
./demo/e2e.sh
```

Or the same steps manually:

```bash
./target/debug/nexus-server --port 7843 --site example --dir sites/example &
./target/debug/nexus-browser --server 127.0.0.1:7843 --site example --path home
./target/debug/nexus-browser --server 127.0.0.1:7843 --site example --path about
./target/debug/nexus-browser --server 127.0.0.1:7843 --site example --path does-not-exist  # expect 404, exit 1
kill %1
```

Run the test suite:

```bash
cargo test --workspace
```

## Docs

- `docs/architecture.md` — system overview
- `docs/protocol.md` — NXP/0.1 wire spec
- `docs/identity.md` — identity model
- `docs/resolution.md` — resolution model
- `docs/decisions/` — architecture decision records
- `docs/SHIP_LOG.md` — engineering log

## Principles

- Small vertical slices: one name resolves → one resource fetches → verifies → renders.
- Tests mandatory: `cargo test --workspace` must pass.
- No invented crypto; Ed25519 + BLAKE3 from reputable crates.
- Explicit capabilities; deny by default.
- Offline-first: local cache → peer → network → origin (roadmap).
