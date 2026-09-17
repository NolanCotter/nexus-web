# 007 — Resource envelope over Page

- Status: accepted (v0)
- Companion: ADR 003 (typed Page), ADR 002 (content addressing)
- Scope: `crates/content`

## Context

`Page` (ADR 003) is the canonical document: typed `components`, JSON on the
wire, BLAKE3 content IDs over canonical bytes. It has worked. But the system
around it now addresses, signs, and resolves content (`ResourceRecord` in
`crates/identity`: site → path → content_hash; `crates/resolver`),
and every layer re-derives the same facts by hand:

- **identity** — `Page::content_id()` is computed on demand; the served
  bytes never carry them. A cache cannot tell what it is holding without
  hashing it.
- **version** — `metadata.revision: u64` exists, but there is no link to the
  previous revision, so history/invalidation need external bookkeeping.
- **references** — links live inside `Component::Link` targets; the renderer
  string-matches `LinkTarget::Page { site, path }` and there is no
  machine-readable list of a page's outbound edges (needed for prefetch,
  verification, crawls).

The question: is `Page` still the right top-level primitive, or does a
general `Resource` envelope (identity + content + capabilities + version +
references) wrap it?

## Problem

A served unit of content is more than its document tree. Addressability
(`b3:` id, site, path), version lineage (revision, previous id), and outbound
edges (references) are structural — every consumer needs them — yet none are
first-class in the type. Consumers that need them either recompute ad hoc
(renderer walks components) or invent parallel structures (resolver's
`content_hash` strings). The content model should say what a content unit
*is*, once.

## Options

| Option | Gives you | Costs | Verdict |
|---|---|---|---|
| Keep `Page` only, compute identity/edges in callers | zero churn | every consumer re-derives the same facts; no envelope to validate or cache against | rejected |
| Replace `Page` with a flat `Resource` (schema 2), migrate all JSON | one clean type | breaks `sites/example/*.json`, every consumer, ADR 003's canonical wire shape; rename-only churn | rejected |
| `Resource` envelope **wraps** `Page`; dual-mode JSON (envelope in, bare Page still parses) | identity/version/references first-class; zero breakage; additive | two accepted input shapes (documented); envelope is presentation, not hash input | **accepted** |

The deciding constraints: (a) existing site JSON must keep parsing, (b) ADR
003's document tree is correct and unchanged, (c) identity must not depend on
envelope adornment — the same page must have the same content ID whether it
arrives bare or enveloped.

## Decision

`Page` remains the canonical content payload — unchanged, wire-compatible.
A new `Resource` envelope becomes the addressed, served primitive:

```rust
pub struct Resource {
    pub id: String,                    // b3:<hex> over the BARE Page bytes
    pub content: Page,                 // ADR 003 payload
    pub previous: Option<String>,      // content id of prior revision (version chain)
    pub references: Vec<Reference>,    // derived outbound edges (label + LinkTarget)
}
```

- **Identity**: `id` is always `content_id_of(content.to_canonical_json())`
  — the hash is over the bare Page bytes, never the envelope. A bare fetch
  and an enveloped fetch of the same page therefore agree on identity, and
  `previous`/`references` can change without moving the hash.
- **Version**: `content.metadata.revision` is the version number;
  `previous` links the lineage. `Resource::validate` checks `previous` is a
  valid content ID when present.
- **Capabilities**: stay on `Page` (ADR 003) — they are content-level grants,
  not addressing data. The envelope does not duplicate them.
- **References**: `Reference { label, target: LinkTarget }`, derived by
  walking components (collections included) in document order. Stored
  `references` on the wire are validated to equal the derived set; when
  absent, they are derived (so bare Page JSON is a valid envelope-less
  input).
- **Dual-mode JSON**: `Resource::from_json` accepts (1) a full envelope
  `{ id, content, previous?, references? }` with validation, or (2) bare
  Page JSON (a `sites/example/` file today), which wraps it, derives
  `references`, and computes `id`. Serialization emits the envelope.
- **Resolution helper**: `ReferenceResolver` maps `(site, path) -> content id`
  (v0: an in-memory table; later `crates/resolver` feeds it) and resolves a
  resource's edges to `ResolvedReference { label, target, content_id }`.
  Renderers stop string-matching targets.

`Page::from_json` still parses bare Page JSON exactly as before; no consumer
changes.

## Consequences

- `sites/example/*.json` parse unchanged (as `Page`, and as `Resource` via
  the bare-page fallback).
- Page's data model is untouched; ADR 003 stands. Envelope adoption is
  incremental — a server may serve bare pages today and enveloped resources
  later without breaking hashes.
- Content IDs stay stable under re-addressing: moving a page between sites
  changes nothing about its hash, only its `Reference::Page` edges and the
  resolver's `(site, path)` map.
- Two accepted input shapes is a small parser surface; both go through the
  same `validate()` path and the envelope's `id` is self-checking
  (declared id must equal the recomputed hash), so a mismatched envelope is
  rejected, not trusted.
- Validation cost: an extra canonical-JSON hash per envelope parse — trivial
  at v0 sizes (1 MiB cap), buys tamper-evidence at the type boundary.
- `ReferenceResolver`'s table is a v0 stand-in; replacing it with
  signed-record lookup (ADR 006) is a drop-in swap behind the same
  `(site, path) -> content id` contract.

## Files

- `crates/content/src/lib.rs` — `Resource`, `Reference`, `ResolvedReference`,
  `ReferenceResolver`, dual-mode serde, validation, tests
- `docs/decisions/007-resource-model.md` — this ADR