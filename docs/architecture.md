# Nexus architecture (v0 experiment)

Experimental alternative web stack. Not production-ready.

```text
IDENTITY  -> Ed25519 site keys; site ID = hex(pubkey)
RESOURCE  -> (site, path) validated names, no `..`, no leading `/`
CONTENT   -> typed Page JSON, content ID = b3:<blake3 hex>
CAPABILITIES -> explicit per-page grants, deny by default (webvm Broker)
REPLICATION -> roadmap: local cache -> peer -> network -> origin
```

## Data flow (M1 slice)

```text
browser CLI input (site, path)
  -> LocalResolver petname -> endpoint
  -> NXP/0.1 FETCH site path over TCP
  -> server SiteStore lookup
  -> Page JSON bytes
  -> Page::from_json + validate
  -> renderer render_text
```

## Crates

| crate | role | trusts |
|---|---|---|
| protocol | NXP line + header codec, limits | nothing |
| transport | TCP framing, timeouts | protocol |
| resolver | petname table + Resolver trait | nothing |
| identity | Ed25519 keys, signed records, expiry | ed25519-dalek |
| content | Page model, validation, content IDs | blake3, serde_json |
| storage | MemStore + FsStore CAS, verify-on-read | blake3 |
| server | SiteStore, one-thread-per-conn TCP | transport, content |
| renderer | Page -> text | content |
| webvm | capability Broker, deny-by-default | content |
| browser | navigate + history + CLI | all above |

## Key limits (DoS posture)

- Request line <= 4096 B; body <= 1 MiB; page <= 1 MiB; blob <= 4 MiB.
- Site `[a-z0-9-]{1,64}`; path `[A-Za-z0-9/_.\-+]{1,256}`, no `..`, no `//`, no leading `/`.
- Components <= 4096, depth <= 32, text node <= 256 KiB.

## Roadmap

M0 skeleton (this) -> M1 network (done: TCP+NXP+local resolver) ->
M2 website (done: example site + renderer) -> M3 signatures wired into fetch ->
M4 distributed resolution prototype -> M5 browser TUI/cache/history ->
M6 WebVM exec -> M7 replication/offline -> M8 public experiment.

See `docs/decisions/` for ADRs and `docs/SHIP_LOG.md` for the log.
Subagent survey synthesis (naming/protocol/content/identity/DHT/browser/page/sandbox/offline/storage/security/Rust/Nix/OSS) informed these choices; detailed per-topic proposals are summarized in ADR context sections.
