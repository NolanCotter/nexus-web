# 006 — Decentralized Resolution (name → identity → records → nodes)

- Status: **proposed — extension layer. Companion to ADR 004 (accepted: local-first resolver behind a trait).**
- Owner: resolution lane
- Scope: `crates/resolver` (`Resolver` trait, `Backend` seam, `CachingResolver`), riding on `crates/identity` signed records (`ResourceRecord`/`SiteIdentity`).

## 1. Problem

A user types `alice`. The system must answer: *who owns that name, what
does their identity vouch for, and how do I reach the machines behind it?*
A chain of three lookups with different trust semantics:

```
name  ──(trust anchor)──▶  identity        "alice" → site key (out-of-band, known_hosts-style)
identity ──(publication)─▶  records         site key → signed records (what it vouches for)
records ──(rendezvous)──▶  nodes           records → transport addresses (Route endpoints)
```

Each hop fails differently. Name→identity needs registration/anti-squatting
policy (a separate task lane). Identity→records needs authenticity
(Ed25519), freshness, expiry. Records→nodes needs a transport model. The
trap: building a global DHT before hops 1–2 have a correct local model.
This document is the recommendation to **not do that** — ADR 004 already
decided it; here is the distributed layer it defers.

## 2. Candidate approaches

| Approach | Gives you | Costs | Verdict |
|---|---|---|---|
| Kademlia DHT | global lookup, replication, churn tolerance | routing, bootstrap, sybil/eclipse defense, mutable-record rules | **v3, gated** |
| Gossip / epidemic | offline-first replication, eventual consistency | unbounded state, weak point-lookup, sync latency | **v2, ambient sync** |
| Signed records (Ed25519) | authenticity of every hop, forge-proof caches | key lifecycle (rotation, delegation) | **v0 base layer — done** (`crates/identity`) |
| Peer discovery | bootstrap chicken-and-egg fix | bootstrap nodes are trust points | **v0 component** (transport lane) |
| Federated resolvers | fast, cacheable, DNS-like pull | operator can withhold (cannot forge) | **v1, first networked backend** |
| Hybrid | incremental capability, no rewrite | precedence must be documented | **this is the plan** |

Signed records are not an option — they are the prerequisite. Everything
else became safe the moment records verify against the site key before
they are trusted or stored.

### Why not the DHT first

1. **The hard part is mutation semantics, not routing.** Updates,
   revocations, key rotation, cache staleness — none of it is answered by
   XOR-distance routing, and all of it must be fixed before the DHT value
   format is frozen (values are replicated and painful to migrate).
2. **A DHT is a multi-month tax.** Kademlia done properly (bucket refresh,
   iterative lookup, replication, bootstrap discipline, eclipse defense)
   is the largest subsystem in this project. Building it before the local
   model exists means the DHT encodes guesses.
3. **Bootstrap is unsolved anyway.** A DHT still needs seed peers — the
   federated/peer-discovery layer is needed regardless.
4. **Testability.** Routing tables are hard to unit test; signed-record
   semantics are pure logic. Land the pure logic, and the DHT becomes *one
   more backend* behind a conformance test — not the whole world.

## 3. What v0 actually is (shipped, per SHIP_LOG #5/#6)

- `crates/identity`: Ed25519 `SiteIdentity`, signed `ResourceRecord`
  (site → path → content hash, with expiry), strict `verify_strict`
  verification, `Delegation` + `RotationLog` types.
- `crates/resolver`: `Resolver` trait (`resolve(name) -> Route`,
  `list_names`), `LocalResolver` petname table, name validation.
- `Route { endpoints: Vec<String>, pinned_site_id: Option<String> }`.

Missing today, by design: **sequence numbers** were deferred from v0 and
landed in M3 (`docs/decisions/007-signed-fetch-path.md`): a monotonic
per-name `seq` on `EndpointRecord` with "newest verified wins", signed
revocation tombstones, key rotation/delegation wired into `RecordStore`
admission, and fail-closed browser pinning against the signed chain.

## 4. Extension layer (this task, `crates/resolver`)

The chain is completed without touching `crates/identity`:

- `EndpointRecord` (`resolve.rs`): signed *node/address* record —
  `site ‖ transport ‖ host ‖ port ‖ expires`, canonical bytes + strict
  Ed25519, mirroring `ResourceRecord`'s shape. This is the **records →
  nodes** hop: site key to routable endpoint.
- `RecordStore` (`resolve.rs`): verified local-first cache. Admission =
  full verification against the name's trust anchor (out-of-band, like a
  DNSSEC root). A poisoned backend can deliver garbage; verification
  discards it for free. Injected clock for deterministic expiry tests.
- `CachingResolver<B>` (`resolve.rs`): implements the `Resolver` trait.
  Fast path = warm petname table; cold path = pull signed records from
  backends, verify, admit, warm the table. Works with zero backends.
- `Backend` trait (`backend.rs`): the seam. `fetch(name) -> Vec<SignedRecord>`,
  `advertise(record)`. Backends never validate, merge, or decide policy.
- Stubs: `FederatedBackend` (v1), `GossipBackend` (v2), `DhtBackend` (v3),
  `MemoryBackend` (in-memory conformance double — a real backend passing
  the same scenarios as `MemoryBackend` is a correct backend).

### The frozen DHT wire contract (v3, decided now so the graft is mechanical)

- **Key**: `blake3(name ‖ 0x00 ‖ record_kind)` — one key per
  (name, kind), so a lookup fetches exactly one record family.
- **Value**: signed-record envelope list, cap 16 per key; merge = the core's
  rule (newest verified wins). Replicas never "repair" toward a lower version.
- **Accept**: record verified against the site key *before* storing;
  replication within the key's k-bucket; refresh on expiry; re-publish on
  version change.
- **Bootstrap**: federated node records + cached peers + optional static
  file. Never a hard dependency of resolution.
- **Gate**: DHT ships only when (a) v0 model tests green, (b) federated
  backend dogfooded, (c) a second independent implementation interoperates
  on this envelope format. If it never clears the gate, shipping without a
  DHT is a valid outcome.

## 5. Advantages

- Correctness-critical code is pure, offline, and unit-tested (14 tests,
  real Ed25519, zero network).
- Backends are swappable behind one trait; the DHT later is ~1 new file +
  conformance tests, not a rewrite of resolution.
- Offline-first: warm cache + trust anchors resolve with no network.
- Forged data from any backend dies at the validation boundary for free.
- One merge rule everywhere (newest verified wins), so behavior is
  predictable as backends are added.

## 6. Disadvantages

- v1 depends on federated resolvers for *cold* global lookups —
  centralized availability (never centralized authenticity).
- Three backends = more moving parts; precedence and timeouts must be
  documented (v0 backend seam is synchronous; async lands with real I/O).
- Gossip needs expiry-based GC or state grows unbounded (v2 problem, known
  answer).

## 7. Risks

- **Missing seq**: single-source assumption breaks the moment two backends
  disagree. Mitigation: seq is the FIRST multi-source upgrade, gated
  before gossip/DHT.
- **v0 endpoint convention is provisional**: records are carried under
  path `@{name}` with the `EndpointRecord` JSON in `content_hash`
  (`resolve.rs`). This is protocol-lane negotiable; the seam isolates it.
- **Key lifecycle**: rotation/delegation types exist in `crates/identity`;
  wiring them into `RecordStore` admission is a follow-up before v1.
- **DHT scope creep**: the frozen contract + three gates are the tripwire;
  shipping without the DHT is a valid outcome.
- **Trust anchor bootstrapping** (name → key, out-of-band) is the real
  decentralization bottleneck; it is exactly as hard as DNS trust anchors.

## 8. Recommended prototype (next steps, mapped onto SHIP_LOG's M3/M4)

1. ~~Model + store~~ — **done** (SHIP_LOG #5/#6; extension layer added by
   this task, 14 tests green).
2. **Next (M3): seq numbers + revocation.** Add `seq` to the record
   envelope, per-site "newest verified wins", revocation as an explicit
   tombstone record. Frees the model for multi-source.
3. **Then: `FederatedBackend` for real** — `GET /resolve/{name}` → JSON
   envelopes over the transport layer; `MemoryBackend` scenarios as the
   conformance test. Dogfood in the field.
4. **v2: `GossipBackend`** — state-summary exchange (bloom + high water),
   expiry-based GC.
5. **v3: `DhtBackend`**, only after the three gates. Wire contract frozen
   above; mechanically grafted behind `Backend`.

## 9. Files

- `crates/resolver/src/lib.rs` — `Resolver` trait, `LocalResolver`, errors (extended)
- `crates/resolver/src/backend.rs` — `Backend` trait, federated/gossip/DHT stubs, `MemoryBackend`
- `crates/resolver/src/resolve.rs` — `EndpointRecord`, `RecordStore`, `CachingResolver`, 14 tests
- `crates/identity/src/lib.rs` — unchanged base layer (`SiteIdentity`, `ResourceRecord`)
- `docs/decisions/004-resolution.md` — accepted local-first decision
- `docs/resolution.md` — v0 resolution model notes