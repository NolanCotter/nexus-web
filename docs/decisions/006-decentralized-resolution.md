# 006 — Decentralized Resolution (name → identity → records → nodes)

- Status: proposed
- Owner: resolution lane
- Scope: `crates/resolver`, and the on-wire contract consumed by `crates/identity` and `crates/protocol`

## 1. Problem

A user types `alice.nex`. The system must answer: *who owns that name,
what does their identity vouch for, and how do I reach the machines behind
it?* That is a chain of three lookups with different trust semantics:

```
name  ──(registration)──▶  identity        "alice.nex" → public key (anchor of trust)
identity ──(publication)─▶  records         public key → signed records (what it vouches for)
records ──(rendezvous)──▶  nodes           records → transport addresses (how to connect)
```

Each hop has its own failure mode. Name→identity needs a registry with
anti-squatting policy. Identity→records needs authenticity (signatures),
freshness (sequence numbers), and expiry. Records→nodes needs a transport
model that survives NAT, churn, and censorship (tcp/quic, tor, i2p, relay).

The trap: it is very easy to spend months building a global DHT before the
first two hops even have a correct data model. This document is the
recommendation to **not do that**.

## 2. Candidate approaches

| Approach | What it gives you | Cost | Verdict |
|---|---|---|---|
| Kademlia DHT | global name→record lookup, replication, churn tolerance | routing tables, bootstrap, sybil/eclipse defense, mutable-record rules | **v3, after the data model is proven** |
| Gossip / epidemic | offline-first replication, eventual consistency | unbounded state, weak point-lookup, sync latency | **v2, ambient sync among trusted peers** |
| Signed records | authenticity of every hop, cache-safe, forgery-proof mirrors | needs key lifecycle (rotation, revocation) | **v0, the base layer — not optional** |
| Peer discovery | solves the bootstrap chicken-and-egg | bootstrap nodes are trust points | **v0 component, not a resolver** |
| Federated resolvers | fast, cacheable, familiar DNS-ish semantics | operator can censor (cannot forge) | **v1, the only networked backend** |
| Hybrid | incremental capability, no rewrite | multiple moving parts, defined precedence | **this is the plan** |

The cryptographic core is *signed records*, and it is not really an option:
every other approach becomes safe the moment values are
signed-by-identity and cheap to verify. The decision below layers the rest
on top of it.

### Why not the DHT first

1. **The hard part is mutation semantics, not routing.** How do updates,
   revocations, and key rotation interact? Which record wins? What does a
   cache do with a stale-but-valid record? None of that is answered by
   XOR-distance routing, and all of it must be nailed down *before* the
   DHT value format is frozen (DHT values are amortized/replicated and
   painful to migrate).
2. **DHTs are a multi-month tax.** Kademlia done properly (bucket refresh,
   iterative lookups, replication, bootstrap discipline, eclipse defense)
   is the largest subsystem in this project. Spending it before the
   local resolver exists means the DHT encodes guesses.
3. **Bootstrap is unsolved anyway.** A DHT still needs seed peers, which
   means you need the federated/peer-discovery layer regardless.
4. **Testability.** Routing tables and network timeouts are terrible to
   unit test. Signed-record semantics are pure logic and test perfectly.
   Land the pure logic first, and the DHT becomes *one more backend* with a
   conformance test instead of the whole world.

## 3. Resolution in one paragraph

Every identity owns a monotonically-versioned set of signed records under a
zone key. A resolver is a *read-mostly cache*: it validates everything it
receives (signature, sequence, expiry, revocation ledger), stores what is
valid, and answers from the best record it has seen — offline if necessary.
Backends (local store, federated resolver, later gossip, later DHT) are
pluggable *transport* for the same signed records; they never change the
trust model, because records authenticate themselves.

## 4. Data model (v0 — gets this exactly right)

```
ZoneId      = blake3(name_bytes)                        // namespaced, opaque, registered
IdentityId  = blake3(public_key_bytes)                  // the anchor of trust
SignedRecord = { zone, seq, kind, payload, expires_at, signature }
  signature covers: zone ‖ seq ‖ kind ‖ payload ‖ expires_at
  seq is strictly monotonic per (zone, kind); newer wins
RecordKind: Node | Service | Content | Alias | Delegation | Revocation
NodeAddr = { transport: Tcp|Quic|Tor|I2p|Relay, multiaddr: bytes, roles: [Resolver|Relay|Storage|Gateway] }
Revocation  = { seq, invalidates_up_to }                // tombstone, kept forever (short)
Delegation  = { seq, delegate_key, scope }              // key rotation / sub-key publish
```

Rules that are testable before any network exists:

- Signature must verify for the record to enter the store (v1: mock provider).
- For each `(zone, kind)` only the highest `seq` is *live*; lower seqs are
  kept for audit but never served.
- Expired records are not served; negative cache entries expire too, so a
  name can come back into existence.
- A revocation invalidates all records of that zone with `seq ≤ N`,
  including the revocation's own predecessor set — revocations cannot be
  un-revoked except by a *higher* revocation, not by a resurrected record.
- Delegations expand the set of keys accepted for a zone; revocation of the
  delegator kills the delegation.

## 5. Local-first resolver trait + DHT extension point (Rust)

`crates/resolver` ships:

```rust
pub trait Resolver {                                          // the app-facing API
    fn resolve(&self, name: &str) -> Result<Resolution, ResolveError>;
    fn publish(&mut self, record: SignedRecord) -> Result<(), PublishError>;
    fn validate(&self, record: &SignedRecord) -> Result<ValidatedRecord, ValidationError>;
}

#[async_trait]
pub trait Backend: Send + Sync {                              // the extension point
    async fn lookup(&self, q: &Query) -> Vec<SignedRecord>;   // best-effort pull
    async fn advertise(&self, r: &ValidatedRecord) -> Result<(), BackendError>;
    async fn subscribe(&self, q: &Query) -> mpsc::Receiver<SignedRecord>; // default: no-op
}
```

`LocalStore` is a `Backend` (disk-backed). `FederatedBackend` is the only
networked backend in v1. `GossipBackend` is v2. `DhtBackend` is v3 and is
declared now as a typed stub with its wire contract frozen in this doc:

### DHT wire contract (frozen at v0 so the v3 graft is mechanical)

- **Key**: `blake3(zone_id ‖ 0x00 ‖ record_kind_discriminant)` — one key
  per (zone, kind), so a resolver fetches exactly the record family it needs.
- **Value**: a signed-record envelope (cap 16 records per key, newest seq
  wins on merge — the resolver's merge rule is the DHT's merge rule).
- **Acceptance**: signature verified before storing; higher `seq` replaces.
  Replicas never "repair" a record with a lower seq.
- **Replication**: nodes within `k` of the key hold replicas; refresh on
  record expiry; re-publish on seq change.
- **Bootstrap**: seed list from `FederatedBackend` node records + cached
  peers + optional static file. Never a hard dependency.
- **Milestone gate**: DHT ships only after (a) the v0 model tests pass,
  (b) the federated backend is dogfooded in the field, (c) a second
  independent implementation interoperates on this exact envelope format.

The `LayeredResolver` wires `[LocalStore, FederatedBackend, …]` with a
policy: query all backends, validate everything, merge by (seq, expiry,
revocation), return the best resolution bounded by a freshness window —
never wait longer than `resolve_timeout` on a cache hit.

## 6. Advantages of this plan

- The correctness-critical code is pure, offline, and unit-testable today.
- Backends are swappable behind one trait; the DHT later is ~1 new file +
  conformance tests, not a rewrite of resolution.
- Offline-first: a node with a warm cache resolves names with zero network.
- Forged/stale data from any backend is discarded at the validation
  boundary — poisoning a federated resolver or a DHT replica costs nothing.
- Semantics are the same at every layer (same merge rule), so behavior is
  predictable as backends are added.

## 7. Disadvantages

- v1 depends on federated resolvers for *cold* global lookups — a
  centralized availability point (authenticity is never centralized, but
  availability is). Acceptable for the first mile; gossip/DHT remove it.
- Three more backends = more moving parts; precedence and timeout policy
  must be documented and tested, or behavior becomes "whatever finished
  first."
- Gossip can grow unbounded state unless GC policy (expiry-based pruning)
  is enforced; this is a v2 problem with a known answer, not a research gap.

## 8. Risks

- **Data-model drift**: if name semantics (case sensitivity, Unicode, zone
  scope, squatting rules) are not fixed at v0, the zone-key derivation and
  DHT key contract must change later. Mitigation: names are normalized
  (NFKC, lowercase, punycode) at the *registration* layer before they ever
  touch `blake3`; resolver treats names as opaque bytes.
- **Key lifecycle churn**: rotation/revocation must exist in the model now
  or every published record becomes immortal lock-in. Mitigation: `Delegation`
  + `Revocation` record kinds are part of v0 (minimal semantics, tested).
- **DHT scope creep returning**: the trait boundary + frozen wire contract +
  three milestone gates above are the tripwire. If the DHT is still not
  warranted at v3, shipping without it is a valid outcome.
- **Backend poisoning**: mitigated by validation-at-the-boundary (see §6) —
  this is exactly why signed records are the base layer.
- **Consistency confusion**: "which answer is right" when backends disagree
  must be one deterministic rule (max seq, then expiry, then revocation),
  not a race. The resolver owns the merge; backends never do.

## 9. Recommended prototype (one working week, sequential)

1. **Day 1–2 — model + store (pure logic).** `SignedRecord`, validation,
   `LocalStore` (append-only JSONL/hex log + per-zone kind index). Unit
   tests: bad sig rejected; higher seq wins; expiry not served; revocation
   tombstones; delegation expands accepted keys; negative cache. No network,
   no crypto dependency (mock verifier behind `CryptoProvider`).
2. **Day 3 — resolution + CLI.** `resolve("alice.nex")` and
   `publish record.json` in a thin `nexus-resolve` binary. Fully offline.
3. **Day 4 — federated backend.** Minimal `query(name) → envelopes` over
   HTTP/QUIC (see `crates/protocol`), storing only validated records, with
   a mock-server conformance test for the `Backend` trait.
4. **Day 5 — reboot test.** Cold start offline: resolve from warm cache
   with correct TTL/negative-cache behavior; record expiry observed.
   Write the `Backend` conformance test suite (so DHT/gossip land behind a
   green gate).
5. **v2** gossip backend (ambient sync). **v3** DHT, gated on interop.

Concrete acceptance for v0: the resolver answers correctly from a local
fixture for (valid update, replay, expired, revoked, delegated) — a
sequence of ~40 property-test scenarios, no network involved.

## 10. Files

- `docs/decisions/006-decentralized-resolution.md` — this document
- `crates/resolver/Cargo.toml` — std-only, `crypto-ed25519` feature seam
- `crates/resolver/src/lib.rs` — crate docs, re-exports
- `crates/resolver/src/model.rs` — types, envelope, wire helpers
- `crates/resolver/src/crypto.rs` — `CryptoProvider` trait + mock + real seam
- `crates/resolver/src/store.rs` — `LocalStore`, merge/conflict rules
- `crates/resolver/src/backend.rs` — `Backend`/`Resolver` traits, layered
  resolver, `DhtBackend`/`GossipBackend`/`FederatedBackend` stubs
- `crates/resolver/src/resolve.rs` — the resolution pipeline
- `crates/resolver/tests/resolve_smoke.rs` — offline behavior tests