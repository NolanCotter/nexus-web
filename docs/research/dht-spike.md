# DHT Spike — minimal Kademlia, churn/sybil, verification-boundary wiring

- Status: **experiment only** (branch `experiment/dht-kademlia`; never merged to main).
- Date: 2026-09-18. Lane: resolution (DHT spike, time-boxed).
- Answer: **NO-GO** for the v3 DHT backend under the ADR 006 gates — with
  measurements below. The value layer is safe; the routing layer is not
  attack-ready, and the gate is not met.

## What was built

New crate `crates/dht-spike` (399 source lines; std-only routing core plus
already-locked deps `nexus-resolver`, `ed25519-dalek`, `hex`, `blake3`).
No existing crate's `src` was touched. Workspace member was added.

- `src/kademlia.rs` — 64-bit XOR distance, per-bit k-buckets (K=20, LRU
  eviction), iterative lookup (α=3, K-termination). Silent (offline) nodes
  never become fetch targets.
- `src/sim.rs` — deterministic xorshift RNG; network build with a 3-seed
  join protocol + one refresh round; publish replicates the record to the
  `replicate` closest ids; churn (offline fraction) and sybil (random-id or
  ID-targeted attackers) knobs. **Every fetched record is admitted through
  the real `nexus_resolver::resolve::RecordStore::admit`** — the same
  boundary production resolution uses (verify → site match → expiry → seq
  high-water, ADR 006 §4 + ADR 009). Trust anchor: `"alice"` → honest key
  only, out-of-band; attacker-signed records for the same name must die at
  admit.
- `src/main.rs` — measurement driver (below).
- 6 unit tests, including the boundary proof:
  `forged_records_die_at_verification_boundary` and
  `sybil_forgery_never_admits_even_under_eclipse`.

## Method / sim assumptions (explicit)

- Single frozen key: `blake3("alice\0endpoint")` → 64-bit id (ADR 006 key
  contract). Value = signed `EndpointRecord` ("alice", seq 1, honest
  `10.0.0.1:7443` vs forged `6.6.6.6:6666`).
- `K=20`, `α=3`, `MAX_ROUNDS=32`; LRU bucket eviction (no ping discipline,
  no bucket splitting/refresh, no replacement cache — all deferred).
- Per cell: 10 network realizations × 40 lookups = 400. A realization is a
  static network → within it all lookups are i.i.d. but outcome is
  all-or-nothing, so `success%` is a 10%-granularity estimate of
  "P(≥1 honest replica reachable)". Disclosed; not smoothed.
- Churn = random offline fraction (origin node excluded). Malicious nodes
  answer every record fetch with the forged record.
- Targeted sybil = attacker ids within XOR distance 2^30 of the key
  (honest uniform ids are ~2^54+ away at N=1000, so attackers dominate the
  key's neighborhood).
- Lookups do not mutate routing state (no STORE refresh traffic counted).
  These are background-free, single-key cold resolves — a lower bound on
  message cost vs a production DHT.

## Measurements

Command (all numbers below are this binary's stdout, verbatim):

```
cargo run -p dht-spike --release
```

E1 — messages & rounds vs network size (K=20, alpha=3, 400 lookups/cell, 0 malicious)

| nodes | find_node msgs | fetch msgs | total msgs | rounds | contacted |
| --- | --- | --- | --- | --- | --- |
| 100 | 45.60 | 40.00 | 85.60 | 8.60 | 20.00 |
| 1000 | 61.20 | 40.00 | 101.20 | 11.20 | 20.00 |

10× nodes → **1.18× messages, 1.30× rounds** (near-log scaling; the fetch
leg is constant at 2·K=40). 85–101 messages per cold resolve of one signed
key — cheap in absolute terms.

E2/E3 — sybil: success vs malicious fraction (N=100, 400 lookups/cell)

| mode | malicious_frac | verified | success% | forged_admitted_total | avg_msgs |
| --- | --- | --- | --- | --- | --- |
| random | 0.00 | 400 | 100.0 | 0 | 87.40 |
| random | 0.10 | 400 | 100.0 | 0 | 87.40 |
| random | 0.15 | 400 | 100.0 | 0 | 85.00 |
| random | 0.20 | 400 | 100.0 | 0 | 86.20 |
| random | 0.25 | 400 | 100.0 | 0 | 87.40 |
| random | 0.50 | 400 | 100.0 | 0 | 91.00 |
| targeted | 0.00 | 400 | 100.0 | 0 | 88.00 |
| targeted | 0.10 | 400 | 100.0 | 0 | 85.00 |
| targeted | 0.15 | 400 | 100.0 | 0 | 85.00 |
| targeted | 0.20 | 0 | 0.0 | 0 | 82.00 |
| targeted | 0.25 | 0 | 0.0 | 0 | 82.00 |
| targeted | 0.50 | 0 | 0.0 | 0 | 83.20 |

- **Random-id sybils**: 100% success through 50% malicious. Mean-field
  explanation: the top-K neighborhood still contains ~K(1−f) honest
  replicas. Availability holds; authenticity trivially holds.
- **ID-targeted sybils**: hard cliff at f=0.20 (attackers ≥ K=20 → the key's
  entire replica set is attacker-controlled). Below the cliff 100%, at/above
  **0.0%** — honest replicas eclipsed, no verified route exists.
- **forged_admitted_total = 0 across every cell** (12 cells × 400 lookups =
  4,800 fetch/admit cycles). Forged records die at `RecordStore::admit`
  exactly as ADR 006 predicts: "a poisoned backend can deliver garbage;
  verification discards it for free." The boundary held even when the
  network was 100% attacker-owned around the key.

E4 — churn: success vs offline fraction (N=100, 400 lookups/cell, 0 malicious)

| offline_frac | replication R | verified | success% | avg_msgs |
| --- | --- | --- | --- | --- |
| 0.5 | 20 | 400 | 100.0 | 67.70 |
| 0.8 | 20 | 320 | 80.0 | 41.40 |
| 0.8 | 4 | 160 | 40.0 | 38.00 |
| 0.9 | 4 | 120 | 30.0 | 26.80 |

- Replication depth is the churn shield: R=20 keeps 100% at 50% offline and
  drops to 80% at 80% offline; R=4 collapses (40% / 30%). Matches the
  closed form 1 − c^R once reachability is included.
- Messages *fall* under churn (fewer repliers → fewer fetches; early
  termination) — **failures are cheap**, but they are failures: a cold
  resolve returns no route.

## Validation notes

- The sim was cross-checked against closed forms: churn survival ≈ 1 − c^R
  (matched within realization noise), eclipse threshold = attackers ≥ K
  (observed cliff exactly at f=0.20). One real bug was caught this way:
  offline nodes were initially fetch targets, inflating churn success —
  fixed by restricting `Lookup::contacted` to actual repliers; rerun
  preserved all other cells bit-for-bit.
- Deterministic seeds: `cargo run -p dht-spike --release` is reproducible
  (stdout hash `da45a63cbfa1a0b8fef42de1174de3982b2d9f4b`).

## Gate check against ADR 006 §4 ("DHT ships only when…")

| Gate | Status |
| --- | --- |
| (a) v0 model tests green | ✅ `cargo test -p nexus-resolver` → 20/20 passed (worktree, origin/main; also full `cargo test` green) |
| (b) federated backend dogfooded | ❌ not built/dogfooded yet (v1 path) |
| (c) second independent implementation interoperates on the frozen envelope | ❌ not demonstrated |

Only gate (a) is met.

## Recommendation: NO-GO (park the DHT; keep the boundary)

The wiring is sound and cheap: ~101 messages / ~11 rounds for a cold
single-key resolve at 1000 nodes, and **0 forged admissions in 4,800
admit cycles even under full eclipse** — the frozen envelope + `RecordStore`
boundary (verify → seq → tombstone) make the DHT safe as a *backend*.
But the routing layer as modeled **fails closed, hard, against a 20-sybil
ID-targeted eclipse** (E3: 100% → 0.0%): no verified route exists, and a
resolver with only a DHT backend stops resolving that name entirely.
That is a documented ADR 006 risk ("routing, bootstrap, sybil/eclipse
defense" was the listed cost of Kademlia) and it is not covered by the
current frozen contract.

Combined with gates (b) and (c) being unmet, the v3 DHT does not clear the
merge gate. Per ADR 006, "shipping without a DHT is a valid outcome." This
spike's numbers *support* that: the honest path is federated (v1) + gossip
(v2) behind the same `Backend` seam, with the DHT re-spiked later against
(a) bucket-locking / S-Kademlia entry rules to break ID-targeting, (b) a
constrained-ID constraint on the key format, or (c) a bounded replica
quorum.

## Files

- `crates/dht-spike/` — new crate (Cargo.toml, src/{lib,kademlia,sim,main}.rs; 399 lines incl. tests).
- `Cargo.toml` — workspace member `crates/dht-spike` added.
- `docs/research/dht-spike.md` — this report.