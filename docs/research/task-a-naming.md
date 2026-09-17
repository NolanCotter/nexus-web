# Task A: Naming systems — proposal (archived subagent report)

> Source: Naming/Resolution Engineer (background research crew).
> Status: proposal, not yet adopted. Current v0 decision: petname-first
> local resolver; see `docs/decisions/001-site-identity.md` and
> `docs/decisions/004-resolution.md`.

## Thesis

Naming isn't one problem — it's four problems: memory, uniqueness,
authenticity, and liveness. Every system solves two and dodges the other
two. The buildable answer is layering, not picking.

## Options compared

### 1. DNS-like human names

Keep hierarchical labels (`alice.shop`) but replace transport/governance:
records in a DHT, signed zones, no ICANN-style root.

- Advantages: memorable, brandable; cheap delegation; TTL caching solved.
- Disadvantages: global uniqueness requires global authority; squatting and
  disputes inherent; name says nothing about authenticity; poor offline.
- Risks: registry capture/fork, typosquatting, alt-root fragmentation.

### 2. Content-addressed naming

The name *is* the content: `cid:b3:<blake3-hex>`. Self-verifying,
dedup-friendly, cacheable, replicable.

- Advantages: integrity free; immutable; zero coordination; offline-safe.
- Disadvantages: not memorable; not mutable (edit = new name); no
  discovery; retention problem (resolves only while someone hosts blocks).
- Risks: liveness collapse, algorithm migration, GC incentives. The usual
  fix (mutable pointer signed by a key) is option 3 in disguise.

### 3. Public-key identity naming (recommended core)

A name binds to an Ed25519 public key: `www@<key>`. The key *is* the zone
authority; the owner signs records mapping labels to content addresses,
delegations, or text. Anyone can fetch a zone from anywhere and verify
locally. Human memory is bolted on as **petnames**: a user-local table
(`~alice` -> key), synced socially like contacts. This is the GNUnet GNS
model — the most battle-tested alternative naming system.

- Advantages: self-authenticating; offline-verifiable from cached zones;
  no squatting at core layer; delegation is a signed record; rotation is a
  signed `rotate` record (chain of custody).
- Disadvantages: key-management UX tax; discovery still needs DHT/peer
  sync; vanity-key mining possible.
- Risks: key loss without rotation = identity death (needs recovery:
  multi-sig or social rekey); revocation propagation; stale-record replay
  (mitigate with per-zone `version` counters).

### 4. Distributed naming (DHT / ledger)

(a) DHT: Kademlia `name -> record`, replicated across peers.
(b) Ledger: global uniqueness via consensus (Namecoin/ENS style).

- Advantages: no single point of failure; censorship-resistant; ledger
  gives auditable uniqueness.
- Disadvantages: bare DHT has no uniqueness/authority (poisonable without
  signed records); ledgers are slow, costly, state-bloated, not local-first.
- Risks: eclipse/routing attacks; governance capture; churn/latency.

## Recommended: hybrid layered naming

| Layer | Form | Solves | Trust anchor |
|---|---|---|---|
| L0 immutable content | `cid:b3:<hex>` | integrity, dedup, caching, offline | hash |
| L1 self-auth zones | `www@<pubkey>` | mutable naming, authenticity | key + signature |
| L2 petnames | `~alice` | human memory, zero coordination | local table |
| L3 registry (optional, late) | `alice.shop` | brandable uniqueness | consensus, minimal |

Resolution is a typed pipeline: petname (local) -> registry binding (if
used) -> zone records (signature-verified) -> CID (hash-verified). Every
hop appends to a verifiable chain. Each layer works even if layers above
fail; the registry is optional.

## Recommended prototype slice

Three crates, no networking in v1:

- `nexus-name`: pure types, canonical bytes, parse/format, no I/O.
- `nexus-resolve`: resolver, cache, `ZoneSource` trait + memory impl.
- `nexus-cli`: `zone gen` / `zone publish` / `resolve <name>`.

Deps: `ed25519-dalek`, `blake3`, `thiserror`, `clap`. Milestones: M0 types
+ canonical bytes; M1 sign/verify + tamper tests; M2 in-memory resolver
(petnames, alias-following with cycle guard, TTL/expiry); M3 CLI.
DHT/gossip/registry deferred behind the `ZoneSource` seam.

## Implications for current v0

- `LocalResolver` + `Route { endpoints, pinned_site_id }` already covers
  L2 (petname) with an optional L1 pin field. Good seam: grow pins into
  full zone verification (M3) rather than replacing the trait.
- Adopt the report's canonical-bytes rule now: exactly one serialization
  is ever signed or compared (identity crate already does this with
  `0x00`-joined fields; keep that invariant as the model grows).
- Add per-record `version` counters when signed records enter the fetch
  path, to defeat stale-replay from future DHT/gossip sources.
