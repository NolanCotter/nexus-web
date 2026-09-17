# Nexus — Task D: Cryptographic Site Identity

**Status:** Proposal (Draft v1)
**Engineer:** Cryptography / Identity
**Model:** `site identity -> public key -> signed resource records -> content`
**Constraint:** established primitives only (ed25519-dalek etc.), no novel crypto.

---

## 1. Summary

A site's identity **is** its public key. From that key we derive a self-certifying
identifier, and against that key we verify a set of **signed resource records**
(content pointers, delegates, rotations, revocations). Content itself is
hash-addressed; authenticity comes from the key, freshness from sequence
numbers and expiration, availability from the content layer. No CA, no PKI
hierarchy, no global registry to trust. Everything needed to verify is either
derivable from the public key or present in the signed record bundle itself.

The v1 primitive is **Ed25519** (RFC 8032) via `ed25519-dalek` 2.x, with an algorithm tag in the identity encoding so the scheme can roll over later (e.g. to a post-quantum hybrid) without breaking the record format.

---

## 2. Threat model

The identity layer defends against these actors:

| Threat | What it means | Defended by |
|---|---|---|
| Impersonation | Attacker claims someone else's identity | ID is derived from the key; a fake key gives a different ID. Nothing to forge. |
| Record forgery | Records signed by someone else's key | Ed25519 unforgeability |
| Replay | Replaying old (validly signed) records | Monotonic `seq` per signer + expiration windows |
| Stale deletion | Withholding the newest bundle, showing old state | Short TTLs force re-signing; clients fetch from k vantage points, prefer highest valid seq |
| Key compromise | Root key stolen | Recovery key path, short TTLs bound blast radius, explicit revocation |
| Clock skew | Shifting perceived time to extend/shorten validity | Time-source trait + tolerance; TTL caps; later: consensus anchor time |
| Algorithm downgrade | Tricking verifier into an old weaker algo | Version byte + algorithm tag in every key reference |
| Serialization ambiguity | One logical record verifying under two encodings | Canonical encoding specified byte-for-byte; verifier rejects non-canonical input |

Out of scope: Sybil (identity is cheap by design), content availability/DoS,
reputation, naming (human-readable names are a separate layer above the
crypto identity), transport.

---

## 3. Design principles

1. **Self-certifying.** The identity string is derived from the public key by a pure function. Verifying identity requires no external trust.
2. **Everything that matters is signed.** Every record carries its signer's key id, a sequence number, and optional validity window. No unsigned metadata.
3. **Bounded lifetimes.** Nothing is valid forever. Records expire; the system degrades to "site unreachable" rather than "site trusted".
4. **One key, one job.** Root key signs structure (rotation, delegation,
   revocation, recovery). Delegates sign content. Recovery key only ever
   overrides a compromised root. Offline-first.
5. **Deterministic bytes.** Signing covers a canonical byte encoding. Two
   implementations must produce identical bytes for identical records.
6. **Failure loud, default deny.** Unknown record type, bad seq, expired window, scope mismatch, non-canonical encoding → refuse the whole update.

---

## 4. Building blocks (vetted crates)

| Purpose | Crate | Notes |
|---|---|---|
| Signatures | `ed25519-dalek` 2.x | Pure RFC 8032 Ed25519, strict verification, audited, no_std-capable |
| Keygen RNG | `rand_core` `OsRng` | CSPRNG from OS |
| Hashing | `sha2` | SHA-256 for content hashes + key fingerprints |
| ID encoding | `bech32` (BIP-173/350) | bech32m, strong typo detection |
| Canonical encoding | hand-rolled (~150 lines, spec below) | Not a crate: must be byte-pinned by golden vectors |
| Key hygiene | `zeroize` | Zero signing-key buffers on drop |
| Serde | `serde` (optionally `postcard`) | Convenience only; never the signing encoding |

Explicitly avoided: any hand-rolled signature scheme, `ring`/OpenSSL bindings
(dependency weight, no benefit here), secp256k1 (wrong properties: ECDSA is
non-deterministic, needs RFC 6979), RSA (large keys, no benefit), anything
"quantum-resistant" not standardized yet.

Ed25519 gives us deterministic signatures (RFC 8032) — same key + same message ⇒ same signature. That kills nonce-reuse bugs by construction and makes golden test vectors exact.

---

## 5. Identity model

### 5.1 Key id

```rust
/// Algorithm tag byte, versioned:
///   0x00 = Ed25519 (RFC 8032) — the only one defined in v1
pub const ALG_ED25519: u8 = 0x00;

/// A reference to any site key: 1 tag byte + 32 raw key bytes.
/// For Ed25519 this is the 32-byte compressed point (VerifyingKey::to_bytes()).
pub type KeyId = [u8; 33];
```

### 5.2 Human-readable identity (the "site id")

```
id := bech32m(hrp = "nex", version = ALG, payload = raw 32 bytes)
```

- Example shape: `nex1qg5...` (~57 chars, checksummed).
- The **same bytes** that appear in records and in the bech32 string. No hash indirection: parse the id, you have the key. Verify, don't look up.
- Optional display fingerprint `fp` = bech32m of SHA-256(id) truncated to 8 bytes for humans comparing strings in chat; never used in verification.

```rust
pub fn parse_id(s: &str) -> Result<KeyId, IdError>;   // bech32m decode, hrp+version check
pub fn format_id(k: &KeyId) -> String;                // canonical rendering
```

---

## 6. Rust data model

```rust
// core.rs — types (serde only for CLI ergonomics; signing uses canonical.rs)

pub type ContentHash = [u8; 32];     // SHA-256 of content bytes
pub type Ts = i64;                   // unix seconds; >0 = valid
pub type Seq = u64;                  // per-signer monotonic counter

/// Path-scope for delegation. Prefix match on "/"-delimited paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope { pub prefix: String }   // e.g. "/", "/content/", "/blog/"

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordBody {
    /// Point a content path at hash-addressed content.
    Content(ContentRecord),
    /// Root authorizes a delegate key within a path scope for a window.
    Delegate(DelegateRecord),
    /// Planned key handoff: current root -> new root.
    Rotate(RotateRecord),
    /// Permanent kill switch: whole identity, or a single delegate key.
    Revoke(RevokeRecord),
    /// Declare (or, with recovery key signature, exercise) the recovery key.
    Recovery(RecoveryRecord),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentRecord {
    pub path: String,                 // "/" or "/blog/2026-09-16"
    pub content_hash: ContentHash,
    pub addresses: Vec<Addr>,         // where to fetch; opaque in v1
    pub not_before: Option<Ts>,
    pub not_after: Option<Ts>,        // REQUIRED by policy (see §8.2)
    pub seq: Seq,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegateRecord {
    pub delegate: KeyId,
    pub scope: Scope,
    pub not_before: Option<Ts>,
    pub not_after: Option<Ts>,
    pub seq: Seq,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotateRecord {
    pub new_root: KeyId,
    pub not_before: Option<Ts>,       // both keys valid from here
    pub not_after: Option<Ts>,        // old root fully retired here
    pub seq: Seq,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokeRecord {
    /// None = revoke the entire identity. Some(key) = revoke that delegate.
    pub target: Option<KeyId>,
    pub reason: String,               // informational
    pub seq: Seq,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryRecord {
    /// Declared while root is healthy: recovery_key must equal root.
    /// Exercised later: recovery_key signs a RotateRecord with recovery=true.
    pub recovery_key: KeyId,
    pub seq: Seq,
}

/// Every record is wrapped in exactly this shell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRecord {
    pub version: u8,                  // format version; MUST be 1 in v1
    pub signer: KeyId,                // root, delegate, or recovery key
    pub body: RecordBody,
    pub signature: [u8; 64],
}

/// An atomic published unit: everything a verifier needs for one identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    pub records: Vec<SignedRecord>,   // any order; verifier sorts by (signer, seq)
}
```

Constraints enforced at construction time (`SignedRecord::new`):

- `body.seq` is supplied by the **signer's** counter, not the root's. Each
  key owns its own counter. Delegates start fresh at any seq > 0.
- A `RecoveryRecord` may only be signed by the root (declaration) or the
  recovery key itself (exercise); never by a delegate.
- Revoke/Delegate/Rotate bodies may only be signed by the current root (or,
  for recovery handoff, the recovery key); never by delegates.
- Content bodies may be signed by the root or by an active delegate.

---

## 7. Canonical signing encoding (wire spec, v1)

Signing and hashing always operate on this byte encoding. Stable, versioned at the top by `version = 1`, and MUST be rejected if any reserved byte or non-minimal integer encoding appears (canonicality enforcement). Big-endian everywhere. Length prefixes are `u32 BE`.

```
signed_record :=
    version: u8            (1)
  | signer: key_id
  | body: record_body
  | signature: 64 bytes

key_id := alg: u8 | raw: 32 bytes
         (alg MUST be 0x00 in v1; otherwise refuse)

record_body := tag: u8 | payload

  tag 0x01 content:
    path:       len: u32 | utf8 bytes
    content_hash: 32 bytes
    addresses:  count: u32
                each: len: u32 | opaque bytes
    not_before: present: u8 (0|1) | i64        (canonical: absent = 0x00)
    not_after:  present: u8 (0|1) | i64
    seq:        u64

  tag 0x02 delegate:
    delegate:   key_id
    scope:      len: u32 | utf8 bytes
    not_before: present: u8 | i64
    not_after:  present: u8 | i64
    seq:        u64

  tag 0x03 rotate:
    new_root:   key_id
    not_before: present: u8 | i64
    not_after:  present: u8 | i64
    seq:        u64

  tag 0x04 revoke:
    target: present: u8            (0 = whole identity, 1 = delegate id follows)
          | key_id
    reason: len: u32 | utf8 bytes
    seq:    u64

  tag 0x05 recovery:
    recovery_key: key_id
    seq:          u64

signing_bytes(signed_record) := signed_record WITHOUT the final signature field
hash_bytes(bundle) := sha256(canonical encoding of records in
                    canonical order: sort by (signer, seq))
```

Minimality rules: `len` prefixes fixed-width (`u32 BE` — nothing to truncate); `seq`/`ts` fixed-width; UTF-8 validated; strings compared byte-wise in scope matching. Golden vectors for every record type ship in tests (the vectors, not the code, are the cross-implementation contract).

---

## 8. Record semantics

### 8.1 Sequence numbers and freshness

- Each key has its own monotonic `seq`. Verifier keeps per-signer high-water
  mark. A record with `seq <= hwm` for that signer is **replayed** → refused,
  and poisons any bundle claiming it as its best state.
- On rotation/recovery the successor root starts its counter at
  `old_root_max_seq + 1` (recorded in the handoff semantics) so replay
  across key generations is detectable.

### 8.2 Expiration

- `not_after` is **mandatory** (policy) on Content and Delegate records:
  default policy = 7 days, absolute cap = 90 days (enforced by the signing
  CLI, not by the format — a verifier does not police TTL length, only
  validity).
- A record is valid only if `not_before <= now <= not_after` (clock
  tolerance applied, see §11).
- Expired records are dead. The publisher re-signs periodically; that
  heartbeat is also the liveness signal ("site is alive if it can re-sign").

### 8.3 Content records

- One record per path. `content_hash` is SHA-256 (multi-hash-tagged byte
  `0x12 0x20` when stored externally); `addresses` say where to fetch
  (multiaddr strings, opaque to this crate in v1).
- Hash-addressing means a fetcher can verify content integrity without
  trusting the server; the signed record supplies *authenticity* of the
  mapping path → hash.
- Newer seq for the same path wins; old records are shadowed, not deleted.

### 8.4 Delegation

- `DelegateRecord` (root-signed): delegate key, path-prefix scope, window.
- Delegates sign Content records only. No delegate→delegate chains in v1
  (depth exactly 1) — keeps verification and reasoning simple; can be
  extended with a `parent` field later if needed.
- Content signed by a delegate is valid iff a DelegateRecord exists such
  that: root lineage valid at verification time, delegate == signer,
  scope.prefix matches path, delegation window covers `now`, and the
  content record's seq > 0.
- Revoking a delegate = `RevokeRecord { target: Some(delegate) }` signed by
  the root. Content already published by that delegate dies at its own
  `not_after`; no new records from it verify.

### 8.5 Rotation (planned handoff)

- Current root signs `RotateRecord { new_root, overlap window }`.
- During `[not_before, not_after]` both keys are roots; after `not_after` only `new_root` is.
- Old-root content records (and their delegates' records) stay valid until their own `not_after` → rotation is seamless, no content outage.
- New content must come from the new root's chain.
- Rotation is one step: A → B. A verifier walks `RotateRecord`s by seq; a chain A→B→C is just two records. The verifier tracks one "current root lineage"; any record signed by a key no longer in the lineage (post `not_after`) is refused for **new** content but honored for **existing** content within its own window (rule in §8.5/§9 step 6).

### 8.6 Recovery (compromise / lost key)

Mechanism: at keygen the operator generates a **recovery key** (second
Ed25519 keypair, kept offline — printed, not stored on the server) and the
root signs `RecoveryRecord { recovery_key }` with the highest seq, published
with the very first bundle. From then on:

- **Exercise:** if the root is compromised or lost, the recovery key signs a
  `RotateRecord { new_root }` (recovery flag = the RecoveryRecord itself,
  now signed *by* the recovery key with `seq > root_max_seq`). Verifiers
  accept a rotate signed by the recovery key if a root-signed RecoveryRecord
  exists naming that key, and refuse any subsequent records from the old
  root (its seq is superseded by the recovery handoff's higher watermark).
- **Damage bound:** because TTLs are short, the attacker's extra lifetime is
  at most ~TTL, and the recovery handoff signal is itself signed and
  propagated the same way as any bundle.
- v1 keeps exactly one recovery key for one identity. Multi-sig / Shamir
  (`shamir` crate, threshold k-of-n over the recovery seed) is a listed
  v2 option; v1 punts on it to keep the audit surface minimal.

### 8.7 Revocation

- `RevokeRecord { target: None }` = **identity death**. Everything with that
  root in its lineage is invalid immediately.
- `RevokeRecord { target: Some(k) }` = delegate death (§8.4).
- Only a current-root (or recovery) key can revoke.
- Revocation is a *record*, not a registry entry: its power equals its
  propagation. Verifiers fetch bundles from k independent sources and take
  the highest-valid-seq state; short TTLs mean a suppressed revocation costs
  the attacker a re-sign before expiry anyway. This is a documented
  availability trade-off, not a security hole: a revoked identity is
  eventually refused by everyone who can see *any* current bundle.

### 8.8 Ordering rules (the verifier decides)

1. Sort all records by `(signer, seq)`.
2. Reject non-canonical encodings, bad signatures, future-`not_before`
   (beyond tolerance), expired `not_after`.
3. Reject duplicate `(signer, seq)`.
4. Apply Revoke/Recovery/Rotate/Delegate in seq order to build root lineage
   + delegate table + high-water marks.
5. Identity revocation → whole bundle refused.
6. Validate Content records against the lineage at their `not_before`
   (not at `now`) — this is what makes rotation seamless and replay of
   pre-rotation content impossible to inject as "new".

---

## 9. Signing flow (publisher side)

```rust
// sign.rs — pseudocode-quality Rust, matches ed25519-dalek 2.x API
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

pub struct Identity {
    pub id: KeyId,             // derived from public key
    pub root: SigningKey,      // zeroized on drop
    pub recovery: Option<SigningKey>, // offline; only importable for recovery
}

pub fn sign_record(key: &SigningKey, signer: &KeyId, body: RecordBody) -> SignedRecord {
    let version = 1u8;
    let unsigned = SignedRecord { version, signer: *signer, body, signature: [0; 64] };
    let bytes = canonical::signing_bytes(&unsigned);
    let sig = key.sign(&bytes);                       // deterministic (RFC 8032)
    SignedRecord { signature: sig.to_bytes(), ..unsigned }
}

pub fn build_bundle(records: Vec<SignedRecord>) -> Bundle {
    Bundle { records }   // verifier sorts; publisher may too
}
```

Publisher loop (CLI or daemon):

```
loop {
    bundle = collect(current_records + fresh Content records with
                     not_after = now + site_ttl, seq = ++n)
    blob   = canonical::encode(&bundle)
    ref    = sha256(blob)
    publish(ref -> blob) to content layer / DHT
    sleep(site_ttl / 2)
}
```

The `ref` is self-describing: anyone fetching it can verify the bytes hash to `ref` and every signature inside verifies against the id.

---

## 10. Verification flow (client side)

```rust
// verify.rs
pub struct Policy {
    pub clock: Box<dyn TimeSource>,   // SystemTime by default
    pub skew_tolerance: Duration,     // default: 5 min
    pub min_sources: u8,              // default: 3 independent fetches
}

pub fn verify_site(id: KeyId, bundles: &[Bundle], pol: &Policy) -> Result<VerifiedState, VerifyError> {
    // 1. Fetch bundles by ref from >= min_sources vantage points (caller's job);
    //    take the union. (Hash mismatch / fetch error = VerifyError.)
    // 2. Canonical checks: every record parses, canonical, version == 1.
    // 3. Per-record signature check against `signer` key id using
    //    VerifyingKey::verify_strict (rejects non-canonical signatures).
    //    signer must equal root, a declared delegate, or the declared
    //    recovery key — decided by rule 4.
    // 4. Sort (signer, seq); replay check; build lineage (§8.8).
    // 5. Highest-valid-seq state wins; conflicting bundles resolved by
    //    taking max (seq, signer) tuples — same state, content-addressed,
    //    so disagreement is only ever "older vs newer".
    // 6. Return VerifiedState:
    //      root: KeyId, delegates: Vec<DelegateRecord>,
    //      content: Vec<ContentRecord> // path -> hash, addr, window
    //   Content fetch + hash check happens in the content layer, using
    //   content_hash from here.
}

// Strict verification is REQUIRED:
let vk = VerifyingKey::from_bytes(&id.raw)?;
vk.verify_strict(&canonical::signing_bytes(record), &Signature::from_bytes(&sig))?;
```

Properties a client can now rely on: the content it renders is exactly what
the identity's key chain authorized at fetch time, within the policy's
validity windows. Nothing else. That is the whole contract.

---

## 11. Time handling

- Records carry `i64` unix seconds. No level-1 trust in any clock — the
  crate exposes `TimeSource`, and verification applies `now ± skew`.
  - `not_before > now + skew` → "not yet valid"
  - `not_after < now - skew` → "expired"
- v1 default: `SystemTime`. Later: Nexus consensus anchor time preferred
  over local when within skew (min-of-N of independent beacons), still
  clamped by local sanity (anti rewind).
- Because TTLs are short, a clock attack on a client only shifts acceptance
  windows by `skew`, never minting validity out of nothing: records are
  signed, so time can only gate them, not forge them.

---

## 12. Key lifecycle cheat sheet

| Event | Record | Signed by | Effect |
|---|---|---|---|
| Genesis | — | — | id = root pubkey; bundle 0 also carries RecoveryRecord |
| Publish content | Content | root or delegate | path → hash, window |
| Hire delegate | Delegate | root | delegate signs content in scope |
| Fire delegate | Revoke(target) | root | delegate's content dies at its TTL |
| Rotate keys | Rotate | current root | seamless handoff, overlap window |
| Key compromised | Rotate (+RecoveryRecord) | recovery key | old root dead, new root live |
| Delete site | Revoke(target=None) | (current) root | bundle refused by all verifiers |
| Key lost, no recovery key | — | — | identity dead (documented) — this is why recovery key is generated at genesis |

---

## 13. Advantages

- **No PKI, no CA, no registry.** Identity and verification are pure functions
  of signed bytes. Perfect fit for a decentralized content layer.
- **Self-certifying ids.** `nex1…` string ⇒ key ⇒ verify. Zero lookup.
- **Offline-root friendly.** Root key can live on a USB stick; delegates
  re-sign content on the server; rotation is a rare ceremony.
- **Compromise is survivable and bounded.** Recovery key + short TTLs cap the
  attacker's window; recovery is a signed record, not a support ticket.
- **Deterministic signatures.** Ed25519 (RFC 8032) removes the entire class
  of nonce-reuse disasters; golden test vectors are exact.
- **Small, auditable.** ~5 record types, one canonical encoder, one strict
  verification path. Fits in a weekend of review. no_std-clean core.
- **Content-addressed bundles.** Fetchers verify hashes before trusting
  servers; the DHT is never trusted for authenticity, only availability.
- **Forward-compatible.** Algorithm tag byte + version byte allow Ed25519 →
  Ed25519+ML-DSA hybrid later without format breakage.

## 14. Disadvantages

- **Identity is opaque.** `nex1…` has no human meaning; naming needs a
  separate layer (Nexus Task E territory).
- **Operator burden.** Someone must keep the root key safe, do rotations,
  re-sign before TTL expiry. If the operator vanishes, the site silently
  expires (by design — availability, not authenticity, is what dies).
- **No recourse after loss.** Lost root + lost recovery key = dead identity.
  No escrow, no authority to appeal to. That's the point, but it's a UX tax.
- **Revocation is gossip, not law.** Suppressed revocation records mean
  stale-but-signed state persists up to TTL. Clients mitigate via k-source
  fetching; the residual window is documented.
- **Freshness requires liveness.** A site that stops re-signing disappears
  within one TTL. This is a feature (stale = gone) that some operators will
  experience as a bug.
- **Clock sensitivity.** v1 leans on client clocks (mitigated: tolerance,
  short TTLs, later consensus time anchor).

## 15. Risks

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| 1 | Root key compromise undetected | Medium | High (full impersonation until TTL) | Recovery record from genesis; TTL cap 90d; operator practices (offline root) |
| 2 | Recovery key itself compromised/lost | Low | Critical (permanent takeover / lockout) | Offline generation at genesis; v2: Shamir k-of-n over recovery seed |
| 3 | Clock manipulation of a client | Medium | Low–Med | ±5min tolerance; short TTLs; v2 consensus anchor |
| 4 | Canonical encoding divergence across implementations | Medium | High (verification split-brain) | Byte-exact spec + golden vectors; reject non-canonical input (fail loud) |
| 5 | SemVer/dependency drift in ed25519-dalek | Low | Medium | Pin exact versions; vendor-verify Cargo.lock; audit path is tiny |
| 6 | Bundle withholding (censorship-ish) | Certain-ish | Medium | k-source fetch ≥3; hash-addressed blobs are cacheable and replicable by anyone |
| 7 | Delegate key compromise | Medium | Medium | Scope confinement; delegate TTLs; instant revoke via root-signed Revoke(target) |
| 8 | Replay across key generations | Low | Medium | Rotation/recovery bumps the successor's starting seq; per-key HWMs |
| 9 | Ed25519 is not post-quantum | Long-term | High (far future) | Algorithm tag + version byte; hybrid Ed25519‖ML-DSA-44 planned after pqcrypto standard settles; v1 unchanged |
| 10 | Sloppy operator (TTL missed) | High | Low (downtime only) | Default 7d TTL, daemon re-signs at TTL/2, health checks |

---

## 16. Recommended prototype

Single crate, `crates/nexus-identity`, plus a CLI `nexus-id`. No network code
in v1 — the content layer is a trait, tests use an in-memory fake.

```
nexus-identity/
  src/
    lib.rs          # re-exports
    key.rs          # keygen, bech32m id encode/decode, fingerprints
    record.rs       # types (§6) + construction constraints
    canonical.rs    # wire encoder/decoder (§7), strictness checks
    sign.rs         # sign_record, build_bundle (§9)
    verify.rs       # verify_site, Policy, TimeSource (§10, §11)
    store.rs        # trait BundleStore { put/get/recent } — hash-addressed
    error.rs
  tests/
    vectors.rs      # RFC 8032 test vectors + golden canonical vectors
    lifecycle.rs    # genesis -> publish -> delegate -> rotate -> recover -> revoke
    attack.rs       # replay, tamper-every-byte, scope bypass, clock skew, reorder
  src/bin/nexus-id.rs
    gen | sign-content | verify | bundle | delegate | revoke | rotate | recover
```

Milestones:

1. **M1 — Foundations.** keygen, bech32m id, canonical encoder, RFC 8032
   vectors in tests. (Half a day.)
2. **M2 — Sign/verify.** Content records end-to-end over a fake store;
   tamper byte 0..N → must fail; reorder → must fail. (Half a day.)
3. **M3 — Lifecycle.** Delegate scoping, rotation with overlap, recovery
   handoff, revocation, TTL expiry, seq replay across generations.
   Property tests (proptest): random record orders, random valid/invalid
   mutations. (1 day.)
4. **M4 — CLI + integration harness.** Publisher daemon loop simulated;
   verifier consuming k sources; drift/failure injection. (1 day.)

Deliverables after M4: `nexus-identity` crate + `nexus-id` CLI + a short
integration demo where two processes (publisher, verifier) exchange bundles
over a fake content DHT and the verifier's rendered content provably equals
what the publisher signed. Prototype budget: ~3 days, single engineer.

## 17. Open questions (for Nexus design review)

1. **Naming layer:** does Nexus resolve human names → `nex1…` ids via DHT or
   consensus? Identity layer doesn't care; just needs the resolution to be
   over signed records.
2. **Consensus time anchor:** should verification prefer a consensus-provided
   `now` when within skew? (Recommend yes, v2.)
3. **Multi-delegate depth:** is delegate→delegate ever needed (large orgs,
   per-section editors)? v1 says no.
4. **Recovery ceremony** UX: QR recovery-key printout at genesis?
   Hardware wallet support later?
5. **Cross-layer hygiene:** content records pointing at CCN/IPFS/HTTP
   addresses — should the record carry a per-address signature/enc key hint
   for transport auth, or is hash-integrity enough? (Enough, v1.)

## 18. References

- RFC 8032 (Ed25519) — deterministic signatures
- ed25519-dalek 2.x (SigningKey / VerifyingKey / verify_strict)
- BIP-173 / BIP-350 (bech32 / bech32m)
- Multi-hash convention (0x12 = sha2-256 prefix)
- IPFS/libp2p content-addressing (hash-addressed blobs) — bundle model
- DNSSEC (delegation, signed records, TTLs) — conceptual ancestor,
  adapted to zero-trust decentralized setting