//! Signed-record resolution: the **records → nodes** hop.
//!
//! The chain, with the piece this module adds in bold:
//!
//! ```text
//! name ──▶ identity (site key, trusted out-of-band) ──▶ records ──▶ Route
//!                                                          ▲ this module
//! ```
//!
//! [`EndpointRecord`] is a *node/address record*: signed by the site key,
//! carrying a transport address and expiry. It mirrors the shape of
//! [`ResourceRecord`] in `crates/identity` (canonical bytes + strict
//! Ed25519), but binds host/port instead of content — the missing hop
//! between identity records and a routable [`Route`].
//!
//! [`RecordStore`] is the verified, local-first cache: records are admitted
//! ONLY after signature+expiry verification against the name's trust anchor
//! (out-of-band, known_hosts-style). A poisoned backend can deliver garbage;
//! verification discards it for free.
//!
//! See `docs/decisions/006-decentralized-resolution.md` for the full
//! comparison and the DHT/gossip/federated extension plan.

use std::collections::HashMap;
use std::sync::Mutex;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use nexus_identity::{Delegation, RotationLog};
use serde::{Deserialize, Serialize};

use crate::backend::{Backend, MemoryBackend};
use crate::{lock_ignoring_poison, LocalResolver, ResolveError, Resolver, Route};

/// Transport family of an endpoint record. Unknown values are carried
/// opaquely and refused by the router (forward compatibility).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Transport {
    /// Plain TCP.
    Tcp = 1,
    /// QUIC/UDP.
    Quic = 2,
    /// Tor onion service.
    Tor = 3,
    /// I2P destination.
    I2p = 4,
}

impl Transport {
    fn to_u8(self) -> u8 {
        self as u8
    }

    #[allow(dead_code)] // decode counterpart used by future wire backends
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Transport::Tcp,
            2 => Transport::Quic,
            3 => Transport::Tor,
            4 => Transport::I2p,
            _ => return None,
        })
    }
}

/// Signed node/address record. `seq` is the per-name version (see
/// `docs/decisions/009-signed-fetch-path.md`): admission requires strictly
/// advancing the name's high-water mark, so stale replays die.
///
/// Canonical signed bytes (fixed order, never reordered):
/// `site \0 transport \0 host \0 port \0 seq \0 expires`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointRecord {
    /// Site hex id (pubkey) this record is bound to.
    pub site: String,
    /// Wire discriminant of the transport family.
    pub transport: Transport,
    /// Host string (IP, onion v3, i2p destination).
    pub host: String,
    /// Port.
    pub port: u16,
    /// Monotonic per-name version: higher wins, stale replays are dropped.
    #[serde(default)] // pre-M3 records decode as seq 0 (immediately stale)
    pub seq: u64,
    /// Unix seconds after which this record is dead.
    pub expires_at_unix: u64,
    /// Ed25519 signature over `canonical_bytes()`, lower-hex.
    pub signature_hex: String,
}

impl EndpointRecord {
    /// Canonical bytes that are signed. Fixed layout, never reordered.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for part in [
            self.site.as_str(),
            &self.transport.to_u8().to_string(),
            self.host.as_str(),
            &self.port.to_string(),
            &self.seq.to_string(),
            &self.expires_at_unix.to_string(),
        ] {
            out.extend_from_slice(part.as_bytes());
            out.push(0);
        }
        out.pop();
        out
    }

    /// Sign a new endpoint record with a site key.
    pub fn sign(
        signing: &SigningKey,
        site: &str,
        transport: Transport,
        host: &str,
        port: u16,
        seq: u64,
        expires_at_unix: u64,
    ) -> Self {
        let record = Self {
            site: site.to_string(),
            transport,
            host: host.to_string(),
            port,
            seq,
            expires_at_unix,
            signature_hex: String::new(),
        };
        let sig = signing.sign(&record.canonical_bytes());
        Self {
            signature_hex: hex::encode(sig.to_bytes()),
            ..record
        }
    }

    /// Strict verification: signature + site match + expiry, against `now`.
    pub fn verify(&self, verify: &VerifyingKey, now_unix: u64) -> Result<(), ResolveError> {
        let site_hex = hex::encode(verify.to_bytes());
        if self.site != site_hex {
            return Err(ResolveError::BadSignature(format!(
                "site mismatch: record claims {}, key is {}",
                self.site, site_hex
            )));
        }
        if self.expires_at_unix <= now_unix {
            return Err(ResolveError::Expired(self.expires_at_unix, now_unix));
        }
        let sig_bytes = hex::decode(&self.signature_hex)
            .map_err(|e| ResolveError::BadSignature(e.to_string()))?;
        if sig_bytes.len() != 64 {
            return Err(ResolveError::BadSignature(format!(
                "expected 64 bytes, got {}",
                sig_bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&sig_bytes);
        verify
            .verify_strict(&self.canonical_bytes(), &Signature::from_bytes(&arr))
            .map_err(|e| ResolveError::BadSignature(e.to_string()))
    }

    /// Render as a `host:port` endpoint string.
    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Signed revocation tombstone: kills every endpoint record of `site` with
/// `seq <= max_seq`, permanently, once verified. The signer must be the
/// target site's own accepted key. Canonical: `site \0 max_seq \0 expires`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    /// Site hex id whose endpoint records are revoked.
    pub site: String,
    /// Endpoint records of `site` with `seq <= max_seq` are suppressed.
    pub max_seq: u64,
    /// Unix seconds after which this revocation record itself is stale.
    pub expires_at_unix: u64,
    /// Ed25519 signature over `canonical_bytes()`, lower-hex.
    pub signature_hex: String,
}

impl Revocation {
    /// Canonical bytes that are signed. Fixed layout, never reordered.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for part in [
            self.site.as_str(),
            &self.max_seq.to_string(),
            &self.expires_at_unix.to_string(),
        ] {
            out.extend_from_slice(part.as_bytes());
            out.push(0);
        }
        out.pop();
        out
    }

    /// Sign a revocation with the *target site's* key.
    pub fn sign(signing: &SigningKey, site: &str, max_seq: u64, expires_at_unix: u64) -> Self {
        let revocation = Self {
            site: site.to_string(),
            max_seq,
            expires_at_unix,
            signature_hex: String::new(),
        };
        let sig = signing.sign(&revocation.canonical_bytes());
        Self {
            signature_hex: hex::encode(sig.to_bytes()),
            ..revocation
        }
    }

    /// Strict verification (signature + site match + expiry) against `now`.
    pub fn verify(&self, verify: &VerifyingKey, now_unix: u64) -> Result<(), ResolveError> {
        verify_signed(
            verify,
            &self.site,
            &self.canonical_bytes(),
            self.expires_at_unix,
            &self.signature_hex,
            now_unix,
        )
    }
}

/// Clock abstraction: a plain function returning unix seconds. Real code
/// uses `crate::resolve_now`; tests inject a fixed epoch for determinism.
pub type Clock = fn() -> u64;

/// A tombstone: endpoint records of `site` with `seq <= max_seq` are dead.
/// Installed from a signed [`Revocation`] or by a rotation cutover. Permanent:
/// signatures don't rot (expiry exists for future pruning policy).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Tombstone {
    site: String,
    max_seq: u64,
}

/// Verified, local-first cache of endpoint records keyed by name.
///
/// Admission = full verification against the name's accepted keys; no record
/// enters unverified. Conflict rule (M3): `seq` is a *per-name* high-water
/// mark shared by all accepted keys — admission requires strictly advancing
/// it, so newest verified wins and stale replays die; routing picks the
/// highest live, non-tombstoned seq (pin follows the winner).
#[derive(Debug)]
pub struct RecordStore {
    /// Verified records per name.
    records: HashMap<String, Vec<EndpointRecord>>,
    /// Revocation/rotation tombstones per name (permanent).
    tombstones: HashMap<String, Vec<Tombstone>>,
    /// Accepted keys per name: site hex → key (anchor + rotated + delegated).
    trusted: HashMap<String, HashMap<String, VerifyingKey>>,
    /// Name → seq high-water mark.
    seq_high: HashMap<String, u64>,
    /// Applied rotation logs (observability/chain discovery).
    #[allow(dead_code)]
    rotations: HashMap<String, RotationLog>,
    /// Accepted delegations (observability/audit).
    #[allow(dead_code)]
    delegations: HashMap<String, Vec<Delegation>>,
    /// Time source for expiry checks.
    clock: Clock,
}

impl Default for RecordStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordStore {
    /// Create an empty store using the real system clock.
    pub fn new() -> Self {
        Self::with_clock(crate::resolve_now)
    }

    /// Create an empty store with an injected clock (tests).
    pub fn with_clock(clock: Clock) -> Self {
        Self {
            records: HashMap::new(),
            tombstones: HashMap::new(),
            trusted: HashMap::new(),
            seq_high: HashMap::new(),
            rotations: HashMap::new(),
            delegations: HashMap::new(),
            clock,
        }
    }

    /// Trust `name` at `verify` (out-of-band, known_hosts-style).
    pub fn trust(&mut self, name: &str, verify: VerifyingKey) {
        let site = hex::encode(verify.to_bytes());
        self.trusted
            .entry(name.to_string())
            .or_default()
            .insert(site, verify);
    }

    /// Trust a name anchored at a public key given as 32 raw bytes.
    pub fn trust_bytes(&mut self, name: &str, public: &[u8; 32]) -> Result<(), ResolveError> {
        let verify = VerifyingKey::from_bytes(public)
            .map_err(|e| ResolveError::BadSignature(e.to_string()))?;
        self.trust(name, verify);
        Ok(())
    }

    /// Is `name` anchored (and therefore resolvable at all)?
    pub fn is_trusted(&self, name: &str) -> bool {
        self.trusted.get(name).is_some_and(|keys| !keys.is_empty())
    }

    /// Rotation cutover: each trusted `old → new` entry removes the old key,
    /// tombstones its records up to the high-water mark, and lets the new key
    /// continue the sequence. Log = policy input; every hop's old-key
    /// signature over the rotation binding is verified before the cutover
    /// (unverifiable hops are skipped). Signed carrier is future work
    /// (009 doc). Chains apply topologically.
    pub fn rotate(&mut self, name: &str, log: &RotationLog) -> bool {
        if log.entries.is_empty() || !self.trusted.contains_key(name) {
            return false;
        }
        // Collect verified (old_hex, new_hex) hops; skip anything that does
        // not verify under the claimed old key.
        let mut entries: Vec<(String, String)> = Vec::new();
        for (old_hex, entry) in log.entries.iter() {
            let Ok(old_vk) = parse_pubkey(old_hex) else {
                continue;
            };
            let binding = RotationLog::canonical_binding(old_hex, &entry.new_pub_hex);
            let Ok(sig) = parse_signature(&entry.signature_hex) else {
                continue;
            };
            if old_vk.verify_strict(&binding, &sig).is_err() {
                continue;
            }
            entries.push((old_hex.clone(), entry.new_pub_hex.clone()));
        }
        if entries.is_empty() {
            return false;
        }
        let mut applied = false;
        let mut cut_olds: Vec<String> = Vec::new();
        for _ in 0..=entries.len() {
            let mut pass = false;
            for (old_hex, new_hex) in &entries {
                if old_hex == new_hex {
                    continue;
                }
                let cut = {
                    let Some(keys) = self.trusted.get_mut(name) else {
                        continue;
                    };
                    if !keys.contains_key(old_hex) {
                        continue;
                    }
                    let Ok(vk) = parse_pubkey(new_hex) else {
                        continue;
                    };
                    let new_site = hex::encode(vk.to_bytes());
                    if !new_site.eq_ignore_ascii_case(new_hex) {
                        continue;
                    }
                    keys.remove(old_hex);
                    keys.insert(new_site, vk);
                    true
                };
                if cut {
                    let hw = *self.seq_high.get(name).unwrap_or(&0);
                    self.tombstones
                        .entry(name.to_string())
                        .or_default()
                        .push(Tombstone {
                            site: old_hex.clone(),
                            max_seq: hw,
                        });
                    applied = true;
                    cut_olds.push(old_hex.clone());
                    pass = true;
                }
            }
            if !pass {
                break;
            }
        }
        if applied {
            let stored = self.rotations.entry(name.to_string()).or_default();
            for old_hex in &cut_olds {
                if let Some(entry) = log.entries.get(old_hex) {
                    stored.entries.insert(old_hex.clone(), entry.clone());
                }
            }
        }
        applied
    }

    /// Accept a delegation (ed25519-verified, unexpired, `path_prefix`
    /// covers the `@name` record path) and add the delegate key.
    pub fn delegate(&mut self, name: &str, d: &Delegation) -> bool {
        if d.expires_at_unix <= (self.clock)() {
            return false;
        }
        let Ok(vk) = parse_pubkey(&d.delegate_pub_hex) else {
            return false;
        };
        let Some(issuer) = self.trusted.get(name).and_then(|keys| keys.get(&d.site)) else {
            return false;
        };
        if !format!("@{name}").starts_with(&d.path_prefix) {
            return false;
        }
        let Ok(sig) = parse_signature(&d.signature_hex) else {
            return false;
        };
        if issuer.verify_strict(&d.canonical_bytes(), &sig).is_err() {
            return false;
        }
        self.trusted
            .entry(name.to_string())
            .or_default()
            .insert(hex::encode(vk.to_bytes()), vk);
        self.delegations
            .entry(name.to_string())
            .or_default()
            .push(d.clone());
        true
    }

    /// Admit a signed revocation as a permanent tombstone (revoking key =
    /// an accepted key of `name` whose site the revocation names).
    pub fn revoke(&mut self, name: &str, revocation: Revocation) -> bool {
        let Some(vk) = self
            .trusted
            .get(name)
            .and_then(|keys| keys.get(&revocation.site))
        else {
            return false;
        };
        if revocation.verify(vk, (self.clock)()).is_err() {
            return false;
        }
        let max_seq = revocation.max_seq;
        self.tombstones
            .entry(name.to_string())
            .or_default()
            .push(Tombstone {
                site: revocation.site,
                max_seq,
            });
        true
    }

    /// Do tombstones for `name` suppress `site` records at `seq`?
    fn tombstoned(&self, name: &str, site: &str, seq: u64) -> bool {
        self.tombstones
            .get(name)
            .is_some_and(|ts| ts.iter().any(|t| t.site == site && seq <= t.max_seq))
    }

    /// Verify against accepted keys, then admit. Unanchored, unverifiable,
    /// expired, tombstoned, or non-advancing records are never stored.
    pub fn admit(&mut self, name: &str, record: EndpointRecord) -> bool {
        let Some(vk) = self
            .trusted
            .get(name)
            .and_then(|keys| keys.get(&record.site))
        else {
            return false;
        };
        if record.verify(vk, (self.clock)()).is_err() {
            return false;
        }
        if self.tombstoned(name, &record.site, record.seq) {
            return false;
        }
        let hw = self.seq_high.entry(name.to_string()).or_default();
        if record.seq <= *hw {
            return false; // stale replay: must strictly advance the sequence
        }
        *hw = record.seq;
        let list = self.records.entry(name.to_string()).or_default();
        list.retain(|r| r.site != record.site);
        list.push(record);
        true
    }

    /// Best valid route for `name`, or `None`: highest live, non-tombstoned
    /// seq wins (newest verified), and routing pins to the winner's site.
    pub fn route(&self, name: &str) -> Option<Route> {
        let now = (self.clock)();
        let records = self.records.get(name)?;
        let live = records
            .iter()
            .filter(|r| r.expires_at_unix > now && !self.tombstoned(name, &r.site, r.seq))
            .max_by_key(|r| (r.seq, r.expires_at_unix))?;
        Some(Route {
            endpoints: vec![live.endpoint()],
            pinned_site_id: Some(live.site.clone()),
        })
    }

    /// Anchored names (sorted), for `list_names`.
    pub fn known_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.trusted.keys().cloned().collect();
        names.sort();
        names
    }
}

/// Parse a 32-byte ed25519 public key from lower-hex.
fn parse_pubkey(hex_str: &str) -> Result<VerifyingKey, ResolveError> {
    let bytes = decode_hex(hex_str, 32)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).map_err(|e| ResolveError::BadSignature(e.to_string()))
}

/// Parse a 64-byte ed25519 signature from lower-hex.
fn parse_signature(hex_str: &str) -> Result<Signature, ResolveError> {
    let bytes = decode_hex(hex_str, 64)?;
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    Ok(Signature::from_bytes(&arr))
}

/// Decode `len` raw bytes from lower-hex.
fn decode_hex(hex_str: &str, len: usize) -> Result<Vec<u8>, ResolveError> {
    let bytes = hex::decode(hex_str).map_err(|e| ResolveError::BadSignature(e.to_string()))?;
    if bytes.len() != len {
        return Err(ResolveError::BadSignature(format!(
            "expected {len} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Shared strict verification: site match + expiry + ed25519 `verify_strict`.
fn verify_signed(
    verify: &VerifyingKey,
    site: &str,
    canonical: &[u8],
    expires_at_unix: u64,
    signature_hex: &str,
    now_unix: u64,
) -> Result<(), ResolveError> {
    if site != hex::encode(verify.to_bytes()) {
        return Err(ResolveError::BadSignature(format!(
            "site mismatch: record claims {site}, key is {}",
            hex::encode(verify.to_bytes())
        )));
    }
    if expires_at_unix <= now_unix {
        return Err(ResolveError::Expired(expires_at_unix, now_unix));
    }
    let bytes = decode_hex(signature_hex, 64)?;
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    verify
        .verify_strict(canonical, &Signature::from_bytes(&arr))
        .map_err(|e| ResolveError::BadSignature(e.to_string()))
}

/// Resolver that chains: warm petname table → signed records → backends.
///
/// Fast path: the petname table (a [`LocalResolver`]) answers immediately.
/// Cold path: pull signed records from backends, verify against the trust
/// anchor, admit to the [`RecordStore`], then warm the table. Everything
/// works with zero backends (offline, records supplied via `admit`).
///
/// Interior mutability (`Mutex`): the `Resolver` trait takes `&self`, but
/// resolution *is* cache mutation (admission + table warming) — the same
/// read-mostly-cache model as a DNS cache. std `Mutex`, no executor needed.
#[derive(Debug)]
pub struct CachingResolver<B: Backend = MemoryBackend> {
    table: Mutex<LocalResolver>,
    store: Mutex<RecordStore>,
    backends: Vec<B>,
}

impl<B: Backend> CachingResolver<B> {
    /// Build over a warm table, a store, and an ordered backend list.
    pub fn new(table: LocalResolver, store: RecordStore, backends: Vec<B>) -> Self {
        Self {
            table: Mutex::new(table),
            store: Mutex::new(store),
            backends,
        }
    }

    /// Trust anchor + direct (offline) record admission.
    pub fn trust(&mut self, name: &str, verify: VerifyingKey) {
        lock_ignoring_poison(&self.store).trust(name, verify);
    }

    /// Direct record admission (bypasses backends; offline publishing).
    pub fn admit_record(&mut self, name: &str, record: EndpointRecord) -> bool {
        lock_ignoring_poison(&self.store).admit(name, record)
    }

    /// Direct revocation admission; invalidates the warmed table entry so
    /// the tombstone applies on the next resolve (fast path never re-consults
    /// backends — see 009 doc gap).
    pub fn revoke_record(&mut self, name: &str, revocation: Revocation) -> bool {
        if !lock_ignoring_poison(&self.store).revoke(name, revocation) {
            return false;
        }
        lock_ignoring_poison(&self.table).remove(name);
        true
    }

    /// Backends in query order.
    pub fn backends(&self) -> &[B] {
        &self.backends
    }
}

impl<B: Backend> Resolver for CachingResolver<B> {
    fn resolve(&self, name: &str) -> Result<Route, ResolveError> {
        if !crate::is_valid_name(name) {
            return Err(ResolveError::InvalidName(name.to_string()));
        }
        // 1. Fast path: warm table.
        if let Ok(route) = lock_ignoring_poison(&self.table).resolve(name) {
            return Ok(route);
        }
        // 2. Cold path: pull records from backends, verify, admit.
        for backend in &self.backends {
            for signed in backend.fetch(name) {
                // Endpoint records are carried under path "@{name}" inside
                // the identity record envelope (see backend.rs docs).
                if signed.record.path != format!("@{name}") {
                    continue;
                }
                // Decode the endpoint payload (v0 convention: JSON in
                // content_hash, path "@name"). Revocations ride the same
                // envelope and become tombstones.
                let Ok(decoded) =
                    serde_json::from_str::<EndpointRecord>(&signed.record.content_hash)
                else {
                    if let Ok(revocation) =
                        serde_json::from_str::<Revocation>(&signed.record.content_hash)
                    {
                        let _ = lock_ignoring_poison(&self.store).revoke(name, revocation);
                    }
                    continue;
                };
                let mut store = lock_ignoring_poison(&self.store);
                if store.admit(name, decoded) {
                    if let Some(route) = store.route(name) {
                        // Warm the table; also pins the verified route.
                        let _ = lock_ignoring_poison(&self.table).insert(name, route.clone());
                        return Ok(route);
                    }
                }
            }
        }
        // 3. Verified store may already hold a route (offline warm cache).
        lock_ignoring_poison(&self.store)
            .route(name)
            .ok_or_else(|| ResolveError::UnknownSite(name.to_string()))
    }

    fn list_names(&self) -> Vec<String> {
        let mut names = lock_ignoring_poison(&self.table).list_names();
        for n in lock_ignoring_poison(&self.store).known_names() {
            if !names.contains(&n) {
                names.push(n);
            }
        }
        names.sort();
        names
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MemoryBackend;
    use crate::LocalResolver;
    use nexus_identity::SiteIdentity;

    /// Deterministic test key (fixed secret, no RNG needed).
    fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn now() -> u64 {
        1_700_000_000
    }

    fn make_record(signing: &SigningKey, host: &str, port: u16, seq: u64) -> EndpointRecord {
        let site = hex::encode(signing.verifying_key().to_bytes());
        EndpointRecord::sign(
            signing,
            &site,
            Transport::Tcp,
            host,
            port,
            seq,
            now() + 86_400,
        )
    }

    #[test]
    fn endpoint_record_roundtrip() {
        let k = test_key(1);
        let site = hex::encode(k.verifying_key().to_bytes());
        let rec = make_record(&k, "127.0.0.1", 7843, 1);
        rec.verify(&k.verifying_key(), now()).unwrap();
        assert_eq!(rec.site, site);
        assert_eq!(rec.endpoint(), "127.0.0.1:7843");
    }

    #[test]
    fn tampered_endpoint_rejected() {
        let k = test_key(2);
        let mut rec = make_record(&k, "127.0.0.1", 7843, 1);
        rec.port = 9999;
        assert!(matches!(
            rec.verify(&k.verifying_key(), now()),
            Err(ResolveError::BadSignature(_))
        ));
    }

    #[test]
    fn expired_endpoint_rejected() {
        let k = test_key(3);
        let rec = EndpointRecord::sign(
            &k,
            &hex::encode(k.verifying_key().to_bytes()),
            Transport::Tcp,
            "127.0.0.1",
            7843,
            1,
            now() - 10,
        );
        assert!(matches!(
            rec.verify(&k.verifying_key(), now()),
            Err(ResolveError::Expired(_, _))
        ));
    }

    #[test]
    fn wrong_site_rejected() {
        let a = test_key(4);
        let b = test_key(5);
        let rec = make_record(&a, "127.0.0.1", 7843, 1);
        // Verify with B's key: site mismatch must fail.
        assert!(rec.verify(&b.verifying_key(), now()).is_err());
        assert!(matches!(
            rec.verify(&b.verifying_key(), now()),
            Err(ResolveError::BadSignature(_))
        ));
    }

    #[test]
    fn unanchored_records_discarded() {
        let k = test_key(6);
        let mut store = RecordStore::with_clock(now);
        assert!(!store.admit("nobody", make_record(&k, "127.0.0.1", 1, 1)));
        assert!(store.route("nobody").is_none());
    }

    #[test]
    fn anchored_admit_and_route() {
        let k = test_key(7);
        let mut store = RecordStore::with_clock(now);
        store.trust("alice", k.verifying_key());
        assert!(store.admit("alice", make_record(&k, "10.0.0.1", 7843, 1)));
        let route = store.route("alice").unwrap();
        assert_eq!(route.endpoints, vec!["10.0.0.1:7843"]);
        assert_eq!(
            route.pinned_site_id.as_deref(),
            Some(hex::encode(k.verifying_key().to_bytes()).as_str())
        );
    }

    #[test]
    fn wrong_key_cannot_publish_under_trusted_name() {
        let owner = test_key(8);
        let attacker = test_key(9);
        let mut store = RecordStore::with_clock(now);
        store.trust("alice", owner.verifying_key());
        // Attacker's record signed by attacker's key: fails site match.
        assert!(!store.admit("alice", make_record(&attacker, "evil", 666, 1)));
        assert!(store.route("alice").is_none());
    }

    #[test]
    fn caching_resolver_fetches_from_backend_then_warms_table() {
        let site_key = test_key(10);
        let site = hex::encode(site_key.verifying_key().to_bytes());

        // Backend holds a signed endpoint record under path "@alice".
        let rec = make_record(&site_key, "10.9.9.9", 7843, 1);
        let signed = nexus_identity::SignedRecord {
            record: nexus_identity::ResourceRecord {
                site: site.clone(),
                path: "@alice".to_string(),
                content_hash: serde_json::to_string(&rec).unwrap(),
                expires_at_unix: now() + 86_400,
            },
            signature_hex: String::new(), // unused by resolver at v0; identity lane owns content records
        };
        let backend = MemoryBackend::new();
        backend.advertise(&signed).unwrap();

        let table = LocalResolver::new();
        let mut store = RecordStore::with_clock(now);
        store.trust("alice", site_key.verifying_key());
        let resolver = CachingResolver::new(table, store, vec![backend]);

        // Cold: fetched from the backend, verified, routed.
        let route = resolver.resolve("alice").unwrap();
        assert_eq!(route.endpoints, vec!["10.9.9.9:7843"]);
        assert_eq!(route.pinned_site_id.as_deref(), Some(site.as_str()));

        // Warm: second resolve survives without the backend.
        let route2 = resolver.resolve("alice").unwrap();
        assert_eq!(route2, route);
        assert!(resolver.list_names().contains(&"alice".to_string()));
    }

    #[test]
    fn unknown_name_not_found() {
        let resolver =
            CachingResolver::<MemoryBackend>::new(LocalResolver::new(), RecordStore::new(), vec![]);
        assert!(matches!(
            resolver.resolve("nope"),
            Err(ResolveError::UnknownSite(_))
        ));
    }

    // ---- M3: seq, revocation tombstones, key rotation/delegation ----

    #[test]
    fn seq_newest_wins_stale_replay_rejected() {
        let k = test_key(11);
        let mut s = RecordStore::with_clock(now);
        s.trust("alice", k.verifying_key());
        assert!(s.admit("alice", make_record(&k, "10.0.0.1", 1, 1)));
        assert!(s.admit("alice", make_record(&k, "10.0.0.2", 2, 2)));
        assert_eq!(s.route("alice").unwrap().endpoints, vec!["10.0.0.2:2"]);
        // Replays — same seq or lower — must be rejected.
        assert!(!s.admit("alice", make_record(&k, "10.0.0.1", 1, 1)));
        assert!(!s.admit("alice", make_record(&k, "10.0.0.3", 3, 1)));
        assert_eq!(s.route("alice").unwrap().endpoints, vec!["10.0.0.2:2"]);
    }

    #[test]
    fn revocation_tombstone_suppresses_matching_records() {
        let k = test_key(12);
        let site = hex::encode(k.verifying_key().to_bytes());
        let mut s = RecordStore::with_clock(now);
        s.trust("alice", k.verifying_key());
        assert!(s.admit("alice", make_record(&k, "10.0.0.1", 1, 1)));
        assert!(s.admit("alice", make_record(&k, "10.0.0.2", 2, 2)));
        assert!(s.revoke("alice", Revocation::sign(&k, &site, 3, now() + 86_400)));
        assert!(s.route("alice").is_none()); // admitted records now suppressed
        assert!(!s.admit("alice", make_record(&k, "10.0.0.3", 3, 3))); // at/under tombstone
        assert!(s.admit("alice", make_record(&k, "10.0.0.4", 4, 4))); // above tombstone
        assert_eq!(s.route("alice").unwrap().endpoints, vec!["10.0.0.4:4"]);
    }

    #[test]
    fn revocation_scoped_and_unforgeable() {
        let k = test_key(13);
        let site = hex::encode(k.verifying_key().to_bytes());
        let mut s = RecordStore::with_clock(now);
        s.trust("alice", k.verifying_key());
        assert!(s.admit("alice", make_record(&k, "10.0.0.1", 1, 1)));
        assert!(s.revoke("alice", Revocation::sign(&k, &site, 1, now() + 86_400)));
        assert!(s.admit("alice", make_record(&k, "10.0.0.2", 2, 2))); // seq 2 > tombstone
        assert_eq!(s.route("alice").unwrap().endpoints, vec!["10.0.0.2:2"]);
        let attacker = test_key(14);
        assert!(!s.revoke(
            "alice",
            Revocation::sign(&attacker, &site, 99, now() + 86_400)
        ));
    }

    #[test]
    fn rotation_cuts_over_to_new_key() {
        let (a, b) = (test_key(15), test_key(16));
        let a_hex = hex::encode(a.verifying_key().to_bytes());
        let b_hex = hex::encode(b.verifying_key().to_bytes());
        let mut s = RecordStore::with_clock(now);
        s.trust("alice", a.verifying_key());
        assert!(s.admit(
            "alice",
            EndpointRecord::sign(&a, &a_hex, Transport::Tcp, "10.0.0.1", 1, 1, now() + 86_400)
        ));
        let mut log = RotationLog::default();
        log.rotate(
            &SiteIdentity {
                signing: Some(a.clone()),
                verify: a.verifying_key(),
            },
            &SiteIdentity {
                signing: Some(b.clone()),
                verify: b.verifying_key(),
            },
        )
        .unwrap();
        assert!(s.rotate("alice", &log));
        // New key continues the sequence; pins follow the winning record.
        assert!(s.admit(
            "alice",
            EndpointRecord::sign(&b, &b_hex, Transport::Tcp, "10.0.0.2", 2, 2, now() + 86_400)
        ));
        let route = s.route("alice").unwrap();
        assert_eq!(route.endpoints, vec!["10.0.0.2:2"]);
        assert_eq!(route.pinned_site_id.as_deref(), Some(b_hex.as_str()));
        // Rotated-out key no longer verifies (removed from accepted keys);
        // its pre-rotation records are tombstoned.
        assert!(!s.admit(
            "alice",
            EndpointRecord::sign(&a, &a_hex, Transport::Tcp, "10.0.0.9", 9, 3, now() + 86_400)
        ));
    }

    #[test]
    fn delegation_admits_scoped_key() {
        let (owner, dev) = (test_key(17), test_key(18));
        let owner_hex = hex::encode(owner.verifying_key().to_bytes());
        let dev_hex = hex::encode(dev.verifying_key().to_bytes());
        let mut s = RecordStore::with_clock(now);
        s.trust("alice", owner.verifying_key());
        let mut d = Delegation {
            site: owner_hex.clone(),
            delegate_pub_hex: dev_hex.clone(),
            path_prefix: "@".into(),
            expires_at_unix: now() + 86_400,
            signature_hex: String::new(),
        };
        d.signature_hex = hex::encode(owner.sign(&d.canonical_bytes()).to_bytes());
        assert!(s.delegate("alice", &d));
        assert!(s.admit(
            "alice",
            EndpointRecord::sign(
                &dev,
                &dev_hex,
                Transport::Tcp,
                "10.0.0.7",
                7,
                1,
                now() + 86_400
            )
        ));
        assert_eq!(
            s.route("alice").unwrap().pinned_site_id.as_deref(),
            Some(dev_hex.as_str())
        );
        // Unsigned delegation is rejected.
        let forged = Delegation {
            site: owner_hex,
            delegate_pub_hex: hex::encode(test_key(19).verifying_key().to_bytes()),
            path_prefix: "@".into(),
            expires_at_unix: now() + 86_400,
            signature_hex: String::new(),
        };
        assert!(!s.delegate("alice", &forged));
    }

    #[test]
    fn revoke_invalidates_warmed_table() {
        let k = test_key(20);
        let site = hex::encode(k.verifying_key().to_bytes());
        let mut r = CachingResolver::<MemoryBackend>::new(
            LocalResolver::new(),
            RecordStore::with_clock(now),
            vec![],
        );
        r.trust("alice", k.verifying_key());
        assert!(r.admit_record(
            "alice",
            EndpointRecord::sign(&k, &site, Transport::Tcp, "10.0.0.1", 1, 1, now() + 86_400)
        ));
        assert!(r.resolve("alice").is_ok()); // warms the petname table
        assert!(r.revoke_record("alice", Revocation::sign(&k, &site, 1, now() + 86_400)));
        // Warm entry invalidated + tombstone active: route is gone.
        assert!(matches!(
            r.resolve("alice"),
            Err(ResolveError::UnknownSite(_))
        ));
    }
}
