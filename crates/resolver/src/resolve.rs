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
use serde::{Deserialize, Serialize};

use crate::backend::{Backend, MemoryBackend};
use crate::{LocalResolver, ResolveError, Resolver, Route};

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

/// Signed node/address record: binds a site key to a reachable endpoint.
///
/// Field order is fixed for canonical bytes (mirrors `ResourceRecord` in
/// `crates/identity`): `site \0 transport \0 host \0 port \0 expires`.
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
        expires_at_unix: u64,
    ) -> Self {
        let record = Self {
            site: site.to_string(),
            transport,
            host: host.to_string(),
            port,
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

/// Clock abstraction: a plain function returning unix seconds. Real code
/// uses `crate::resolve_now`; tests inject a fixed epoch for determinism.
pub type Clock = fn() -> u64;

/// Verified, local-first store of endpoint records keyed by name.
///
/// Admission = full verification against the name's trust anchor. No record
/// enters the store unverified, regardless of which backend delivered it.
/// Conflict rule (v0): newest-admitted wins per site; the first multi-source
/// upgrade is per-site sequence numbers (see 006 design doc).
#[derive(Debug)]
pub struct RecordStore {
    /// Verified records per name.
    records: HashMap<String, Vec<EndpointRecord>>,
    /// Trust anchors: name → site verifying key (out-of-band, known_hosts).
    anchors: HashMap<String, VerifyingKey>,
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
            anchors: HashMap::new(),
            clock,
        }
    }

    /// Trust `name` to be anchored at `verify` (out-of-band, like installing
    /// a DNSSEC root or SSH known_hosts entry). Required before any record
    /// for the name can be admitted.
    pub fn trust(&mut self, name: &str, verify: VerifyingKey) {
        self.anchors.insert(name.to_string(), verify);
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
        self.anchors.contains_key(name)
    }

    /// Verify `record` against the name's anchor (if any) and admit it.
    /// Returns `false` for unanchored names and anything that fails
    /// verification — invalid input is discarded, never stored.
    pub fn admit(&mut self, name: &str, record: EndpointRecord) -> bool {
        let Some(verify) = self.anchors.get(name) else {
            return false;
        };
        let now = (self.clock)();
        if record.verify(verify, now).is_err() {
            return false;
        }
        // Newest-admitted wins per site (v0 rule).
        let list = self.records.entry(name.to_string()).or_default();
        list.retain(|r| r.site != record.site);
        list.push(record);
        true
    }

    /// Best valid route for `name`, or `None`.
    pub fn route(&self, name: &str) -> Option<Route> {
        let now = (self.clock)();
        let records = self.records.get(name)?;
        let live = records
            .iter()
            .filter(|r| r.expires_at_unix > now)
            .max_by_key(|r| r.expires_at_unix)?;
        Some(Route {
            endpoints: vec![live.endpoint()],
            pinned_site_id: Some(live.site.clone()),
        })
    }

    /// Anchored names (sorted), for `list_names`.
    pub fn known_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.anchors.keys().cloned().collect();
        names.sort();
        names
    }
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
        self.store.lock().unwrap().trust(name, verify);
    }

    /// Direct record admission (bypasses backends; offline publishing).
    pub fn admit_record(&mut self, name: &str, record: EndpointRecord) -> bool {
        self.store.lock().unwrap().admit(name, record)
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
        if let Ok(route) = self.table.lock().unwrap().resolve(name) {
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
                // Decode the endpoint payload out of the content hash field
                // (v0 convention, protocol-lane negotiable).
                let Ok(decoded) =
                    serde_json::from_str::<EndpointRecord>(&signed.record.content_hash)
                else {
                    continue;
                };
                let mut store = self.store.lock().unwrap();
                if store.admit(name, decoded) {
                    if let Some(route) = store.route(name) {
                        // Warm the table; also pins the verified route.
                        let _ = self.table.lock().unwrap().insert(name, route.clone());
                        return Ok(route);
                    }
                }
            }
        }
        // 3. Verified store may already hold a route (offline warm cache).
        self.store
            .lock()
            .unwrap()
            .route(name)
            .ok_or_else(|| ResolveError::UnknownSite(name.to_string()))
    }

    fn list_names(&self) -> Vec<String> {
        let mut names = self.table.lock().unwrap().list_names();
        for n in self.store.lock().unwrap().known_names() {
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

    /// Deterministic test key (fixed secret, no RNG needed).
    fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn now() -> u64 {
        1_700_000_000
    }

    fn make_record(signing: &SigningKey, host: &str, port: u16) -> EndpointRecord {
        let site = hex::encode(signing.verifying_key().to_bytes());
        EndpointRecord::sign(signing, &site, Transport::Tcp, host, port, now() + 86_400)
    }

    #[test]
    fn endpoint_record_roundtrip() {
        let k = test_key(1);
        let site = hex::encode(k.verifying_key().to_bytes());
        let rec = make_record(&k, "127.0.0.1", 7843);
        rec.verify(&k.verifying_key(), now()).unwrap();
        assert_eq!(rec.site, site);
        assert_eq!(rec.endpoint(), "127.0.0.1:7843");
    }

    #[test]
    fn tampered_endpoint_rejected() {
        let k = test_key(2);
        let mut rec = make_record(&k, "127.0.0.1", 7843);
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
        let rec = make_record(&a, "127.0.0.1", 7843);
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
        assert!(!store.admit("nobody", make_record(&k, "127.0.0.1", 1)));
        assert!(store.route("nobody").is_none());
    }

    #[test]
    fn anchored_admit_and_route() {
        let k = test_key(7);
        let mut store = RecordStore::with_clock(now);
        store.trust("alice", k.verifying_key());
        assert!(store.admit("alice", make_record(&k, "10.0.0.1", 7843)));
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
        assert!(!store.admit("alice", make_record(&attacker, "evil", 666)));
        assert!(store.route("alice").is_none());
    }

    #[test]
    fn caching_resolver_fetches_from_backend_then_warms_table() {
        let site_key = test_key(10);
        let site = hex::encode(site_key.verifying_key().to_bytes());

        // Backend holds a signed endpoint record under path "@alice".
        let rec = make_record(&site_key, "10.9.9.9", 7843);
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
}
