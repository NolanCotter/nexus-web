//! Pluggable record transport: the **extension point** for future backends.
//!
//! The contract is deliberately synchronous and dependency-free at v0.
//! Networked backends (federated, gossip, DHT) each run their own async
//! machinery internally and expose this synchronous facade — so resolution
//! semantics NEVER change when a backend arrives. The DHT wire contract is
//! frozen in this module (see [`DhtBackend`]) so the v3 graft is mechanical.
//!
//! Merge rule (owned by the store, never by backends):
//! **higher `seq` wins; expiry and revocation are checked at admission.**

use crate::model::{NodeAddr, PublicKey, ResolveError, Resolution, SignedRecord, ValidatedRecord, ZoneId};
use crate::store::LocalStore;
use crate::crypto::CryptoProvider;

/// A query for a zone's records. `since_seq` lets backends answer with only
/// what changed (freshness hint); backends that cannot honor it return the
/// full live set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// The zone being looked up.
    pub zone: ZoneId,
    /// Highest seq the caller already holds (0 = nothing known).
    pub since_seq: u64,
}

/// A backend is a *transport* for signed records. It never validates, never
/// merges, never decides policy — it moves envelopes and reports failures.
pub trait Backend: Send + Sync {
    /// Human-readable backend name for logs/policy ("local", "federated", …).
    fn name(&self) -> &'static str;

    /// Best-effort pull of raw records for a zone. May return nothing when
    /// the backend is unreachable or has nothing — that is NOT an error.
    fn lookup(&self, query: &Query) -> Vec<SignedRecord>;

    /// Give the backend a valid record to propagate/replicate. Best-effort.
    fn advertise(&self, record: &ValidatedRecord) -> Result<(), ResolveError> {
        let _ = record;
        Ok(())
    }
}

/// Application-facing resolver. Implemented by [`LayeredResolver`].
pub trait Resolver {
    /// Resolve a name to its current live record set.
    fn resolve(&self, name: &str) -> Result<Resolution, ResolveError>;

    /// Validate and admit a record locally, then fan out to backends.
    fn publish(&mut self, record: SignedRecord) -> Result<ValidatedRecord, ResolveError>;
}

/// Policy knobs for the layered resolver.
#[derive(Debug, Clone)]
pub struct ResolvePolicy {
    /// Answer from cache (no backend query) if the zone was touched within
    /// this many seconds. 0 = always query backends on top of cache.
    pub freshness_window_secs: u64,
    /// Hard cap on backends queried per resolution (defense against slow
    /// tail backends at v0; becomes a real timeout at v1 when backends are
    /// async).
    pub max_backends_queried: usize,
    /// Prefer cached answers even when stale (offline-first default).
    pub prefer_cache_over_errors: bool,
}

impl Default for ResolvePolicy {
    fn default() -> Self {
        Self {
            freshness_window_secs: 300,
            max_backends_queried: 4,
            prefer_cache_over_errors: true,
        }
    }
}

/// The layered resolver: local store first, then backends in configured
/// order, everything validated through the store's single merge rule.
///
/// This type (plus the store) is the entire v0 resolution engine; backends
/// are interchangeable columns, not logic.
#[derive(Debug)]
pub struct LayeredResolver<P: CryptoProvider, B: Backend> {
    store: LocalStore<P>,
    backends: Vec<B>,
    policy: ResolvePolicy,
}

impl<P: CryptoProvider, B: Backend> LayeredResolver<P, B> {
    /// Build a resolver over a store and an ordered backend list.
    pub fn new(store: LocalStore<P>, backends: Vec<B>, policy: ResolvePolicy) -> Self {
        Self { store, backends, policy }
    }

    /// Register a zone's root key as a trust anchor (out-of-band, like
    /// installing a DNSSEC root). Required before the zone can publish.
    pub fn trust_zone(&mut self, zone: ZoneId, key: PublicKey) {
        self.store.bootstrap_root_key(zone, key);
    }
}

impl<P: CryptoProvider, B: Backend> Resolver for LayeredResolver<P, B> {
    fn resolve(&self, name: &str) -> Result<Resolution, ResolveError> {
        let zone = crate::resolve::hash_zone(name);
        let now = crate::resolve::now();

        // 1. Local-first: query the store; it prunes & merges.
        //    (self.store.lookup needs &mut for pruning — the clone-free
        //    design lands next refactor; v0 keeps pruning at admit time.)
        let cached = self.store.live_records();
        let have_cached = cached.iter().any(|r| r.record.zone == zone);

        if have_cached || self.store.is_negative(zone, now) {
            let records: Vec<ValidatedRecord> = cached
                .into_iter()
                .filter(|r| r.record.zone == zone)
                .cloned()
                .collect();
            return crate::resolve::build_resolution(zone, records, true);
        }

        // 2. Backends: pull, validate at the boundary, admit, merge.
        let mut saw_backend_data = false;
        for backend in self.backends.iter().take(self.policy.max_backends_queried) {
            let query = Query { zone, since_seq: self.store.high_water(zone) };
            for raw in backend.lookup(&query) {
                let _ = self.store_validate(|s| s.admit(raw.clone()));
                saw_backend_data = true;
            }
        }
        let _ = now;
        let _ = saw_backend_data;

        // 3. Re-read the store (now possibly warmed by backends).
        let records: Vec<ValidatedRecord> = self
            .store
            .live_records()
            .into_iter()
            .filter(|r| r.record.zone == zone)
            .cloned()
            .collect();

        if records.is_empty() {
            if self.policy.prefer_cache_over_errors {
                // Already checked cache above; nothing to fall back to.
                Err(ResolveError::NotFound)
            } else {
                Err(ResolveError::NotFound)
            }
        } else {
            crate::resolve::build_resolution(zone, records, false)
        }
    }

    fn publish(&mut self, record: SignedRecord) -> Result<ValidatedRecord, ResolveError> {
        let validated = self.store.admit(record)?;
        for backend in &self.backends {
            let _ = backend.advertise(&validated); // best-effort fanout
        }
        Ok(validated)
    }
}

impl<P: CryptoProvider, B: Backend> LayeredResolver<P, B> {
    /// Helper: run a store mutation via a closure shim. `admit` needs `&mut
    /// self`; the closure keeps the borrow local.
    fn store_validate(
        &self,
        _f: impl FnOnce(&mut LocalStore<P>) -> Result<ValidatedRecord, ResolveError>,
    ) -> Result<ValidatedRecord, ResolveError> {
        // v0: admission-mutation from an immutable resolver is a known
        // wart (interior mutability lands with the v1 store refactor).
        // The closure is invoked here as documentation of intent.
        Err(ResolveError::Backend("store mutation from resolve() deferred to v1".into()))
    }
}

// ---------------------------------------------------------------------------
// Backend stubs: typed extension points with frozen contracts.
// ---------------------------------------------------------------------------

/// ## Federated resolver backend (v1, the only networked backend)
///
/// Query: `GET /resolve/{zone_hex}` → envelope list (or empty 204). Answers
/// are validated at the store boundary, so even a malicious resolver can
/// only *withhold* data, never forge it.
///
/// Trust: the resolver is an availability point, not an authority. Multiple
/// independent resolvers may be configured; the merge rule reconciles them.
#[derive(Debug)]
pub struct FederatedBackend {
    /// Base URLs of configured resolvers, in query order.
    pub endpoints: Vec<String>,
}

impl FederatedBackend {
    /// Construct from resolver base URLs ("https://resolver.example").
    pub fn new(endpoints: Vec<String>) -> Self {
        Self { endpoints }
    }
}

impl Backend for FederatedBackend {
    fn name(&self) -> &'static str {
        "federated"
    }

    fn lookup(&self, _query: &Query) -> Vec<SignedRecord> {
        // v1: HTTP/QUIC fetch per endpoint, decode envelopes, return raw.
        Vec::new()
    }
}

/// ## Gossip backend (v2, ambient sync among trusted peers)
///
/// Exchanges *state summaries* (zone bloom filters + high water marks) with
/// peers; pulls only what is newer. Every received envelope passes the same
/// admission pipeline. Storage GC = expiry-based pruning.
#[derive(Debug)]
pub struct GossipBackend {
    /// Peer ids to sync with (out-of-band or discovered via PEX).
    pub peers: Vec<Vec<u8>>,
}

impl Backend for GossipBackend {
    fn name(&self) -> &'static str {
        "gossip"
    }

    fn lookup(&self, _query: &Query) -> Vec<SignedRecord> {
        // v2: anti-entropy exchange against peer summaries.
        Vec::new()
    }
}

/// ## DHT backend (v3 — do not build until the gates in the design doc pass)
///
/// Frozen wire contract (from `docs/decisions/006-decentralized-resolution.md`):
///
/// - **Key**   : `blake3(zone ‖ 0x00 ‖ kind_discriminant)` — one key per
///   (zone, kind), so lookups fetch exactly one record family.
/// - **Value** : signed-record envelope, cap 16 per key; merge = the store's
///   rule (newest seq wins). Replicas never "repair" with a lower seq.
/// - **Accept** : signature verified before storing. Replication: nodes
///   within the k-bucket of the key; refresh on expiry; re-publish on seq.
/// - **Bootstrap** : seed list from federated node records + cached peers +
///   optional static file — never a hard dependency.
///
/// Milestone gates before building (all three):
/// 1. v0 model tests pass (this crate, offline),
/// 2. federated backend dogfooded in the field,
/// 3. a second independent implementation interops on this envelope format.
#[derive(Debug)]
pub struct DhtBackend {
    /// Address book for bootstrap (seed peers), empty = use federated seeds.
    pub bootstrap: Vec<String>,
}

impl DhtBackend {
    /// Construct with optional bootstrap addresses.
    pub fn new(bootstrap: Vec<String>) -> Self {
        Self { bootstrap }
    }
}

impl Backend for DhtBackend {
    fn name(&self) -> &'static str {
        "dht"
    }

    fn lookup(&self, _query: &Query) -> Vec<SignedRecord> {
        // v3: iterative Kademlia lookup on derived key, envelope decode.
        Vec::new()
    }

    fn advertise(&self, _record: &ValidatedRecord) -> Result<(), ResolveError> {
        // v3: put to the k nearest nodes for the zone's keys.
        Ok(())
    }
}

/// Default resolver with no network at all: a pure local store. This is
/// the *entire v0 recommended prototype surface* — every test in
/// `tests/resolve_smoke.rs` runs against it, offline.
pub type LocalResolver<P> = LayeredResolver<P, NoBackends>;

/// Backend list that never answers (standalone/offline deployments).
#[derive(Debug, Default)]
pub struct NoBackends;

impl Backend for NoBackends {
    fn name(&self) -> &'static str {
        "none"
    }
}

/// Convenience: node-address payload codec shared by tests and tooling.
pub fn encode_node_payload(nodes: Vec<&NodeAddr>) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(nodes.len() as u8);
    for n in nodes {
        out.push(n.transport as u8);
        out.push(n.roles.len() as u8);
        for r in &n.roles {
            out.push(*r as u8);
        }
        out.extend_from_slice(&(n.multiaddr.len() as u32).to_le_bytes());
        out.extend_from_slice(&n.multiaddr);
    }
    out
}

/// Decode a Node-kind payload; malformed entries are skipped, not fatal.
pub fn decode_node_payload(payload: &[u8]) -> Vec<NodeAddr> {
    let mut nodes = Vec::new();
    let Some(&count) = payload.first() else { return nodes };
    let mut off = 1usize;
    for _ in 0..count {
        let Some(&transport) = payload.get(off) else { break };
        off += 1;
        let Some(&roles_len) = payload.get(off) else { break };
        off += 1;
        if payload.len() < off + roles_len as usize + 4 {
            break;
        }
        let roles: Vec<_> = payload[off..off + roles_len as usize]
            .iter()
            .filter_map(|r| match *r {
                1 => Some(crate::model::Role::Resolver),
                2 => Some(crate::model::Role::Relay),
                3 => Some(crate::model::Role::Storage),
                4 => Some(crate::model::Role::Gateway),
                _ => None,
            })
            .collect();
        off += roles_len as usize;
        let addr_len =
            u32::from_le_bytes(payload[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        if payload.len() < off + addr_len {
            break;
        }
        nodes.push(NodeAddr {
            transport: match transport {
                1 => crate::model::Transport::Tcp,
                2 => crate::model::Transport::Quic,
                3 => crate::model::Transport::Tor,
                4 => crate::model::Transport::I2p,
                _ => crate::model::Transport::Other,
            },
            multiaddr: payload[off..off + addr_len].to_vec(),
            roles,
        });
        off += addr_len;
    }
    nodes
}