//! Distributed-resolution extension points: the **backend** seam.
//!
//! The local-first core lives in `lib.rs` (petname table → `Route`). This
//! module adds the *pluggable transport* layer for signed records,
//! following `docs/decisions/004-resolution.md`:
//!
//! > ship `Resolver` trait + `LocalResolver`; DHT experiment branch only after.
//!
//! Backends move signed records ([`nexus_identity::SignedRecord`]) between
//! nodes. They NEVER validate, merge, or decide policy — verification and
//! conflict resolution stay in the resolver core, so a poisoned or forged
//! backend answer costs nothing: it fails verification and is dropped.
//!
//! Roadmap of implementations:
//! - v1 [`FederatedBackend`]  — fast, cacheable, DNS-like pull (only networked backend)
//! - v2 [`GossipBackend`]     — ambient sync among trusted peers
//! - v3 [`DhtBackend`]        — global discovery, gated behind the milestones below

use std::fmt::Debug;

use nexus_identity::SignedRecord;

use crate::lock_ignoring_poison;

/// Transport-level backend failure (distinct from resolution semantics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendError {
    /// Backend unreachable or timed out (message for logs only).
    Unreachable(String),
    /// Backend returned data that failed structural decode.
    Malformed,
    /// Backend refused the advertisement.
    Refused(String),
}

/// A backend is a *transport* for signed records. It never validates, never
/// merges — it moves envelopes and reports failures. Sync facade over
/// internally-async machinery: a QUIC or Kademlia backend runs its I/O on
/// its own runtime and fulfills this trait synchronously (empty vec on
/// "still in flight"), so resolution semantics never depend on the backend.
pub trait Backend: Debug + Send + Sync {
    /// Human-readable backend name for logs and policy ("federated", …).
    fn name(&self) -> &'static str;

    /// Best-effort pull of signed records relevant to `name`. Returning an
    /// empty vec is NOT an error (backend down / nothing known / in flight).
    fn fetch(&self, name: &str) -> Vec<SignedRecord>;

    /// Give the backend a valid record to propagate/replicate. Best-effort.
    fn advertise(&self, record: &SignedRecord) -> Result<(), BackendError> {
        let _ = record;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Backend implementations: typed extension points with frozen contracts.
// ---------------------------------------------------------------------------

/// ## v1 — Federated resolver backend (the only networked backend)
///
/// Pull-only, DNS-like: `fetch(name)` sends one `RECORDS` request per
/// configured endpoint over nexus-transport TCP framing and returns the raw
/// [`SignedRecord`] envelopes the servers answered with, aggregated across
/// endpoints. Shared wire convention: `docs/decisions/010-federated-records-convention.md`.
///
/// Trust: resolvers are availability points, not authorities. This backend
/// is a pure transport — it moves envelopes and keeps transport counters,
/// but NEVER verifies, merges, or decides policy. Everything it returns is
/// admitted (or dropped) through the exact same core path as
/// [`MemoryBackend`]: signature + site match + expiry + strictly-advancing
/// seq against the out-of-band trust anchor in the resolver's store. A
/// malicious resolver can *withhold* data (serve 404/empty) but can never
/// forge it. Configure several; aggregation plus the core's merge rule
/// (newest verified wins) reconciles them.
///
/// Publish is out-of-band: NXP/0.1 has no push verb, so `advertise` stays
/// the default best-effort no-op; records are signed and published at the
/// resolver itself.
#[derive(Debug)]
pub struct FederatedBackend {
    /// Resolver endpoints as `host:port`, queried in order and aggregated.
    pub endpoints: Vec<String>,
    /// Transport observability: raw wire outcomes, never admission decisions.
    stats: std::sync::Mutex<BackendStats>,
}

/// Transport-level counters for [`FederatedBackend`] queries. They describe
/// what the wire did, never what the verified store admitted.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BackendStats {
    /// RECORDS requests sent.
    pub requests: u64,
    /// Envelopes returned by servers (pre-verification).
    pub records: u64,
    /// Transport/decode failures (unreachable, malformed, refused).
    pub failures: u64,
    /// Status code of the last response seen (0 = none).
    pub last_code: u16,
}

/// One RECORDS round-trip against a single endpoint. Line shape:
/// `NXP/0.1 RECORDS <name> @<name>\n` — the path is the `@name`
/// endpoint-record namespace the resolver core keys on (010 decision).
/// `name` already passed `is_valid_site` at the caller, so the interpolated
/// line can carry no injection bytes.
fn query(endpoint: &str, name: &str) -> Result<(u16, Vec<SignedRecord>), BackendError> {
    let line = format!("{} RECORDS {name} @{name}\n", nexus_protocol::VERSION);
    let (code, body) = nexus_transport::fetch_raw(endpoint, &line)
        .map_err(|e| BackendError::Unreachable(e.to_string()))?;
    if code != 200 {
        return if code == 404 {
            Ok((404, Vec::new())) // authoritative "nothing here"
        } else {
            Err(BackendError::Refused(format!("server answered {code}")))
        };
    }
    serde_json::from_slice::<Vec<SignedRecord>>(&body)
        .map(|records| (200, records))
        .map_err(|_| BackendError::Malformed)
}

impl FederatedBackend {
    /// Construct from resolver endpoints as `host:port` TCP addresses.
    pub fn new(endpoints: Vec<String>) -> Self {
        Self {
            endpoints,
            stats: std::sync::Mutex::new(BackendStats::default()),
        }
    }

    /// Snapshot of the transport counters (logs, tests).
    pub fn stats(&self) -> BackendStats {
        crate::lock_ignoring_poison(&self.stats).clone()
    }
}

impl Backend for FederatedBackend {
    fn name(&self) -> &'static str {
        "federated"
    }

    fn fetch(&self, name: &str) -> Vec<SignedRecord> {
        if !crate::is_valid_name(name) {
            return Vec::new(); // the core rejects invalid names anyway
        }
        let mut stats = crate::lock_ignoring_poison(&self.stats);
        let mut out = Vec::new();
        for endpoint in &self.endpoints {
            stats.requests += 1;
            match query(endpoint, name) {
                Ok((code, mut records)) => {
                    stats.last_code = code;
                    stats.records += records.len() as u64;
                    out.append(&mut records);
                }
                Err(_) => stats.failures += 1, // availability over single answers
            }
        }
        out
    }
}

/// ## v2 — Gossip backend (ambient sync among collaborating peers)
///
/// Peers exchange *state summaries* (name high-water marks / bloom filters)
/// over the transport (`crates/transport`); each side pulls only what it
/// lacks. Every received envelope passes the same verification pipeline.
/// Storage GC = expiry-based pruning.
#[derive(Debug)]
pub struct GossipBackend {
    /// Peer identifiers to sync with (out-of-band or discovered via PEX).
    pub peers: Vec<String>,
}

impl Backend for GossipBackend {
    fn name(&self) -> &'static str {
        "gossip"
    }

    fn fetch(&self, _name: &str) -> Vec<SignedRecord> {
        // v2: anti-entropy exchange against peer summaries.
        Vec::new()
    }
}

/// ## v3 — DHT backend (Kademlia). DO NOT BUILD until all gates pass.
///
/// Frozen wire contract (from `docs/decisions/006-decentralized-resolution.md`):
///
/// - **Key**   : `blake3(name ‖ 0x00 ‖ record_kind)` — one key per
///   (name, record kind), so a lookup fetches exactly one record family.
/// - **Value** : signed-record envelope list, cap 16 per key; merge rule =
///   the core's rule (newest verified wins). Replicas never "repair" toward
///   a lower version.
/// - **Accept**: record verified against the site key *before* storing.
///   Replication: nodes within the k-bucket of the key; refresh on expiry;
///   re-publish on version change.
/// - **Bootstrap**: seed list from federated node records + cached peers +
///   optional static file — never a hard dependency of resolution.
///
/// Milestone gates (all three required):
/// 1. v0 local model + tests green (this crate, offline),
/// 2. federated backend dogfooded in the field,
/// 3. a second, independent implementation interoperates on the envelope format.
#[derive(Debug)]
pub struct DhtBackend {
    /// Bootstrap seed addresses; empty = fall back to federated seeds.
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

    fn fetch(&self, _name: &str) -> Vec<SignedRecord> {
        // v3: iterative Kademlia lookup on derived key, envelope decode.
        Vec::new()
    }

    fn advertise(&self, _record: &SignedRecord) -> Result<(), BackendError> {
        // v3: put to the k nearest nodes for the name's keys.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Test double
// ---------------------------------------------------------------------------

/// In-memory backend for tests and single-process demos: serves whatever
/// records were advertised to it. This is also the conformance harness —
/// a real backend that passes the same scenarios as `MemoryBackend` is a
/// correct backend, by definition of the seam.
#[derive(Debug, Default)]
pub struct MemoryBackend {
    records: std::sync::Mutex<Vec<SignedRecord>>,
}

impl MemoryBackend {
    /// Create an empty in-memory backend.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record count (test assertions).
    pub fn len(&self) -> usize {
        lock_ignoring_poison(&self.records).len()
    }

    /// True when no records are stored.
    pub fn is_empty(&self) -> bool {
        lock_ignoring_poison(&self.records).is_empty()
    }
}

impl Backend for MemoryBackend {
    fn name(&self) -> &'static str {
        "memory"
    }

    fn fetch(&self, name: &str) -> Vec<SignedRecord> {
        lock_ignoring_poison(&self.records)
            .iter()
            .filter(|r| r.record.path == format!("@{name}"))
            .cloned()
            .collect()
    }

    fn advertise(&self, record: &SignedRecord) -> Result<(), BackendError> {
        lock_ignoring_poison(&self.records).push(record.clone());
        Ok(())
    }
}
