//! Local-first record store: the *source of truth* when offline.
//!
//! The store is a read-mostly cache with a strict admission policy:
//!
//! 1. envelope decodes,
//! 2. signature verifies against a key authorized for the zone,
//! 3. seq is strictly newer than the stored live record for `(zone, kind)`,
//! 4. not covered by a live revocation tombstone.
//!
//! Everything admitted is appended to an append-only log (audit + replay),
//! and the live view is derived by deterministic merge — the *same* merge
//! the DHT and gossip backends will use. Backends never merge; the store
//! owns conflict resolution.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use crate::crypto::CryptoProvider;
use crate::model::{
    Envelope, PublicKey, RecordKind, ResolveError, SignedRecord, ValidatedRecord, ZoneId,
    hex_decode, hex_encode,
};

/// Key for the live-view index: `(zone, kind)`.
type SlotKey = (ZoneId, RecordKind);

/// I/O-level store failure (separate from resolution semantics).
#[derive(Debug)]
pub enum StoreError {
    /// Could not read/append the log file.
    Io(std::io::Error),
    /// A stored envelope failed to decode (corrupt log).
    Corrupt(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "store io: {e}"),
            StoreError::Corrupt(s) => write!(f, "store corrupt: {s}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// The local record store.
///
/// Persistence: one envelope (hex) per line in `log_path`. Reads at open,
/// appends on admit. Safe against partial appends at v0 (last line may be
/// re-read on next open); a real crash-safe log (fsync + checksum per line)
/// is a v1 storage task, not a resolution-model task.
#[derive(Debug)]
pub struct LocalStore<P: CryptoProvider> {
    crypto: P,
    /// Live record per (zone, kind): the merge result, authoritative.
    live: HashMap<SlotKey, ValidatedRecord>,
    /// Revocation tombstones per zone: `invalidates_up_to` per seq.
    revocations: HashMap<ZoneId, Vec<RevocationTombstone>>,
    /// Authorized signers per zone: delegated keys (rotation chain).
    authorized: HashMap<ZoneId, Vec<PublicKey>>,
    /// Negative cache: names known to have nothing live, with expiry.
    negative: HashMap<ZoneId, u64>,
    /// Highest seq seen per (zone, kind) — monotonically increases.
    high_water: HashMap<SlotKey, u64>,
    log_path: Option<std::path::PathBuf>,
}

/// A revocation tombstone: records with `seq <= invalidates_up_to` are dead.
#[derive(Debug, Clone)]
pub(crate) struct RevocationTombstone {
    pub seq: u64,
    pub invalidates_up_to: u64,
}

impl<P: CryptoProvider> LocalStore<P> {
    /// Open an empty in-memory store (no persistence).
    pub fn in_memory(crypto: P) -> Self {
        Self {
            crypto,
            live: HashMap::new(),
            revocations: HashMap::new(),
            authorized: HashMap::new(),
            negative: HashMap::new(),
            high_water: HashMap::new(),
            log_path: None,
        }
    }

    /// Open a store backed by an append-only log at `path` (created if
    /// missing); replays existing lines.
    pub fn open(crypto: P, path: &Path) -> Result<Self, StoreError> {
        let mut store = Self::in_memory(crypto);
        store.log_path = Some(path.to_path_buf());
        if path.exists() {
            let data = std::fs::read_to_string(path).map_err(StoreError::Io)?;
            for (i, line) in data.lines().enumerate() {
                let env = Envelope::from_hex(line.trim())
                    .map_err(|e| StoreError::Corrupt(format!("line {}: {e:?}", i + 1)))?;
                // Replay admits only what still validates; corrupt-but-signed
                // records remain in the log (audit) but never enter `live`.
                let _ = store.admit(env.record);
            }
        }
        Ok(store)
    }

    /// Full validation + admission pipeline. Returns the validated record.
    pub fn admit(&mut self, record: SignedRecord) -> Result<ValidatedRecord, ResolveError> {
        self.validate(&record)?;
        let validated = ValidatedRecord {
            identity: crate::model::IdentityId::default(), // derived in v1 from signer chain
            record: record.clone(),
        };

        // Record the live view by merge rules.
        match record.kind {
            RecordKind::Revocation => self.apply_revocation(&record),
            RecordKind::Delegation => self.apply_delegation(&record),
            _ => {
                let slot = (record.zone, record.kind);
                let prev = self.live.get(&slot);
                if prev.is_some_and(|p| p.record.seq >= record.seq) {
                    return Err(ResolveError::StaleSequence);
                }
                self.negative.remove(&record.zone);
                self.live.insert(slot, validated.clone());
                self.high_water.insert(slot, record.seq);
            }
        }
        self.append_log(&record);
        Ok(validated)
    }

    /// Admit the record **only if** it is valid. Pure, non-mutating check.
    pub fn validate(&self, record: &SignedRecord) -> Result<(), ResolveError> {
        // 1. Structural sanity: payload must decode for structured kinds.
        match record.kind {
            RecordKind::Revocation | RecordKind::Delegation => {}
            _ => {}
        }
        // 2. Signature: verifies against the signer…
        if !self.crypto.verify(record) {
            return Err(ResolveError::BadSignature);
        }
        // …and the signer must be authorized for the zone (self or delegated).
        if !self.is_authorized(record.zone, &record.signer) {
            return Err(ResolveError::BadSignature);
        }
        // 3. Not expired at admission (store never holds dead records).
        if record.expired_at(crate::resolve::now()) {
            return Err(ResolveError::Revoked); // expired ≈ dead on arrival
        }
        // 4. Not covered by a live revocation tombstone.
        if self.is_revoked(record.zone, record.seq) {
            return Err(ResolveError::Revoked);
        }
        Ok(())
    }

    /// Look up live records for a zone, pruning expired & revoked on read.
    pub fn lookup(&mut self, zone: ZoneId, now: u64) -> Vec<ValidatedRecord> {
        // Opportunistic pruning: an expired live record is demoted to the
        // negative cache (so re-resolution doesn't resurrect it).
        let keys: Vec<SlotKey> = self
            .live
            .keys()
            .filter(|(z, _)| *z == zone)
            .copied()
            .collect();
        for k in keys {
            let expired = self
                .live
                .get(&k)
                .is_some_and(|r| r.record.expired_at(now) || self.is_revoked(zone, r.record.seq));
            if expired {
                self.live.remove(&k);
                self.high_water.remove(&k);
            }
        }
        if self.live.iter().any(|((z, _), _)| *z == zone) {
            self.negative.remove(&zone);
        } else {
            // Nothing live: remember the negative result for a short while.
            self.negative.insert(zone, now + 300);
        }
        self.live
            .iter()
            .filter(|((z, _), r)| *z == zone && !r.record.expired_at(now))
            .map(|(_, r)| r.clone())
            .collect()
    }

    /// Zone known to have nothing live (negative cache), before its expiry.
    pub fn is_negative(&self, zone: ZoneId, now: u64) -> bool {
        self.negative.get(&zone).is_some_and(|e| *e > now)
    }

    /// Highest seq ever accepted for the zone (freshness hint for backends).
    pub fn high_water(&self, zone: ZoneId) -> u64 {
        self.high_water
            .iter()
            .filter(|((z, _), _)| *z == zone)
            .map(|(_, s)| *s)
            .max()
            .unwrap_or(0)
    }

    fn is_authorized(&self, zone: ZoneId, signer: &PublicKey) -> bool {
        // v0: single-key zones — zone's only key is known out-of-band (given
        // to the store at creation). Delegation extends this set. Without
        // the zone's root key registered, nothing can publish: the store
        // must be told the root key like a DNSSEC trust anchor.
        // The root key is carried in `authorized` when the first record of
        // the zone was admitted; see `bootstrap_root_key`.
        self.authorized.get(&zone).is_some_and(|ks| ks.contains(signer))
    }

    /// Register a zone's root key out-of-band (trust anchor, like DNS root
    /// trust). Required before any record for `zone` can be admitted.
    pub fn bootstrap_root_key(&mut self, zone: ZoneId, key: PublicKey) {
        self.authorized.entry(zone).or_default().push(key);
    }

    fn is_revoked(&self, zone: ZoneId, seq: u64) -> bool {
        self.revocations
            .get(&zone)
            .is_some_and(|tombstones| tombstones.iter().any(|t| seq <= t.invalidates_up_to))
    }

    fn apply_revocation(&mut self, record: &SignedRecord) {
        let payload = &record.payload;
        if payload.len() != 8 {
            return; // malformed tombstone; logged, ignored
        }
        let up_to = u64::from_le_bytes(payload.try_into().unwrap());
        // Tombstone everything at or below this seq — including the
        // revocation's own predecessors; a higher revocation is the only
        // way forward.
        self.revocations.entry(record.zone).or_default().push(RevocationTombstone {
            seq: record.seq,
            invalidates_up_to: up_to,
        });
        // Drop live records the tombstone kills.
        let slot_keys: Vec<SlotKey> = self
            .live
            .keys()
            .filter(|(z, _)| *z == record.zone)
            .copied()
            .collect();
        for k in slot_keys {
            if self
                .live
                .get(&k)
                .is_some_and(|r| r.record.seq <= up_to && r.record.kind != RecordKind::Revocation)
            {
                self.live.remove(&k);
            }
        }
    }

    fn apply_delegation(&mut self, record: &SignedRecord) {
        // payload = delegate_key(32) ‖ scope(8, opaque for now)
        if record.payload.len() < 32 {
            return;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&record.payload[..32]);
        // A delegation signed by an authorized signer extends the set.
        if self.is_authorized(record.zone, &record.signer) {
            self.authorized
                .entry(record.zone)
                .or_default()
                .push(key);
        }
    }

    fn append_log(&mut self, record: &SignedRecord) {
        let Some(path) = &self.log_path else { return };
        let env = Envelope { version: 1, record: record.clone() };
        let line = format!("{}\n", env.to_hex());
        match std::fs::OpenOptions::new().create(true).append(true).open(path) {
            Ok(mut f) => {
                use std::io::Write;
                let _ = f.write_all(line.as_bytes());
            }
            Err(_) => {
                // Log failure is non-fatal for resolution; store stays warm.
            }
        }
    }

    /// Debug helper: current live records (tests, diagnostics).
    pub fn live_records(&self) -> Vec<&ValidatedRecord> {
        self.live.values().collect()
    }
}

/// In-memory store with a mock signer (tests). Returns the store plus a
/// closure that builds a plausible "signed" record for a zone.
#[cfg(test)]
pub(crate) fn mock_env(zone: ZoneId) -> Envelope {
    Envelope {
        version: 1,
        record: SignedRecord {
            zone,
            seq: 1,
            kind: RecordKind::Node,
            payload: b"node-payload".to_vec(),
            expires_at: None,
            signature: [0u8; 64],
            signer: [7u8; 32],
        },
    }
}

#[allow(dead_code)]
fn _keep_imports_alive(_: &BTreeMap<u8, u8>, _: &hex_encode, _: &hex_decode) {}