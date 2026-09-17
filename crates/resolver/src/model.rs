//! Core data model: the signed-record envelope and the resolution chain.
//!
//! The single most important property of this module: **the model is the
//! contract**. Every backend — disk, federated resolver, gossip, DHT —
//! moves these exact bytes and applies these exact merge rules. Nothing in
//! this file knows what a network is.

/// Identifier for a name-zone: `blake3(name_bytes)`.
///
/// Names are normalized (NFKC, lowercase, punycode) at the *registration*
/// layer *before* they are hashed; the resolver treats zone ids as opaque
/// bytes and never re-derives them from raw untrusted name strings.
pub type ZoneId = [u8; 32];

/// Anchor of trust: `blake3(public_key_bytes)`.
///
/// Records are not trusted because of *where* they came from (backend) but
/// because they verify against the identity that owns this zone.
pub type IdentityId = [u8; 32];

/// Public key bytes (ed25519 in the real impl; raw bytes here).
pub type PublicKey = [u8; 32];

/// Signature bytes (64 for ed25519).
pub type Signature = [u8; 64];

/// What a record actually is. The discriminant is stable wire data: the
/// future DHT key is derived from it, so these values are frozen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum RecordKind {
    /// `payload` = serialized [`NodeAddr`] list: how to reach the zone's machines.
    Node = 1,
    /// Named service endpoint ("http", "gemini", "mail"…), payload = opaque.
    Service = 2,
    /// Content id (content hash) for a path, payload = opaque.
    Content = 3,
    /// `payload` = name bytes: this zone is an alias pointer (chase on resolve).
    Alias = 4,
    /// `payload` = `(delegate_key, scope)`; expands the set of keys accepted
    /// for this zone (sub-keys, key rotation).
    Delegation = 5,
    /// `payload` = `(invalidates_up_to: u64)`; tombstones all records of this
    /// zone with `seq <= invalidates_up_to`. Revocations cannot be undone by
    /// resurrecting an older record.
    Revocation = 6,
}

impl RecordKind {
    /// Stable wire discriminant. Used by the DHT key derivation contract:
    /// `blake3(zone ‖ 0x00 ‖ kind_discriminant)`.
    pub fn discriminant(self) -> u8 {
        self as u8
    }
}

/// One self-authenticating statement by a zone's identity.
///
/// Signature covers `zone ‖ seq ‖ kind ‖ payload ‖ expires_at` (all as
/// little-endian/raw bytes). The envelope version lives in [`Envelope`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRecord {
    /// Owning zone (name anchor), opaque bytes.
    pub zone: ZoneId,
    /// Strictly monotonic per `(zone, kind)`. Higher seq wins on merge.
    pub seq: u64,
    /// Record family; frozen discriminant (see [`RecordKind`]).
    pub kind: RecordKind,
    /// Kind-specific payload (see [`RecordKind`] docs).
    pub payload: Vec<u8>,
    /// Absolute expiry as unix seconds; `None` = never expires.
    pub expires_at: Option<u64>,
    /// Signature over the above fields, by a key authorized for this zone.
    pub signature: Signature,
    /// Which key signed it (for delegation-chain auditing).
    pub signer: PublicKey,
}

impl SignedRecord {
    /// Bytes that must be signed/verified, in a canonical order.
    ///
    /// The boundary between this and [`Envelope::to_wire`] is deliberate:
    /// the wire format may gain framing/versioning, but the *signed payload*
    /// is the identity's statement and must be stable forever.
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 8 + 1 + self.payload.len() + 8 + 8);
        out.extend_from_slice(&self.zone);
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.push(self.kind.discriminant());
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&self.expires_at.unwrap_or(u64::MAX).to_le_bytes());
        out.extend_from_slice(&self.signer);
        out
    }

    /// Is this record past its expiry, given `now` (unix seconds)?
    pub fn expired_at(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|e| e < now)
    }
}

/// A record that passed full validation (signature + envelope + policy).
///
/// Only `ValidatedRecord`s are admitted to stores and forwarded to backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedRecord {
    /// The underlying record.
    pub record: SignedRecord,
    /// Identity that anchors this zone, if derivable from the signer chain.
    pub identity: IdentityId,
}

/// One node behind a zone: a transport address plus the roles it plays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeAddr {
    /// Which protocol family this address speaks.
    pub transport: Transport,
    /// Raw multiaddr-style bytes (`/ip4/…/tcp/…`, `.onion`, `.i2p`, …).
    pub multiaddr: Vec<u8>,
    /// What this node is willing/able to do.
    pub roles: Vec<Role>,
}

/// Transport families the resolver understands. Unknown future transports
/// are carried as opaque multiaddr bytes; an unknown-to-*us* address is
/// still a valid record (forward compatibility).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Transport {
    Tcp = 1,
    Quic = 2,
    Tor = 3,
    I2p = 4,
    Relay = 5,
    Other = 0xff,
}

/// Functional roles a node can announce for a zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    /// Serves resolution queries for this zone (a zone-run resolver).
    Resolver = 1,
    /// Relays traffic (NAT traversal assist).
    Relay = 2,
    /// Stores/replicates records for offline availability.
    Storage = 3,
    /// Serves content (web/gemini).
    Gateway = 4,
}

/// Versioned on-wire envelope. Version 1 is the current record framing;
/// the envelope may gain versions without touching [`SignedRecord`] itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Framing version. `1` at v0.
    pub version: u8,
    /// The signed record this envelope carries.
    pub record: SignedRecord,
}

impl Envelope {
    /// Serialize to a line-safe text form (`version:hex(payload)`).
    ///
    /// Chosen over bincode/postcard at v0 to keep the crate dependency-free
    /// and the fixture files human-inspectable in tests/debug. The on-wire
    /// binary codec is owned by `crates/protocol`; this is the canonical
    /// *byte form* records are stored and exchanged in.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.version);
        // Payload layout: zone(32) seq(8) kind(1) payload_len(8) payload
        // expires(8) signer(32) signature(64)
        out.extend_from_slice(&self.record.zone);
        out.extend_from_slice(&self.record.seq.to_le_bytes());
        out.push(self.record.kind.discriminant());
        out.extend_from_slice(&(self.record.payload.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.record.payload);
        out.extend_from_slice(&self.record.expires_at.unwrap_or(u64::MAX).to_le_bytes());
        out.extend_from_slice(&self.record.signer);
        out.extend_from_slice(&self.record.signature);
        out
    }

    /// Parse the canonical wire form produced by [`Envelope::to_wire`].
    pub fn from_wire(bytes: &[u8]) -> Result<Self, ResolveError> {
        if bytes.len() < 1 + 32 + 8 + 1 + 8 + 8 + 32 + 64 {
            return Err(ResolveError::Malformed);
        }
        let mut off = 0usize;
        let version = bytes[off];
        off += 1;
        if version != 1 {
            return Err(ResolveError::UnsupportedVersion(version));
        }
        let mut zone = [0u8; 32];
        zone.copy_from_slice(&bytes[off..off + 32]);
        off += 32;
        let seq = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
        off += 8;
        let kind = match bytes[off] {
            1 => RecordKind::Node,
            2 => RecordKind::Service,
            3 => RecordKind::Content,
            4 => RecordKind::Alias,
            5 => RecordKind::Delegation,
            6 => RecordKind::Revocation,
            k => return Err(ResolveError::UnknownKind(k)),
        };
        off += 1;
        let payload_len = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap()) as usize;
        off += 8;
        if bytes[off..].len() < payload_len + 8 + 32 + 64 {
            return Err(ResolveError::Malformed);
        }
        let payload = bytes[off..off + payload_len].to_vec();
        off += payload_len;
        let expires_raw = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
        off += 8;
        let expires_at = (expires_raw != u64::MAX).then_some(expires_raw);
        let mut signer = [0u8; 32];
        signer.copy_from_slice(&bytes[off..off + 32]);
        off += 32;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[off..off + 64]);
        Ok(Envelope {
            version,
            record: SignedRecord {
                zone,
                seq,
                kind,
                payload,
                expires_at,
                signature,
                signer,
            },
        })
    }

    /// Hex form used by the store's JSONL-style log (one envelope per line).
    pub fn to_hex(&self) -> String {
        hex_encode(&self.to_wire())
    }

    /// Parse from the hex form produced by [`Envelope::to_hex`].
    pub fn from_hex(s: &str) -> Result<Self, ResolveError> {
        Self::from_wire(&hex_decode(s)?)
    }
}

/// Result of a successful resolution: the live record set for a zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// Zone that answered.
    pub zone: ZoneId,
    /// Live (non-expired, non-revoked) node addresses.
    pub nodes: Vec<NodeAddr>,
    /// Live service endpoints (kind=Service), raw payloads.
    pub services: Vec<Vec<u8>>,
    /// Live content ids (kind=Content).
    pub contents: Vec<Vec<u8>>,
    /// Alias target, if the zone is an alias.
    pub alias: Option<Vec<u8>>,
    /// Identity anchoring this zone.
    pub identity: IdentityId,
    /// Highest sequence number observed for the zone (audit/freshness).
    pub max_seq: u64,
    /// Whether this answer came purely from local/offline data.
    pub from_cache: bool,
}

/// Errors the resolver can produce. Deliberately small; the resolver never
/// leaks backend internals into application error space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// Unknown name: no zone, or nothing live for it (negative cache hit).
    NotFound,
    /// A record or envelope failed structural decoding.
    Malformed,
    /// Envelope version we do not speak.
    UnsupportedVersion(u8),
    /// Record kind discriminant we do not know.
    UnknownKind(u8),
    /// Signature did not verify against any authorized key for the zone.
    BadSignature,
    /// Record seq not strictly newer for its (zone, kind).
    StaleSequence,
    /// Record overlaps a live revocation tombstone.
    Revoked,
    /// All backends were queried and none answered within the policy window.
    Timeout,
    /// Backend/transport-level failure, message for logs only.
    Backend(String),
}

/// <3 free functions for hex, kept local to avoid a dependency.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

pub(crate) fn hex_decode(s: &str) -> Result<Vec<u8>, ResolveError> {
    if s.len() % 2 != 0 {
        return Err(ResolveError::Malformed);
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16).ok_or(ResolveError::Malformed)?;
        let lo = (pair[1] as char).to_digit(16).ok_or(ResolveError::Malformed)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}