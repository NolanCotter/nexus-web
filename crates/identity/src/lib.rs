//! Ed25519 site identities and signed resource records.
//!
//! A site owns a keypair. Its identity is the 32-byte public key
//! (rendered as lowercase hex). Records bind (site, path) -> content hash
//! with expiry, signed by the site key. Verifiers check signature + expiry.
//!
//! # Signature domain separation (M3)
//!
//! New signatures (v1) are produced over the tagged message
//! `"nexus/v1/record"\0 || canonical_bytes()`; legacy v0 signatures are over
//! bare `canonical_bytes()`. `verify_record` accepts both: it tries v1 first,
//! then falls back to v0. Cross-verification is impossible by construction —
//! Ed25519 binds a signature to the exact message, the two messages differ by
//! the tag prefix, so a v1 signature cannot verify against the v0 message and
//! vice versa. `canonical_bytes()` itself is frozen (resolver/vectors depend
//! on it); versioning lives entirely in the signed message, so a signature
//! self-describes its version.

mod keyfile;
mod rotation;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use rotation::{RotationEntry, RotationLog};

/// Domain-separation tag for record signatures, version 1.
pub const SIG_V1_TAG: &[u8] = b"nexus/v1/record";

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("bad key length: expected 32 bytes, got {0}")]
    BadKeyLen(usize),
    #[error("bad signature: {0}")]
    BadSignature(String),
    #[error("record expired at {0} (now {1})")]
    Expired(u64, u64),
    #[error("site mismatch: record claims {0}, expected {1}")]
    SiteMismatch(String, String),
    #[error("serialization: {0}")]
    Serialization(String),
    #[error("key file: {0}")]
    KeyFile(String),
    #[error("insecure key file permissions (0o{0:o}); expected 0600 or stricter")]
    InsecureKeyPerms(u32),
    #[error("rotation chain broken: {0}")]
    BrokenChain(String),
}

/// A site identity: an Ed25519 keypair (secret kept locally) or pubkey only.
#[derive(Debug, Clone)]
pub struct SiteIdentity {
    pub signing: Option<SigningKey>,
    pub verify: VerifyingKey,
}

impl SiteIdentity {
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        let signing = SigningKey::generate(&mut OsRng);
        let verify = signing.verifying_key();
        Self {
            signing: Some(signing),
            verify,
        }
    }

    pub fn from_secret_bytes(secret: &[u8]) -> Result<Self, IdentityError> {
        if secret.len() != 32 {
            return Err(IdentityError::BadKeyLen(secret.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(secret);
        let signing = SigningKey::from_bytes(&arr);
        let verify = signing.verifying_key();
        Ok(Self {
            signing: Some(signing),
            verify,
        })
    }

    pub fn from_public_bytes(public: &[u8]) -> Result<Self, IdentityError> {
        if public.len() != 32 {
            return Err(IdentityError::BadKeyLen(public.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(public);
        let verify = VerifyingKey::from_bytes(&arr)
            .map_err(|e| IdentityError::BadSignature(e.to_string()))?;
        Ok(Self {
            signing: None,
            verify,
        })
    }

    /// Lowercase hex of the 32-byte public key. This is the canonical site ID.
    pub fn site_id(&self) -> String {
        hex::encode(self.verify.as_bytes())
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.verify.to_bytes()
    }

    /// Sign a resource record for (path -> content_hash) with expiry.
    ///
    /// Emits a **v1** signature: over `SIG_V1_TAG\0 || canonical_bytes()`.
    /// `verify_record` still accepts legacy v0 (untagged) signatures.
    pub fn sign_record(
        &self,
        path: &str,
        content_hash: &str,
        expires_at_unix: u64,
    ) -> Result<SignedRecord, IdentityError> {
        let signing = self
            .signing
            .as_ref()
            .ok_or_else(|| IdentityError::BadSignature("no secret key".into()))?;
        let record = ResourceRecord {
            site: self.site_id(),
            path: path.to_string(),
            content_hash: content_hash.to_string(),
            expires_at_unix,
        };
        let bytes = record.canonical_bytes_v1();
        let sig = signing.sign(&bytes);
        Ok(SignedRecord {
            record,
            signature_hex: hex::encode(sig.to_bytes()),
        })
    }

    /// Verify a signed record against this identity's public key.
    ///
    /// Accepts both v0 (bare `canonical_bytes()`) and v1
    /// (`SIG_V1_TAG\0 || canonical_bytes()`) signatures. v1 is tried first.
    pub fn verify_record(&self, signed: &SignedRecord, now_unix: u64) -> Result<(), IdentityError> {
        self.check_meta(signed, now_unix)?;
        match self.verify_v1(signed) {
            Ok(()) => Ok(()),
            Err(_) => self.verify_v0(signed),
        }
    }

    /// Strict v1-only check. Fails on legacy v0 signatures (cross-reject).
    fn verify_v1(&self, signed: &SignedRecord) -> Result<(), IdentityError> {
        let sig = decode_signature(&signed.signature_hex)?;
        self.verify
            .verify_strict(&signed.record.canonical_bytes_v1(), &sig)
            .map_err(|e| IdentityError::BadSignature(e.to_string()))
    }

    /// Strict v0-only check. Fails on v1 signatures (cross-reject).
    fn verify_v0(&self, signed: &SignedRecord) -> Result<(), IdentityError> {
        let sig = decode_signature(&signed.signature_hex)?;
        self.verify
            .verify_strict(&signed.record.canonical_bytes(), &sig)
            .map_err(|e| IdentityError::BadSignature(e.to_string()))
    }

    /// Site match + expiry, shared by every verify path.
    fn check_meta(&self, signed: &SignedRecord, now_unix: u64) -> Result<(), IdentityError> {
        if signed.record.site != self.site_id() {
            return Err(IdentityError::SiteMismatch(
                signed.record.site.clone(),
                self.site_id(),
            ));
        }
        if signed.record.expires_at_unix <= now_unix {
            return Err(IdentityError::Expired(
                signed.record.expires_at_unix,
                now_unix,
            ));
        }
        Ok(())
    }
}

fn decode_signature(signature_hex: &str) -> Result<Signature, IdentityError> {
    let sig_bytes =
        hex::decode(signature_hex).map_err(|e| IdentityError::BadSignature(e.to_string()))?;
    if sig_bytes.len() != 64 {
        return Err(IdentityError::BadSignature(format!(
            "expected 64 bytes, got {}",
            sig_bytes.len()
        )));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    Ok(Signature::from_bytes(&arr))
}

/// The signed payload. Field order is fixed for canonical bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceRecord {
    pub site: String,
    pub path: String,
    pub content_hash: String,
    pub expires_at_unix: u64,
}

impl ResourceRecord {
    /// Frozen v0 canonical form: `site\0path\0content_hash\0expires`.
    /// Do not change — deployed vectors and `nexus-resolver` depend on it.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.site.as_bytes());
        out.push(0);
        out.extend_from_slice(self.path.as_bytes());
        out.push(0);
        out.extend_from_slice(self.content_hash.as_bytes());
        out.push(0);
        out.extend_from_slice(self.expires_at_unix.to_string().as_bytes());
        out
    }

    /// v1 signed message: `SIG_V1_TAG\0 || canonical_bytes()`.
    pub fn canonical_bytes_v1(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIG_V1_TAG.len() + 1 + self.canonical_bytes().len());
        out.extend_from_slice(SIG_V1_TAG);
        out.push(0);
        out.extend_from_slice(&self.canonical_bytes());
        out
    }
}

/// The signed payload envelope. Signature self-describes its version: v1
/// verifies against `canonical_bytes_v1()`, v0 against `canonical_bytes()`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedRecord {
    pub record: ResourceRecord,
    pub signature_hex: String,
}

/// Delegation: site A authorizes key B to sign for a path prefix until expiry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Delegation {
    pub site: String,
    pub delegate_pub_hex: String,
    pub path_prefix: String,
    pub expires_at_unix: u64,
    pub signature_hex: String,
}

impl Delegation {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for part in [
            &self.site,
            &self.delegate_pub_hex,
            &self.path_prefix,
            &self.expires_at_unix.to_string(),
        ] {
            out.extend_from_slice(part.as_bytes());
            out.push(0);
        }
        out.pop();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_emits_v1_tagged_signature() {
        let id = SiteIdentity::generate();
        let sr = id.sign_record("home", "b3:abc123", 9_999_999_999).unwrap();
        let expected = sr.record.canonical_bytes_v1();
        assert_eq!(expected, {
            let mut v = Vec::new();
            v.extend_from_slice(SIG_V1_TAG);
            v.push(0);
            v.extend_from_slice(&sr.record.canonical_bytes());
            v
        });
        // v1 signature must NOT verify against the untagged v0 message.
        assert!(id.verify_v0(&sr).is_err());
        // ... but the combined verifier accepts it.
        id.verify_record(&sr, 1_000_000).unwrap();
    }

    #[test]
    fn verify_accepts_legacy_v0_signature() {
        let id = SiteIdentity::generate();
        let record = ResourceRecord {
            site: id.site_id(),
            path: "home".into(),
            content_hash: "b3:abc123".into(),
            expires_at_unix: 9_999_999_999,
        };
        // Legacy signer: bare canonical bytes, no tag.
        let sig = id.signing.as_ref().unwrap().sign(&record.canonical_bytes());
        let sr = SignedRecord {
            record,
            signature_hex: hex::encode(sig.to_bytes()),
        };
        id.verify_record(&sr, 1_000_000).unwrap();
        // Cross-reject: legacy signature must NOT verify against v1 message.
        assert!(id.verify_v1(&sr).is_err());
    }

    #[test]
    fn sign_verify_roundtrip() {
        let id = SiteIdentity::generate();
        let sr = id.sign_record("home", "b3:abc123", 9_999_999_999).unwrap();
        id.verify_record(&sr, 1_000_000).unwrap();
    }

    #[test]
    fn rejects_tampered_content() {
        let id = SiteIdentity::generate();
        let mut sr = id.sign_record("home", "b3:abc", 9_999_999_999).unwrap();
        sr.record.content_hash = "b3:evil".into();
        assert!(id.verify_record(&sr, 1_000).is_err());
    }

    #[test]
    fn rejects_expired() {
        let id = SiteIdentity::generate();
        let sr = id.sign_record("home", "b3:abc", 100).unwrap();
        assert!(matches!(
            id.verify_record(&sr, 200),
            Err(IdentityError::Expired(100, 200))
        ));
    }

    #[test]
    fn rejects_wrong_key() {
        let a = SiteIdentity::generate();
        let b = SiteIdentity::generate();
        let sr = a.sign_record("home", "b3:abc", 9_999_999_999).unwrap();
        assert!(b.verify_record(&sr, 1).is_err());
    }

    #[test]
    fn public_only_verifies() {
        let a = SiteIdentity::generate();
        let sr = a.sign_record("home", "b3:abc", 9_999_999_999).unwrap();
        let pub_only = SiteIdentity::from_public_bytes(&a.public_bytes()).unwrap();
        pub_only.verify_record(&sr, 1).unwrap();
    }

    #[test]
    fn site_id_is_hex_64() {
        let id = SiteIdentity::generate();
        let sid = id.site_id();
        assert_eq!(sid.len(), 64);
        assert!(sid.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(sid, sid.to_lowercase());
    }
}
