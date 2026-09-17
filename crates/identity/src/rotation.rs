//! Key rotation chains (M3 enforcement).
//!
//! Each hop is `old_pub -> new_pub` attested by a signature from the **old**
//! key over the domain-separated binding
//! `"nexus/v1/rotation"\0 || old_hex\0new_hex`. `verify_rotation_chain`
//! walks the log from a trusted anchor and returns the current key, so a
//! verifier can upgrade its trust anchor by following attestations — and
//! nothing else. Any tampering (bad signature, edited target, cycle) breaks
//! the chain loudly.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::{IdentityError, SiteIdentity};

/// Domain-separation tag for rotation bindings (distinct from record tag).
pub const ROTATION_TAG: &[u8] = b"nexus/v1/rotation";

/// One rotation hop: the map key's owner attests `new_pub_hex`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotationEntry {
    pub new_pub_hex: String,
    pub signature_hex: String,
}

/// Key rotation log: `old site hex -> signed binding to replacement key`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RotationLog {
    pub entries: BTreeMap<String, RotationEntry>,
}

impl RotationLog {
    /// Tagged canonical bytes for an `old -> new` binding.
    pub fn canonical_binding(old_hex: &str, new_hex: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(ROTATION_TAG.len() + 1 + 64 + 1 + 64);
        out.extend_from_slice(ROTATION_TAG);
        out.push(0);
        out.extend_from_slice(old_hex.as_bytes());
        out.push(0);
        out.extend_from_slice(new_hex.as_bytes());
        out
    }

    /// Record an `old -> new` rotation: the old key signs the binding.
    /// Overwrites any prior hop from `old`.
    pub fn rotate(&mut self, old: &SiteIdentity, new: &SiteIdentity) -> Result<(), IdentityError> {
        let old_hex = old.site_id();
        let new_hex = new.site_id();
        let signer = old
            .signing
            .as_ref()
            .ok_or_else(|| IdentityError::KeyFile("cannot rotate from a public-only key".into()))?;
        let sig = signer.sign(&Self::canonical_binding(&old_hex, &new_hex));
        self.entries.insert(
            old_hex,
            RotationEntry {
                new_pub_hex: new_hex,
                signature_hex: hex::encode(sig.to_bytes()),
            },
        );
        Ok(())
    }

    /// Walk the chain starting at the trusted anchor `from`, verifying each
    /// hop under the *previous* key over `binding(prev, next)`. Returns the
    /// current (last) key. A key that never rotated is its own chain end.
    ///
    /// Broken chains (missing bytes, bad signature, tampered target, cycle)
    /// return `IdentityError::BrokenChain`.
    pub fn verify_rotation_chain(
        &self,
        from: &VerifyingKey,
    ) -> Result<VerifyingKey, IdentityError> {
        let mut current = *from;
        let mut current_hex = hex::encode(from.as_bytes());
        let mut seen = BTreeSet::new();
        loop {
            if !seen.insert(current_hex.clone()) {
                return Err(IdentityError::BrokenChain(format!(
                    "cycle detected at {current_hex}"
                )));
            }
            let Some(entry) = self.entries.get(&current_hex) else {
                return Ok(current);
            };
            let sig = decode_rotation_signature(&entry.signature_hex, &current_hex)?;
            let msg = Self::canonical_binding(&current_hex, &entry.new_pub_hex);
            current
                .verify_strict(&msg, &sig)
                .map_err(|e| IdentityError::BrokenChain(format!("hop {current_hex}: {e}")))?;
            current = parse_verifying_key(&entry.new_pub_hex, &current_hex)?;
            current_hex = entry.new_pub_hex.clone();
        }
    }
}

fn decode_rotation_signature(signature_hex: &str, hop: &str) -> Result<Signature, IdentityError> {
    let bytes = hex::decode(signature_hex)
        .map_err(|e| IdentityError::BrokenChain(format!("hop {hop}: {e}")))?;
    if bytes.len() != 64 {
        return Err(IdentityError::BrokenChain(format!(
            "hop {hop}: expected 64-byte signature, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    Ok(Signature::from_bytes(&arr))
}

fn parse_verifying_key(pub_hex: &str, hop: &str) -> Result<VerifyingKey, IdentityError> {
    let bytes =
        hex::decode(pub_hex).map_err(|e| IdentityError::BrokenChain(format!("hop {hop}: {e}")))?;
    if bytes.len() != 32 {
        return Err(IdentityError::BrokenChain(format!(
            "hop {hop}: expected 32-byte key, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| IdentityError::BrokenChain(format!("hop {hop}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_valid_three_key_chain() {
        let a = SiteIdentity::generate();
        let b = SiteIdentity::generate();
        let c = SiteIdentity::generate();
        let mut log = RotationLog::default();
        log.rotate(&a, &b).unwrap();
        log.rotate(&b, &c).unwrap();
        let end = {
            let k = log.verify_rotation_chain(&a.verify).unwrap();
            k.to_bytes()
        };
        assert_eq!(end, c.public_bytes());
    }

    #[test]
    fn unrotated_key_is_its_own_chain_end() {
        let a = SiteIdentity::generate();
        let log = RotationLog::default();
        assert_eq!(
            log.verify_rotation_chain(&a.verify).unwrap().to_bytes(),
            a.public_bytes()
        );
    }

    #[test]
    fn rejects_tampered_signature() {
        let a = SiteIdentity::generate();
        let b = SiteIdentity::generate();
        let mut log = RotationLog::default();
        log.rotate(&a, &b).unwrap();
        log.entries.get_mut(&a.site_id()).unwrap().signature_hex =
            format!("00{}", &log.entries[&a.site_id()].signature_hex[2..]);
        assert!(matches!(
            log.verify_rotation_chain(&a.verify),
            Err(IdentityError::BrokenChain(_))
        ));
    }

    #[test]
    fn rejects_tampered_target_key() {
        let a = SiteIdentity::generate();
        let b = SiteIdentity::generate();
        let mut log = RotationLog::default();
        log.rotate(&a, &b).unwrap();
        // Attacker rewrites the advertised target; signature no longer binds.
        log.entries.get_mut(&a.site_id()).unwrap().new_pub_hex = SiteIdentity::generate().site_id();
        assert!(matches!(
            log.verify_rotation_chain(&a.verify),
            Err(IdentityError::BrokenChain(_))
        ));
    }

    #[test]
    fn rejects_cycle() {
        let a = SiteIdentity::generate();
        let b = SiteIdentity::generate();
        let mut log = RotationLog::default();
        log.rotate(&a, &b).unwrap();
        log.rotate(&b, &a).unwrap();
        assert!(matches!(
            log.verify_rotation_chain(&a.verify),
            Err(IdentityError::BrokenChain(msg)) if msg.contains("cycle")
        ));
    }

    #[test]
    fn public_only_key_cannot_rotate() {
        let a = SiteIdentity::generate();
        let b = SiteIdentity::generate();
        let pub_only = SiteIdentity::from_public_bytes(&a.public_bytes()).unwrap();
        let mut log = RotationLog::default();
        assert!(log.rotate(&pub_only, &b).is_err());
        assert!(log.entries.is_empty());
    }
}
