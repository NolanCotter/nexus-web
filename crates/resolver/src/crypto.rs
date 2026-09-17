//! Crypto seam: signatures are the base layer of the whole trust model, but
//! the *data model* does not depend on any specific signature scheme.
//!
//! v0 ships a mock provider so the resolver builds and tests offline with
//! zero dependencies. The real implementation is a feature gate away
//! (`crypto-ed25519`); swapping providers must not change a single line
//! outside this module.

use crate::model::{PublicKey, SignedRecord};

/// Anything that can verify (and, for tests, produce) signatures.
pub trait CryptoProvider: Send + Sync {
    /// Verify a record's signature against `signer`. The record's
    /// `signed_bytes()` are the canonical signed payload.
    fn verify(&self, record: &SignedRecord) -> bool;

    /// Sign `signed_bytes` with `signer`'s private key. Only implemented by
    /// providers that hold private key material (mock does, for tests).
    fn sign(&self, signed_bytes: &[u8], signer: &PublicKey) -> Option<[u8; 64]>;
}

/// Test/demo provider: accepts any signature of the right shape.
///
/// # Safety
/// This is a **mock**. It authenticates nothing cryptographically. It exists
/// so the store/merge/conflict logic is testable offline before crypto is
/// wired. Never enable in a real node.
#[derive(Debug, Default)]
pub struct MockProvider;

impl CryptoProvider for MockProvider {
    fn verify(&self, _record: &SignedRecord) -> bool {
        true
    }

    fn sign(&self, _signed_bytes: &[u8], _signer: &PublicKey) -> Option<[u8; 64]> {
        Some([0u8; 64])
    }
}

/// Real ed25519 provider. Compiled only with the `crypto-ed25519` feature;
/// body is intentionally thin — the seam is the point.
///
/// ```ignore
/// #[cfg(feature = "crypto-ed25519")]
/// pub struct Ed25519Provider { /* ed25519-dalek::SigningKey */ }
///
/// #[cfg(feature = "crypto-ed25519")]
/// impl CryptoProvider for Ed25519Provider {
///     fn verify(&self, record: &SignedRecord) -> bool {
///         // verify(record.signature, &record.signer, &record.signed_bytes())
///     }
///     fn sign(&self, bytes: &[u8], signer: &PublicKey) -> Option<[u8; 64]> {
///         // sign 64 bytes with the key identified by `signer`
///     }
/// }
/// ```
#[cfg(feature = "crypto-ed25519")]
pub struct Ed25519Provider; // placeholder — wire to ed25519-dalek on demand

#[cfg(feature = "crypto-ed25519")]
impl CryptoProvider for Ed25519Provider {
    fn verify(&self, _record: &SignedRecord) -> bool {
        // TODO(006): ed25519_dalek::Verifier
        false
    }

    fn sign(&self, _signed_bytes: &[u8], _signer: &PublicKey) -> Option<[u8; 64]> {
        None
    }
}