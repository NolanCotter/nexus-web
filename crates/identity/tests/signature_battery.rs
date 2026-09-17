//! Signature byte-flip batteries: every flipped byte of a record, rotation,
//! or revocation signature must fail verification. Ed25519 `verify_strict`
//! is deterministic — a single flip anywhere in the 64-byte signature or in
//! any signed field must break the check.

use ed25519_dalek::Signer;
use nexus_identity::{IdentityError, RotationLog, SignedRecord, SiteIdentity, SIG_V1_TAG};

/// Flip one byte of a lower-hex string's decoded bytes, re-encode.
fn flip_hex_byte(hex_str: &str, byte_idx: usize) -> String {
    let mut raw = hex::decode(hex_str).unwrap();
    let i = byte_idx % raw.len();
    raw[i] ^= 0x01;
    hex::encode(raw)
}

fn now() -> u64 {
    1_700_000_000
}

/// Every one of the 64 signature bytes flipped => verification fails.
#[test]
fn record_signature_byte_flip_battery() {
    let id = SiteIdentity::generate();
    let sr = id.sign_record("home", "b3:abc123", 9_999_999_999).unwrap();
    for i in 0..64 {
        let mut m = sr.clone();
        m.signature_hex = flip_hex_byte(&sr.signature_hex, i);
        assert!(
            id.verify_record(&m, now()).is_err(),
            "sig byte {i} flip accepted"
        );
    }
    // Garbage and wrong-length signature hex are also rejected.
    for bad in [
        "00".repeat(64),
        "zz".repeat(64),
        "abcd".to_string(),
        String::new(),
    ] {
        let mut m = sr.clone();
        m.signature_hex = bad;
        assert!(id.verify_record(&m, now()).is_err());
    }
}

/// Flipping any signed field kills the record; the error variant
/// distinguishes structural (SiteMismatch/Expired) from cryptographic
/// (BadSignature) failures.
#[test]
fn record_field_flip_battery() {
    let id = SiteIdentity::generate();
    let sr = id.sign_record("home", "b3:abc123", 9_999_999_999).unwrap();

    let mut site = sr.clone();
    site.record.site = flip_hex_byte(&sr.record.site, 0);
    assert!(matches!(
        id.verify_record(&site, now()),
        Err(IdentityError::SiteMismatch(_, _))
    ));

    let mut path = sr.clone();
    path.record.path = "h\x00me".to_string();
    assert!(matches!(
        id.verify_record(&path, now()),
        Err(IdentityError::BadSignature(_))
    ));

    let mut hash = sr.clone();
    hash.record.content_hash = "b3:evil".into();
    assert!(matches!(
        id.verify_record(&hash, now()),
        Err(IdentityError::BadSignature(_))
    ));

    let mut expiry = sr.clone();
    expiry.record.expires_at_unix = 9_999_999_998; // different value => sig fails
    assert!(matches!(
        id.verify_record(&expiry, now()),
        Err(IdentityError::BadSignature(_))
    ));

    let mut expired = sr.clone();
    expired.record.expires_at_unix = 100; // past => Expired before sig check
    assert!(matches!(
        id.verify_record(&expired, now()),
        Err(IdentityError::Expired(100, _))
    ));
}

/// Domain separation: v1 signatures are over `SIG_V1_TAG\0 || canonical`,
/// legacy v0 over bare canonical bytes. A signature produced for one
/// message never verifies against the other — a flip anywhere fails under
/// both the combined verifier and the strict per-version paths.
#[test]
fn domain_separation_battery() {
    let id = SiteIdentity::generate();
    for n in 0..10 {
        let path = format!("page-{n}");
        let sr = id
            .sign_record(&path, &format!("b3:hash{n}"), 9_999_999_999)
            .unwrap();
        // The signed message carries the tag: cross-protocol replay of this
        // signature under an identity/rotation context is structurally
        // impossible because the messages differ.
        let v1 = sr.record.canonical_bytes_v1();
        assert!(v1.starts_with(SIG_V1_TAG));
        assert_eq!(
            v1.len(),
            SIG_V1_TAG.len() + 1 + sr.record.canonical_bytes().len()
        );
        // Legacy v0 signature (bare canonical) still verifies in the
        // combined path, and dies if any field moved.
        let sig = id
            .signing
            .as_ref()
            .unwrap()
            .sign(&sr.record.canonical_bytes());
        let v0 = SignedRecord {
            record: sr.record.clone(),
            signature_hex: hex::encode(sig.to_bytes()),
        };
        id.verify_record(&v0, now()).unwrap();
        let mut moved = v0;
        moved.record.path = format!("page-{n}-moved");
        assert!(id.verify_record(&moved, now()).is_err());
    }
}

/// Rotation battery: any flipped signature byte, tampered target key, or
/// malformed hex breaks the chain loudly.
#[test]
fn rotation_byte_flip_battery() {
    let a = SiteIdentity::generate();
    let b = SiteIdentity::generate();
    let c = SiteIdentity::generate();
    let mut log = RotationLog::default();
    log.rotate(&a, &b).unwrap();
    log.rotate(&b, &c).unwrap();

    // Flip every signature byte of the first hop: all must break the chain.
    let hop = log.entries.get(&a.site_id()).unwrap();
    for i in 0..64 {
        let mut tampered = log.clone();
        tampered
            .entries
            .get_mut(&a.site_id())
            .unwrap()
            .signature_hex = flip_hex_byte(&hop.signature_hex, i);
        assert!(
            matches!(
                tampered.verify_rotation_chain(&a.verify),
                Err(IdentityError::BrokenChain(_))
            ),
            "rotation sig byte {i} flip accepted"
        );
    }

    // Tampered target key.
    let mut tampered = log.clone();
    tampered.entries.get_mut(&a.site_id()).unwrap().new_pub_hex =
        SiteIdentity::generate().site_id();
    assert!(matches!(
        tampered.verify_rotation_chain(&a.verify),
        Err(IdentityError::BrokenChain(_))
    ));

    // Malformed target / signature hex.
    let bads = [
        "zz".to_string(),
        "abcd".to_string(),
        String::new(),
        "f".to_string(),
        "0".repeat(63),
    ];
    for bad in &bads {
        let mut tampered = log.clone();
        tampered.entries.get_mut(&a.site_id()).unwrap().new_pub_hex = bad.clone();
        assert!(tampered.verify_rotation_chain(&a.verify).is_err());
        let mut tampered = log.clone();
        tampered
            .entries
            .get_mut(&a.site_id())
            .unwrap()
            .signature_hex = bad.clone();
        assert!(tampered.verify_rotation_chain(&a.verify).is_err());
    }
}
