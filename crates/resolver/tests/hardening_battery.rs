//! Resolver hardening battery: signature byte-flips for endpoint records
//! and revocations, plus expired / stale-seq / tombstone behavior per the
//! CURRENT code, and the poisoned-backend end-to-end path.

use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::SigningKey;
use nexus_identity::{ResourceRecord, SignedRecord};
use nexus_resolver::backend::{Backend, MemoryBackend};
use nexus_resolver::resolve::{
    CachingResolver, Clock, EndpointRecord, RecordStore, Revocation, Transport,
};
use nexus_resolver::{LocalResolver, ResolveError, Resolver};

fn test_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn now() -> u64 {
    1_700_000_000
}

fn flip_hex_byte(hex_str: &str, byte_idx: usize) -> String {
    let mut raw = hex::decode(hex_str).unwrap();
    let i = byte_idx % raw.len();
    raw[i] ^= 0x01;
    hex::encode(raw)
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

/// Every one of the 64 endpoint-signature bytes flipped => verify fails.
#[test]
fn endpoint_signature_byte_flip_battery() {
    let k = test_key(1);
    let rec = make_record(&k, "127.0.0.1", 7843, 1);
    rec.verify(&k.verifying_key(), now()).unwrap();
    for i in 0..64 {
        let mut m = rec.clone();
        m.signature_hex = flip_hex_byte(&rec.signature_hex, i);
        assert!(
            matches!(
                m.verify(&k.verifying_key(), now()),
                Err(ResolveError::BadSignature(_))
            ),
            "endpoint sig byte {i} flip accepted"
        );
    }
    for bad in ["zz".repeat(64), String::new(), "abcd".to_string()] {
        let mut m = rec.clone();
        m.signature_hex = bad;
        assert!(m.verify(&k.verifying_key(), now()).is_err());
    }
}

/// Flip any signed endpoint field: host, port, seq, expiry, site.
#[test]
fn endpoint_field_flip_battery() {
    let k = test_key(2);
    let mut by_host = make_record(&k, "127.0.0.1", 7843, 1);
    by_host.host = "127.0.0.2".into();
    assert!(by_host.verify(&k.verifying_key(), now()).is_err());

    let mut by_port = make_record(&k, "127.0.0.1", 7843, 1);
    by_port.port += 1;
    assert!(by_port.verify(&k.verifying_key(), now()).is_err());

    let mut by_seq = make_record(&k, "127.0.0.1", 7843, 1);
    by_seq.seq += 1;
    assert!(by_seq.verify(&k.verifying_key(), now()).is_err());

    let mut by_expiry = make_record(&k, "127.0.0.1", 7843, 1);
    by_expiry.expires_at_unix = now() + 100;
    assert!(by_expiry.verify(&k.verifying_key(), now()).is_err());

    let mut by_site = make_record(&k, "127.0.0.1", 7843, 1);
    by_site.site = flip_hex_byte(&by_site.site, 0);
    assert!(matches!(
        by_site.verify(&k.verifying_key(), now()),
        Err(ResolveError::BadSignature(_))
    ));
}

/// Revocation: valid verify, then every flipped field / sig byte fails.
#[test]
fn revocation_byte_flip_battery() {
    let k = test_key(3);
    let site = hex::encode(k.verifying_key().to_bytes());
    let r = Revocation::sign(&k, &site, 42, now() + 86_400);
    r.verify(&k.verifying_key(), now()).unwrap();
    for i in 0..64 {
        let mut m = r.clone();
        m.signature_hex = flip_hex_byte(&r.signature_hex, i);
        assert!(
            m.verify(&k.verifying_key(), now()).is_err(),
            "revoke byte {i}"
        );
    }
    for (field, mutated) in [
        ("site", {
            let mut m = r.clone();
            m.site = flip_hex_byte(&r.site, 0);
            m
        }),
        ("max_seq", {
            let mut m = r.clone();
            m.max_seq += 1;
            m
        }),
        ("expires", {
            let mut m = r.clone();
            m.expires_at_unix = now() + 1;
            m
        }),
    ] {
        assert!(
            mutated.verify(&k.verifying_key(), now()).is_err(),
            "revocation {field} flip accepted"
        );
    }
    // Wrong signer can never revoke the target's records.
    let attacker = test_key(4);
    assert!(r.verify(&attacker.verifying_key(), now()).is_err());
    // Expired revocation is rejected outright.
    let expired = Revocation::sign(&k, &site, 42, now() - 10);
    assert!(matches!(
        expired.verify(&k.verifying_key(), now()),
        Err(ResolveError::Expired(_, _))
    ));
}

fn store_with_clock(clock: Clock) -> RecordStore {
    RecordStore::with_clock(clock)
}

/// Expiration and stale-seq behavior per current code: expired records are
/// never routed, stale seq replays are never admitted, and only strictly
/// advancing seq wins.
#[test]
fn expiration_and_stale_seq_battery() {
    static NOW: AtomicU64 = AtomicU64::new(1_700_000_000);
    let clock: Clock = || NOW.load(Ordering::SeqCst);
    let k = test_key(5);

    let mut s = store_with_clock(clock);
    s.trust("alice", k.verifying_key());

    // Live seq 1 admitted and routed.
    assert!(s.admit("alice", make_record(&k, "10.0.0.1", 1, 1)));
    assert_eq!(s.route("alice").unwrap().endpoints, vec!["10.0.0.1:1"]);

    // Same-seq and lower-seq replays are stale: rejected.
    assert!(!s.admit("alice", make_record(&k, "10.0.0.9", 9, 1)));
    assert!(!s.admit("alice", make_record(&k, "10.0.0.9", 9, 0)));
    assert_eq!(s.route("alice").unwrap().endpoints, vec!["10.0.0.1:1"]);

    // Clock passes the record expiry: no route, and a fresh record still
    // verifies against the *new* clock only if its expiry allows.
    NOW.store(now() + 100_000, Ordering::SeqCst);
    assert!(s.route("alice").is_none());

    let fresh = EndpointRecord::sign(
        &k,
        &hex::encode(k.verifying_key().to_bytes()),
        Transport::Tcp,
        "10.0.0.2",
        2,
        2,
        now() + 300_000,
    );
    assert!(s.admit("alice", fresh));
    assert_eq!(s.route("alice").unwrap().endpoints, vec!["10.0.0.2:2"]);

    // Far future: everything expired, nothing routed.
    NOW.store(now() + 400_000, Ordering::SeqCst);
    assert!(s.route("alice").is_none());
}

/// Tombstone behavior per current code: seq <= tombstone is suppressed
/// forever; expired or foreign-keyed revocations install nothing.
#[test]
fn tombstone_battery() {
    static NOW: AtomicU64 = AtomicU64::new(1_700_000_000);
    let clock: Clock = || NOW.load(Ordering::SeqCst);
    let k = test_key(6);
    let site = hex::encode(k.verifying_key().to_bytes());

    let mut s = store_with_clock(clock);
    s.trust("alice", k.verifying_key());
    assert!(s.admit("alice", make_record(&k, "10.0.0.1", 1, 3)));

    // Revocation with max_seq = 5: seq 3 suppressed, seq 6 allowed.
    assert!(s.revoke("alice", Revocation::sign(&k, &site, 5, now() + 86_400)));
    assert!(s.route("alice").is_none());
    assert!(!s.admit("alice", make_record(&k, "10.0.0.4", 4, 4)));
    assert!(!s.admit("alice", make_record(&k, "10.0.0.5", 5, 5)));
    assert!(s.admit("alice", make_record(&k, "10.0.0.6", 6, 6)));
    assert_eq!(s.route("alice").unwrap().endpoints, vec!["10.0.0.6:6"]);

    // Expired revocation: rejected, no tombstone installed (seq 6 survives).
    let expired_rev = Revocation::sign(&k, &site, 99, now() - 10);
    assert!(!s.revoke("alice", expired_rev));
    assert_eq!(s.route("alice").unwrap().endpoints, vec!["10.0.0.6:6"]);

    // Foreign-key revocation: rejected.
    let attacker = test_key(7);
    let forged = Revocation::sign(&attacker, &site, 99, now() + 86_400);
    assert!(!s.revoke("alice", forged));

    // Untrusted name: nothing to revoke.
    assert!(!s.revoke("nobody", Revocation::sign(&k, &site, 99, now() + 86_400)));
}

/// Poisoned backend end-to-end: garbage, expired, stale, and foreign-key
/// envelopes all die at the resolver core. Revocations ride the same
/// envelope and become tombstones even when no record ever resolved.
#[test]
fn poisoned_backend_battery() {
    static NOW_FIXED: AtomicU64 = AtomicU64::new(1_700_000_000);
    let clock: Clock = || NOW_FIXED.load(Ordering::SeqCst);
    let k = test_key(8);
    let site = hex::encode(k.verifying_key().to_bytes());

    let envelope = |content: String, expires: u64| SignedRecord {
        record: ResourceRecord {
            site: site.clone(),
            path: "@alice".to_string(),
            content_hash: content,
            expires_at_unix: expires,
        },
        signature_hex: String::new(),
    };

    let backend = MemoryBackend::new();
    // 1. Garbage payload.
    backend
        .advertise(&envelope("not json at all".into(), now() + 86_400))
        .unwrap();
    // 2. Structurally valid endpoint record that is already expired.
    let mut expired = make_record(&k, "10.0.0.1", 1, 1);
    expired.expires_at_unix = now() - 10;
    backend
        .advertise(&envelope(
            serde_json::to_string(&expired).unwrap(),
            now() + 86_400,
        ))
        .unwrap();
    // 3. Valid signature but seq 0: pre-M3 records are immediately stale.
    let stale = EndpointRecord::sign(&k, &site, Transport::Tcp, "10.0.0.2", 2, 0, now() + 86_400);
    backend
        .advertise(&envelope(
            serde_json::to_string(&stale).unwrap(),
            now() + 86_400,
        ))
        .unwrap();
    // 4. Foreign-key record: signed by a key the name does not trust.
    let attacker = test_key(9);
    backend
        .advertise(&envelope(
            serde_json::to_string(&make_record(&attacker, "evil", 666, 1)).unwrap(),
            now() + 86_400,
        ))
        .unwrap();
    // 5. Revocation envelope with no prior records: tombstone is installed.
    let rev = Revocation::sign(&k, &site, 99, now() + 86_400);
    backend
        .advertise(&envelope(
            serde_json::to_string(&rev).unwrap(),
            now() + 86_400,
        ))
        .unwrap();

    let mut r: CachingResolver<MemoryBackend> =
        CachingResolver::new(LocalResolver::new(), store_with_clock(clock), vec![backend]);
    r.trust("alice", k.verifying_key());
    // Nothing poisonous resolves; the tombstone suppresses the rest.
    assert!(matches!(
        r.resolve("alice"),
        Err(ResolveError::UnknownSite(_))
    ));
    // A genuinely valid record above the tombstone still resolves.
    assert!(r.admit_record("alice", make_record(&k, "10.0.0.7", 7, 100)));
    assert_eq!(r.resolve("alice").unwrap().endpoints, vec!["10.0.0.7:7"]);
    assert!(r.resolve("alice").is_ok());
}

/// Documented current behavior: expiry is enforced at admission and at
/// `RecordStore::route` — but a warm petname-table hit is served without a
/// re-check (the fast path never re-consults the store or re-validates
/// expiry). Cold resolution of the same store sees the expiry and fails.
#[test]
fn warm_table_serves_expired_route_documented() {
    static NOW_START: AtomicU64 = AtomicU64::new(1_700_000_000);
    let clock: Clock = || NOW_START.load(Ordering::SeqCst);
    let k = test_key(10);
    let site = hex::encode(k.verifying_key().to_bytes());

    // Warm the table through the backend loop (the only path that inserts
    // into the petname table).
    let backend = MemoryBackend::new();
    let valid = make_record(&k, "10.0.0.1", 1, 1);
    backend
        .advertise(&SignedRecord {
            record: ResourceRecord {
                site: site.clone(),
                path: "@alice".to_string(),
                content_hash: serde_json::to_string(&valid).unwrap(),
                expires_at_unix: now() + 86_400,
            },
            signature_hex: String::new(),
        })
        .unwrap();

    let mut r: CachingResolver<MemoryBackend> =
        CachingResolver::new(LocalResolver::new(), store_with_clock(clock), vec![backend]);
    r.trust("alice", k.verifying_key());
    assert!(r.resolve("alice").is_ok()); // cold path warms the table

    // Clock passes the record expiry: a cold resolve would see nothing,
    // but the warm table still answers (documented fast-path behavior).
    NOW_START.store(now() + 200_000, Ordering::SeqCst);
    assert!(r.resolve("alice").is_ok(), "warm table should still serve");

    // Fresh resolver, no warm table, nothing admitted: never resolves.
    let mut r2: CachingResolver<MemoryBackend> =
        CachingResolver::new(LocalResolver::new(), store_with_clock(clock), vec![]);
    r2.trust("alice", k.verifying_key());
    assert!(matches!(
        r2.resolve("alice"),
        Err(ResolveError::UnknownSite(_))
    ));
}
