//! Dogfood: the STOCK `nexus-server` as a federated resolution endpoint.
//!
//! A `SiteStore` serves a signed endpoint-record chain at
//! `RECORDS alice @alice` (ADR 010); a `CachingResolver` with a
//! `FederatedBackend` pointed at it must resolve `alice` to the advertised
//! route — verification running entirely on the client side.

use std::net::TcpListener;

use ed25519_dalek::SigningKey;
use nexus_resolver::backend::FederatedBackend;
use nexus_resolver::resolve::{CachingResolver, EndpointRecord, RecordStore, Transport};
use nexus_resolver::{LocalResolver, Resolver};

fn test_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// Serve the stock store on an ephemeral port (multi-connection).
fn spawn_stock(store: nexus_server::SiteStore) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let store = store.clone();
            std::thread::spawn(move || {
                let _ = nexus_server::handle_one(&stream, &store);
            });
        }
    });
    addr.to_string()
}

/// Build the `@alice` chain: endpoint record (JSON) inside an identity
/// `SignedRecord` envelope, exactly what `sign_pages` would NOT produce
/// (that path signs content records) — endpoint chains are published
/// out-of-band by the name owner.
fn alice_chain(key: &SigningKey) -> Vec<u8> {
    let site = hex::encode(key.verifying_key().to_bytes());
    let endpoint = EndpointRecord::sign(
        key,
        &site,
        Transport::Tcp,
        "127.0.0.1",
        9999,
        1,
        9_999_999_999,
    );
    let endpoint_json = serde_json::to_string(&endpoint).unwrap();
    let identity = nexus_identity::SiteIdentity::from_secret_bytes(&key.to_bytes()).unwrap();
    let signed = identity
        .sign_record("@alice", &endpoint_json, 9_999_999_999)
        .unwrap();
    serde_json::to_vec(&[signed]).unwrap()
}

#[test]
fn stock_server_answers_federated_backend() {
    let key = test_key(71);
    let mut store = nexus_server::SiteStore::new();
    store.insert_endpoint_records("alice", alice_chain(&key));

    let endpoint = spawn_stock(store);
    let backend = FederatedBackend::new(vec![endpoint]);
    let mut store = RecordStore::new();
    store.trust("alice", key.verifying_key());
    let resolver = CachingResolver::new(LocalResolver::new(), store, vec![backend]);

    let route = resolver.resolve("alice").unwrap();
    assert_eq!(route.endpoints, vec!["127.0.0.1:9999"]);
    assert_eq!(
        route.pinned_site_id.as_deref(),
        Some(hex::encode(key.verifying_key().to_bytes()).as_str())
    );
}

#[test]
fn stock_server_forged_chain_never_admits() {
    // Attacker serves a chain for alice signed by the WRONG key: the
    // client verifies against its trust anchor and admits nothing.
    let owner = test_key(72);
    let attacker = test_key(73);
    let mut store = nexus_server::SiteStore::new();
    store.insert_endpoint_records("alice", alice_chain(&attacker));

    let endpoint = spawn_stock(store);
    let backend = FederatedBackend::new(vec![endpoint]);
    let mut store = RecordStore::new();
    store.trust("alice", owner.verifying_key());
    let resolver = CachingResolver::new(LocalResolver::new(), store, vec![backend]);

    assert!(resolver.resolve("alice").is_err());
}
