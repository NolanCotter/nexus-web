//! Federated backend conformance + malicious-server battery over loopback
//! TCP, via the `RECORDS` convention (`docs/decisions/010-federated-records-convention.md`)
//! served by the test-only server below on nexus-transport framing:
//!
//! ```text
//! request   NXP/0.1 RECORDS <name> @<name>\n
//! response  NXP/0.1 200 <len>\n<JSON array of SignedRecord> | 404 = none
//! ```
//!
//! The same scenarios the unit tests run against `MemoryBackend` (cold fetch
//! → verify → warm table; the poisoned-backend battery) run here against
//! `FederatedBackend`. Verification never moves: admission still requires
//! signature + site match + expiry + strictly-advancing seq against the
//! out-of-band trust anchor. Negative cases double as the security check:
//! forged / expired / stale / foreign-key records, garbage bodies, or error
//! codes all come back empty (transport failure) or die at the core — never
//! admitted.

use std::collections::HashMap;
use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

use ed25519_dalek::SigningKey;
use nexus_identity::{ResourceRecord, SignedRecord};
use nexus_resolver::backend::{Backend, FederatedBackend};
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

/// One signed envelope under path `@name` (v0 convention: endpoint or
/// revocation JSON in `content_hash`, exactly what `CachingResolver` reads).
fn envelope(name: &str, site: &str, content: String, expires: u64) -> SignedRecord {
    SignedRecord {
        record: ResourceRecord {
            site: site.to_string(),
            path: format!("@{name}"),
            content_hash: content,
            expires_at_unix: expires,
        },
        signature_hex: String::new(),
    }
}

/// Envelope carrying a signed endpoint record for `name`.
fn endpoint_envelope(name: &str, rec: &EndpointRecord) -> SignedRecord {
    envelope(
        name,
        &rec.site,
        serde_json::to_string(rec).unwrap(),
        now() + 86_400,
    )
}

/// A test-only record server answer for one name.
#[derive(Debug)]
enum Serve {
    /// 200 + JSON array of envelopes.
    Records(Vec<SignedRecord>),
    /// Fixed status code + raw body (garbage bodies, 500s, ...).
    Status(u16, Vec<u8>),
}

/// Serve one name from a single endpoint record (the common case).
fn serve_records(name: &str, rec: &EndpointRecord) -> (String, Serve) {
    (
        name.to_string(),
        Serve::Records(vec![endpoint_envelope(name, rec)]),
    )
}

/// Spawn a record server; returns its `host:port` endpoint.
fn spawn_server(serve: HashMap<String, Serve>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            handle_one(&stream, &serve);
        }
    });
    format!("{}:{}", addr.ip(), addr.port())
}

/// Serve one RECORDS request (nexus-transport line framing).
fn handle_one(mut stream: &TcpStream, serve: &HashMap<String, Serve>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let Ok(line) = nexus_transport::read_line_limited(&mut reader) else {
        return;
    };
    let mut parts = line.trim_end().splitn(4, ' ');
    let (Some(version), Some(verb), Some(site), Some(path)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return;
    };
    if version != nexus_protocol::VERSION
        || verb != "RECORDS"
        || path.strip_prefix('@') != Some(site)
    {
        return;
    }
    let frame = match serve.get(site) {
        Some(Serve::Records(records)) => {
            nexus_protocol::encode_response(200, &serde_json::to_vec(records).unwrap()).unwrap()
        }
        Some(Serve::Status(code, body)) => nexus_protocol::encode_response(*code, body).unwrap(),
        None => nexus_protocol::encode_response(404, b"no records").unwrap(),
    };
    let _ = stream.write_all(&frame);
}

/// A loopback port that refuses connections (listener destroyed).
fn closed_port() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("{}:{}", addr.ip(), addr.port())
}

/// Trust `name` at `key` and build a resolver over the given endpoints.
fn trust_and_resolve(
    name: &str,
    key: &SigningKey,
    endpoints: Vec<String>,
    clock: Clock,
) -> CachingResolver<FederatedBackend> {
    let mut store = RecordStore::with_clock(clock);
    store.trust(name, key.verifying_key());
    CachingResolver::new(
        LocalResolver::new(),
        store,
        vec![FederatedBackend::new(endpoints)],
    )
}

/// Resolving `name` fails with `UnknownSite`: nothing was admitted.
fn assert_unknown(r: &CachingResolver<FederatedBackend>, name: &str) {
    assert!(matches!(r.resolve(name), Err(ResolveError::UnknownSite(_))));
}

// ---------------------------------------------------------------------------
// Conformance: the MemoryBackend scenarios, over loopback TCP.
// ---------------------------------------------------------------------------

/// Mirror of `caching_resolver_fetches_from_backend_then_warms_table`.
#[test]
fn federated_cold_fetch_verifies_and_warms_table() {
    let site_key = test_key(1);
    let site = hex::encode(site_key.verifying_key().to_bytes());
    let rec = make_record(&site_key, "10.9.9.9", 7843, 1);
    let server = spawn_server(HashMap::from([serve_records("alice", &rec)]));
    let resolver = trust_and_resolve("alice", &site_key, vec![server], now);

    // Cold: fetched from the server, verified, routed.
    let route = resolver.resolve("alice").unwrap();
    assert_eq!(route.endpoints, vec!["10.9.9.9:7843"]);
    assert_eq!(route.pinned_site_id.as_deref(), Some(site.as_str()));
    // Warm: second resolve survives without touching the backend again.
    assert_eq!(resolver.resolve("alice").unwrap(), route);
    assert!(resolver.list_names().contains(&"alice".to_string()));

    let stats = resolver.backends()[0].stats();
    assert_eq!((stats.requests, stats.records, stats.failures), (1, 1, 0));
}

/// Mirror of `poisoned_backend_battery`, served by a malicious server:
/// garbage, expired, stale-seq-0, and foreign-key records, plus a
/// revocation tombstone — all in one answer.
#[test]
fn federated_poisoned_server_battery() {
    static NOW_FIXED: AtomicU64 = AtomicU64::new(1_700_000_000);
    let clock: Clock = || NOW_FIXED.load(Ordering::SeqCst);
    let k = test_key(2);
    let site = hex::encode(k.verifying_key().to_bytes());
    let mut expired = make_record(&k, "10.0.0.1", 1, 1);
    expired.expires_at_unix = now() - 10;
    let stale = EndpointRecord::sign(&k, &site, Transport::Tcp, "10.0.0.2", 2, 0, now() + 86_400);
    let attacker = test_key(3);
    let rev_json = serde_json::to_string(&Revocation::sign(&k, &site, 99, now() + 86_400)).unwrap();

    let server = spawn_server(HashMap::from([(
        "alice".into(),
        Serve::Records(vec![
            envelope("alice", &site, "not json at all".into(), now() + 86_400),
            endpoint_envelope("alice", &expired),
            endpoint_envelope("alice", &stale),
            endpoint_envelope("alice", &make_record(&attacker, "evil", 666, 1)),
            envelope("alice", &site, rev_json, now() + 86_400),
        ]),
    )]));
    let mut r = trust_and_resolve("alice", &k, vec![server], clock);
    // Nothing poisonous resolves; the tombstone suppresses the rest.
    assert_unknown(&r, "alice");
    // A genuinely valid record above the tombstone still resolves.
    assert!(r.admit_record("alice", make_record(&k, "10.0.0.7", 7, 100)));
    assert_eq!(r.resolve("alice").unwrap().endpoints, vec!["10.0.0.7:7"]);
}

// ---------------------------------------------------------------------------
// Negative battery: malicious server output is never admitted.
// ---------------------------------------------------------------------------

#[test]
fn forged_and_foreign_key_records_never_admit() {
    let owner = test_key(4);
    let attacker = test_key(5);
    let forged = endpoint_envelope("alice", &make_record(&attacker, "evil", 666, 1));
    let server = spawn_server(HashMap::from([(
        "alice".into(),
        Serve::Records(vec![forged.clone()]),
    )]));

    // `fetch` is a pure transport: the forged envelope comes back untouched...
    let backend = FederatedBackend::new(vec![server.clone()]);
    assert_eq!(backend.fetch("alice"), vec![forged]);
    // ...but the core admits nothing: site mismatch vs the trust anchor.
    let r = trust_and_resolve("alice", &owner, vec![server], now);
    assert_unknown(&r, "alice");
}

#[test]
fn expired_records_never_admit() {
    let k = test_key(6);
    let mut rec = make_record(&k, "10.0.0.1", 1, 1);
    rec.expires_at_unix = now() - 10;
    let server = spawn_server(HashMap::from([serve_records("alice", &rec)]));
    let r = trust_and_resolve("alice", &k, vec![server], now);
    assert_unknown(&r, "alice");
}

#[test]
fn stale_replay_rejected_newest_wins() {
    let k = test_key(7);
    let site = hex::encode(k.verifying_key().to_bytes());
    let server = spawn_server(HashMap::from([(
        "alice".into(),
        Serve::Records(vec![
            endpoint_envelope("alice", &make_record(&k, "10.0.0.9", 9, 1)), // replay of seq 1
            endpoint_envelope("alice", &make_record(&k, "10.0.0.2", 2, 2)),
        ]),
    )]));
    let mut r = trust_and_resolve("alice", &k, vec![server], now);
    // Seed the store's high-water mark offline (seq 1); table stays cold.
    assert!(r.admit_record("alice", make_record(&k, "10.0.0.1", 1, 1)));
    let route = r.resolve("alice").unwrap();
    // The replay was dropped by admission; seq 2 wins and pins.
    assert_eq!(route.endpoints, vec!["10.0.0.2:2"]);
    assert_eq!(route.pinned_site_id.as_deref(), Some(site.as_str()));
    // Transport delivered both; the core admitted only the advancing one.
    let stats = r.backends()[0].stats();
    assert_eq!((stats.requests, stats.records, stats.failures), (1, 2, 0));
}

#[test]
fn wrong_path_envelopes_skipped() {
    let k = test_key(8);
    let rec = make_record(&k, "10.0.0.1", 1, 1);
    // Envelope path is @mallory: the core only accepts "@alice" here.
    let server = spawn_server(HashMap::from([serve_records("mallory", &rec)]));
    let r = trust_and_resolve("alice", &k, vec![server], now);
    assert_unknown(&r, "alice");
}

#[test]
fn garbage_and_error_responses_are_transport_failures() {
    let k = test_key(9);
    let server = spawn_server(HashMap::from([
        ("alice".into(), Serve::Status(200, b"not json".to_vec())),
        ("bob".into(), Serve::Status(500, b"boom".to_vec())),
    ]));
    let backend = FederatedBackend::new(vec![server.clone()]);
    assert!(backend.fetch("alice").is_empty());
    assert!(backend.fetch("bob").is_empty());
    let stats = backend.stats();
    assert_eq!((stats.requests, stats.records, stats.failures), (2, 0, 2));

    let r = trust_and_resolve("alice", &k, vec![server], now);
    assert_unknown(&r, "alice");
}

#[test]
fn unreachable_and_authoritative_empty() {
    // Closed port: transport failure, empty fetch.
    let backend = FederatedBackend::new(vec![closed_port()]);
    assert!(backend.fetch("alice").is_empty());
    assert_eq!(backend.stats().failures, 1);

    // Authoritative 404: empty, but not a failure (DNS-like negative answer).
    let server = spawn_server(HashMap::new());
    let backend = FederatedBackend::new(vec![server.clone()]);
    assert!(backend.fetch("nobody").is_empty());
    assert_eq!(
        (backend.stats().failures, backend.stats().last_code),
        (0, 404)
    );

    let k = test_key(10);
    let r = trust_and_resolve("nobody", &k, vec![server], now);
    assert_unknown(&r, "nobody");
}

#[test]
fn multi_endpoint_failover_and_aggregation() {
    let k = test_key(11);
    let site = hex::encode(k.verifying_key().to_bytes());
    let attacker = test_key(12);
    let bad = spawn_server(HashMap::from([serve_records(
        "alice",
        &make_record(&attacker, "evil", 666, 1),
    )]));
    let good = spawn_server(HashMap::from([serve_records(
        "alice",
        &make_record(&k, "10.0.0.5", 5, 5),
    )]));

    let backend = FederatedBackend::new(vec![closed_port(), bad, good]);
    let mut store = RecordStore::with_clock(now);
    store.trust("alice", k.verifying_key());
    let r = CachingResolver::new(LocalResolver::new(), store, vec![backend]);
    // Unreachable + poisoned endpoints cannot veto the valid answer.
    let route = r.resolve("alice").unwrap();
    assert_eq!(route.endpoints, vec!["10.0.0.5:5"]);
    assert_eq!(route.pinned_site_id.as_deref(), Some(site.as_str()));
    let stats = r.backends()[0].stats();
    assert_eq!((stats.requests, stats.records, stats.failures), (3, 2, 1));
}

#[test]
fn invalid_names_never_hit_the_wire() {
    let backend = FederatedBackend::new(vec!["127.0.0.1:1".into()]);
    assert!(backend.fetch("").is_empty());
    assert!(backend.fetch("UPPER").is_empty());
    assert_eq!(backend.stats().requests, 0);
    let r = trust_and_resolve("u p", &test_key(13), vec!["127.0.0.1:1".into()], now);
    assert!(matches!(
        r.resolve("u p"),
        Err(ResolveError::InvalidName(_))
    ));
}

#[test]
fn authoritative_empty_caches_negative_until_ttl() {
    let k = test_key(20);
    let server = spawn_server(HashMap::new()); // 404 for every name
    let mut store = RecordStore::with_clock(now);
    store.trust("nobody", k.verifying_key());
    let r = CachingResolver::new(
        LocalResolver::new(),
        store,
        vec![FederatedBackend::new(vec![server])],
    )
    .with_negative_ttl(std::time::Duration::from_millis(80));
    // First miss hits the wire; second is served from the negative cache.
    assert_unknown(&r, "nobody");
    assert_unknown(&r, "nobody");
    assert_eq!(r.backends()[0].stats().requests, 1);
    // After the TTL lapses the backend is consulted again.
    std::thread::sleep(std::time::Duration::from_millis(150));
    assert_unknown(&r, "nobody");
    assert_eq!(r.backends()[0].stats().requests, 2);
}

#[test]
fn transport_failure_never_caches_negative() {
    let k = test_key(21);
    let mut store = RecordStore::with_clock(now);
    store.trust("nobody", k.verifying_key());
    let r = CachingResolver::new(
        LocalResolver::new(),
        store,
        vec![FederatedBackend::new(vec![closed_port()])],
    )
    .with_negative_ttl(std::time::Duration::from_secs(3600));
    // Failures are not knowledge: every resolve retries the wire.
    assert_unknown(&r, "nobody");
    assert_unknown(&r, "nobody");
    let stats = r.backends()[0].stats();
    assert_eq!((stats.requests, stats.failures), (2, 2));
}

#[test]
fn admitted_record_clears_negative() {
    let k = test_key(22);
    let server = spawn_server(HashMap::new());
    let mut store = RecordStore::with_clock(now);
    store.trust("nobody", k.verifying_key());
    let mut r = CachingResolver::new(
        LocalResolver::new(),
        store,
        vec![FederatedBackend::new(vec![server])],
    );
    assert_unknown(&r, "nobody");
    assert_eq!(r.backends()[0].stats().requests, 1);
    // Out-of-band valid record clears the negative: the next resolve
    // consults the backend again (requests 1 -> 2 proves no fast-fail)
    // and then serves the admitted record from the store.
    assert!(r.admit_record("nobody", make_record(&k, "10.0.0.9", 9, 1)));
    let route = r.resolve("nobody").unwrap();
    assert_eq!(route.endpoints, vec!["10.0.0.9:9"]);
    assert_eq!(r.backends()[0].stats().requests, 2);
}
