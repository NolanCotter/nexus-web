//! Milestone G: offline-first cache behavior over real loopback TCP:
//! stale-after-server-death, corruption-as-miss + eviction, revision replace.

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::thread::JoinHandle;

use nexus_browser::{BrowserError, CacheStatus, OfflineCache};
use nexus_content::{Component, Metadata, Page};

fn page_bytes(revision: u64) -> Vec<u8> {
    Page {
        metadata: Metadata {
            schema: 1,
            site: "example".into(),
            path: "home".into(),
            title: "T".into(),
            revision,
        },
        components: vec![Component::Text { text: "hi".into() }],
        capabilities: vec![],
    }
    .to_canonical_json()
    .unwrap()
}

/// Server that answers exactly one request, then dies (listener dropped,
/// port closed). Joining the handle is the deterministic "kill server".
fn serve_once(bytes: Vec<u8>) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let mut store = nexus_server::SiteStore::new();
        store.insert("example", "home", bytes);
        let (stream, _) = listener.accept().unwrap();
        nexus_server::handle_one(&stream, &store).unwrap();
    });
    (addr, handle)
}

fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nexus-offline-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// Server that answers exactly two requests (RECORDS + FETCH, in the order
/// verified fetches issue them), then dies. The store signs its page.
fn serve_signed_twice(
    bytes: Vec<u8>,
    identity: &nexus_identity::SiteIdentity,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let identity = identity.clone();
    let handle = std::thread::spawn(move || {
        let mut store = nexus_server::SiteStore::new();
        store.insert("example", "home", bytes);
        store.sign_pages(&identity, 9_999_999_999).unwrap();
        for _ in 0..2 {
            let (stream, _) = listener.accept().unwrap();
            nexus_server::handle_one(&stream, &store).unwrap();
        }
    });
    (addr, handle)
}

fn test_key(seed: u8) -> nexus_identity::SiteIdentity {
    nexus_identity::SiteIdentity::from_secret_bytes(&[seed; 32]).unwrap()
}

#[test]
fn pinned_offline_serves_verified_stale() {
    let dir = temp_dir("verified-stale");
    let cache = OfflineCache::new(&dir);
    let id = test_key(31);
    let (addr, server) = serve_signed_twice(page_bytes(1), &id);

    let (page, status) = cache
        .fetch_verified(&addr.to_string(), "example", "home", &id.site_id())
        .unwrap();
    assert!(matches!(status, CacheStatus::Fresh));
    assert_eq!(page.metadata.revision, 1);

    server.join().unwrap(); // server dead: port closed

    let (page2, status2) = cache
        .fetch_verified(&addr.to_string(), "example", "home", &id.site_id())
        .unwrap();
    assert!(matches!(status2, CacheStatus::StaleVerified));
    assert_eq!(page2.to_canonical_json().unwrap(), page_bytes(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn verified_stale_rejects_wrong_pin_and_tamper() {
    let dir = temp_dir("verified-pin");
    let cache = OfflineCache::new(&dir);
    let id = test_key(32);
    let other = test_key(33);
    let (addr, server) = serve_signed_twice(page_bytes(1), &id);
    cache
        .fetch_verified(&addr.to_string(), "example", "home", &id.site_id())
        .unwrap();
    server.join().unwrap();

    // Wrong pin: no entry applies, transport error propagates.
    let err = cache
        .fetch_verified(&addr.to_string(), "example", "home", &other.site_id())
        .unwrap_err();
    assert!(matches!(err, BrowserError::Transport(_)));

    // Tamper with the cached chain: verified lookup must miss + evict.
    let idx: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("index.json")).unwrap()).unwrap();
    let rid = idx["pages"]["example\u{1f}home"]["records_id"]
        .as_str()
        .unwrap();
    let blob = dir.join("blobs").join(&rid[3..5]).join(&rid[5..]);
    let mut bad = std::fs::read(&blob).unwrap();
    // Length-preserving flip inside the JSON (keeps the blob length, breaks
    // the signature over the content hash).
    let mid = bad.len() / 2;
    bad[mid] ^= 0xff;
    std::fs::write(&blob, bad).unwrap();
    // NOTE: flipping may break JSON parsing or the signature; either way
    // the entry must not serve. (BLAKE3 catches it first → miss + evict.)
    let err = cache
        .fetch_verified(&addr.to_string(), "example", "home", &id.site_id())
        .unwrap_err();
    assert!(matches!(err, BrowserError::Transport(_)));
    let idx: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("index.json")).unwrap()).unwrap();
    assert!(idx["pages"].get("example\u{1f}home").is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn offline_fetch_returns_stale_after_server_dies() {
    let dir = temp_dir("stale");
    let cache = OfflineCache::new(&dir);
    let (addr, server) = serve_once(page_bytes(1));

    let (page, status) = cache.fetch(&addr.to_string(), "example", "home").unwrap();
    assert!(matches!(status, CacheStatus::Fresh));
    assert_eq!(page.metadata.revision, 1);

    server.join().unwrap(); // server dead: port closed

    let (page2, status2) = cache.fetch(&addr.to_string(), "example", "home").unwrap();
    assert!(matches!(status2, CacheStatus::Stale));
    assert_eq!(page2.metadata.revision, 1);
    assert_eq!(page2.to_canonical_json().unwrap(), page_bytes(1)); // identical content

    // Cold cache + dead server: transport error must propagate (no phantom page).
    let cache2 = OfflineCache::new(temp_dir("stale-cold"));
    let err = cache2
        .fetch(&addr.to_string(), "example", "home")
        .unwrap_err();
    assert!(matches!(err, BrowserError::Transport(_)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn corrupt_blob_is_miss_and_evicted() {
    let dir = temp_dir("corrupt");
    let cache = OfflineCache::new(&dir);
    let (addr, server) = serve_once(page_bytes(1));
    cache.fetch(&addr.to_string(), "example", "home").unwrap();
    server.join().unwrap();

    // Flip a byte inside the stored blob (length-preserving): BLAKE3 must
    // reject it before any parsing/validation even runs.
    let idx: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("index.json")).unwrap()).unwrap();
    let cid = idx["pages"]["example\u{1f}home"]["content_id"]
        .as_str()
        .unwrap();
    let blob = dir.join("blobs").join(&cid[3..5]).join(&cid[5..]);
    let mut bad = std::fs::read(&blob).unwrap();
    *bad.last_mut().unwrap() ^= 0xff;
    std::fs::write(&blob, bad).unwrap();

    let err = cache
        .fetch(&addr.to_string(), "example", "home")
        .unwrap_err();
    assert!(matches!(err, BrowserError::Transport(_)));

    // The poisoned entry was evicted from the index.
    let idx: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("index.json")).unwrap()).unwrap();
    assert!(idx["pages"].get("example\u{1f}home").is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn fresh_server_revision_replaces_cached_copy() {
    let dir = temp_dir("rev");
    let cache = OfflineCache::new(&dir);
    let (addr, server) = serve_once(page_bytes(1));
    cache.fetch(&addr.to_string(), "example", "home").unwrap();
    server.join().unwrap();

    // Server returns with revision 2 on a new port (cache keys by site+path).
    let (addr2, server2) = serve_once(page_bytes(2));
    let (page, status) = cache.fetch(&addr2.to_string(), "example", "home").unwrap();
    assert!(matches!(status, CacheStatus::Fresh));
    assert_eq!(page.metadata.revision, 2);
    server2.join().unwrap();

    // Offline now serves the new revision, not the superseded one.
    let (page2, status2) = cache.fetch(&addr2.to_string(), "example", "home").unwrap();
    assert!(matches!(status2, CacheStatus::Stale));
    assert_eq!(page2.metadata.revision, 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn second_fetch_sends_precondition_and_takes_304() {
    use std::io::{BufRead, Write};
    use std::sync::{Arc, Mutex};
    let dir = temp_dir("revalidate");
    let cache = OfflineCache::new(&dir);

    // Prime the cache with a real fetch.
    let (addr, server) = serve_once(page_bytes(1));
    let (page, _) = cache.fetch(&addr.to_string(), "example", "home").unwrap();
    let want = page.content_id().unwrap();
    server.join().unwrap();

    // Spy server: capture the request line, answer 304 with empty body.
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen2 = Arc::clone(&seen);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr2 = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut r = std::io::BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        seen2.lock().unwrap().push(line);
        let frame = nexus_protocol::encode_response(304, b"").unwrap();
        stream.try_clone().unwrap().write_all(&frame).unwrap();
    });
    let (page2, status) = cache.fetch(&addr2.to_string(), "example", "home").unwrap();
    assert!(matches!(status, CacheStatus::Fresh));
    assert_eq!(page2.content_id().unwrap(), want);
    handle.join().unwrap();

    // The client actually sent what it holds — bandwidth saved server-side.
    let lines = seen.lock().unwrap();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0], format!("NXP/0.1 FETCH example home {want}\n"));
    let _ = std::fs::remove_dir_all(&dir);
}
