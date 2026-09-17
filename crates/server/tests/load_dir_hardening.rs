//! `SiteStore::load_dir` hardening: traversal-shaped names, symlink
//! reality, and fail-loud behavior. load_dir serves only from an
//! operator-controlled dir (unlike the content-addressed storage data dir),
//! so symlink following here is documented behavior — the ADR's no-symlink
//! rule targets the *storage* root (`crates/storage`), not site dirs.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use nexus_content::{Component, Metadata, Page};
use nexus_server::{ServerError, SiteStore};

static N: AtomicU64 = AtomicU64::new(0);

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "nx-load-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn page_bytes(site: &str, path: &str) -> Vec<u8> {
    Page {
        metadata: Metadata {
            schema: 1,
            site: site.into(),
            path: path.into(),
            title: "T".into(),
            revision: 1,
        },
        components: vec![Component::Text { text: "hi".into() }],
        capabilities: vec![],
    }
    .to_canonical_json()
    .unwrap()
}

/// Baseline: only `*.json` files load, keyed by stem, and served pages are
/// the exact validated bytes that were read.
#[test]
fn loads_json_only_and_skips_others() {
    let dir = tmpdir("baseline");
    std::fs::write(dir.join("a.json"), page_bytes("example", "a")).unwrap();
    std::fs::write(dir.join("b.txt"), b"not a page").unwrap();
    std::fs::write(dir.join("home.json"), page_bytes("example", "home")).unwrap();
    let mut store = SiteStore::new();
    assert_eq!(store.load_dir("example", &dir).unwrap(), 2);
    assert!(store.get("example", "a").is_some());
    assert!(store.get("example", "home").is_some());
    assert!(store.get("example", "b").is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Metadata mismatch (site or path) aborts the whole load: the server never
/// serves a page whose file name disagrees with its claimed identity.
#[test]
fn metadata_mismatch_aborts_loud() {
    let dir = tmpdir("meta-mismatch");
    std::fs::write(dir.join("a.json"), page_bytes("example", "a")).unwrap();
    std::fs::write(dir.join("evil.json"), page_bytes("example", "other")).unwrap();
    let mut store = SiteStore::new();
    assert!(matches!(
        store.load_dir("example", &dir),
        Err(ServerError::Content(_))
    ));
    // Fail-loud: nothing from the aborted load is served.
    assert!(store.get("example", "a").is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Symlink reality: load_dir follows file symlinks pointing outside the
/// site dir. Documented as operator-domain behavior (the site dir is not
/// attacker-writable in the current threat model); the storage data dir is
/// the no-symlink boundary and is tested separately.
#[cfg(unix)]
#[test]
fn symlink_escape_reality_documented() {
    let root = tmpdir("symlink");
    let site_dir = root.join("site");
    std::fs::create_dir_all(&site_dir).unwrap();
    // The "outside" file lives next to the site dir, not inside it.
    std::fs::write(root.join("outside.json"), page_bytes("example", "outside")).unwrap();
    std::os::unix::fs::symlink(root.join("outside.json"), site_dir.join("outside.json")).unwrap();

    let mut store = SiteStore::new();
    assert_eq!(store.load_dir("example", &site_dir).unwrap(), 1);
    assert!(store.get("example", "outside").is_some());
    let _ = std::fs::remove_dir_all(&root);
}

/// Broken symlink: unreadable entry aborts the load loudly (fail-closed
/// for serving, at the cost of one bad file blocking the whole site dir).
#[cfg(unix)]
#[test]
fn broken_symlink_aborts_loud() {
    let root = tmpdir("broken");
    let site_dir = root.join("site");
    std::fs::create_dir_all(&site_dir).unwrap();
    std::fs::write(site_dir.join("a.json"), page_bytes("example", "a")).unwrap();
    std::os::unix::fs::symlink(root.join("gone.json"), site_dir.join("gone.json")).unwrap();

    let mut store = SiteStore::new();
    assert!(matches!(
        store.load_dir("example", &site_dir),
        Err(ServerError::Content(_))
    ));
    let _ = std::fs::remove_dir_all(&root);
}

/// A file named `..json` has file stem `.` — a page at path `.` is legal
/// on the wire (`is_valid_path(".")` is true). Documents current behavior:
/// dot-root pages load and are serveable, but resolve to the site's own
/// root entry, never outside it (the in-memory map has no filesystem reach).
#[test]
fn dot_stem_page_loads_documented() {
    let dir = tmpdir("dot-stem");
    std::fs::write(dir.join("..json"), page_bytes("example", ".")).unwrap();
    let mut store = SiteStore::new();
    assert_eq!(store.load_dir("example", &dir).unwrap(), 1);
    assert!(store.get("example", ".").is_some());
    let _ = std::fs::remove_dir_all(&dir);
}

/// load_dir does not protocol-validate the site parameter or page stems
/// (no `is_valid_site`/`is_valid_path` check). The wire layer still blocks
/// such keys from ever being fetched, so this is a defense-in-depth gap,
/// not reachable from the network today.
#[test]
fn unvalidated_site_and_stem_documented() {
    let dir = tmpdir("unvalidated");
    std::fs::write(dir.join("a.json"), page_bytes("ExamplE", "a")).unwrap();
    let mut store = SiteStore::new();
    assert_eq!(store.load_dir("ExamplE", &dir).unwrap(), 1);
    assert!(store.get("ExamplE", "a").is_some());
    // Uppercase site passes the in-memory store but fails the wire parser.
    assert!(nexus_protocol::parse_request("NXP/0.1 FETCH ExamplE a\n").is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
