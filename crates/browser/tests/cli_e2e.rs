//! End-to-end: the unified `nexus` binary against a real SiteStore over
//! loopback TCP. Exercises nav parsing, lazy resolution, history, and
//! back/forward through the actual CLI's stdin protocol.

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};

use nexus_content::{Component, Metadata, Page};

fn page_bytes(site: &str, path: &str, title: &str) -> Vec<u8> {
    Page {
        metadata: Metadata {
            schema: 1,
            site: site.into(),
            path: path.into(),
            title: title.into(),
            revision: 1,
        },
        components: vec![Component::Text {
            text: format!("body of {path}"),
        }],
        capabilities: vec![],
    }
    .to_canonical_json()
    .unwrap()
}

/// Multi-connection SiteStore server on an ephemeral port.
fn spawn_store() -> std::net::SocketAddr {
    let mut store = nexus_server::SiteStore::new();
    store.insert(
        "example",
        "home",
        page_bytes("example", "home", "Example Home"),
    );
    store.insert(
        "example",
        "about",
        page_bytes("example", "about", "About Nexus"),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let store = store.clone();
            std::thread::spawn(move || {
                let _ = nexus_server::handle_one(&stream, &store);
                let _ = TcpStream::shutdown(&stream, std::net::Shutdown::Both);
            });
        }
    });
    addr
}

#[test]
fn nexus_binary_browses_back_forward_over_tcp() {
    let addr = spawn_store();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nexus"))
        .args(["browse", "example/home", "--server", &addr.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = child.stdin.take().unwrap();
    // goto about, list history, back, forward, list history again, quit.
    stdin
        .write_all(b"g example/about\nh\nb\nf\nh\nq\n")
        .unwrap();
    drop(stdin);

    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    assert!(stderr.is_empty(), "unexpected stderr: {stderr}");

    let stdout = String::from_utf8_lossy(&out.stdout);
    // Both pages rendered at least once (initial + goto, back + forward).
    assert!(stdout.contains("Example Home"));
    assert!(stdout.contains("About Nexus"));
    // History listing: 2 entries, current marker on `/about` (=> 2.), not `/home`.
    assert!(stdout.contains("=> 2. @example /about"));
    assert!(!stdout.contains("=> 1. @example /home"));
}

#[test]
fn nexus_sync_mirrors_site_to_dir() {
    let addr = spawn_store();
    let dir = std::env::temp_dir().join(format!("nexus-sync-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let out = Command::new(env!("CARGO_BIN_EXE_nexus"))
        .args([
            "sync",
            "--server",
            &addr.to_string(),
            "--site",
            "example",
            "--dir",
            dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("synced 2 page(s)"), "stdout: {stdout}");

    // Synced files load back as valid pages through the normal path.
    let mut store = nexus_server::SiteStore::new();
    let n = store.load_dir("example", &dir).unwrap();
    assert_eq!(n, 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn nexus_sync_verified_mirrors_with_chain() {
    let mut store = nexus_server::SiteStore::new();
    store.insert(
        "example",
        "home",
        page_bytes("example", "home", "Example Home"),
    );
    let id = nexus_identity::SiteIdentity::from_secret_bytes(&[51u8; 32]).unwrap();
    store.sign_pages(&id, 9_999_999_999).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        // LIST + RECORDS + FETCH.
        for _ in 0..3 {
            let (stream, _) = listener.accept().unwrap();
            nexus_server::handle_one(&stream, &store).unwrap();
        }
    });
    let dir = std::env::temp_dir().join(format!("nexus-sync-pin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let out = Command::new(env!("CARGO_BIN_EXE_nexus"))
        .args([
            "sync",
            "--server",
            &addr.to_string(),
            "--site",
            "example",
            "--dir",
            dir.to_str().unwrap(),
            "--pin",
            &id.site_id(),
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("1 verified"), "stdout: {stdout}");
    assert!(dir.join("home.json").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn nexus_export_pack_imports_into_fresh_store() {
    // Signed origin: page + chain.
    let mut store = nexus_server::SiteStore::new();
    store.insert(
        "example",
        "home",
        page_bytes("example", "home", "Example Home"),
    );
    let id = nexus_identity::SiteIdentity::from_secret_bytes(&[61u8; 32]).unwrap();
    store.sign_pages(&id, 9_999_999_999).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        // LIST + RECORDS + FETCH.
        for _ in 0..3 {
            let (stream, _) = listener.accept().unwrap();
            nexus_server::handle_one(&stream, &store).unwrap();
        }
    });
    let pack = std::env::temp_dir().join(format!("nexus-export-e2e-{}.nxpack", std::process::id()));
    let _ = std::fs::remove_file(&pack);

    let out = Command::new(env!("CARGO_BIN_EXE_nexus"))
        .args([
            "export",
            "--server",
            &addr.to_string(),
            "--site",
            "example",
            "--out",
            pack.to_str().unwrap(),
            "--pin",
            &id.site_id(),
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");

    // Fresh store imports the pack and serves the page + chain.
    let bytes = std::fs::read(&pack).unwrap();
    let mut store2 = nexus_server::SiteStore::new();
    let report = store2.load_pack(&bytes).unwrap();
    assert_eq!((report.pages, report.chains), (1, 1));
    let page = nexus_content::Page::from_json(store2.get("example", "home").unwrap()).unwrap();
    assert_eq!(page.metadata.title, "Example Home");
    let records: Vec<nexus_identity::SignedRecord> =
        serde_json::from_slice(store2.get_records("example", "home").unwrap()).unwrap();
    id.verify_record(&records[0], 1_000_000).unwrap();
    let _ = std::fs::remove_file(&pack);
}
