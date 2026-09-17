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
        for stream in listener.incoming() {
            if let Ok(stream) = stream {
                let store = store.clone();
                std::thread::spawn(move || {
                    let _ = nexus_server::handle_one(&stream, &store);
                    let _ = TcpStream::shutdown(&stream, std::net::Shutdown::Both);
                });
            }
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
