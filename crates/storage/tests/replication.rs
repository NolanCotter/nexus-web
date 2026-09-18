//! NXPACK1 replication: `FsStore::export` -> pack file -> `FsStore::import`.
//!
//! Includes the milestone scenario: node A packs a page, node B imports the
//! pack and serves the page over real NXP/TCP (transport + protocol codecs,
//! the same path `nexus_server::handle_one` uses).

use std::collections::HashMap;
use std::io::{BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;

use nexus_storage::{FsStore, ImportReport, StoreError, MAX_BLOB, MAX_PACK};

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nx-repl-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cleanup(dir: &PathBuf) {
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn roundtrip() {
    let dir_a = tmp_dir("roundtrip-a");
    let dir_b = tmp_dir("roundtrip-b");
    let a = FsStore::new(&dir_a);
    let b = FsStore::new(&dir_b);
    let ids = vec![
        a.put(b"hello replication").unwrap(),
        a.put(b"").unwrap(), // empty blob is valid
        a.put(&vec![7u8; 1000]).unwrap(),
    ];
    let pack = a.export(&ids).unwrap();
    assert_eq!(&pack[..7], b"NXPACK1");

    let report = b.import(&pack).unwrap();
    assert_eq!(
        report,
        ImportReport {
            blobs: 3,
            total_bytes: 1017
        }
    );
    for id in &ids {
        assert_eq!(b.get(id).unwrap(), a.get(id).unwrap());
    }
    // Re-import is idempotent.
    assert_eq!(b.import(&pack).unwrap().blobs, 3);

    // Empty export/import round-trips.
    let empty = a.export(&[]).unwrap();
    assert_eq!(empty.len(), nexus_storage::PACK_HEADER_LEN);
    assert_eq!(
        b.import(&empty).unwrap(),
        ImportReport {
            blobs: 0,
            total_bytes: 0
        }
    );

    cleanup(&dir_a);
    cleanup(&dir_b);
}

#[test]
fn tamper_reject() {
    let dir_a = tmp_dir("tamper-a");
    let dir_b = tmp_dir("tamper-b");
    let a = FsStore::new(&dir_a);
    let b = FsStore::new(&dir_b);
    let id_a = a.put(b"AAAAAAAAAAAAAAAAAAAA").unwrap();
    let id_b = a.put(b"BBBBBBBBBBBBBBBBBBBB").unwrap();
    let pack = a.export(&[id_a.clone(), id_b.clone()]).unwrap();

    // Flip one payload byte (first payload starts at 11 + 36 = 47).
    let mut evil = pack.clone();
    evil[48] ^= 0xff;
    assert!(matches!(b.import(&evil), Err(StoreError::Corrupt(_))));
    // Nothing was stored by the failed import.
    assert!(matches!(b.get(&id_a), Err(StoreError::NotFound(_))));
    assert!(matches!(b.get(&id_b), Err(StoreError::NotFound(_))));

    // Valid pack still imports into the same untouched store.
    assert_eq!(b.import(&pack).unwrap().blobs, 2);
    assert_eq!(b.get(&id_a).unwrap(), b"AAAAAAAAAAAAAAAAAAAA");

    cleanup(&dir_a);
    cleanup(&dir_b);
}

#[test]
fn truncation_reject() {
    let dir_a = tmp_dir("trunc-a");
    let dir_b = tmp_dir("trunc-b");
    let a = FsStore::new(&dir_a);
    let b = FsStore::new(&dir_b);
    let id = a.put(b"truncate me please").unwrap();
    let pack = a.export(&[id]).unwrap();

    // Cut into the payload.
    assert!(b.import(&pack[..pack.len() - 5]).is_err());
    // Cut mid-length-field.
    assert!(b.import(&pack[..10]).is_err());
    // Header only, count claims entries that are not there.
    assert!(b.import(&pack[..11]).is_err());
    // Bad magic.
    let mut evil = pack.clone();
    evil[0] = b'X';
    assert!(matches!(b.import(&evil), Err(StoreError::Corrupt(_))));

    cleanup(&dir_a);
    cleanup(&dir_b);
}

#[test]
fn trailing_garbage_reject() {
    let dir_a = tmp_dir("trail-a");
    let dir_b = tmp_dir("trail-b");
    let a = FsStore::new(&dir_a);
    let b = FsStore::new(&dir_b);
    let id = a.put(b"clean data").unwrap();
    let pack = a.export(std::slice::from_ref(&id)).unwrap();

    let mut evil = pack.clone();
    evil.extend_from_slice(b"GARBAGE");
    let err = b.import(&evil).unwrap_err();
    assert!(matches!(err, StoreError::Corrupt(_)));
    assert!(err.to_string().contains("trailing"));
    assert!(matches!(b.get(&id), Err(StoreError::NotFound(_))));

    cleanup(&dir_a);
    cleanup(&dir_b);
}

#[test]
fn oversize_reject() {
    let dir_a = tmp_dir("over-a");
    let dir_b = tmp_dir("over-b");
    let a = FsStore::new(&dir_a);
    let b = FsStore::new(&dir_b);

    // Hand-crafted pack claiming a blob above MAX_BLOB.
    let mut evil: Vec<u8> = Vec::new();
    evil.extend_from_slice(b"NXPACK1");
    evil.extend_from_slice(&1u32.to_le_bytes());
    evil.extend_from_slice(&((MAX_BLOB + 1) as u32).to_le_bytes());
    evil.extend_from_slice(&[0u8; 32]);
    assert!(matches!(b.import(&evil), Err(StoreError::TooLarge(_))));

    // Pack that exceeds the total 64 MiB cap.
    let mut huge = vec![0u8; MAX_PACK + 1];
    huge[..7].copy_from_slice(b"NXPACK1");
    assert!(matches!(b.import(&huge), Err(StoreError::TooLarge(_))));

    // Export refuses to build an overlarge pack too.
    let big_blob = vec![0u8; MAX_BLOB];
    let big_id = a.put(&big_blob).unwrap();
    let ids: Vec<String> = vec![big_id; MAX_PACK / MAX_BLOB + 2];
    assert!(matches!(a.export(&ids), Err(StoreError::TooLarge(_))));

    cleanup(&dir_a);
    cleanup(&dir_b);
}

/// Milestone H scenario: node A packs a page, node B imports the pack and
/// serves the page over the real NXP wire stack.
#[test]
fn node_a_to_node_b_serves_page() {
    use nexus_content::{Component, Metadata, Page};

    let page = Page {
        metadata: Metadata {
            schema: 1,
            site: "example".into(),
            path: "home".into(),
            title: "T".into(),
            revision: 1,
        },
        components: vec![Component::Text { text: "hi".into() }],
        capabilities: vec![],
    };
    let body = page.to_canonical_json().unwrap();

    // Node A: store + export to a pack file.
    let dir_a = tmp_dir("node-a");
    let dir_b = tmp_dir("node-b");
    let dir_pack = tmp_dir("pack");
    let node_a = FsStore::new(&dir_a);
    let node_b = FsStore::new(&dir_b);
    let id = node_a.put(&body).unwrap();
    let pack = node_a.export(std::slice::from_ref(&id)).unwrap();
    let pack_file = dir_pack.join("example-home.nxpack");
    std::fs::write(&pack_file, &pack).unwrap();

    // Node B: import the pack file (attacker-controlled bytes) and serve.
    let imported = node_b.import(&std::fs::read(&pack_file).unwrap()).unwrap();
    assert_eq!(imported.blobs, 1);
    assert_eq!(node_b.get(&id).unwrap(), body); // store-level assert

    let mut pages: HashMap<(String, String), Vec<u8>> = HashMap::new();
    pages.insert(("example".into(), "home".into()), node_b.get(&id).unwrap());

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let line = nexus_transport::read_line_limited(&mut reader).unwrap();
        let response = match nexus_protocol::parse_request(&line) {
            Ok(req) => match pages.get(&(req.site, req.path)) {
                Some(b) => nexus_protocol::encode_response(200, b).unwrap(),
                None => nexus_protocol::encode_response(404, b"not found").unwrap(),
            },
            Err(_) => nexus_protocol::encode_response(400, b"bad request").unwrap(),
        };
        stream.write_all(&response).unwrap();
        stream.flush().unwrap();
    });

    let req = nexus_protocol::FetchRequest {
        site: "example".into(),
        path: "home".into(),
        if_id: None,
    };
    let (code, got) = nexus_transport::fetch(addr, &req).unwrap();
    assert_eq!(code, 200);
    let served = nexus_content::Page::from_json(&got).unwrap();
    assert_eq!(served.metadata.site, "example");
    assert_eq!(served.metadata.path, "home");
    assert_eq!(got, body);

    cleanup(&dir_a);
    cleanup(&dir_b);
    cleanup(&dir_pack);
}
