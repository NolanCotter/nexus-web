//! Security hardening battery for `FsStore`: adversarial content ids,
//! hash-mismatch-on-read, symlink-planted blob paths, and hostile NXPACK1
//! imports. Contract: errors (never panic), and no byte ever leaves the
//! store unless it re-hashes to the requested id.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use nexus_storage::{FsStore, StoreError, PACK_MAGIC};

static N: AtomicU64 = AtomicU64::new(0);

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "nx-sec-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn blob_path(dir: &Path, id: &str) -> PathBuf {
    let hex = id.trim_start_matches("b3:");
    dir.join(&hex[..2]).join(&hex[2..])
}

/// Hostile content ids: traversal shapes, wrong lengths, non-hex, and
/// encodings that could alias a filesystem path. Every one must error
/// without touching anything outside the store root.
#[test]
fn traversal_id_battery_never_touches_fs() {
    let dir = tmpdir("traversal");
    let fs = FsStore::new(&dir);
    let f = |n: usize| "f".repeat(n);
    let ids = [
        "".to_string(),
        "b3:".to_string(),
        "../secret".to_string(),
        "..\\..\\x".to_string(),
        "b3:../x".to_string(),
        "b3:..".to_string(),
        "b3:.".to_string(),
        "b3:/etc/passwd".to_string(),
        "b3:../../../../etc/passwd".to_string(),
        "b3:.".to_string(),
        format!("b3:{}", f(63)),
        format!("b3:{}", f(65)),
        format!("b3:{}", "g".repeat(64)),
        format!("b3:{}", "F".repeat(64)), // valid hex, uppercase: no such blob
        format!("b3:{}/..", f(62)),
        format!("b3:{}.json", "00".repeat(31)),
        format!("b3:{}..", f(62)),
        "B3:".to_string() + &f(64),
        format!("b3:{}\n", f(64)),
    ];
    for id in &ids {
        // Must return Err, never panic, never leak bytes.
        assert!(fs.get(id).is_err(), "id {id:?} resolved");
    }
    // No shard or blob was ever materialized by a hostile get.
    match std::fs::read_dir(&dir) {
        Ok(mut entries) => assert!(
            entries.next().is_none(),
            "hostile gets wrote to the store root"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("unexpected read_dir error: {e}"),
    }
}

/// Hash-mismatch on read: corrupting the on-disk blob at any sampled
/// position, truncating, appending, or replacing content must yield
/// `Corrupt` (or `NotFound`) — never the wrong bytes.
#[test]
fn hash_mismatch_on_read_battery() {
    let dir = tmpdir("hash-mismatch");
    let fs = FsStore::new(&dir);
    let payload = b"integrity-battery-payload-0123456789";
    let id = fs.put(payload).unwrap();
    assert_eq!(fs.get(&id).unwrap(), payload);

    // Byte flips at first/middle/last positions.
    for pos in [0usize, payload.len() / 2, payload.len() - 1] {
        let path = blob_path(&dir, &id);
        let mut raw = std::fs::read(&path).unwrap();
        raw[pos] ^= 0x01;
        std::fs::write(&path, &raw).unwrap();
        assert!(
            matches!(fs.get(&id), Err(StoreError::Corrupt(_))),
            "flip at {pos} not detected"
        );
    }
    // Truncated on disk.
    let path = blob_path(&dir, &id);
    std::fs::write(&path, &payload[..8]).unwrap();
    assert!(matches!(fs.get(&id), Err(StoreError::Corrupt(_))));
    // Appended garbage on disk.
    let mut raw = payload.to_vec();
    raw.extend_from_slice(b"EXTRA");
    std::fs::write(&path, &raw).unwrap();
    assert!(matches!(fs.get(&id), Err(StoreError::Corrupt(_))));
    // Same-length different content (plausible swap attack).
    std::fs::write(&path, vec![0x41; payload.len()]).unwrap();
    assert!(matches!(fs.get(&id), Err(StoreError::Corrupt(_))));

    // A different blob's id still resolves to exactly its own bytes.
    let id2 = fs.put(b"other-blob").unwrap();
    assert_eq!(fs.get(&id2).unwrap(), b"other-blob");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Symlink planted at a blob path: `fs::read` follows it, but the read-side
/// BLAKE3 verification means the symlink target's bytes can never be
/// exfiltrated as the requested id's content.
#[cfg(unix)]
#[test]
fn symlink_at_blob_path_cannot_exfiltrate() {
    use nexus_storage::id_of;
    let dir = tmpdir("symlink");
    let fs = FsStore::new(&dir);

    // Outside secret the store must never return.
    let secret = dir.parent().unwrap().join(format!(
        "nx-sec-secret-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::write(&secret, b"TOPSECRET-NOT-A-NEXUS-BLOB").unwrap();

    // Plant a symlink at the exact path get(&id) will read.
    let id = id_of(b"innocent-looking-blob"); // never stored
    let hex = id.trim_start_matches("b3:");
    let shard = dir.join(&hex[..2]);
    std::fs::create_dir_all(&shard).unwrap();
    std::os::unix::fs::symlink(&secret, shard.join(&hex[2..])).unwrap();

    match fs.get(&id) {
        Err(StoreError::Corrupt(_)) => {}
        other => panic!("expected Corrupt, got {other:?}"),
    }
    // And a stored blob next to it still verifies normally.
    let ok_id = fs.put(b"real-blob").unwrap();
    assert_eq!(fs.get(&ok_id).unwrap(), b"real-blob");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&secret);
}

/// Hostile NXPACK1 headers: magic/count/length claims that must never
/// panic, never pre-allocate blindly, and never store partial packs.
#[test]
fn nxpack1_header_battery() {
    let dir = tmpdir("pack-header");
    let fs = FsStore::new(&dir);
    let magic = PACK_MAGIC.as_slice();

    // Wrong or missing magic.
    assert!(matches!(fs.import(b""), Err(StoreError::Corrupt(_))));
    assert!(matches!(
        fs.import(b"NXPACK2\x00\x00\x00\x01"),
        Err(StoreError::Corrupt(_))
    ));
    // Magic only: count field truncated.
    assert!(matches!(fs.import(magic), Err(StoreError::Corrupt(_))));
    // Magic + count = 0: valid empty pack.
    let mut empty = magic.to_vec();
    empty.extend_from_slice(&0u32.to_le_bytes());
    let report = fs.import(&empty).unwrap();
    assert_eq!(report.blobs, 0);
    // Count huge (attacker claims u32::MAX blobs): must fail fast on the
    // first truncated entry read, not pre-allocate a giant vector.
    let mut huge = magic.to_vec();
    huge.extend_from_slice(&u32::MAX.to_le_bytes());
    huge.extend_from_slice(&[0u8; 16]); // one partial entry
    assert!(matches!(fs.import(&huge), Err(StoreError::Corrupt(_))));
    // Count claims 2 but only one entry present: truncated.
    let mut two = magic.to_vec();
    two.extend_from_slice(&2u32.to_le_bytes());
    let payload = b"hello";
    two.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    two.extend_from_slice(&blake3_digest(payload));
    two.extend_from_slice(payload);
    assert!(matches!(fs.import(&two), Err(StoreError::Corrupt(_))));
    // Blob length claim exceeding the pack: rejected without allocation.
    let mut badlen = magic.to_vec();
    badlen.extend_from_slice(&1u32.to_le_bytes());
    badlen.extend_from_slice(&u32::MAX.to_le_bytes());
    badlen.extend_from_slice(&blake3_digest(payload));
    badlen.extend_from_slice(payload);
    assert!(matches!(fs.import(&badlen), Err(StoreError::TooLarge(_))));
    let _ = std::fs::remove_dir_all(&dir);
}

fn blake3_digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}
