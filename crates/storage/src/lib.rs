//! Immutable content-addressed store: bytes in, content ID out.
//!
//! Prototype is in-memory + optional filesystem persistence.
//! Content IDs are `b3:<hex(blake3)>`. Verification is hash recomputation.
//!
//! `FsStore` hardening (Milestone A+):
//! - restrictive permissions on unix: dirs `0700`, blob files `0600`.
//! - optional per-store quota (`max_bytes`, `max_blobs`) enforced by
//!   evicting unpinned blobs oldest-first before each write.
//! - eviction order uses file mtime as a heuristic for insertion age
//!   (mtime can be altered externally; treat as best-effort, not security).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("io: {0}")]
    Io(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("too large: {0} bytes")]
    TooLarge(usize),
    #[error("corrupt: {0}")]
    Corrupt(String),
    #[error("quota exceeded: {0}")]
    QuotaExceeded(String),
}

pub const MAX_BLOB: usize = 4 * 1024 * 1024;

pub fn id_of(bytes: &[u8]) -> String {
    format!("b3:{}", hex::encode(blake3::hash(bytes).as_bytes()))
}

#[derive(Debug, Default)]
pub struct MemStore {
    blobs: HashMap<String, Vec<u8>>,
}

impl MemStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&mut self, bytes: &[u8]) -> Result<String, StoreError> {
        if bytes.len() > MAX_BLOB {
            return Err(StoreError::TooLarge(bytes.len()));
        }
        let id = id_of(bytes);
        self.blobs
            .entry(id.clone())
            .or_insert_with(|| bytes.to_vec());
        Ok(id)
    }

    pub fn get(&self, id: &str) -> Result<&[u8], StoreError> {
        self.blobs
            .get(id)
            .map(Vec::as_slice)
            .ok_or_else(|| StoreError::NotFound(id.to_string()))
    }

    /// Verify bytes match their claimed ID (constant-time-ish compare).
    pub fn verify(id: &str, bytes: &[u8]) -> Result<(), StoreError> {
        let actual = id_of(bytes);
        if actual == id {
            Ok(())
        } else {
            Err(StoreError::Corrupt(format!(
                "expected {id}, computed {actual}"
            )))
        }
    }

    pub fn len(&self) -> usize {
        self.blobs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty()
    }
}

#[derive(Debug)]
struct FsInner {
    dir: PathBuf,
    max_bytes: Option<u64>,
    max_blobs: Option<usize>,
    pinned: Mutex<HashSet<String>>,
}

/// Filesystem-backed CAS dir: `<dir>/<first2>/<rest>` (hex after `b3:`).
#[derive(Debug, Clone)]
pub struct FsStore {
    inner: std::sync::Arc<FsInner>,
}

impl FsStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            inner: std::sync::Arc::new(FsInner {
                dir: dir.into(),
                max_bytes: None,
                max_blobs: None,
                pinned: Mutex::new(HashSet::new()),
            }),
        }
    }

    /// Set per-store quota. `None` disables that dimension.
    /// Quota is enforced by evicting unpinned blobs oldest-first
    /// (mtime heuristic) before each write.
    pub fn with_quota(self, max_bytes: Option<u64>, max_blobs: Option<usize>) -> Self {
        let pinned = self.inner.pinned.lock().unwrap().clone();
        Self {
            inner: std::sync::Arc::new(FsInner {
                dir: self.inner.dir.clone(),
                max_bytes,
                max_blobs,
                pinned: Mutex::new(pinned),
            }),
        }
    }

    /// Pin a blob ID so quota eviction never removes it.
    pub fn pin(&self, id: &str) {
        self.inner.pinned.lock().unwrap().insert(id.to_string());
    }

    pub fn unpin(&self, id: &str) {
        self.inner.pinned.lock().unwrap().remove(id);
    }

    pub fn is_pinned(&self, id: &str) -> bool {
        self.inner.pinned.lock().unwrap().contains(id)
    }

    fn path_for(&self, id: &str) -> Result<PathBuf, StoreError> {
        let hex_part = id
            .strip_prefix("b3:")
            .ok_or_else(|| StoreError::Corrupt(format!("bad content id {id}")))?;
        if hex_part.len() != 64 || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(StoreError::Corrupt(format!("bad content id {id}")));
        }
        // Reject path traversal defensively (hex check already covers it).
        if id.contains('/') || id.contains('.') {
            return Err(StoreError::Corrupt("bad content id".into()));
        }
        Ok(self.inner.dir.join(&hex_part[..2]).join(&hex_part[2..]))
    }

    fn ensure_dir(&self, path: &Path) -> Result<(), StoreError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            let mut b = std::fs::DirBuilder::new();
            b.recursive(true).mode(0o700);
            b.create(path).map_err(|e| StoreError::Io(e.to_string()))?;
            // Harden pre-existing dirs that may have wider perms.
            for p in [path, &self.inner.dir] {
                let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
            }
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(path).map_err(|e| StoreError::Io(e.to_string()))?;
        }
        Ok(())
    }

    fn write_restricted(&self, tmp: &Path, bytes: &[u8]) -> Result<(), StoreError> {
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(tmp)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            f.write_all(bytes)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            // Belt-and-braces: umask can only narrow `mode`, but an
            // attacker-precreated tmp could be wider; force 0600.
            std::fs::set_permissions(tmp, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| StoreError::Io(e.to_string()))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(tmp, bytes).map_err(|e| StoreError::Io(e.to_string()))?;
        }
        Ok(())
    }

    /// List live blobs as `(id, path, size, mtime)`. Skips `*.tmp` files
    /// from interrupted writes.
    fn inventory(&self) -> Result<Vec<(String, PathBuf, u64, SystemTime)>, StoreError> {
        let mut out = Vec::new();
        let root = self.inner.dir.clone();
        let top = match std::fs::read_dir(&root) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(StoreError::Io(e.to_string())),
        };
        for shard in top {
            let shard = shard.map_err(|e| StoreError::Io(e.to_string()))?;
            let shard_name = shard.file_name().to_string_lossy().into_owned();
            if shard_name.len() != 2 || !shard_name.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            if !shard
                .file_type()
                .map_err(|e| StoreError::Io(e.to_string()))?
                .is_dir()
            {
                continue;
            }
            let inner =
                std::fs::read_dir(shard.path()).map_err(|e| StoreError::Io(e.to_string()))?;
            for ent in inner {
                let ent = ent.map_err(|e| StoreError::Io(e.to_string()))?;
                if !ent
                    .file_type()
                    .map_err(|e| StoreError::Io(e.to_string()))?
                    .is_file()
                {
                    continue;
                }
                let name = ent.file_name().to_string_lossy().into_owned();
                if name.ends_with(".tmp") || name.len() != 62 {
                    continue;
                }
                if !name.chars().all(|c| c.is_ascii_hexdigit()) {
                    continue;
                }
                let meta =
                    std::fs::metadata(ent.path()).map_err(|e| StoreError::Io(e.to_string()))?;
                out.push((
                    format!("b3:{shard_name}{name}"),
                    ent.path(),
                    meta.len(),
                    meta.modified().unwrap_or(UNIX_EPOCH),
                ));
            }
        }
        Ok(out)
    }

    /// Evict unpinned blobs oldest-first (mtime heuristic, id tiebreak)
    /// until `incoming_len` bytes plus one blob fit. Errors without
    /// evicting anything if the blob alone exceeds quota.
    fn ensure_quota(&self, incoming_len: usize) -> Result<(), StoreError> {
        let (max_bytes, max_blobs) = (self.inner.max_bytes, self.inner.max_blobs);
        if max_bytes.is_none() && max_blobs.is_none() {
            return Ok(());
        }
        if let Some(m) = max_bytes {
            if incoming_len as u64 > m {
                return Err(StoreError::QuotaExceeded(format!(
                    "blob {incoming_len}B exceeds max_bytes {m}B"
                )));
            }
        }
        if let Some(m) = max_blobs {
            if m == 0 {
                return Err(StoreError::QuotaExceeded("max_blobs is 0".into()));
            }
        }
        let mut inv = self.inventory()?;
        let mut total: u64 = inv.iter().map(|(_, _, s, _)| s).sum();
        let mut count = inv.len();
        let fits = |total: u64, count: usize| {
            max_bytes.map_or(true, |m| total + incoming_len as u64 <= m)
                && max_blobs.map_or(true, |m| count + 1 <= m)
        };
        if fits(total, count) {
            return Ok(());
        }
        // Oldest-first via mtime (id tiebreak for same-tick files).
        inv.sort_by(|a, b| a.3.cmp(&b.3).then_with(|| a.0.cmp(&b.0)));
        let pinned = self.inner.pinned.lock().unwrap();
        for (id, path, size, _) in &inv {
            if fits(total, count) {
                break;
            }
            if pinned.contains(id) {
                continue;
            }
            match std::fs::remove_file(path) {
                Ok(()) => {
                    total = total.saturating_sub(*size);
                    count = count.saturating_sub(1);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    count = count.saturating_sub(1);
                }
                Err(e) => return Err(StoreError::Io(e.to_string())),
            }
        }
        if fits(total, count) {
            Ok(())
        } else {
            Err(StoreError::QuotaExceeded(
                "quota full and only pinned blobs remain".into(),
            ))
        }
    }

    pub fn put(&self, bytes: &[u8]) -> Result<String, StoreError> {
        if bytes.len() > MAX_BLOB {
            return Err(StoreError::TooLarge(bytes.len()));
        }
        let id = id_of(bytes);
        let path = self.path_for(&id)?;
        if path.exists() {
            return Ok(id);
        }
        if let Some(parent) = path.parent() {
            self.ensure_dir(parent)?;
        }
        self.ensure_quota(bytes.len())?;
        // Write to temp file then rename (atomic publish).
        let tmp = path.with_extension("tmp");
        self.write_restricted(&tmp, bytes)?;
        std::fs::rename(&tmp, &path).map_err(|e| StoreError::Io(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(id)
    }

    pub fn get(&self, id: &str) -> Result<Vec<u8>, StoreError> {
        let path = self.path_for(id)?;
        let bytes = std::fs::read(&path).map_err(|_| StoreError::NotFound(id.to_string()))?;
        MemStore::verify(id, &bytes)?;
        Ok(bytes)
    }

    /// Number of live blobs (excludes stray `*.tmp` files).
    pub fn blob_count(&self) -> Result<usize, StoreError> {
        Ok(self.inventory()?.len())
    }

    /// Total live blob bytes.
    pub fn total_bytes(&self) -> Result<u64, StoreError> {
        Ok(self.inventory()?.iter().map(|(_, _, s, _)| s).sum())
    }

    pub fn dir(&self) -> &Path {
        &self.inner.dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static N: AtomicU64 = AtomicU64::new(0);

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nexus-cas-{}-{}-{}",
            std::process::id(),
            tag,
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn nap() {
        // Separate mtimes for oldest-first ordering (ns-granular FS: ms is plenty).
        std::thread::sleep(std::time::Duration::from_millis(30));
    }

    #[test]
    fn mem_put_get_roundtrip() {
        let mut s = MemStore::new();
        let id = s.put(b"hello").unwrap();
        assert!(id.starts_with("b3:"));
        assert_eq!(s.get(&id).unwrap(), b"hello");
    }

    #[test]
    fn dedup_same_bytes() {
        let mut s = MemStore::new();
        let a = s.put(b"same").unwrap();
        let b = s.put(b"same").unwrap();
        assert_eq!(a, b);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn rejects_missing() {
        let s = MemStore::new();
        assert!(matches!(
            s.get("b3:0000000000000000000000000000000000000000000000000000000000000000"),
            Err(StoreError::NotFound(_))
        ));
    }

    #[test]
    fn verify_catches_tamper() {
        assert!(MemStore::verify(&id_of(b"a"), b"b").is_err());
    }

    #[test]
    fn fs_roundtrip() {
        let dir = tmpdir("roundtrip");
        let fs = FsStore::new(&dir);
        let id = fs.put(b"persistent").unwrap();
        assert_eq!(fs.get(&id).unwrap(), b"persistent");
        // second put is idempotent
        assert_eq!(fs.put(b"persistent").unwrap(), id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fs_rejects_traversal_id() {
        let fs = FsStore::new("/tmp/nexus-test-nope");
        assert!(fs.get("b3:../evil").is_err());
        assert!(fs.get("nope").is_err());
    }

    #[test]
    fn fs_detects_corruption_on_read() {
        let dir = tmpdir("corrupt");
        let fs = FsStore::new(&dir);
        let id = fs.put(b"integrity-matters").unwrap();
        assert_eq!(fs.get(&id).unwrap(), b"integrity-matters");
        // Flip a byte directly on disk, bypassing the store.
        let hex_part = id.strip_prefix("b3:").unwrap();
        let path = dir.join(&hex_part[..2]).join(&hex_part[2..]);
        let mut raw = std::fs::read(&path).unwrap();
        raw[0] ^= 0xff;
        std::fs::write(&path, &raw).unwrap();
        match fs.get(&id) {
            Err(StoreError::Corrupt(_)) => {}
            other => panic!("expected Corrupt, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn fs_restrictive_perms() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("perms");
        let fs = FsStore::new(&dir);
        let id = fs.put(b"secret-bytes").unwrap();
        let root_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(root_mode, 0o700, "store root should be 0700");
        let hex_part = id.strip_prefix("b3:").unwrap();
        let shard = dir.join(&hex_part[..2]);
        let shard_mode = std::fs::metadata(&shard).unwrap().permissions().mode() & 0o777;
        assert_eq!(shard_mode, 0o700, "shard dir should be 0700");
        let file_mode = std::fs::metadata(shard.join(&hex_part[2..]))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600, "blob file should be 0600");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fs_quota_count_evicts_oldest_first() {
        let dir = tmpdir("quota-count");
        let fs = FsStore::new(&dir).with_quota(None, Some(2));
        let a = fs.put(b"blob-a-quota").unwrap();
        nap();
        let b = fs.put(b"blob-b-quota").unwrap();
        nap();
        let c = fs.put(b"blob-c-quota").unwrap();
        assert_eq!(fs.blob_count().unwrap(), 2);
        // Oldest (a) evicted; newest two survive.
        assert!(matches!(fs.get(&a), Err(StoreError::NotFound(_))));
        assert_eq!(fs.get(&b).unwrap(), b"blob-b-quota");
        assert_eq!(fs.get(&c).unwrap(), b"blob-c-quota");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fs_quota_bytes_evicts_until_fits() {
        let dir = tmpdir("quota-bytes");
        let small = vec![0x11u8; 64];
        let fs = FsStore::new(&dir).with_quota(Some(200), None);
        let a = fs.put(&small).unwrap();
        nap();
        let b_blob = vec![0x22u8; 64];
        let b = fs.put(&b_blob).unwrap();
        nap();
        let c_blob = vec![0x33u8; 100];
        let c = fs.put(&c_blob).unwrap();
        assert!(fs.total_bytes().unwrap() <= 200);
        // a (oldest, 64B) evicted to fit c: 64+100=164 <= 200.
        assert!(matches!(fs.get(&a), Err(StoreError::NotFound(_))));
        assert_eq!(fs.get(&b).unwrap(), b_blob);
        assert_eq!(fs.get(&c).unwrap(), c_blob);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fs_quota_single_blob_over_limit_errors_without_wipe() {
        let dir = tmpdir("quota-oversize");
        let fs = FsStore::new(&dir).with_quota(Some(16), Some(10));
        let keep = fs.put(b"keep-me").unwrap();
        match fs.put(&[9u8; 64]) {
            Err(StoreError::QuotaExceeded(_)) => {}
            other => panic!("expected QuotaExceeded, got {other:?}"),
        }
        // Pre-existing blob untouched.
        assert_eq!(fs.get(&keep).unwrap(), b"keep-me");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fs_quota_pinned_survives_and_blocks_when_nothing_evictable() {
        let dir = tmpdir("quota-pin");
        let fs = FsStore::new(&dir).with_quota(None, Some(1));
        let a = fs.put(b"pinned-blob").unwrap();
        fs.pin(&a);
        // Unpinned newcomer cannot displace the pinned blob.
        match fs.put(b"newcomer-blob") {
            Err(StoreError::QuotaExceeded(_)) => {}
            other => panic!("expected QuotaExceeded, got {other:?}"),
        }
        assert_eq!(fs.get(&a).unwrap(), b"pinned-blob");
        // After unpin, oldest-first eviction proceeds.
        fs.unpin(&a);
        nap();
        let b = fs.put(b"newcomer-blob").unwrap();
        assert!(matches!(fs.get(&a), Err(StoreError::NotFound(_))));
        assert_eq!(fs.get(&b).unwrap(), b"newcomer-blob");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fs_quota_dedup_put_does_not_evict() {
        let dir = tmpdir("quota-dedup");
        let fs = FsStore::new(&dir).with_quota(None, Some(1));
        let a = fs.put(b"only-blob").unwrap();
        assert_eq!(fs.put(b"only-blob").unwrap(), a);
        assert_eq!(fs.blob_count().unwrap(), 1);
        assert_eq!(fs.get(&a).unwrap(), b"only-blob");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
