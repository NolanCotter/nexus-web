//! Immutable content-addressed store: bytes in, content ID out.
//!
//! Prototype is in-memory + optional filesystem persistence.
//! Content IDs are `b3:<hex(blake3)>`. Verification is hash recomputation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Store failures: I/O problems, missing blobs, oversize puts, and hash
/// mismatches (corruption or wrong ID).
#[derive(Debug, Error)]
pub enum StoreError {
    /// Filesystem operation failed (carries the OS message).
    #[error("io: {0}")]
    Io(String),
    /// No blob for this content ID.
    #[error("not found: {0}")]
    NotFound(String),
    /// Put exceeds [`MAX_BLOB`] (carries the attempted size).
    #[error("too large: {0} bytes")]
    TooLarge(usize),
    /// Bytes do not match their claimed ID, or the ID is malformed.
    #[error("corrupt: {0}")]
    Corrupt(String),
}

/// Max bytes accepted by a single put.
pub const MAX_BLOB: usize = 4 * 1024 * 1024;

/// BLAKE3 content ID (`b3:<hex>`) for raw bytes.
pub fn id_of(bytes: &[u8]) -> String {
    format!("b3:{}", hex::encode(blake3::hash(bytes).as_bytes()))
}

/// Volatile content-addressed map: bytes in, content ID out. Dedupes
/// identical blobs; verification is hash recomputation.
#[derive(Debug, Default)]
pub struct MemStore {
    blobs: HashMap<String, Vec<u8>>,
}

impl MemStore {
    /// Empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store bytes, returning their content ID. Idempotent for duplicates.
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

    /// Fetch blob bytes by content ID.
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

    /// Number of distinct blobs held.
    pub fn len(&self) -> usize {
        self.blobs.len()
    }

    /// True when no blobs are held.
    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty()
    }
}

/// Filesystem-backed CAS dir: `<dir>/<first2>/<rest>` (hex after `b3:`).
#[derive(Debug, Clone)]
pub struct FsStore {
    dir: PathBuf,
}

impl FsStore {
    /// Open (not create) a CAS directory; files materialize on [`FsStore::put`].
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
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
        Ok(self.dir.join(&hex_part[..2]).join(&hex_part[2..]))
    }

    /// Store bytes durably (atomic temp-file + rename). Idempotent.
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
            std::fs::create_dir_all(parent).map_err(|e| StoreError::Io(e.to_string()))?;
        }
        // Write to temp file then rename (atomic publish).
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, bytes).map_err(|e| StoreError::Io(e.to_string()))?;
        std::fs::rename(&tmp, &path).map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(id)
    }

    /// Fetch blob bytes by content ID, verifying the hash on read.
    pub fn get(&self, id: &str) -> Result<Vec<u8>, StoreError> {
        let path = self.path_for(id)?;
        let bytes = std::fs::read(&path).map_err(|_| StoreError::NotFound(id.to_string()))?;
        MemStore::verify(id, &bytes)?;
        Ok(bytes)
    }

    /// Backing directory root.
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let dir = std::env::temp_dir().join(format!("nexus-cas-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
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
}
