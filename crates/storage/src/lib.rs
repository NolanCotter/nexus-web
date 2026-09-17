//! Immutable content-addressed store: bytes in, content ID out.
//!
//! Prototype is in-memory + optional filesystem persistence.
//! Content IDs are `b3:<hex(blake3)>`. Verification is hash recomputation.
//!
//! # NXPACK1 replication packs
//!
//! `FsStore::export` packs blobs into a single file; `FsStore::import` loads
//! one back. Both speak one format (all integers little-endian, no padding):
//!
//! ```text
//! magic   7 bytes  "NXPACK1"
//! count   u32      number of blobs
//! per blob:
//!   len   u32      payload length in bytes
//!   id    32 bytes raw BLAKE3 content id (payload with the "b3:" prefix)
//!   data  len bytes
//! ```
//!
//! The embedded id is what makes verify-on-import sound: import re-hashes
//! every payload and rejects the whole pack unless each id matches, before
//! any byte is stored. Trailing data is rejected. Individual blobs are capped
//! at [`MAX_BLOB`] and the whole pack at [`MAX_PACK`] (64 MiB). Input is
//! attacker-controlled: the import path is total (parse errors, no panics).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
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
}

pub const MAX_BLOB: usize = 4 * 1024 * 1024;

/// NXPACK1 magic bytes (7 bytes).
pub const PACK_MAGIC: &[u8; 7] = b"NXPACK1";

/// Raw content-id size used by packs (BLAKE3 output, no `b3:` prefix).
pub const PACK_ID_LEN: usize = blake3::OUT_LEN;

/// Total packed size cap: header + count + all ids + all payloads.
pub const MAX_PACK: usize = 64 * 1024 * 1024;

/// Fixed header size: magic + count.
pub const PACK_HEADER_LEN: usize = PACK_MAGIC.len() + 4;

/// Per-blob framing overhead: len + id.
pub const PACK_ENTRY_OVERHEAD: usize = 4 + PACK_ID_LEN;

/// Result of an `import`: how much of the pack was consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportReport {
    /// Number of blobs stored (or already present).
    pub blobs: usize,
    /// Sum of payload bytes stored.
    pub total_bytes: usize,
}

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

/// Filesystem-backed CAS dir: `<dir>/<first2>/<rest>` (hex after `b3:`).
#[derive(Debug, Clone)]
pub struct FsStore {
    dir: PathBuf,
}

impl FsStore {
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

    pub fn get(&self, id: &str) -> Result<Vec<u8>, StoreError> {
        let path = self.path_for(id)?;
        let bytes = std::fs::read(&path).map_err(|_| StoreError::NotFound(id.to_string()))?;
        MemStore::verify(id, &bytes)?;
        Ok(bytes)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Pack the given content ids into one NXPACK1 file (see module docs).
    ///
    /// Every id must exist, or the export errors. Total pack size (header +
    /// ids + payloads) is capped at [`MAX_PACK`]; individual blobs keep the
    /// [`MAX_BLOB`] cap. Blobs are re-hashed on the way out, so a tampered
    /// file on disk fails export (verify-on-read).
    pub fn export(&self, ids: &[String]) -> Result<Vec<u8>, StoreError> {
        let count = u32::try_from(ids.len()).map_err(|_| StoreError::TooLarge(ids.len()))?;
        let mut out = Vec::with_capacity(
            PACK_HEADER_LEN
                .saturating_add(ids.len().saturating_mul(PACK_ENTRY_OVERHEAD))
                .min(MAX_PACK),
        );
        out.extend_from_slice(PACK_MAGIC);
        out.extend_from_slice(&count.to_le_bytes());
        let mut total = PACK_HEADER_LEN;
        for id in ids {
            let bytes = self.get(id)?;
            let len = bytes.len();
            if len > MAX_BLOB {
                return Err(StoreError::TooLarge(len));
            }
            total += PACK_ENTRY_OVERHEAD + len;
            if total > MAX_PACK {
                return Err(StoreError::TooLarge(total));
            }
            out.extend_from_slice(&(len as u32).to_le_bytes());
            out.extend_from_slice(blake3::hash(&bytes).as_bytes());
            out.extend_from_slice(&bytes);
        }
        Ok(out)
    }

    /// Load an NXPACK1 file, storing every blob it carries (see module docs).
    ///
    /// The whole pack is parsed and every payload is re-hashed against its
    /// embedded id before anything is written: a single flipped byte, a
    /// truncated file, an overlarge blob, or trailing garbage all reject the
    /// entire pack and leave the store untouched. Bytes are never `unwrap`ed.
    pub fn import(&self, pack: &[u8]) -> Result<ImportReport, StoreError> {
        if pack.len() > MAX_PACK {
            return Err(StoreError::TooLarge(pack.len()));
        }
        let mut pos = 0usize;
        if pack.len() < PACK_MAGIC.len() || &pack[..PACK_MAGIC.len()] != PACK_MAGIC {
            return Err(StoreError::Corrupt("bad magic".into()));
        }
        pos += PACK_MAGIC.len();
        let count = read_pack_u32(pack, &mut pos)?;
        // count is attacker-controlled: cap the pre-allocation, never the loop.
        let mut blobs: Vec<(String, Vec<u8>)> = Vec::with_capacity(count.min(1024) as usize);
        let mut total_bytes = 0usize;
        for _ in 0..count {
            let len = read_pack_u32(pack, &mut pos)? as usize;
            if len > MAX_BLOB {
                return Err(StoreError::TooLarge(len));
            }
            let raw_id = read_pack_bytes(pack, &mut pos, PACK_ID_LEN)?;
            let payload = read_pack_bytes(pack, &mut pos, len)?;
            let digest = blake3::hash(payload);
            let actual = digest.as_bytes();
            if raw_id != actual {
                return Err(StoreError::Corrupt(format!(
                    "hash mismatch: expected {}, computed {}",
                    hex::encode(raw_id),
                    hex::encode(actual)
                )));
            }
            total_bytes = total_bytes
                .checked_add(len)
                .ok_or_else(|| StoreError::Corrupt("total overflow".into()))?;
            blobs.push((format!("b3:{}", hex::encode(raw_id)), payload.to_vec()));
        }
        if pos != pack.len() {
            return Err(StoreError::Corrupt(format!(
                "{} trailing bytes",
                pack.len() - pos
            )));
        }
        // Verification completed above; only now touch the store.
        for (_, bytes) in &blobs {
            self.put(bytes)?; // idempotent; content hashes to the verified id
        }
        Ok(ImportReport {
            blobs: blobs.len(),
            total_bytes,
        })
    }
}

/// Read 4 little-endian bytes as `u32` from a pack, bounds-checked.
fn read_pack_u32(pack: &[u8], pos: &mut usize) -> Result<u32, StoreError> {
    let bytes = read_pack_bytes(pack, pos, 4)?;
    let fixed: [u8; 4] = bytes
        .try_into()
        .map_err(|_| StoreError::Corrupt("bad length field".into()))?;
    Ok(u32::from_le_bytes(fixed))
}

/// Bounds-checked slice read that advances `pos`.
fn read_pack_bytes<'a>(
    pack: &'a [u8],
    pos: &mut usize,
    len: usize,
) -> Result<&'a [u8], StoreError> {
    let end = pos
        .checked_add(len)
        .ok_or_else(|| StoreError::Corrupt("length overflow".into()))?;
    if end > pack.len() {
        return Err(StoreError::Corrupt("truncated pack".into()));
    }
    let out = &pack[*pos..end];
    *pos = end;
    Ok(out)
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
