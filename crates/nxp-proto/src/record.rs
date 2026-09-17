//! Resource records: name -> (content_hash, size, cursor), signed by the
//! publisher. The signature is Ed25519 over `canonical_bytes()`, so any cache
//! can store/serve records without being trusted.

use crate::wire::{Reader, WireError, Writer};

pub const KIND_BLOB: u8 = 0;
pub const KIND_TREE: u8 = 1;
pub const KIND_STREAM: u8 = 2;
pub const KIND_NAMESPACE: u8 = 3;

pub const ENC_IDENTITY: u8 = 0;
pub const ENC_DEFLATE: u8 = 1;
pub const ENC_ZSTD: u8 = 2;

/// max serialized record size (setting MAX_RECORD, default 64 KiB)
pub const MAX_RECORD: usize = 64 * 1024;
/// max Ed25519 signature length (sigs are 64 bytes; slack for future schemes)
pub const MAX_SIGNATURE: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub name: String,
    pub selector: String,
    pub kind: u8,
    /// multihash-style: hash-id byte + varint digest length + digest
    /// (blake3 = 0x1e, 32-byte digest).
    pub content_hash: Vec<u8>,
    pub size: u64,
    pub encoding: u8,
    pub mime: String,
    /// Publisher-monotonic version; caches revalidate against this exactly.
    pub cursor: u64,
    /// Previous cursor; 0 = none. Links records into a per-name hash chain
    /// for rollback/fork detection.
    pub prev_cursor: u64,
    /// Ed25519 over canonical_bytes(); empty on unsigned (test) records.
    pub signature: Vec<u8>,
    /// Extension TLVs: (id, value). Ids are registered; 0.x = reserved.
    pub meta: Vec<(u64, Vec<u8>)>,
}

impl ResourceRecord {
    /// Deterministic bytes that get signed. Field order is fixed and must never
    /// change within a protocol version.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.lenstr(self.name.as_bytes());
        w.lenstr(self.selector.as_bytes());
        w.u8(self.kind);
        w.lenstr(&self.content_hash);
        w.be_u64(self.size);
        w.u8(self.encoding);
        w.lenstr(self.mime.as_bytes());
        w.be_u64(self.cursor);
        w.be_u64(self.prev_cursor);
        w.varint(self.meta.len() as u64);
        for (id, val) in &self.meta {
            w.varint(*id);
            w.lenstr(val);
        }
        w.into_bytes()
    }

    /// Wire form: `lenstr(canonical) lenstr(signature)` — self-delimiting,
    /// so decoding does not depend on the canonical encoding being a prefix.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let canon = self.canonical_bytes();
        w.lenstr(&canon);
        w.lenstr(&self.signature);
        w.into_bytes()
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let canon = r.lenstr(MAX_RECORD)?;
        let sig = r.lenstr(MAX_SIGNATURE)?.to_vec();
        let mut cr = Reader::new(canon);
        let rec = Self::decode_canonical(&mut cr)?;
        if cr.remaining() != 0 || r.remaining() != 0 {
            return Err(WireError::TrailingData);
        }
        Ok(Self { signature: sig, ..rec })
    }

    fn decode_canonical(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let name = r.str(2048)?.to_owned();
        let selector = r.str(256)?.to_owned();
        let kind = r.u8()?;
        let content_hash = r.lenstr(64)?.to_vec();
        let size = r.be_u64()?;
        let encoding = r.u8()?;
        let mime = r.str(128)?.to_owned();
        let cursor = r.be_u64()?;
        let prev_cursor = r.be_u64()?;
        let nmeta = r.varint()?;
        if nmeta > 256 {
            return Err(WireError::LengthOverflow { max: 256, got: nmeta as usize });
        }
        let mut meta = Vec::new();
        for _ in 0..nmeta {
            let id = r.varint()?;
            let val = r.lenstr(4096)?.to_vec();
            meta.push((id, val));
        }
        Ok(Self {
            name,
            selector,
            kind,
            content_hash,
            size,
            encoding,
            mime,
            cursor,
            prev_cursor,
            signature: Vec::new(),
            meta,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> ResourceRecord {
        let mut ch = vec![0xAAu8; 34]; // hash-id + len + 32-byte digest
        ch[0] = 0x1e; // blake3
        ch[1] = 32;
        ResourceRecord {
            name: "NX://acme.nexus/docs/guide".into(),
            selector: String::new(),
            kind: KIND_BLOB,
            content_hash: ch,
            size: 1000,
            encoding: ENC_ZSTD,
            mime: "text/markdown".into(),
            cursor: 41,
            prev_cursor: 40,
            signature: Vec::new(),
            meta: vec![(1, b"range-hash-placeholder".to_vec())],
        }
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let rec = sample_record();
        assert_eq!(rec.canonical_bytes(), rec.canonical_bytes());
    }

    #[test]
    fn record_roundtrip() {
        let rec = sample_record();
        let bytes = rec.encode();
        let mut r = Reader::new(&bytes);
        let back = ResourceRecord::decode(&mut r).unwrap();
        assert_eq!(r.remaining(), 0);
        assert_eq!(back.name, rec.name);
        assert_eq!(back.cursor, 41);
        assert_eq!(back.prev_cursor, 40);
        assert_eq!(back.content_hash, rec.content_hash);
        assert_eq!(back.encoding, ENC_ZSTD);
        assert_eq!(back.meta, rec.meta);
        assert_eq!(back.canonical_bytes(), rec.canonical_bytes());
    }

    #[test]
    fn record_trailing_bytes_rejected() {
        let rec = sample_record();
        let mut val = rec.encode();
        val.push(0x99); // junk after the record
        let mut r = Reader::new(&val);
        assert!(ResourceRecord::decode(&mut r).is_err());
    }

    #[test]
    fn record_truncated_rejected() {
        let rec = sample_record();
        let bytes = rec.encode();
        let mut r = Reader::new(&bytes[..bytes.len() - 3]);
        assert!(ResourceRecord::decode(&mut r).is_err());
    }
}