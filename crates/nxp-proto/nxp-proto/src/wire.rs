//! Low-level codec: bounds-checked big-endian + LEB128 varint reader/writer.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    UnexpectedEof,
    VarintOverflow,
    LengthOverflow { max: usize, got: usize },
    BadUtf8,
    InvalidTag(u8),
    TrailingData,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::UnexpectedEof => write!(f, "unexpected end of input"),
            WireError::VarintOverflow => write!(f, "varint too long or non-minimal"),
            WireError::LengthOverflow { max, got } => {
                write!(f, "length {got} exceeds max {max}")
            }
            WireError::BadUtf8 => write!(f, "invalid utf-8"),
            WireError::InvalidTag(b) => write!(f, "invalid tag 0x{b:02x}"),
            WireError::TrailingData => write!(f, "trailing bytes after record"),
        }
    }
}

impl std::error::Error for WireError {}

/// Borrowing, bounds-checked reader over a byte slice.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::UnexpectedEof)?;
        let slice = self.buf.get(self.pos..end).ok_or(WireError::UnexpectedEof)?;
        self.pos = end;
        Ok(slice)
    }

    pub fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    pub fn be_u16(&mut self) -> Result<u16, WireError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn be_u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn be_u64(&mut self) -> Result<u64, WireError> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// LEB128 unsigned varint, max 10 bytes; rejects non-minimal top bytes.
    pub fn varint(&mut self) -> Result<u64, WireError> {
        let mut out: u64 = 0;
        for i in 0..10u32 {
            let b = self.u8()?;
            if i == 9 && (b & 0x7e) != 0 {
                return Err(WireError::VarintOverflow);
            }
            out |= u64::from(b & 0x7f) << (i * 7);
            if b & 0x80 == 0 {
                return Ok(out);
            }
        }
        Err(WireError::VarintOverflow)
    }

    /// Length-prefixed byte string, bounded by `max` (checked before allocation).
    pub fn lenstr(&mut self, max: usize) -> Result<&'a [u8], WireError> {
        let len = usize::try_from(self.varint()?)
            .map_err(|_| WireError::LengthOverflow { max, got: usize::MAX })?;
        if len > max {
            return Err(WireError::LengthOverflow { max, got: len });
        }
        self.take(len)
    }

    /// Length-prefixed UTF-8 string, bounded by `max`.
    pub fn str(&mut self, max: usize) -> Result<&'a str, WireError> {
        let b = self.lenstr(max)?;
        std::str::from_utf8(b).map_err(|_| WireError::BadUtf8)
    }
}

/// Growable big-endian + varint writer.
#[derive(Default)]
pub struct Writer {
    out: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(&mut self, b: u8) {
        self.out.push(b);
    }

    pub fn be_u16(&mut self, v: u16) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }

    pub fn be_u32(&mut self, v: u32) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }

    pub fn be_u64(&mut self, v: u64) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }

    pub fn varint(&mut self, mut v: u64) {
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                self.out.push(byte);
                return;
            }
            self.out.push(byte | 0x80);
        }
    }

    pub fn lenstr(&mut self, s: &[u8]) {
        self.varint(s.len() as u64);
        self.out.extend_from_slice(s);
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        let vals = [0u64, 1, 127, 128, 300, u32::MAX as u64, u64::MAX];
        for v in vals {
            let mut w = Writer::new();
            w.varint(v);
            let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
            assert_eq!(r.varint().unwrap(), v);
            assert_eq!(r.remaining(), 0);
        }
    }

    #[test]
    fn varint_rejects_overflow_and_eof() {
        let eleven_continuations = [0x80u8; 11];
        let mut r = Reader::new(&eleven_continuations);
        assert_eq!(r.varint(), Err(WireError::VarintOverflow));

        let mut r = Reader::new(&[0x80u8]); // continuation, then EOF
        assert_eq!(r.varint(), Err(WireError::UnexpectedEof));
    }

    #[test]
    fn lenstr_and_ints() {
        let mut w = Writer::new();
        w.be_u64(0x0102030405060708);
        w.lenstr(b"hello");
        w.u8(0xff);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.be_u64().unwrap(), 0x0102030405060708);
        assert_eq!(r.lenstr(16).unwrap(), b"hello");
        assert_eq!(r.u8().unwrap(), 0xff);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn lenstr_enforces_max() {
        let mut w = Writer::new();
        w.lenstr(b"toolong");
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.lenstr(4), Err(WireError::LengthOverflow { max: 4, got: 7 }));
    }

    #[test]
    fn str_rejects_bad_utf8() {
        let mut w = Writer::new();
        w.lenstr(&[0xff, 0xfe]);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.str(8), Err(WireError::BadUtf8));
    }
}