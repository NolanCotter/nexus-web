//! 10-byte frame header, frame types, and the FETCH payload codec.

use crate::wire::{Reader, WireError, Writer};

/// Fixed header size: length u32 | type u8 | flags u8 | stream_id u32.
pub const HEADER_LEN: usize = 10;

/// Hard ceiling for frame payloads (16 MiB); negotiable down via settings.
pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data = 0x01,
    Headers = 0x02,
    Fetch = 0x03,
    Subscribe = 0x04,
    Update = 0x05,
    Status = 0x06,
    Ping = 0x07,
    GoAway = 0x08,
    Capabilities = 0x09, // reserved for in-connection renegotiation
    Window = 0x0A,
}

impl FrameType {
    pub fn from_u8(b: u8) -> Option<FrameType> {
        use FrameType::*;
        match b {
            0x01 => Some(Data),
            0x02 => Some(Headers),
            0x03 => Some(Fetch),
            0x04 => Some(Subscribe),
            0x05 => Some(Update),
            0x06 => Some(Status),
            0x07 => Some(Ping),
            0x08 => Some(GoAway),
            0x09 => Some(Capabilities),
            0x0A => Some(Window),
            _ => None,
        }
    }
}

/// Frame flag bits (0.1).
pub mod flags {
    pub const END_STREAM: u8 = 0x01; // last frame of this stream
    pub const END_HEADERS: u8 = 0x02; // headers block complete
    pub const INTERRUPT: u8 = 0x04; // reset the stream
    pub const SYN: u8 = 0x08; // first frame of a stream
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub len: u32,
    pub ty: FrameType,
    pub flags: u8,
    pub stream_id: u32,
}

impl FrameHeader {
    pub fn new(ty: FrameType, flags: u8, stream_id: u32, len: u32) -> Self {
        Self { len, ty, flags, stream_id }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.len.to_be_bytes());
        out.push(self.ty as u8);
        out.push(self.flags);
        out.extend_from_slice(&self.stream_id.to_be_bytes());
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let len = r.be_u32()?;
        if len > MAX_FRAME {
            return Err(WireError::LengthOverflow {
                max: MAX_FRAME as usize,
                got: len as usize,
            });
        }
        let b = r.u8()?;
        let ty = FrameType::from_u8(b).ok_or(WireError::InvalidTag(b))?;
        let flags = r.u8()?;
        let stream_id = r.be_u32()?;
        Ok(Self { len, ty, flags, stream_id })
    }
}

/// A decoded frame: header + raw payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub header: FrameHeader,
    pub payload: Vec<u8>,
}

/// FETCH payload (0.1).
///
/// Wire: `lenstr(name) lenstr(selector) varint(nranges) {u64 start, u64 end}*
///        u64(if_cursor) lenstr(hash_pin)`.
/// `end == 0` means "to EOF". `if_cursor == 0` means "no precondition".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRequest<'a> {
    pub name: &'a str,
    pub selector: &'a str,
    pub ranges: Vec<(u64, u64)>,
    pub if_cursor: u64,
    pub hash_pin: &'a [u8],
}

impl<'a> FetchRequest<'a> {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.lenstr(self.name.as_bytes());
        w.lenstr(self.selector.as_bytes());
        w.varint(self.ranges.len() as u64);
        for (start, end) in &self.ranges {
            w.be_u64(*start);
            w.be_u64(*end);
        }
        w.be_u64(self.if_cursor);
        w.lenstr(self.hash_pin);
        w.into_bytes()
    }

    pub fn decode(r: &mut Reader<'a>) -> Result<Self, WireError> {
        let name = r.str(2048)?;
        let selector = r.str(256)?;
        let n = r.varint()?;
        if n > 1024 {
            return Err(WireError::LengthOverflow { max: 1024, got: n as usize });
        }
        let mut ranges = Vec::new();
        for _ in 0..n {
            let start = r.be_u64()?;
            let end = r.be_u64()?;
            ranges.push((start, end));
        }
        let if_cursor = r.be_u64()?;
        let hash_pin = r.lenstr(64)?;
        Ok(Self { name, selector, ranges, if_cursor, hash_pin })
    }
}

/// STATUS codes (0.1): overlap HTTP where the semantics genuinely match.
pub mod status {
    pub const OK: u64 = 200;
    pub const NO_CONTENT: u64 = 204; // subscription snapshot complete
    pub const UNCHANGED: u64 = 304; // if_cursor satisfied
    pub const NOT_FOUND: u64 = 404;
    pub const CONFLICT: u64 = 409; // hash_pin mismatch, fresh record attached
    pub const PRECONDITION_FAILED: u64 = 412;
    pub const RANGE_INVALID: u64 = 416;
    pub const RATE_LIMITED: u64 = 429;
    pub const INTERNAL: u64 = 500;
    pub const UNSUPPORTED: u64 = 501;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = FrameHeader::new(FrameType::Fetch, flags::SYN, 1, 31);
        let mut buf = Vec::new();
        h.encode(&mut buf);
        let mut r = Reader::new(&buf);
        assert_eq!(FrameHeader::decode(&mut r).unwrap(), h);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn header_rejects_oversized_frame() {
        let mut w = Writer::new();
        w.be_u32(MAX_FRAME + 1);
        w.u8(FrameType::Data as u8);
        w.u8(0);
        w.be_u32(1);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(
            FrameHeader::decode(&mut r),
            Err(WireError::LengthOverflow {
                max: MAX_FRAME as usize,
                got: MAX_FRAME as usize + 1
            })
        );
    }

    #[test]
    fn fetch_roundtrip() {
        let bytes = {
            let req = FetchRequest {
                name: "NX://acme.nexus/docs/guide",
                selector: "",
                ranges: vec![(0, 0)],
                if_cursor: 42,
                hash_pin: &[],
            };
            req.encode()
        };
        let mut r = Reader::new(&bytes);
        let req = FetchRequest::decode(&mut r).unwrap();
        assert_eq!(req.name, "NX://acme.nexus/docs/guide");
        assert_eq!(req.selector, "");
        assert_eq!(req.ranges, vec![(0, 0)]);
        assert_eq!(req.if_cursor, 42);
        assert_eq!(req.hash_pin, b"");
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn fetch_rejects_many_ranges() {
        let mut w = Writer::new();
        w.lenstr(b"NX://x/y");
        w.lenstr(b"");
        w.varint(2048); // range count over the 1024 cap
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert!(FetchRequest::decode(&mut r).is_err());
    }
}