//! Async frame reader/writer over any tokio AsyncRead/Write (TCP, TLS, and
//! later QUIC streams all implement these traits).

use crate::frame::{Frame, FrameHeader, HEADER_LEN};
use crate::wire::{Reader, WireError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub struct FrameReader<R> {
    inner: R,
}

#[derive(Debug)]
pub enum FrameReadError {
    Io(std::io::Error),
    Wire(WireError),
    /// EOF in the middle of a frame: connection died mid-header or mid-payload.
    Truncated,
}

impl std::fmt::Display for FrameReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameReadError::Io(e) => write!(f, "io: {e}"),
            FrameReadError::Wire(e) => write!(f, "wire: {e}"),
            FrameReadError::Truncated => write!(f, "truncated frame"),
        }
    }
}

impl std::error::Error for FrameReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FrameReadError::Io(e) => Some(e),
            FrameReadError::Wire(_) | FrameReadError::Truncated => None,
        }
    }
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }

    /// Read `buf` fully. Ok(true) = buffer filled; Ok(false) = clean EOF at
    /// a buffer boundary; Err(Truncated) = EOF inside the buffer.
    async fn read_full(inner: &mut R, buf: &mut [u8]) -> Result<bool, FrameReadError> {
        let mut off = 0;
        while off < buf.len() {
            let n = inner.read(&mut buf[off..]).await.map_err(FrameReadError::Io)?;
            if n == 0 {
                return if off == 0 { Ok(false) } else { Err(FrameReadError::Truncated) };
            }
            off += n;
        }
        Ok(true)
    }

    /// Read one frame. `Ok(None)` = clean EOF at a frame boundary.
    pub async fn next_frame(&mut self) -> Result<Option<Frame>, FrameReadError> {
        let mut hdr = [0u8; HEADER_LEN];
        if !Self::read_full(&mut self.inner, &mut hdr).await? {
            return Ok(None);
        }
        let header = FrameHeader::decode(&mut Reader::new(&hdr)).map_err(FrameReadError::Wire)?;
        let mut payload = vec![0u8; header.len as usize];
        self.inner
            .read_exact(&mut payload)
            .await
            .map_err(FrameReadError::Io)?;
        Ok(Some(Frame { header, payload }))
    }
}

pub struct FrameWriter<R> {
    inner: R,
}

impl<R: AsyncWrite + Unpin> FrameWriter<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }

    pub async fn write_frame(&mut self, f: &Frame) -> std::io::Result<()> {
        let mut hdr = Vec::with_capacity(HEADER_LEN);
        f.header.encode(&mut hdr);
        self.inner.write_all(&hdr).await?;
        self.inner.write_all(&f.payload).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{flags, FrameType};
    use tokio::io::duplex;

    #[tokio::test]
    async fn frame_roundtrip_over_duplex() {
        let (a, b) = duplex(4096);
        let mut writer = FrameWriter::new(a);
        let mut reader = FrameReader::new(b);

        let header = FrameHeader::new(FrameType::Data, flags::END_STREAM, 1, 4);
        let frame = Frame { header, payload: vec![0xde, 0xad, 0xbe, 0xef] };

        writer.write_frame(&frame).await.unwrap();
        drop(writer); // close write half so reader sees clean EOF later

        let got = reader.next_frame().await.unwrap().unwrap();
        assert_eq!(got.header, frame.header);
        assert_eq!(got.payload, frame.payload);

        // clean EOF at boundary -> None
        assert!(reader.next_frame().await.unwrap().is_none());
    }
}