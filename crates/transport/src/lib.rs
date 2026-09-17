//! TCP transport framing for NXP.
//!
//! Frame on the wire: ASCII header line + raw body bytes.
//! Helpers read exactly one request line (server) or one response (client)
//! with strict size limits to prevent resource exhaustion.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use nexus_protocol as nxp;
use thiserror::Error;

/// Transport failures: protocol violations vs. underlying I/O.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Peer sent bytes that fail [`nexus_protocol`] parsing/limits.
    #[error("protocol: {0}")]
    Protocol(#[from] nxp::ProtocolError),
    /// Socket/read/write failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Timeout for establishing a TCP connection.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Timeout for a single socket read/write during FETCH.
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Read a single `\n`-terminated line, enforcing MAX_LINE.
pub fn read_line_limited<R: BufRead>(r: &mut R) -> Result<String, TransportError> {
    let mut buf = Vec::with_capacity(256);
    let mut total = 0usize;
    loop {
        let mut byte = [0u8; 1];
        match r.read_exact(&mut byte) {
            Ok(()) => {
                buf.push(byte[0]);
                total += 1;
                if total > nxp::MAX_LINE + 1 {
                    return Err(nxp::ProtocolError::LineTooLong.into());
                }
                if byte[0] == b'\n' {
                    break;
                }
            }
            Err(e) => return Err(TransportError::Io(e)),
        }
    }
    String::from_utf8(buf).map_err(|_| {
        TransportError::Protocol(nxp::ProtocolError::Malformed("non-utf8 line".into()))
    })
}

/// Read exactly `len` body bytes, enforcing MAX_BODY.
pub fn read_body<R: Read>(r: &mut R, len: usize) -> Result<Vec<u8>, TransportError> {
    if len > nxp::MAX_BODY {
        return Err(nxp::ProtocolError::BodyTooLarge(len).into());
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Client: FETCH over TCP. Returns (status code, body).
pub fn fetch<A: ToSocketAddrs>(
    addr: A,
    req: &nxp::FetchRequest,
) -> Result<(u16, Vec<u8>), TransportError> {
    let stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    writer.write_all(nxp::encode_request(req)?.as_bytes())?;
    writer.flush()?;
    let header_line = read_line_limited(&mut reader)?;
    let header = nxp::parse_response_header(&header_line)?;
    let body = read_body(&mut reader, header.body_len)?;
    Ok((header.code, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn line_reader_ok() {
        let mut c = BufReader::new(Cursor::new(b"NXP/0.1 FETCH a b\nrest"));
        let line = read_line_limited(&mut c).unwrap();
        assert_eq!(line, "NXP/0.1 FETCH a b\n");
    }

    #[test]
    fn line_reader_rejects_huge() {
        let big = vec![b'x'; nxp::MAX_LINE + 16];
        let mut c = BufReader::new(Cursor::new(big));
        assert!(read_line_limited(&mut c).is_err());
    }

    #[test]
    fn body_rejects_huge_claim() {
        let mut c = Cursor::new(vec![0u8; 8]);
        assert!(read_body(&mut c, nxp::MAX_BODY + 1).is_err());
    }
}
