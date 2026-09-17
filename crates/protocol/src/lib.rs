//! NXP/0.1 — minimal prototype wire protocol.
//!
//! Text request line over TCP (prototype, not final):
//!   `NXP/0.1 FETCH <site> <path>\n`
//! Response:
//!   `NXP/0.1 <CODE> <LEN>\n<body bytes>`
//!
//! Limits are enforced to bound resource exhaustion (see ADR-005).

use std::fmt;

pub const VERSION: &str = "NXP/0.1";
pub const MAX_LINE: usize = 4096;
pub const MAX_BODY: usize = 1024 * 1024;
pub const MAX_SITE_LEN: usize = 64;
pub const MAX_PATH_LEN: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRequest {
    pub site: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHeader {
    pub code: u16,
    pub body_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    Empty,
    LineTooLong,
    BodyTooLarge(usize),
    BadVersion(String),
    BadVerb(String),
    BadSite(String),
    BadPath(String),
    BadCode(String),
    BadLength(String),
    Malformed(String),
    Truncated,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty request"),
            Self::LineTooLong => write!(f, "line exceeds {MAX_LINE} bytes"),
            Self::BodyTooLarge(n) => write!(f, "body {n} exceeds {MAX_BODY} bytes"),
            Self::BadVersion(v) => write!(f, "bad version: {v}"),
            Self::BadVerb(v) => write!(f, "bad verb: {v}"),
            Self::BadSite(s) => write!(f, "bad site: {s}"),
            Self::BadPath(s) => write!(f, "bad path: {s}"),
            Self::BadCode(s) => write!(f, "bad status code: {s}"),
            Self::BadLength(s) => write!(f, "bad length: {s}"),
            Self::Malformed(s) => write!(f, "malformed: {s}"),
            Self::Truncated => write!(f, "truncated frame"),
        }
    }
}

impl std::error::Error for ProtocolError {}

pub fn is_valid_site(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_SITE_LEN {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

pub fn is_valid_path(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_PATH_LEN {
        return false;
    }
    if s.starts_with('/') || s.contains("//") || s.contains("..") {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '.' | '+'))
}

pub fn encode_request(req: &FetchRequest) -> Result<String, ProtocolError> {
    if !is_valid_site(&req.site) {
        return Err(ProtocolError::BadSite(req.site.clone()));
    }
    if !is_valid_path(&req.path) {
        return Err(ProtocolError::BadPath(req.path.clone()));
    }
    Ok(format!("{VERSION} FETCH {} {}\n", req.site, req.path))
}

pub fn parse_request(line: &str) -> Result<FetchRequest, ProtocolError> {
    let line = line.strip_suffix('\n').unwrap_or(line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.is_empty() {
        return Err(ProtocolError::Empty);
    }
    if line.len() > MAX_LINE {
        return Err(ProtocolError::LineTooLong);
    }
    let mut parts = line.splitn(4, ' ');
    let version = parts.next().unwrap_or("");
    let verb = parts.next().unwrap_or("");
    let site = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    if version != VERSION {
        return Err(ProtocolError::BadVersion(version.to_string()));
    }
    if verb != "FETCH" {
        return Err(ProtocolError::BadVerb(verb.to_string()));
    }
    if !is_valid_site(site) {
        return Err(ProtocolError::BadSite(site.to_string()));
    }
    if !is_valid_path(path) {
        return Err(ProtocolError::BadPath(path.to_string()));
    }
    // Reject trailing extra tokens: path must not contain spaces (splitn(4) already),
    // and exactly 3 spaces-separated fields required.
    if site.is_empty() || path.is_empty() || path.contains(' ') {
        return Err(ProtocolError::Malformed(line.to_string()));
    }
    Ok(FetchRequest {
        site: site.to_string(),
        path: path.to_string(),
    })
}

pub fn encode_response(code: u16, body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if body.len() > MAX_BODY {
        return Err(ProtocolError::BodyTooLarge(body.len()));
    }
    if !(100..=599).contains(&code) {
        return Err(ProtocolError::BadCode(code.to_string()));
    }
    let mut out = Vec::with_capacity(32 + body.len());
    out.extend_from_slice(format!("{VERSION} {code} {}\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// Parse a response header line (without consuming body).
pub fn parse_response_header(line: &str) -> Result<ResponseHeader, ProtocolError> {
    let line = line.strip_suffix('\n').unwrap_or(line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.len() > MAX_LINE {
        return Err(ProtocolError::LineTooLong);
    }
    let mut parts = line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    let code = parts.next().unwrap_or("");
    let len = parts.next().unwrap_or("");
    if version != VERSION {
        return Err(ProtocolError::BadVersion(version.to_string()));
    }
    let code: u16 = code
        .parse()
        .map_err(|_| ProtocolError::BadCode(code.to_string()))?;
    if !(100..=599).contains(&code) {
        return Err(ProtocolError::BadCode(code.to_string()));
    }
    let body_len: usize = len
        .parse()
        .map_err(|_| ProtocolError::BadLength(len.to_string()))?;
    if body_len > MAX_BODY {
        return Err(ProtocolError::BodyTooLarge(body_len));
    }
    Ok(ResponseHeader { code, body_len })
}

/// Split a full response frame into header + body.
pub fn split_response(frame: &[u8]) -> Result<(ResponseHeader, &[u8]), ProtocolError> {
    let nl = frame
        .iter()
        .position(|&b| b == b'\n')
        .ok_or(ProtocolError::Truncated)?;
    if nl > MAX_LINE {
        return Err(ProtocolError::LineTooLong);
    }
    let header = parse_response_header(std::str::from_utf8(&frame[..=nl]).map_err(|_| {
        ProtocolError::Malformed("response header is not valid UTF-8".to_string())
    })?)?;
    let body = &frame[nl + 1..];
    if body.len() < header.body_len {
        return Err(ProtocolError::Truncated);
    }
    if body.len() > header.body_len {
        return Err(ProtocolError::Malformed(format!(
            "body has {} bytes, header claims {}",
            body.len(),
            header.body_len
        )));
    }
    Ok((header, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_request() {
        let req = FetchRequest {
            site: "example".into(),
            path: "home".into(),
        };
        let line = encode_request(&req).unwrap();
        assert_eq!(line, "NXP/0.1 FETCH example home\n");
        assert_eq!(parse_request(&line).unwrap(), req);
    }

    #[test]
    fn nested_path_ok() {
        let req = FetchRequest {
            site: "nolan".into(),
            path: "blog/hello-world".into(),
        };
        let line = encode_request(&req).unwrap();
        assert_eq!(parse_request(&line).unwrap(), req);
    }

    #[test]
    fn rejects_bad_version() {
        assert!(matches!(
            parse_request("NXP/9.9 FETCH example home\n"),
            Err(ProtocolError::BadVersion(_))
        ));
    }

    #[test]
    fn rejects_bad_verb() {
        assert!(matches!(
            parse_request("NXP/0.1 GET example home\n"),
            Err(ProtocolError::BadVerb(_))
        ));
    }

    #[test]
    fn rejects_uppercase_site() {
        assert!(matches!(
            parse_request("NXP/0.1 FETCH Example home\n"),
            Err(ProtocolError::BadSite(_))
        ));
    }

    #[test]
    fn rejects_traversal() {
        assert!(matches!(
            parse_request("NXP/0.1 FETCH example ../secret\n"),
            Err(ProtocolError::BadPath(_))
        ));
        assert!(matches!(
            parse_request("NXP/0.1 FETCH example a//b\n"),
            Err(ProtocolError::BadPath(_))
        ));
        assert!(matches!(
            parse_request("NXP/0.1 FETCH example /home\n"),
            Err(ProtocolError::BadPath(_))
        ));
    }

    #[test]
    fn rejects_injection_newline_in_site() {
        // encode path must reject spaces/newlines
        let bad = FetchRequest {
            site: "a\nINJECT".into(),
            path: "home".into(),
        };
        assert!(encode_request(&bad).is_err());
    }

    #[test]
    fn roundtrip_response() {
        let body = br#"{"hello":"world"}"#;
        let frame = encode_response(200, body).unwrap();
        let (h, b) = split_response(&frame).unwrap();
        assert_eq!(h.code, 200);
        assert_eq!(b, body);
    }

    #[test]
    fn rejects_oversize_body_claim() {
        assert!(matches!(
            parse_response_header(&format!("NXP/0.1 200 {}\n", MAX_BODY + 1)),
            Err(ProtocolError::BodyTooLarge(_))
        ));
    }

    #[test]
    fn rejects_truncated_body() {
        let mut frame = encode_response(200, b"hello").unwrap();
        frame.truncate(frame.len() - 2);
        assert!(matches!(
            split_response(&frame),
            Err(ProtocolError::Truncated)
        ));
    }

    #[test]
    fn rejects_trailing_garbage() {
        let mut frame = encode_response(200, b"hi").unwrap();
        frame.extend_from_slice(b"EXTRA");
        assert!(matches!(
            split_response(&frame),
            Err(ProtocolError::Malformed(_))
        ));
    }
}
