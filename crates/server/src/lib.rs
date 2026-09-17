//! Reference origin server: serves JSON pages over NXP/TCP.
//!
//! The store maps (site, path) -> canonical page bytes. The wire layer is
//! deliberately synchronous std::net for M1; concurrency is one thread per
//! connection with a strict cap.

use std::collections::HashMap;
use std::io::{BufReader, Write};
use std::net::TcpListener;

use nexus_protocol as nxp;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("transport: {0}")]
    Transport(#[from] nexus_transport::TransportError),
    #[error("protocol: {0}")]
    Protocol(#[from] nxp::ProtocolError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("content: {0}")]
    Content(String),
}

#[derive(Debug, Default, Clone)]
pub struct SiteStore {
    pages: HashMap<(String, String), Vec<u8>>,
}

impl SiteStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, site: &str, path: &str, page_json: Vec<u8>) {
        self.pages
            .insert((site.to_string(), path.to_string()), page_json);
    }

    pub fn get(&self, site: &str, path: &str) -> Option<&[u8]> {
        self.pages
            .get(&(site.to_string(), path.to_string()))
            .map(Vec::as_slice)
    }

    /// Load every `*.json` file in `dir` as path = file stem for `site`.
    pub fn load_dir(&mut self, site: &str, dir: &std::path::Path) -> Result<usize, ServerError> {
        let mut count = 0;
        let entries = std::fs::read_dir(dir).map_err(|e| ServerError::Content(e.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|e| ServerError::Content(e.to_string()))?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| ServerError::Content("bad filename".into()))?;
            let bytes = std::fs::read(&path).map_err(|e| ServerError::Content(e.to_string()))?;
            // Validate eagerly so the server never serves invalid pages.
            let page = nexus_content::Page::from_json(&bytes)
                .map_err(|e| ServerError::Content(e.to_string()))?;
            if page.metadata.site != site || page.metadata.path != stem {
                return Err(ServerError::Content(format!(
                    "metadata mismatch in {}: expected {site}/{stem}",
                    path.display()
                )));
            }
            self.insert(site, stem, bytes);
            count += 1;
        }
        Ok(count)
    }

    pub fn routes(&self) -> Vec<(String, String)> {
        let mut v: Vec<_> = self.pages.keys().cloned().collect();
        v.sort();
        v
    }
}

/// Handle one connection: read request line, write one response, close.
pub fn handle_one(stream: &std::net::TcpStream, store: &SiteStore) -> Result<(), ServerError> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let line = nexus_transport::read_line_limited(&mut reader)?;
    let response = match nxp::parse_request(&line) {
        Ok(req) => match store.get(&req.site, &req.path) {
            Some(body) => nxp::encode_response(200, body)?,
            None => nxp::encode_response(404, b"not found")?,
        },
        Err(_) => nxp::encode_response(400, b"bad request")?,
    };
    let mut writer = stream.try_clone()?;
    writer.write_all(&response)?;
    writer.flush()?;
    Ok(())
}

/// Serve forever on `listener`. Each connection gets its own thread.
pub fn serve(listener: TcpListener, store: SiteStore) -> Result<(), ServerError> {
    for stream in listener.incoming() {
        let stream = stream?;
        let store = store.clone();
        std::thread::spawn(move || {
            if let Err(e) = handle_one(&stream, &store) {
                eprintln!("connection error: {e}");
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_content::{Component, Metadata, Page};

    fn page_bytes(site: &str, path: &str) -> Vec<u8> {
        let p = Page {
            metadata: Metadata {
                schema: 1,
                site: site.into(),
                path: path.into(),
                title: "T".into(),
                revision: 1,
            },
            components: vec![Component::Text { text: "hi".into() }],
            capabilities: vec![],
        };
        p.to_canonical_json().unwrap()
    }

    #[test]
    fn store_get() {
        let mut s = SiteStore::new();
        s.insert("example", "home", page_bytes("example", "home"));
        assert!(s.get("example", "home").is_some());
        assert!(s.get("example", "missing").is_none());
    }

    #[test]
    fn end_to_end_tcp() {
        let mut store = SiteStore::new();
        store.insert("example", "home", page_bytes("example", "home"));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_one(&stream, &store).unwrap();
        });
        let req = nxp::FetchRequest {
            site: "example".into(),
            path: "home".into(),
        };
        let (code, body) = nexus_transport::fetch(addr, &req).unwrap();
        assert_eq!(code, 200);
        let page = nexus_content::Page::from_json(&body).unwrap();
        assert_eq!(page.metadata.site, "example");
    }

    #[test]
    fn missing_returns_404_bytes() {
        let store = SiteStore::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_one(&stream, &store).unwrap();
        });
        let req = nxp::FetchRequest {
            site: "example".into(),
            path: "nope".into(),
        };
        let (code, _) = nexus_transport::fetch(addr, &req).unwrap();
        assert_eq!(code, 404);
    }
}
