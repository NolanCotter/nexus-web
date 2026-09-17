//! Reference origin server: serves JSON pages over NXP/TCP.
//!
//! The store maps (site, path) -> canonical page bytes. The wire layer is
//! deliberately synchronous std::net for M1; concurrency is one thread per
//! connection with a strict cap.

use std::collections::HashMap;
use std::io::{BufReader, Write};
use std::net::TcpListener;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use nexus_protocol as nxp;
use thiserror::Error;

/// Server failures: transport/protocol/I/O plus content problems
/// (unreadable site dir, invalid page JSON, metadata mismatch).
#[derive(Debug, Error)]
pub enum ServerError {
    /// Framing or socket failure on a connection.
    #[error("transport: {0}")]
    Transport(#[from] nexus_transport::TransportError),
    /// Request line or response encoding failure.
    #[error("protocol: {0}")]
    Protocol(#[from] nxp::ProtocolError),
    /// Filesystem or socket I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Site directory or page payload failed validation.
    #[error("content: {0}")]
    Content(String),
}

/// In-memory map of (site, path) to canonical page bytes served over NXP.
#[derive(Debug, Default, Clone)]
pub struct SiteStore {
    pages: HashMap<(String, String), Vec<u8>>,
}

impl SiteStore {
    /// Empty store; populate with [`SiteStore::insert`] or [`SiteStore::load_dir`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert one page's canonical JSON bytes (no validation; use `load_dir`
    /// for the validating path).
    pub fn insert(&mut self, site: &str, path: &str, page_json: Vec<u8>) {
        self.pages
            .insert((site.to_string(), path.to_string()), page_json);
    }

    /// Look up a page's bytes by (site, path).
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

    /// Sorted list of served (site, path) pairs, for startup logging.
    pub fn routes(&self) -> Vec<(String, String)> {
        let mut v: Vec<_> = self.pages.keys().cloned().collect();
        v.sort();
        v
    }
}

/// Default cap on concurrent connections (see `ServerConfig`).
pub const DEFAULT_MAX_CONNECTIONS: usize = 64;
/// Default per-connection read deadline. Slow senders (slowloris) are
/// closed when a read exceeds this.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Default per-connection write deadline.
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Runtime knobs for [`serve_with_config`]. All wire behavior stays NXP/0.1.
#[derive(Debug, Clone, Copy)]
pub struct ServerConfig {
    /// Max concurrent connections. Excess connections get `503` then close.
    pub max_connections: usize,
    /// Per-connection read deadline (slowloris protection).
    pub read_timeout: Duration,
    /// Per-connection write deadline.
    pub write_timeout: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            read_timeout: DEFAULT_READ_TIMEOUT,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
        }
    }
}

/// Handle one connection: read request line, write one response, close.
///
/// The caller is responsible for read/write deadlines on `stream`
/// ([`serve_with_config`] sets them from [`ServerConfig`]); a slow sender
/// otherwise blocks this thread's read indefinitely.
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

/// Serve forever on `listener` with default config. Each connection gets
/// its own thread, up to [`DEFAULT_MAX_CONNECTIONS`] concurrent.
pub fn serve(listener: TcpListener, store: SiteStore) -> Result<(), ServerError> {
    serve_with_config(listener, store, ServerConfig::default())
}

/// `true` if the active-connection counter was incremented (slot acquired).
fn try_acquire(active: &AtomicUsize, max: usize) -> bool {
    let mut cur = active.load(Ordering::SeqCst);
    loop {
        if cur >= max {
            return false;
        }
        match active.compare_exchange_weak(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return true,
            Err(v) => cur = v,
        }
    }
}

/// Decrements the active-connection counter when the handler thread exits.
struct InFlight {
    active: Arc<AtomicUsize>,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Serve forever on `listener`. Each connection gets its own thread, capped
/// at `config.max_connections` concurrent connections. Connections beyond
/// the cap get a `503` response then close. Every connection gets
/// `config.read_timeout` / `config.write_timeout` deadlines so slow senders
/// cannot hold a slot forever.
pub fn serve_with_config(
    listener: TcpListener,
    store: SiteStore,
    config: ServerConfig,
) -> Result<(), ServerError> {
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let stream = stream?;
        if !try_acquire(&active, config.max_connections) {
            // Best-effort 503, then close. Use short timeouts so a wedged
            // peer cannot stall the accept loop (handled inline, no slot).
            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
            if let Ok(body) = nxp::encode_response(503, b"server busy") {
                let mut w = &stream;
                let _ = w.write_all(&body);
                let _ = w.flush();
            }
            continue;
        }
        let store = store.clone();
        let active = Arc::clone(&active);
        std::thread::spawn(move || {
            let _guard = InFlight { active };
            let _ = stream.set_read_timeout(Some(config.read_timeout));
            let _ = stream.set_write_timeout(Some(config.write_timeout));
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

    fn read_response(stream: &std::net::TcpStream) -> (u16, Vec<u8>) {
        use std::io::{BufRead, Read};
        let mut r = std::io::BufReader::new(stream);
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        let h = nxp::parse_response_header(&line).unwrap();
        let mut body = vec![0u8; h.body_len];
        r.read_exact(&mut body).unwrap();
        (h.code, body)
    }

    #[test]
    fn connection_cap_rejects_excess_with_503() {
        use std::io::Write;
        let config = ServerConfig {
            max_connections: 2,
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(5),
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || serve_with_config(listener, SiteStore::new(), config));
        // Occupy both slots with idle holders (server blocks in read).
        let _held = (0..2)
            .map(|_| std::net::TcpStream::connect(addr).unwrap())
            .collect::<Vec<_>>();
        std::thread::sleep(Duration::from_millis(500));
        // Many concurrent clients racing for the full server: every one must
        // get *some* well-formed NXP response (503 while full, never a hang).
        let mut threads = Vec::new();
        for _ in 0..16 {
            threads.push(std::thread::spawn(move || {
                let mut s = std::net::TcpStream::connect(addr).unwrap();
                s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                s.write_all(b"NXP/0.1 FETCH example home\n").unwrap();
                read_response(&s).0
            }));
        }
        for t in threads {
            assert_eq!(t.join().unwrap(), 503);
        }
    }

    #[test]
    fn slowloris_partial_line_closed_within_deadline() {
        use std::io::{Read, Write};
        let config = ServerConfig {
            max_connections: 8,
            read_timeout: Duration::from_millis(300),
            write_timeout: Duration::from_secs(5),
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || serve_with_config(listener, SiteStore::new(), config));
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        s.write_all(b"NXP/0.1 FETCH example ").unwrap(); // partial line, no \n
        s.flush().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let start = std::time::Instant::now();
        let mut buf = [0u8; 64];
        // Server must close the connection when the read deadline fires:
        // read returns EOF (0) or an error, well within the client timeout.
        let closed = match s.read(&mut buf) {
            Ok(0) => true,
            Ok(_) => false, // unexpected data, not a close
            Err(_) => start.elapsed() < Duration::from_secs(5),
        };
        assert!(closed, "slowloris connection was not closed");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "close took too long: {:?}",
            start.elapsed()
        );
    }
}
