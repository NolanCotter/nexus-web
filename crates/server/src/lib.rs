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

/// In-memory map of (site, path) to canonical page bytes served over NXP,
/// plus the signed records that vouch for them (`RECORDS` verb).
#[derive(Debug, Default, Clone)]
pub struct SiteStore {
    pages: HashMap<(String, String), Vec<u8>>,
    records: HashMap<(String, String), Vec<u8>>,
    /// Endpoint records by name (`RECORDS <name> @<name>`): the federated
    /// resolution plane (ADR 010). Keyed by name, not (site, path).
    endpoint_records: HashMap<String, Vec<u8>>,
    signer: Option<SignerState>,
}

/// Identity + TTL used to (re-)sign pages into `RECORDS`.
#[derive(Debug, Clone)]
struct SignerState {
    identity: nexus_identity::SiteIdentity,
    ttl_secs: u64,
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

    /// Look up the signed-records JSON array for (site, path), if any.
    pub fn get_records(&self, site: &str, path: &str) -> Option<&[u8]> {
        self.records
            .get(&(site.to_string(), path.to_string()))
            .map(Vec::as_slice)
    }

    /// Insert a pre-signed endpoint-record chain for `name` (JSON array of
    /// `SignedRecord`; validation is the client's job, see ADR 010).
    pub fn insert_endpoint_records(&mut self, name: &str, chain_json: Vec<u8>) {
        self.endpoint_records.insert(name.to_string(), chain_json);
    }

    /// Look up the endpoint-record chain for `name`, if any.
    pub fn get_endpoint_records(&self, name: &str) -> Option<&[u8]> {
        self.endpoint_records.get(name).map(Vec::as_slice)
    }

    /// Sorted names with endpoint chains (startup logging).
    pub fn endpoint_routes(&self) -> Vec<String> {
        let mut v: Vec<String> = self.endpoint_records.keys().cloned().collect();
        v.sort();
        v
    }
} // end impl SiteStore (pages, records, endpoint plane)

/// Outcome of [`SiteStore::load_pack`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackReport {
    /// Page blobs admitted (validated + wire-legal site/path).
    pub pages: usize,
    /// Record chains admitted.
    pub chains: usize,
    /// Blobs that were neither (skipped, still hash-verified).
    pub skipped: usize,
}

impl SiteStore {
    // (pack import methods live here so pages/records share one impl)
    /// Load a site from an NXPACK1 pack (sneakernet import): every blob is
    /// hash-verified by the pack decoder first; then each blob is tried as
    /// a page (validated, wire-legal metadata) and otherwise as a record
    /// chain (every record's site/path validated). Anything else is
    /// skipped but counted. Pages land under their own metadata
    /// (site, path); chains merge per route (replace, like `sign_pages`).
    pub fn load_pack(&mut self, pack: &[u8]) -> Result<PackReport, ServerError> {
        let blobs = nexus_storage::FsStore::unpack(pack)
            .map_err(|e| ServerError::Content(e.to_string()))?;
        let mut report = PackReport {
            pages: 0,
            chains: 0,
            skipped: 0,
        };
        // Pass 1: pages land under their own metadata (site, path).
        let mut chain_blobs: Vec<&Vec<u8>> = Vec::new();
        for bytes in blobs.iter().map(|(_, b)| b) {
            if let Ok(page) = nexus_content::Page::from_json(bytes) {
                if nxp::is_valid_site(&page.metadata.site)
                    && nxp::is_valid_path(&page.metadata.path)
                {
                    self.pages.insert(
                        (page.metadata.site.clone(), page.metadata.path.clone()),
                        bytes.to_vec(),
                    );
                    report.pages += 1;
                    continue;
                }
            }
            if serde_json::from_slice::<Vec<serde_json::Value>>(bytes)
                .map(|records| Self::valid_chain(&records))
                .unwrap_or(false)
            {
                chain_blobs.push(bytes);
                continue;
            }
            report.skipped += 1;
        }
        // Pass 2: chains bind to the ROUTE they vouch for — the page with
        // the same path — because record sites are key hexes while routes
        // are petnames. A chain with no page of its path keeps its own key
        // (still servable by exact lookup, still verifiable).
        for bytes in chain_blobs {
            let records: Vec<serde_json::Value> =
                serde_json::from_slice(bytes).expect("re-parses: validated in pass 1");
            let path = records[0]["record"]["path"].as_str().unwrap_or_default();
            let route_site = self
                .pages
                .keys()
                .find(|(_, p)| p == path)
                .map(|(site, _)| site.clone())
                .unwrap_or_else(|| {
                    records[0]["record"]["site"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string()
                });
            self.records
                .insert((route_site, path.to_string()), bytes.to_vec());
            report.chains += 1;
        }
        Ok(report)
    }

    /// Every element must look like a `SignedRecord` with wire-legal
    /// site/path, all naming the SAME route (one chain, one route).
    fn valid_chain(records: &[serde_json::Value]) -> bool {
        if records.is_empty() {
            return false;
        }
        let (mut site, mut path) = (None, None);
        for r in records {
            let s = r["record"]["site"].as_str().unwrap_or_default();
            let p = r["record"]["path"].as_str().unwrap_or_default();
            let sig = r["signature_hex"].as_str().unwrap_or_default();
            if !nxp::is_valid_site(s) || s.is_empty() {
                return false;
            }
            if p.is_empty()
                || (!nxp::is_valid_path(p) && !(p.starts_with('@') && nxp::is_valid_site(&p[1..])))
            {
                return false;
            }
            if sig.is_empty() {
                return false;
            }
            match (&site, &path) {
                (None, None) => {
                    site = Some(s);
                    path = Some(p);
                }
                _ if site != Some(s) || path != Some(p) => return false,
                _ => {}
            }
        }
        true
    }

    /// Install the identity + TTL used for background re-signing. The next
    /// [`SiteStore::sign_pages`] call (manual or via the re-signer thread in
    /// [`serve_with_config`]) publishes fresh records; pages themselves are
    /// untouched.
    pub fn set_signer(&mut self, identity: nexus_identity::SiteIdentity, ttl_secs: u64) {
        self.signer = Some(SignerState { identity, ttl_secs });
    }

    /// Sign every stored page with `identity` and publish one
    /// [`SignedRecord`](nexus_identity::SignedRecord) per (site, path),
    /// expiring at `expires_at_unix`. Returns the number of records
    /// published. Replaces any previous records for those routes.
    pub fn sign_pages(
        &mut self,
        identity: &nexus_identity::SiteIdentity,
        expires_at_unix: u64,
    ) -> Result<usize, ServerError> {
        // Collect first so a mid-loop failure cannot leave a half-signed store.
        let mut signed = Vec::new();
        for ((site, path), bytes) in &self.pages {
            let page = nexus_content::Page::from_json(bytes)
                .map_err(|e| ServerError::Content(e.to_string()))?;
            let content_id = page
                .content_id()
                .map_err(|e| ServerError::Content(e.to_string()))?;
            let record = identity
                .sign_record(path, &content_id, expires_at_unix)
                .map_err(|e| ServerError::Content(e.to_string()))?;
            let body =
                serde_json::to_vec(&[record]).map_err(|e| ServerError::Content(e.to_string()))?;
            signed.push(((site.clone(), path.clone()), body));
        }
        let count = signed.len();
        for (route, body) in signed {
            self.records.insert(route, body);
        }
        Ok(count)
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
        // Optional `endpoints/` subdir: `<name>.json` files holding JSON
        // arrays of SignedRecord, served at `RECORDS <name> @<name>`
        // (ADR 010). Missing dir = no endpoint records, not an error.
        let endpoints = dir.join("endpoints");
        if endpoints.is_dir() {
            let entries =
                std::fs::read_dir(&endpoints).map_err(|e| ServerError::Content(e.to_string()))?;
            for entry in entries {
                let entry = entry.map_err(|e| ServerError::Content(e.to_string()))?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("json") {
                    continue;
                }
                let name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| ServerError::Content("bad endpoint filename".into()))?;
                if !nxp::is_valid_site(name) {
                    return Err(ServerError::Content(format!(
                        "bad endpoint name in {}",
                        path.display()
                    )));
                }
                let bytes =
                    std::fs::read(&path).map_err(|e| ServerError::Content(e.to_string()))?;
                // Fail loud on garbage: must be a JSON array (element shape
                // is the client's verification job, not the server's).
                let v: serde_json::Value = serde_json::from_slice(&bytes)
                    .map_err(|e| ServerError::Content(format!("{}: {e}", path.display())))?;
                if !v.is_array() {
                    return Err(ServerError::Content(format!(
                        "{}: endpoint chain must be a JSON array",
                        path.display()
                    )));
                }
                self.insert_endpoint_records(name, bytes);
            }
        }
        Ok(count)
    }

    /// Sorted list of served (site, path) pairs, for startup logging.
    pub fn routes(&self) -> Vec<(String, String)> {
        let mut v: Vec<_> = self.pages.keys().cloned().collect();
        v.sort();
        v
    }

    /// Sorted paths served for `site` (the `LIST` verb body is this as
    /// JSON). Empty when the site is unknown — the handler answers 404.
    pub fn list_paths(&self, site: &str) -> Vec<String> {
        let mut paths: Vec<String> = self
            .pages
            .keys()
            .filter(|(s, _)| s == site)
            .map(|(_, p)| p.clone())
            .collect();
        paths.sort();
        paths
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
    /// When `Some`, a background thread re-signs all pages into `RECORDS`
    /// on this cadence (only if the store has a signer; see
    /// [`SiteStore::set_signer`]). `None` (default) serves the startup
    /// records until they expire.
    pub resign_interval: Option<Duration>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            read_timeout: DEFAULT_READ_TIMEOUT,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            resign_interval: None,
        }
    }
}

/// Split an `@name` record path into its endpoint name. Returns `Some`
/// only when the path is exactly `@<site>` with a valid site name —
/// anything else (`@` alone, `@other`, `@../x`) is not an endpoint lookup.
/// Note: `@` never reaches [`nxp::is_valid_path`] (content paths); this is
/// the only place the `@` namespace exists on the server.
fn endpoint_name(site: &str, path: &str) -> Option<String> {
    let name = path.strip_prefix('@')?;
    if name.is_empty() || name != site || !nxp::is_valid_site(name) {
        return None;
    }
    Some(name.to_string())
}

/// Content id of served `body`, or `None` when the bytes do not parse
/// (corrupt store entries never match a precondition — the client gets a
/// normal 200 and revalidates the bytes itself).
fn page_content_id(body: &[u8]) -> Option<String> {
    nexus_content::Page::from_json(body).ok()?.content_id().ok()
}

/// Handle one connection: read request line, write one response, close.
///
/// The caller is responsible for read/write deadlines on `stream`
/// ([`serve_with_config`] sets them from [`ServerConfig`]); a slow sender
/// otherwise blocks this thread's read indefinitely.
pub fn handle_one(stream: &std::net::TcpStream, store: &SiteStore) -> Result<(), ServerError> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let line = nexus_transport::read_line_limited(&mut reader)?;
    // FETCH and RECORDS share the line shape; LIST stands alone (no path).
    // Anything else (including malformed lines) is a 400 — never a panic.
    let response = match nxp::parse_request(&line) {
        Ok(req) => match store.get(&req.site, &req.path) {
            Some(body) => match &req.if_id {
                // Precondition hit: the client already holds these exact
                // bytes — confirm with an empty 304, not a resend.
                Some(id) if page_content_id(body).as_ref() == Some(id) => {
                    nxp::encode_response(304, b"")?
                }
                _ => nxp::encode_response(200, body)?,
            },
            None => nxp::encode_response(404, b"not found")?,
        },
        Err(nxp::ProtocolError::BadVerb(_)) => match nxp::parse_records_request(&line) {
            Ok(req) => match endpoint_name(&req.site, &req.path) {
                // `@name` namespace: federated endpoint records (ADR 010).
                Some(name) => match store.get_endpoint_records(&name) {
                    Some(body) => nxp::encode_response(200, body)?,
                    None => nxp::encode_response(404, b"no records")?,
                },
                None => match store.get_records(&req.site, &req.path) {
                    Some(body) => nxp::encode_response(200, body)?,
                    None => nxp::encode_response(404, b"no records")?,
                },
            },
            Err(nxp::ProtocolError::BadVerb(_)) => match nxp::parse_list_request(&line) {
                Ok(req) => {
                    let paths = store.list_paths(&req.site);
                    if paths.is_empty() {
                        nxp::encode_response(404, b"unknown site")?
                    } else {
                        let body = serde_json::to_vec(&paths)
                            .map_err(|e| ServerError::Content(e.to_string()))?;
                        nxp::encode_response(200, &body)?
                    }
                }
                Err(_) => nxp::encode_response(400, b"bad request")?,
            },
            Err(_) => nxp::encode_response(400, b"bad request")?,
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
    let shared = Arc::new(std::sync::RwLock::new(store));
    if let Some(interval) = config.resign_interval {
        let shared = Arc::clone(&shared);
        std::thread::spawn(move || resign_loop(shared, interval));
    }
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
        // Snapshot under a read lock so the re-signer can publish fresh
        // records concurrently; each connection serves a consistent view.
        let snapshot = read_store(&shared).clone();
        let active = Arc::clone(&active);
        std::thread::spawn(move || {
            let _guard = InFlight { active };
            let _ = stream.set_read_timeout(Some(config.read_timeout));
            let _ = stream.set_write_timeout(Some(config.write_timeout));
            if let Err(e) = handle_one(&stream, &snapshot) {
                eprintln!("connection error: {e}");
            }
        });
    }
    Ok(())
}

/// Read-lock the shared store, recovering from poisoning instead of
/// panicking the accept loop.
fn read_store(
    shared: &Arc<std::sync::RwLock<SiteStore>>,
) -> std::sync::RwLockReadGuard<'_, SiteStore> {
    shared
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Background record refresh: re-sign every page into `RECORDS` on each
/// tick so long-lived servers never serve expired chains. Skips ticks when
/// no signer is installed (pages-only mode). Failures are logged, never
/// fatal: the previous records stay live until replaced.
fn resign_loop(shared: Arc<std::sync::RwLock<SiteStore>>, interval: Duration) {
    loop {
        std::thread::sleep(interval);
        let (identity, ttl) = match read_store(&shared).signer.clone() {
            Some(s) => (s.identity, s.ttl_secs),
            None => continue,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut store = shared.write().unwrap_or_else(|p| p.into_inner());
        match store.sign_pages(&identity, now.saturating_add(ttl)) {
            Ok(n) => eprintln!("resigned {n} record(s)"),
            Err(e) => eprintln!("resign failed (keeping old records): {e}"),
        }
    }
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
            if_id: None,
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
            if_id: None,
        };
        let (code, _) = nexus_transport::fetch(addr, &req).unwrap();
        assert_eq!(code, 404);
    }

    #[test]
    fn records_roundtrip_over_tcp() {
        use nexus_identity::SiteIdentity;
        let id = SiteIdentity::generate();
        let mut store = SiteStore::new();
        store.insert("example", "home", page_bytes("example", "home"));
        let n = store.sign_pages(&id, 9_999_999_999).unwrap();
        assert_eq!(n, 1);
        let page = nexus_content::Page::from_json(store.get("example", "home").unwrap()).unwrap();
        let want = page.content_id().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_one(&stream, &store).unwrap();
        });
        let line = nxp::encode_records_request(&nxp::RecordsRequest {
            site: "example".into(),
            path: "home".into(),
        })
        .unwrap();
        let (code, body) = nexus_transport::fetch_raw(addr, &line).unwrap();
        assert_eq!(code, 200);
        let records: Vec<nexus_identity::SignedRecord> = serde_json::from_slice(&body).unwrap();
        assert_eq!(records.len(), 1);
        // The served record verifies and vouches for the served page.
        id.verify_record(&records[0], 1_000_000).unwrap();
        assert_eq!(records[0].record.content_hash, want);
    }

    #[test]
    fn records_missing_without_key() {
        // A store that never signed has no records: 404, not 400.
        let mut store = SiteStore::new();
        store.insert("example", "home", page_bytes("example", "home"));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_one(&stream, &store).unwrap();
        });
        let line = nxp::encode_records_request(&nxp::RecordsRequest {
            site: "example".into(),
            path: "home".into(),
        })
        .unwrap();
        let (code, _) = nexus_transport::fetch_raw(addr, &line).unwrap();
        assert_eq!(code, 404);
    }

    #[test]
    fn unknown_verb_still_400() {
        use std::io::Write;
        let store = SiteStore::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_one(&stream, &store).unwrap();
        });
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        s.write_all(b"NXP/0.1 DELETE example home\n").unwrap();
        let (code, _) = read_response(&s);
        assert_eq!(code, 400);
    }

    #[test]
    fn resign_refresh_bumps_expiry() {
        use nexus_identity::SiteIdentity;
        let id = SiteIdentity::generate();
        let mut store = SiteStore::new();
        store.insert("example", "home", page_bytes("example", "home"));
        store.set_signer(id.clone(), 3600);
        store.sign_pages(&id, 1_000).unwrap();
        let first: Vec<nexus_identity::SignedRecord> =
            serde_json::from_slice(store.get_records("example", "home").unwrap()).unwrap();
        assert_eq!(first[0].record.expires_at_unix, 1_000);
        // A later signing round replaces (not appends) the chain.
        store.sign_pages(&id, 2_000).unwrap();
        let second: Vec<nexus_identity::SignedRecord> =
            serde_json::from_slice(store.get_records("example", "home").unwrap()).unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].record.expires_at_unix, 2_000);
        id.verify_record(&second[0], 1_500).unwrap();
    }

    #[test]
    fn background_resign_refreshes_served_records() {
        use nexus_identity::SiteIdentity;
        let id = SiteIdentity::generate();
        let mut store = SiteStore::new();
        store.insert("example", "home", page_bytes("example", "home"));
        store.set_signer(id.clone(), 3600);
        // Startup chain is already expired: without refresh it stays dead.
        store.sign_pages(&id, 1).unwrap();
        let config = ServerConfig {
            resign_interval: Some(Duration::from_millis(100)),
            ..ServerConfig::default()
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || serve_with_config(listener, store, config));
        // Wait for at least one background tick (generous margin).
        std::thread::sleep(Duration::from_millis(500));
        let line = nxp::encode_records_request(&nxp::RecordsRequest {
            site: "example".into(),
            path: "home".into(),
        })
        .unwrap();
        let (code, body) = nexus_transport::fetch_raw(addr, &line).unwrap();
        assert_eq!(code, 200);
        let records: Vec<nexus_identity::SignedRecord> = serde_json::from_slice(&body).unwrap();
        // Refreshed expiry must be in the future (background thread signed
        // with now+ttl), not the stale startup value of 1.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        assert!(
            records[0].record.expires_at_unix > now,
            "records were not refreshed in the background"
        );
        id.verify_record(&records[0], now).unwrap();
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
            resign_interval: None,
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
            resign_interval: None,
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

    #[test]
    fn list_serves_sorted_paths_and_404s_unknown_site() {
        let mut store = SiteStore::new();
        store.insert("example", "home", page_bytes("example", "home"));
        store.insert("example", "about", page_bytes("example", "about"));
        assert_eq!(store.list_paths("example"), vec!["about", "home"]);
        assert!(store.list_paths("ghost").is_empty());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for _ in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                handle_one(&stream, &store).unwrap();
            }
        });
        let line = nxp::encode_list_request(&nxp::ListRequest {
            site: "example".into(),
        })
        .unwrap();
        let (code, body) = nexus_transport::fetch_raw(addr, &line).unwrap();
        assert_eq!(code, 200);
        let paths: Vec<String> = serde_json::from_slice(&body).unwrap();
        assert_eq!(paths, vec!["about", "home"]);

        let line = nxp::encode_list_request(&nxp::ListRequest {
            site: "ghost".into(),
        })
        .unwrap();
        let (code, _) = nexus_transport::fetch_raw(addr, &line).unwrap();
        assert_eq!(code, 404);
    }

    #[test]
    fn endpoint_records_serve_over_at_namespace() {
        let mut store = SiteStore::new();
        store.insert_endpoint_records("alice", br#"[{"record":{"site":"s","path":"@alice","content_hash":"b3:x","expires_at_unix":9},"signature_hex":"aa"}]"#.to_vec());
        assert_eq!(store.endpoint_routes(), vec!["alice"]);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            // Valid @alice, mismatched @other, bare @, unknown name.
            for _ in 0..4 {
                let (stream, _) = listener.accept().unwrap();
                handle_one(&stream, &store).unwrap();
            }
        });
        let good = nxp::encode_records_request(&nxp::RecordsRequest {
            site: "alice".into(),
            path: "@alice".into(),
        })
        .unwrap();
        let (code, body) = nexus_transport::fetch_raw(addr, &good).unwrap();
        assert_eq!(code, 200);
        assert!(body.starts_with(b"["));

        // @other against site alice: the encoder refuses to build it, so
        // send the raw hostile line — malformed (400), never served.
        let (code, _) = nexus_transport::fetch_raw(addr, "NXP/0.1 RECORDS alice @other\n").unwrap();
        assert_eq!(code, 400);
        let (code, _) = nexus_transport::fetch_raw(addr, "NXP/0.1 RECORDS alice @\n").unwrap();
        assert_eq!(code, 400);
        // Unknown name with well-formed @: 404, not 400.
        let ghost = nxp::encode_records_request(&nxp::RecordsRequest {
            site: "ghost".into(),
            path: "@ghost".into(),
        })
        .unwrap();
        let (code, _) = nexus_transport::fetch_raw(addr, &ghost).unwrap();
        assert_eq!(code, 404);
    }

    #[test]
    fn endpoints_subdir_loads_and_rejects_garbage() {
        let dir = std::env::temp_dir().join(format!("nexus-endpoints-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("endpoints")).unwrap();
        std::fs::write(dir.join("endpoints").join("alice.json"), b"[]").unwrap();
        std::fs::write(
            dir.join("home.json"),
            serde_json::to_vec(&serde_json::json!({
                "metadata": {"schema": 1, "site": "example", "path": "home",
                             "title": "T", "revision": 1},
                "components": [{"type": "text", "text": "hi"}],
                "capabilities": []
            }))
            .unwrap(),
        )
        .unwrap();
        let mut store = SiteStore::new();
        assert_eq!(store.load_dir("example", &dir).unwrap(), 1);
        assert_eq!(store.endpoint_routes(), vec!["alice"]);

        // Non-array JSON and bad names fail loud.
        std::fs::write(dir.join("endpoints").join("bob.json"), b"{}").unwrap();
        let mut bad = SiteStore::new();
        assert!(bad.load_dir("example", &dir).is_err());
        std::fs::write(dir.join("endpoints").join("bob.json"), b"[]").unwrap();
        std::fs::write(dir.join("endpoints").join("BAD.json"), b"[]").unwrap();
        let mut bad2 = SiteStore::new();
        assert!(bad2.load_dir("example", &dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_pack_roundtrip_pages_and_chains() {
        use nexus_identity::SiteIdentity;
        let dir = std::env::temp_dir().join(format!("nexus-pack-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let fs = nexus_storage::FsStore::new(&dir);
        let page = page_bytes("example", "home");
        let page_id = fs.put(&page).unwrap();
        let id = SiteIdentity::generate();
        let content_id = nexus_content::Page::from_json(&page)
            .unwrap()
            .content_id()
            .unwrap();
        let chain =
            serde_json::to_vec(&[id.sign_record("home", &content_id, 9_999_999_999).unwrap()])
                .unwrap();
        let chain_id = fs.put(&chain).unwrap();
        // An opaque blob rides along and is skipped, not admitted.
        let junk_id = fs.put(b"just bytes").unwrap();
        let pack = fs.export(&[page_id, chain_id, junk_id]).unwrap();

        let mut store = SiteStore::new();
        let report = store.load_pack(&pack).unwrap();
        assert_eq!((report.pages, report.chains, report.skipped), (1, 1, 1));
        assert!(store.get("example", "home").is_some());
        // The chain verifies against the loaded page.
        let records: Vec<nexus_identity::SignedRecord> =
            serde_json::from_slice(store.get_records("example", "home").unwrap()).unwrap();
        id.verify_record(&records[0], 1_000_000).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_pack_rejects_tampered_and_bad_metadata() {
        let dir = std::env::temp_dir().join(format!("nexus-pack-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let fs = nexus_storage::FsStore::new(&dir);
        let id = fs.put(b"nope").unwrap();
        let mut pack = fs.export(&[id]).unwrap();
        // Flip a payload byte: whole pack rejected, store untouched.
        let flip_at = pack.len() - 1;
        pack[flip_at] ^= 0xff;
        let mut store = SiteStore::new();
        assert!(store.load_pack(&pack).is_err());
        assert!(store.get("example", "home").is_none());

        // A page claiming an illegal site is skipped, not admitted.
        let evil = Page {
            metadata: Metadata {
                schema: 1,
                site: "EVIL".into(),
                path: "home".into(),
                title: "T".into(),
                revision: 1,
            },
            components: vec![Component::Text { text: "x".into() }],
            capabilities: vec![],
        };
        // Bypass from_json validation: serialize the struct directly.
        let bytes = serde_json::to_vec(&evil).unwrap();
        let eid = fs.put(&bytes).unwrap();
        let pack = fs.export(&[eid]).unwrap();
        let report = store.load_pack(&pack).unwrap();
        assert_eq!((report.pages, report.chains, report.skipped), (0, 0, 1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fetch_precondition_304_when_unchanged() {
        let mut store = SiteStore::new();
        store.insert("example", "home", page_bytes("example", "home"));
        let id = nexus_content::Page::from_json(store.get("example", "home").unwrap())
            .unwrap()
            .content_id()
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for _ in 0..3 {
                let (stream, _) = listener.accept().unwrap();
                handle_one(&stream, &store).unwrap();
            }
        });
        // Matching id: 304 with an empty body.
        let req = nxp::FetchRequest {
            site: "example".into(),
            path: "home".into(),
            if_id: Some(id),
        };
        let line = nxp::encode_request(&req).unwrap();
        let (code, body) = nexus_transport::fetch_raw(addr, &line).unwrap();
        assert_eq!(code, 304);
        assert!(body.is_empty());
        // Stale id: full 200.
        let stale = nxp::FetchRequest {
            site: "example".into(),
            path: "home".into(),
            if_id: Some(format!("b3:{}", "00".repeat(32))),
        };
        let line = nxp::encode_request(&stale).unwrap();
        let (code, body) = nexus_transport::fetch_raw(addr, &line).unwrap();
        assert_eq!(code, 200);
        assert!(!body.is_empty());
        // No precondition: full 200 (backwards compatible).
        let plain = nxp::FetchRequest {
            site: "example".into(),
            path: "home".into(),
            if_id: None,
        };
        let line = nxp::encode_request(&plain).unwrap();
        let (code, _) = nexus_transport::fetch_raw(addr, &line).unwrap();
        assert_eq!(code, 200);
    }
}
