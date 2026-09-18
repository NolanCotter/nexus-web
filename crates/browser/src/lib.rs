//! CLI browser core: resolve petname -> endpoint, FETCH, parse, render.
//!
//! Navigation history is a simple past/present/future stack (no tabs).
//! [`cache`] adds the offline-first disk page cache (Milestone G).

pub mod cache;
pub mod tui;

pub use cache::{CacheStatus, OfflineCache};

use nexus_content::Page;
use nexus_resolver::{LocalResolver, ResolveError, Resolver, Route};
use thiserror::Error;

/// Browser failures: resolution, transport, protocol, bad content, or a
/// non-200 server status (carries code + body for display).
#[derive(Debug, Error)]
pub enum BrowserError {
    /// Petname resolution failed.
    #[error("resolve: {0}")]
    Resolve(#[from] nexus_resolver::ResolveError),
    /// FETCH transport failure.
    #[error("transport: {0}")]
    Transport(#[from] nexus_transport::TransportError),
    /// Request encoding failed (invalid site/path caught locally).
    #[error("protocol: {0}")]
    Protocol(#[from] nexus_protocol::ProtocolError),
    /// Route had no endpoints, or the body failed page validation.
    #[error("content: {0}")]
    Content(String),
    /// Server answered with a non-200 status.
    #[error("cache: {0}")]
    Cache(String),
    #[error("server returned {0}: {1}")]
    Status(u16, String),
    #[error("bad target '{0}': {1}")]
    BadTarget(String, String),
    #[error("route pins site {0} but no signed records were provided; refusing to fetch")]
    PinRecordsRequired(String),
    #[error("pinned page verification failed for {site}/{path}: {reason}")]
    PinMismatch {
        site: String,
        path: String,
        reason: String,
    },
}

impl From<nexus_storage::StoreError> for BrowserError {
    fn from(e: nexus_storage::StoreError) -> Self {
        BrowserError::Cache(e.to_string())
    }
}

/// One history entry: where we went plus the parsed page we saw.

#[derive(Debug, Clone)]
pub struct Visit {
    /// Site that was visited.
    pub site: String,
    /// Path that was visited.
    pub path: String,
    /// Parsed page at visit time.
    pub page: Page,
}

/// Past/present/future navigation stack (no tabs in v0).
#[derive(Debug, Default)]
pub struct History {
    past: Vec<Visit>,
    present: Option<Visit>,
    future: Vec<Visit>,
}

impl History {
    /// Empty history (no current page).
    pub fn new() -> Self {
        Self::default()
    }

    /// Visit a page: current becomes past, future is dropped.
    pub fn push(&mut self, visit: Visit) {
        if let Some(cur) = self.present.take() {
            self.past.push(cur);
        }
        self.present = Some(visit);
        self.future.clear();
    }

    /// Step back; `None` when already at the oldest visit (stays put).
    pub fn back(&mut self) -> Option<&Visit> {
        let cur = self.present.take()?;
        if let Some(prev) = self.past.pop() {
            self.future.push(cur);
            self.present = Some(prev);
        } else {
            self.present = Some(cur);
            return None;
        }
        self.present.as_ref()
    }

    /// Step forward; `None` when no forward history exists.
    pub fn forward(&mut self) -> Option<&Visit> {
        let next = self.future.pop()?;
        if let Some(cur) = self.present.take() {
            self.past.push(cur);
        }
        self.present = Some(next);
        self.present.as_ref()
    }

    /// Currently displayed visit, if any.
    pub fn current(&self) -> Option<&Visit> {
        self.present.as_ref()
    }

    /// Total visits (past + present + future).
    pub fn len(&self) -> usize {
        self.past.len() + usize::from(self.present.is_some()) + self.future.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Index of the current visit within [`History::entries`].
    pub fn position(&self) -> usize {
        self.past.len()
    }

    /// Visits in chronological order, oldest first.
    pub fn entries(&self) -> Vec<&Visit> {
        let mut v: Vec<&Visit> = self.past.iter().collect();
        if let Some(cur) = &self.present {
            v.push(cur);
        }
        v.extend(self.future.iter().rev());
        v
    }

    /// Swap the current page in place (reload) without clearing the future.
    pub fn replace_current(&mut self, page: Page) {
        if let Some(cur) = self.present.as_mut() {
            cur.page = page;
        }
    }
}

/// Parse a navigation target: `site`, `site/path`, or `site/a/b`.
/// A missing path defaults to `home` (example-site convention).
pub fn parse_target(target: &str) -> Result<(String, String), BrowserError> {
    let (site, path) = match target.split_once('/') {
        Some((s, p)) => (s, p),
        None => (target, "home"),
    };
    if site.is_empty() || path.is_empty() {
        return Err(BrowserError::BadTarget(
            target.to_string(),
            "empty site or path".into(),
        ));
    }
    if !nexus_protocol::is_valid_site(site) {
        return Err(BrowserError::BadTarget(
            site.to_string(),
            "invalid site name".into(),
        ));
    }
    if !nexus_protocol::is_valid_path(path) {
        return Err(BrowserError::BadTarget(
            path.to_string(),
            "invalid path".into(),
        ));
    }
    Ok((site.to_string(), path.to_string()))
}

/// Interactive browsing session: owns resolution + history and drives the
/// same resolve->fetch path as [`navigate`], keeping state for back/forward.
///
/// Sites resolve lazily against the single `--server` endpoint; distributed
/// resolution plugs in behind the same `Resolver` trait later.
#[derive(Debug)]
pub struct ClientSession {
    resolver: LocalResolver,
    server: String,
    pin: Option<String>,
    cache: Option<OfflineCache>,
    last_status: Option<CacheStatus>,
    pub history: History,
}

impl ClientSession {
    pub fn new(server: impl Into<String>) -> Self {
        Self {
            resolver: LocalResolver::new(),
            server: server.into(),
            pin: None,
            cache: None,
            last_status: None,
            history: History::new(),
        }
    }

    /// Serve fetches through `cache` (offline fallback) when present.
    /// Without a cache the session fetches from the network only.
    pub fn with_cache(mut self, cache: OfflineCache) -> Self {
        self.cache = Some(cache);
        self
    }

    /// How the current page was obtained, if anything was fetched yet.
    /// Interactive shells (and the TUI status line) use this to show
    /// offline banners.
    pub fn last_status(&self) -> Option<CacheStatus> {
        self.last_status
    }

    /// Pin all lazily-created routes to `site_id`: every fetch then goes
    /// through `RECORDS` verification and fails closed without a chain.
    pub fn with_pin(mut self, pin: Option<String>) -> Self {
        self.pin = pin;
        self
    }

    /// The pinned site id, if this session verifies fetches.
    pub fn pin(&self) -> Option<&str> {
        self.pin.as_deref()
    }

    fn route(&mut self, site: &str) -> Result<Route, BrowserError> {
        if matches!(
            self.resolver.resolve(site),
            Err(ResolveError::UnknownSite(_))
        ) {
            self.resolver.insert(
                site,
                Route {
                    endpoints: vec![self.server.clone()],
                    pinned_site_id: self.pin.clone(),
                },
            )?;
        }
        Ok(self.resolver.resolve(site)?)
    }

    fn fetch(&mut self, site: &str, path: &str) -> Result<Page, BrowserError> {
        let route = self.route(site)?;
        let endpoint = route
            .endpoints
            .first()
            .ok_or_else(|| BrowserError::Content("route has no endpoints".into()))?;
        let (page, status) = match (&self.cache, route.pinned_site_id.clone()) {
            // Pinned + cached: verified fetch with verified-stale fallback.
            // A verified refusal (no chain) is returned as-is even when the
            // plain cache holds the page: unpinned bytes never satisfy a pin.
            (Some(cache), Some(pinned)) => cache.fetch_verified(endpoint, site, path, &pinned),
            (Some(cache), None) => cache.fetch(endpoint, site, path),
            (None, Some(_)) => {
                navigate_verified(&self.resolver, site, path).map(|page| (page, CacheStatus::Fresh))
            }
            (None, None) => fetch_page(endpoint, site, path).map(|page| (page, CacheStatus::Fresh)),
        }?;
        self.last_status = Some(status);
        Ok(page)
    }

    /// Navigate to `<site[/path]>`, pushing a history entry.
    pub fn open(&mut self, target: &str) -> Result<(), BrowserError> {
        let (site, path) = parse_target(target)?;
        let page = self.fetch(&site, &path)?;
        self.history.push(Visit { site, path, page });
        Ok(())
    }

    pub fn back(&mut self) -> Result<(), BrowserError> {
        if self.history.back().is_none() {
            return Err(BrowserError::Content("at the start of history".into()));
        }
        Ok(())
    }

    pub fn forward(&mut self) -> Result<(), BrowserError> {
        if self.history.forward().is_none() {
            return Err(BrowserError::Content("at the end of history".into()));
        }
        Ok(())
    }

    /// Refetch the current page and replace it in place (no new history entry).
    pub fn reload(&mut self) -> Result<(), BrowserError> {
        let (site, path) = self
            .history
            .current()
            .map(|v| (v.site.clone(), v.path.clone()))
            .ok_or_else(|| BrowserError::Content("nothing loaded yet".into()))?;
        let page = self.fetch(&site, &path)?;
        self.history.replace_current(page);
        Ok(())
    }

    pub fn render_current(&self) -> String {
        match self.history.current() {
            Some(v) => nexus_renderer::render_text(&v.page),
            None => String::new(),
        }
    }
}

/// Fetch and parse one page. `endpoint` is `host:port`.
pub fn fetch_page(endpoint: &str, site: &str, path: &str) -> Result<Page, BrowserError> {
    let req = nexus_protocol::FetchRequest {
        site: site.to_string(),
        path: path.to_string(),
    };
    // Validate before sending so errors are local, not network roundtrips.
    nexus_protocol::encode_request(&req)?;
    let (code, body) = nexus_transport::fetch(endpoint, &req)?;
    if code != 200 {
        return Err(BrowserError::Status(
            code,
            String::from_utf8_lossy(&body).into_owned(),
        ));
    }
    nexus_content::Page::from_json(&body).map_err(|e| BrowserError::Content(e.to_string()))
}

/// Resolve `site` via `resolver`, then fetch `path` from the first endpoint.
/// With no records supplied, any pinned route (`Some` `pinned_site_id`)
/// fails closed: fetching unverified content is refused.
pub fn navigate(resolver: &LocalResolver, site: &str, path: &str) -> Result<Page, BrowserError> {
    navigate_with_records(resolver, site, path, &[])
}

/// Resolve, fetch, and verify against an explicit chain of signed records.
///
/// When `Route.pinned_site_id` is `Some`, at least one record must match the
/// pinned site, the path, and the fetched page's BLAKE3 content id.
/// Prefer [`navigate_verified`], which fetches the chain from the server
/// over `RECORDS`; this variant exists for out-of-band chains (tests,
/// offline bundles, future transports).
pub fn navigate_with_records(
    resolver: &LocalResolver,
    site: &str,
    path: &str,
    records: &[nexus_identity::SignedRecord],
) -> Result<Page, BrowserError> {
    let route = resolver.resolve(site)?;
    let endpoint = route
        .endpoints
        .first()
        .ok_or_else(|| BrowserError::Content("route has no endpoints".into()))?;
    let page = fetch_page(endpoint, site, path)?;
    if let Some(pinned) = &route.pinned_site_id {
        if records.is_empty() {
            return Err(BrowserError::PinRecordsRequired(pinned.clone()));
        }
        verify_pinned(&page, pinned, path, records, now_unix())?;
    }
    Ok(page)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Fail-closed pin check: at least one record must vouch that the canonical
/// content id of `page` is what `pinned_site_id` signed for `path`.
pub(crate) fn verify_pinned(
    page: &Page,
    pinned_site_id: &str,
    path: &str,
    records: &[nexus_identity::SignedRecord],
    now_unix: u64,
) -> Result<(), BrowserError> {
    let pin_err = |reason: String| BrowserError::PinMismatch {
        site: pinned_site_id.to_string(),
        path: path.to_string(),
        reason,
    };
    let key_bytes = hex::decode(pinned_site_id).map_err(|e| pin_err(e.to_string()))?;
    let identity = nexus_identity::SiteIdentity::from_public_bytes(&key_bytes)
        .map_err(|e| pin_err(e.to_string()))?;
    let want = page.content_id().map_err(|e| pin_err(e.to_string()))?;
    let vouches = records.iter().any(|rec| {
        rec.record.path == path
            && rec.record.site == pinned_site_id
            && rec.record.content_hash == want
            && identity.verify_record(rec, now_unix).is_ok()
    });
    if vouches {
        Ok(())
    } else {
        Err(pin_err(
            "no signed record matches the fetched content".into(),
        ))
    }
}

/// Fetch the signed-record chain for (site, path) from `endpoint` over
/// `RECORDS`. A 404 (server has no records) yields an empty chain; any
/// other non-200 status is an error, as is an unparseable body.
pub fn fetch_records(
    endpoint: &str,
    site: &str,
    path: &str,
) -> Result<Vec<nexus_identity::SignedRecord>, BrowserError> {
    let req = nexus_protocol::RecordsRequest {
        site: site.to_string(),
        path: path.to_string(),
    };
    let line = nexus_protocol::encode_records_request(&req)?;
    let (code, body) = nexus_transport::fetch_raw(endpoint, &line)?;
    match code {
        200 => serde_json::from_slice(&body)
            .map_err(|e| BrowserError::Content(format!("bad records body: {e}"))),
        404 => Ok(Vec::new()),
        other => Err(BrowserError::Status(
            other,
            String::from_utf8_lossy(&body).into_owned(),
        )),
    }
}

/// Resolve, then fetch the page *and* its signed records from the first
/// endpoint and verify the page against `Route.pinned_site_id`.
///
/// This closes the M3 gap: records travel over the wire (`RECORDS`) from
/// the same host that serves the page, and a pinned route fails closed
/// when the chain is missing or does not vouch for the fetched bytes.
/// Routes without a pin fetch the page unverified, exactly like
/// [`navigate`].
pub fn navigate_verified(
    resolver: &LocalResolver,
    site: &str,
    path: &str,
) -> Result<Page, BrowserError> {
    let route = resolver.resolve(site)?;
    let endpoint = route
        .endpoints
        .first()
        .ok_or_else(|| BrowserError::Content("route has no endpoints".into()))?;
    if route.pinned_site_id.is_none() {
        return fetch_page(endpoint, site, path);
    }
    let records = fetch_records(endpoint, site, path)?;
    if records.is_empty() {
        // Fail before touching page bytes: no chain, no fetch.
        return Err(BrowserError::PinRecordsRequired(
            route.pinned_site_id.clone().unwrap_or_default(),
        ));
    }
    navigate_with_records(resolver, site, path, &records)
}
/// Resolve `site`, then fetch `path` through `cache` (offline fallback).
/// Returns the page plus its [`CacheStatus`] banner marker.
pub fn navigate_cached(
    resolver: &LocalResolver,
    cache: &OfflineCache,
    site: &str,
    path: &str,
) -> Result<(Page, CacheStatus), BrowserError> {
    let route = resolver.resolve(site)?;
    let endpoint = route
        .endpoints
        .first()
        .ok_or_else(|| BrowserError::Content("route has no endpoints".into()))?;
    cache.fetch(endpoint, site, path)
}

/// Resolve `site`, then fetch `path` verified against the route pin with
/// offline fallback. Routes without a pin behave exactly like
/// [`navigate_cached`]; pinned routes store and serve the record chain
/// through the cache (`Fresh` / [`CacheStatus::StaleVerified`]).
pub fn navigate_cached_verified(
    resolver: &LocalResolver,
    cache: &OfflineCache,
    site: &str,
    path: &str,
) -> Result<(Page, CacheStatus), BrowserError> {
    let route = resolver.resolve(site)?;
    let endpoint = route
        .endpoints
        .first()
        .ok_or_else(|| BrowserError::Content("route has no endpoints".into()))?;
    match route.pinned_site_id.clone() {
        None => cache.fetch(endpoint, site, path),
        Some(pin) => cache.fetch_verified(endpoint, site, path, &pin),
    }
}

/// Mirror a whole site into one NXPACK1 pack (sneakernet export): LIST
/// the paths, FETCH each page (plus RECORDS + verification when `pin` is
/// set), and pack the verified bytes. Only verified-or-unpinned pages
/// enter the pack: a pin mismatch aborts with an error and no pack.
/// Pack layout is the storage NXPACK1 format; [`SiteStore::load_pack`]
/// (server crate) imports it.
pub fn export_site(endpoint: &str, site: &str, pin: Option<&str>) -> Result<Vec<u8>, BrowserError> {
    let list_line = nexus_protocol::encode_list_request(&nexus_protocol::ListRequest {
        site: site.to_string(),
    })?;
    let (code, body) = nexus_transport::fetch_raw(endpoint, &list_line)?;
    if code != 200 {
        return Err(BrowserError::Status(
            code,
            String::from_utf8_lossy(&body).into_owned(),
        ));
    }
    let paths: Vec<String> = serde_json::from_slice(&body)
        .map_err(|e| BrowserError::Content(format!("bad LIST body: {e}")))?;
    // Stage through a temp CAS: blobs are hashed on the way into the pack.
    let stage = std::env::temp_dir().join(format!(
        "nexus-export-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&stage);
    let store = nexus_storage::FsStore::new(&stage);
    let mut ids = Vec::new();
    let result = (|| {
        for path in &paths {
            if !nexus_protocol::is_valid_path(path) {
                continue;
            }
            let page = match pin {
                None => fetch_page(endpoint, site, path)?,
                Some(p) => {
                    let records = fetch_records(endpoint, site, path)?;
                    if records.is_empty() {
                        return Err(BrowserError::PinRecordsRequired(p.to_string()));
                    }
                    let page = fetch_page(endpoint, site, path)?;
                    verify_pinned(&page, p, path, &records, now_unix())?;
                    let chain = serde_json::to_vec(&records)
                        .map_err(|e| BrowserError::Content(format!("bad records body: {e}")))?;
                    ids.push(store.put(&chain).map_err(BrowserError::from)?);
                    page
                }
            };
            let bytes = page
                .to_canonical_json()
                .map_err(|e| BrowserError::Content(e.to_string()))?;
            ids.push(store.put(&bytes).map_err(BrowserError::from)?);
        }
        store.export(&ids).map_err(BrowserError::from)
    })();
    let _ = std::fs::remove_dir_all(&stage);
    result
}

/// Outcome of [`sync_site`]: how many pages landed on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncReport {
    /// Pages fetched and written.
    pub pages: usize,
    /// Pages verified against `pin` (subset of `pages`; all of them when
    /// a pin is given, since unverified pages are refused, not written).
    pub verified: usize,
    /// Listed paths skipped as invalid (never written, never fetched).
    pub skipped: usize,
}

/// Mirror a whole site to `dir`: LIST the paths, FETCH each page (plus
/// RECORDS + verification when `pin` is set), and write
/// `<dir>/<path>.json` atomically. A page that fails validation or pin
/// verification aborts the sync with an error and writes nothing for that
/// path (earlier paths stay written; sync is per-page atomic, not
/// transactional).
pub fn sync_site(
    endpoint: &str,
    site: &str,
    pin: Option<&str>,
    dir: &std::path::Path,
) -> Result<SyncReport, BrowserError> {
    let list_line = nexus_protocol::encode_list_request(&nexus_protocol::ListRequest {
        site: site.to_string(),
    })?;
    let (code, body) = nexus_transport::fetch_raw(endpoint, &list_line)?;
    if code != 200 {
        return Err(BrowserError::Status(
            code,
            String::from_utf8_lossy(&body).into_owned(),
        ));
    }
    let paths: Vec<String> = serde_json::from_slice(&body)
        .map_err(|e| BrowserError::Content(format!("bad LIST body: {e}")))?;
    let mut report = SyncReport {
        pages: 0,
        verified: 0,
        skipped: 0,
    };
    for path in paths {
        // Never let a hostile listing touch the filesystem: only wire-valid
        // relative paths pass, and they cannot contain `..` or absolutes.
        if !nexus_protocol::is_valid_path(&path) {
            report.skipped += 1;
            continue;
        }
        let page = match pin {
            None => fetch_page(endpoint, site, &path)?,
            Some(p) => {
                let records = fetch_records(endpoint, site, &path)?;
                if records.is_empty() {
                    return Err(BrowserError::PinRecordsRequired(p.to_string()));
                }
                let page = fetch_page(endpoint, site, &path)?;
                verify_pinned(&page, p, &path, &records, now_unix())?;
                report.verified += 1;
                page
            }
        };
        let bytes = page
            .to_canonical_json()
            .map_err(|e| BrowserError::Content(e.to_string()))?;
        let dest = dir.join(format!("{path}.json"));
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| BrowserError::Content(format!("mkdir: {e}")))?;
        }
        let tmp = dest.with_extension("json.tmp");
        std::fs::write(&tmp, &bytes).map_err(|e| BrowserError::Content(format!("write: {e}")))?;
        std::fs::rename(&tmp, &dest).map_err(|e| BrowserError::Content(format!("publish: {e}")))?;
        report.pages += 1;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_content::{Component, Metadata};
    use std::net::TcpListener;

    fn test_page(site: &str, path: &str) -> Vec<u8> {
        nexus_content::Page {
            metadata: Metadata {
                schema: 1,
                site: site.into(),
                path: path.into(),
                title: "T".into(),
                revision: 1,
            },
            components: vec![Component::Text { text: "hi".into() }],
            capabilities: vec![],
        }
        .to_canonical_json()
        .unwrap()
    }

    fn serve_once(bytes: Vec<u8>) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut store = nexus_server::SiteStore::new();
            store.insert("example", "home", bytes);
            let (stream, _) = listener.accept().unwrap();
            nexus_server::handle_one(&stream, &store).unwrap();
        });
        addr
    }

    /// Serve one page plus its signed records; accepts two connections
    /// (RECORDS then FETCH, in the order `navigate_verified` issues them).
    fn serve_signed_twice(
        page_bytes: Vec<u8>,
        identity: &nexus_identity::SiteIdentity,
    ) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let identity = identity.clone();
        std::thread::spawn(move || {
            let mut store = nexus_server::SiteStore::new();
            store.insert("example", "home", page_bytes);
            store.sign_pages(&identity, 9_999_999_999).unwrap();
            for _ in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                nexus_server::handle_one(&stream, &store).unwrap();
            }
        });
        addr
    }

    fn pinned_route(addr: std::net::SocketAddr, site_id: String) -> LocalResolver {
        let mut r = LocalResolver::new();
        r.insert(
            "example",
            nexus_resolver::Route {
                endpoints: vec![addr.to_string()],
                pinned_site_id: Some(site_id),
            },
        )
        .unwrap();
        r
    }

    #[test]
    fn navigate_via_resolver() {
        let addr = serve_once(test_page("example", "home"));
        let mut r = LocalResolver::new();
        r.insert(
            "example",
            nexus_resolver::Route {
                endpoints: vec![addr.to_string()],
                pinned_site_id: None,
            },
        )
        .unwrap();
        let page = navigate(&r, "example", "home").unwrap();
        assert_eq!(page.metadata.title, "T");
    }

    #[test]
    fn verified_fetch_succeeds_over_wire() {
        let id = nexus_identity::SiteIdentity::from_secret_bytes(&[21u8; 32]).unwrap();
        let addr = serve_signed_twice(test_page("example", "home"), &id);
        let r = pinned_route(addr, id.site_id());
        let page = navigate_verified(&r, "example", "home").unwrap();
        assert_eq!(page.metadata.title, "T");
    }

    #[test]
    fn verified_fetch_rejects_wrong_key() {
        let id = nexus_identity::SiteIdentity::from_secret_bytes(&[22u8; 32]).unwrap();
        let other = nexus_identity::SiteIdentity::from_secret_bytes(&[23u8; 32]).unwrap();
        let addr = serve_signed_twice(test_page("example", "home"), &id);
        // Pinned to a key that never signed the page: fail closed.
        let r = pinned_route(addr, other.site_id());
        assert!(matches!(
            navigate_verified(&r, "example", "home"),
            Err(BrowserError::PinMismatch { .. })
        ));
    }

    #[test]
    fn verified_fetch_fails_closed_without_records() {
        // Recordless server + pinned route: RECORDS 404s, page refused.
        let addr = serve_once(test_page("example", "home"));
        let id = nexus_identity::SiteIdentity::from_secret_bytes(&[24u8; 32]).unwrap();
        let r = pinned_route(addr, id.site_id());
        assert!(matches!(
            navigate_verified(&r, "example", "home"),
            Err(BrowserError::PinRecordsRequired(_))
        ));
    }

    #[test]
    fn session_pin_verifies_history_nav() {
        let id = nexus_identity::SiteIdentity::from_secret_bytes(&[25u8; 32]).unwrap();
        let addr = serve_signed_twice(test_page("example", "home"), &id);
        // NOTE: the test server answers twice; open consumes both (RECORDS
        // + FETCH), so back/forward here only exercise history plumbing.
        let mut session = ClientSession::new(addr.to_string()).with_pin(Some(id.site_id()));
        session.open("example/home").unwrap();
        assert_eq!(session.history.current().unwrap().page.metadata.title, "T");
        // Wrong pin from the start: open fails closed, history stays empty.
        let other = nexus_identity::SiteIdentity::from_secret_bytes(&[26u8; 32]).unwrap();
        let addr2 = serve_signed_twice(test_page("example", "home"), &id);
        let mut bad = ClientSession::new(addr2.to_string()).with_pin(Some(other.site_id()));
        assert!(matches!(
            bad.open("example/home"),
            Err(BrowserError::PinMismatch { .. })
        ));
        assert!(bad.history.current().is_none());
    }

    fn session_cache_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("nexus-session-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn session_with_cache_serves_stale_offline() {
        use std::net::TcpListener;
        let dir = session_cache_dir("stale");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        // One-shot server: answers a single FETCH, then the port dies.
        let page = test_page("example", "home");
        std::thread::spawn(move || {
            let mut store = nexus_server::SiteStore::new();
            store.insert("example", "home", page);
            let (stream, _) = listener.accept().unwrap();
            nexus_server::handle_one(&stream, &store).unwrap();
        });
        let mut session = ClientSession::new(addr.clone()).with_cache(OfflineCache::new(&dir));
        session.open("example/home").unwrap();
        assert_eq!(session.last_status(), Some(CacheStatus::Fresh));
        // Port is dead now: the session serves the cached revision.
        session.open("example/home").unwrap();
        assert_eq!(session.last_status(), Some(CacheStatus::Stale));
        assert_eq!(session.history.current().unwrap().page.metadata.title, "T");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn session_with_cache_serves_verified_stale_offline() {
        use std::net::TcpListener;
        let dir = session_cache_dir("verified");
        let id = nexus_identity::SiteIdentity::from_secret_bytes(&[27u8; 32]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        // Two-shot server: RECORDS + FETCH, then dies.
        let page = test_page("example", "home");
        let server_id = id.clone();
        std::thread::spawn(move || {
            let mut store = nexus_server::SiteStore::new();
            store.insert("example", "home", page);
            store.sign_pages(&server_id, 9_999_999_999).unwrap();
            for _ in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                nexus_server::handle_one(&stream, &store).unwrap();
            }
        });
        let mut session = ClientSession::new(addr.clone())
            .with_pin(Some(id.site_id()))
            .with_cache(OfflineCache::new(&dir));
        session.open("example/home").unwrap();
        assert_eq!(session.last_status(), Some(CacheStatus::Fresh));
        session.open("example/home").unwrap();
        assert_eq!(session.last_status(), Some(CacheStatus::StaleVerified));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_back_forward() {
        let mut h = History::new();
        let visit = |t: &str| Visit {
            site: "example".into(),
            path: t.into(),
            page: nexus_content::Page {
                metadata: Metadata {
                    schema: 1,
                    site: "example".into(),
                    path: t.into(),
                    title: t.into(),
                    revision: 1,
                },
                components: vec![Component::Text { text: "x".into() }],
                capabilities: vec![],
            },
        };
        h.push(visit("a"));
        h.push(visit("b"));
        assert_eq!(h.current().unwrap().path, "b");
        h.back();
        assert_eq!(h.current().unwrap().path, "a");
        h.forward();
        assert_eq!(h.current().unwrap().path, "b");
    }

    #[test]
    fn missing_page_is_status_error() {
        let addr = serve_once(test_page("example", "home"));
        let err = fetch_page(&addr.to_string(), "example", "missing").unwrap_err();
        assert!(matches!(err, BrowserError::Status(404, _)));
    }

    fn visit(path: &str, title: &str) -> Visit {
        Visit {
            site: "example".into(),
            path: path.into(),
            page: nexus_content::Page {
                metadata: Metadata {
                    schema: 1,
                    site: "example".into(),
                    path: path.into(),
                    title: title.into(),
                    revision: 1,
                },
                components: vec![Component::Text { text: "x".into() }],
                capabilities: vec![],
            },
        }
    }

    #[test]
    fn parse_target_defaults_to_home() {
        assert_eq!(
            parse_target("example").unwrap(),
            ("example".into(), "home".into())
        );
        assert_eq!(
            parse_target("example/about").unwrap(),
            ("example".into(), "about".into())
        );
        assert_eq!(
            parse_target("nolan/blog/hello").unwrap(),
            ("nolan".into(), "blog/hello".into())
        );
    }

    #[test]
    fn parse_target_rejects_bad_input() {
        for bad in ["", "example/", "/home", "EXAMPLE", "example/../x", "a b"] {
            assert!(parse_target(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn history_position_len_entries() {
        let mut h = History::new();
        h.push(visit("a", "A"));
        h.push(visit("b", "B"));
        h.push(visit("c", "C"));
        assert_eq!(h.len(), 3);
        assert_eq!(h.position(), 2);
        h.back();
        assert_eq!(h.position(), 1);
        let paths: Vec<&str> = h.entries().iter().map(|v| v.path.as_str()).collect();
        assert_eq!(paths, vec!["a", "b", "c"]);
        h.forward();
        assert_eq!(h.position(), 2);
    }

    #[test]
    fn reload_replaces_current_keeps_future() {
        let mut h = History::new();
        h.push(visit("a", "A"));
        h.push(visit("b", "B"));
        h.back(); // present = a, future = [b]
        h.replace_current(visit("a", "A2").page);
        assert_eq!(h.current().unwrap().page.metadata.title, "A2");
        assert_eq!(h.len(), 2);
        h.forward();
        assert_eq!(h.current().unwrap().path, "b");
    }

    #[test]
    fn pinned_route_fails_closed_without_records() {
        let addr = serve_once(test_page("example", "home"));
        let mut r = LocalResolver::new();
        r.insert(
            "example",
            nexus_resolver::Route {
                endpoints: vec![addr.to_string()],
                pinned_site_id: Some("ab".repeat(32)),
            },
        )
        .unwrap();
        let err = navigate(&r, "example", "home").unwrap_err();
        assert!(matches!(err, BrowserError::PinRecordsRequired(_)));
    }

    #[test]
    fn pinned_route_accepts_matching_signed_record() {
        let addr = serve_once(test_page("example", "home"));
        let id = nexus_identity::SiteIdentity::from_secret_bytes(&[7u8; 32]).unwrap();
        let rec = id
            .sign_record(
                "home",
                &nexus_content::content_id_of(&test_page("example", "home")),
                9_999_999_999,
            )
            .unwrap();
        let mut r = LocalResolver::new();
        r.insert(
            "example",
            nexus_resolver::Route {
                endpoints: vec![addr.to_string()],
                pinned_site_id: Some(id.site_id()),
            },
        )
        .unwrap();
        let page = navigate_with_records(&r, "example", "home", &[rec]).unwrap();
        assert_eq!(page.metadata.title, "T");
    }

    #[test]
    fn pinned_route_rejects_tampered_content() {
        let addr = serve_once(test_page("example", "home"));
        let id = nexus_identity::SiteIdentity::from_secret_bytes(&[8u8; 32]).unwrap();
        // Record vouches for a DIFFERENT hash than the served page.
        let rec = id
            .sign_record("home", &format!("b3:{}", "ab".repeat(32)), 9_999_999_999)
            .unwrap();
        let mut r = LocalResolver::new();
        r.insert(
            "example",
            nexus_resolver::Route {
                endpoints: vec![addr.to_string()],
                pinned_site_id: Some(id.site_id()),
            },
        )
        .unwrap();
        let err = navigate_with_records(&r, "example", "home", &[rec]).unwrap_err();
        assert!(matches!(err, BrowserError::PinMismatch { .. }));
    }
}
