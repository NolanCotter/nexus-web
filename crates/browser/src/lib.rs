//! CLI browser core: resolve petname -> endpoint, FETCH, parse, render.
//!
//! Navigation history is a simple past/present/future stack (no tabs).
//! [`cache`] adds the offline-first disk page cache (Milestone G).

pub mod cache;

pub use cache::{CacheStatus, OfflineCache};

use nexus_content::Page;
use nexus_resolver::{LocalResolver, Resolver};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BrowserError {
    #[error("resolve: {0}")]
    Resolve(#[from] nexus_resolver::ResolveError),
    #[error("transport: {0}")]
    Transport(#[from] nexus_transport::TransportError),
    #[error("protocol: {0}")]
    Protocol(#[from] nexus_protocol::ProtocolError),
    #[error("content: {0}")]
    Content(String),
    #[error("cache: {0}")]
    Cache(String),
    #[error("server returned {0}: {1}")]
    Status(u16, String),
}

impl From<nexus_storage::StoreError> for BrowserError {
    fn from(e: nexus_storage::StoreError) -> Self {
        BrowserError::Cache(e.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct Visit {
    pub site: String,
    pub path: String,
    pub page: Page,
}

#[derive(Debug, Default)]
pub struct History {
    past: Vec<Visit>,
    present: Option<Visit>,
    future: Vec<Visit>,
}

impl History {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, visit: Visit) {
        if let Some(cur) = self.present.take() {
            self.past.push(cur);
        }
        self.present = Some(visit);
        self.future.clear();
    }

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

    pub fn forward(&mut self) -> Option<&Visit> {
        let next = self.future.pop()?;
        if let Some(cur) = self.present.take() {
            self.past.push(cur);
        }
        self.present = Some(next);
        self.present.as_ref()
    }

    pub fn current(&self) -> Option<&Visit> {
        self.present.as_ref()
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
pub fn navigate(resolver: &LocalResolver, site: &str, path: &str) -> Result<Page, BrowserError> {
    let route = resolver.resolve(site)?;
    let endpoint = route
        .endpoints
        .first()
        .ok_or_else(|| BrowserError::Content("route has no endpoints".into()))?;
    fetch_page(endpoint, site, path)
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
}
