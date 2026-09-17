//! CLI browser core: resolve petname -> endpoint, FETCH, parse, render.
//!
//! Navigation history is a simple past/present/future stack (no tabs).

use nexus_content::Page;
use nexus_resolver::{LocalResolver, Resolver};
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
    #[error("server returned {0}: {1}")]
    Status(u16, String),
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
