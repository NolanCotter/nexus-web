//! CLI browser core: resolve petname -> endpoint, FETCH, parse, render.
//!
//! Navigation history is a simple past/present/future stack (no tabs).

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
    #[error("server returned {0}: {1}")]
    Status(u16, String),
    #[error("bad target '{0}': {1}")]
    BadTarget(String, String),
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
    pub history: History,
}

impl ClientSession {
    pub fn new(server: impl Into<String>) -> Self {
        Self {
            resolver: LocalResolver::new(),
            server: server.into(),
            history: History::new(),
        }
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
                    pinned_site_id: None,
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
        fetch_page(endpoint, site, path)
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
}
