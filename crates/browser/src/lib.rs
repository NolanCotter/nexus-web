//! CLI browser core: resolve petname -> endpoint, FETCH, parse, render.
//!
//! Navigation history is a simple past/present/future stack (no tabs).

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
    #[error("server returned {0}: {1}")]
    Status(u16, String),
    #[error("route pins site {0} but no signed records were provided; refusing to fetch")]
    PinRecordsRequired(String),
    #[error("pinned page verification failed for {site}/{path}: {reason}")]
    PinMismatch {
        site: String,
        path: String,
        reason: String,
    },
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
/// With no records supplied, any pinned route (`Some` `pinned_site_id`)
/// fails closed: fetching unverified content is refused.
pub fn navigate(resolver: &LocalResolver, site: &str, path: &str) -> Result<Page, BrowserError> {
    navigate_with_records(resolver, site, path, &[])
}

/// Resolve, fetch, and verify against an explicit chain of signed records.
///
/// The server does not serve [`SignedRecord`]s yet (gap — 007 doc), so
/// records are accepted explicitly instead of fetched from the wire. When
/// `Route.pinned_site_id` is `Some`, at least one record must match the
/// pinned site, the path, and the fetched page's BLAKE3 content id.
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
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        verify_pinned(&page, pinned, path, records, now)?;
    }
    Ok(page)
}

/// Fail-closed pin check: at least one record must vouch that the canonical
/// content id of `page` is what `pinned_site_id` signed for `path`.
fn verify_pinned(
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
