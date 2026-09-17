//! Petname-first resolution: name -> identity -> records -> nodes.
//!
//! The local resolver maps human petnames (e.g. `example`) to a
//! [`Route`] describing where to reach the site. Distributed resolution
//! (DHT/gossip) is a future extension behind the [`Resolver`] trait.
//!
//! Extension layer (Task E):
//! - [`backend`]  — the backend seam: federated (v1), gossip (v2), DHT (v3),
//!   plus an in-memory conformance backend.
//! - [`resolve`]  — signed-record resolution: `EndpointRecord` (records →
//!   nodes), the verified `RecordStore`, and `CachingResolver` chaining the
//!   warm petname table with record backends.

pub mod backend;
pub mod resolve;

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Current unix time in seconds (single clock for the whole resolver,
/// so tests can reason about expiry deterministically).
pub(crate) fn resolve_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("unknown site: {0}")]
    UnknownSite(String),
    #[error("invalid name: {0}")]
    InvalidName(String),
    #[error("resolver misconfigured: {0}")]
    Misconfigured(String),
    #[error("signature verification failed: {0}")]
    BadSignature(String),
    #[error("record expired at {0} (now {1})")]
    Expired(u64, u64),
}

/// Where a site can be reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// TCP endpoints as `host:port`.
    pub endpoints: Vec<String>,
    /// Optional expected site ID (hex pubkey) for pinning.
    pub pinned_site_id: Option<String>,
}

impl Route {
    pub fn local(port: u16) -> Self {
        Self {
            endpoints: vec![format!("127.0.0.1:{port}")],
            pinned_site_id: None,
        }
    }
}

pub trait Resolver: std::fmt::Debug + Send + Sync {
    fn resolve(&self, name: &str) -> Result<Route, ResolveError>;
    fn list_names(&self) -> Vec<String>;
}

/// Petname validity: canonical site-name rule, single-sourced from
/// [`nexus_protocol::is_valid_site`] so wire parsing and the petname table
/// can never disagree (same charset, same 64-char limit, same dash rules).
pub use nexus_protocol::is_valid_site as is_valid_name;

/// Simplest resolver: static in-memory petname table.
#[derive(Debug, Default, Clone)]
pub struct LocalResolver {
    table: HashMap<String, Route>,
}

impl LocalResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, name: &str, route: Route) -> Result<(), ResolveError> {
        if !is_valid_name(name) {
            return Err(ResolveError::InvalidName(name.to_string()));
        }
        if route.endpoints.is_empty() {
            return Err(ResolveError::Misconfigured("route has no endpoints".into()));
        }
        self.table.insert(name.to_string(), route);
        Ok(())
    }

    pub fn remove(&mut self, name: &str) {
        self.table.remove(name);
    }
}

impl Resolver for LocalResolver {
    fn resolve(&self, name: &str) -> Result<Route, ResolveError> {
        if !is_valid_name(name) {
            return Err(ResolveError::InvalidName(name.to_string()));
        }
        self.table
            .get(name)
            .cloned()
            .ok_or_else(|| ResolveError::UnknownSite(name.to_string()))
    }

    fn list_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.table.keys().cloned().collect();
        names.sort();
        names
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_known_name() {
        let mut r = LocalResolver::new();
        r.insert("example", Route::local(7843)).unwrap();
        let route = r.resolve("example").unwrap();
        assert_eq!(route.endpoints, vec!["127.0.0.1:7843"]);
    }

    #[test]
    fn unknown_site_errors() {
        let r = LocalResolver::new();
        assert!(matches!(
            r.resolve("nope"),
            Err(ResolveError::UnknownSite(_))
        ));
    }

    #[test]
    fn rejects_invalid_names() {
        let mut r = LocalResolver::new();
        assert!(r.insert("Example", Route::local(1)).is_err());
        assert!(r.resolve("EXAMPLE").is_err());
        assert!(r.resolve("../evil").is_err());
        assert!(r.resolve("").is_err());
    }

    #[test]
    fn rejects_empty_route() {
        let mut r = LocalResolver::new();
        assert!(r
            .insert(
                "example",
                Route {
                    endpoints: vec![],
                    pinned_site_id: None
                }
            )
            .is_err());
    }

    #[test]
    fn list_names_sorted() {
        let mut r = LocalResolver::new();
        r.insert("beta", Route::local(2)).unwrap();
        r.insert("alpha", Route::local(1)).unwrap();
        assert_eq!(r.list_names(), vec!["alpha", "beta"]);
    }
}
