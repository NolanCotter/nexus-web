//! Disk-backed offline page cache (Milestone G).
//!
//! Storage root: `$NEXUS_CACHE_DIR` or `~/.cache/nexus` (survives reboots and
//! is shared by every CLI invocation, unlike per-session OS temp dirs).
//! Layout: `index.json` — (site, path) -> { content_id, fetched_at } with
//! atomic writes — plus `blobs/`, a content-addressed store via
//! `nexus_storage::FsStore`.
//!
//! Semantics:
//! - Successful fetches are stored best-effort; a disk failure never fails a
//!   fresh fetch (caching is optimization, not correctness).
//! - A transport-layer fetch failure (connection refused/timeout) serves the
//!   cached revision as [`CacheStatus::Stale`].
//! - Every fresh fetch replaces the entry for (site, path), so a changed
//!   server revision supersedes the stale copy immediately (revision-based
//!   TTL; no wall-clock expiry).
//! - Cached bytes are BLAKE3-verified and re-validated via `Page::from_json`
//!   before serving. Corruption, invalid pages, or metadata mismatches are a
//!   miss and evict the entry; a page failing `Page::validate` is never served.
//! - Evicted/superseded blob revisions remain in the CAS (GC is future work).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use nexus_content::Page;
use nexus_storage::FsStore;
use serde::{Deserialize, Serialize};

use crate::BrowserError;

/// How a page was obtained. `Stale` is the offline banner marker: served
/// from cache after a transport failure instead of the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheStatus {
    Fresh, // served from the network on this fetch
    Stale, // served from cache (offline)
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Index {
    pages: BTreeMap<String, Entry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    content_id: String,
    fetched_at: u64,
}

/// Disk-backed cache shared by every CLI invocation.
#[derive(Debug)]
pub struct OfflineCache {
    dir: PathBuf,
    blobs: FsStore,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Index key; 0x1f (unit separator) cannot appear in a validated site/path.
fn key(site: &str, path: &str) -> String {
    format!("{site}\u{1f}{path}")
}

fn valid_key(site: &str, path: &str) -> bool {
    nexus_protocol::is_valid_site(site) && nexus_protocol::is_valid_path(path)
}

impl OfflineCache {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        Self {
            blobs: FsStore::new(dir.join("blobs")),
            dir,
        }
    }

    pub fn open_default() -> Self {
        Self::new(Self::default_dir())
    }

    /// `$NEXUS_CACHE_DIR`, else `~/.cache/nexus`.
    pub fn default_dir() -> PathBuf {
        if let Ok(dir) = std::env::var("NEXUS_CACHE_DIR") {
            return PathBuf::from(dir);
        }
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".cache").join("nexus")
    }

    /// Fetch `(site, path)` from `endpoint`, persisting on success. On
    /// transport failure only, serve the cached revision as `Stale`; other
    /// errors (404, malformed response) are never shadowed.
    pub fn fetch(
        &self,
        endpoint: &str,
        site: &str,
        path: &str,
    ) -> Result<(Page, CacheStatus), BrowserError> {
        match crate::fetch_page(endpoint, site, path) {
            Ok(page) => {
                let _ = self.put(site, path, &page);
                Ok((page, CacheStatus::Fresh))
            }
            Err(e @ BrowserError::Transport(nexus_transport::TransportError::Io(_))) => self
                .lookup(site, path)
                .map(|p| (p, CacheStatus::Stale))
                .ok_or(e),
            Err(e) => Err(e),
        }
    }

    /// Best-effort store of a validated page under (site, path), replacing
    /// any previous revision (cache writes never fail a fresh fetch).
    pub fn put(&self, site: &str, path: &str, page: &Page) -> Result<(), BrowserError> {
        if !valid_key(site, path) {
            return Ok(());
        }
        let bytes = page
            .to_canonical_json()
            .map_err(|e| BrowserError::Content(e.to_string()))?;
        let content_id = page
            .content_id()
            .map_err(|e| BrowserError::Content(e.to_string()))?;
        self.blobs.put(&bytes)?;
        let mut idx = self.read_index().unwrap_or_default();
        let entry = Entry {
            content_id,
            fetched_at: now(),
        };
        idx.pages.insert(key(site, path), entry);
        self.write_index(&idx)
    }

    /// Cache lookup: verify content hash, re-validate the page, and confirm it
    /// claims (site, path). Any failure — missing entry, corrupt blob, invalid
    /// page, metadata mismatch — is a miss and evicts the entry.
    pub fn lookup(&self, site: &str, path: &str) -> Option<Page> {
        if !valid_key(site, path) {
            return None;
        }
        let idx = self.read_index().ok()?;
        let content_id = idx.pages.get(&key(site, path))?.content_id.clone();
        let bytes = match self.blobs.get(&content_id) {
            Ok(b) => b,
            Err(_) => {
                self.remove(site, path);
                return None;
            }
        };
        match Page::from_json(&bytes) {
            Ok(page) if page.metadata.site == site && page.metadata.path == path => Some(page),
            _ => {
                self.remove(site, path);
                None
            }
        }
    }

    pub fn remove(&self, site: &str, path: &str) {
        if !valid_key(site, path) {
            return;
        }
        let Ok(mut idx) = self.read_index() else {
            return;
        };
        if idx.pages.remove(&key(site, path)).is_some() {
            let _ = self.write_index(&idx);
        }
    }

    fn read_index(&self) -> Result<Index, BrowserError> {
        let bytes = match std::fs::read(self.dir.join("index.json")) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Index::default()),
            Err(e) => return Err(BrowserError::Cache(e.to_string())),
        };
        serde_json::from_slice(&bytes).map_err(|e| BrowserError::Cache(e.to_string()))
    }

    fn write_index(&self, idx: &Index) -> Result<(), BrowserError> {
        let bytes = serde_json::to_vec(idx).map_err(|e| BrowserError::Cache(e.to_string()))?;
        std::fs::create_dir_all(&self.dir).map_err(|e| BrowserError::Cache(e.to_string()))?;
        let tmp = self.dir.join("index.json.tmp");
        std::fs::write(&tmp, bytes).map_err(|e| BrowserError::Cache(e.to_string()))?;
        std::fs::rename(&tmp, self.dir.join("index.json"))
            .map_err(|e| BrowserError::Cache(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("nexus-cache-unit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn page(site: &str, path: &str, revision: u64) -> Page {
        use nexus_content::{Component, Metadata};
        Page {
            metadata: Metadata {
                schema: 1,
                site: site.into(),
                path: path.into(),
                title: "T".into(),
                revision,
            },
            components: vec![Component::Text { text: "hi".into() }],
            capabilities: vec![],
        }
    }

    /// Defense in depth: keys failing protocol validation never reach the index
    /// or blob store (`put`/`lookup` are public API; wire validation blocks
    /// them first). Roundtrip/revision behavior is covered by the e2e tests.
    #[test]
    fn invalid_keys_never_touch_cache() {
        let dir = temp_dir("keys");
        let c = OfflineCache::new(&dir);
        assert_eq!(c.lookup("../../etc", "passwd"), None);
        assert_eq!(c.lookup("example", "../secret"), None);
        assert_eq!(c.lookup("", "home"), None);
        c.put("Example", "home", &page("Example", "home", 1))
            .unwrap(); // invalid site: no-op
        assert!(c.lookup("Example", "home").is_none());
        assert!(!dir.join("index.json").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
