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
//!
//! Verified entries (pinning + offline): [`OfflineCache::put_verified`]
//! stores the page together with the signed chain that vouched for it and
//! the pinned site id. [`OfflineCache::lookup_verified`] re-verifies the
//! chain before serving, so a pinned page stays trustworthy with no
//! network. A chain that no longer verifies is a miss and evicts the entry.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use nexus_content::Page;
use nexus_storage::FsStore;
use serde::{Deserialize, Serialize};

use crate::BrowserError;

/// How a page was obtained. `Stale`/`StaleVerified` are the offline banner
/// markers: served from cache after a transport failure instead of the
/// network (`StaleVerified` additionally re-checked the record chain).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheStatus {
    /// Served from the network on this fetch.
    Fresh,
    /// Served from cache (offline), unverified.
    Stale,
    /// Served from cache (offline) with the pinned chain re-verified.
    StaleVerified,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Index {
    pages: BTreeMap<String, Entry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    content_id: String,
    fetched_at: u64,
    /// CAS id of the JSON-encoded record chain, if the fetch was verified.
    #[serde(default)]
    records_id: Option<String>,
    /// Pinned site id the chain was verified against, if any.
    #[serde(default)]
    pin: Option<String>,
}

/// Outcome of [`OfflineCache::gc`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GcReport {
    /// Blob/tmp files deleted.
    pub files_removed: usize,
    /// Sum of deleted file sizes.
    pub bytes_freed: u64,
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

/// True for canonical `b3:<64 lowercase hex>` ids (the only names the blob
/// store itself ever creates; anything else on disk is foreign).
fn is_blob_id(id: &str) -> bool {
    let hex = match id.strip_prefix("b3:") {
        Some(h) => h,
        None => return false,
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
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

    /// Content id currently cached for (site, path), if any (index read
    /// only — no blob verification; the 304 path revalidates fully).
    pub fn cached_id(&self, site: &str, path: &str) -> Option<String> {
        if !valid_key(site, path) {
            return None;
        }
        self.read_index()
            .ok()?
            .pages
            .get(&key(site, path))
            .map(|e| e.content_id.clone())
    }

    /// Fetch `(site, path)` from `endpoint`, persisting on success. Sends
    /// the cached content id as a precondition when present: an unchanged
    /// page comes back `304` with no body and is served from cache as
    /// `Fresh` (revalidated, not stale). On transport failure only, serve
    /// the cached revision as `Stale`; other errors (404, malformed
    /// response) are never shadowed.
    pub fn fetch(
        &self,
        endpoints: &[String],
        site: &str,
        path: &str,
    ) -> Result<(Page, CacheStatus), BrowserError> {
        let req = nexus_protocol::FetchRequest {
            site: site.to_string(),
            path: path.to_string(),
            if_id: self.cached_id(site, path),
        };
        // Validate before sending so errors are local, not network roundtrips.
        nexus_protocol::encode_request(&req)?;
        match crate::failover(endpoints, |endpoint| {
            nexus_transport::fetch(endpoint, &req).map_err(BrowserError::from)
        }) {
            Ok((200, body)) => {
                let page = nexus_content::Page::from_json(&body)
                    .map_err(|e| BrowserError::Content(e.to_string()))?;
                let _ = self.put(site, path, &page);
                Ok((page, CacheStatus::Fresh))
            }
            Ok((304, _)) => match self.lookup(site, path) {
                // Confirmed current by the server; corrupt local copy falls
                // back to one unconditional fetch rather than failing.
                Some(page) => Ok((page, CacheStatus::Fresh)),
                None => Ok((
                    crate::fetch_page_any(endpoints, site, path)?,
                    CacheStatus::Fresh,
                )),
            },
            Ok((code, body)) => Err(BrowserError::Status(
                code,
                String::from_utf8_lossy(&body).into_owned(),
            )),
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
        self.put_inner(site, path, page, None, None)
    }

    /// Best-effort store of a verified fetch: the page plus the record
    /// chain that vouched for it and the pinned site id. Replaces any
    /// previous revision.
    pub fn put_verified(
        &self,
        site: &str,
        path: &str,
        page: &Page,
        records: &[nexus_identity::SignedRecord],
        pin: &str,
    ) -> Result<(), BrowserError> {
        let chain = serde_json::to_vec(records)
            .map_err(|e| BrowserError::Content(format!("bad records body: {e}")))?;
        let records_id = self.blobs.put(&chain)?;
        self.put_inner(site, path, page, Some(records_id), Some(pin.to_string()))
    }

    fn put_inner(
        &self,
        site: &str,
        path: &str,
        page: &Page,
        records_id: Option<String>,
        pin: Option<String>,
    ) -> Result<(), BrowserError> {
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
            records_id,
            pin,
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

    /// Verified lookup: like [`OfflineCache::lookup`], but the entry must
    /// carry a record chain for exactly `pin`, and the chain must still
    /// verify against the cached page right now (expiry included). Anything
    /// less is a miss and evicts the entry — a stale chain must never
    /// shadow a future honest fetch.
    pub fn lookup_verified(&self, site: &str, path: &str, pin: &str) -> Option<Page> {
        if !valid_key(site, path) {
            return None;
        }
        let idx = self.read_index().ok()?;
        let entry = idx.pages.get(&key(site, path))?;
        if entry.pin.as_deref() != Some(pin) {
            return None;
        }
        // Any chain failure evicts: a stale chain must never shadow a
        // future honest fetch.
        let records_id = entry.records_id.as_ref()?;
        let chain_bytes = match self.blobs.get(records_id) {
            Ok(b) => b,
            Err(_) => {
                self.remove(site, path);
                return None;
            }
        };
        let records: Vec<nexus_identity::SignedRecord> = match serde_json::from_slice(&chain_bytes)
        {
            Ok(r) => r,
            Err(_) => {
                self.remove(site, path);
                return None;
            }
        };
        let page = self.lookup(site, path)?;
        if crate::verify_pinned(&page, pin, path, &records, now()).is_err() {
            self.remove(site, path);
            return None;
        }
        Some(page)
    }

    /// Fetch with pin verification and offline fallback. Fresh path stores
    /// page + chain via [`OfflineCache::put_verified`]; transport failure
    /// serves [`CacheStatus::StaleVerified`] from [`OfflineCache::lookup_verified`].
    /// Non-transport errors (404, bad records, pin mismatch) are never shadowed.
    pub fn fetch_verified(
        &self,
        endpoints: &[String],
        site: &str,
        path: &str,
        pin: &str,
    ) -> Result<(Page, CacheStatus), BrowserError> {
        let fresh = (|| {
            let page = crate::fetch_page_any(endpoints, site, path)?;
            let records = crate::fetch_records_any(endpoints, site, path)?;
            if records.is_empty() {
                return Err(BrowserError::PinRecordsRequired(pin.to_string()));
            }
            crate::verify_pinned(&page, pin, path, &records, now())?;
            let _ = self.put_verified(site, path, &page, &records, pin);
            Ok((page, CacheStatus::Fresh))
        })();
        match fresh {
            Err(e @ BrowserError::Transport(nexus_transport::TransportError::Io(_))) => self
                .lookup_verified(site, path, pin)
                .map(|p| (p, CacheStatus::StaleVerified))
                .ok_or(e),
            other => other,
        }
    }

    /// Garbage-collect the blob store: delete `*.tmp` leftovers from
    /// interrupted writes and valid content blobs no live index entry points
    /// at (superseded revisions, evicted chains, corruption leftovers).
    /// Files that do not look like content blobs are left alone. Returns
    /// what was removed. Concurrent `put`s may race a collection run;
    /// treat GC as maintenance, not as synchronized with fetching.
    pub fn gc(&self) -> GcReport {
        use std::collections::HashSet;
        let mut report = GcReport::default();
        // Live set: every blob id named by the index (pages + chains).
        let mut live: HashSet<String> = HashSet::new();
        if let Ok(idx) = self.read_index() {
            for entry in idx.pages.values() {
                live.insert(entry.content_id.clone());
                live.extend(entry.records_id.clone());
            }
        }
        let blobs_root = self.blobs.dir();
        let Ok(root) = std::fs::read_dir(blobs_root) else {
            return report;
        };
        for shard in root.flatten() {
            let Ok(level) = std::fs::read_dir(shard.path()) else {
                continue;
            };
            for file in level.flatten() {
                let name = file.file_name().to_string_lossy().into_owned();
                // Interrupted-write leftovers always go.
                if name.ends_with(".tmp") {
                    if let Ok(meta) = file.metadata() {
                        report.bytes_freed += meta.len();
                        report.files_removed += 1;
                    }
                    let _ = std::fs::remove_file(file.path());
                    continue;
                }
                // Reconstruct the content id this file would carry.
                let shard_name = shard.file_name().to_string_lossy().into_owned();
                let id = format!("b3:{shard_name}{name}");
                if !is_blob_id(&id) {
                    continue; // foreign file: not ours, don't touch
                }
                if live.contains(&id) {
                    continue;
                }
                if let Ok(meta) = file.metadata() {
                    report.bytes_freed += meta.len();
                    report.files_removed += 1;
                }
                let _ = std::fs::remove_file(file.path());
            }
        }
        report
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

    #[test]
    fn gc_reaps_orphans_and_tmp_but_not_foreign() {
        let dir = temp_dir("gc");
        let c = OfflineCache::new(&dir);
        c.put("example", "home", &page("example", "home", 1))
            .unwrap();
        c.put("example", "home", &page("example", "home", 2))
            .unwrap();
        // One live blob (rev 2); rev 1 is orphaned.
        // Foreign file + stale tmp alongside the shards:
        let shard = dir.join("blobs").join("ab");
        std::fs::create_dir_all(&shard).unwrap();
        std::fs::write(shard.join("not-a-blob"), b"hands off").unwrap();
        std::fs::write(shard.join("deadbeef.tmp"), b"partial").unwrap();
        let report = c.gc();
        assert_eq!(
            report.files_removed, 2,
            "orphan blob + tmp, not the foreign file"
        );
        assert!(report.bytes_freed > 0);
        assert!(shard.join("not-a-blob").exists());
        assert!(!shard.join("deadbeef.tmp").exists());
        // Live entry still serves after collection.
        assert!(c.lookup("example", "home").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unverified_put_supersedes_verified_entry() {
        // A pin must never be satisfiable by unpinned bytes: a plain `put`
        // drops the chain, so verified lookup misses afterwards.
        use nexus_identity::SiteIdentity;
        let dir = temp_dir("supersede");
        let c = OfflineCache::new(&dir);
        let id = SiteIdentity::from_secret_bytes(&[41u8; 32]).unwrap();
        let p = page("example", "home", 1);
        let rec = id
            .sign_record("home", &p.content_id().unwrap(), 9_999_999_999)
            .unwrap();
        c.put_verified("example", "home", &p, &[rec], &id.site_id())
            .unwrap();
        assert!(c
            .lookup_verified("example", "home", &id.site_id())
            .is_some());
        c.put("example", "home", &p).unwrap();
        assert!(c
            .lookup_verified("example", "home", &id.site_id())
            .is_none());
        // ...but the plain lookup still serves (unverified path unaffected).
        assert!(c.lookup("example", "home").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
