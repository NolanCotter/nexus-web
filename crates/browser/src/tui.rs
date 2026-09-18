//! Full-screen terminal browser state machine (Milestone: TUI).
//!
//! [`TuiState`] is pure logic over [`ClientSession`]: input line, scroll
//! offset, and status text. It knows nothing about terminals, so every
//! transition is unit-testable. The `nexus-tui` binary wires it to
//! ratatui/crossterm for drawing and key events.
//!
//! Extra polish, all in here so the binary stays thin:
//! - `visited` log persisted to `$NEXUS_CACHE_DIR/history.json` (cap 100,
//!   corrupt/missing file starts empty, writes are best-effort).
//! - find-in-page: `/` starts a query, matches are case-insensitive
//!   substrings over rendered lines, `n` jumps to the next match.
//! - `?` toggles a keybinding cheatsheet overlay.

use std::path::{Path, PathBuf};

use crossterm::event::KeyCode;
use serde::{Deserialize, Serialize};

use crate::{BrowserError, ClientSession};

/// What the event loop should do after a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyAction {
    /// Keep running.
    Continue,
    /// Exit the browser.
    Quit,
}

/// Cap for the persisted visited log (oldest entries drop first).
pub const HISTORY_MAX_ENTRIES: usize = 100;

/// One persisted history entry: where we went (page bytes are refetched,
/// never stored here).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryVisit {
    /// Site that was visited.
    pub site: String,
    /// Path that was visited.
    pub path: String,
}

/// Editable address line + scroll + status over a browsing session.
#[derive(Debug)]
pub struct TuiState {
    session: ClientSession,
    input: String,
    scroll: usize,
    status: String,
    visited: Vec<HistoryVisit>,
    finding: bool,
    find_query: String,
    find_matches: Vec<usize>,
    find_pos: usize,
    show_help: bool,
}

impl TuiState {
    /// New browser against `server`; `pin` enables verified fetches.
    pub fn new(server: impl Into<String>, pin: Option<String>) -> Self {
        Self {
            session: ClientSession::new(server).with_pin(pin),
            input: String::new(),
            scroll: 0,
            status: String::from("type a target (site[/path]) and press Enter"),
            visited: Vec::new(),
            finding: false,
            find_query: String::new(),
            find_matches: Vec::new(),
            find_pos: 0,
            show_help: false,
        }
    }

    /// Open `target`, resetting scroll; failures become status text and
    /// leave the current page (and history) untouched. Transport failures
    /// (nothing listening) read as `offline:` since the TUI fetches fresh
    /// only — no cache is plumbed in (out of scope).
    pub fn open(&mut self, target: &str) {
        match self.session.open(target) {
            Ok(()) => {
                self.scroll = 0;
                self.input.clear();
                self.clear_find();
                if let Some(v) = self.session.history.current() {
                    self.record_visit(&v.site.clone(), &v.path.clone());
                }
                self.status = self.where_am_i();
            }
            Err(e) if matches!(e, BrowserError::Transport(_)) => {
                self.status = format!("offline: {e}");
            }
            Err(e) => self.status = format!("error: {e}"),
        }
    }

    /// History navigation and reload; failures become status text.
    pub fn back(&mut self) {
        self.navigate(|s| s.back(), "at the start of history");
    }

    /// History navigation and reload; failures become status text.
    pub fn forward(&mut self) {
        self.navigate(|s| s.forward(), "at the end of history");
    }

    /// History navigation and reload; failures become status text.
    pub fn reload(&mut self) {
        self.navigate(|s| s.reload(), "reload failed");
    }

    fn navigate(
        &mut self,
        step: impl FnOnce(&mut ClientSession) -> Result<(), BrowserError>,
        empty_note: &str,
    ) {
        match step(&mut self.session) {
            Ok(()) => {
                self.scroll = 0;
                self.clear_find();
                self.status = self.where_am_i();
            }
            Err(e) => self.status = format!("{empty_note}: {e}"),
        }
    }

    /// Attach the offline page cache: fetches fall back to cached
    /// revisions (verified ones when pinned) with no network.
    pub fn with_cache(mut self, cache: crate::OfflineCache) -> Self {
        // Move the live session out, apply the builder, move it back; the
        // placeholder never serves a fetch.
        let session = std::mem::replace(&mut self.session, ClientSession::new(String::new()));
        self.session = session.with_cache(cache);
        self
    }

    /// Human-readable location line for the status bar, with an offline
    /// marker when the current page came from cache.
    pub fn where_am_i(&self) -> String {
        let base = match self.session.history.current() {
            Some(v) => format!("@{} /{} — {}", v.site, v.path, v.page.metadata.title),
            None => String::from("(no page loaded)"),
        };
        match self.session.last_status() {
            Some(crate::CacheStatus::Stale) => format!("{base} [offline]"),
            Some(crate::CacheStatus::StaleVerified) => format!("{base} [offline, verified]"),
            _ => base,
        }
    }

    /// Current page rendered as terminal lines (unwrapped here; the
    /// widget layer wraps).
    pub fn page_lines(&self) -> Vec<String> {
        match self.session.history.current() {
            Some(v) => nexus_renderer::render_text(&v.page)
                .lines()
                .map(str::to_string)
                .collect(),
            None => vec![String::from("No page. Open site[/path] above.")],
        }
    }

    /// Scroll offset clamped to the content for `viewport_height`.
    pub fn visible_range(&self, viewport_height: usize) -> (usize, usize) {
        let total = self.page_lines().len();
        let max_start = total.saturating_sub(viewport_height.max(1));
        let start = self.scroll.min(max_start);
        (start, (start + viewport_height).min(total))
    }

    /// Move the viewport; clamps at both ends, never panics on empty pages.
    pub fn scroll_by(&mut self, delta: isize, viewport_height: usize) {
        let total = self.page_lines().len();
        let max_start = total.saturating_sub(viewport_height.max(1)) as isize;
        let next = (self.scroll as isize + delta).clamp(0, max_start.max(0));
        self.scroll = next as usize;
    }

    /// Handle one key press. Single-letter commands only fire when the
    /// input line is empty, so target text is never hijacked.
    pub fn handle_key(&mut self, code: KeyCode) -> KeyAction {
        if self.finding {
            match code {
                KeyCode::Enter => self.commit_find(),
                KeyCode::Esc => self.cancel_find(),
                KeyCode::Backspace => self.edit_find(None),
                KeyCode::Char(c) => self.edit_find(Some(c)),
                _ => {}
            }
            return KeyAction::Continue;
        }
        match code {
            KeyCode::Char('q') if self.input.is_empty() => return KeyAction::Quit,
            KeyCode::Char('?') if self.input.is_empty() => self.toggle_help(),
            KeyCode::Char('/') if self.input.is_empty() => self.enter_find(),
            KeyCode::Char('n') if self.input.is_empty() => self.next_match(24),
            KeyCode::Char('b') if self.input.is_empty() => self.back(),
            KeyCode::Char('f') if self.input.is_empty() => self.forward(),
            KeyCode::Char('r') if self.input.is_empty() => self.reload(),
            KeyCode::Enter => {
                if !self.input.trim().is_empty() {
                    let target = self.input.trim().to_string();
                    self.open(&target);
                }
            }
            KeyCode::Esc => {
                if self.input.is_empty() && self.show_help {
                    self.show_help = false;
                } else {
                    self.input.clear();
                }
            }
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Up => self.scroll_by(-1, 24),
            KeyCode::Down => self.scroll_by(1, 24),
            KeyCode::PageUp => self.scroll_by(-20, 24),
            KeyCode::PageDown => self.scroll_by(20, 24),
            KeyCode::Char(c) => self.input.push(c),
            _ => {}
        }
        KeyAction::Continue
    }

    /// Current address-line contents.
    pub fn input(&self) -> &str {
        &self.input
    }

    /// Current scroll offset (lines from the top).
    pub fn scroll(&self) -> usize {
        self.scroll
    }

    /// Current status-bar text.
    pub fn status(&self) -> &str {
        &self.status
    }

    /// Number of history entries (for the status bar).
    pub fn history_len(&self) -> usize {
        self.session.history.len()
    }

    /// Whether this session verifies fetches against a pinned site id.
    pub fn is_pinned(&self) -> bool {
        self.session.pin().is_some()
    }

    /// Visited (site, path) log, oldest first; persisted via
    /// [`TuiState::save_history`] / [`TuiState::load_history`].
    pub fn visited(&self) -> &[HistoryVisit] {
        &self.visited
    }

    /// History file: `$NEXUS_CACHE_DIR/history.json` (same dir logic as
    /// the offline page cache).
    pub fn history_file() -> PathBuf {
        crate::OfflineCache::default_dir().join("history.json")
    }

    /// Record a visit (consecutive duplicates collapse); oldest entries
    /// drop past [`HISTORY_MAX_ENTRIES`].
    pub fn record_visit(&mut self, site: &str, path: &str) {
        if self
            .visited
            .last()
            .is_some_and(|v| v.site == site && v.path == path)
        {
            return;
        }
        self.visited.push(HistoryVisit {
            site: site.into(),
            path: path.into(),
        });
        if self.visited.len() > HISTORY_MAX_ENTRIES {
            self.visited
                .drain(..self.visited.len() - HISTORY_MAX_ENTRIES);
        }
    }

    /// Write the visited log to `path` (atomic tmp + rename). Errors are
    /// returned so tests can assert; [`TuiState::save_history`] swallows.
    pub fn save_to_file(&self, path: &Path) -> Result<(), String> {
        let bytes = serde_json::to_vec(&self.visited).map_err(|e| e.to_string())?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Load the visited log from `path`. Missing, empty, or corrupt files
    /// (and entries failing site/path validation) yield an empty log —
    /// never an error, never a panic. Over-long files keep the newest.
    pub fn load_from_file(&mut self, path: &Path) {
        let Ok(bytes) = std::fs::read(path) else {
            self.visited.clear();
            return;
        };
        let mut entries: Vec<HistoryVisit> = serde_json::from_slice(&bytes).unwrap_or_default();
        entries.retain(|v| {
            nexus_protocol::is_valid_site(&v.site) && nexus_protocol::is_valid_path(&v.path)
        });
        if entries.len() > HISTORY_MAX_ENTRIES {
            entries.drain(..entries.len() - HISTORY_MAX_ENTRIES);
        }
        self.visited = entries;
    }

    /// Best-effort save to [`TuiState::history_file`] (disk failure keeps
    /// the session running; the in-memory log is unaffected).
    pub fn save_history(&self) {
        let _ = self.save_to_file(&Self::history_file());
    }

    /// Restore from [`TuiState::history_file`]; corrupt/missing starts empty.
    pub fn load_history(&mut self) {
        let path = Self::history_file();
        self.load_from_file(&path);
    }

    /// Start a find query (live: each keystroke recomputes + jumps).
    pub fn enter_find(&mut self) {
        self.finding = true;
        self.find_query.clear();
        self.find_matches.clear();
        self.find_pos = 0;
        self.status = String::from("find: type a query, Enter confirms, Esc cancels");
    }

    /// Whether a find query is being typed (address line shows the query).
    pub fn is_finding(&self) -> bool {
        self.finding
    }

    /// Current find query (live buffer while typing, committed after Enter).
    pub fn find_query(&self) -> &str {
        &self.find_query
    }

    /// Rendered-line indices matching the query, ascending.
    pub fn find_matches(&self) -> &[usize] {
        &self.find_matches
    }

    /// Rendered-line index of the current match, if any.
    pub fn current_match_line(&self) -> Option<usize> {
        self.find_matches.get(self.find_pos).copied()
    }

    /// Advance to the next match (wraps); no-op without matches.
    pub fn next_match(&mut self, viewport_height: usize) {
        if self.find_matches.is_empty() {
            return;
        }
        self.find_pos = (self.find_pos + 1) % self.find_matches.len();
        self.jump_to_match(viewport_height);
        self.status = self.find_status_text();
    }

    fn edit_find(&mut self, push: Option<char>) {
        match push {
            Some(c) => self.find_query.push(c),
            None => {
                self.find_query.pop();
            }
        }
        self.recompute_find(24);
    }

    fn commit_find(&mut self) {
        self.finding = false;
        if self.find_query.is_empty() {
            self.find_matches.clear();
            self.status = self.where_am_i();
        } else {
            self.status = self.find_status_text();
        }
    }

    fn cancel_find(&mut self) {
        self.finding = false;
        self.clear_find();
        self.status = self.where_am_i();
    }

    fn clear_find(&mut self) {
        self.find_query.clear();
        self.find_matches.clear();
        self.find_pos = 0;
    }

    fn recompute_find(&mut self, viewport_height: usize) {
        let q = self.find_query.to_lowercase();
        self.find_matches = if q.is_empty() {
            Vec::new()
        } else {
            self.page_lines()
                .iter()
                .enumerate()
                .filter(|(_, l)| l.to_lowercase().contains(&q))
                .map(|(i, _)| i)
                .collect()
        };
        self.find_pos = 0;
        self.jump_to_match(viewport_height);
        self.status = self.find_status_text();
    }

    fn jump_to_match(&mut self, viewport_height: usize) {
        if let Some(line) = self.current_match_line() {
            let max_start = self
                .page_lines()
                .len()
                .saturating_sub(viewport_height.max(1));
            self.scroll = line.min(max_start);
        }
    }

    fn find_status_text(&self) -> String {
        if self.find_query.is_empty() {
            return String::from("find: type a query, Enter confirms, Esc cancels");
        }
        let n = self.find_matches.len();
        if n == 0 {
            format!("find {:?}: no matches", self.find_query)
        } else {
            format!(
                "find {:?}: match {}/{} (n = next)",
                self.find_query,
                self.find_pos + 1,
                n
            )
        }
    }

    /// Toggle the keybinding cheatsheet overlay.
    pub fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
    }

    /// Whether the cheatsheet overlay is up.
    pub fn help_visible(&self) -> bool {
        self.show_help
    }

    /// Cheatsheet lines rendered by the binary when the overlay is up.
    pub fn help_lines() -> Vec<String> {
        [
            "nexus-tui keys",
            "Enter         open site[/path] / confirm find",
            "Esc           clear input / cancel find / close help",
            "Up Down       scroll one line (PgUp/PgDn: 20)",
            "b / f         back / forward",
            "r             reload current page",
            "/             find in page, then n = next match",
            "?             toggle this help",
            "q, Ctrl-C/D   quit",
        ]
        .iter()
        .map(ToString::to_string)
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_content::{Component, Metadata, Page};

    fn visit(site: &str, path: &str, filler_lines: usize) -> crate::Visit {
        // Long lines: the wrapping renderer keeps each on its own rows.
        let mut text = String::from(
            "line0-pad-to-make-this-row-long-enough-to-wrap-around-eighty-columns-0123456789",
        );
        for i in 1..=filler_lines {
            text.push_str(&format!("\nline{i}-pad-to-make-this-row-long-enough-to-wrap-around-eighty-columns-0123456789"));
        }
        crate::Visit {
            site: site.into(),
            path: path.into(),
            page: Page {
                metadata: Metadata {
                    schema: 1,
                    site: site.into(),
                    path: path.into(),
                    title: "T".into(),
                    revision: 1,
                },
                components: vec![Component::Text { text }],
                capabilities: vec![],
            },
        }
    }

    fn wordy_visit() -> crate::Visit {
        // Matchable lines first (so scroll jumps are observable: the page
        // is taller than the find viewport of 24), filler after.
        let mut components = vec![
            Component::Text {
                text: "apple pie".into(),
            },
            Component::Text {
                text: "cherry tart".into(),
            },
            Component::Text {
                text: "green APPLE crumble".into(),
            },
        ];
        for i in 0..40 {
            components.push(Component::Text {
                text: format!("filler line {i} with enough words to be a row"),
            });
        }
        crate::Visit {
            site: "example".into(),
            path: "home".into(),
            page: Page {
                metadata: Metadata {
                    schema: 1,
                    site: "example".into(),
                    path: "home".into(),
                    title: "T".into(),
                    revision: 1,
                },
                components,
                capabilities: vec![],
            },
        }
    }

    fn loaded(lines: usize) -> TuiState {
        let mut s = TuiState::new("127.0.0.1:9", None);
        s.session.history.push(visit("example", "home", lines));
        s.status = s.where_am_i();
        s
    }

    fn tmp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("nexus-tui-unit-{name}-{}", std::process::id()))
    }

    #[test]
    fn input_commands_need_empty_line() {
        let mut s = loaded(0);
        // Non-empty line: keys append as text, never navigate.
        s.handle_key(KeyCode::Char('x'));
        assert_eq!(s.handle_key(KeyCode::Char('b')), KeyAction::Continue);
        assert_eq!(s.input(), "xb");
        // Backspace and Esc edit the line.
        assert_eq!(s.handle_key(KeyCode::Backspace), KeyAction::Continue);
        assert_eq!(s.input(), "x");
        assert_eq!(s.handle_key(KeyCode::Esc), KeyAction::Continue);
        assert_eq!(s.input(), "");
        // Empty line: q quits; b tries history nav (single entry: fails
        // into status, but must not touch the input line).
        assert_eq!(s.handle_key(KeyCode::Char('b')), KeyAction::Continue);
        assert_eq!(s.input(), "");
        assert!(s.status().contains("start of history"));
        assert_eq!(s.handle_key(KeyCode::Char('q')), KeyAction::Quit);
    }

    #[test]
    fn scroll_clamps_both_ends() {
        let mut s = loaded(50);
        let total = s.page_lines().len();
        assert!(total > 10);
        s.scroll_by(10_000, 10);
        let (start, end) = s.visible_range(10);
        assert_eq!(end - start, 10);
        assert_eq!(end, total);
        s.scroll_by(-10_000, 10);
        assert_eq!(s.visible_range(10).0, 0);
        // Viewport taller than content: everything visible, no panic.
        let (start, end) = s.visible_range(total + 100);
        assert_eq!((start, end), (0, total));
    }

    #[test]
    fn where_am_i_reports_location() {
        let s = loaded(0);
        assert!(s.where_am_i().contains("@example /home"));
        let fresh = TuiState::new("127.0.0.1:9", None);
        assert_eq!(fresh.where_am_i(), "(no page loaded)");
        assert!(!fresh.is_pinned());
        let pinned = TuiState::new("127.0.0.1:9", Some("abc".into()));
        assert!(pinned.is_pinned());
    }

    #[test]
    fn failed_open_keeps_current_page() {
        let mut s = loaded(0);
        // Nothing listens on :9, so open fails and the page stays. A bare
        // refused connection reads as offline (TUI fetches fresh only).
        s.open("example/home");
        assert!(s.status().starts_with("offline:"));
        assert!(s.where_am_i().contains("@example /home"));
    }

    #[test]
    fn history_persistence_roundtrip_and_cap() {
        let path = tmp_path("hist");
        let _ = std::fs::remove_file(&path);
        let mut s = TuiState::new("127.0.0.1:9", None);
        s.record_visit("example", "home");
        s.record_visit("example", "home"); // consecutive dup collapses
        s.record_visit("example", "about");
        assert_eq!(s.visited().len(), 2);
        s.save_to_file(&path).unwrap();
        let mut r = TuiState::new("127.0.0.1:9", None);
        r.load_from_file(&path);
        assert_eq!(r.visited(), s.visited());
        // Over-long logs keep the newest 100.
        let mut big = TuiState::new("127.0.0.1:9", None);
        for i in 0..(HISTORY_MAX_ENTRIES + 50) {
            big.record_visit("example", &format!("p{i}"));
        }
        assert_eq!(big.visited().len(), HISTORY_MAX_ENTRIES);
        assert_eq!(big.visited().last().unwrap().path, "p149");
        big.save_to_file(&path).unwrap();
        let mut r2 = TuiState::new("127.0.0.1:9", None);
        r2.load_from_file(&path);
        assert_eq!(r2.visited().len(), HISTORY_MAX_ENTRIES);
        assert_eq!(r2.visited()[0].path, "p50");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn history_load_missing_empty_corrupt_never_fails() {
        let missing = tmp_path("missing");
        let _ = std::fs::remove_file(&missing);
        let mut s = TuiState::new("127.0.0.1:9", None);
        s.record_visit("example", "home");
        s.load_from_file(&missing); // missing -> empty, no panic
        assert!(s.visited().is_empty());
        let empty = tmp_path("empty");
        std::fs::write(&empty, b"").unwrap();
        s.record_visit("example", "home");
        s.load_from_file(&empty); // empty -> empty, no panic
        assert!(s.visited().is_empty());
        let corrupt = tmp_path("corrupt");
        std::fs::write(&corrupt, b"{not json!!").unwrap();
        s.record_visit("example", "home");
        s.load_from_file(&corrupt); // corrupt -> empty, no panic
        assert!(s.visited().is_empty());
        // Valid JSON with invalid entries: bad rows drop, good rows stay.
        std::fs::write(
            &corrupt,
            br#"[{"site":"example","path":"home"},{"site":"BAD NAME","path":"home"}]"#,
        )
        .unwrap();
        s.load_from_file(&corrupt);
        assert_eq!(s.visited().len(), 1);
        assert_eq!(s.visited()[0].path, "home");
        let _ = std::fs::remove_file(&empty);
        let _ = std::fs::remove_file(&corrupt);
    }

    #[test]
    fn find_first_match_jumps_and_n_cycles() {
        let mut s = TuiState::new("127.0.0.1:9", None);
        s.session.history.push(wordy_visit());
        // `/` + query via keys: live match, scroll jumps to first hit.
        assert_eq!(s.handle_key(KeyCode::Char('/')), KeyAction::Continue);
        assert!(s.is_finding());
        for c in "APPLE".chars() {
            s.handle_key(KeyCode::Char(c));
        }
        assert_eq!(s.find_query(), "APPLE");
        assert_eq!(s.find_matches().len(), 2); // case-insensitive
        assert_eq!(
            Some(s.scroll()),
            s.current_match_line(),
            "first match is scrolled to"
        );
        assert!(s.status().contains("1/2"));
        // Enter commits; n cycles to second match, then wraps to first.
        s.handle_key(KeyCode::Enter);
        assert!(!s.is_finding());
        let first = s.current_match_line().unwrap();
        s.handle_key(KeyCode::Char('n'));
        let second = s.current_match_line().unwrap();
        assert_ne!(first, second);
        assert!(s.status().contains("2/2"));
        s.handle_key(KeyCode::Char('n'));
        assert_eq!(s.current_match_line(), Some(first));
        // Navigating clears the find state.
        s.session.history.push(visit("example", "about", 0));
        s.back();
        assert!(s.find_matches().is_empty());
        assert!(s.find_query().is_empty());
    }

    #[test]
    fn find_no_match_and_esc_cancels() {
        let mut s = TuiState::new("127.0.0.1:9", None);
        s.session.history.push(wordy_visit());
        s.handle_key(KeyCode::Char('/'));
        for c in "zzz-nope".chars() {
            s.handle_key(KeyCode::Char(c));
        }
        assert!(s.find_matches().is_empty());
        assert!(s.status().contains("no matches"));
        assert_eq!(s.current_match_line(), None);
        s.handle_key(KeyCode::Esc); // cancel: query cleared, status restored
        assert!(!s.is_finding());
        assert!(s.find_query().is_empty());
        assert!(s.where_am_i() == s.status());
    }

    #[test]
    fn help_overlay_toggles_and_esc_closes() {
        let mut s = loaded(0);
        assert!(!s.help_visible());
        s.handle_key(KeyCode::Char('?'));
        assert!(s.help_visible());
        assert!(!TuiState::help_lines().is_empty());
        s.handle_key(KeyCode::Char('?'));
        assert!(!s.help_visible());
        // Empty-line Esc closes the overlay; with typed text Esc edits.
        s.handle_key(KeyCode::Char('?'));
        s.handle_key(KeyCode::Esc);
        assert!(!s.help_visible());
        s.handle_key(KeyCode::Char('x'));
        s.handle_key(KeyCode::Char('?')); // non-empty line: literal text
        assert_eq!(s.input(), "x?");
    }
}
