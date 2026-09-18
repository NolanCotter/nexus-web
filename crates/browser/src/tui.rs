//! Full-screen terminal browser state machine (Milestone: TUI).
//!
//! [`TuiState`] is pure logic over [`ClientSession`]: input line, scroll
//! offset, and status text. It knows nothing about terminals, so every
//! transition is unit-testable. The `nexus-tui` binary wires it to
//! ratatui/crossterm for drawing and key events.

use crossterm::event::KeyCode;

use crate::{BrowserError, ClientSession};

/// What the event loop should do after a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyAction {
    /// Keep running.
    Continue,
    /// Exit the browser.
    Quit,
}

/// Editable address line + scroll + status over a browsing session.
#[derive(Debug)]
pub struct TuiState {
    session: ClientSession,
    input: String,
    scroll: usize,
    status: String,
}

impl TuiState {
    /// New browser against `server`; `pin` enables verified fetches.
    pub fn new(server: impl Into<String>, pin: Option<String>) -> Self {
        Self {
            session: ClientSession::new(server).with_pin(pin),
            input: String::new(),
            scroll: 0,
            status: String::from("type a target (site[/path]) and press Enter"),
        }
    }

    /// Open `target`, resetting scroll; failures become status text and
    /// leave the current page (and history) untouched.
    pub fn open(&mut self, target: &str) {
        match self.session.open(target) {
            Ok(()) => {
                self.scroll = 0;
                self.input.clear();
                self.status = self.where_am_i();
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
                self.status = self.where_am_i();
            }
            Err(e) => self.status = format!("{empty_note}: {e}"),
        }
    }

    /// Human-readable location line for the status bar.
    pub fn where_am_i(&self) -> String {
        match self.session.history.current() {
            Some(v) => format!("@{} /{} — {}", v.site, v.path, v.page.metadata.title),
            None => String::from("(no page loaded)"),
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
        match code {
            KeyCode::Char('q') if self.input.is_empty() => return KeyAction::Quit,
            KeyCode::Char('b') if self.input.is_empty() => self.back(),
            KeyCode::Char('f') if self.input.is_empty() => self.forward(),
            KeyCode::Char('r') if self.input.is_empty() => self.reload(),
            KeyCode::Enter => {
                if !self.input.trim().is_empty() {
                    let target = self.input.trim().to_string();
                    self.open(&target);
                }
            }
            KeyCode::Esc => self.input.clear(),
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

    fn loaded(lines: usize) -> TuiState {
        let mut s = TuiState::new("127.0.0.1:9", None);
        s.session.history.push(visit("example", "home", lines));
        s.status = s.where_am_i();
        s
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
        // Nothing listens on :9, so open fails and the page stays.
        s.open("example/home");
        assert!(s.status().starts_with("error:"));
        assert!(s.where_am_i().contains("@example /home"));
    }
}
