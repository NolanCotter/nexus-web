//! `nexus-tui`: full-screen terminal browser for Nexus.
//!
//! Thin shell over [`nexus_browser::tui::TuiState`]: ratatui draws three
//! panes (address line, page viewport, status bar) and crossterm feeds it
//! key events. All navigation logic lives in the state machine, which is
//! unit-tested without a terminal.

use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use nexus_browser::tui::{KeyAction, TuiState};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Terminal,
};
use std::io;

const DEFAULT_SERVER: &str = "127.0.0.1:7843";

fn usage() -> &'static str {
    "usage: nexus-tui [--server HOST:PORT] [--pin SITE_ID] [site[/path]]"
}

#[derive(Debug, PartialEq, Eq)]
struct Args {
    server: String,
    pin: Option<String>,
    target: Option<String>,
}

fn parse_args(args: &[String]) -> Result<Args, i32> {
    let mut server = DEFAULT_SERVER.to_string();
    let mut pin = None;
    let mut target = None;
    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                println!("{}", usage());
                return Err(0);
            }
            "--server" | "--pin" => {
                let is_server = *a == "--server";
                match it.next() {
                    Some(v) => {
                        if is_server {
                            server = v.clone();
                        } else {
                            pin = Some(v.clone());
                        }
                    }
                    None => {
                        eprintln!("{}", usage());
                        return Err(2);
                    }
                }
            }
            s if s.starts_with('-') => {
                eprintln!("unknown arg: {s}\n{}", usage());
                return Err(2);
            }
            s => target = Some(s.to_string()),
        }
    }
    Ok(Args {
        server,
        pin,
        target,
    })
}

fn draw(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, state: &TuiState) -> io::Result<()> {
    terminal.draw(|frame| {
        let area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(1),
                Constraint::Length(3),
            ])
            .split(area);

        let viewport_h = chunks[1].height as usize;
        let (start, end) = state.visible_range(viewport_h);
        let lines = state.page_lines();
        let hits = state.find_matches().to_vec();
        let current = state.current_match_line();
        let body: Vec<Line> = lines[start..end.min(lines.len())]
            .iter()
            .enumerate()
            .map(|(k, l)| {
                let idx = start + k;
                if Some(idx) == current {
                    Line::from(Span::styled(
                        l.as_str(),
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ))
                } else if hits.contains(&idx) {
                    Line::from(Span::styled(l.as_str(), Style::default().fg(Color::Yellow)))
                } else {
                    Line::from(l.as_str())
                }
            })
            .collect();
        frame.render_widget(
            Paragraph::new(body)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(state.where_am_i()),
                )
                .wrap(Wrap { trim: false }),
            chunks[1],
        );

        let pin_tag = if state.is_pinned() {
            Span::styled(" PINNED", Style::default().fg(Color::Green))
        } else {
            Span::styled(" UNVERIFIED", Style::default().fg(Color::Yellow))
        };
        if state.is_finding() {
            frame.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::raw(format!("/{}", state.find_query())),
                    Span::styled("▌", Style::default().fg(Color::Gray)),
                ]))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("find (Enter confirms, Esc cancels)"),
                ),
                chunks[0],
            );
        } else {
            frame.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::raw("> "),
                    Span::raw(state.input()),
                    Span::styled("▌", Style::default().fg(Color::Gray)),
                ]))
                .block(Block::default().borders(Borders::ALL).title("address")),
                chunks[0],
            );
        }
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::raw(state.status()),
                pin_tag,
                Span::raw("  (b/f back/fwd, r reload, / find, ? keys, q quit)"),
            ]))
            .block(Block::default().borders(Borders::ALL)),
            chunks[2],
        );

        if state.help_visible() {
            let popup = centered_popup(area, 54, TuiState::help_lines().len() as u16 + 2);
            frame.render_widget(Clear, popup);
            frame.render_widget(
                Paragraph::new(TuiState::help_lines().join("\n")).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("keys (?/Esc closes)"),
                ),
                popup,
            );
        }
    })?;
    Ok(())
}

/// Fixed-size rect centered in `area` (clamped to fit tiny terminals).
fn centered_popup(area: ratatui::layout::Rect, width: u16, height: u16) -> ratatui::layout::Rect {
    let w = width.min(area.width.saturating_sub(2)).max(1);
    let h = height.min(area.height.saturating_sub(2)).max(1);
    ratatui::layout::Rect::new(
        area.x + area.width.saturating_sub(w) / 2,
        area.y + area.height.saturating_sub(h) / 2,
        w,
        h,
    )
}

fn run(server: String, pin: Option<String>, target: Option<String>) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state =
        TuiState::new(server, pin).with_cache(nexus_browser::OfflineCache::open_default());
    state.load_history();
    if let Some(t) = target {
        state.open(&t);
        state.save_history();
    }

    loop {
        draw(&mut terminal, &state)?;
        let action = match event::read()? {
            Event::Key(key) => {
                // Ctrl-C / Ctrl-D always quit, even mid-typing.
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('d'))
                {
                    state.save_history();
                    KeyAction::Quit
                } else {
                    let opened = matches!(key.code, KeyCode::Enter);
                    let action = state.handle_key(key.code);
                    if opened {
                        state.save_history();
                    }
                    action
                }
            }
            _ => KeyAction::Continue,
        };
        if action == KeyAction::Quit {
            state.save_history();
            break;
        }
        // Clamp scroll after navigation changed the page.
        let h = terminal.size()?.height as usize;
        state.scroll_by(0, h.saturating_sub(6));
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match parse_args(&args) {
        Ok(a) => a,
        Err(code) => std::process::exit(code),
    };
    if let Err(e) = run(parsed.server, parsed.pin, parsed.target) {
        let _ = disable_raw_mode();
        eprintln!("nexus-tui: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tui_args() {
        let a = parse_args(&["example/home".into()]).unwrap();
        assert_eq!(a.server, DEFAULT_SERVER);
        assert_eq!(a.target, Some("example/home".into()));
        assert_eq!(a.pin, None);
        let a = parse_args(&[
            "--server".into(),
            "10.0.0.1:1".into(),
            "--pin".into(),
            "abc".into(),
            "example".into(),
        ])
        .unwrap();
        assert_eq!(
            (a.server, a.pin, a.target),
            (
                "10.0.0.1:1".into(),
                Some("abc".into()),
                Some("example".into())
            )
        );
        assert_eq!(parse_args(&["--nope".into()]), Err(2));
        assert_eq!(parse_args(&["--server".into()]), Err(2));
    }
}
