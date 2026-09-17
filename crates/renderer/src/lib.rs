//! Terminal renderer: Page -> human-readable text.
//!
//! Pure function (`render_text`) suitable for snapshot tests. A graphical
//! renderer can reuse the same `Page` model later.
//!
//! Richer terminal output (Milestone E):
//! - word wrap at 80 columns (greedy, no hyphenation; over-long words overflow)
//! - numbered link references (`label [n]`) with a `Links:` footer index
//! - nested [`Component::Collection`] rendering as indented `- ` bullets
//! - [`Component::Image`] as an `[image: alt (content_id)]` placeholder
//! - [`Component::App`] as a capability-gated `(not executed)` placeholder
//!   listing the page's required capabilities.

use nexus_content::{Capability, Component, LinkTarget, Page};

/// Terminal line width. Simple greedy word wrap, no hyphenation.
pub const WRAP_WIDTH: usize = 80;

/// Render a page to human-readable terminal text (pure function).
pub fn render_text(page: &Page) -> String {
    let mut out = String::new();
    let mut links: Vec<String> = Vec::new();

    out.push_str(&wrap_para(&page.metadata.title, "# ", "  ", WRAP_WIDTH));
    out.push_str(&format!(
        "@{} /{}  rev:{}\n\n",
        page.metadata.site, page.metadata.path, page.metadata.revision
    ));
    for c in &page.components {
        render_component(c, 0, false, &page.capabilities, &mut out, &mut links);
    }
    if !links.is_empty() {
        out.push_str("Links:\n");
        for (i, target) in links.iter().enumerate() {
            out.push_str(&format!("  [{}] {}\n", i + 1, target));
        }
    }
    out
}

fn render_component(
    c: &Component,
    indent: usize,
    bulleted: bool,
    caps: &[Capability],
    out: &mut String,
    links: &mut Vec<String>,
) {
    let pad = "  ".repeat(indent);
    let first = if bulleted {
        format!("{pad}- ")
    } else {
        pad.clone()
    };
    let cont = if bulleted {
        format!("{pad}  ")
    } else {
        pad.clone()
    };
    match c {
        Component::Text { text } => {
            out.push_str(&wrap_para(text, &first, &cont, WRAP_WIDTH));
            if !bulleted {
                out.push('\n');
            }
        }
        Component::Heading { level, text } => {
            let marks = "#".repeat((*level).clamp(1, 6) as usize);
            out.push_str(&wrap_para(
                &format!("{marks} {text}"),
                &first,
                &cont,
                WRAP_WIDTH,
            ));
            if !bulleted {
                out.push('\n');
            }
        }
        Component::Image { alt, content_id } => {
            out.push_str(&wrap_para(
                &format!("[image: {alt} ({content_id})]"),
                &first,
                &cont,
                WRAP_WIDTH,
            ));
            if !bulleted {
                out.push('\n');
            }
        }
        Component::Link { label, target } => {
            links.push(fmt_target(target));
            let n = links.len();
            out.push_str(&wrap_para(
                &format!("{label} [{n}]"),
                &first,
                &cont,
                WRAP_WIDTH,
            ));
            if !bulleted {
                out.push('\n');
            }
        }
        Component::Collection { items } => {
            for item in items {
                match item {
                    Component::Collection { .. } => {
                        render_component(item, indent + 1, false, caps, out, links)
                    }
                    _ => render_component(item, indent + 1, true, caps, out, links),
                }
            }
            // Blank line after a top-level list; nested lists stay tight.
            if indent == 0 && !bulleted {
                out.push('\n');
            }
        }
        Component::App { app_id, props } => {
            out.push_str(&wrap_para(
                &format!("[app:{app_id}] (not executed)"),
                &first,
                &cont,
                WRAP_WIDTH,
            ));
            let sub = format!("{cont}  ");
            let req = if caps.is_empty() {
                "none".to_string()
            } else {
                caps.iter()
                    .map(fmt_capability)
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            out.push_str(&wrap_para(
                &format!("requires: {req}"),
                &sub,
                &sub,
                WRAP_WIDTH,
            ));
            if !props.is_null() {
                out.push_str(&wrap_para(
                    &format!("props: {props}"),
                    &sub,
                    &sub,
                    WRAP_WIDTH,
                ));
            }
            if !bulleted {
                out.push('\n');
            }
        }
    }
}

fn fmt_target(t: &LinkTarget) -> String {
    match t {
        LinkTarget::Page { site, path } => format!("{site}/{path}"),
        LinkTarget::External { hint } => format!("external: {hint}"),
        LinkTarget::Action { action_id } => format!("action: {action_id}"),
    }
}

fn fmt_capability(c: &Capability) -> String {
    match c {
        Capability::Storage { max_kb } => format!("storage({max_kb}KB)"),
        Capability::Network { hosts } => {
            if hosts.is_empty() {
                "network(none)".to_string()
            } else {
                format!("network({})", hosts.join(","))
            }
        }
        Capability::Notify => "notify".to_string(),
        Capability::Audio => "audio".to_string(),
        Capability::Camera => "camera".to_string(),
        Capability::Microphone => "microphone".to_string(),
    }
}

/// Greedy word wrap: `first` prefixes the first line, `cont` prefixes the
/// rest. Words are never split (no hyphenation); a single over-long word
/// overflows its line. Returns text ending in exactly one `\n`.
fn wrap_para(text: &str, first: &str, cont: &str, width: usize) -> String {
    let width = width.max(first.len() + 10).max(cont.len() + 10);
    let mut buf = String::from(first);
    let mut line_len = first.len();
    let mut fresh = true;
    for word in text.split_whitespace() {
        let w = word.chars().count();
        if fresh {
            buf.push_str(word);
            line_len += w;
            fresh = false;
        } else if line_len + 1 + w <= width {
            buf.push(' ');
            buf.push_str(word);
            line_len += 1 + w;
        } else {
            buf.push('\n');
            buf.push_str(cont);
            buf.push_str(word);
            line_len = cont.len() + w;
        }
    }
    if fresh {
        // Empty or whitespace-only input: avoid a dangling prefix.
        buf = buf.trim_end().to_string();
    }
    buf.push('\n');
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_content::{Metadata, Page};
    use serde_json::json;

    fn page() -> Page {
        Page {
            metadata: Metadata {
                schema: 1,
                site: "example".into(),
                path: "home".into(),
                title: "Example".into(),
                revision: 1,
            },
            components: vec![
                Component::Heading {
                    level: 1,
                    text: "Hi".into(),
                },
                Component::Text {
                    text: "Welcome to Nexus.".into(),
                },
            ],
            capabilities: vec![],
        }
    }

    fn link_page() -> Page {
        let mut p = page();
        p.components.push(Component::Link {
            label: "About".into(),
            target: LinkTarget::Page {
                site: "example".into(),
                path: "about".into(),
            },
        });
        p.components.push(Component::Link {
            label: "Docs".into(),
            target: LinkTarget::External {
                hint: "example.net/docs".into(),
            },
        });
        p
    }

    #[test]
    fn renders_title_and_body() {
        let s = render_text(&page());
        assert!(s.contains("Example"));
        assert!(s.contains("Welcome to Nexus."));
    }

    #[test]
    fn renders_links() {
        let mut p = page();
        p.components.push(Component::Link {
            label: "About".into(),
            target: LinkTarget::Page {
                site: "example".into(),
                path: "about".into(),
            },
        });
        assert!(render_text(&p).contains("example/about"));
    }

    #[test]
    fn links_numbered_with_footer_snapshot() {
        let s = render_text(&link_page());
        let expected = "\
# Example
@example /home  rev:1

# Hi

Welcome to Nexus.

About [1]

Docs [2]

Links:
  [1] example/about
  [2] external: example.net/docs
";
        assert_eq!(s, expected);
    }

    #[test]
    fn wraps_long_text_at_80_cols() {
        let mut p = page();
        p.components = vec![Component::Text {
            text: "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod \
                   tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam."
                .into(),
        }];
        let s = render_text(&p);
        for line in s.lines() {
            assert!(line.chars().count() <= 80, "overflow: {line:?}");
        }
        // Greedy wrap: second line starts a fresh 80-col budget.
        assert!(
            s.contains("\nincididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam.\n")
        );
    }

    #[test]
    fn long_word_overflows_without_hyphenation() {
        let mut p = page();
        let word = "x".repeat(100);
        p.components = vec![Component::Text {
            text: format!("hi {word}"),
        }];
        let s = render_text(&p);
        assert!(s.contains(&word), "long word must survive unsplit");
    }

    #[test]
    fn nested_collections_render_as_bullets_snapshot() {
        let mut p = page();
        p.components = vec![Component::Collection {
            items: vec![
                Component::Text {
                    text: "First".into(),
                },
                Component::Collection {
                    items: vec![
                        Component::Text {
                            text: "Nested one".into(),
                        },
                        Component::Link {
                            label: "Nested link".into(),
                            target: LinkTarget::Page {
                                site: "example".into(),
                                path: "about".into(),
                            },
                        },
                    ],
                },
            ],
        }];
        let s = render_text(&p);
        let expected = "\
# Example
@example /home  rev:1

  - First
    - Nested one
    - Nested link [1]

Links:
  [1] example/about
";
        assert_eq!(s, expected);
    }

    #[test]
    fn image_placeholder_snapshot() {
        let mut p = page();
        p.components = vec![Component::Image {
            content_id: format!("b3:{}", "ab".repeat(32)),
            alt: "Demo image".into(),
        }];
        let s = render_text(&p);
        // Long alt+id wraps (greedy, no hyphenation); both parts survive.
        assert!(s.contains("Demo image"));
        assert!(s.contains(&"ab".repeat(32)));
        assert!(s.contains("[image:"));
    }

    #[test]
    fn app_placeholder_gated_on_capabilities_snapshot() {
        let mut p = page();
        p.capabilities = vec![Capability::Storage { max_kb: 512 }, Capability::Notify];
        p.components = vec![Component::App {
            app_id: "counter".into(),
            props: json!({"start": 3}),
        }];
        let s = render_text(&p);
        let expected = format!(
            "\
# Example
@example /home  rev:1

[app:counter] (not executed)
  requires: storage(512KB), notify
  props: {{\"start\":3}}

"
        );
        assert_eq!(s, expected);
    }

    #[test]
    fn app_without_capabilities_requires_none() {
        let mut p = page();
        p.components = vec![Component::App {
            app_id: "clock".into(),
            props: serde_json::Value::Null,
        }];
        let s = render_text(&p);
        assert!(s.contains("[app:clock] (not executed)"));
        assert!(s.contains("requires: none"));
        assert!(!s.contains("props:"));
    }

    #[test]
    fn heading_levels_snapshot() {
        let mut p = page();
        p.components = vec![
            Component::Heading {
                level: 1,
                text: "One".into(),
            },
            Component::Heading {
                level: 2,
                text: "Two".into(),
            },
            Component::Heading {
                level: 3,
                text: "Three".into(),
            },
        ];
        let s = render_text(&p);
        assert!(s.contains("# One\n"));
        assert!(s.contains("## Two\n"));
        assert!(s.contains("### Three\n"));
    }
}
