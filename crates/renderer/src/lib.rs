//! Terminal renderer: Page -> human-readable text.
//!
//! Deliberately primitive for M2. No layout engine yet; the contract is a
//! pure function suitable for snapshot tests. A graphical renderer can reuse
//! the same `Page` model later.

use nexus_content::{Component, LinkTarget, Page};

/// Render a page to human-readable terminal text (pure function).
pub fn render_text(page: &Page) -> String {
    let mut out = String::new();
    out.push_str(&format!("# {}\n", page.metadata.title));
    out.push_str(&format!(
        "@{} /{}  rev:{}\n\n",
        page.metadata.site, page.metadata.path, page.metadata.revision
    ));
    for c in &page.components {
        render_component(c, 0, &mut out);
    }
    out
}

fn render_component(c: &Component, indent: usize, out: &mut String) {
    let pad = "  ".repeat(indent);
    match c {
        Component::Text { text } => {
            out.push_str(&format!("{pad}{text}\n\n"));
        }
        Component::Heading { level, text } => {
            let marks = "#".repeat((*level).clamp(1, 6) as usize);
            out.push_str(&format!("{pad}{marks} {text}\n\n"));
        }
        Component::Image { alt, content_id } => {
            out.push_str(&format!("{pad}[image: {alt} ({content_id})]\n\n"));
        }
        Component::Link { label, target } => match target {
            LinkTarget::Page { site, path } => {
                out.push_str(&format!("{pad}[{label}]({site}/{path})\n\n"));
            }
            LinkTarget::External { hint } => {
                out.push_str(&format!("{pad}[{label}](external: {hint})\n\n"));
            }
            LinkTarget::Action { action_id } => {
                out.push_str(&format!("{pad}[{label}](action: {action_id})\n\n"));
            }
        },
        Component::Collection { items } => {
            for item in items {
                render_component(item, indent + 1, out);
            }
        }
        Component::App { app_id, props } => {
            out.push_str(&format!("{pad}<app:{app_id} props={props}>\n\n"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_content::{Metadata, Page};

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
}
