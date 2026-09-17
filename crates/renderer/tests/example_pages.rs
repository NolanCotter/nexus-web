//! Example pages must keep parsing and rendering after renderer changes.

use std::path::PathBuf;

fn example_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sites/example")
}

fn load(name: &str) -> nexus_content::Page {
    let bytes = std::fs::read(example_dir().join(name)).expect("example page exists");
    nexus_content::Page::from_json(&bytes).expect("example page validates")
}

#[test]
fn existing_pages_still_parse_and_render() {
    for name in ["home.json", "about.json", "showcase.json"] {
        let page = load(name);
        let text = nexus_renderer::render_text(&page);
        assert!(text.contains(&page.metadata.title), "{name} renders title");
    }
}

#[test]
fn showcase_renders_all_rich_features() {
    let text = nexus_renderer::render_text(&load("showcase.json"));
    assert!(text.contains("## Wrapping"));
    assert!(text.contains("About this experiment [1]"));
    assert!(text.contains("Do the thing [3]"));
    assert!(text.contains("- Identity over domain names."));
    assert!(text.contains("- Content over servers."));
    assert!(text.contains("[image:"));
    assert!(text.contains("Demo image"));
    assert!(text.contains("[app:counter] (not executed)"));
    assert!(text.contains("requires: storage(512KB), notify"));
    assert!(text.contains("Links:\n  [1] example/about"));
    for line in text.lines() {
        assert!(line.chars().count() <= 80, "overflow: {line:?}");
    }
}
