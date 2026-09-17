//! Structured page model — the Nexus alternative to HTML.
//!
//! A page is typed data (serde JSON on the wire for v0), not a document
//! string. The browser renders it natively. Content IDs are BLAKE3 hashes
//! (`b3:<hex>`) over canonical JSON bytes.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PAGE_SCHEMA: u32 = 1;
pub const MAX_COMPONENTS: usize = 4096;
pub const MAX_TEXT_BYTES: usize = 256 * 1024;

#[derive(Debug, Error)]
pub enum ContentError {
    #[error("validation: {0}")]
    Validation(String),
    #[error("serialization: {0}")]
    Serialization(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Page {
    pub metadata: Metadata,
    pub components: Vec<Component>,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Metadata {
    pub schema: u32,
    pub site: String,
    pub path: String,
    pub title: String,
    pub revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Component {
    Text {
        text: String,
    },
    Heading {
        level: u8,
        text: String,
    },
    Image {
        content_id: String,
        alt: String,
    },
    Link {
        label: String,
        target: LinkTarget,
    },
    Collection {
        items: Vec<Component>,
    },
    App {
        app_id: String,
        props: serde_json::Value,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LinkTarget {
    Page { site: String, path: String },
    External { hint: String },
    Action { action_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Capability {
    Storage { max_kb: u32 },
    Network { hosts: Vec<String> },
    Notify,
    Audio,
    Camera,
    Microphone,
}

impl Page {
    pub fn validate(&self) -> Result<(), ContentError> {
        if self.metadata.schema != PAGE_SCHEMA {
            return Err(ContentError::Validation(format!(
                "unsupported schema {}",
                self.metadata.schema
            )));
        }
        if self.metadata.title.is_empty() || self.metadata.title.len() > 256 {
            return Err(ContentError::Validation("bad title length".into()));
        }
        if self.components.is_empty() {
            return Err(ContentError::Validation("page has no components".into()));
        }
        if self.components.len() > MAX_COMPONENTS {
            return Err(ContentError::Validation("too many components".into()));
        }
        let mut count = 0usize;
        for c in &self.components {
            Self::validate_component(c, 0, &mut count)?;
        }
        Ok(())
    }

    fn validate_component(
        c: &Component,
        depth: usize,
        count: &mut usize,
    ) -> Result<(), ContentError> {
        *count += 1;
        if *count > MAX_COMPONENTS {
            return Err(ContentError::Validation("too many components".into()));
        }
        if depth > 32 {
            return Err(ContentError::Validation("component tree too deep".into()));
        }
        match c {
            Component::Text { text } | Component::Heading { text, .. } => {
                if text.len() > MAX_TEXT_BYTES {
                    return Err(ContentError::Validation("text too large".into()));
                }
                if let Component::Heading { level, .. } = c {
                    if !(1..=6).contains(level) {
                        return Err(ContentError::Validation("bad heading level".into()));
                    }
                }
            }
            Component::Image { content_id, .. } => {
                if !is_content_id(content_id) {
                    return Err(ContentError::Validation(format!(
                        "bad content id {content_id}"
                    )));
                }
            }
            Component::Link { label, .. } => {
                if label.is_empty() || label.len() > 1024 {
                    return Err(ContentError::Validation("bad link label".into()));
                }
            }
            Component::Collection { items } => {
                for item in items {
                    Self::validate_component(item, depth + 1, count)?;
                }
            }
            Component::App { app_id, .. } => {
                if app_id.is_empty() || app_id.len() > 128 {
                    return Err(ContentError::Validation("bad app id".into()));
                }
            }
        }
        Ok(())
    }

    pub fn to_canonical_json(&self) -> Result<Vec<u8>, ContentError> {
        serde_json::to_vec(self).map_err(|e| ContentError::Serialization(e.to_string()))
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, ContentError> {
        if bytes.len() > nexus_protocol_limits::max_page_bytes() {
            return Err(ContentError::Validation("page too large".into()));
        }
        let page: Self =
            serde_json::from_slice(bytes).map_err(|e| ContentError::Validation(e.to_string()))?;
        page.validate()?;
        Ok(page)
    }

    /// BLAKE3 content ID over canonical JSON.
    pub fn content_id(&self) -> Result<String, ContentError> {
        let bytes = self.to_canonical_json()?;
        Ok(content_id_of(&bytes))
    }
}

pub fn content_id_of(bytes: &[u8]) -> String {
    format!("b3:{}", hex::encode(blake3::hash(bytes).as_bytes()))
}

pub fn is_content_id(s: &str) -> bool {
    let hex_part = s.strip_prefix("b3:").unwrap_or("__invalid__");
    hex_part.len() == 64 && hex_part.chars().all(|c| c.is_ascii_hexdigit())
}

mod nexus_protocol_limits {
    pub fn max_page_bytes() -> usize {
        1024 * 1024
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn example_page() -> Page {
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
                    text: "Hello, Nexus".into(),
                },
                Component::Text {
                    text: "A page without HTML.".into(),
                },
                Component::Link {
                    label: "About".into(),
                    target: LinkTarget::Page {
                        site: "example".into(),
                        path: "about".into(),
                    },
                },
            ],
            capabilities: vec![],
        }
    }

    #[test]
    fn validates_ok() {
        example_page().validate().unwrap();
    }

    #[test]
    fn rejects_bad_schema() {
        let mut p = example_page();
        p.metadata.schema = 99;
        assert!(p.validate().is_err());
    }

    #[test]
    fn rejects_empty_components() {
        let mut p = example_page();
        p.components.clear();
        assert!(p.validate().is_err());
    }

    #[test]
    fn rejects_deep_nesting() {
        let mut inner = Component::Text { text: "x".into() };
        for _ in 0..40 {
            inner = Component::Collection { items: vec![inner] };
        }
        let mut p = example_page();
        p.components = vec![inner];
        assert!(p.validate().is_err());
    }

    #[test]
    fn content_id_stable() {
        let p = example_page();
        let a = p.content_id().unwrap();
        let b = p.content_id().unwrap();
        assert_eq!(a, b);
        assert!(a.starts_with("b3:"));
        // changing content changes id
        let mut p2 = p.clone();
        p2.metadata.revision = 2;
        assert_ne!(a, p2.content_id().unwrap());
    }

    #[test]
    fn json_roundtrip() {
        let p = example_page();
        let bytes = p.to_canonical_json().unwrap();
        let q = Page::from_json(&bytes).unwrap();
        assert_eq!(p, q);
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(Page::from_json(b"not json").is_err());
    }

    #[test]
    fn app_props_preserved() {
        let mut p = example_page();
        p.components.push(Component::App {
            app_id: "counter".into(),
            props: json!({"start": 3}),
        });
        p.validate().unwrap();
        let bytes = p.to_canonical_json().unwrap();
        assert_eq!(Page::from_json(&bytes).unwrap(), p);
    }
}
