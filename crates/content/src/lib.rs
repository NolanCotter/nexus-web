//! Structured page model — the Nexus alternative to HTML.
//!
//! A page is typed data (serde JSON on the wire for v0), not a document
//! string. The browser renders it natively. Content IDs are BLAKE3 hashes
//! (`b3:<hex>`) over canonical JSON bytes.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Page schema version accepted by [`Page::validate`].
pub const PAGE_SCHEMA: u32 = 1;
/// Max components in one page, including nested ones.
pub const MAX_COMPONENTS: usize = 4096;
/// Max bytes of a single text/heading component.
pub const MAX_TEXT_BYTES: usize = 256 * 1024;

/// Content failures: invalid page data vs. serialization problems.
#[derive(Debug, Error)]
pub enum ContentError {
    /// Page or component failed validation (schema, size, shape, limits).
    #[error("validation: {0}")]
    Validation(String),
    /// JSON encoding failed.
    #[error("serialization: {0}")]
    Serialization(String),
}

/// A structured page: typed metadata + components, never raw HTML.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Page {
    /// Schema version, site/path identity, title, revision.
    pub metadata: Metadata,
    /// Top-level components (non-empty, bounded by [`MAX_COMPONENTS`]).
    pub components: Vec<Component>,
    /// Capabilities requested by embedded apps (default: none).
    #[serde(default)]
    pub capabilities: Vec<Capability>,
}

/// Page identity and bookkeeping header.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Metadata {
    /// Must equal [`PAGE_SCHEMA`].
    pub schema: u32,
    /// Owning site name.
    pub site: String,
    /// Path within the site.
    pub path: String,
    /// Human-readable title (1-256 bytes).
    pub title: String,
    /// Monotonic revision for cache invalidation.
    pub revision: u64,
}

/// One renderable unit of a page.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Component {
    /// Plain paragraph text.
    Text {
        /// Body text, bounded by [`MAX_TEXT_BYTES`].
        text: String,
    },
    /// Section heading (`level` 1-6).
    Heading {
        /// Heading level, 1 (largest) to 6.
        level: u8,
        /// Heading text, bounded by [`MAX_TEXT_BYTES`].
        text: String,
    },
    /// Content-addressed image reference.
    Image {
        /// `b3:<hex>` content ID (see [`is_content_id`]).
        content_id: String,
        /// Accessible description.
        alt: String,
    },
    /// Navigable link.
    Link {
        /// Visible label (1-1024 bytes).
        label: String,
        /// Where the link goes.
        target: LinkTarget,
    },
    /// Nested group of components (depth bounded to 32).
    Collection {
        /// Child components.
        items: Vec<Component>,
    },
    /// Interactive app with capability-gated props.
    App {
        /// App identifier (1-128 bytes).
        app_id: String,
        /// Opaque props passed to the app backend.
        props: serde_json::Value,
    },
}

/// Where a [`Component::Link`] points.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LinkTarget {
    /// Another Nexus page.
    Page {
        /// Destination site.
        site: String,
        /// Destination path.
        path: String,
    },
    /// Outside Nexus (rendered as a hint, never auto-followed).
    External {
        /// Human-readable destination hint.
        hint: String,
    },
    /// An app action invoked through the capability broker.
    Action {
        /// Action identifier.
        action_id: String,
    },
}

/// A capability an app component requests; granted/denied by the WebVM broker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Capability {
    /// Local storage quota request.
    Storage {
        /// Requested quota in KiB.
        max_kb: u32,
    },
    /// Network access to listed hosts.
    Network {
        /// Allowed host allowlist.
        hosts: Vec<String>,
    },
    /// Show notifications.
    Notify,
    /// Play audio.
    Audio,
    /// Access the camera.
    Camera,
    /// Access the microphone.
    Microphone,
}

impl Page {
    /// Check schema, title length, component count/depth/shape. Pure:
    /// takes only `&self`, reports the first violation as [`ContentError`].
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

    /// Serialize to canonical JSON bytes (field order fixed by the struct).
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, ContentError> {
        serde_json::to_vec(self).map_err(|e| ContentError::Serialization(e.to_string()))
    }

    /// Parse and validate untrusted page bytes (size-capped, then [`Page::validate`]).
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

/// BLAKE3 content ID (`b3:<hex>`) over raw bytes.
pub fn content_id_of(bytes: &[u8]) -> String {
    format!("b3:{}", hex::encode(blake3::hash(bytes).as_bytes()))
}

/// True for well-formed content IDs: `b3:` plus 64 lowercase/uppercase hex chars.
pub fn is_content_id(s: &str) -> bool {
    let hex_part = s.strip_prefix("b3:").unwrap_or("__invalid__");
    hex_part.len() == 64 && hex_part.chars().all(|c| c.is_ascii_hexdigit())
}

mod nexus_protocol_limits {
    /// Max accepted page bytes (kept in sync with the wire body limit).
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
