//! Structured page model — the Nexus alternative to HTML.
//!
//! A page is typed data (serde JSON on the wire for v0), not a document
//! string. The browser renders it natively. Content IDs are BLAKE3 hashes
//! (`b3:<hex>`) over canonical JSON bytes.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

/// An outbound edge of a resource: a labelled [`LinkTarget`].
///
/// Derived from `Component::Link` (collections included) in document order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reference {
    pub label: String,
    pub target: LinkTarget,
}

/// A `Reference` resolved against known targets: `content_id` is `Some`
/// exactly when the target is a local page the resolver can map to a hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedReference {
    pub label: String,
    pub target: LinkTarget,
    pub content_id: Option<String>,
}

/// Maps `(site, path) -> content id` and resolves a resource's edges.
///
/// v0 keeps the map in memory; ADR 006 signed-record lookup can feed the
/// same contract later. `resolve` alone gives renderers a typed answer
/// instead of string-matching targets.
#[derive(Debug, Clone, Default)]
pub struct ReferenceResolver {
    targets: HashMap<(String, String), String>,
}

impl ReferenceResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &mut self,
        site: impl Into<String>,
        path: impl Into<String>,
        content_id: impl Into<String>,
    ) {
        self.targets
            .insert((site.into(), path.into()), content_id.into());
    }

    pub fn resolve(&self, reference: &Reference) -> ResolvedReference {
        let content_id = match &reference.target {
            LinkTarget::Page { site, path } => {
                self.targets.get(&(site.clone(), path.clone())).cloned()
            }
            _ => None,
        };
        ResolvedReference {
            label: reference.label.clone(),
            target: reference.target.clone(),
            content_id,
        }
    }

    pub fn resolve_resource(&self, resource: &Resource) -> Vec<ResolvedReference> {
        resource
            .references
            .iter()
            .map(|r| self.resolve(r))
            .collect()
    }
}

/// The served, addressed unit of content: identity + version + references
/// around the ADR 003 [`Page`] payload.
///
/// The content ID is always computed over the **bare** `Page` canonical
/// JSON, never the envelope — a page has the same identity whether fetched
/// bare or enveloped, and envelope adornment (`previous`, `references`)
/// cannot move the hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource {
    pub id: String,
    pub content: Page,
    /// Content id of the previous revision, if any (version lineage).
    pub previous: Option<String>,
    /// Outbound edges; always the derived set after validation.
    pub references: Vec<Reference>,
}

/// Wire shape for a full envelope. `references` is optional on input so
/// bare Page JSON (which has none) parses as the envelope-less case.
#[derive(Deserialize)]
struct ResourceEnvelope {
    id: String,
    content: Page,
    #[serde(default)]
    previous: Option<String>,
    #[serde(default)]
    references: Option<Vec<Reference>>,
}

#[derive(Serialize)]
struct ResourceEnvelopeSer<'a> {
    id: &'a str,
    content: &'a Page,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous: &'a Option<String>,
    references: &'a [Reference],
}

impl Serialize for Resource {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        ResourceEnvelopeSer {
            id: &self.id,
            content: &self.content,
            previous: &self.previous,
            references: &self.references,
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for Resource {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let value = serde_json::Value::deserialize(d)?;
        if value.get("content").is_some() && value.get("id").is_some() {
            // Full envelope: identity and references are self-checking.
            let env = ResourceEnvelope::deserialize(value).map_err(D::Error::custom)?;
            let derived = references_of(&env.content);
            if !is_content_id(&env.id) {
                return Err(D::Error::custom("resource id is not a content id"));
            }
            if content_id_of(&env.content.to_canonical_json().map_err(D::Error::custom)?) != env.id
            {
                return Err(D::Error::custom("resource id does not match content hash"));
            }
            if let Some(stored) = &env.references {
                if stored != &derived {
                    return Err(D::Error::custom("references do not match content"));
                }
            }
            Ok(Resource {
                id: env.id,
                content: env.content,
                previous: env.previous,
                references: derived,
            })
        } else {
            // Bare Page JSON (existing sites/example/*.json): wrap it.
            let page = Page::deserialize(value).map_err(D::Error::custom)?;
            Ok(Resource::from_page(page))
        }
    }
}

impl Resource {
    /// Wrap a page: computes the content id over bare page bytes and
    /// derives the outbound references.
    pub fn from_page(page: Page) -> Resource {
        let id = content_id_of(
            &page
                .to_canonical_json()
                .expect("page serialization infallible"),
        );
        let references = references_of(&page);
        Resource {
            id,
            content: page,
            previous: None,
            references,
        }
    }

    /// Full validation: page rules, id == hash of bare content bytes,
    /// `previous` well-formedness, references == derived set.
    pub fn validate(&self) -> Result<(), ContentError> {
        self.content.validate()?;
        if !is_content_id(&self.id) {
            return Err(ContentError::Validation("bad resource id".into()));
        }
        if self.id != content_id_of(&self.content.to_canonical_json()?) {
            return Err(ContentError::Validation(
                "resource id does not match content hash".into(),
            ));
        }
        if let Some(prev) = &self.previous {
            if !is_content_id(prev) {
                return Err(ContentError::Validation("bad previous content id".into()));
            }
        }
        if self.references != references_of(&self.content) {
            return Err(ContentError::Validation(
                "references do not match content".into(),
            ));
        }
        Ok(())
    }

    pub fn to_canonical_json(&self) -> Result<Vec<u8>, ContentError> {
        serde_json::to_vec(self).map_err(|e| ContentError::Serialization(e.to_string()))
    }

    /// Accepts either a full resource envelope or bare Page JSON (the v0
    /// site file shape), then validates.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ContentError> {
        if bytes.len() > nexus_protocol_limits::max_page_bytes() {
            return Err(ContentError::Validation("resource too large".into()));
        }
        let resource: Self =
            serde_json::from_slice(bytes).map_err(|e| ContentError::Validation(e.to_string()))?;
        resource.validate()?;
        Ok(resource)
    }
}

/// Outbound edges of a page in document order (iterative walk; bounded by
/// serde_json's recursion limit on input).
fn references_of(page: &Page) -> Vec<Reference> {
    let mut out = Vec::new();
    let mut stack: Vec<&Component> = page.components.iter().rev().collect();
    while let Some(c) = stack.pop() {
        match c {
            Component::Link { label, target } => {
                out.push(Reference {
                    label: label.clone(),
                    target: target.clone(),
                });
            }
            Component::Collection { items } => stack.extend(items.iter().rev()),
            _ => {}
        }
    }
    out
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

#[cfg(test)]
mod resource_tests {
    use super::*;
    use std::collections::HashMap;

    /// The committed example site file — must keep parsing (bare Page JSON).
    const EXAMPLE_HOME: &str = include_str!("../../../sites/example/home.json");
    const EXAMPLE_ABOUT: &str = include_str!("../../../sites/example/about.json");

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
                Component::Link {
                    label: "About".into(),
                    target: LinkTarget::Page {
                        site: "example".into(),
                        path: "about".into(),
                    },
                },
                Component::Link {
                    label: "External".into(),
                    target: LinkTarget::External {
                        hint: "https://x".into(),
                    },
                },
                Component::Collection {
                    items: vec![Component::Link {
                        label: "Nested".into(),
                        target: LinkTarget::Action {
                            action_id: "go".into(),
                        },
                    }],
                },
            ],
            capabilities: vec![],
        }
    }

    #[test]
    fn site_files_still_parse_as_page_and_resource() {
        for bytes in [EXAMPLE_HOME.as_bytes(), EXAMPLE_ABOUT.as_bytes()] {
            let page = Page::from_json(bytes).unwrap();
            assert!(!page.components.is_empty());
            let resource = Resource::from_json(bytes).unwrap();
            assert_eq!(resource.content, page);
            assert_eq!(resource.id, page.content_id().unwrap());
        }
    }

    #[test]
    fn bare_page_json_wraps_with_derived_references() {
        let resource = Resource::from_json(EXAMPLE_HOME.as_bytes()).unwrap();
        let labels: Vec<&str> = resource
            .references
            .iter()
            .map(|r| r.label.as_str())
            .collect();
        assert_eq!(labels, vec!["About this experiment"]);
        assert_eq!(resource.previous, None);
    }

    #[test]
    fn envelope_roundtrip_equality() {
        let resource = Resource::from_page(example_page());
        let bytes = resource.to_canonical_json().unwrap();
        let back = Resource::from_json(&bytes).unwrap();
        assert_eq!(resource, back);
    }

    #[test]
    fn id_is_over_bare_page_bytes_not_envelope() {
        let page = example_page();
        let bare = Resource::from_page(page.clone());
        let mut enveloped = bare.clone();
        enveloped.previous = Some("b3:".to_owned() + &"a".repeat(64));
        let back = Resource::from_json(&enveloped.to_canonical_json().unwrap()).unwrap();
        assert_eq!(bare.id, page.content_id().unwrap());
        assert_eq!(back.id, bare.id); // adornment does not move the hash
        assert_eq!(back.previous, enveloped.previous);
    }

    #[test]
    fn previous_roundtrips_and_validates() {
        let mut r = Resource::from_page(example_page());
        let prev = format!("b3:{}", "c".repeat(64));
        r.previous = Some(prev.clone());
        let back = Resource::from_json(&r.to_canonical_json().unwrap()).unwrap();
        assert_eq!(back.previous.as_deref(), Some(prev.as_str()));
        r.previous = Some("nope".into());
        assert!(r.validate().is_err());
    }

    #[test]
    fn envelope_with_wrong_id_rejected() {
        let bare = Resource::from_page(example_page());
        let mut json: serde_json::Value =
            serde_json::from_slice(&bare.to_canonical_json().unwrap()).unwrap();
        json["id"] = serde_json::Value::String(format!("b3:{}", "0".repeat(64)));
        assert!(serde_json::from_slice::<Resource>(&serde_json::to_vec(&json).unwrap()).is_err());
    }

    #[test]
    fn envelope_with_mismatched_references_rejected() {
        let bare = Resource::from_page(example_page());
        let mut json: serde_json::Value =
            serde_json::from_slice(&bare.to_canonical_json().unwrap()).unwrap();
        json["references"] = serde_json::json!([]);
        assert!(Resource::from_json(&serde_json::to_vec(&json).unwrap()).is_err());
    }

    #[test]
    fn references_documented_order_including_nested() {
        let r = Resource::from_page(example_page());
        let kinds: Vec<&str> = r
            .references
            .iter()
            .map(|ref_| match &ref_.target {
                LinkTarget::Page { .. } => "page",
                LinkTarget::External { .. } => "external",
                LinkTarget::Action { .. } => "action",
            })
            .collect();
        assert_eq!(kinds, vec!["page", "external", "action"]);
    }

    #[test]
    fn resolver_maps_page_edges_to_content_ids() {
        let r = Resource::from_page(example_page());
        let mut targets = HashMap::from([(
            ("example".to_string(), "about".to_string()),
            format!("b3:{}", "d".repeat(64)),
        )]);
        let mut resolver = ReferenceResolver::default();
        for ((site, path), id) in targets.drain() {
            resolver.insert(site, path, id);
        }
        let resolved = resolver.resolve_resource(&r);
        assert_eq!(resolved.len(), 3);
        assert!(resolved[0].content_id.is_some());
        assert_eq!(
            resolved[0].content_id.as_deref(),
            Some(format!("b3:{}", "d".repeat(64)).as_str())
        );
        assert!(resolved[1].content_id.is_none()); // external
        assert!(resolved[2].content_id.is_none()); // action
    }

    #[test]
    fn rejects_oversized_input() {
        let resource = Resource::from_page(example_page());
        let mut big = resource.to_canonical_json().unwrap();
        big.resize(1024 * 1024 + 1, b' ');
        assert!(Resource::from_json(&big).is_err());
    }
}
