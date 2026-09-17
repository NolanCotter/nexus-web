//! Deterministic adversarial corpus for `Page::from_json`.
//!
//! Fallback companion to `fuzz/fuzz_targets/page_from_json.rs`.
//! Contract under test: any byte string returns `Ok(valid page)` or `Err` —
//! never a panic, stack overflow, or unbounded allocation.
//! Run with plain `cargo test --workspace` (no nightly required).

use nexus_content::{Component, LinkTarget, Metadata, Page};
use serde_json::json;

fn valid_page_json() -> Vec<u8> {
    let p = Page {
        metadata: Metadata {
            schema: 1,
            site: "example".into(),
            path: "home".into(),
            title: "Example".into(),
            revision: 1,
        },
        components: vec![Component::Text { text: "hi".into() }],
        capabilities: vec![],
    };
    p.to_canonical_json().unwrap()
}

/// Fixed AFL-style seeds: structural breaks, limit probes, hostile shapes.
fn page_corpus() -> Vec<Vec<u8>> {
    let c: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"not json".to_vec(),
        b"null".to_vec(),
        b"[]".to_vec(),
        b"{}".to_vec(),
        b"\"str\"".to_vec(),
        b"123".to_vec(),
        b"{".to_vec(),
        b"{\"metadata\":".to_vec(),
        valid_page_json(),
        b"{\"metadata\":null,\"components\":[]}".to_vec(),
        b"{\"metadata\":{\"schema\":99,\"site\":\"e\",\"path\":\"p\",\"title\":\"t\",\"revision\":0},\"components\":[{\"type\":\"text\",\"text\":\"x\"}]}".to_vec(),
        // empty title
        b"{\"metadata\":{\"schema\":1,\"site\":\"e\",\"path\":\"p\",\"title\":\"\",\"revision\":0},\"components\":[{\"type\":\"text\",\"text\":\"x\"}]}".to_vec(),
        // empty components
        b"{\"metadata\":{\"schema\":1,\"site\":\"e\",\"path\":\"p\",\"title\":\"t\",\"revision\":0},\"components\":[]}".to_vec(),
        // bad heading levels
        b"{\"metadata\":{\"schema\":1,\"site\":\"e\",\"path\":\"p\",\"title\":\"t\",\"revision\":0},\"components\":[{\"type\":\"heading\",\"level\":0,\"text\":\"x\"}]}".to_vec(),
        b"{\"metadata\":{\"schema\":1,\"site\":\"e\",\"path\":\"p\",\"title\":\"t\",\"revision\":0},\"components\":[{\"type\":\"heading\",\"level\":7,\"text\":\"x\"}]}".to_vec(),
        // bad content id
        b"{\"metadata\":{\"schema\":1,\"site\":\"e\",\"path\":\"p\",\"title\":\"t\",\"revision\":0},\"components\":[{\"type\":\"image\",\"content_id\":\"nope\",\"alt\":\"a\"}]}".to_vec(),
        // empty link label
        b"{\"metadata\":{\"schema\":1,\"site\":\"e\",\"path\":\"p\",\"title\":\"t\",\"revision\":0},\"components\":[{\"type\":\"link\",\"label\":\"\",\"target\":{\"kind\":\"action\",\"action_id\":\"a\"}}]}".to_vec(),
        // empty app id
        b"{\"metadata\":{\"schema\":1,\"site\":\"e\",\"path\":\"p\",\"title\":\"t\",\"revision\":0},\"components\":[{\"type\":\"app\",\"app_id\":\"\",\"props\":{}}]}".to_vec(),
        // unknown component type
        b"{\"metadata\":{\"schema\":1,\"site\":\"e\",\"path\":\"p\",\"title\":\"t\",\"revision\":0},\"components\":[{\"type\":\"evil\",\"x\":1}]}".to_vec(),
        // deeply nested JSON arrays (parser-depth probe, not yet a Page)
        format!("{{\"a\":{}}}", "[".repeat(500)).into_bytes(),
        format!("{{\"a\":{}}}", "{".repeat(500)).into_bytes(),
        // deeply nested Collection components (validator-depth probe)
        {
            let mut inner = json!({"type":"text","text":"x"});
            for _ in 0..60 {
                inner = json!({"type":"collection","items":[inner]});
            }
            format!(
                "{{\"metadata\":{{\"schema\":1,\"site\":\"e\",\"path\":\"p\",\"title\":\"t\",\"revision\":0}},\"components\":[{inner}]}}"
            )
            .into_bytes()
        },
        // many components (count-limit probe, small items to stay < 1MiB)
        {
            let items = vec![json!({"type":"text","text":"x"}); 5000];
            format!(
                "{{\"metadata\":{{\"schema\":1,\"site\":\"e\",\"path\":\"p\",\"title\":\"t\",\"revision\":0}},\"components\":{}}}",
                serde_json::to_string(&items).unwrap()
            )
            .into_bytes()
        },
        // huge text field (256KiB + 1)
        {
            let big = "t".repeat(256 * 1024 + 1);
            format!(
                "{{\"metadata\":{{\"schema\":1,\"site\":\"e\",\"path\":\"p\",\"title\":\"t\",\"revision\":0}},\"components\":[{{\"type\":\"text\",\"text\":{}}}]}}",
                serde_json::to_string(&big).unwrap()
            )
            .into_bytes()
        },
        // title 300 chars (over 256 limit)
        {
            let t = "t".repeat(300);
            format!(
                "{{\"metadata\":{{\"schema\":1,\"site\":\"e\",\"path\":\"p\",\"title\":\"{t}\",\"revision\":0}},\"components\":[{{\"type\":\"text\",\"text\":\"x\"}}]}}"
            )
            .into_bytes()
        },
        // duplicate keys, trailing garbage, trailing newline
        b"{\"metadata\":{\"schema\":1,\"site\":\"e\",\"path\":\"p\",\"title\":\"t\",\"revision\":0},\"components\":[{\"type\":\"text\",\"text\":\"x\"}],\"components\":[]}".to_vec(),
        {
            let mut v = valid_page_json();
            v.extend_from_slice(b"TRAILING");
            v
        },
        {
            let mut v = valid_page_json();
            v.push(b'\n');
            v
        },
        // truncated valid page
        {
            let mut v = valid_page_json();
            v.truncate(v.len() / 2);
            v
        },
        // non-UTF8 bytes
        vec![0xff, 0xfe, 0x00, 0x01, 0x80],
        // NUL inside JSON
        b"{\"metadata\":\x00}".to_vec(),
        // unicode-heavy text
        "{\"metadata\":{\"schema\":1,\"site\":\"e\",\"path\":\"p\",\"title\":\"café中文\",\"revision\":0},\"components\":[{\"type\":\"text\",\"text\":\"hello world\"}]}"
            .as_bytes()
            .to_vec(),
        // oversized page (> 1MiB pre-parse gate)
        vec![b'x'; 1024 * 1024 + 1],
        // almost-oversized but structurally invalid (gate must fire first)
        vec![b'{'; 1024 * 1024],
    ];
    c
}

#[test]
fn adversarial_page_from_json_never_panics() {
    let corpus = page_corpus();
    assert!(corpus.len() >= 30, "corpus too small: {}", corpus.len());
    for (i, input) in corpus.iter().enumerate() {
        let r = Page::from_json(input);
        match r {
            Ok(page) => {
                // Any accepted page must validate and round-trip.
                page.validate()
                    .unwrap_or_else(|_| panic!("case {i}: from_json accepted an invalid page"));
                let bytes = page
                    .to_canonical_json()
                    .expect("case {i}: re-encode failed");
                let q = Page::from_json(&bytes).expect("case {i}: round-trip failed");
                assert_eq!(page, q, "case {i}: round-trip mismatch");
            }
            Err(_) => {}
        }
    }
}

#[test]
fn adversarial_page_title_boundary() {
    // 256-char title is the documented max; 257 must fail.
    for (len, ok) in [(256, true), (257, false)] {
        let t = "t".repeat(len);
        let bytes = format!(
            "{{\"metadata\":{{\"schema\":1,\"site\":\"e\",\"path\":\"p\",\"title\":\"{t}\",\"revision\":0}},\"components\":[{{\"type\":\"text\",\"text\":\"x\"}}]}}"
        )
        .into_bytes();
        assert_eq!(
            Page::from_json(&bytes).is_ok(),
            ok,
            "title len {len} expected ok={ok}"
        );
    }
}

#[test]
fn adversarial_page_link_targets_never_panic() {
    // Every LinkTarget kind with hostile strings.
    let targets = vec![
        json!({"kind":"page","site":"","path":""}),
        json!({"kind":"page","site":"UPPER","path":"/abs"}),
        json!({"kind":"page","site":"a".repeat(500),"path":"b".repeat(500)}),
        json!({"kind":"external","hint":""}),
        json!({"kind":"external","hint":"x".repeat(5000)}),
        json!({"kind":"action","action_id":""}),
        json!({"kind":"unknown_kind"}),
        json!("just a string"),
        json!(null),
    ];
    for (i, t) in targets.iter().enumerate() {
        let v = json!({
            "metadata":{"schema":1,"site":"e","path":"p","title":"t","revision":0},
            "components":[{"type":"link","label":"ok","target":t}]
        });
        let bytes = serde_json::to_vec(&v).unwrap();
        let r = Page::from_json(&bytes);
        match r {
            Ok(p) => {
                p.validate().expect("accepted page must validate");
                let _ = p.content_id().expect("content id must compute");
            }
            Err(_) => {}
        }
        let _ = i;
    }
    // Sanity: a well-formed page link still works and hashes.
    let v = json!({
        "metadata":{"schema":1,"site":"e","path":"p","title":"t","revision":0},
        "components":[{"type":"link","label":"About","target":{"kind":"page","site":"example","path":"about"}}]
    });
    let p = Page::from_json(&serde_json::to_vec(&v).unwrap()).unwrap();
    assert!(p.content_id().unwrap().starts_with("b3:"));
    let _ = LinkTarget::Page {
        site: "e".into(),
        path: "p".into(),
    };
}
