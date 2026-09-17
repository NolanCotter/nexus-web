//! Total-parser corpus extension (gap-filler beyond the sibling
//! `adversarial.rs`): a programmatically generated battery of 200+ hostile
//! inputs. Contract: `Err`, never panic, never allocate unboundedly.
//!
//! Covers gaps the sibling corpus leaves open: byte-level `split_response`
//! with non-UTF8/NUL header bytes, version/verb/number edge cases, and a
//! characterization battery for `is_valid_site`/`is_valid_path`.

use nexus_protocol::{
    is_valid_path, is_valid_site, parse_request, parse_response_header, split_response,
    MAX_PATH_LEN, MAX_SITE_LEN,
};

/// Truncations + hostile single-byte substitutions at every position.
fn request_mutations() -> Vec<Vec<u8>> {
    let base: &[u8] = b"NXP/0.1 FETCH example home\n";
    let mut out: Vec<Vec<u8>> = Vec::new();
    for cut in 0..=base.len() {
        out.push(base[..cut].to_vec());
    }
    for (i, _) in base.iter().enumerate() {
        for &hb in b"\0\n\xff " {
            let mut m = base.to_vec();
            m[i] = hb;
            out.push(m);
        }
    }
    out
}

fn response_mutations() -> Vec<Vec<u8>> {
    let base: &[u8] = b"NXP/0.1 200 5\nhello";
    let mut out: Vec<Vec<u8>> = Vec::new();
    for cut in 0..=base.len() {
        out.push(base[..cut].to_vec());
    }
    for (i, _) in base.iter().enumerate() {
        for &hb in b"\0\n\xff\t" {
            let mut m = base.to_vec();
            m[i] = hb;
            out.push(m);
        }
    }
    // Header bytes that survive per-position edits: NUL in header, non-UTF8
    // inside the header line, non-UTF8 inside the body, MAX_BODY claim with
    // no body, and a two-newline frame.
    out.push(b"NXP/0.1 200\x00 5\nhello".to_vec());
    out.push(b"NXP/0.1 \xff00 5\nhello".to_vec());
    out.push(b"NXP/0.1 200 5\nh\xffllo".to_vec());
    out.push(b"NXP/0.1 200 1048576\n".to_vec());
    out.push(b"NXP/0.1 200 5\nhello\nworld".to_vec());
    out
}

#[test]
fn mutation_battery_over_200_inputs_never_panics() {
    let reqs = request_mutations();
    let resps = response_mutations();
    let total = reqs.len() + resps.len();
    assert!(total >= 200, "mutation corpus too small: {total}");
    for input in &reqs {
        let s = String::from_utf8_lossy(input);
        if let Ok(req) = parse_request(&s) {
            // Accepted requests must round-trip stably.
            assert!(!req.site.is_empty() && !req.path.is_empty());
            let line = nexus_protocol::encode_request(&req).unwrap();
            assert_eq!(parse_request(&line).unwrap(), req);
        }
    }
    for frame in &resps {
        if let Ok((h, body)) = split_response(frame) {
            assert!(body.len() == h.body_len, "len mismatch on accepted frame");
        }
        // Header-only parse must also be total on any first-line candidate.
        let s = String::from_utf8_lossy(frame);
        let line = s.lines().next().unwrap_or("");
        let _ = parse_response_header(&format!("{line}\n"));
    }
}

/// Explicit field-level corpus: every variant must be rejected.
#[test]
fn request_field_battery_rejects() {
    for v in [
        "",
        "get",
        "GET",
        "FETCHX",
        "FETC ",
        "FETCH\t",
        "FETCH\nX",
        "FETCH ",
        " F\u{fffd}TCH",
    ] {
        assert!(
            parse_request(&format!("NXP/0.1 {v} example home\n")).is_err(),
            "verb {v:?} accepted"
        );
    }
    for v in [
        "",
        "NXP/",
        "NXP/0",
        "NXP/0.",
        "NXP/0.1x",
        "NXP/0.10",
        "NXP/00.1",
        "NXP/0.1 ",
        "NXP/0.1\t",
        "NXP/ 0.1",
        "NXP//0.1",
        "NXP/0.1\x00",
        "nxp/0.1",
        "NXP/9.9",
        "HTTP/1.1",
        "XNP/0.1",
        "0.1",
    ] {
        assert!(
            parse_request(&format!("{v} FETCH example home\n")).is_err(),
            "version {v:?} accepted"
        );
    }
    for s in [
        "",
        "-",
        "-a",
        "a-",
        "--",
        "A",
        "a_b",
        "ExamplE",
        "\t",
        "a\x00b",
        "ä",
        "α",
        "ａ",
        &"a".repeat(MAX_SITE_LEN + 1),
    ] {
        assert!(
            parse_request(&format!("NXP/0.1 FETCH {s} home\n")).is_err(),
            "site {s:?} accepted"
        );
    }
    for p in [
        "",
        "/",
        "//",
        "../",
        "..",
        "...",
        "a..b",
        "a/../b",
        "a//b",
        "/a",
        "\\",
        "a\\b",
        "%2e%2e",
        "a b",
        "a\tb",
        "a\nb",
        "a\x00b",
        "é",
        &"b".repeat(MAX_PATH_LEN + 1),
    ] {
        assert!(
            parse_request(&format!("NXP/0.1 FETCH example {p}\n")).is_err(),
            "path {p:?} accepted"
        );
    }
}

/// Response header field battery: every variant must be rejected.
#[test]
fn response_field_battery_rejects() {
    for code in [
        "",
        "99",
        "600",
        "0",
        "abc",
        "200 ",
        "200.0",
        "0xC8",
        "2 0",
        "200\t5",
        "\u{ff12}00",
    ] {
        assert!(
            parse_response_header(&format!("NXP/0.1 {code} 5\n")).is_err(),
            "code {code:?} accepted"
        );
    }
    for len in [
        "",
        "-1",
        "0x5",
        "5 ",
        "\t5",
        "\u{ff15}",
        "1_000",
        "18446744073709551615",
        "18446744073709551616",
        "99999999999999999999999999999999999999",
        "1e5",
        "1048577",
    ] {
        assert!(
            parse_response_header(&format!("NXP/0.1 200 {len}\n")).is_err(),
            "len {len:?} accepted"
        );
    }
    for v in ["", "NXP/0.2", "NXP/1.0", "nxp/0.1", "HTTP/1.1", "NXP/0.1 "] {
        assert!(
            parse_response_header(&format!("{v} 200 5\n")).is_err(),
            "version {v:?} accepted"
        );
    }
}

/// Documented non-canonical acceptance: Rust integer parsing tolerates a
/// leading `+` and leading zeros, so `+200`/`0200`/`+5` parse. Range
/// enforcement still applies, so this is a canonical-encoding soft gap
/// (ADR wants one canonical form), not an allocation or range hazard.
#[test]
fn non_canonical_plus_sign_accepted_bounded() {
    for line in ["NXP/0.1 +200 +5\n", "NXP/0.1 0200 5\n"] {
        let h = parse_response_header(line).unwrap();
        assert_eq!((h.code, h.body_len), (200, 5), "{line:?}");
    }
    assert!(parse_response_header("NXP/0.1 +99 +5\n").is_err()); // range
    assert!(parse_response_header("NXP/0.1 +600 +5\n").is_err()); // range
    assert!(parse_response_header("NXP/0.1 +200 +1048577\n").is_err()); // cap
    assert!(parse_response_header("NXP/0.1 +200 +99999999999999999999999999\n").is_err());
}

/// Boundary acceptance: limits are inclusive, one over is rejected.
#[test]
fn boundary_battery() {
    let ok = |req: &str| assert!(parse_request(req).is_ok(), "{req:?} should parse");
    ok(&format!(
        "NXP/0.1 FETCH {} home\n",
        "a".repeat(MAX_SITE_LEN)
    ));
    ok(&format!(
        "NXP/0.1 FETCH example {}\n",
        "b".repeat(MAX_PATH_LEN)
    ));
    assert!(parse_request(&format!(
        "NXP/0.1 FETCH {} home\n",
        "a".repeat(MAX_SITE_LEN + 1)
    ))
    .is_err());
    assert!(parse_request(&format!(
        "NXP/0.1 FETCH example {}\n",
        "b".repeat(MAX_PATH_LEN + 1)
    ))
    .is_err());
    // A site cannot contain `.`; a path can.
    assert!(parse_request("NXP/0.1 FETCH site-0-example-9 a/b_c-d.e+f/0\n").is_ok());
    assert!(parse_request("NXP/0.1 FETCH site.example home\n").is_err());
}

/// Characterization battery for the canonical path/site validators.
#[test]
fn validator_characterization_battery() {
    // Single-byte chars: exactly the documented allow set is valid, except
    // `/` alone (leading-slash rule) and `-` alone (leading-dash rule).
    for b in 0u8..=127 {
        let c = b as char;
        let expect =
            (c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '.' | '+')) && c != '/';
        let s = c.to_string();
        assert_eq!(is_valid_path(&s), expect, "path char {c:?} ({b})");
        let expect_site = c.is_ascii_lowercase() || c.is_ascii_digit();
        assert_eq!(is_valid_site(&s), expect_site, "site char {c:?} ({b})");
    }
    // Path strings: traversal, separators, NULs, unicode. Note `a/` and `.`
    // are accepted today (trailing-slash and dot-root paths are legal wire
    // paths) — documented current behavior, not a blessing.
    for (p, expect) in [
        ("a/b", true),
        ("a/", true),
        ("a.", true),
        (".hidden", true),
        (".", true),
        ("..", false),
        ("...", false),
        ("a..b", false),
        ("../x", false),
        ("a/../b", false),
        ("a//b", false),
        ("/a", false),
        ("a\\b", false),
        ("%2e%2e", false),
        ("a b", false),
        ("a\tb", false),
        ("a\x00b", false),
        ("é", false),
    ] {
        assert_eq!(is_valid_path(p), expect, "path {p:?}");
    }
    // Site strings: case, dashes, underscores, unicode.
    for (s, expect) in [
        ("a-b", true),
        ("0a1", true),
        ("-a", false),
        ("a-", false),
        ("--", false),
        ("a_b", false),
        ("A", false),
        ("a\x00b", false),
        ("ä", false),
    ] {
        assert_eq!(is_valid_site(s), expect, "site {s:?}");
    }
}
