//! Deterministic adversarial corpus for the NXP/0.1 wire parsers.
//!
//! Fallback companion to the `cargo-fuzz` targets in `fuzz/fuzz_targets/`.
//! Each input asserts the Err-never-panic contract: parsers return `Ok` or
//! `Err`, they must never panic, overflow, or allocate unboundedly.
//! Run with plain `cargo test --workspace` (no nightly required).

use nexus_protocol::{parse_request, parse_response_header, split_response, MAX_BODY, MAX_LINE};

// ---- parse_request corpus ------------------------------------------------

/// Fixed AFL-style seeds: valid frames, boundary lengths, and known-hostile shapes.
fn request_corpus() -> Vec<Vec<u8>> {
    let mut c: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"\n".to_vec(),
        b"\r\n".to_vec(),
        b"NXP/0.1 FETCH example home\n".to_vec(),
        b"NXP/0.1 FETCH example home".to_vec(), // no trailing newline (accepted)
        b"NXP/0.1 FETCH example home\r\n".to_vec(),
        b"NXP/0.1 FETCH a b\n".to_vec(),
        b"NXP/9.9 FETCH example home\n".to_vec(),
        b"nxp/0.1 FETCH example home\n".to_vec(),
        b"NXP/0.1 fetch example home\n".to_vec(),
        b"NXP/0.1 GET example home\n".to_vec(),
        b"NXP/0.1 FETCH Example home\n".to_vec(), // uppercase site
        b"NXP/0.1 FETCH -abc home\n".to_vec(),    // leading dash
        b"NXP/0.1 FETCH abc- home\n".to_vec(),    // trailing dash
        b"NXP/0.1 FETCH  home\n".to_vec(),        // empty site (double space)
        b"NXP/0.1 FETCH example \n".to_vec(),     // empty path
        b"NXP/0.1 FETCH example\n".to_vec(),      // missing path
        b"NXP/0.1 FETCH\n".to_vec(),
        b"NXP/0.1\n".to_vec(),
        b"NXP/0.1 FETCH example /home\n".to_vec(), // leading slash
        b"NXP/0.1 FETCH example a//b\n".to_vec(),
        b"NXP/0.1 FETCH example ../secret\n".to_vec(),
        b"NXP/0.1 FETCH example a b c\n".to_vec(), // extra token / space in path
        b"NXP/0.1  FETCH  example  home\n".to_vec(), // double spaces
        b" NXP/0.1 FETCH example home\n".to_vec(), // leading space
        b"NXP/0.1 FETCH example home \n".to_vec(), // trailing space
        b"NXP/0.1 FETCH example h\x00ome\n".to_vec(), // NUL byte
        b"NXP/0.1 FETCH example caf\xc3\xa9\n".to_vec(), // non-ASCII UTF-8
        b"NXP/0.1 FETCH example a\tb\n".to_vec(),  // tab
        b"\xff\xfeNXP/0.1 FETCH example home\n".to_vec(), // invalid UTF-8 prefix
        b"NXP/0.1 FETCH example .hidden\n".to_vec(),
        b"NXP/0.1 FETCH example a+b_c-d.e/f\n".to_vec(), // all allowed punct
    ];
    // Boundary: max-length site/path, overlong site, overlong line.
    c.push(format!("NXP/0.1 FETCH {} home\n", "a".repeat(64)).into_bytes()); // site == MAX
    c.push(format!("NXP/0.1 FETCH {} home\n", "a".repeat(65)).into_bytes()); // site > MAX
    c.push(format!("NXP/0.1 FETCH example {}\n", "b".repeat(256)).into_bytes()); // path == MAX
    c.push(format!("NXP/0.1 FETCH example {}\n", "b".repeat(257)).into_bytes()); // path > MAX
    c.push(format!("NXP/0.1 FETCH example {}\n", "c".repeat(5000)).into_bytes()); // line > MAX_LINE
    c.push(b"NXP/0.1 FETCH example home\nEXTRA".to_vec()); // trailing garbage, no newline split
    c.push(b"NXP/0.1 FETCH example home\n\n".to_vec()); // extra blank line
    c.push("NXP/0.1 FETCH example home\n".repeat(300).into_bytes()); // many lines in one buffer
    c
}

#[test]
fn adversarial_parse_request_never_panics() {
    let corpus = request_corpus();
    assert!(corpus.len() >= 30, "corpus too small: {}", corpus.len());
    for (i, input) in corpus.iter().enumerate() {
        let s = String::from_utf8_lossy(input);
        // Contract: must return, never panic.
        let r = parse_request(&s);
        match r {
            Ok(req) => {
                // Any accepted request must re-encode and re-parse cleanly.
                assert!(!req.site.is_empty(), "case {i}: empty site accepted");
                assert!(!req.path.is_empty(), "case {i}: empty path accepted");
                let line = nexus_protocol::encode_request(&req).expect("accepted req must encode");
                assert_eq!(parse_request(&line).unwrap(), req, "case {i}: not stable");
            }
            Err(_) => {}
        }
    }
}

#[test]
fn adversarial_parse_request_rejects_overlong_line() {
    let overlong = format!("NXP/0.1 FETCH example {}\n", "x".repeat(MAX_LINE + 1));
    assert!(
        parse_request(&overlong).is_err(),
        "line > MAX_LINE ({MAX_LINE}) must be rejected"
    );
}

// ---- split_response / parse_response_header corpus -----------------------

fn response_corpus() -> Vec<Vec<u8>> {
    let mut c: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"\n".to_vec(),
        b"NXP/0.1 200 5\nhello".to_vec(),
        b"NXP/0.1 200 5\nhello\n".to_vec(), // trailing newline beyond claimed len
        b"NXP/0.1 200 0\n".to_vec(),        // empty body
        b"NXP/0.1 404 0\n".to_vec(),
        b"NXP/0.1 99 0\n".to_vec(),  // code below range
        b"NXP/0.1 600 0\n".to_vec(), // code above range
        b"NXP/0.1 0 0\n".to_vec(),
        b"NXP/0.1 99999 0\n".to_vec(),
        b"NXP/0.1 abc 0\n".to_vec(),              // non-numeric code
        b"NXP/0.1 200 xyz\n".to_vec(),            // non-numeric len
        b"NXP/0.1 200 -1\n".to_vec(),             // negative len
        b"NXP/0.1 200\n".to_vec(),                // missing len
        b"NXP/0.1 200 5".to_vec(),                // no newline at all
        b"NXP/9.9 200 0\n".to_vec(),              // bad version
        b"HTTP/1.1 200 0\n".to_vec(),             // wrong protocol entirely
        b"NXP/0.1 200 5\r\nhello".to_vec(),       // CRLF header
        b"\xff\xfe\x00bad header\nbody".to_vec(), // non-UTF8 header
        b"NXP/0.1 200 5\nhel".to_vec(),           // truncated body
        b"NXP/0.1 200 2\nhiEXTRA".to_vec(),       // trailing garbage
        b"NXP/0.1 200 18446744073709551615\n".to_vec(), // usize::MAX claim
        b"NXP/0.1 200 1048577\n".to_vec(),        // MAX_BODY + 1 claim
        b"NXP/0.1 200 1048576\n".to_vec(),        // MAX_BODY exact claim, body missing
        format!("NXP/0.1 200 0\n{}", "y".repeat(3000)).into_bytes(), // body, claims 0
    ];
    // Overlong header line (> MAX_LINE, no newline within limit).
    c.push(format!("NXP/0.1 200 0 {}\n", "z".repeat(MAX_LINE + 1)).into_bytes());
    // Header split across multiple newlines: first line claims body, rest is body.
    c.push(b"NXP/0.1 200 11\nhello\nworld".to_vec());
    c
}

#[test]
fn adversarial_split_response_never_panics() {
    let corpus = response_corpus();
    assert!(corpus.len() >= 20, "corpus too small: {}", corpus.len());
    for (i, frame) in corpus.iter().enumerate() {
        let r = split_response(frame);
        match r {
            Ok((h, body)) => {
                assert!(
                    (100..=599).contains(&h.code),
                    "case {i}: out-of-range code accepted"
                );
                assert!(
                    body.len() == h.body_len,
                    "case {i}: body len mismatch accepted"
                );
                assert!(h.body_len <= MAX_BODY, "case {i}: oversize accepted");
            }
            Err(_) => {}
        }
        // Header-only path must also never panic on any first-line candidate.
        if let Ok(s) = std::str::from_utf8(frame) {
            let line = s.lines().next().unwrap_or("");
            let _ = parse_response_header(line);
            let _ = parse_response_header(&format!("{line}\n"));
        }
    }
}

#[test]
fn adversarial_split_response_limits() {
    // Oversize claim rejected without allocating the body.
    let hdr = format!("NXP/0.1 200 {}\n", MAX_BODY + 1);
    assert!(parse_response_header(&hdr).is_err());
    assert!(split_response(hdr.as_bytes()).is_err());
    // Exact-limit claim with missing body is Truncated, not a panic.
    let hdr = format!("NXP/0.1 200 {}\n", MAX_BODY);
    assert!(split_response(hdr.as_bytes()).is_err());
}
