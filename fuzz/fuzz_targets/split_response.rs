#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // split_response takes raw bytes. Contract: Err-never-panic.
    let _ = nexus_protocol::split_response(data);
    // Also cover the header-only path when input is UTF-8-ish.
    if let Ok(s) = std::str::from_utf8(data) {
        // Take up to the first line as a header candidate.
        let line = s.lines().next().unwrap_or("");
        let _ = nexus_protocol::parse_response_header(line);
    }
});
