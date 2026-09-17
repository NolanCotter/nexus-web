#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Page::from_json takes raw bytes. Contract: Err-never-panic,
    // including deeply nested / oversized / truncated JSON.
    let _ = nexus_content::Page::from_json(data);
});
