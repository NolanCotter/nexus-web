#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // parse_request takes &str: exercise both valid-UTF8 and lossy paths.
    // The contract is Err-never-panic on any input.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = nexus_protocol::parse_request(s);
    } else {
        let s = String::from_utf8_lossy(data);
        let _ = nexus_protocol::parse_request(&s);
    }
});
