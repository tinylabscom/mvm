// Adversarial fuzz for the hardened snapshot-frame parser.
//
// Feeds arbitrary bytes to `mvm_core::snapshot_frame::parse_header` and
// `parse_sections` and asserts the single property the format guarantees:
//
//   the parser never panics on any byte input.
//
// `parse_sections` exercises the whole chain — magic/version/arch checks,
// `cap_count` against the section ceiling, and `checked_region` bounds/overflow
// math — so a hostile header (huge counts, offsets past EOF, overflowing
// offset+len) must fail closed with a typed `FrameError`, never an allocation
// blow-up, slice OOB, or arithmetic overflow panic.
//
// CI gate: `.github/workflows/security.yml::fuzz`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_core::snapshot_frame::{parse_header, parse_sections};

fuzz_target!(|data: &[u8]| {
    let _ = parse_header(data);

    // On success, every returned section region must be in bounds — slicing it
    // must not panic. (`parse_sections` validates this via `checked_region`;
    // the assertion makes a regression in that contract a fuzz crash.)
    if let Ok(sections) = parse_sections(data) {
        for section in &sections {
            let bytes = section.data(data);
            assert!(section.region.offset + bytes.len() <= data.len());
        }
    }
});
