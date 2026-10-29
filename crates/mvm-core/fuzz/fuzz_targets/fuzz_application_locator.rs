// Adversarial fuzz for the application locator validator.
//
// Feeds arbitrary bytes to `validate_application_source`, the hand-written
// grammar that admits `https://` and digest-pinned `oci://` locators. The
// properties asserted are crash-freedom and, for anything accepted, that the
// locator is bounded printable ASCII with no userinfo, backslash, query,
// fragment or `xn--` label in its authority.
//
// CI gate: `.github/workflows/security.yml::fuzz`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_core::registry_pack::application::validate_application_source;

fuzz_target!(|data: &[u8]| {
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };
    if validate_application_source(source).is_err() {
        return;
    }
    assert!(source.bytes().all(|byte| (33..127).contains(&byte)));
    let rest = source
        .strip_prefix("https://")
        .or_else(|| source.strip_prefix("oci://"))
        .expect("accepted locators carry a known scheme");
    let authority = rest.split('/').next().unwrap_or("");
    assert!(!authority.contains(['@', '\\', '?', '#', '%']));
    assert!(!authority.split(['.', ':']).any(|label| label.starts_with("xn--")));
});
