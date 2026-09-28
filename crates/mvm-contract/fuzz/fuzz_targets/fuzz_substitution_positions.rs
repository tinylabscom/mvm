//! Fuzz placeholder position classification and position-specific encodings.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_contract::substitution::{
    SECRET_PLACEHOLDER_PREFIX, basic_credential, basic_header, locate_placeholders,
    percent_encode,
};

fuzz_target!(|data: &[u8]| {
    let (url_bytes, value_bytes) = data.split_at(data.len() / 2);
    let url = String::from_utf8_lossy(url_bytes);
    let value = String::from_utf8_lossy(value_bytes);
    let headers = vec![
        ("X-Fuzz".to_string(), value.to_string()),
        ("Authorization".to_string(), basic_header(&value)),
    ];

    let first = locate_placeholders(&url, &headers);
    let second = locate_placeholders(&url, &headers);
    assert_eq!(first, second, "classification must be deterministic");
    for located in first {
        assert!(located.placeholder.starts_with(SECRET_PLACEHOLDER_PREFIX));
    }

    let encoded = basic_header(&value);
    assert_eq!(basic_credential("authorization", &encoded).as_deref(), Some(value.as_ref()));
    let escaped = percent_encode(&value);
    assert!(!escaped.bytes().any(|byte| byte.is_ascii_whitespace()));
});
