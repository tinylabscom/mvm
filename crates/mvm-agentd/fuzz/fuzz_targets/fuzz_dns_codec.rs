//! Exercise the bounded DNS parser and response encoder with arbitrary bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_protocol::protocol::dns::{decode_query, encode_response, DnsRcode};

fuzz_target!(|data: &[u8]| {
    if let Ok(question) = decode_query(data) {
        let response = encode_response(&question, DnsRcode::NoError, &[]);
        assert!(response.len() <= mvm_protocol::protocol::dns::MAX_DNS_MESSAGE);
    }
});
