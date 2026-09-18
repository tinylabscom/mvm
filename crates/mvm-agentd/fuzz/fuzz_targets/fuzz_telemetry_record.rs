//! Exercise the size/depth-bounded post-decryption telemetry parser.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_core::protocol::telemetry::{MAX_RECORD_BYTES, TelemetryRecord};

fuzz_target!(|data: &[u8]| {
    if let Ok(record) = TelemetryRecord::decode(data) {
        // A legal input can expand when noncanonical JSON is canonicalized.
        // Encoding may refuse that expansion, but never emit an oversized frame.
        if let Ok(encoded) = record.encode() {
            assert!(encoded.len() <= MAX_RECORD_BYTES);
            assert_eq!(TelemetryRecord::decode(&encoded).unwrap(), record);
        }
    }
});
