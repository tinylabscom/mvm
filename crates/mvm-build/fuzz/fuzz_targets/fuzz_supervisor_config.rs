// Claim 5 — fuzz the host-side `SupervisorConfig` JSON parser the
// `mvm-vz-supervisor` Swift binary reads on stdin.
//
// The Rust parser is the canonical schema; the Swift `JSONDecoder`
// mirrors it field-for-field with deny-unknown-fields semantics
// (`StrictKeys` protocol). The Rust and Swift decoders must reject the
// same inputs; for them to be rejection-equivalent, neither can panic —
// `serde_json::Error` is the expected outcome for malformed bytes.
//
// Analog of `crates/mvm-libkrun/fuzz/fuzz_targets/fuzz_supervisor_config.rs`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_build::vz::SupervisorConfig;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<SupervisorConfig>(data);
});
