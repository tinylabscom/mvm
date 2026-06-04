// Plan 97 Phase A / ADR-002 claim 5 — fuzz the host-side
// `SupervisorConfig` JSON parser the `mvm-vz-supervisor` Swift binary
// reads on stdin.
//
// The Rust parser is the canonical schema; the Swift `JSONDecoder` in
// `crates/mvm-vz-supervisor/Sources/mvm-vz-supervisor/Config.swift`
// mirrors it field-for-field with deny-unknown-fields semantics
// (`StrictKeys` protocol). The intent of the corpus equivalence
// assertion (Plan 97 Phase A checklist item) is "the Rust and Swift
// decoders reject the same inputs"; for both decoders to be
// rejection-equivalent, neither can panic — `serde_json::Error` is the
// expected outcome for malformed bytes.
//
// Analog of `crates/mvm-libkrun/fuzz/fuzz_targets/fuzz_supervisor_config.rs`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_build::vz::SupervisorConfig;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<SupervisorConfig>(data);
});
