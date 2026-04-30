// ADR-002 §W4.2 — fuzz the authenticated-frame envelope. The wrapper is
// deserialized before any signature check runs, so a panic in the envelope
// parser would let an unauthenticated attacker crash the agent. Inputs are
// fed straight into `serde_json::from_slice::<AuthenticatedFrame>`; we are
// not asserting verification, only that the parser never panics.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_core::security::AuthenticatedFrame;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<AuthenticatedFrame>(data);
});
