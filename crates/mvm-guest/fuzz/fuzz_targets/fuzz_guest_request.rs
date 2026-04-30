// ADR-002 §W4.2 — fuzz the host→guest JSON deserializer. Every byte
// arriving on vsock port 52 lands in `serde_json::from_slice::<GuestRequest>`
// before any agent logic runs, so this is the agent's first parser-shaped
// surface. The fuzzer must never produce a panic; deserialization errors
// are the expected result for malformed input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_guest::vsock::GuestRequest;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<GuestRequest>(data);
});
