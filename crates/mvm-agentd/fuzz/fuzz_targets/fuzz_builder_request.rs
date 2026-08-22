// Fuzz the persistent builder VM dispatch wire.
//
// Mirror of fuzz_guest_request.rs / fuzz_sealed_frame.rs:
// arbitrary bytes are fed straight into
// `serde_json::from_slice::<HostVmRequest>` and
// `serde_json::from_slice::<HostVmResponse>`. We're asserting only
// that the deserializer never panics — every parse failure must be a
// typed `serde_json::Error`, not an unwind. The signed-envelope layer
// (`SealedFrame`) is fuzzed separately by fuzz_sealed_frame.rs and
// fuzz_authed_path.rs;
// this target covers only the inner HostVmRequest / HostVmResponse
// payloads.
//
// The seed corpus directory at
// `corpus/fuzz_builder_request/` carries one entry per known wire
// edge case the unit tests exercise (deny_unknown_fields rejection,
// each variant of each enum). A specific
// adversarial-length-prefix seed is exercised in mvm-build's unit
// tests via `mvm_agentd::vsock::read_frame` against a real
// UnixStream — fuzzing the JSON parser alone can't trigger the
// length-prefix path because that lives in the framing wrapper, not
// the inner payload.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_build::builder_protocol::{HostVmRequest, HostVmResponse};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<HostVmRequest>(data);
    let _ = serde_json::from_slice::<HostVmResponse>(data);
});
