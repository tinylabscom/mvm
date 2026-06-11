// Fuzz the host-side `EntrypointEvent` JSON deserializer. The host
// reads each frame of a `RunEntrypoint` response stream, deserializes
// it as `EntrypointEvent`, and acts on the variant. A compromised or
// buggy guest can write whatever bytes it wants on the wire, so this
// is the host's first parser-shaped surface for the entrypoint verb.
//
// The fuzzer must never produce a panic; deserialization errors are
// the expected result for malformed input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_guest::vsock::EntrypointEvent;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<EntrypointEvent>(data);
});
