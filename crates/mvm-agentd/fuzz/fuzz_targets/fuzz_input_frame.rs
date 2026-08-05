// Fuzz the guest-side workload-input deserializers. The host→guest input
// plane puts two new parser-shaped types on the guest's wire: `InputFrame`,
// one chunk of bytes bound for the entrypoint's stdin, and `CloseInput`, the
// end-of-input marker carrying the tail the host withheld. Both arrive over
// vsock and both are read before anything else looks at them, so a panic here
// is a guest-agent death triggered by whatever the peer chose to send.
//
// Fuzzed together because they travel the same channel and a writer controls
// which one it sends; splitting them would halve the corpus each gets for no
// coverage gain.
//
// The fuzzer must never produce a panic; deserialization errors are the
// expected result for malformed input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_contract::stream::input::{CloseInput, InputFrame};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<InputFrame>(data);
    let _ = serde_json::from_slice::<CloseInput>(data);
});
