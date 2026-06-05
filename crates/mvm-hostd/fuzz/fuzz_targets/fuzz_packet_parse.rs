// Plan 141 / ADR-064 — fuzz the gateway packet parser + payload rebuilder.
//
// `packet::parse` is the first real parse on the guest's network path
// (pre-Plan-141 the bridge byte-copied opaquely). `rebuild_with_payload`
// re-serializes a frame after an observer's `Verdict::Modify`. Both run on
// attacker-influenced bytes (claim 5). The harness goal is "never panic on
// any input": `parse` must fail closed to `None` on garbage, and rebuilding
// with the frame's own payload must round-trip without panicking for any
// frame `parse` accepted.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_hostd::supervisor::network::packet;

fuzz_target!(|data: &[u8]| {
    if let Some(parsed) = packet::parse(data) {
        // Re-emitting the original payload must never panic (it may Err on
        // extension-header / over-MTU frames — that is the fail-closed path).
        let payload = parsed.l4_payload.to_vec();
        let _ = packet::rebuild_with_payload(data, &payload, 1514);
    }
});
