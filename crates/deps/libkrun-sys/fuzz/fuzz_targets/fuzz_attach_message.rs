// Fuzz the host-side `SupervisorAttachConfig` JSON parser — a new
// untrusted-input surface.
//
// The prelaunched `mvm-libkrun-supervisor` reads this struct off a same-uid
// control UDS — the only attacker-reachable surface after spawn. Any panic
// here is a hard process death before `start_enter`. Sibling of
// `fuzz_supervisor_config`; the harness goal is "never panic on any input"
// (`serde_json::Error` is the expected outcome for malformed bytes).

#![no_main]

use libfuzzer_sys::fuzz_target;
use libkrun_sys::SupervisorAttachConfig;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<SupervisorAttachConfig>(data);
});
