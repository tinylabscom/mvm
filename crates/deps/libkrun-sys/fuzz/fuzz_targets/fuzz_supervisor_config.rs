// Plan 88 W6 / ADR-055 §"New untrusted-input surfaces" — fuzz the
// host-side `SupervisorConfig` JSON parser.
//
// `mvm-libkrun-supervisor`'s `main()` reads a `SupervisorConfig`
// document on stdin before any libkrun call. The bytes come from a
// pipe the calling `mvmctl` writes, which is same-uid trust today,
// but the parser is the entry point for the supervisor's lifetime
// and any panic here turns into a hard process death before the
// state directory or PID file are written.
//
// Analog of `crates/mvm-guest/fuzz/fuzz_targets/fuzz_guest_request.rs`
// for the host side. The harness goal is "never panic on any input";
// `serde_json::Error` is the expected outcome for malformed bytes.
//
// `KrunContext` (the inner field) carries the `NetworkingMode` enum
// that Plan 88 extended to `{Tsi, Passt {..}, Gvproxy {..}}` — so
// this target also covers the new gvproxy variant's tag parser.

#![no_main]

use libfuzzer_sys::fuzz_target;
use libkrun_sys::SupervisorConfig;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<SupervisorConfig>(data);
});
