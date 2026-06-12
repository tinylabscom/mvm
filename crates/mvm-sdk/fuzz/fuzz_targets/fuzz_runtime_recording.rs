// Fuzz the SDK runtime-recording parse + lowering.
//
// The recording JSON is the promotion path's untrusted input: it is
// written by user-spawned code to a tmpfile and read back by the CLI.
// The harness contract is "never panic on any input": serde must fail
// closed on garbage (deny_unknown_fields), and every lowering refusal
// (op limits, duplicate paths, oversize or malformed FilesWrite b64,
// missing entrypoint) must surface as Err, never as a panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_sdk::runtime::{compile_recording_with_findings, RuntimeRecording};

fuzz_target!(|data: &[u8]| {
    if let Ok(rec) = serde_json::from_slice::<RuntimeRecording>(data) {
        let _ = compile_recording_with_findings(&rec);
    }
});
