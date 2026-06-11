//! Test fixture for the warm-process worker pool.
//!
//! Reads framed [`WorkerCallRequest`]s from stdin and writes
//! [`WorkerCallResponse`]s to stdout in a loop. Honours an env var
//! `MVM_FAKE_RUNNER_BEHAVIOR` so tests can drive the worker through
//! every recycling and crash path:
//!
//! - `ok` (default): echo stdin → stdout, exit 0 on every call.
//! - `user_fault`: echo stdin → stdout, exit-code 1 on every call.
//!   Simulates a wrapper that converts user exceptions to a
//!   sanitized envelope and returns non-zero — the pool must NOT
//!   recycle on this.
//! - `crash_after_n=N`: serve N calls normally, then `std::process::exit(1)`
//!   from outside any call (worker dies between calls).
//! - `crash_during_call_n=N`: on the Nth call, after reading the
//!   request, exit without writing a response. The agent should
//!   surface `wrapper_crash` for that call and recycle.
//! - `malformed_frame_on_n=N`: on the Nth call, write a length
//!   prefix that promises 1 GiB followed by no body (oversized).
//! - `leak_50mib_per_call`: allocate ~50 MiB per call and hold it,
//!   so RSS grows. Used by the `max_rss_mb` recycle test.
//! - `slow_secs=N`: sleep N seconds before responding (used by
//!   timeout / queue saturation tests).
//!
//! Lives under `tests/bin/` and is declared as `[[bin]] test = false`
//! so it never ships in the production guest closure. The
//! `prod-agent-no-exec` symbol gate operates on
//! `mvm-guest-agent` only and is unaffected.

use std::env;
use std::io::{self, Write};
use std::process::ExitCode;

use mvm_guest::worker_protocol::{
    WorkerCallRequest, WorkerCallResponse, WorkerControlRecord, WorkerOutcome, read_pipe_frame,
    write_pipe_frame,
};

#[derive(Debug, Clone)]
enum Behavior {
    Ok,
    UserFault,
    CrashAfter(u64),
    CrashDuringCallN(u64),
    MalformedFrameOnN(u64),
    Leak50MibPerCall,
    SlowSecs(u64),
    /// Emit one envelope-style control record per call alongside the
    /// response. Exercises the `controls` channel end-to-end through
    /// the warm-process pool.
    EmitControl,
}

impl Behavior {
    fn from_env() -> Self {
        let raw = env::var("MVM_FAKE_RUNNER_BEHAVIOR").unwrap_or_else(|_| "ok".into());
        let raw = raw.trim();
        if raw == "ok" {
            return Behavior::Ok;
        }
        if raw == "user_fault" {
            return Behavior::UserFault;
        }
        if raw == "leak_50mib_per_call" {
            return Behavior::Leak50MibPerCall;
        }
        if let Some(n) = raw.strip_prefix("crash_after_n=") {
            return Behavior::CrashAfter(n.parse().expect("crash_after_n value"));
        }
        if let Some(n) = raw.strip_prefix("crash_during_call_n=") {
            return Behavior::CrashDuringCallN(n.parse().expect("crash_during_call_n value"));
        }
        if let Some(n) = raw.strip_prefix("malformed_frame_on_n=") {
            return Behavior::MalformedFrameOnN(n.parse().expect("malformed_frame_on_n value"));
        }
        if let Some(n) = raw.strip_prefix("slow_secs=") {
            return Behavior::SlowSecs(n.parse().expect("slow_secs value"));
        }
        if raw == "emit_control" {
            return Behavior::EmitControl;
        }
        panic!("unknown MVM_FAKE_RUNNER_BEHAVIOR={raw}");
    }
}

fn main() -> ExitCode {
    let behavior = Behavior::from_env();
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    let mut call_no: u64 = 0;
    // Holds anything we want to keep allocated across calls.
    let mut leaked: Vec<Vec<u8>> = Vec::new();

    loop {
        // Block on the next request frame. EOF here means the pool is
        // shutting us down — exit cleanly.
        let req: WorkerCallRequest = match read_pipe_frame(&mut stdin) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return ExitCode::from(0),
            Err(e) => {
                eprintln!("fake_runner: read frame error: {e}");
                return ExitCode::from(2);
            }
        };
        call_no = call_no.saturating_add(1);

        match &behavior {
            Behavior::Ok | Behavior::UserFault => {
                let code = matches!(behavior, Behavior::UserFault) as i32;
                let resp = WorkerCallResponse {
                    stdout: req.stdin.clone(),
                    stderr: format!("fake_runner: call {call_no}\n").into_bytes(),
                    controls: Vec::new(),
                    outcome: WorkerOutcome::Exit { code },
                };
                if let Err(e) = write_pipe_frame(&mut stdout, &resp) {
                    eprintln!("fake_runner: write frame error: {e}");
                    return ExitCode::from(2);
                }
            }
            Behavior::CrashAfter(after) => {
                if call_no > *after {
                    // Should not happen — we exit at the moment we
                    // serve call N+1's request (below).
                    return ExitCode::from(1);
                }
                let resp = WorkerCallResponse {
                    stdout: req.stdin.clone(),
                    stderr: Vec::new(),
                    controls: Vec::new(),
                    outcome: WorkerOutcome::Exit { code: 0 },
                };
                if write_pipe_frame(&mut stdout, &resp).is_err() {
                    return ExitCode::from(2);
                }
                if call_no == *after {
                    // Drain stdout and exit before next call.
                    let _ = stdout.flush();
                    return ExitCode::from(0);
                }
            }
            Behavior::CrashDuringCallN(n) => {
                if call_no == *n {
                    // Don't write a response — exit. The agent's
                    // read_pipe_frame will see EOF.
                    drop(stdout);
                    return ExitCode::from(13);
                }
                let resp = WorkerCallResponse {
                    stdout: req.stdin.clone(),
                    stderr: Vec::new(),
                    controls: Vec::new(),
                    outcome: WorkerOutcome::Exit { code: 0 },
                };
                if write_pipe_frame(&mut stdout, &resp).is_err() {
                    return ExitCode::from(2);
                }
            }
            Behavior::MalformedFrameOnN(n) => {
                if call_no == *n {
                    // Write a length prefix promising 1 GiB but no
                    // body. The agent's read_pipe_frame should
                    // reject the oversized length.
                    let bogus_len: u32 = 1u32 << 30;
                    let _ = stdout.write_all(&bogus_len.to_be_bytes());
                    let _ = stdout.flush();
                    // Exit so the pipe closes; the agent surfaces
                    // wrapper_crash.
                    return ExitCode::from(0);
                }
                let resp = WorkerCallResponse {
                    stdout: req.stdin.clone(),
                    stderr: Vec::new(),
                    controls: Vec::new(),
                    outcome: WorkerOutcome::Exit { code: 0 },
                };
                if write_pipe_frame(&mut stdout, &resp).is_err() {
                    return ExitCode::from(2);
                }
            }
            Behavior::Leak50MibPerCall => {
                // Touch each page so the kernel actually backs them
                // and RSS grows.
                let mut chunk: Vec<u8> = vec![0; 50 * 1024 * 1024];
                for i in (0..chunk.len()).step_by(4096) {
                    chunk[i] = 1;
                }
                leaked.push(chunk);
                let resp = WorkerCallResponse {
                    stdout: req.stdin.clone(),
                    stderr: Vec::new(),
                    controls: Vec::new(),
                    outcome: WorkerOutcome::Exit { code: 0 },
                };
                if write_pipe_frame(&mut stdout, &resp).is_err() {
                    return ExitCode::from(2);
                }
            }
            Behavior::SlowSecs(secs) => {
                std::thread::sleep(std::time::Duration::from_secs(*secs));
                let resp = WorkerCallResponse {
                    stdout: req.stdin.clone(),
                    stderr: Vec::new(),
                    controls: Vec::new(),
                    outcome: WorkerOutcome::Exit { code: 0 },
                };
                if write_pipe_frame(&mut stdout, &resp).is_err() {
                    return ExitCode::from(2);
                }
            }
            Behavior::EmitControl => {
                let resp = WorkerCallResponse {
                    stdout: req.stdin.clone(),
                    // stderr stays as opaque user output — proves the
                    // host can't be tricked into reparsing stderr as
                    // an envelope (the spoof gadget this design
                    // eliminates).
                    stderr: b"MVMFORGE_ENVELOPE: this-must-not-be-parsed\n".to_vec(),
                    controls: vec![WorkerControlRecord {
                        header_json: format!(r#"{{"kind":"envelope","call":{call_no}}}"#),
                        payload: Vec::new(),
                    }],
                    outcome: WorkerOutcome::Exit { code: 0 },
                };
                if write_pipe_frame(&mut stdout, &resp).is_err() {
                    return ExitCode::from(2);
                }
            }
        }
    }
}
