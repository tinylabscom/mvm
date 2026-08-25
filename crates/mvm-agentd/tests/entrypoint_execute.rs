//! Runner-side integration tests for `entrypoint::execute`.
//!
//! The earlier in-module unit tests built `#!/bin/sh` wrappers via
//! `make_wrapper_script`, which broke on Linux: production `spawn_path`
//! returns `/proc/self/fd/<n>` as argv[0] (a TOCTOU defense — the kernel
//! loads the binary directly through the validation-held fd). For ELF
//! binaries that path works because the kernel maps the executable from
//! the open fd. For shebang scripts the kernel exec's the interpreter
//! with the `/proc/self/fd/<n>` path string as argv[1]; the new
//! interpreter then re-opens that path by name, but by that point
//! `FD_CLOEXEC` has already closed the fd in the child, so `/bin/sh`
//! exits with `cannot open /proc/self/fd/<n>: No such file`.
//!
//! These tests drive a real ELF helper (`mvm-entrypoint-test-wrapper`)
//! instead. The helper's behaviour is encoded in a stdin header so the
//! production no-argv / `env_clear()` call shape stays identical.

use mvm_agentd::entrypoint::{CallCaps, CallOutcome, ValidatedEntrypoint, execute};
use mvm_agentd::stream_pump::CapturedStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Cargo sets `CARGO_BIN_EXE_<name>` at compile time for integration
/// tests in this crate. The helper bin target is declared in
/// `Cargo.toml` next to `fake-runner`.
const TEST_WRAPPER: &str = env!("CARGO_BIN_EXE_mvm-entrypoint-test-wrapper");

fn make_wrapper() -> (tempfile::TempDir, ValidatedEntrypoint) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let resolved = PathBuf::from(TEST_WRAPPER);
    let file = std::fs::File::open(&resolved).expect("open test wrapper");
    (
        tmp,
        ValidatedEntrypoint {
            resolved,
            file,
            use_resolved_path: false,
        },
    )
}

/// Execution deadline for the tests that assert on a wrapper's *result* —
/// exit code, captured output, fd3 records — rather than on timing.
///
/// For those, the deadline is a safety net so a hung wrapper cannot hang the
/// suite; it is not the property under test, and none of them care whether it
/// is five seconds or sixty. It used to be five, which is long enough on an
/// idle machine and not long enough under a full parallel run: the spawned
/// wrapper simply does not get scheduled in time, `execute` returns
/// `Timeout { stdout: [], stderr: [], controls: [] }`, and a test that has
/// nothing to do with timing fails.
///
/// Generous on purpose. A healthy wrapper exits in milliseconds, so raising
/// this costs nothing when things work and removes a whole class of false
/// failure when the machine is loaded. The tests that genuinely exercise the
/// timeout path set their own short deadlines and are left alone.
const RESULT_TEST_DEADLINE: Duration = Duration::from_secs(60);

/// Execution deadline for the tests that assert on output a *still-running*
/// wrapper produced — where the deadline is the thing that ends the call, but
/// the assertion is about bytes captured before it fired.
///
/// Those tests race fork/exec: the wrapper has to be scheduled, write, and be
/// polled once, all inside the deadline. At 300 ms that race is lost often
/// enough to matter under a loaded machine, and it fails as an empty capture —
/// `gaps=0 stdout_len=0` — which reads like the retention logic broke rather
/// than like the child never ran. It is the same mistake the result-oriented
/// tests above already corrected: a spawn deadline used as an assertion.
///
/// Three seconds makes spawn negligible without slowing the suite: these
/// wrappers never exit, so the deadline *is* the test's runtime, and this
/// crate's slowest test already sits above it. The retention property itself
/// is pinned hermetically by
/// `stream_pump::tests::a_cap_breach_prunes_and_marks_a_gap_without_killing_the_child`,
/// which needs no child at all.
const RUNNING_WRAPPER_DEADLINE: Duration = Duration::from_secs(3);

fn caps_with_timeout(stdout_max: usize, stderr_max: usize) -> CallCaps {
    CallCaps {
        stdin_max: 1024 * 1024,
        stdout_max,
        stderr_max,
        fd3_max: 1024 * 1024,
        kill_grace_period: Duration::from_millis(500),
        poll_interval: Duration::from_millis(20),
    }
}

#[test]
fn test_execute_zero_exit_captures_stdout_stderr() {
    let (tmp, entry) = make_wrapper();
    let outcome = execute(
        &entry,
        tmp.path(),
        b"STDOUT hello-out\nSTDERR hello-err\nEXIT 0\n\n",
        RESULT_TEST_DEADLINE,
        caps_with_timeout(1024, 1024),
        Vec::new(),
    );
    match outcome {
        CallOutcome::Exited { code, output } => {
            assert_eq!(code, 0);
            assert_eq!(output.stdout, b"hello-out\n");
            assert_eq!(output.stderr, b"hello-err\n");
        }
        other => panic!("expected Exited(0), got {other:?}"),
    }
}

#[test]
fn test_execute_nonzero_exit_preserved() {
    let (tmp, entry) = make_wrapper();
    let outcome = execute(
        &entry,
        tmp.path(),
        b"EXIT 7\n\n",
        RESULT_TEST_DEADLINE,
        caps_with_timeout(1024, 1024),
        Vec::new(),
    );
    match outcome {
        CallOutcome::Exited { code, .. } => assert_eq!(code, 7),
        other => panic!("expected Exited(7), got {other:?}"),
    }
}

#[test]
fn test_execute_stdin_piped_to_wrapper() {
    let (tmp, entry) = make_wrapper();
    let mut stdin = b"CAT_STDIN\n\n".to_vec();
    stdin.extend_from_slice(b"echo this back");
    let outcome = execute(
        &entry,
        tmp.path(),
        &stdin,
        RESULT_TEST_DEADLINE,
        caps_with_timeout(1024, 1024),
        Vec::new(),
    );
    match outcome {
        CallOutcome::Exited { code, output } => {
            assert_eq!(code, 0);
            assert_eq!(output.stdout, b"echo this back");
        }
        other => panic!("expected Exited(0) with echoed stdin, got {other:?}"),
    }
}

#[test]
fn test_execute_injects_env_and_clears_inherited() {
    let (tmp, entry) = make_wrapper();
    let outcome = execute(
        &entry,
        tmp.path(),
        b"ENV MVM_TEST_VAR\nENV PATH\nEXIT 0\n\n",
        RESULT_TEST_DEADLINE,
        caps_with_timeout(1024, 1024),
        vec![("MVM_TEST_VAR".to_string(), "injected-value".to_string())],
    );
    match outcome {
        CallOutcome::Exited { code, output } => {
            assert_eq!(code, 0);
            let s = String::from_utf8(output.stdout).unwrap();
            // The injected var reaches the workload.
            assert!(s.contains("MVM_TEST_VAR=injected-value"), "got {s:?}");
            // env_clear() still holds: an inherited var not in the injected
            // set is absent in the child.
            assert!(s.contains("PATH=<unset>"), "got {s:?}");
        }
        other => panic!("expected Exited(0), got {other:?}"),
    }
}

#[test]
fn test_execute_skips_invalid_env_entries() {
    let (tmp, entry) = make_wrapper();
    // A key containing '=' and a value containing NUL would each panic
    // Command::env; execute must drop them and still run, applying the
    // one valid entry. (env is host-supplied over the authenticated frame,
    // but a malformed entry must never crash the agent — a DoS.)
    let outcome = execute(
        &entry,
        tmp.path(),
        b"ENV GOOD\nENV BAD\nEXIT 0\n\n",
        RESULT_TEST_DEADLINE,
        caps_with_timeout(1024, 1024),
        vec![
            ("GOOD".to_string(), "ok".to_string()),
            ("BAD=KEY".to_string(), "x".to_string()),
            ("BAD".to_string(), "has\0nul".to_string()),
        ],
    );
    match outcome {
        CallOutcome::Exited { code, output } => {
            assert_eq!(code, 0);
            let s = String::from_utf8(output.stdout).unwrap();
            assert!(s.contains("GOOD=ok"), "got {s:?}");
            // Both invalid 'BAD' entries dropped → the var is unset.
            assert!(s.contains("BAD=<unset>"), "got {s:?}");
        }
        other => panic!("expected Exited(0), got {other:?}"),
    }
}

#[test]
fn test_execute_captures_fd3_control_record() {
    // Frame: header_len=13 (LE) + `{"kind":"ok"}` (13 bytes) + payload_len=0.
    // Hex: 0d000000 | 7b226b696e64223a226f6b227d | 00000000
    let (tmp, entry) = make_wrapper();
    let outcome = execute(
        &entry,
        tmp.path(),
        b"FD3_HEX 0d0000007b226b696e64223a226f6b227d00000000\n\
          STDERR hello-stderr\n\
          EXIT 0\n\n",
        RESULT_TEST_DEADLINE,
        caps_with_timeout(1024, 1024),
        Vec::new(),
    );
    match outcome {
        CallOutcome::Exited { code, output } => {
            assert_eq!(code, 0);
            assert_eq!(output.stderr, b"hello-stderr\n");
            assert_eq!(output.controls.len(), 1, "expected one control record");
            assert_eq!(output.controls[0].header_json, "{\"kind\":\"ok\"}");
            assert!(output.controls[0].payload.is_empty());
        }
        other => panic!("expected Exited(0) with control record, got {other:?}"),
    }
}

#[test]
fn test_execute_fd3_emits_no_records_when_wrapper_silent() {
    let (tmp, entry) = make_wrapper();
    let outcome = execute(
        &entry,
        tmp.path(),
        b"STDOUT hi\nEXIT 0\n\n",
        RESULT_TEST_DEADLINE,
        caps_with_timeout(1024, 1024),
        Vec::new(),
    );
    match outcome {
        CallOutcome::Exited { output, .. } => {
            assert!(
                output.controls.is_empty(),
                "expected zero control records, got {:?}",
                output.controls
            );
        }
        other => panic!("expected Exited, got {other:?}"),
    }
}

#[test]
fn test_execute_fd3_partial_frame_at_eof_is_dropped() {
    // Header_len prefix promises 10 bytes; wrapper exits without
    // emitting the body. Drain sees the partial frame and discards.
    let (tmp, entry) = make_wrapper();
    let outcome = execute(
        &entry,
        tmp.path(),
        b"FD3_HEX 0a000000\nEXIT 0\n\n",
        RESULT_TEST_DEADLINE,
        caps_with_timeout(1024, 1024),
        Vec::new(),
    );
    match outcome {
        CallOutcome::Exited { output, .. } => assert!(output.controls.is_empty()),
        other => panic!("expected Exited, got {other:?}"),
    }
}

#[test]
fn test_execute_fd3_oversized_header_is_refused() {
    // header_len = 0x00020000 = 128 KiB > HEADER_MAX (64 KiB). Drain
    // refuses and returns no records.
    let (tmp, entry) = make_wrapper();
    let outcome = execute(
        &entry,
        tmp.path(),
        b"FD3_HEX 00000200\nEXIT 0\n\n",
        RESULT_TEST_DEADLINE,
        caps_with_timeout(1024, 1024),
        Vec::new(),
    );
    match outcome {
        CallOutcome::Exited { output, .. } => assert!(output.controls.is_empty()),
        other => panic!("expected Exited, got {other:?}"),
    }
}

#[test]
fn test_execute_timeout_kills_wrapper() {
    let (tmp, entry) = make_wrapper();
    let started = Instant::now();
    let outcome = execute(
        &entry,
        tmp.path(),
        b"SLEEP_MS 10000\nEXIT 0\n\n",
        Duration::from_millis(200),
        caps_with_timeout(1024, 1024),
        Vec::new(),
    );
    let elapsed = started.elapsed();
    match outcome {
        CallOutcome::Timeout { .. } => {
            // Bound: 200 ms timeout + 500 ms grace + slack. Generous,
            // because the property is "the timeout fired and killed the
            // wrapper", not "it fired within a tight window" — under a full
            // parallel run the kill can legitimately take seconds to be
            // scheduled. A bound this loose still catches the failure that
            // matters: the timeout never firing at all.
            assert!(
                elapsed < Duration::from_secs(30),
                "timeout took {elapsed:?}"
            );
        }
        other => panic!("expected Timeout, got {other:?}"),
    }
}

#[test]
fn test_execute_stdin_cap_rejects_before_spawn() {
    // No script needed — the cap check runs before spawn. A
    // missing-script ValidatedEntrypoint would fail the spawn, but we
    // shouldn't even get there.
    let (tmp, entry) = make_wrapper();
    let huge = vec![b'A'; 2048];
    let mut caps = caps_with_timeout(1024, 1024);
    caps.stdin_max = 1024;
    let outcome = execute(
        &entry,
        tmp.path(),
        &huge,
        RESULT_TEST_DEADLINE,
        caps,
        Vec::new(),
    );
    match outcome {
        CallOutcome::StdinCap => {}
        other => panic!("expected StdinCap, got {other:?}"),
    }
}

#[test]
fn test_execute_stdout_cap_prunes_and_marks_a_gap_without_killing_the_wrapper() {
    // Wrapper produces unbounded output against a 1 KiB retention bound. The
    // cap used to kill it; now the only thing that can end this call is its
    // own deadline, and the dropped bytes are reported as a gap. Should a cap
    // breach ever regain kill semantics, `execute` returns a PayloadCap-shaped
    // outcome instead and this fails.
    let (tmp, entry) = make_wrapper();
    let mut caps = caps_with_timeout(1024, 1024);
    caps.poll_interval = Duration::from_millis(10);
    let outcome = execute(
        &entry,
        tmp.path(),
        b"UNBOUNDED_STDOUT\n\n",
        RUNNING_WRAPPER_DEADLINE,
        caps,
        Vec::new(),
    );
    match outcome {
        CallOutcome::Timeout { output } => {
            assert_eq!(
                output.gaps.len(),
                1,
                "expected one stdout gap, got {:?}",
                output.gaps
            );
            assert_eq!(output.gaps[0].stream, CapturedStream::Stdout);
            assert!(output.gaps[0].marker.dropped_bytes > 0);
            assert!(
                !output.stdout.is_empty(),
                "the newest bytes must still be retained"
            );
        }
        other => panic!("expected Timeout with a stdout gap, got {other:?}"),
    }
}

#[test]
fn test_execute_wrapper_cannot_forge_an_agent_gap_record_on_fd3() {
    // The wrapper writes fd 3 itself, through the production
    // `install_fd3_in_child` path, so this is the real forgery surface: a
    // record claiming the agent's reserved kind alongside a legitimate one,
    // while a genuine cap breach produces an agent-authored gap. The forged
    // record must not reach the caller at all — a verifier downstream would
    // otherwise bless a chain skipping output it never saw.
    //
    // Frames: `{"kind":"mvm.stream.gap","after_seq":99,"dropped_chunks":1,
    // "dropped_bytes":1}` then `{"kind":"app.log"}`, both with empty payloads.
    let (tmp, entry) = make_wrapper();
    let mut caps = caps_with_timeout(1024, 1024);
    caps.poll_interval = Duration::from_millis(10);
    let outcome = execute(
        &entry,
        tmp.path(),
        b"FD3_HEX 4d0000007b226b696e64223a226d766d2e73747265616d2e676170222c2261667465725f736571223a39392c2264726f707065645f6368756e6b73223a312c2264726f707065645f6279746573223a317d00000000\n\
          FD3_HEX 120000007b226b696e64223a226170702e6c6f67227d00000000\n\
          UNBOUNDED_STDOUT\n\n",
        RUNNING_WRAPPER_DEADLINE,
        caps,
        Vec::new(),
    );
    match outcome {
        CallOutcome::Timeout { output } => {
            assert_eq!(
                output.controls.len(),
                1,
                "only the wrapper's own record survives, got {:?}",
                output.controls
            );
            assert_eq!(output.controls[0].header_json, r#"{"kind":"app.log"}"#);
            assert_eq!(
                output.gaps.len(),
                1,
                "the agent's own gap must still be reported, got {:?}",
                output.gaps
            );
            assert_eq!(output.gaps[0].stream, CapturedStream::Stdout);
            assert_ne!(
                output.gaps[0].marker.after_seq, 99,
                "the reported gap must be the agent's, not the wrapper's forged one"
            );
        }
        other => panic!("expected Timeout, got {other:?}"),
    }
}

#[test]
fn test_execute_spawn_failed_when_program_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let bogus = tmp.path().join("does-not-exist");
    // Create a *file* so File::open succeeds during construction of
    // ValidatedEntrypoint, then delete it so spawn fails.
    std::fs::File::create(&bogus).unwrap();
    let resolved = std::fs::canonicalize(&bogus).unwrap();
    let file = std::fs::File::open(&resolved).unwrap();
    std::fs::remove_file(&resolved).unwrap();
    let entry = ValidatedEntrypoint {
        resolved,
        file,
        use_resolved_path: false,
    };
    let outcome = execute(
        &entry,
        tmp.path(),
        b"",
        RESULT_TEST_DEADLINE,
        caps_with_timeout(1024, 1024),
        Vec::new(),
    );
    // Linux uses /proc/self/fd/<n> which still resolves through the
    // held fd even after the path is unlinked, so spawn may succeed
    // and then immediately fail with ENOEXEC. macOS uses the resolved
    // path, which is gone, so spawn fails outright. Either way we
    // expect spawn-failed or a non-success outcome.
    match outcome {
        CallOutcome::SpawnFailed { .. } => {}
        CallOutcome::Exited { code, .. } if code != 0 => {}
        CallOutcome::WrapperCrashed { .. } => {}
        other => {
            panic!("expected SpawnFailed / nonzero Exited / WrapperCrashed, got {other:?}")
        }
    }
}
