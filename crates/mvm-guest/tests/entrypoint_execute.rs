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

use mvm_guest::entrypoint::{
    CallCaps, CallOutcome, PayloadCapStream, ValidatedEntrypoint, execute,
};
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
    (tmp, ValidatedEntrypoint { resolved, file })
}

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
        Duration::from_secs(5),
        caps_with_timeout(1024, 1024),
        Vec::new(),
    );
    match outcome {
        CallOutcome::Exited {
            code,
            stdout,
            stderr,
            ..
        } => {
            assert_eq!(code, 0);
            assert_eq!(stdout, b"hello-out\n");
            assert_eq!(stderr, b"hello-err\n");
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
        Duration::from_secs(5),
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
        Duration::from_secs(5),
        caps_with_timeout(1024, 1024),
        Vec::new(),
    );
    match outcome {
        CallOutcome::Exited { code, stdout, .. } => {
            assert_eq!(code, 0);
            assert_eq!(stdout, b"echo this back");
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
        Duration::from_secs(5),
        caps_with_timeout(1024, 1024),
        vec![("MVM_TEST_VAR".to_string(), "injected-value".to_string())],
    );
    match outcome {
        CallOutcome::Exited { code, stdout, .. } => {
            assert_eq!(code, 0);
            let s = String::from_utf8(stdout).unwrap();
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
        Duration::from_secs(5),
        caps_with_timeout(1024, 1024),
        vec![
            ("GOOD".to_string(), "ok".to_string()),
            ("BAD=KEY".to_string(), "x".to_string()),
            ("BAD".to_string(), "has\0nul".to_string()),
        ],
    );
    match outcome {
        CallOutcome::Exited { code, stdout, .. } => {
            assert_eq!(code, 0);
            let s = String::from_utf8(stdout).unwrap();
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
        Duration::from_secs(5),
        caps_with_timeout(1024, 1024),
        Vec::new(),
    );
    match outcome {
        CallOutcome::Exited {
            code,
            stderr,
            controls,
            ..
        } => {
            assert_eq!(code, 0);
            assert_eq!(stderr, b"hello-stderr\n");
            assert_eq!(controls.len(), 1, "expected one control record");
            assert_eq!(controls[0].header_json, "{\"kind\":\"ok\"}");
            assert!(controls[0].payload.is_empty());
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
        Duration::from_secs(5),
        caps_with_timeout(1024, 1024),
        Vec::new(),
    );
    match outcome {
        CallOutcome::Exited { controls, .. } => {
            assert!(
                controls.is_empty(),
                "expected zero control records, got {controls:?}"
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
        Duration::from_secs(5),
        caps_with_timeout(1024, 1024),
        Vec::new(),
    );
    match outcome {
        CallOutcome::Exited { controls, .. } => assert!(controls.is_empty()),
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
        Duration::from_secs(5),
        caps_with_timeout(1024, 1024),
        Vec::new(),
    );
    match outcome {
        CallOutcome::Exited { controls, .. } => assert!(controls.is_empty()),
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
            // Bound: 200 ms timeout + 500 ms grace + slack. If it
            // takes longer than 5 s the test is broken, not slow.
            assert!(elapsed < Duration::from_secs(5), "timeout took {elapsed:?}");
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
        Duration::from_secs(5),
        caps,
        Vec::new(),
    );
    match outcome {
        CallOutcome::PayloadCap {
            stream: PayloadCapStream::Stdin,
            stdout,
            stderr,
            ..
        } => {
            assert!(stdout.is_empty());
            assert!(stderr.is_empty());
        }
        other => panic!("expected PayloadCap(Stdin), got {other:?}"),
    }
}

#[test]
fn test_execute_stdout_cap_kills_wrapper() {
    // Wrapper produces unbounded output; stdout_max is 1 KiB. Drain
    // thread sets the breach flag; poll loop kills the wrapper's
    // process group (the wrapper IS the producer, so SIGKILL on the
    // pgid terminates the writer directly).
    let (tmp, entry) = make_wrapper();
    let mut caps = caps_with_timeout(1024, 1024);
    caps.poll_interval = Duration::from_millis(10);
    let started = Instant::now();
    let outcome = execute(
        &entry,
        tmp.path(),
        b"UNBOUNDED_STDOUT\n\n",
        Duration::from_secs(10),
        caps,
        Vec::new(),
    );
    let elapsed = started.elapsed();
    match outcome {
        CallOutcome::PayloadCap {
            stream: PayloadCapStream::Stdout,
            stdout,
            ..
        } => {
            assert_eq!(stdout.len(), 1024, "stdout truncated to cap");
            assert!(elapsed < Duration::from_secs(2), "kill took {elapsed:?}");
        }
        other => panic!("expected PayloadCap(Stdout), got {other:?}"),
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
    let entry = ValidatedEntrypoint { resolved, file };
    let outcome = execute(
        &entry,
        tmp.path(),
        b"",
        Duration::from_secs(5),
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
