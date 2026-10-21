#![cfg(unix)]

#[path = "support/pty_capture.rs"]
mod pty_capture;

use std::process::Command;
use std::time::{Duration, Instant};

fn shell(script: &str) -> Command {
    let mut command = Command::new("sh");
    command.args(["-c", script]);
    command
}

#[test]
fn child_retains_terminal_stdio_with_atomic_allocation() {
    let output = pty_capture::output(
        shell("test -t 0 && test -t 1 && test -t 2 && printf terminal-ok"),
        Duration::from_secs(3),
    )
    .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"terminal-ok");
}

#[test]
fn direct_child_exit_preserves_output_with_a_descendant_holding_the_slave() {
    // The descendant holds all three terminal descriptors until this test
    // explicitly kills it; waiting for terminal EOF would time out.
    let start = Instant::now();
    let output = pty_capture::output(
        shell("sleep 30 & echo helper=$!; printf 'console-ok\\n'; exit 7"),
        Duration::from_secs(3),
    )
    .expect("direct child must finish without waiting for its helper");
    let text = String::from_utf8_lossy(&output.stdout);
    let pid = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("helper="))
        .expect("helper PID")
        .parse::<i32>()
        .unwrap();
    // SAFETY: this is the process the fixture just started, still sleeping.
    unsafe { nix::libc::kill(pid, nix::libc::SIGKILL) };
    assert!(start.elapsed() < Duration::from_secs(2), "{text}");
    assert_eq!(output.status.code(), Some(7));
    assert!(text.contains("console-ok"), "{text}");
}

#[test]
fn output_larger_than_one_drain_pass_is_preserved_after_exit() {
    let output = pty_capture::output(
        shell("awk 'BEGIN { for (i=0; i<100000; i++) printf \"console-line\" }'"),
        Duration::from_secs(30),
    )
    .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout)
            .matches("console-line")
            .count(),
        100000
    );
}

#[test]
fn timeout_is_an_error_with_partial_output_and_reaps_the_child() {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("pid");
    let mut command = shell("echo $$ > \"$1\"; printf timeout-marker; exec sleep 30");
    command.args(["fixture", pid_file.to_str().unwrap()]);
    let error = pty_capture::output(command, Duration::from_millis(200)).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(error.to_string().contains("timeout-marker"), "{error}");
    let pid = std::fs::read_to_string(pid_file)
        .unwrap()
        .trim()
        .parse::<i32>()
        .unwrap();
    // SAFETY: signal zero only checks whether the reaped fixture is alive.
    assert_eq!(unsafe { nix::libc::kill(pid, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(nix::libc::ESRCH)
    );
}

#[test]
fn read_error_preserves_output_and_kills_and_reaps_the_child() {
    use std::io::Read;
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("pid");
    let mut command = shell("echo $$ > \"$1\"; printf read-marker; exec sleep 30");
    command.args(["fixture", pid_file.to_str().unwrap()]);
    let mut seen = false;
    let error =
        pty_capture::capture_using_reader(command, Duration::from_secs(3), move |mut fd, buf| {
            if seen {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "injected read failure",
                ));
            }
            let n = fd.read(buf)?;
            seen = n > 0;
            Ok(n)
        })
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("read-marker"), "{error}");
    let pid = std::fs::read_to_string(pid_file)
        .unwrap()
        .trim()
        .parse::<i32>()
        .unwrap();
    // SAFETY: signal zero only checks whether this fixture child is alive.
    assert_eq!(unsafe { nix::libc::kill(pid, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(nix::libc::ESRCH)
    );
}

#[test]
fn continuously_readable_descendant_cannot_extend_capture_past_deadline() {
    use std::io::Read;
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("helper");
    let mut command = shell("yes descendant & echo $! > \"$1\"; printf writer-marker; exit 0");
    command.args(["fixture", pid_file.to_str().unwrap()]);
    let mut seen = false;
    let result = pty_capture::capture_using_reader(
        command,
        Duration::from_millis(200),
        move |mut fd, buf| {
            // Once the real writer produces data, make readiness deterministic:
            // no scheduler-dependent gap may turn the continuous stream into EOF.
            if seen {
                buf[0] = b'x';
                return Ok(1);
            }
            let n = fd.read(buf)?;
            seen = n > 0;
            Ok(n)
        },
    );
    let pid = std::fs::read_to_string(pid_file)
        .unwrap()
        .trim()
        .parse::<i32>()
        .unwrap();
    // SAFETY: this is the descendant started by this fixture.
    unsafe { nix::libc::kill(pid, nix::libc::SIGKILL) };
    let error = result.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(
        error.to_string().contains("captured terminal output"),
        "{error}"
    );
}
