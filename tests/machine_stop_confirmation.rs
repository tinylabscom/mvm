use assert_cmd::cargo::CommandCargoExt;
use std::process::{Command, Stdio};

/// Destructive machine stops fail closed when no TTY is available and
/// automation has not supplied explicit confirmation.
#[test]
fn machine_stop_without_tty_requires_yes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .expect("mvmctl binary")
        .env("HOME", tmp.path())
        .env("MVM_HOME", tmp.path())
        .stdin(Stdio::null())
        .args(["machine", "stop", "ghost"])
        .output()
        .expect("run mvmctl machine stop");

    assert!(!out.status.success(), "unconfirmed stop must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("pass --yes"),
        "failure must explain explicit confirmation: {stderr}"
    );
}

/// Stopping a machine that is not running succeeds every time it is repeated.
#[test]
fn repeated_machine_stop_of_a_stopped_machine_exits_zero() {
    let tmp = tempfile::tempdir().expect("tempdir");
    for attempt in 0..2 {
        let out = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
            .env("HOME", tmp.path())
            .env("MVM_HOME", tmp.path())
            .stdin(Stdio::null())
            .args(["machine", "stop", "ghost", "--yes"])
            .output()
            .expect("run mvmctl machine stop");
        assert!(
            out.status.success(),
            "stop attempt {attempt} must exit 0: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
