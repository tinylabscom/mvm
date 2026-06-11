//! CLI surface tests for session resume/ephemeral flags.

use assert_cmd::cargo::CommandCargoExt;
use std::process::Command;

fn mvmctl(args: &[&str]) -> std::process::Output {
    #[allow(deprecated)]
    Command::cargo_bin("mvmctl")
        .expect("locate mvmctl")
        .args(args)
        .output()
        .expect("spawn")
}

#[test]
fn session_attach_help_lists_continue_and_resume() {
    let out = mvmctl(&["vm", "session", "attach", "--help"]);
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(s.contains("--continue"), "missing --continue:\n{s}");
    assert!(s.contains("--resume"), "missing --resume:\n{s}");
}

#[test]
fn session_start_help_lists_ephemeral() {
    let out = mvmctl(&["vm", "session", "start", "--help"]);
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(s.contains("--ephemeral"), "missing --ephemeral:\n{s}");
}
