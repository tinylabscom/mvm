//! `mvmctl` CLI flag contract tests — fast, no VM boot required.

use assert_cmd::cargo::CommandCargoExt;
use std::process::Command;

/// Regression guard: `--stdin` was removed from `machine run`; piped stdin is
/// auto-detected from the host TTY state at dispatch instead.
/// This test locks the public contract: the flag must not reappear in help.
#[test]
fn machine_run_help_has_no_stdin_flag() {
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args(["machine", "run", "--help"])
        .output()
        .unwrap();
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "machine run --help must exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !help.contains("--stdin"),
        "help still advertises --stdin:\n{help}"
    );
    assert!(
        help.contains("--entrypoint"),
        "help is missing --entrypoint (truncated or empty render):\n{help}"
    );
}

#[test]
fn machine_reconfigure_help_lists_patch_flags() {
    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .unwrap()
        .args(["machine", "reconfigure", "--help"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "machine reconfigure --help must exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    for flag in [
        "--net",
        "--no-net",
        "--allow-host",
        "--cpus",
        "--memory",
        "--mem-initial",
    ] {
        assert!(text.contains(flag), "help missing {flag}");
    }
}
