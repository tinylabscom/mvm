//! CLI surface tests for `mvmctl sign`.

use assert_cmd::cargo::CommandCargoExt;
use std::process::Command;

fn mvmctl(args: &[&str]) -> std::process::Output {
    #[allow(deprecated)]
    Command::cargo_bin("mvmctl")
        .expect("locate mvmctl")
        .args(args)
        .output()
        .expect("spawn mvmctl")
}

#[test]
fn sign_help_lists_json_flag() {
    let out = mvmctl(&["sign", "--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("--json"),
        "`mvmctl sign --help` missing --json; got:\n{stdout}"
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn sign_is_noop_off_macos() {
    let out = mvmctl(&["sign"]);
    assert!(
        out.status.success(),
        "sign should be a successful no-op off macOS"
    );
}
