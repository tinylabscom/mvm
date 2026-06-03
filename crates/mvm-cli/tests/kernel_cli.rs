//! CLI surface tests for `mvmctl kernel`.
//!
//! Asserts the verb is wired and `kernel build` parses its flags
//! without needing a builder VM or any on-disk state.

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

/// `mvmctl kernel --help` lists the `build` subcommand.
#[test]
fn kernel_help_lists_build() {
    let out = mvmctl(&["kernel", "--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "expected success, got: {}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("build"),
        "`mvmctl kernel --help` missing 'build'; stdout:\n{stdout}"
    );
}

/// `mvmctl kernel build --help` names its flags.
#[test]
fn kernel_build_help_names_flags() {
    let out = mvmctl(&["kernel", "build", "--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    for expected in &[
        "--which", "--all", "--source", "--arch", "compile", "download", "auto",
    ] {
        assert!(
            stdout.contains(expected),
            "`mvmctl kernel build --help` missing {expected:?}; stdout:\n{stdout}"
        );
    }
}

/// `--arch` accepts only the two supported arches.
#[test]
fn kernel_build_rejects_unknown_arch() {
    let out = mvmctl(&["kernel", "build", "--arch", "riscv64"]);
    assert!(
        !out.status.success(),
        "unknown --arch value should fail to parse"
    );
}

/// The global `--kernel-source` flag accepts only compile|download|auto.
#[test]
fn global_kernel_source_rejects_unknown() {
    let out = mvmctl(&["--kernel-source", "bogus", "dev", "up"]);
    assert!(
        !out.status.success(),
        "unknown --kernel-source value should fail to parse"
    );
}

/// `--which` accepts only the two kernels; a bogus value is rejected.
#[test]
fn kernel_build_rejects_unknown_which() {
    let out = mvmctl(&["kernel", "build", "--which", "bogus"]);
    assert!(
        !out.status.success(),
        "unknown --which value should fail to parse"
    );
}
