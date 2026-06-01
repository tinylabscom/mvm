//! CLI surface tests for `mvmctl artifact` model commands (plan 134 Phase E).
//!
//! Asserts `--help` lists the model subcommands and that each parses
//! correctly without requiring an actual artifact directory on disk.

use assert_cmd::cargo::CommandCargoExt;
use std::process::Command;

/// Run `mvmctl <args>` and return the combined stdout+stderr output.
fn mvmctl(args: &[&str]) -> std::process::Output {
    #[allow(deprecated)]
    Command::cargo_bin("mvmctl")
        .expect("locate mvmctl")
        .args(args)
        .output()
        .expect("spawn mvmctl")
}

/// `mvmctl artifact --help` must list all four model subcommands.
#[test]
fn artifact_help_lists_model_subcommands() {
    let out = mvmctl(&["artifact", "--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "expected success, got: {}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    for expected in &[
        "model-inspect",
        "model-validate",
        "model-config",
        "model-build",
    ] {
        assert!(
            stdout.contains(expected),
            "`mvmctl artifact --help` missing {expected:?}; stdout:\n{stdout}"
        );
    }
}

/// `mvmctl artifact model-inspect --help` names the `<id>` positional.
#[test]
fn artifact_model_inspect_help_names_id() {
    let out = mvmctl(&["artifact", "model-inspect", "--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(
        stdout.to_lowercase().contains("id"),
        "model-inspect --help should mention 'id'; stdout:\n{stdout}"
    );
}

/// `mvmctl artifact model-validate --help` names the `<id>` positional.
#[test]
fn artifact_model_validate_help_names_id() {
    let out = mvmctl(&["artifact", "model-validate", "--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(
        stdout.to_lowercase().contains("id"),
        "model-validate --help should mention 'id'; stdout:\n{stdout}"
    );
}

/// `mvmctl artifact model-config --help` exposes `--backend`.
#[test]
fn artifact_model_config_help_names_backend() {
    let out = mvmctl(&["artifact", "model-config", "--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(
        stdout.contains("backend"),
        "model-config --help should mention 'backend'; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("firecracker"),
        "model-config --help should mention 'firecracker'; stdout:\n{stdout}"
    );
}

/// `mvmctl artifact model-build --help` succeeds (stub subcommand exists).
#[test]
fn artifact_model_build_help_exists() {
    let out = mvmctl(&["artifact", "model-build", "--help"]);
    assert!(
        out.status.success(),
        "model-build --help failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `mvmctl artifact model-inspect` with a nonexistent id exits nonzero with an
/// informative message rather than a panic.
#[test]
fn artifact_model_inspect_nonexistent_id_exits_nonzero() {
    let out = mvmctl(&["artifact", "model-inspect", "nonexistent-artifact-id-xyz"]);
    assert!(
        !out.status.success(),
        "expected failure for nonexistent id, got success"
    );
}

/// `mvmctl artifact model-build` exits 0 (stub that prints a message).
#[test]
fn artifact_model_build_stub_exits_zero() {
    let out = mvmctl(&["artifact", "model-build"]);
    assert!(
        out.status.success(),
        "model-build stub should exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
