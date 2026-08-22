//! CLI integration tests for `mvmctl capture`.

use assert_cmd::cargo::CommandCargoExt;
use std::path::PathBuf;
use std::process::Command;

fn mvmctl() -> Command {
    #[allow(deprecated)]
    Command::cargo_bin("mvmctl").expect("mvmctl binary")
}

#[test]
fn capture_subcommand_appears_in_help() {
    let output = mvmctl().arg("--help").output().expect("run mvmctl --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("capture"),
        "top-level help should list capture subcommand: {stdout}"
    );
}

#[test]
fn capture_project_emits_report_and_resolve_emits_ir() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/capture/rust-hello")
        .canonicalize()
        .expect("fixture exists");
    let capture_json = tmp.path().join("capture.json");
    let env_json = tmp.path().join("environment.json");

    let output = mvmctl()
        .arg("capture")
        .arg("project")
        .arg(&fixture)
        .arg("--run")
        .arg("cargo run")
        .arg("--output")
        .arg(&capture_json)
        .output()
        .expect("run capture project");
    assert!(
        output.status.success(),
        "capture project failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(capture_json.exists(), "capture.json written");

    let capture_text = std::fs::read_to_string(&capture_json).expect("read capture.json");
    assert!(
        !capture_text.contains("super_secret_value_12345"),
        "secret not in capture report"
    );

    let output = mvmctl()
        .arg("capture")
        .arg("resolve")
        .arg(&capture_json)
        .arg("--output")
        .arg(&env_json)
        .output()
        .expect("run capture resolve");
    assert!(
        output.status.success(),
        "capture resolve failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(env_json.exists(), "environment.json written");

    let env_text = std::fs::read_to_string(&env_json).expect("read environment.json");
    assert!(
        env_text.contains("captured-project"),
        "canonical IR contains captured-project workload"
    );
}

#[test]
fn capture_verify_renders_artifacts_and_records_verification() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/capture/rust-hello")
        .canonicalize()
        .expect("fixture exists");
    let capture_json = tmp.path().join("capture.json");
    let env_json = tmp.path().join("environment.json");
    let out_dir = tmp.path().join("verify-out");

    assert!(
        mvmctl()
            .arg("capture")
            .arg("project")
            .arg(&fixture)
            .arg("--run")
            .arg("cargo run")
            .arg("--output")
            .arg(&capture_json)
            .output()
            .expect("run capture project")
            .status
            .success()
    );

    assert!(
        mvmctl()
            .arg("capture")
            .arg("resolve")
            .arg(&capture_json)
            .arg("--output")
            .arg(&env_json)
            .output()
            .expect("run capture resolve")
            .status
            .success()
    );

    let output = mvmctl()
        .arg("capture")
        .arg("verify")
        .arg(&env_json)
        .arg("--manifest-dir")
        .arg(&fixture)
        .arg("--run")
        .arg("cargo test")
        .arg("--out-dir")
        .arg(&out_dir)
        .output()
        .expect("run capture verify");
    assert!(
        output.status.success(),
        "capture verify failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(out_dir.join("flake.nix").exists(), "flake.nix rendered");
    assert!(out_dir.join("launch.json").exists(), "launch.json rendered");
    let verification_json = out_dir.join("verification.json");
    assert!(verification_json.exists(), "verification.json written");

    let verification_text =
        std::fs::read_to_string(&verification_json).expect("read verification.json");
    assert!(
        verification_text.contains("recorded"),
        "verification status is recorded by default"
    );
    assert!(
        verification_text.contains("\"cargo\"") && verification_text.contains("\"test\""),
        "verification command recorded"
    );
}
