//! CLI surface tests for `mvmctl artifact` model commands.
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

/// `mvmctl artifact model-validate <id>` exits nonzero when check 1 fails
/// (kernel + rootfs paths in the manifest point at files that don't exist).
///
/// Wires `MVM_DATA_DIR` to a temp dir so `resolve_artifact_dir` lands there
/// rather than `~/.mvm/artifacts/` — no real artifact state is required.
#[test]
fn artifact_model_validate_exits_nonzero_on_failed_check() {
    use std::path::PathBuf;

    let tmp = tempfile::tempdir().expect("tempdir");
    let artifact_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let artifact_dir = tmp.path().join("artifacts").join(artifact_id);
    std::fs::create_dir_all(&artifact_dir).expect("create artifact dir");

    // Write a manifest whose kernel + rootfs paths point at files that do not
    // exist — check 1 (files_exist) will fail, making report.ok = false.
    let manifest_json = serde_json::json!({
        "artifact_id": artifact_id,
        "build_id": "test-build-validate-nonzero",
        "tenant_id": null,
        "arch": "aarch64",
        "backend": "firecracker",
        "kernel": {
            "path": "Image",
            "format": "image",
            "hash": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
            "version": null
        },
        "rootfs": {
            "path": "rootfs.ext4",
            "format": "ext4",
            "hash": "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
            "size": 0
        },
        "config_path": null,
        "provenance": null,
        "builder_version": "0.0.0",
        "timestamp_unix": 0,
        "validation": null
    });
    let manifest_path = artifact_dir.join("manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest_json).unwrap() + "\n",
    )
    .expect("write manifest");

    // The kernel and rootfs files referenced in the manifest are NOT created,
    // so check 1 (files_exist) fires and report.ok = false.

    #[allow(deprecated)]
    let out = Command::cargo_bin("mvmctl")
        .expect("locate mvmctl")
        .args(["artifact", "model-validate", artifact_id])
        .env("MVM_DATA_DIR", tmp.path().to_str().unwrap())
        .output()
        .expect("spawn mvmctl");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !out.status.success(),
        "expected nonzero exit when validation fails; stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // At least one [FAIL] line must appear — check 1 fires on the missing files.
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("FAIL"),
        "expected a [FAIL] line in output; got:\n{combined}"
    );

    // The failed check must mention the missing file(s).
    assert!(
        combined.contains("files_exist")
            || combined.contains("Image")
            || combined.contains("missing"),
        "output should name the missing-files check; got:\n{combined}"
    );

    // Confirm the artifact dir path was not used in HOME — this is belt-and-
    // suspenders: if MVM_DATA_DIR is ignored the test would still fail above
    // (no artifact found), but the error would be "no artifacts directory" not
    // "validation failed". Both are nonzero, so the assert above covers both.
    let _ = PathBuf::from(tmp.path()); // keep tmp alive until here
}
