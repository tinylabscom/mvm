//! `mvmctl machine check-artifact` round-trip: seal a signed `.mvmpkg` for
//! this host's arch, then verify it and preview its posture. Read-only — no
//! install, no boot.

use assert_cmd::cargo::CommandCargoExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use mvmctl::core::plan::bundle::BundleMember;

fn signed_bundle_fixture(root: &Path) -> (PathBuf, PathBuf) {
    signed_bundle_fixture_with(root, Vec::new())
}

fn signed_bundle_fixture_with(root: &Path, members: Vec<BundleMember>) -> (PathBuf, PathBuf) {
    use mvmctl::core::plan::bundle::{
        ArtifactRole, BUNDLE_SCHEMA_VERSION, BundleArtifact, BundleManifest, key_id_from_pubkey,
        sha256_hex, write_bundle,
    };

    let key = ed25519_dalek::SigningKey::from_bytes(&[91; 32]);
    let key_id = key_id_from_pubkey(&key.verifying_key());
    let kernel = b"portable bundle kernel".to_vec();
    let manifest = BundleManifest {
        schema_version: BUNDLE_SCHEMA_VERSION,
        publisher: "check-artifact-test".to_string(),
        key_id: key_id.clone(),
        arch: std::env::consts::ARCH.to_string(),
        kernel_version: None,
        profile: None,
        workload_label: Some("portable-test".to_string()),
        created_at: "2026-09-29T00:00:00Z".to_string(),
        labels: Default::default(),
        artifacts: vec![BundleArtifact {
            name: "vmlinux".to_string(),
            role: ArtifactRole::Kernel,
            path: "artifacts/vmlinux".to_string(),
            sha256: sha256_hex(&kernel),
            size_bytes: kernel.len() as u64,
        }],
        members,
        verity: None,
        resources: None,
    };
    let archive = write_bundle(
        &manifest,
        &key,
        vec![("artifacts/vmlinux".to_string(), kernel)],
    )
    .expect("write bundle");
    let archive_path = root.join("app.mvmpkg");
    std::fs::write(&archive_path, archive).expect("write bundle archive");
    let trust_dir = root.join("trusted");
    std::fs::create_dir_all(&trust_dir).expect("create trust directory");
    std::fs::write(
        trust_dir.join(format!("{}.pub", key_id.0)),
        key.verifying_key().to_bytes(),
    )
    .expect("enrol publisher key");
    (archive_path, trust_dir)
}

#[test]
fn check_artifact_verifies_a_signed_mvmpkg_without_booting() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data");
    let (artifact, trust_dir) = signed_bundle_fixture(tmp.path());

    #[allow(deprecated)]
    let check = Command::cargo_bin("mvmctl")
        .expect("mvmctl binary")
        .env("HOME", &data)
        .env("MVM_HOME", &data)
        .args(["machine", "check-artifact"])
        .arg(&artifact)
        .arg("--trust-store")
        .arg(&trust_dir)
        .arg("--json")
        .output()
        .expect("run check-artifact");
    assert!(
        check.status.success(),
        "check-artifact failed: {}",
        String::from_utf8_lossy(&check.stderr)
    );
    let verdict: serde_json::Value = serde_json::from_slice(&check.stdout).expect("JSON verdict");
    assert_eq!(verdict["verified"], true);
    assert_eq!(verdict["artifact_count"], 1);
    assert_eq!(verdict["embedded_image_sets"], serde_json::json!([]));
    assert_eq!(verdict.get("runnable_here"), Some(&serde_json::Value::Null));
    assert_eq!(verdict["host_arch_compatible"], true);
    assert_eq!(verdict["backend_compatibility_checked"], false);
    assert!(!data.join("cache").exists());
    assert!(!data.join("bundles").exists());
    assert!(!data.join("vms").exists());
}

fn check_artifact_json(home: &Path, artifact: &Path, trust_dir: &Path) -> std::process::Output {
    #[allow(deprecated)]
    Command::cargo_bin("mvmctl")
        .expect("mvmctl binary")
        .env("HOME", home)
        .env("MVM_HOME", home)
        .args(["machine", "check-artifact"])
        .arg(artifact)
        .arg("--trust-store")
        .arg(trust_dir)
        .arg("--json")
        .output()
        .expect("run check-artifact")
}

#[test]
fn check_artifact_previews_a_declared_posture() {
    use mvmctl::core::plan::bundle::BundleSecurityPosture;
    use mvmctl::core::security::AgentProfile;

    let tmp = tempfile::tempdir().expect("tempdir");
    let (artifact, trust_dir) = signed_bundle_fixture_with(
        tmp.path(),
        vec![
            BundleMember::KernelCmdline {
                cmdline: "console=ttyS0".to_string(),
            },
            BundleMember::SecurityPosture(BundleSecurityPosture {
                profile: AgentProfile::Dev,
                verity_protected: false,
                requires_auth: true,
                allows_volumes: false,
                allows_egress: false,
            }),
        ],
    );

    let check = check_artifact_json(&tmp.path().join("data"), &artifact, &trust_dir);
    assert!(
        check.status.success(),
        "check-artifact failed: {}",
        String::from_utf8_lossy(&check.stderr)
    );
    let verdict: serde_json::Value = serde_json::from_slice(&check.stdout).expect("JSON verdict");
    assert_eq!(verdict.get("runnable_here"), Some(&serde_json::Value::Null));
    assert_eq!(verdict["host_arch_compatible"], true);
    assert_eq!(verdict["backend_compatibility_checked"], false);
    assert_eq!(verdict["posture"]["profile"], "dev");
    assert_eq!(verdict["posture"]["egress"], "deny-all");
    assert_eq!(verdict["posture"]["volumes"], false);
    assert_eq!(verdict["kernel_cmdline"], "console=ttyS0");
}

#[test]
fn check_artifact_refuses_a_path_that_is_not_a_bundle() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let not_a_bundle = tmp.path().join("app.mvm");
    std::fs::write(&not_a_bundle, b"retired format").expect("write fixture");

    let check = check_artifact_json(&tmp.path().join("data"), &not_a_bundle, tmp.path());
    assert!(!check.status.success());
    assert!(
        String::from_utf8_lossy(&check.stderr).contains("not a .mvmpkg bundle"),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn check_artifact_does_not_infer_runtime_or_freshness_from_unverified_cache() {
    for cached in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("consumer");
        let (artifact, trust_dir) = signed_bundle_fixture(tmp.path());
        let overlay = home.join(format!(
            "cache/runtime-overlay/0.24.0/{}/overlay.ext4",
            mvmctl::core::arch::GuestArch::host()
        ));
        if cached {
            std::fs::create_dir_all(overlay.parent().unwrap()).unwrap();
            std::fs::write(&overlay, b"unverified runtime").unwrap();
        }
        #[allow(deprecated)]
        let check = Command::cargo_bin("mvmctl")
            .unwrap()
            .env("HOME", &home)
            .env("MVM_HOME", &home)
            .args(["machine", "check-artifact"])
            .arg(&artifact)
            .arg("--trust-store")
            .arg(&trust_dir)
            .args(["--backend", "hvf", "--json"])
            .output()
            .unwrap();
        assert!(
            check.status.success(),
            "{}",
            String::from_utf8_lossy(&check.stderr)
        );
        let verdict: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
        assert_eq!(verdict["verified"], true);
        assert_eq!(verdict.get("runnable_here"), Some(&serde_json::Value::Null));
        assert_eq!(verdict["backend_compatibility_checked"], false);
        assert!(!home.join("bundles").exists());
        assert!(!home.join("vms").exists());
        if cached {
            assert_eq!(std::fs::read(&overlay).unwrap(), b"unverified runtime");
        } else {
            assert!(!home.join("cache").exists());
        }
        #[allow(deprecated)]
        let human = Command::cargo_bin("mvmctl")
            .unwrap()
            .env("HOME", &home)
            .env("MVM_HOME", &home)
            .args(["machine", "check-artifact"])
            .arg(&artifact)
            .arg("--trust-store")
            .arg(&trust_dir)
            .output()
            .unwrap();
        assert!(human.status.success());
        // The requested report must not disappear as suppressed UI chatter.
        let text = String::from_utf8_lossy(&human.stdout);
        assert!(text.contains("launch readiness not checked"), "{text}");
        assert!(!text.contains("runnable on"), "{text}");
    }
}
