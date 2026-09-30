//! `mvmctl machine check-artifact` round-trip: pack a dev `.mvm` for this
//! host's arch, then verify + preview its admission. Read-only — no boot.

use assert_cmd::cargo::CommandCargoExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn signed_bundle_fixture(root: &Path) -> (PathBuf, PathBuf) {
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
        members: Vec::new(),
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
fn check_artifact_reports_verified_runnable_and_admission_preview() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let work = tmp.path();
    let data = work.join("data");
    let kernel = work.join("vmlinux");
    let rootfs = work.join("rootfs.ext4");
    let cmdline = work.join("cmdline.txt");
    std::fs::write(&kernel, b"kernel bytes").unwrap();
    std::fs::write(&rootfs, b"rootfs bytes").unwrap();
    std::fs::write(&cmdline, b"console=hvc0").unwrap();
    let artifact = work.join("out.mvm");

    // Pack for THIS host's arch so the arch-gate reports runnable everywhere
    // (CI is x86_64, dev boxes aarch64). `std::env::consts::ARCH` matches
    // mvm's GuestArch strings ("aarch64" / "x86_64").
    let host_arch = std::env::consts::ARCH;

    #[allow(deprecated)]
    let pack = Command::cargo_bin("mvmctl")
        .unwrap()
        .env("HOME", &data)
        .env("MVM_HOME", &data)
        .args([
            "artifact",
            "pack",
            "--kernel",
            kernel.to_str().unwrap(),
            "--rootfs",
            rootfs.to_str().unwrap(),
            "--cmdline",
            cmdline.to_str().unwrap(),
            "--target-arch",
            host_arch,
            "--profile",
            "dev",
            "--allows-egress",
            "--allows-volumes",
            "--out",
            artifact.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        pack.status.success(),
        "pack failed: {}",
        String::from_utf8_lossy(&pack.stderr)
    );

    #[allow(deprecated)]
    let check = Command::cargo_bin("mvmctl")
        .unwrap()
        .env("HOME", &data)
        .env("MVM_HOME", &data)
        .args([
            "machine",
            "check-artifact",
            artifact.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "check-artifact failed: {}",
        String::from_utf8_lossy(&check.stderr)
    );

    let stdout = String::from_utf8_lossy(&check.stdout);
    assert!(
        stdout.contains("\"runnable_here\": true"),
        "expected runnable_here=true, got: {stdout}"
    );
    // The artifact declares egress + volumes; the preview reflects the
    // declared posture (proving it flows through admission_for).
    assert!(
        stdout.contains("\"egress\": \"allowed\""),
        "expected egress=allowed for an egress-declaring artifact, got: {stdout}"
    );
    assert!(
        stdout.contains("\"volumes\": true"),
        "expected volumes=true for a volume-declaring artifact, got: {stdout}"
    );
    assert!(
        stdout.contains(&format!("\"target_arch\": \"{host_arch}\"")),
        "expected target_arch={host_arch}, got: {stdout}"
    );
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
}
