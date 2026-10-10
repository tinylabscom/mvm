//! `mvmctl run ./app.mvmpkg -- <cmd>`: a signed artifact named before `--` is
//! the same run as `--manifest ./app.mvmpkg`. It is verified against the trust
//! store before anything else happens; `--dry-run` verifies, installs nothing,
//! and boots nothing.

use assert_cmd::cargo::CommandCargoExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SIDECAR: &[u8] = br#"{"name":"app","accessible":false}"#;

/// A signed bundle for this host's architecture, and the publisher key that
/// signed it.
fn signed_artifact(dir: &Path) -> (PathBuf, String, [u8; 32]) {
    use mvmctl::core::plan::bundle::{
        ArtifactRole, BUNDLE_SCHEMA_VERSION, BundleArtifact, BundleManifest, bundle_sha256,
        key_id_from_pubkey, sha256_hex, write_bundle,
    };

    let key = ed25519_dalek::SigningKey::from_bytes(&[73; 32]);
    let key_id = key_id_from_pubkey(&key.verifying_key());
    let files: [(&str, ArtifactRole, &[u8]); 3] = [
        ("vmlinux", ArtifactRole::Kernel, b"artifact kernel"),
        ("rootfs.ext4", ArtifactRole::Rootfs, b"artifact rootfs"),
        ("mvm-meta.json", ArtifactRole::Other, SIDECAR),
    ];
    let manifest = BundleManifest {
        schema_version: BUNDLE_SCHEMA_VERSION,
        publisher: "run-artifact-test".to_string(),
        key_id: key_id.clone(),
        arch: std::env::consts::ARCH.to_string(),
        kernel_version: None,
        profile: Some("minimal".to_string()),
        workload_label: Some("app".to_string()),
        created_at: "2026-10-04T00:00:00Z".to_string(),
        labels: Default::default(),
        artifacts: files
            .iter()
            .map(|(name, role, bytes)| BundleArtifact {
                name: name.to_string(),
                role: role.clone(),
                path: format!("artifacts/{name}"),
                sha256: sha256_hex(bytes),
                size_bytes: bytes.len() as u64,
            })
            .collect(),
        members: Vec::new(),
        verity: None,
        resources: None,
    };
    let payload = files
        .iter()
        .map(|(name, _, bytes)| (format!("artifacts/{name}"), bytes.to_vec()))
        .collect();
    let archive = write_bundle(&manifest, &key, payload).expect("write bundle");
    let sha = bundle_sha256(&archive);
    let path = dir.join("app.mvmpkg");
    std::fs::write(&path, archive).expect("write artifact");
    (path, sha, key.verifying_key().to_bytes())
}

fn trust(mvm_home: &Path, public_key: &[u8; 32]) {
    use mvmctl::core::plan::bundle::key_id_from_pubkey;
    let key = ed25519_dalek::VerifyingKey::from_bytes(public_key).expect("public key");
    let dir = mvm_home.join("trusted-publishers");
    std::fs::create_dir_all(&dir).expect("trust store");
    std::fs::write(
        dir.join(format!("{}.pub", key_id_from_pubkey(&key).0)),
        public_key,
    )
    .expect("enrol publisher");
}

fn run_dry(work: &Path, mvm_home: &Path, verb: &[&str]) -> Output {
    #[allow(deprecated)]
    Command::cargo_bin("mvmctl")
        .expect("mvmctl")
        .current_dir(work)
        .env("HOME", mvm_home)
        .env("MVM_HOME", mvm_home)
        .args(verb)
        .args(["--dry-run", "./app.mvmpkg", "--", "echo", "hi"])
        .output()
        .expect("spawn mvmctl")
}

fn installed(mvm_home: &Path, sha: &str) -> bool {
    mvm_home
        .join("bundles")
        .join(sha)
        .join("manifest.json")
        .is_file()
}

#[test]
fn a_trusted_artifact_is_verified_and_planned_without_installing_or_booting() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (work, mvm_home) = (tmp.path().join("work"), tmp.path().join("home"));
    std::fs::create_dir_all(&work).unwrap();
    let (_, sha, public_key) = signed_artifact(&work);
    trust(&mvm_home, &public_key);

    for verb in [&["run"][..], &["machine", "run"][..]] {
        let output = run_dry(&work, &mvm_home, verb);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{verb:?} dry run failed:\n{stderr}"
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("no VM will be booted"),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            stderr.contains(&format!("as bundle {sha}")),
            "{verb:?} verified the artifact as its bundle: {stderr}"
        );
        assert!(!installed(&mvm_home, &sha), "a dry run installs nothing");
    }
}

#[test]
fn an_untrusted_artifact_is_refused_before_it_is_installed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (work, mvm_home) = (tmp.path().join("work"), tmp.path().join("home"));
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(&mvm_home).unwrap();
    let (_, sha, _) = signed_artifact(&work);

    let output = run_dry(&work, &mvm_home, &["run"]);

    assert!(!output.status.success(), "an untrusted bundle must not run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("app.mvmpkg"), "{stderr}");
    assert!(stderr.contains("trust store"), "{stderr}");
    assert!(!installed(&mvm_home, &sha), "nothing was installed");
}

#[test]
fn a_command_without_the_separator_is_a_parse_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    #[allow(deprecated)]
    let output = Command::cargo_bin("mvmctl")
        .expect("mvmctl")
        .env("HOME", tmp.path())
        .env("MVM_HOME", tmp.path())
        .args(["run", "--image", "alpine", "echo", "hi"])
        .output()
        .expect("spawn mvmctl");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("-- <ARGV>"), "{stderr}");
    assert!(stderr.contains("goes after `--`"), "{stderr}");
}
