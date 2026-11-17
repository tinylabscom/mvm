//! Standalone helper builds must retain signed registry verification.

use std::process::Command;

#[test]
fn standalone_host_verifies_signed_registry_bytes_and_refuses_tampering() {
    use mvm_core::registry_pack::{PackAdoption, adopt_registry_pack, official_publisher_policy};
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../mvm-cli/tests/fixtures/signed-registry-go");
    let manifest = std::fs::read(fixture.join("manifest.json")).unwrap();
    let bundle = std::fs::read(fixture.join("manifest.sigstore.json")).unwrap();
    let requested = "runtime/go@1.0.0".parse().unwrap();
    let policy = official_publisher_policy();
    let request = PackAdoption {
        requested: &requested,
        manifest_bytes: &manifest,
        signature_bundle: &bundle,
        publisher_policy: &policy,
    };
    adopt_registry_pack(&request).expect("standalone host must verify a genuine signed descriptor");
    let mut tampered = manifest.clone();
    tampered.push(b' ');
    assert!(
        adopt_registry_pack(&PackAdoption {
            manifest_bytes: &tampered,
            ..request
        })
        .is_err(),
        "changed bytes must not verify under the original signature"
    );
}

fn package() -> serde_json::Value {
    let output = Command::new("cargo")
        .args([
            "metadata",
            "--offline",
            "--no-deps",
            "--format-version",
            "1",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo metadata runs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    metadata["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|package| package["name"] == "mvm-hostd")
        .unwrap()
        .clone()
}

#[test]
fn standalone_host_defaults_enable_manifest_verification() {
    let package = package();
    assert!(
        package["features"]["default"]
            .as_array()
            .unwrap()
            .iter()
            .any(|feature| feature == "manifest-verify")
    );
    assert!(
        package["features"]["manifest-verify"]
            .as_array()
            .unwrap()
            .iter()
            .any(|feature| feature == "mvm-core/manifest-verify")
    );
}

#[test]
fn hvf_helper_cannot_be_built_with_verification_disabled() {
    let package = package();
    let helper = package["targets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|target| target["name"] == "mvm-hvf-supervisor")
        .unwrap();
    assert!(
        helper["required-features"]
            .as_array()
            .is_some_and(|features| features.iter().any(|feature| feature == "manifest-verify"))
    );
}

#[test]
fn release_shaped_host_dependency_graph_includes_the_real_verifier() {
    let output = Command::new("cargo")
        .args([
            "tree",
            "--locked",
            "--offline",
            "-p",
            "mvm-hostd",
            "--target",
            "aarch64-apple-darwin",
            "-e",
            "normal,build",
            "--prefix",
            "none",
            "--format",
            "{p} features={f}",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree runs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .filter(|line| line.starts_with("mvm-core "))
            .filter_map(|line| line.split_once(" features=").map(|(_, features)| features))
            .any(|features| {
                features
                    .split_whitespace()
                    .next()
                    .is_some_and(|features| features.split(',').any(|f| f == "manifest-verify"))
            }),
        "the standalone release graph must not select the unconditional refusal stub"
    );
}
