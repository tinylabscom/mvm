//! Step definitions for booting a signed `.mvmpkg` named on `machine run`.
//!
//! Hermetic: each scenario seals a small bundle with a fixed test key in a
//! scratch directory, enrols (or misfiles, or omits) that key in an isolated
//! `MVM_HOME`, and runs the real `mvmctl` against it with `--dry-run`. The
//! verifier runs exactly as it does before a boot, and a dry run stops before
//! any backend is chosen, so no hypervisor is needed. Booting the same file is
//! the live `@bundle_boot_live` witness.

use std::path::Path;

use cucumber::{given, then, when};
use ed25519_dalek::SigningKey;
use mvm_core::plan::bundle::{
    ArtifactRole, BUNDLE_SCHEMA_VERSION, BundleArtifact, BundleManifest, key_id_from_pubkey,
    sha256_hex, write_bundle,
};

use crate::world::CliWorld;

/// The publisher every scenario seals with.
const PUBLISHER_KEY: [u8; 32] = [73; 32];

/// A key that is not the publisher's.
const OTHER_KEY: [u8; 32] = [91; 32];

const ROOTFS: &[u8] = b"signed-artifact-conformance-rootfs";

fn publisher() -> SigningKey {
    SigningKey::from_bytes(&PUBLISHER_KEY)
}

fn scratch(world: &CliWorld) -> &Path {
    world
        .scratch_dir
        .as_ref()
        .expect("`Given a scratch working directory` must run before this step")
        .path()
}

fn home(world: &CliWorld) -> &Path {
    world
        .isolated_home
        .as_ref()
        .expect("`Given an isolated mvm home` must run before this step")
        .path()
}

/// A signed kernel + rootfs bundle for this host's architecture.
fn sealed_bundle() -> Vec<u8> {
    let key = publisher();
    let kernel = b"signed-artifact-conformance-kernel".to_vec();
    let artifact = |name: &str, role, bytes: &[u8]| BundleArtifact {
        name: name.to_string(),
        role,
        path: format!("artifacts/{name}"),
        sha256: sha256_hex(bytes),
        size_bytes: bytes.len() as u64,
    };
    let manifest = BundleManifest {
        schema_version: BUNDLE_SCHEMA_VERSION,
        publisher: "conformance".to_string(),
        key_id: key_id_from_pubkey(&key.verifying_key()),
        arch: std::env::consts::ARCH.to_string(),
        kernel_version: None,
        profile: None,
        workload_label: Some("app".to_string()),
        created_at: "2026-10-10T00:00:00Z".to_string(),
        labels: Default::default(),
        artifacts: vec![
            artifact("vmlinux", ArtifactRole::Kernel, &kernel),
            artifact("rootfs.ext4", ArtifactRole::Rootfs, ROOTFS),
        ],
        members: Vec::new(),
        verity: None,
        resources: None,
    };
    write_bundle(
        &manifest,
        &key,
        vec![
            ("artifacts/vmlinux".to_string(), kernel),
            ("artifacts/rootfs.ext4".to_string(), ROOTFS.to_vec()),
        ],
    )
    .expect("seal the conformance bundle")
}

/// Put `public_key` in the isolated home's trust store under `key_id_of`'s id.
fn enrol(world: &CliWorld, key_id_of: &SigningKey, public_key: [u8; 32]) {
    let dir = home(world).join("trusted-publishers");
    std::fs::create_dir_all(&dir).expect("create the trust store");
    let key_id = key_id_from_pubkey(&key_id_of.verifying_key());
    std::fs::write(dir.join(format!("{}.pub", key_id.0)), public_key).expect("enrol a key");
}

#[given(expr = "a signed artifact {string} in the scratch directory")]
fn signed_artifact(world: &mut CliWorld, name: String) {
    std::fs::write(scratch(world).join(name), sealed_bundle()).expect("write the artifact");
}

#[given(expr = "the artifact {string} has its rootfs altered after signing")]
fn tamper_artifact(world: &mut CliWorld, name: String) {
    let path = scratch(world).join(name);
    let mut bytes = std::fs::read(&path).expect("read the artifact");
    let at = bytes
        .windows(ROOTFS.len())
        .position(|window| window == ROOTFS)
        .expect("the rootfs payload is stored uncompressed");
    bytes[at] ^= 0xff;
    std::fs::write(&path, bytes).expect("rewrite the artifact");
}

#[given(expr = "an unsigned file {string} in the scratch directory")]
fn unsigned_artifact(world: &mut CliWorld, name: String) {
    std::fs::write(scratch(world).join(name), b"not a signed bundle").expect("write the file");
}

#[given("the isolated mvm home trusts the artifact's publisher")]
fn trust_publisher(world: &mut CliWorld) {
    enrol(world, &publisher(), publisher().verifying_key().to_bytes());
}

#[given("the isolated mvm home holds another key under the publisher's key id")]
fn misfile_publisher_key(world: &mut CliWorld) {
    let other = SigningKey::from_bytes(&OTHER_KEY)
        .verifying_key()
        .to_bytes();
    enrol(world, &publisher(), other);
}

/// Where the live scenario's sealed artifact is written.
const LIVE_ARTIFACT: &str = "witness.mvmpkg";

/// Seal an OCI image into a signed artifact in the live home, then trust the
/// home's own signer, through the same verbs an operator runs. The artifact is
/// sealed for this host's architecture, so the boot that follows exercises
/// whichever backend this host auto-selects.
#[when(expr = "I seal {string} into a signed artifact in the live home")]
fn seal_live_artifact(world: &mut CliWorld, image: String) {
    let out = scratch(world).join(LIVE_ARTIFACT);
    super::cli::run_mvmctl_isolated_live_home_argv(
        world,
        vec![
            "bundle".into(),
            "build".into(),
            "--image".into(),
            image.clone(),
            "--out".into(),
            out.display().to_string(),
        ],
    );
    require_success(world, &format!("seal {image} into {}", out.display()));
    let signer = world
        .last_live_home
        .as_deref()
        .map(|home| mvm_core::config::mvm_keys_dir_at(home).join("host-signer.pub"))
        .expect("the seal ran in a live home");
    super::cli::run_mvmctl_isolated_live_home_argv(
        world,
        vec!["trust".into(), "add".into(), signer.display().to_string()],
    );
    require_success(world, "trust the live home's bundle signer");
}

/// Boot the sealed artifact as the positional source: the verify, install and
/// admitted-boot path a user's `mvmctl run ./app.mvmpkg` takes.
#[when(expr = "I boot the signed artifact in the live home with {string}")]
fn boot_live_artifact(world: &mut CliWorld, rest: String) {
    let mut argv = vec![
        "machine".to_string(),
        "run".to_string(),
        scratch(world).join(LIVE_ARTIFACT).display().to_string(),
    ];
    argv.extend(mvm_conformance::doc_examples::tokenize(&rest));
    super::cli::run_mvmctl_isolated_live_home_argv(world, argv);
}

fn require_success(world: &CliWorld, what: &str) {
    let output = world.last_output();
    assert!(
        output.status.success(),
        "{what}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[then("the isolated mvm home has no installed bundle")]
fn no_installed_bundle(world: &mut CliWorld) {
    let _ = world.last_output();
    let installed: Vec<_> = std::fs::read_dir(home(world).join("bundles"))
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| entry.path().join("manifest.json").is_file())
                .map(|entry| entry.file_name())
                .collect()
        })
        .unwrap_or_default();
    assert!(
        installed.is_empty(),
        "a refused or dry-run artifact must install nothing; found {installed:?}"
    );
}
