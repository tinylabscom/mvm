//! Public, nonbootable fixture for the existing keyless signing smoke.
//! Bundle-author trust is explicitly enrolled in a disposable consumer home.
//! The descriptor remains unauthenticated until the workflow signs its bytes.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use mvm_core::packs::Sha256Hex;
use mvm_core::plan::bundle::{
    ArtifactRole, BUNDLE_SCHEMA_VERSION, BundleArtifact, BundleManifest, BundleRegistry,
    FsTrustStore, key_id_from_pubkey, sha256_hex, write_bundle,
};
use mvm_core::registry_pack::application::{
    ApplicationManifestKind, RegistryApplication, RegistryApplicationBundle,
    RegistryApplicationManifest, parse_application_manifest,
};
use mvm_core::registry_pack::{RegistryPackPublisher, RegistryPackPublisherPolicy};
use mvm_core::registry_pack_store::save_publisher_policy;
use rand::Rng;
use serde_json::json;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 4 && args[0] == "--out-dir" && args[2] == "--identity",
        "usage: application-inspection-fixture --out-dir ABSOLUTE_PATH --identity WORKFLOW_IDENTITY"
    );
    let output = PathBuf::from(&args[1]);
    ensure!(output.is_absolute(), "fixture output must be absolute");
    let home = output.join("consumer-home");
    ensure!(
        std::env::var_os("MVM_HOME").as_deref() == Some(home.as_os_str()),
        "MVM_HOME must explicitly name the fresh fixture consumer-home"
    );
    fs::create_dir(&output).context("create fresh fixture output; refusing reuse")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700))?;
    }
    fs::create_dir(&home)?;
    let mut seed = [0; 32];
    rand::rng().fill_bytes(&mut seed);
    let key = SigningKey::from_bytes(&seed);
    let key_id = key_id_from_pubkey(&key.verifying_key());
    let payload = b"nonbootable application inspection fixture\n";
    let bundle = BundleManifest {
        schema_version: BUNDLE_SCHEMA_VERSION,
        publisher: "inspection-smoke".into(),
        key_id: key_id.clone(),
        arch: "aarch64".into(),
        kernel_version: None,
        profile: None,
        workload_label: None,
        created_at: "2026-01-01T00:00:00Z".into(),
        labels: Default::default(),
        artifacts: vec![BundleArtifact {
            name: "rootfs".into(),
            role: ArtifactRole::Rootfs,
            path: "artifacts/rootfs.ext4".into(),
            sha256: sha256_hex(payload),
            size_bytes: u64::try_from(payload.len())?,
        }],
        members: Vec::new(),
        verity: None,
        resources: None,
    };
    let archive = write_bundle(
        &bundle,
        &key,
        vec![("artifacts/rootfs.ext4".into(), payload.to_vec())],
    )?;
    let archive_hash = sha256_hex(&archive);
    let descriptor = RegistryApplicationManifest {
        schema_version: 2,
        kind: ApplicationManifestKind::Application,
        reference: "runtime/inspection-fixture@1.0.0".parse()?,
        description: "Nonbootable cryptographic inspection smoke".into(),
        application: RegistryApplication {
            schema_version: 1,
            guest_arch: "aarch64".into(),
            bundle: RegistryApplicationBundle {
                source: "https://example.test/inspection-fixture.mvmpkg".into(),
                archive_sha256: Sha256Hex::from_bytes(&archive),
                archive_size: u64::try_from(archive.len())?,
                key_id: key_id.clone(),
            },
        },
    };
    let descriptor_bytes = serde_json::to_vec_pretty(&descriptor)?;
    parse_application_manifest(&descriptor_bytes)?;
    let descriptor_hash = sha256_hex(&descriptor_bytes);
    let trust = FsTrustStore::default_path()?;
    fs::create_dir_all(trust.root())?;
    let public_key = trust.root().join(format!("{}.pub", key_id.0));
    write_new(&public_key, key.verifying_key().as_bytes())?;
    let policy = RegistryPackPublisherPolicy::new(vec![RegistryPackPublisher::new(
        "runtime",
        "https://token.actions.githubusercontent.com",
        vec![args[3].clone()],
    )?])?;
    let policy_path = mvm_core::config::registry_pack_publisher_policy_path();
    save_publisher_policy(&policy_path, &policy)?;
    let relative = |path: PathBuf| -> Result<String> {
        Ok(path.strip_prefix(&home)?.to_string_lossy().into_owned())
    };
    let metadata = json!({
        "schema_version": 1,
        "scope": "synthetic_publisher_policy_not_official_registry_or_launch",
        "reference": descriptor.reference,
        "identity": args[3],
        "manifest_sha256": descriptor_hash,
        "bundle": descriptor.application.bundle,
        "paths": {
            "policy": relative(policy_path)?,
            "lock": relative(mvm_core::config::pack_lockfile_path())?,
            "registry_cache": relative(mvm_core::config::registry_pack_cache_dir())?,
            "revocation_trust": relative(mvm_core::config::registry_pack_revocation_trust_path())?,
            "bundle_key": relative(public_key)?,
            "archive": relative(BundleRegistry::default_path()?.archive_path(&archive_hash))?
        }
    });
    write_new(&output.join("application.mvmpkg"), &archive)?;
    write_new(&output.join("manifest.json"), &descriptor_bytes)?;
    write_new(
        &output.join("bundle-author.pub"),
        key.verifying_key().as_bytes(),
    )?;
    write_new(
        &output.join("fixture.json"),
        &serde_json::to_vec_pretty(&metadata)?,
    )?;
    // No seed, secret signing key, or consumer-home tree is an output artifact.
    println!("created public nonbootable fixture; descriptor still requires keyless signing");
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?
        .write_all(bytes)?;
    Ok(())
}
