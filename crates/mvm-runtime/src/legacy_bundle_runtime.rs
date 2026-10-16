//! Authenticate a baked runtime without treating paths or adjacent metadata as proof.

use anyhow::{Context, Result, ensure};
use mvm_core::plan::bundle::{
    ArtifactRole, BundleResolveError, BundleResolver, FsTrustStore, VerifiedBundle,
    verify_plan_bundle,
};
use mvm_core::vm_backend::VmStartConfig;
use std::path::Path;

/// Only the verifier can construct this capability. Metadata and initrd bytes
/// are read from the authenticated archive, not mutable extracted sidecars.
#[derive(Debug)]
pub struct VerifiedLegacyBundleRuntime {
    archive: Vec<u8>,
    initrd: Option<Vec<u8>>,
    rootfs_sha256: String,
}

impl VerifiedLegacyBundleRuntime {
    pub(crate) fn rootfs_sha256(&self) -> &str {
        &self.rootfs_sha256
    }

    pub(crate) fn snapshot_in(
        &self,
        config: &VmStartConfig,
        parent: &Path,
    ) -> Result<VmStartConfig> {
        let mut bound = config.clone();
        let generation = tempfile::Builder::new()
            .prefix("legacy-runtime-")
            .tempdir_in(parent)?;
        mvm_core::private_fs::set_mode(generation.path(), 0o700)?;
        let archive = generation.path().join("bundle.mvmpkg");
        mvm_core::util::atomic_io::write_private_new(&archive, &self.archive)?;
        mvm_core::private_fs::set_mode(&archive, 0o400)?;
        mvm_core::util::atomic_io::sync_file(&archive)?;
        bound
            .legacy_bundle_runtime
            .as_mut()
            .context("legacy bundle proof missing")?
            .archive = archive;
        if let Some(bytes) = &self.initrd {
            let path = generation.path().join("initrd");
            mvm_core::util::atomic_io::write_private_new(&path, bytes)?;
            mvm_core::private_fs::set_mode(&path, 0o400)?;
            mvm_core::util::atomic_io::sync_file(&path)?;
            bound.initrd_path = Some(path.display().to_string());
        }
        mvm_core::util::atomic_io::sync_dir(generation.path())?;
        // As with external runtime generations, retain even if spawn fails:
        // the backend may already have opened this file before returning.
        let _retained = generation.keep();
        mvm_core::util::atomic_io::sync_dir(parent)?;
        Ok(bound)
    }
}

struct ArchiveResolver<'a>(&'a [u8]);

impl BundleResolver for ArchiveResolver<'_> {
    fn resolve(&self, _bundle_sha256: &str) -> Result<Vec<u8>, BundleResolveError> {
        Ok(self.0.to_vec())
    }
}

pub(crate) fn verify(
    config: &VmStartConfig,
    minimum_protocol: u32,
) -> Result<VerifiedLegacyBundleRuntime> {
    let verified = verify_retained(config, minimum_protocol)?;
    ensure!(
        mvm_core::crypto::image_verify::sha256_file(Path::new(&config.rootfs_path))?
            == verified.rootfs_sha256,
        "selected legacy Rootfs differs from authenticated bundle"
    );
    Ok(verified)
}

/// Authenticate bundle metadata and retained initrd independently of the
/// historical rootfs pathname. Restores compare the observed rootfs to the
/// returned signed role digest, permitting an identical private fork copy.
pub(crate) fn verify_retained(
    config: &VmStartConfig,
    minimum_protocol: u32,
) -> Result<VerifiedLegacyBundleRuntime> {
    let proof = config
        .legacy_bundle_runtime
        .as_ref()
        .context("legacy initrd requires authenticated bundle provenance")?;
    let trust = FsTrustStore::default_path()?;
    let archive = std::fs::read(&proof.archive)?;
    let verified = verify_plan_bundle(&proof.pin, &ArchiveResolver(&archive), &trust)
        .context("verifying legacy runtime bundle")?;
    ensure!(
        verified.boot_assets.is_none(),
        "portable bundle cannot be admitted as a baked runtime"
    );
    mvm_core::arch::GuestArch::require_host(&verified.manifest.arch)?;
    let rootfs_sha256 = verified
        .manifest
        .find_by_role(&ArtifactRole::Rootfs)
        .context("legacy bundle has no Rootfs artifact")?
        .sha256
        .clone();
    let initrd = config
        .initrd_path
        .as_deref()
        .map(|path| {
            selected_artifact(&verified, ArtifactRole::Initrd, Path::new(path)).map(<[u8]>::to_vec)
        })
        .transpose()?;
    let metadata_artifact = verified
        .manifest
        .artifacts
        .iter()
        .find(|artifact| {
            artifact.role == ArtifactRole::Other
                && artifact.name == mvm_core::guest_sidecar::SIDECAR_FILENAME
        })
        .context("legacy bundle has no authenticated guest metadata")?;
    let metadata: mvm_build::builder_vm::GuestSidecar = serde_json::from_slice(
        verified
            .artifacts
            .get(&metadata_artifact.path)
            .context("authenticated guest metadata bytes are missing")?,
    )?;
    ensure!(
        !metadata.runtime_lean
            && metadata.agent_binary == "real"
            && u32::from(metadata.protocol_version) >= minimum_protocol
            && u32::from(metadata.protocol_version)
                <= crate::runtime_evidence::GUEST_RPC_PROTOCOL_VERSION,
        "authenticated image does not declare a compatible baked guest runtime"
    );
    Ok(VerifiedLegacyBundleRuntime {
        archive,
        initrd,
        rootfs_sha256,
    })
}

fn selected_artifact<'a>(
    verified: &'a VerifiedBundle,
    role: ArtifactRole,
    path: &Path,
) -> Result<&'a [u8]> {
    let artifact = verified
        .manifest
        .find_by_role(&role)
        .with_context(|| format!("legacy bundle has no {role:?} artifact"))?;
    ensure!(
        mvm_core::crypto::image_verify::sha256_file(path)? == artifact.sha256,
        "selected legacy {role:?} differs from authenticated bundle"
    );
    verified
        .artifacts
        .get(&artifact.path)
        .map(Vec::as_slice)
        .context("authenticated legacy artifact bytes are missing")
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) mod fixtures {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use mvm_core::plan::bundle::{
        BUNDLE_SCHEMA_VERSION, BundleArtifact, BundleManifest, PlanArtifact,
        canonical_manifest_bytes, key_id_from_pubkey, sha256_hex, write_bundle,
    };
    use mvm_core::vm_backend::LegacyBundleRuntimeProof;

    /// Synthetic signed archive inputs, never a verified runtime capability.
    pub fn signed_legacy_runtime_fixture(
        home: &Path,
        trust_home: &Path,
        lean: bool,
    ) -> VmStartConfig {
        let key = SigningKey::from_bytes(&[73; 32]);
        let key_id = key_id_from_pubkey(&key.verifying_key());
        let mut metadata = mvm_build::builder_vm::GuestSidecar::for_oci_run("legacy", true, lean);
        metadata.agent_binary = "real".into();
        metadata.protocol_version = crate::runtime_evidence::MIN_GUEST_RPC_PROTOCOL_VERSION as u8;
        let payloads = vec![
            (
                "rootfs.ext4",
                ArtifactRole::Rootfs,
                b"signed rootfs".to_vec(),
            ),
            (
                "initrd",
                ArtifactRole::Initrd,
                b"signed legacy initrd".to_vec(),
            ),
            (
                mvm_core::guest_sidecar::SIDECAR_FILENAME,
                ArtifactRole::Other,
                serde_json::to_vec(&metadata).unwrap(),
            ),
        ];
        let manifest = BundleManifest {
            schema_version: BUNDLE_SCHEMA_VERSION,
            publisher: "fixture".into(),
            key_id: key_id.clone(),
            arch: mvm_core::arch::GuestArch::host().to_string(),
            kernel_version: None,
            profile: None,
            workload_label: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            labels: Default::default(),
            artifacts: payloads
                .iter()
                .map(|(name, role, bytes)| BundleArtifact {
                    name: (*name).into(),
                    role: role.clone(),
                    path: format!("artifacts/{name}"),
                    sha256: sha256_hex(bytes),
                    size_bytes: bytes.len() as u64,
                })
                .collect(),
            members: vec![],
            verity: None,
            resources: None,
        };
        let signature = key
            .sign(&canonical_manifest_bytes(&manifest).unwrap())
            .to_bytes();
        let archive = write_bundle(
            &manifest,
            &key,
            payloads
                .iter()
                .map(|(name, _, bytes)| (format!("artifacts/{name}"), bytes.clone()))
                .collect(),
        )
        .unwrap();
        let archive_path = home.join("image.mvmpkg");
        std::fs::write(&archive_path, &archive).unwrap();
        for (name, _, bytes) in payloads {
            std::fs::write(home.join(name), bytes).unwrap();
        }
        let trust = trust_home.join("trusted-publishers");
        std::fs::create_dir_all(&trust).unwrap();
        std::fs::write(
            trust.join(format!("{}.pub", key_id.0)),
            key.verifying_key().as_bytes(),
        )
        .unwrap();
        VmStartConfig {
            name: "legacy-authenticated".into(),
            rootfs_path: home.join("rootfs.ext4").display().to_string(),
            initrd_path: Some(home.join("initrd").display().to_string()),
            legacy_bundle_runtime: Some(LegacyBundleRuntimeProof {
                archive: archive_path,
                pin: PlanArtifact::new(sha256_hex(&archive), &signature, key_id),
            }),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_evidence::{
        MIN_GUEST_RPC_PROTOCOL_VERSION, RuntimeLifecycleLease, VerifiedLaunchRuntime,
        verify_runtime_for_launch,
    };
    use ed25519_dalek::SigningKey;
    use mvm_core::util::test_env::TestEnv;
    use mvm_core::vm_backend::LegacyBundleRuntimeProof;

    fn fixture(home: &Path, lean: bool) -> VmStartConfig {
        fixtures::signed_legacy_runtime_fixture(home, home, lean)
    }

    #[test]
    fn signed_legacy_binding_captures_restores_and_authenticates_every_field() {
        use mvm_core::checkpoint::{
            CheckpointClass, CheckpointId, CheckpointMeta, ContentBlob, HVF_FRAME_BLOB,
        };
        use mvm_core::crypto::snapshot_hmac::{self, SnapshotFiles};
        use mvm_core::protocol::runtime_release::RuntimeLaunchBinding;
        use mvm_vmm::runtime_artifacts::{RuntimeArtifact, RuntimeArtifacts};
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let config = fixture(home.path(), false);
        let lease = RuntimeLifecycleLease::acquire(&config.name).unwrap();
        let bound = lease.bind(&config).unwrap();
        let retained_archive = &bound.legacy_bundle_runtime.as_ref().unwrap().archive;
        assert_ne!(
            retained_archive,
            &config.legacy_bundle_runtime.as_ref().unwrap().archive
        );
        std::fs::remove_file(&config.legacy_bundle_runtime.as_ref().unwrap().archive).unwrap();
        std::fs::remove_file(config.initrd_path.as_ref().unwrap()).unwrap();
        mvm_vmm::host::runtime_meta::record_from_start_config(
            &bound.name,
            mvm_core::vm_backend::StartMode::Detached,
            &bound,
        )
        .unwrap();
        let binding = mvm_vmm::host::runtime_meta::read(&bound.name)
            .unwrap()
            .unwrap()
            .runtime_launch_binding
            .unwrap();
        assert!(matches!(binding, RuntimeLaunchBinding::LegacyBundle { .. }));
        let mut inherited = VmStartConfig::default();
        binding.apply_to_config(&mut inherited);
        verify_runtime_for_launch(&inherited, MIN_GUEST_RPC_PROTOCOL_VERSION).unwrap();
        assert!(inherited.runtime_overlay_path.is_none());
        assert!(!inherited.unsigned_runtime_development);
        assert!(
            crate::runtime_evidence::verify_runtime_for_claim(Some(&binding), Some(&inherited))
                .is_err()
        );
        let observe = |path: &str| RuntimeArtifact {
            path: path.into(),
            sha256: mvm_core::crypto::image_verify::sha256_file(Path::new(path)).unwrap(),
        };
        let actual = RuntimeArtifacts {
            kernel: None,
            initramfs: Some(observe(bound.initrd_path.as_deref().unwrap())),
            disks: vec![observe(&bound.rootfs_path)],
            kernel_cmdline: "console=hvc0".into(),
            firecracker_drives: None,
        };
        crate::checkpoint::runtime_binding::verify_capture(Some(&binding), &actual).unwrap();
        let mut fc = actual.clone();
        fc.firecracker_drives = Some(vec![mvm_vmm::runtime_artifacts::FirecrackerDrive {
            drive_id: "blk0".into(),
            path: actual.disks[0].path.clone(),
            is_root_device: true,
            is_read_only: true,
        }]);
        crate::checkpoint::runtime_binding::verify_capture(Some(&binding), &fc).unwrap();
        fc.firecracker_drives.as_mut().unwrap()[0].is_read_only = false;
        fc.disks.clear();
        assert!(crate::checkpoint::runtime_binding::verify_capture(Some(&binding), &fc).is_err());
        let mut remapped = actual.clone();
        let child_root = home.path().join("child-rootfs");
        std::fs::copy(&bound.rootfs_path, &child_root).unwrap();
        remapped.disks[0].path = child_root.clone();
        crate::checkpoint::runtime_binding::verify_capture(Some(&binding), &remapped).unwrap();
        std::fs::remove_file(&bound.rootfs_path).unwrap();
        crate::checkpoint::runtime_binding::verify_capture(Some(&binding), &remapped).unwrap();
        std::fs::write(&bound.rootfs_path, b"changed original").unwrap();
        crate::checkpoint::runtime_binding::verify_capture(Some(&binding), &remapped).unwrap();
        std::fs::copy(&child_root, &bound.rootfs_path).unwrap();
        std::fs::write(child_root, b"wrong rootfs").unwrap();
        assert!(
            crate::checkpoint::runtime_binding::verify_capture(Some(&binding), &remapped).is_err()
        );
        for changed in ["initrd", "rootfs", "tokens"] {
            let mut wrong = actual.clone();
            match changed {
                "initrd" => wrong.initramfs.as_mut().unwrap().sha256 = "00".repeat(32),
                "rootfs" => wrong.disks[0].sha256 = "00".repeat(32),
                "tokens" => wrong.kernel_cmdline.push_str(" mvm.runtime_data=/dev/vdb"),
                _ => unreachable!(),
            }
            assert!(
                crate::checkpoint::runtime_binding::verify_capture(Some(&binding), &wrong).is_err()
            );
        }
        let store = crate::checkpoint::CheckpointStore::at(home.path().join("checkpoints"));
        let id = CheckpointId::new("legacy");
        let content = store.content_dir(&id);
        std::fs::create_dir_all(&content).unwrap();
        let bytes = serde_json::to_vec(&actual).unwrap();
        std::fs::write(content.join("runtime-artifacts.json"), &bytes).unwrap();
        let meta = CheckpointMeta::builder(id, CheckpointClass::VmFull, &bound.name)
            .runtime_launch_binding(Some(binding.clone()))
            .content(vec![
                ContentBlob {
                    name: "runtime-artifacts.json".into(),
                    sha256: mvm_core::crypto::image_verify::sha256_reader(bytes.as_slice())
                        .unwrap(),
                },
                ContentBlob {
                    name: HVF_FRAME_BLOB.into(),
                    sha256: "ab".repeat(32),
                },
            ])
            .build();
        crate::checkpoint::verify_checkpoint_runtime(&store, &meta).unwrap();
        let files = SnapshotFiles {
            vmstate: home.path().join("vmstate"),
            mem: home.path().join("mem"),
        };
        std::fs::write(&files.vmstate, b"state fixture").unwrap();
        std::fs::write(&files.mem, b"memory fixture").unwrap();
        let key = [19; 32];
        let sidecar = snapshot_hmac::seal(
            home.path(),
            &snapshot_hmac::SnapshotIntegrityParams::new(&files, 1, "1", &key)
                .with_runtime_binding(Some(&binding)),
        )
        .unwrap();
        snapshot_hmac::verify(home.path(), &files, 1, "1", &key, false).unwrap();
        let encoded = serde_json::to_value(&binding).unwrap();
        for pointer in [
            "/proof/archive",
            "/proof/pin/bundle_sha256",
            "/proof/pin/manifest_sig_base64",
            "/proof/pin/key_id",
            "/rootfs_path",
            "/initramfs_path",
        ] {
            let mut changed = encoded.clone();
            let value = changed
                .pointer_mut(pointer)
                .unwrap_or_else(|| panic!("missing {pointer} in {encoded}"));
            *value = "tampered".into();
            let changed: RuntimeLaunchBinding = serde_json::from_value(changed).unwrap();
            let mut changed_meta = meta.clone();
            changed_meta.runtime_launch_binding = Some(changed.clone());
            assert_ne!(
                meta.meta_digest,
                changed_meta.compute_meta_digest(),
                "{pointer}"
            );
            if pointer != "/rootfs_path" {
                assert!(
                    crate::checkpoint::verify_checkpoint_runtime(&store, &changed_meta).is_err(),
                    "{pointer}"
                );
            }
            let mut changed_sidecar = sidecar.clone();
            changed_sidecar.runtime_launch_binding = Some(changed);
            std::fs::write(
                home.path().join(snapshot_hmac::SIDECAR_FILENAME),
                serde_json::to_vec(&changed_sidecar).unwrap(),
            )
            .unwrap();
            assert!(
                snapshot_hmac::verify(home.path(), &files, 1, "1", &key, false).is_err(),
                "{pointer}"
            );
        }
        let mut unknown = encoded;
        unknown["verified"] = true.into();
        assert!(serde_json::from_value::<RuntimeLaunchBinding>(unknown.clone()).is_err());
        unknown.as_object_mut().unwrap().remove("verified");
        unknown["proof"]["verified"] = true.into();
        assert!(serde_json::from_value::<RuntimeLaunchBinding>(unknown.clone()).is_err());
        unknown["proof"].as_object_mut().unwrap().remove("verified");
        unknown["runtime"] = "unknown".into();
        assert!(serde_json::from_value::<RuntimeLaunchBinding>(unknown).is_err());
        std::fs::write(
            content.join("runtime-artifacts.json"),
            b"changed observation",
        )
        .unwrap();
        assert!(crate::checkpoint::verify_checkpoint_runtime(&store, &meta).is_err());
    }

    #[test]
    fn retained_signed_archive_uses_verified_bytes_and_refuses_tampering() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let config = fixture(home.path(), false);
        let verified = verify(&config, MIN_GUEST_RPC_PROTOCOL_VERSION).unwrap();
        let original_archive = &config.legacy_bundle_runtime.as_ref().unwrap().archive;
        let lease = RuntimeLifecycleLease::acquire(&config.name).unwrap();
        let bound = lease.bind(&config).unwrap();
        let generation = bound
            .legacy_bundle_runtime
            .as_ref()
            .unwrap()
            .archive
            .parent()
            .unwrap();
        std::fs::write(original_archive, b"substituted after authentication").unwrap();
        let second = verified
            .snapshot_in(&config, generation.parent().unwrap())
            .unwrap();
        std::fs::remove_file(original_archive).unwrap();
        std::fs::remove_file(config.initrd_path.as_ref().unwrap()).unwrap();
        crate::runtime_evidence::verify_retained_legacy_runtime(&second).unwrap();
        let archive = &bound.legacy_bundle_runtime.as_ref().unwrap().archive;
        mvm_core::private_fs::set_mode(archive, 0o600).unwrap();
        std::fs::write(archive, b"retained tamper").unwrap();
        mvm_core::private_fs::set_mode(archive, 0o400).unwrap();
        assert!(crate::runtime_evidence::verify_retained_legacy_runtime(&bound).is_err());
    }

    #[test]
    fn authenticated_legacy_initrd_is_retained_without_cli_runtime_version() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let config = fixture(home.path(), false);
        let checked = verify_runtime_for_launch(&config, MIN_GUEST_RPC_PROTOCOL_VERSION).unwrap();
        assert!(matches!(
            checked,
            Some(VerifiedLaunchRuntime::LegacyBundle(_))
        ));
        let proof = config.legacy_bundle_runtime.as_ref().unwrap();
        let json = serde_json::to_vec(proof).unwrap();
        assert_eq!(
            *proof,
            serde_json::from_slice::<LegacyBundleRuntimeProof>(&json).unwrap()
        );
        assert!(VmStartConfig::default().legacy_bundle_runtime.is_none());
        let lease = RuntimeLifecycleLease::acquire(&config.name).unwrap();
        let bound = lease.bind(&config).unwrap();
        let retained = bound.initrd_path.as_ref().unwrap();
        assert_ne!(bound.initrd_path, config.initrd_path);
        std::fs::write(
            config.initrd_path.as_ref().unwrap(),
            b"substituted after check",
        )
        .unwrap();
        assert_eq!(std::fs::read(retained).unwrap(), b"signed legacy initrd");
        assert!(bound.runtime_overlay_path.is_none());
        assert!(bound.runtime_overlay_version.is_none());
        verify_runtime_for_launch(&bound, MIN_GUEST_RPC_PROTOCOL_VERSION).unwrap();
        drop(lease);
        assert!(Path::new(retained).exists());
    }

    #[test]
    fn substituted_selected_artifacts_bundle_and_trust_are_rejected() {
        for target in ["rootfs.ext4", "initrd", "image.mvmpkg", "trust", "pin"] {
            let home = tempfile::tempdir().unwrap();
            let mut env = TestEnv::new();
            env.isolate_mvm_home(home.path());
            let mut config = fixture(home.path(), false);
            match target {
                "trust" => {
                    let proof = config.legacy_bundle_runtime.as_ref().unwrap();
                    let path = home
                        .path()
                        .join("trusted-publishers")
                        .join(format!("{}.pub", proof.pin.key_id.0));
                    std::fs::write(
                        path,
                        SigningKey::from_bytes(&[74; 32]).verifying_key().as_bytes(),
                    )
                    .unwrap();
                }
                "pin" => {
                    config
                        .legacy_bundle_runtime
                        .as_mut()
                        .unwrap()
                        .pin
                        .bundle_sha256 = "0".repeat(64)
                }
                file => std::fs::write(home.path().join(file), b"substituted").unwrap(),
            }
            assert!(
                verify_runtime_for_launch(&config, MIN_GUEST_RPC_PROTOCOL_VERSION).is_err(),
                "{target}"
            );
        }
    }

    #[test]
    fn signed_lean_image_cannot_be_promoted_by_adjacent_baked_metadata() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let config = fixture(home.path(), true);
        let metadata_path = home.path().join(mvm_core::guest_sidecar::SIDECAR_FILENAME);
        let mut metadata: mvm_build::builder_vm::GuestSidecar =
            serde_json::from_slice(&std::fs::read(&metadata_path).unwrap()).unwrap();
        metadata.runtime_lean = false;
        std::fs::write(metadata_path, serde_json::to_vec(&metadata).unwrap()).unwrap();
        assert!(verify_runtime_for_launch(&config, MIN_GUEST_RPC_PROTOCOL_VERSION).is_err());
    }

    #[test]
    fn paths_and_metadata_alone_never_exempt_initrd_or_external_runtime() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let config = fixture(home.path(), false);
        let mut unproven = config.clone();
        unproven.legacy_bundle_runtime = None;
        assert!(verify_runtime_for_launch(&unproven, MIN_GUEST_RPC_PROTOCOL_VERSION).is_err());
        let mut external = config.clone();
        external.runtime_overlay_path =
            Some(home.path().join("overlay.ext4").display().to_string());
        assert!(verify_runtime_for_launch(&external, MIN_GUEST_RPC_PROTOCOL_VERSION).is_err());
        let mut source_flag = config;
        source_flag.unsigned_runtime_development = true;
        assert!(verify_runtime_for_launch(&source_flag, MIN_GUEST_RPC_PROTOCOL_VERSION).is_err());
    }
}
