use std::cell::Cell;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use mvm_bundler::{BootAssetsInputs, BundleExportInputs, BundleSigner, export_bundle_with_signer};
use mvm_core::arch::GuestArch;
use mvm_core::image_set::*;
use mvm_core::kernel_format::KernelFormat;
use mvm_core::packs::{FlakeLockIdentity, SbomReference, Sha256Hex, SourceRevisionIdentity};
use mvm_core::plan::bundle::{
    KeyId, TrustStore, read_and_verify_bundle, select_boot_asset_members,
};

struct Publisher {
    key: SigningKey,
    calls: Cell<usize>,
}

impl BundleSigner for Publisher {
    fn publisher_id(&self) -> String {
        "test".into()
    }
    fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
    fn sign(&self, bytes: &[u8]) -> anyhow::Result<[u8; 64]> {
        self.calls.set(self.calls.get() + 1);
        Ok(self.key.sign(bytes).to_bytes())
    }
}

impl TrustStore for Publisher {
    fn lookup(&self, key: &KeyId) -> Option<VerifyingKey> {
        (key == &self.key_id()).then(|| self.verifying_key())
    }
}

fn archive_bytes(name: &str) -> Vec<u8> {
    format!("archive:{name}").into_bytes()
}

fn manifest() -> ImageSetManifest {
    let members = ImageSetRequirement::current_train()
        .members()
        .iter()
        .enumerate()
        .map(|(i, required)| {
            let kernel = ArtifactFormat::Kernel(match required.target {
                MemberTarget::Arch(GuestArch::X86_64) => KernelFormat::Elf,
                _ => KernelFormat::Image,
            });
            let (formats, boot_protocol, capabilities) = match required.role {
                ImageSetRole::BuilderVm => (
                    vec![kernel, ArtifactFormat::Ext4],
                    Some(BootProtocol::LinuxDirect),
                    vec![
                        GuestDeviceRequirement::VirtioVsock,
                        GuestDeviceRequirement::VirtioBlk,
                    ],
                ),
                ImageSetRole::WorkloadKernel(_) | ImageSetRole::Stage0BootstrapKernel => (
                    vec![kernel],
                    Some(BootProtocol::LinuxDirect),
                    vec![GuestDeviceRequirement::VirtioVsock],
                ),
                ImageSetRole::WorkloadRootfs(_) => (
                    vec![
                        ArtifactFormat::Ext4,
                        ArtifactFormat::VerityHashTree,
                        ArtifactFormat::VerityRootHash,
                    ],
                    None,
                    vec![
                        GuestDeviceRequirement::VirtioBlk,
                        GuestDeviceRequirement::DmVerity,
                    ],
                ),
                ImageSetRole::RuntimeOverlay
                | ImageSetRole::Initramfs
                | ImageSetRole::SdkSidecar(_)
                | ImageSetRole::QemuWasmSmokePack => (vec![ArtifactFormat::TarGz], None, vec![]),
            };
            ImageSetMember {
                role: required.role,
                target: required.target,
                build_mode: None,
                source_fingerprint: None,
                boot_protocol,
                required_capabilities: capabilities,
                artifacts: formats
                    .into_iter()
                    .enumerate()
                    .map(|(j, format)| {
                        let name = format!("member-{i}-{j}");
                        let bytes = archive_bytes(&name);
                        MemberArtifact {
                            name: ArtifactName::new(name).unwrap(),
                            format,
                            sha256: Sha256Hex::from_bytes(&bytes),
                            size: bytes.len() as u64,
                        }
                    })
                    .collect(),
                pack_hash: Some(Sha256Hex::from_bytes(b"pack")),
                sbom: Some(SbomReference {
                    uri: "https://example.test/sbom".into(),
                    sha256: Sha256Hex::from_bytes(b"sbom"),
                }),
            }
        })
        .collect();
    ImageSetManifest {
        schema_version: IMAGE_SET_SCHEMA_VERSION,
        set_version: ImageSetVersion::new("1.0.0").unwrap(),
        issued_at: "2026-09-23T00:00:00Z".parse().unwrap(),
        producer: ImageSetProducer::Release(ReleaseProducer {
            repository: RepositorySlug::new("tinylabscom/mvm-images").unwrap(),
            workflow: WorkflowPath::new(".github/workflows/release.yml").unwrap(),
            release_tag: ReleaseTag::new("v1.0.0").unwrap(),
            source_commit: GitCommit::new("a".repeat(40)).unwrap(),
        }),
        mvm_source_commit: GitCommit::new("b".repeat(40)).unwrap(),
        compatibility: ImageSetCompatibility {
            guest_agent_protocol: ProtocolRange::new(2, 2).unwrap(),
            builder_cache_contract: 4,
            builder_boot_abi: None,
        },
        nix_inputs: NixInputs {
            flake_locks: vec![FlakeLockIdentity {
                reference: "nix/images".into(),
                lock_hash: Sha256Hex::from_bytes(b"lock"),
            }],
            source_revisions: vec![SourceRevisionIdentity {
                repository: "https://github.com/NixOS/nixpkgs".into(),
                revision: "c".repeat(40),
                tree_hash: Sha256Hex::from_bytes(b"tree"),
            }],
        },
        revocation_channel: Some(
            RevocationChannel::new("https://example.test/revocations.json").unwrap(),
        ),
        supersedes: None,
        members,
    }
}

#[test]
fn boot_export_binds_original_bytes_and_refuses_bad_inputs_before_signing() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = dir.path().join("kernel");
    let rootfs = dir.path().join("rootfs.ext4");
    let overlay = dir.path().join("overlay");
    let initramfs = dir.path().join("initramfs");
    let out = dir.path().join("bundle.mvmpkg");
    std::fs::write(&kernel, b"kernel").unwrap();
    std::fs::write(&rootfs, b"rootfs").unwrap();
    std::fs::write(dir.path().join("mvm-meta.json"), b"{}").unwrap();
    let original = manifest();
    let selected = select_boot_asset_members(&original, GuestArch::Aarch64).unwrap();
    std::fs::write(
        &overlay,
        archive_bytes(selected[0].artifacts[0].name.as_str()),
    )
    .unwrap();
    std::fs::write(
        &initramfs,
        archive_bytes(selected[1].artifacts[0].name.as_str()),
    )
    .unwrap();
    // Whitespace survives export; the root is over original bytes, not a reserialization.
    let bytes = serde_json::to_vec_pretty(&original).unwrap();
    let pin = Sha256Hex::from_bytes(&bytes);
    let publisher = Publisher {
        key: SigningKey::from_bytes(&[11; 32]),
        calls: Cell::new(0),
    };
    let mut inputs = BundleExportInputs::new(
        kernel.to_str().unwrap(),
        rootfs.to_str().unwrap(),
        "aarch64",
        &out,
    );
    inputs.boot_assets = Some(BootAssetsInputs {
        manifest_bytes: &bytes,
        manifest_sha256: &pin,
        runtime_overlay: &overlay,
        initramfs: &initramfs,
    });
    export_bundle_with_signer(&inputs, &publisher).unwrap();
    let verified = read_and_verify_bundle(&std::fs::read(&out).unwrap(), &publisher).unwrap();
    assert_eq!(verified.manifest.schema_version, 4);
    let boot = verified.boot_assets.unwrap();
    assert_eq!(boot.image_set.manifest_sha256, pin);
    assert_eq!(verified.artifacts["artifacts/boot-image-set.json"], bytes);
    assert!(verified.embedded_image_sets.is_empty());
    assert_eq!(boot.image_set.artifact_paths.len(), 2);
    let calls = publisher.calls.get();
    let wrong_pin = Sha256Hex::from_bytes(b"another manifest");
    let mut wrong_pin_inputs = inputs.clone();
    wrong_pin_inputs
        .boot_assets
        .as_mut()
        .unwrap()
        .manifest_sha256 = &wrong_pin;
    assert!(export_bundle_with_signer(&wrong_pin_inputs, &publisher).is_err());
    let mut wrong_size = original.clone();
    let name = selected[0].artifacts[0].name.as_str();
    for artifact in wrong_size
        .members
        .iter_mut()
        .flat_map(|member| &mut member.artifacts)
    {
        if artifact.name.as_str() == name {
            artifact.size += 1;
        }
    }
    let wrong_size_bytes = serde_json::to_vec(&wrong_size).unwrap();
    let wrong_size_pin = Sha256Hex::from_bytes(&wrong_size_bytes);
    let mut wrong_size_inputs = inputs.clone();
    wrong_size_inputs.boot_assets = Some(BootAssetsInputs {
        manifest_bytes: &wrong_size_bytes,
        manifest_sha256: &wrong_size_pin,
        runtime_overlay: &overlay,
        initramfs: &initramfs,
    });
    assert!(export_bundle_with_signer(&wrong_size_inputs, &publisher).is_err());
    let mut missing_role = original.clone();
    missing_role
        .members
        .retain(|member| member.role != ImageSetRole::Initramfs);
    let missing_bytes = serde_json::to_vec(&missing_role).unwrap();
    let missing_pin = Sha256Hex::from_bytes(&missing_bytes);
    let mut missing_inputs = inputs.clone();
    missing_inputs.boot_assets = Some(BootAssetsInputs {
        manifest_bytes: &missing_bytes,
        manifest_sha256: &missing_pin,
        runtime_overlay: &overlay,
        initramfs: &initramfs,
    });
    assert!(export_bundle_with_signer(&missing_inputs, &publisher).is_err());
    inputs.arch_label = "x86_64";
    assert!(export_bundle_with_signer(&inputs, &publisher).is_err());
    inputs.arch_label = "unknown";
    assert!(export_bundle_with_signer(&inputs, &publisher).is_err());
    inputs.arch_label = "aarch64";
    std::fs::write(&overlay, b"tampered").unwrap();
    assert!(export_bundle_with_signer(&inputs, &publisher).is_err());
    std::fs::write(
        &overlay,
        archive_bytes(selected[0].artifacts[0].name.as_str()),
    )
    .unwrap();
    std::fs::remove_file(&initramfs).unwrap();
    assert!(export_bundle_with_signer(&inputs, &publisher).is_err());
    assert_eq!(publisher.calls.get(), calls);
}
