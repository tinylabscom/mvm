//! Synthetic contract tests, not signature, published pack, or native boot evidence.
use super::*;
use crate::image_set::{ImageSetRole, MemberBuildMode, MemberTarget};
use crate::plan::{AssetIdentity, EnvironmentRef};
use crate::registry_pack_image::BuiltImageAsset;

struct Fixture {
    _directory: tempfile::TempDir,
    contract: BuiltPackBootContract,
    plan: ExecutionPlan,
    config: VmStartConfig,
}

fn fixture(arch: GuestArch) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let payload = directory.path().to_owned();
    let mut image = crate::registry_pack_image::tests::descriptor();
    image.platform = match arch {
        GuestArch::Aarch64 => BuiltImagePlatform::LinuxAarch64,
        GuestArch::X86_64 => BuiltImagePlatform::LinuxX86_64,
    };
    let write = |asset: &mut BuiltImageAsset, bytes: &[u8]| {
        std::fs::write(payload.join(asset.name.as_str()), bytes).unwrap();
        asset.size = bytes.len() as u64;
        asset.sha256 = Sha256Hex::from_bytes(bytes);
    };
    write(&mut image.assets.rootfs, b"synthetic-rootfs");
    write(&mut image.assets.verity, b"synthetic-verity");
    write(
        &mut image.assets.mvm_meta,
        br#"{"overlayAware":true,"runtimeLean":true}"#,
    );
    write(
        &mut image.assets.roothash,
        format!("{}\n", "a".repeat(64)).as_bytes(),
    );
    let mut base = synthetic_base(arch);
    let role = ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant);
    let member = base
        .members
        .iter_mut()
        .find(|m| m.role == role && m.target == MemberTarget::Arch(arch) && m.build_mode.is_none())
        .unwrap();
    let kernel = &mut member.artifacts[0];
    kernel.sha256 = Sha256Hex::from_bytes(b"synthetic-kernel");
    kernel.size = b"synthetic-kernel".len() as u64;
    std::fs::write(payload.join("kernel"), b"synthetic-kernel").unwrap();
    let kernel_sha = kernel.sha256.clone();
    let pin = PackPin::new(
        "runtime/python@1.0.0".parse().unwrap(),
        Sha256Hex::from_bytes(b"synthetic-pin"),
    )
    .unwrap();
    let mut plan = crate::plan::test_support::PlanFixture::new().build();
    plan.image.sha256 = image.assets.rootfs.sha256.as_str().to_owned();
    plan.environment = Some(EnvironmentRef {
        kernel_sha256: kernel_sha.as_str().to_owned(),
    });
    plan.asset_identities.push(
        AssetIdentity::new(
            AssetKind::RegistryPack,
            pin.reference().to_string(),
            pin.manifest_sha256().as_str(),
        )
        .unwrap(),
    );
    let config = VmStartConfig {
        rootfs_path: payload.join("rootfs.ext4").display().to_string(),
        kernel_path: Some(payload.join("kernel").display().to_string()),
        verity_path: Some(payload.join("rootfs.verity").display().to_string()),
        roothash: Some("a".repeat(64)),
        ..Default::default()
    };
    Fixture {
        _directory: directory,
        contract: BuiltPackBootContract {
            pin,
            payload,
            image,
            base,
        },
        plan,
        config,
    }
}

fn synthetic_base(arch: GuestArch) -> ImageSetManifest {
    let format = match arch {
        GuestArch::X86_64 => KernelFormat::Elf,
        GuestArch::Aarch64 => KernelFormat::Image,
    };
    serde_json::from_value(serde_json::json!({
        "schema_version": 2,
        "set_version": "0.2.4",
        "issued_at": "2026-10-04T00:00:00Z",
        "producer": {
            "repository": "tinylabscom/mvm-images",
            "workflow": ".github/workflows/release.yml",
            "release_tag": "image-set/v0.2.4",
            "source_commit": "a".repeat(40)
        },
        "mvm_source_commit": "b".repeat(40),
        "compatibility": {
            "guest_agent_protocol": {"min": 2, "max": 2},
            "builder_cache_contract": 5,
            "builder_boot_abi": 1
        },
        "nix_inputs": {"flake_locks": [], "source_revisions": []},
        "revocation_channel": "https://example.test/revocations.json",
        "members": [
            {
                "role": {"workload_kernel": "default_tenant"},
                "target": {"arch": arch},
                "boot_protocol": "linux_direct",
                "artifacts": [{
                    "name": "kernel", "format": {"kernel": format},
                    "sha256": "a".repeat(64), "size": 1
                }],
                "required_capabilities": ["virtio_vsock"]
            },
            {
                "role": {"workload_rootfs": "default_tenant"},
                "target": {"arch": arch},
                "artifacts": [{
                    "name": "base.ext4", "format": "ext4",
                    "sha256": "b".repeat(64), "size": 1
                }],
                "required_capabilities": ["virtio_blk", "dm_verity"]
            }
        ]
    }))
    .unwrap()
}

impl Fixture {
    fn check(&self) -> Result<()> {
        self.contract.verify_image_config(
            &self.plan,
            &self.config,
            GuestArch::X86_64,
            BackendKind::Firecracker,
        )
    }
}

#[test]
fn both_architectures_bind_the_existing_config_to_production_members() {
    for (arch, backend) in [
        (GuestArch::X86_64, BackendKind::Firecracker),
        (GuestArch::Aarch64, BackendKind::Hvf),
    ] {
        let f = fixture(arch);
        f.contract
            .verify_image_config(&f.plan, &f.config, arch, backend)
            .unwrap();
        let resolved = f
            .contract
            .image_config(
                Path::new(f.config.kernel_path.as_deref().unwrap()),
                arch,
                backend,
            )
            .unwrap();
        assert_eq!(resolved.rootfs_path, f.config.rootfs_path);
        assert_eq!(resolved.verity_path, f.config.verity_path);
        assert_eq!(resolved.roothash, f.config.roothash);
        assert_eq!(resolved.revision_hash, f.plan.image.sha256);
    }
}

#[test]
fn caller_chosen_plan_rootfs_and_kernel_are_not_authority() {
    for field in ["rootfs", "kernel", "pin"] {
        let mut f = fixture(GuestArch::X86_64);
        match field {
            "rootfs" => f.plan.image.sha256 = "0".repeat(64),
            "kernel" => f.plan.environment.as_mut().unwrap().kernel_sha256 = "0".repeat(64),
            "pin" => f.plan.asset_identities.clear(),
            _ => unreachable!(),
        }
        assert!(f.check().is_err(), "{field}");
    }
}

#[test]
fn every_actual_file_is_hashed_again_at_use() {
    for name in [
        "kernel",
        "rootfs.ext4",
        "rootfs.verity",
        "rootfs.roothash",
        "mvm-meta.json",
    ] {
        for missing in [false, true] {
            let f = fixture(GuestArch::X86_64);
            f.check().unwrap();
            let path = f.contract.payload.join(name);
            if missing {
                std::fs::remove_file(path).unwrap();
            } else {
                let mut bytes = std::fs::read(&path).unwrap();
                bytes[0] ^= 1;
                std::fs::write(path, bytes).unwrap();
            }
            assert!(f.check().is_err(), "{name}, missing={missing}");
        }
    }
}

#[test]
fn substituted_paths_and_missing_verity_fields_are_refused() {
    for field in ["rootfs", "kernel", "verity", "roothash"] {
        let mut f = fixture(GuestArch::X86_64);
        let wrong = f.contract.payload.join("wrong");
        std::fs::write(&wrong, b"wrong").unwrap();
        match field {
            "rootfs" => f.config.rootfs_path = wrong.display().to_string(),
            "kernel" => f.config.kernel_path = Some(wrong.display().to_string()),
            "verity" => f.config.verity_path = None,
            "roothash" => f.config.roothash = Some("b".repeat(64)),
            _ => unreachable!(),
        }
        assert!(f.check().is_err(), "{field}");
    }
}

#[test]
fn dev_or_rootless_members_cannot_replace_the_default_tenant_kernel() {
    for profile in ["dev", "rootless", "wrong-format"] {
        let mut f = fixture(GuestArch::X86_64);
        for member in &mut f.contract.base.members {
            if member.role == ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant) {
                match profile {
                    "dev" => member.build_mode = Some(MemberBuildMode::Dev),
                    "rootless" => {
                        member.role =
                            ImageSetRole::WorkloadKernel(WorkloadImageProfile::RootlessTenant)
                    }
                    "wrong-format" => {
                        member.artifacts[0].format = ArtifactFormat::Kernel(KernelFormat::ImageGz)
                    }
                    _ => unreachable!(),
                }
            }
        }
        assert!(f.check().is_err(), "{profile}");
    }
}

#[test]
fn a_dev_member_cannot_shadow_the_production_member() {
    let mut f = fixture(GuestArch::X86_64);
    let mut dev = f.contract.base.members[0].clone();
    dev.build_mode = Some(MemberBuildMode::Dev);
    dev.artifacts[0].sha256 = Sha256Hex::from_bytes(b"wrong-dev-kernel");
    f.contract.base.members.insert(0, dev);
    f.check().unwrap();
}

#[test]
fn ambiguous_signed_kernel_formats_are_refused() {
    let mut f = fixture(GuestArch::X86_64);
    let duplicate = f.contract.base.members[0].artifacts[0].clone();
    f.contract.base.members[0].artifacts.push(duplicate);
    assert!(f.check().is_err());
}

#[test]
fn wrong_architecture_and_unsupported_backends_are_refused() {
    let f = fixture(GuestArch::X86_64);
    assert!(
        f.contract
            .kernel(GuestArch::Aarch64, BackendKind::Hvf)
            .is_err()
    );
    for backend in [
        BackendKind::Libkrun,
        BackendKind::Wasm,
        BackendKind::Mock,
        BackendKind::Hvf,
    ] {
        assert!(
            f.contract.kernel(GuestArch::X86_64, backend).is_err(),
            "{backend:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn symlinks_are_not_verified_regular_boot_artifacts() {
    let f = fixture(GuestArch::X86_64);
    let path = f.contract.payload.join("kernel");
    let target = f.contract.payload.join("kernel-real");
    std::fs::rename(&path, &target).unwrap();
    std::os::unix::fs::symlink(target, path).unwrap();
    assert!(f.check().is_err());
}
