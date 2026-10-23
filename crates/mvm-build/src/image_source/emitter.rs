//! In-process local Linux-set production. Inspection and publication share
//! the same staged bytes; no supplied root may use source declarations instead.

use std::io::{Read, Write};
use std::path::Path;

use chrono::{TimeZone, Timelike, Utc};
use mvm_core::image_set::{
    ArtifactFormat, BaseImageContract, BootProtocol, ImageSetCompatibility, ImageSetManifest,
    ImageSetMember, ImageSetProducer, ImageSetRole, ImageSetVersion, LocalCheckouts,
    MemberArtifact, MemberTarget,
};
use mvm_core::packs::{FlakeLockIdentity, Sha256Hex};
use sha2::{Digest, Sha256};

use super::{EmitRequest, LocalImageBuildError, OutputFormat};

fn refused(detail: impl ToString) -> LocalImageBuildError {
    LocalImageBuildError::Tool {
        what: "writing the local Linux image-set manifest".into(),
        detail: detail.to_string(),
    }
}

fn io(op: &'static str, path: &Path, source: std::io::Error) -> LocalImageBuildError {
    LocalImageBuildError::Io {
        op,
        path: path.into(),
        source,
    }
}

fn digest(path: &Path) -> Result<Sha256Hex, LocalImageBuildError> {
    let hex =
        mvm_core::crypto::image_verify::sha256_file(path).map_err(|e| io("hashing", path, e))?;
    Sha256Hex::new(hex).map_err(refused)
}

fn copy_artifact(from: &Path, to: &Path) -> Result<(Sha256Hex, u64), LocalImageBuildError> {
    if !std::fs::metadata(from)
        .map_err(|e| io("reading", from, e))?
        .is_file()
    {
        return Err(refused("artifact must resolve to a regular file"));
    }
    let mut source = std::fs::File::open(from).map_err(|e| io("opening", from, e))?;
    let mut dest = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(to)
        .map_err(|e| io("creating", to, e))?;
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let count = source
            .read(&mut buffer)
            .map_err(|e| io("reading", from, e))?;
        if count == 0 {
            break;
        }
        dest.write_all(&buffer[..count])
            .map_err(|e| io("writing", to, e))?;
        hasher.update(&buffer[..count]);
        size += count as u64;
    }
    if size == 0 {
        return Err(refused("empty artifact"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o644))
            .map_err(|e| io("setting permissions", to, e))?;
    }
    Ok((
        Sha256Hex::new(hex::encode(hasher.finalize())).map_err(refused)?,
        size,
    ))
}

fn role(name: &str) -> Result<ImageSetRole, LocalImageBuildError> {
    use mvm_core::image_set::WorkloadImageProfile::{DefaultTenant, RootlessTenant};
    match name {
        "builder_vm" => Ok(ImageSetRole::BuilderVm),
        "default_tenant_workload_kernel" => Ok(ImageSetRole::WorkloadKernel(DefaultTenant)),
        "default_tenant_workload_rootfs" => Ok(ImageSetRole::WorkloadRootfs(DefaultTenant)),
        "rootless_tenant_workload_kernel" => Ok(ImageSetRole::WorkloadKernel(RootlessTenant)),
        "rootless_tenant_workload_rootfs" => Ok(ImageSetRole::WorkloadRootfs(RootlessTenant)),
        "stage0_bootstrap_kernel" => Ok(ImageSetRole::Stage0BootstrapKernel),
        "qemu_wasm_smoke_pack" => Ok(ImageSetRole::QemuWasmSmokePack),
        _ => Err(refused(format!("not a Linux image role: {name}"))),
    }
}

fn inspect_roots(
    members: &[ImageSetMember],
    staging: &Path,
    compatibility: &ImageSetCompatibility,
) -> Result<(), LocalImageBuildError> {
    for member in members {
        if !matches!(member.role, ImageSetRole::WorkloadRootfs(_)) {
            continue;
        }
        let roots: Vec<_> = member
            .artifacts
            .iter()
            .filter(|a| a.format == ArtifactFormat::Ext4)
            .collect();
        let [root] = roots.as_slice() else {
            return Err(refused(
                "a supplied workload root requires exactly one ext4 artifact",
            ));
        };
        let path = staging.join(root.name.as_str());
        crate::base_image_contract::verify_base_image_contract(&path, compatibility)
            .map_err(|error| refused(format!("{error:#}")))?;
    }
    Ok(())
}

fn verify_artifacts(
    members: &[ImageSetMember],
    staging: &Path,
) -> Result<(), LocalImageBuildError> {
    for artifact in members.iter().flat_map(|m| &m.artifacts) {
        let path = staging.join(artifact.name.as_str());
        let meta = std::fs::symlink_metadata(&path).map_err(|e| io("rechecking", &path, e))?;
        if !meta.is_file() || meta.len() != artifact.size || digest(&path)? != artifact.sha256 {
            return Err(refused(format!(
                "artifact changed while recording: {}",
                artifact.name
            )));
        }
    }
    Ok(())
}

pub(super) fn emit(request: &EmitRequest<'_>) -> Result<(), LocalImageBuildError> {
    emit_observed(
        request,
        || super::super::git::probe_identity(request.images_root),
        |_, _| {},
    )
}

fn emit_observed(
    request: &EmitRequest<'_>,
    mut identity: impl FnMut() -> Result<mvm_core::image_set::RepoIdentity, String>,
    inspected: impl FnOnce(&Path, &[ImageSetMember]),
) -> Result<(), LocalImageBuildError> {
    if request.builder_cache_contract == 0 || request.contract.files.is_empty() {
        return Err(refused(
            "positive builder cache contract and artifacts are required",
        ));
    }
    if super::path_is_within(request.out, request.images_root) {
        return Err(refused("output must be outside the images checkout"));
    }
    if request.out.exists()
        && (!request.out.is_dir()
            || std::fs::read_dir(request.out)
                .map_err(|e| io("reading", request.out, e))?
                .next()
                .is_some())
    {
        return Err(refused(
            "output already exists and is not an empty directory",
        ));
    }
    let before = identity().map_err(refused)?;
    super::read_contract_source(&request.images_root.join(super::BUILDER_BOOT_ABI_FILE))?;
    let boot_abi = super::checkout_builder_boot_abi(request.images_root)?;
    let mut compatibility = ImageSetCompatibility {
        guest_agent_protocol: None,
        builder_cache_contract: request.builder_cache_contract,
        builder_boot_abi: Some(boot_abi),
        base_image_contract: Some(BaseImageContract::LINUX_LAYER),
    };
    let mut locks = Vec::new();
    for lock in ["flake.lock", "kernel/flake.lock"] {
        locks.push(FlakeLockIdentity {
            reference: format!("mvm-images:{lock}"),
            lock_hash: digest(&request.images_root.join(lock))?,
        });
    }
    let parent = request
        .out
        .parent()
        .ok_or_else(|| refused("output has no parent"))?;
    let staging = tempfile::Builder::new()
        .prefix(".local-set-")
        .tempdir_in(parent)
        .map_err(|e| io("creating staging in", parent, e))?;
    let mut members: Vec<ImageSetMember> = Vec::new();
    for file in request.contract.files {
        let role = role(file.role)?;
        let name = if role == ImageSetRole::QemuWasmSmokePack {
            format!("{}-{}", file.role.replace('_', "-"), file.name)
        } else {
            format!(
                "{}-{}-{}",
                file.role.replace('_', "-"),
                request.arch,
                file.name
            )
        };
        let name = mvm_core::image_set::ArtifactName::new(name).map_err(refused)?;
        let path = staging.path().join(name.as_str());
        let (sha256, size) = copy_artifact(&request.built.join(file.name), &path)?;
        let format = match file.format {
            OutputFormat::Kernel => ArtifactFormat::Kernel(super::read_kernel_format(&path)?),
            OutputFormat::Fixed(format) => {
                serde_json::from_value(serde_json::Value::String(format.into())).map_err(refused)?
            }
        };
        let index = if let Some(index) = members.iter().position(|m| m.role == role) {
            index
        } else {
            members.push(ImageSetMember {
                role,
                target: if role == ImageSetRole::QemuWasmSmokePack {
                    MemberTarget::ArchIndependent
                } else {
                    MemberTarget::Arch(request.arch)
                },
                build_mode: None,
                source_fingerprint: None,
                boot_protocol: role.is_bootable().then_some(BootProtocol::LinuxDirect),
                artifacts: Vec::new(),
                required_capabilities: Vec::new(),
                pack_hash: None,
                sbom: None,
            });
            members.len() - 1
        };
        members[index].artifacts.push(MemberArtifact {
            name,
            format,
            sha256,
            size,
        });
    }
    for (name, capability) in request.contract.capabilities {
        let role = role(name)?;
        let member = members
            .iter_mut()
            .find(|m| m.role == role)
            .ok_or_else(|| refused("capability names a role without artifacts"))?;
        let capability = serde_json::from_value(serde_json::Value::String((*capability).into()))
            .map_err(refused)?;
        if !member.required_capabilities.contains(&capability) {
            member.required_capabilities.push(capability);
        }
    }
    if !members
        .iter()
        .any(|m| matches!(m.role, ImageSetRole::WorkloadRootfs(_)))
    {
        let declaration = request.images_root.join(super::BASE_IMAGE_CONTRACT_FILE);
        // A checkout older than the declaration carries no workload root to
        // contradict, so the set records none and is read as the legacy contract.
        if matches!(std::fs::symlink_metadata(&declaration), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
        {
            compatibility.base_image_contract = None;
        } else if super::read_contract_source(&declaration)?.trim() != "1" {
            return Err(refused("unsupported source base-image contract"));
        }
    }
    inspect_roots(&members, staging.path(), &compatibility)?;
    inspected(staging.path(), &members);
    if identity().map_err(refused)? != before {
        return Err(refused("checkout changed while the set was being recorded"));
    }
    verify_artifacts(&members, staging.path())?;
    let issued_at = match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(epoch) => Utc
            .timestamp_opt(epoch.parse().map_err(refused)?, 0)
            .single()
            .ok_or_else(|| refused("invalid SOURCE_DATE_EPOCH"))?,
        Err(std::env::VarError::NotPresent) => Utc::now()
            .with_nanosecond(0)
            .ok_or_else(|| refused("cannot normalize current timestamp"))?,
        Err(error) => return Err(refused(error)),
    };
    let manifest = ImageSetManifest {
        schema_version: mvm_core::image_set::IMAGE_SET_SCHEMA_VERSION,
        set_version: ImageSetVersion::new("0.0.0-local").map_err(refused)?,
        issued_at,
        producer: ImageSetProducer::LocalCheckouts(LocalCheckouts {
            images: before,
            mvm: None,
        }),
        mvm_source_commit: None,
        compatibility,
        nix_inputs: mvm_core::image_set::NixInputs {
            flake_locks: locks,
            source_revisions: Vec::new(),
        },
        revocation_channel: None,
        supersedes: None,
        members,
    };
    let mut bytes = serde_json::to_vec_pretty(&manifest).map_err(refused)?;
    bytes.push(b'\n');
    let path = staging
        .path()
        .join(mvm_core::image_set::LOCAL_SET_MANIFEST_NAME);
    std::fs::write(&path, bytes).map_err(|e| io("writing", &path, e))?;
    if request.out.exists() {
        std::fs::remove_dir(request.out)
            .map_err(|e| io("removing empty output", request.out, e))?;
    }
    std::fs::rename(staging.path(), request.out).map_err(|e| io("publishing", request.out, e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_source::{OutputFile, TargetContract};
    use mvm_core::arch::GuestArch;
    use mvm_core::image_set::{GitCommit, RepoIdentity, WorktreeState};

    const ROOT: OutputFile = OutputFile {
        name: "rootfs.ext4",
        role: "default_tenant_workload_rootfs",
        format: OutputFormat::Fixed("ext4"),
    };
    const ROOTLESS: OutputFile = OutputFile {
        name: "other.ext4",
        role: "rootless_tenant_workload_rootfs",
        format: OutputFormat::Fixed("ext4"),
    };
    const PARTIAL: OutputFile = OutputFile {
        name: "metadata.json",
        role: "builder_vm",
        format: OutputFormat::Fixed("json"),
    };
    const ROOT_CONTRACT: TargetContract = TargetContract {
        files: &[ROOT],
        capabilities: &[],
        set_roles: &[],
        needs_host_binaries: false,
    };
    const MIXED_CONTRACT: TargetContract = TargetContract {
        files: &[ROOT, ROOTLESS],
        capabilities: &[],
        set_roles: &[],
        needs_host_binaries: false,
    };
    const PARTIAL_CONTRACT: TargetContract = TargetContract {
        files: &[PARTIAL],
        capabilities: &[],
        set_roles: &[],
        needs_host_binaries: false,
    };

    fn identity() -> RepoIdentity {
        RepoIdentity {
            commit: GitCommit::new("a".repeat(40)).unwrap(),
            worktree: WorktreeState::Clean,
        }
    }

    fn root(marker: Option<&[u8]>, mode: u16) -> Vec<u8> {
        use mvm_fs::ext4::{Node, Owner};
        let mut nodes: Vec<_> = ["/etc", "/etc/mvm"]
            .into_iter()
            .map(|path| Node::Dir {
                path: path.into(),
                mode: 0o755,
                xattrs: Vec::new(),
                owner: Owner::ROOT,
            })
            .collect();
        if let Some(marker) = marker {
            nodes.push(Node::File {
                path: "/etc/mvm/base-image-contract".into(),
                mode,
                data: marker.into(),
                xattrs: Vec::new(),
                owner: Owner::ROOT,
            });
        }
        mvm_fs::ext4::build_image(nodes, &Default::default()).unwrap()
    }

    struct Fixture {
        temp: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let images = temp.path().join("images");
            std::fs::create_dir_all(images.join("images/builder-vm")).unwrap();
            std::fs::create_dir_all(images.join("kernel")).unwrap();
            std::fs::create_dir(temp.path().join("built")).unwrap();
            std::fs::write(images.join("images/builder-vm/boot-abi.nix"), "2\n").unwrap();
            std::fs::write(images.join("images/base-image-contract.nix"), "1\n").unwrap();
            for lock in ["flake.lock", "kernel/flake.lock"] {
                std::fs::write(images.join(lock), "{}\n").unwrap();
            }
            Self { temp }
        }

        fn emit(
            &self,
            contract: &TargetContract,
            observer: impl FnOnce(&Path, &[ImageSetMember]),
        ) -> Result<(), LocalImageBuildError> {
            emit_observed(
                &EmitRequest {
                    images_root: &self.temp.path().join("images"),
                    legacy_mvm_root: None,
                    arch: GuestArch::Aarch64,
                    builder_cache_contract: 1,
                    built: &self.temp.path().join("built"),
                    out: &self.temp.path().join("set"),
                    contract,
                },
                || Ok(identity()),
                observer,
            )
        }

        fn assert_cleaned(&self) {
            assert!(!self.temp.path().join("set").exists());
            assert_eq!(std::fs::read_dir(self.temp.path()).unwrap().count(), 2);
        }
    }

    #[test]
    fn supplied_roots_require_exact_bytes_and_mode_without_source_fallback() {
        for (marker, mode, accepted) in [
            (Some(b"1\n".as_slice()), 0o444, true),
            (None, 0o444, false),
            (Some(b"1".as_slice()), 0o444, false),
            (Some(b"2\n".as_slice()), 0o444, false),
            (Some(b"1\n".as_slice()), 0o644, false),
            (Some(b"1\n".as_slice()), 0o4444, false),
        ] {
            let fixture = Fixture::new();
            std::fs::write(
                fixture.temp.path().join("built/rootfs.ext4"),
                root(marker, mode),
            )
            .unwrap();
            // A supplied root is authoritative even if source compatibility is absent.
            std::fs::remove_file(
                fixture
                    .temp
                    .path()
                    .join("images/images/base-image-contract.nix"),
            )
            .unwrap();
            let result = fixture.emit(&ROOT_CONTRACT, |_, _| {});
            assert_eq!(
                result.is_ok(),
                accepted,
                "{marker:?} mode {mode:o}: {result:?}"
            );
            if !accepted {
                fixture.assert_cleaned();
            }
        }
    }

    #[test]
    fn malformed_root_and_mixed_contracts_refuse_and_cleanup() {
        let fixture = Fixture::new();
        std::fs::write(fixture.temp.path().join("built/rootfs.ext4"), b"not ext4").unwrap();
        assert!(fixture.emit(&ROOT_CONTRACT, |_, _| {}).is_err());
        fixture.assert_cleaned();
        std::fs::write(
            fixture.temp.path().join("built/rootfs.ext4"),
            root(Some(b"1\n"), 0o444),
        )
        .unwrap();
        std::fs::write(
            fixture.temp.path().join("built/other.ext4"),
            root(Some(b"2\n"), 0o444),
        )
        .unwrap();
        assert!(fixture.emit(&MIXED_CONTRACT, |_, _| {}).is_err());
        fixture.assert_cleaned();
    }

    #[test]
    fn partial_sets_alone_use_source_compatibility() {
        let fixture = Fixture::new();
        std::fs::write(fixture.temp.path().join("built/metadata.json"), b"{}").unwrap();
        std::fs::write(
            fixture
                .temp
                .path()
                .join("images/images/base-image-contract.nix"),
            b"2\n",
        )
        .unwrap();
        assert!(fixture.emit(&PARTIAL_CONTRACT, |_, _| {}).is_err());
        fixture.assert_cleaned();
        std::fs::write(
            fixture
                .temp
                .path()
                .join("images/images/base-image-contract.nix"),
            b"1\n",
        )
        .unwrap();
        fixture.emit(&PARTIAL_CONTRACT, |_, _| {}).unwrap();
        let manifest: ImageSetManifest = serde_json::from_slice(
            &std::fs::read(fixture.temp.path().join("set/image-set.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.schema_version, 3);
        assert_eq!(
            manifest.compatibility.base_image_contract,
            Some(BaseImageContract::LINUX_LAYER)
        );
        assert_eq!(
            manifest.compatibility.builder_boot_abi.unwrap().to_string(),
            "2"
        );
        assert!(manifest.producer.local_checkouts().unwrap().mvm.is_none());
        assert!(manifest.mvm_source_commit.is_none());
        assert!(manifest.compatibility.guest_agent_protocol.is_none());
    }

    #[test]
    fn a_partial_set_from_a_checkout_without_a_declaration_records_none() {
        let fixture = Fixture::new();
        std::fs::write(fixture.temp.path().join("built/metadata.json"), b"{}").unwrap();
        std::fs::remove_file(
            fixture
                .temp
                .path()
                .join("images/images/base-image-contract.nix"),
        )
        .unwrap();
        fixture.emit(&PARTIAL_CONTRACT, |_, _| {}).unwrap();
        let manifest: ImageSetManifest = serde_json::from_slice(
            &std::fs::read(fixture.temp.path().join("set/image-set.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.compatibility.base_image_contract, None);
    }

    #[test]
    fn copied_bytes_are_inspected_and_original_changes_do_not_change_the_set() {
        let fixture = Fixture::new();
        let source = fixture.temp.path().join("built/rootfs.ext4");
        let bytes = root(Some(b"1\n"), 0o444);
        std::fs::write(&source, &bytes).unwrap();
        fixture
            .emit(&ROOT_CONTRACT, |staging, members| {
                std::fs::write(&source, b"original changed").unwrap();
                assert_eq!(
                    std::fs::read(staging.join(members[0].artifacts[0].name.as_str())).unwrap(),
                    bytes
                );
            })
            .unwrap();
        assert_eq!(
            std::fs::read(
                fixture
                    .temp
                    .path()
                    .join("set/default-tenant-workload-rootfs-aarch64-rootfs.ext4")
            )
            .unwrap(),
            bytes
        );
    }

    #[test]
    fn post_inspection_staged_mutation_refuses_and_cleans_up() {
        let fixture = Fixture::new();
        std::fs::write(
            fixture.temp.path().join("built/rootfs.ext4"),
            root(Some(b"1\n"), 0o444),
        )
        .unwrap();
        let result = fixture.emit(&ROOT_CONTRACT, |staging, members| {
            let path = staging.join(members[0].artifacts[0].name.as_str());
            let mut bytes = std::fs::read(&path).unwrap();
            bytes[0] ^= 1;
            std::fs::write(path, bytes).unwrap();
        });
        assert!(result.unwrap_err().to_string().contains("artifact changed"));
        fixture.assert_cleaned();
    }

    #[test]
    fn changed_identity_refuses_and_cleans_up() {
        let fixture = Fixture::new();
        std::fs::write(
            fixture.temp.path().join("built/rootfs.ext4"),
            root(Some(b"1\n"), 0o444),
        )
        .unwrap();
        let images_root = fixture.temp.path().join("images");
        let repository = gix::init(&images_root).unwrap();
        let tree = repository.empty_tree();
        let tree_id = tree.id;
        let signature =
            gix::actor::SignatureRef::from_bytes(b"Test <test@example.com> 1 +0000").unwrap();
        repository
            .commit_as(
                signature,
                signature,
                "HEAD",
                "fixture",
                tree_id,
                std::iter::empty::<gix::ObjectId>(),
            )
            .unwrap();
        let mut index = repository.index_from_tree(&tree_id).unwrap();
        index.write(gix::index::write::Options::default()).unwrap();

        let mut calls = 0;
        let result = emit_observed(
            &EmitRequest {
                images_root: &images_root,
                legacy_mvm_root: None,
                arch: GuestArch::Aarch64,
                builder_cache_contract: 1,
                built: &fixture.temp.path().join("built"),
                out: &fixture.temp.path().join("set"),
                contract: &ROOT_CONTRACT,
            },
            || {
                calls += 1;
                crate::image_source::git::probe_identity(&images_root)
            },
            |_, _| {
                std::fs::write(
                    images_root.join("images/builder-vm/boot-abi.nix"),
                    "mutated\n",
                )
                .unwrap();
            },
        );
        assert!(result.unwrap_err().to_string().contains("checkout changed"));
        assert_eq!(calls, 2);
        fixture.assert_cleaned();
    }
}
