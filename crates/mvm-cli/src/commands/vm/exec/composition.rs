//! Assemble a development-only local bundle; the ordinary run path admits it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use mvm_build::published_image_set::PublishedImageSet;
use mvm_build::runtime_layer::{
    ResolvedComposableLock, compose_authored_candidate, compose_local_authored_candidate,
};
use mvm_client::bundle::{BundleExportInputs, BundleSigner, HostBundleSigner, PostureInputs};
use mvm_client::portable_boot_assets::PreparedPortableBootAssets;
use mvm_client::registry_application::discovery::resolve_runtime_layer_pin;
use mvm_contract::pack_spec::PackTarget;
use mvm_core::arch::GuestArch;
use mvm_core::image_set::WorkloadImageProfile;
use mvm_core::packs::Sha256Hex;
use mvm_core::plan::bundle::{
    BundleMember, BundleOrigin, EnvironmentDescriptor, EnvironmentEntrypoint, EnvironmentPolicy,
    FsTrustStore, LocalBundleTrustStore, LocalComposition, LocalCompositionLayer, bundle_origin,
    verify_bundle_file,
};
use mvm_core::plan::types::{BuildProvenance, InputKind};
use mvm_core::registry_pack::runtime_layer::{
    VerifiedRuntimeLayerInputs, resolve_requested_runtime_layers,
};
use mvm_core::registry_pack::{AuthenticatedRegistryManifest, PackPin, PackReference};
use mvm_core::security::AgentProfile;
use mvm_sdk::pack::composable::{ComposablePackSpec, parse_toml, prepare_composable_application};

use crate::pack_registry::{self, PackIndexEntry, PackRegistryConfig};

/// Retains the unpublished local archive through verification and launch.
pub(super) struct PreparedComposition {
    archive: PathBuf,
    private: mvm_client::launch::transient_composition::TransientComposition,
}

impl PreparedComposition {
    pub(super) fn archive(&self) -> &Path {
        &self.archive
    }

    pub(super) fn consume(
        &mut self,
    ) -> Result<mvm_client::launch::transient_composition::TransientBoot<'_>> {
        self.private.consume()
    }

    pub(super) fn retain_on_error(&mut self) -> Option<PathBuf> {
        self.private.retain_on_error()
    }
}

pub(super) enum Base<'a> {
    SignedDefault,
    #[cfg(feature = "pr-test-synthetic-base")]
    Synthetic {
        fixture: mvm_build::pr_test_synthetic_base::PrTestSyntheticBase,
        #[cfg(feature = "pr-test-guest-runtime")]
        pr_test: PrTestInput<'a>,
    },
    Local {
        manifest: &'a Path,
        kernel: &'a Path,
        tar: &'a Path,
        #[cfg(feature = "pr-test-guest-runtime")]
        pr_test: Option<PrTestInput<'a>>,
    },
}

#[cfg(feature = "pr-test-guest-runtime")]
#[derive(Clone, Copy)]
pub(super) struct PrTestInput<'a> {
    pub directory: &'a Path,
    pub pull_request: u64,
}

pub(super) fn prepare(path: &Path, base: Base<'_>) -> Result<PreparedComposition> {
    let archive = prepare_archive(path, base)?;
    let private = mvm_client::launch::transient_composition::TransientComposition::stage(&archive)?;
    Ok(PreparedComposition { archive, private })
}

/// Verify and cache composition data without granting a boot capability.
pub(super) fn prepare_archive(path: &Path, base: Base<'_>) -> Result<PathBuf> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file() && metadata.len() <= 64 * 1024,
        "composition recipe must be a regular file no larger than 64 KiB"
    );
    let spec = parse_toml(&std::fs::read_to_string(path)?)?;
    let directory = path.parent().context("composition recipe has no parent")?;
    let arch = match spec.target {
        PackTarget::X86_64Linux => GuestArch::X86_64,
        PackTarget::Aarch64Linux => GuestArch::Aarch64,
    };
    ensure!(
        arch == GuestArch::host(),
        "composition target differs from host architecture"
    );
    let registry = PackRegistryConfig::load();
    let index = if spec.runtimes.is_empty() {
        Vec::new()
    } else {
        pack_registry::fetch_index(&registry)?
    };
    let inputs = resolve_inputs(&spec, &registry, &index, arch)?;
    let ordered: Vec<&VerifiedRuntimeLayerInputs> = {
        let descriptors: Vec<_> = inputs
            .iter()
            .map(|input| input.archive().descriptor().clone())
            .collect();
        resolve_requested_runtime_layers(&spec, &descriptors)?
            .iter()
            .map(|selected| {
                inputs
                    .iter()
                    .find(|input| {
                        input.archive().descriptor().manifest_sha256() == selected.manifest_sha256()
                    })
                    .context("resolved runtime layer is not retained")
            })
            .collect::<Result<_>>()?
    };
    let profile = WorkloadImageProfile::DefaultTenant;
    #[cfg(feature = "pr-test-guest-runtime")]
    let pr_test = match &base {
        Base::SignedDefault => None,
        #[cfg(feature = "pr-test-synthetic-base")]
        Base::Synthetic { pr_test, .. } => Some(*pr_test),
        Base::Local { pr_test, .. } => *pr_test,
    };
    #[cfg(feature = "pr-test-synthetic-base")]
    let synthetic = match &base {
        Base::Synthetic { fixture, .. } => Some(fixture),
        Base::SignedDefault | Base::Local { .. } => None,
    };
    let local = match &base {
        Base::SignedDefault => None,
        #[cfg(feature = "pr-test-synthetic-base")]
        Base::Synthetic { fixture, .. } => {
            let verified = fixture.verify(arch)?;
            Some((
                verified.manifest_path,
                verified.manifest,
                verified.kernel,
                verified.tar,
            ))
        }
        Base::Local {
            manifest,
            kernel,
            tar,
            ..
        } => {
            let metadata = std::fs::symlink_metadata(manifest)?;
            ensure!(
                metadata.file_type().is_file()
                    && metadata.len() <= mvm_core::plan::bundle::MAX_IMAGE_SET_MANIFEST_BYTES,
                "local base manifest must be a bounded regular file"
            );
            for input in [kernel, tar] {
                ensure!(
                    std::fs::symlink_metadata(input)?.file_type().is_file(),
                    "local base kernel and tar must be regular, not links"
                );
            }
            Some((
                manifest.to_path_buf(),
                std::fs::read(manifest)?,
                std::fs::canonicalize(kernel)?,
                std::fs::canonicalize(tar)?,
            ))
        }
    };
    let images = if local.is_none() {
        Some(PublishedImageSet::acquire_workload()?)
    } else {
        None
    };
    let tree = if let Some((_, manifest, kernel, tar)) = &local {
        compose_local_authored_candidate(&spec, manifest, kernel, tar, profile, &ordered)?
    } else {
        compose_authored_candidate(
            &spec,
            images.as_ref().context("signed base was not acquired")?,
            profile,
            &ordered,
        )?
    };
    let prepared = prepare_composable_application(&spec, directory)?;
    prepared.reverify()?;
    let archive_sha = Sha256Hex::new(prepared.archive_sha256())?;
    let source_sha = Sha256Hex::new(prepared.source_sha256())?;
    let application = tree
        .with_application_archive(prepared.archive_bytes(), &archive_sha)?
        .with_authored_entrypoint(&spec)?;
    let lock = application.development_lock(&spec, &source_sha, env!("MVM_SOURCE_COMMIT"))?;
    let lock_bytes = serde_json::to_vec(&lock)?;
    let lock_sha = Sha256Hex::from_bytes(&lock_bytes);
    let filesystem_identity = lock.filesystem_identity()?;
    #[cfg(feature = "pr-test-guest-runtime")]
    let pr_test_proof = if let Some(input) = pr_test {
        let name = mvm_build::guest_bins::guest_bins_archive_name(env!("CARGO_PKG_VERSION"));
        let archive = input.directory.join(&name);
        let proof = mvm_core::protocol::runtime_release::PrTestRuntimeProof {
            input: mvm_core::protocol::runtime_release::RuntimeReleaseProof {
                archive: archive.clone(),
                checksum: input.directory.join(format!("{name}.sha256")),
                signature_bundle: input.directory.join(format!("{name}.bundle")),
                archive_sha256: mvm_core::crypto::image_verify::sha256_file(&archive)?,
                version: env!("CARGO_PKG_VERSION").into(),
                arch,
            },
            pull_request: input.pull_request,
        };
        mvm_build::guest_runtime::evidence::verify_pr_test_runtime_proof(
            &proof,
            env!("CARGO_PKG_VERSION"),
            arch,
        )?;
        Some(proof)
    } else {
        None
    };
    // Local source custody is path-bound, even when two paths have identical bytes.
    let cache_sha = if let Some((_, _, _, tar)) = &local {
        #[cfg(feature = "pr-test-guest-runtime")]
        let ordinary = if let Some(proof) = &pr_test_proof {
            Sha256Hex::from_bytes(
                &[
                    lock_bytes.as_slice(),
                    tar.as_os_str().as_encoded_bytes(),
                    &proof.pull_request.to_be_bytes(),
                    proof.input.archive_sha256.as_bytes(),
                ]
                .concat(),
            )
        } else {
            Sha256Hex::from_bytes(
                &[lock_bytes.as_slice(), tar.as_os_str().as_encoded_bytes()].concat(),
            )
        };
        #[cfg(not(feature = "pr-test-guest-runtime"))]
        let ordinary = Sha256Hex::from_bytes(
            &[lock_bytes.as_slice(), tar.as_os_str().as_encoded_bytes()].concat(),
        );
        #[cfg(feature = "pr-test-synthetic-base")]
        {
            if let Some(fixture) = synthetic {
                Sha256Hex::from_bytes(
                    &[
                        b"pr-test-synthetic-base".as_slice(),
                        ordinary.as_str().as_bytes(),
                        &fixture.pull_request().to_be_bytes(),
                    ]
                    .concat(),
                )
            } else {
                ordinary
            }
        }
        #[cfg(not(feature = "pr-test-synthetic-base"))]
        ordinary
    } else {
        lock_sha.clone()
    };
    let cache = PathBuf::from(mvm_core::config::mvm_cache_dir()).join("compositions");
    mvm_core::config::create_private_dir(&cache)?;
    let target = cache.join(format!("{}.mvmpkg", cache_sha.as_str()));
    let reverify_inputs = || -> Result<()> {
        prepared.reverify()?;
        #[cfg(feature = "pr-test-synthetic-base")]
        if let Some(fixture) = synthetic {
            let current = fixture.verify(arch)?;
            let (_, original, kernel, tar) = local
                .as_ref()
                .context("synthetic base selection was lost")?;
            ensure!(
                current.manifest == *original && current.kernel == *kernel && current.tar == *tar,
                "PR synthetic base selection changed before use"
            );
        }
        #[cfg(feature = "pr-test-guest-runtime")]
        if let Some(proof) = &pr_test_proof {
            mvm_build::guest_runtime::evidence::verify_pr_test_runtime_proof(
                proof,
                env!("CARGO_PKG_VERSION"),
                arch,
            )?;
        }
        for input in &inputs {
            mvm_core::registry_pack::runtime_layer::require_offline_runtime_policy(input)?;
        }
        if let Some((manifest_path, original, kernel, tar)) = &local {
            let metadata = std::fs::symlink_metadata(manifest_path)?;
            ensure!(
                metadata.file_type().is_file()
                    && metadata.len() == original.len() as u64
                    && std::fs::read(manifest_path)? == *original,
                "local base manifest changed before signing"
            );
            let declared: mvm_core::image_set::ImageSetManifest = serde_json::from_slice(original)?;
            mvm_core::image_set::check_workload_protocol_compatibility(
                &declared.compatibility,
                &mvm_build::stage0_kernel::current_image_set_protocol_support(),
            )?;
            let (selected_kernel, selected_tar) =
                mvm_core::plan::bundle::select_local_development_source(&declared, arch, profile)?;
            for (file, artifact) in [(kernel, selected_kernel), (tar, selected_tar)] {
                ensure!(
                    std::fs::symlink_metadata(file)?.file_type().is_file()
                        && std::fs::metadata(file)?.len() == artifact.size
                        && mvm_core::crypto::image_verify::sha256_file(file)?
                            == artifact.sha256.as_str(),
                    "selected local base input changed before signing"
                );
            }
        } else {
            images
                .as_ref()
                .context("signed base was not acquired")?
                .retained_publisher_proof()?;
        }
        Ok(())
    };
    if std::fs::symlink_metadata(&target).is_ok() {
        reverify_inputs()?;
        verify_cached_bundle(
            &target,
            &lock_bytes,
            local.as_ref().map(|(_, _, _, tar)| tar.as_path()),
            #[cfg(feature = "pr-test-guest-runtime")]
            pr_test_proof
                .as_ref()
                .map(|proof| (proof.pull_request, proof.input.archive_sha256.as_str())),
            #[cfg(not(feature = "pr-test-guest-runtime"))]
            None,
        )?;
        eprintln!(
            "[mvm] authenticated cached composition {}",
            cache_sha.as_str()
        );
        return Ok(target);
    }
    #[cfg(feature = "pr-test-guest-runtime")]
    let boot = if let Some(input) = pr_test {
        PreparedPortableBootAssets::acquire_pr_test_local(
            arch,
            input.directory,
            input.pull_request,
        )?
    } else if local.is_some() {
        PreparedPortableBootAssets::acquire_local(arch)?
    } else {
        PreparedPortableBootAssets::acquire(arch)?
    };
    #[cfg(not(feature = "pr-test-guest-runtime"))]
    let boot = if local.is_some() {
        PreparedPortableBootAssets::acquire_local(arch)?
    } else {
        PreparedPortableBootAssets::acquire(arch)?
    };
    if local.is_none() {
        ensure!(
            boot.image_set_manifest_sha256() == lock.base_manifest_sha256(),
            "composition and signed CLI boot closure selected different Linux roots"
        );
    }
    reverify_inputs()?;
    let prior = previous_filesystem_bundle(&cache, &filesystem_identity)?;
    let reused = prior
        .map(|(verified, archive)| verified.extract_rootfs_with_verity(archive))
        .transpose()?;
    let directory = tempfile::tempdir()?;
    mvm_core::config::create_private_dir(directory.path())?;
    let image = reused.as_ref().map_or_else(
        || directory.path().join("rootfs.ext4"),
        |root| root.rootfs.clone(),
    );
    let (roothash, verity_path) = if let Some(root) = &reused {
        (root.roothash.clone(), root.verity.clone())
    } else {
        let materialized = application.materialize_candidate(&image)?;
        (
            materialized
                .verity_root_hash
                .context("composed rootfs did not produce dm-verity")?,
            directory.path().join("rootfs.verity"),
        )
    };
    let output_sha256 = mvm_core::crypto::image_verify::sha256_file(&image)?;
    let mut sidecar = mvm_build::builder_vm::GuestSidecar {
        name: spec.identity.name.clone(),
        accessible: false,
        sealed: true,
        entrypoint_kind: "command".to_owned(),
        entrypoint_argv: spec.entrypoint.clone(),
        init_system: "cli-initramfs".to_owned(),
        expected_boot_ms: 300,
        agent_binary: String::new(),
        rootless_entrypoint: true,
        hypervisor: "firecracker".to_owned(),
        overlay_aware: true,
        runtime_lean: true,
        image_tag: String::new(),
        source: String::new(),
        built_at: String::new(),
        protocol_version: 0,
        generator_rev: String::new(),
        libc: Default::default(),
    };
    if let Some(images) = &images {
        sidecar = images.workload_sidecar(&spec.identity.name, spec.entrypoint.clone());
    }
    sidecar.write_to_dir(directory.path())?;
    let (member, evidence) = retain_evidence(directory.path(), &lock_bytes, &ordered)?;
    let supplemental: Vec<(&str, &Path)> = evidence
        .iter()
        .map(|(name, path)| (name.as_str(), path.as_path()))
        .collect();
    let environment = EnvironmentDescriptor {
        descriptor_version: mvm_core::plan::bundle::ENVIRONMENT_DESCRIPTOR_VERSION,
        pack: Some(spec.identity.clone()),
        target: spec.target,
        entrypoint: EnvironmentEntrypoint {
            argv: spec.entrypoint.clone(),
            working_dir: None,
        },
        resources: Some(spec.resources.clone()),
        policy: Some(EnvironmentPolicy {
            allow_hosts: Vec::new(),
            request_budget: None,
        }),
        volumes: Vec::new(),
        secret_slots: Vec::new(),
        capabilities: Vec::new(),
        services: Vec::new(),
    };
    let verity = std::fs::read(&verity_path)?;
    let arch_label = arch.to_string();
    let kernel = local
        .as_ref()
        .map_or_else(|| boot.kernel_path(), |(_, _, kernel, _)| kernel.as_path())
        .to_str()
        .context("kernel path is not UTF-8")?;
    let rootfs = image.to_str().context("rootfs path is not UTF-8")?;
    let initrd = boot
        .initramfs_path()
        .to_str()
        .context("initramfs path is not UTF-8")?;
    let mut export = BundleExportInputs::new(kernel, rootfs, &arch_label, &target)
        .initrd(initrd)
        .verity(&verity, &roothash)
        .profile("dev")
        .resources(spec.resources.cpu_cores.into(), spec.resources.memory_mb)
        .posture(PostureInputs::new(AgentProfile::Dev))
        .environment(environment)
        .provenance(BuildProvenance {
            input_kind: InputKind::LocalProject,
            input_ref: spec.identity.name.clone(),
            lock_digest: Some(lock_sha.as_str().to_owned()),
            builder_id: None,
            artifacts: Default::default(),
        })
        .local_build();
    export.local_composition = Some(member);
    export.supplemental_artifacts = &supplemental;
    reverify_inputs()?;
    let signed = if let Some((_, manifest_bytes, _, tar)) = &local {
        let source: mvm_core::image_set::ImageSetManifest = serde_json::from_slice(manifest_bytes)?;
        let member = source
            .members
            .iter()
            .find(|member| {
                member.role == mvm_core::image_set::ImageSetRole::WorkloadRootfs(profile)
                    && member.target == mvm_core::image_set::MemberTarget::Arch(arch)
            })
            .context("selected local base root is missing")?;
        let tar_artifact = member
            .artifacts
            .iter()
            .find(|artifact| artifact.format == mvm_core::image_set::ArtifactFormat::TarGz)
            .context("selected local composition tar is missing")?;
        let proof = mvm_core::plan::bundle::LocalDevelopmentBaseProof {
            manifest_artifact: "boot-image-set.json".to_owned(),
            composition_tar_sha256: tar_artifact.sha256.as_str().to_owned(),
            composition_tar_size: tar_artifact.size,
            composition_tar_path: tar
                .to_str()
                .context("local tar path is not UTF-8")?
                .to_owned(),
        };
        boot.stage_local(&export, &HostBundleSigner::load()?, manifest_bytes, proof)?
    } else {
        boot.stage(&export, &HostBundleSigner::load()?)?
    };
    reverify_inputs()?;
    ensure!(
        mvm_core::crypto::image_verify::sha256_file(&image)? == output_sha256,
        "composed output changed before local signing"
    );
    if let Err(error) = signed.publish() {
        if std::fs::symlink_metadata(&target).is_err() {
            return Err(error);
        }
        reverify_inputs()?;
    }
    reverify_inputs()?;
    record_filesystem_bundle(&cache, &filesystem_identity, &cache_sha)?;
    verify_cached_bundle(
        &target,
        &lock_bytes,
        local.as_ref().map(|(_, _, _, tar)| tar.as_path()),
        #[cfg(feature = "pr-test-guest-runtime")]
        pr_test_proof
            .as_ref()
            .map(|proof| (proof.pull_request, proof.input.archive_sha256.as_str())),
        #[cfg(not(feature = "pr-test-guest-runtime"))]
        None,
    )?;
    if reused.is_some() {
        eprintln!(
            "[mvm] reused verified filesystem {} for composition {}",
            filesystem_identity.as_str(),
            cache_sha.as_str()
        );
    } else {
        eprintln!(
            "[mvm] assembled and cached composition {}",
            cache_sha.as_str()
        );
    }
    Ok(target)
}

fn verified_local_bundle(path: &Path) -> Result<mvm_core::plan::bundle::VerifiedBundleFile> {
    ensure!(
        std::fs::symlink_metadata(path)?.file_type().is_file(),
        "composed cache entry must be a regular file"
    );
    let signer = HostBundleSigner::load()?;
    let id = signer.key_id();
    let release = mvm_core::registry_pack::application_bundle::trust_for_installed_archive(
        FsTrustStore::default_path()?,
        path,
    );
    let trust = LocalBundleTrustStore::new(release, id.clone(), signer.verifying_key());
    let verified = verify_bundle_file(path, &trust)?;
    ensure!(
        bundle_origin(&verified.manifest, &id, trust.release()) == BundleOrigin::LocalBuild,
        "composed cache entry is not a host-signed local build"
    );
    Ok(verified)
}

fn previous_filesystem_bundle(
    cache: &Path,
    identity: &Sha256Hex,
) -> Result<Option<(mvm_core::plan::bundle::VerifiedBundleFile, std::fs::File)>> {
    let index = cache.join(format!("rootfs-{}.ref", identity.as_str()));
    let metadata = match std::fs::symlink_metadata(&index) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.file_type().is_file() && metadata.len() <= 128,
        "filesystem cache index must be a bounded regular file"
    );
    let entry = std::fs::read_to_string(&index)?;
    let digest = entry
        .strip_suffix(".mvmpkg\n")
        .context("filesystem cache index has an invalid archive name")?;
    let digest = Sha256Hex::new(digest.to_owned())?;
    let archive = cache.join(format!("{}.mvmpkg", digest.as_str()));
    let verified = verified_local_bundle(&archive)?;
    let member = verified
        .manifest
        .members
        .iter()
        .find_map(|member| match member {
            BundleMember::LocalComposition(member) => Some(member),
            _ => None,
        })
        .context("filesystem cache source has no signed composition lock")?;
    let artifact = verified
        .manifest
        .find_by_name(&member.lock_artifact)
        .context("filesystem cache source has no composition lock")?;
    ensure!(
        artifact.role == mvm_core::plan::bundle::ArtifactRole::Other,
        "filesystem cache source lock has the wrong artifact role"
    );
    let original: ResolvedComposableLock =
        serde_json::from_slice(&verified.read_small_verified_member(
            std::fs::File::open(&archive)?,
            &member.lock_artifact,
            1024 * 1024,
        )?)?;
    ensure!(
        original.filesystem_identity()? == *identity,
        "filesystem cache source differs from today's ordered filesystem inputs"
    );
    Ok(Some((verified, std::fs::File::open(archive)?)))
}

fn record_filesystem_bundle(cache: &Path, identity: &Sha256Hex, archive: &Sha256Hex) -> Result<()> {
    let index = cache.join(format!("rootfs-{}.ref", identity.as_str()));
    if std::fs::symlink_metadata(&index).is_ok() {
        ensure!(
            previous_filesystem_bundle(cache, identity)?.is_some(),
            "existing filesystem cache index has no verified source"
        );
        return Ok(());
    }
    let mut pending = tempfile::NamedTempFile::new_in(cache)?;
    std::io::Write::write_all(
        &mut pending,
        format!("{}.mvmpkg\n", archive.as_str()).as_bytes(),
    )?;
    pending.as_file().sync_all()?;
    match pending.persist_noclobber(&index) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            previous_filesystem_bundle(cache, identity)?;
            Ok(())
        }
        Err(error) => Err(error.error.into()),
    }
}

fn verify_cached_bundle(
    path: &Path,
    lock: &[u8],
    local_tar: Option<&Path>,
    pr_test_expected: Option<(u64, &str)>,
) -> Result<()> {
    let verified = verified_local_bundle(path)?;
    let member = verified
        .manifest
        .members
        .iter()
        .find_map(|member| match member {
            BundleMember::LocalComposition(member) => Some(member),
            _ => None,
        })
        .context("cached bundle has no composition evidence")?;
    let artifact = verified
        .manifest
        .find_by_name(&member.lock_artifact)
        .context("cached bundle has no composition lock")?;
    ensure!(
        artifact.role == mvm_core::plan::bundle::ArtifactRole::Other
            && verified.read_small_verified_member(
                std::fs::File::open(path)?,
                &member.lock_artifact,
                1024 * 1024,
            )? == lock,
        "cached composition differs from today's resolved signed inputs"
    );
    let selected_tar = verified
        .manifest
        .members
        .iter()
        .find_map(|member| match member {
            BundleMember::LocalDevelopmentBaseProof(proof) => {
                Some(proof.composition_tar_path.as_str())
            }
            _ => None,
        });
    ensure!(
        selected_tar.map(Path::new) == local_tar,
        "cached composition selected a different local base source"
    );
    let selected_pr_test = verified
        .manifest
        .members
        .iter()
        .find_map(|member| match member {
            BundleMember::EmbeddedCliBootAssets(runtime) => Some(runtime),
            _ => None,
        });
    ensure!(
        selected_pr_test.and_then(|runtime| runtime.pr_test_pull_request)
            == pr_test_expected.map(|(pull_request, _)| pull_request),
        "cached composition selected a different PR test runtime"
    );
    if let Some((_, digest)) = pr_test_expected {
        let runtime = selected_pr_test.context("cached PR test runtime declaration missing")?;
        ensure!(
            verified
                .manifest
                .find_by_name(&runtime.archive_artifact)
                .is_some_and(|artifact| artifact.sha256 == digest),
            "cached composition selected a different signed runtime archive"
        );
    }
    Ok(())
}

fn resolve_inputs(
    spec: &ComposablePackSpec,
    config: &PackRegistryConfig,
    index: &[PackIndexEntry],
    arch: GuestArch,
) -> Result<Vec<VerifiedRuntimeLayerInputs>> {
    let mut pending: Vec<PackPin> = spec
        .runtimes
        .iter()
        .map(|raw| {
            let requested: PackReference = raw.parse()?;
            let entry = index
                .iter()
                .find(|entry| entry.coordinate() == requested.coordinate_string())
                .with_context(|| {
                    format!("runtime {requested} is not in the signed-input catalog")
                })?;
            resolve_runtime_layer_pin(entry, &requested, &arch.to_string())
        })
        .collect::<Result<_>>()?;
    let mut seen = BTreeMap::new();
    let mut held = Vec::new();
    while let Some(pin) = pending.pop() {
        let name = pin.reference().coordinate_string();
        if let Some(existing) = seen.get(&name) {
            ensure!(existing == &pin, "conflicting versions of runtime {name}");
            continue;
        }
        ensure!(
            held.len() < 64,
            "runtime dependency closure exceeds 64 layers"
        );
        let input = pack_registry::acquire_runtime_layer(config, &pin)
            .with_context(|| format!("authenticating runtime {name}"))?;
        pending.extend(
            input
                .archive()
                .descriptor()
                .manifest()
                .runtime_layer
                .dependencies
                .iter()
                .cloned(),
        );
        seen.insert(name, pin);
        held.push(input);
    }
    Ok(held)
}

fn retain_evidence(
    directory: &Path,
    lock: &[u8],
    inputs: &[&VerifiedRuntimeLayerInputs],
) -> Result<(LocalComposition, Vec<(String, PathBuf)>)> {
    let mut files = Vec::with_capacity(1 + inputs.len() * 3);
    let mut layers = Vec::with_capacity(inputs.len());
    let mut write = |name: String, bytes: &[u8]| -> Result<()> {
        let path = directory.join(&name);
        std::fs::write(&path, bytes)?;
        files.push((name, path));
        Ok(())
    };
    let lock_artifact = "composition-lock.json".to_owned();
    write(lock_artifact.clone(), lock)?;
    for (index, input) in inputs.iter().enumerate() {
        let manifest_artifact = format!("runtime-{index}-manifest.json");
        let signature_artifact = format!("runtime-{index}-manifest.bundle");
        let group_artifact = format!("runtime-{index}-group.toml");
        let descriptor = input.archive().descriptor();
        write(manifest_artifact.clone(), descriptor.manifest_bytes())?;
        write(signature_artifact.clone(), descriptor.signature_bundle())?;
        write(
            group_artifact.clone(),
            input
                .policies()
                .group()
                .context("offline runtime has no signed group")?,
        )?;
        layers.push(LocalCompositionLayer {
            manifest_artifact,
            signature_artifact,
            group_artifact,
        });
    }
    Ok((
        LocalComposition {
            lock_artifact,
            layers,
        },
        files,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_only_preparation_refuses_oversized_recipes_before_cache_access() {
        let directory = tempfile::tempdir().expect("recipe directory");
        let recipe = directory.path().join("pack.toml");
        std::fs::write(&recipe, vec![b'x'; 64 * 1024 + 1]).expect("oversized recipe");
        let error = prepare_archive(&recipe, Base::SignedDefault)
            .expect_err("oversized recipe cannot become prepared data");
        assert!(
            error
                .to_string()
                .contains("regular file no larger than 64 KiB"),
            "{error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn data_only_preparation_refuses_symlink_recipes() {
        let directory = tempfile::tempdir().expect("recipe directory");
        let target = directory.path().join("target.toml");
        let recipe = directory.path().join("pack.toml");
        std::fs::write(&target, b"not parsed").expect("target");
        std::os::unix::fs::symlink(&target, &recipe).expect("linked recipe");
        let error = prepare_archive(&recipe, Base::SignedDefault)
            .expect_err("linked recipe cannot become prepared data");
        assert!(
            error
                .to_string()
                .contains("regular file no larger than 64 KiB"),
            "{error:#}"
        );
    }

    #[test]
    fn filesystem_index_is_only_a_hint_not_an_archive_authority() {
        let cache = tempfile::tempdir().expect("private cache");
        let identity = Sha256Hex::from_bytes(b"ordered filesystem inputs");
        let index = cache
            .path()
            .join(format!("rootfs-{}.ref", identity.as_str()));
        assert!(
            previous_filesystem_bundle(cache.path(), &identity)
                .expect("absent cache entry is a miss")
                .is_none()
        );
        for value in [
            "../other.mvmpkg\n".to_owned(),
            "A".repeat(64),
            format!("{}.mvmpkg\n", "a".repeat(64)),
        ] {
            std::fs::write(&index, &value).expect("write invalid hint");
            assert!(
                previous_filesystem_bundle(cache.path(), &identity).is_err(),
                "untrusted hint {value:?} must not authorize reuse"
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            std::fs::remove_file(&index).expect("remove invalid hint");
            symlink(cache.path().join("elsewhere"), &index).expect("link cache hint");
            assert!(
                previous_filesystem_bundle(cache.path(), &identity).is_err(),
                "a linked index cannot authorize a cached rootfs"
            );
        }
    }
}
