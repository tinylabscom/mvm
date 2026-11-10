//! Assemble a development-only local bundle; the ordinary run path admits it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use mvm_build::published_image_set::PublishedImageSet;
use mvm_build::runtime_layer::compose_authored_candidate;
use mvm_client::bundle::{BundleExportInputs, BundleSigner, HostBundleSigner, PostureInputs};
use mvm_client::portable_boot_assets::PreparedPortableBootAssets;
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
}

impl PreparedComposition {
    pub(super) fn archive(&self) -> &Path {
        &self.archive
    }
}

pub(super) fn prepare(path: &Path) -> Result<PreparedComposition> {
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
    let images = PublishedImageSet::acquire_workload()?;
    let profile = WorkloadImageProfile::DefaultTenant;
    let tree = compose_authored_candidate(&spec, &images, profile, &ordered)?;
    let prepared = prepare_composable_application(&spec, directory)?;
    prepared.reverify()?;
    let archive_sha = Sha256Hex::new(prepared.archive_sha256())?;
    let source_sha = Sha256Hex::new(prepared.source_sha256())?;
    let application = tree.with_application_archive(prepared.archive_bytes(), &archive_sha)?;
    let lock = application.development_lock(&spec, &source_sha, env!("MVM_SOURCE_COMMIT"))?;
    let lock_bytes = serde_json::to_vec(&lock)?;
    let lock_sha = Sha256Hex::from_bytes(&lock_bytes);
    let cache = PathBuf::from(mvm_core::config::mvm_cache_dir()).join("compositions");
    mvm_core::config::create_private_dir(&cache)?;
    let target = cache.join(format!("{}.mvmpkg", lock_sha.as_str()));
    let reverify_inputs = || -> Result<()> {
        prepared.reverify()?;
        for input in &inputs {
            mvm_core::registry_pack::runtime_layer::require_offline_runtime_policy(input)?;
        }
        images.retained_publisher_proof()?;
        Ok(())
    };
    if std::fs::symlink_metadata(&target).is_ok() {
        reverify_inputs()?;
        verify_cached_bundle(&target, &lock_bytes)?;
        eprintln!(
            "[mvm] authenticated cached composition {}",
            lock_sha.as_str()
        );
        return Ok(PreparedComposition { archive: target });
    }
    let boot = PreparedPortableBootAssets::acquire(arch)?;
    ensure!(
        boot.image_set_manifest_sha256() == lock.base_manifest_sha256(),
        "composition and signed CLI boot closure selected different Linux roots"
    );
    let directory = tempfile::tempdir()?;
    mvm_core::config::create_private_dir(directory.path())?;
    let image = directory.path().join("rootfs.ext4");
    let materialized = application.materialize_candidate(&image)?;
    let roothash = materialized
        .verity_root_hash
        .as_deref()
        .context("composed rootfs did not produce dm-verity")?;
    let output_sha256 = mvm_core::crypto::image_verify::sha256_file(&image)?;
    images
        .workload_sidecar(&spec.identity.name, spec.entrypoint.clone())
        .write_to_dir(directory.path())?;
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
    let verity = std::fs::read(directory.path().join("rootfs.verity"))?;
    let arch_label = arch.to_string();
    let kernel = boot
        .kernel_path()
        .to_str()
        .context("kernel path is not UTF-8")?;
    let rootfs = image.to_str().context("rootfs path is not UTF-8")?;
    let initrd = boot
        .initramfs_path()
        .to_str()
        .context("initramfs path is not UTF-8")?;
    let mut export = BundleExportInputs::new(kernel, rootfs, &arch_label, &target)
        .initrd(initrd)
        .verity(&verity, roothash)
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
    let signed = boot.stage(&export, &HostBundleSigner::load()?)?;
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
    verify_cached_bundle(&target, &lock_bytes)?;
    eprintln!(
        "[mvm] assembled and cached composition {}",
        lock_sha.as_str()
    );
    Ok(PreparedComposition { archive: target })
}

fn verify_cached_bundle(path: &Path, lock: &[u8]) -> Result<()> {
    ensure!(
        std::fs::symlink_metadata(path)?.file_type().is_file(),
        "composed cache entry must be a regular file"
    );
    let signer = HostBundleSigner::load()?;
    let id = signer.key_id();
    let release = FsTrustStore::default_path()?;
    let trust = LocalBundleTrustStore::new(release, id.clone(), signer.verifying_key());
    let verified = verify_bundle_file(path, &trust)?;
    ensure!(
        bundle_origin(&verified.manifest, &id, trust.release()) == BundleOrigin::LocalBuild,
        "composed cache entry is not a host-signed local build"
    );
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
            let selected =
                pack_registry::resolve_version_for_arch(entry, &requested, &arch.to_string())?;
            let version = entry
                .versions
                .iter()
                .find(|version| {
                    selected
                        .version()
                        .is_some_and(|selected| selected.as_str() == version.version)
                })
                .context("selected runtime has no advertised manifest digest")?;
            PackPin::new(selected, version.manifest_sha256.clone()).map_err(Into::into)
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
