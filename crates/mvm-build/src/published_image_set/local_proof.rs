//! Retained local provenance for the actual installed workload files.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use mvm_core::image_set::{
    ImageSetManifest, ImageSetRole, LocalCheckouts, LocalImageSet, LocalImageSetVerification,
    MemberTarget, WorkloadImageProfile,
};
use mvm_core::packs::Sha256Hex;

use crate::image_source::{CachedImageSet, LocalImageCacheKey, LocalImageCheckout};

const PROOF_DIRECTORY: &str = ".local-image-set";

fn proof_directory(directory: &Path) -> PathBuf {
    directory.join(PROOF_DIRECTORY)
}

pub fn local_workload_proof_path(directory: &Path) -> PathBuf {
    proof_directory(directory).join(mvm_core::image_set::LOCAL_SET_MANIFEST_NAME)
}

fn read_regular(path: &Path) -> Result<Vec<u8>> {
    ensure!(
        std::fs::symlink_metadata(path)?.file_type().is_file(),
        "local proof {} is not a regular file",
        path.display()
    );
    std::fs::read(path).with_context(|| format!("read local proof {}", path.display()))
}

/// Preserve the original manifest and advisory metadata before acquisition
/// stamps the installed sidecar. Boot artifacts are not copied into the proof:
/// verification must read the installed files the VMM will actually use.
pub fn retain_local_workload_proof(entry: &CachedImageSet, directory: &Path) -> Result<()> {
    let bytes = read_regular(&entry.dir.join(mvm_core::image_set::LOCAL_SET_MANIFEST_NAME))?;
    ensure!(
        Sha256Hex::from_bytes(&bytes) == entry.set.manifest_sha256,
        "local manifest changed after verification"
    );
    let record = read_regular(&entry.dir.join(crate::image_source::ENTRY_RECORD_NAME))?;
    crate::image_source::verify_local_cache_entry_record(
        &record,
        &entry.key,
        &entry.set.manifest_sha256,
    )
    .map_err(anyhow::Error::msg)?;
    let proof = proof_directory(directory);
    std::fs::create_dir_all(&proof)?;
    ensure!(
        std::fs::symlink_metadata(&proof)?.file_type().is_dir(),
        "local proof directory is not a directory"
    );
    for artifact in &entry.set.artifacts {
        if entry.set.manifest.members.iter().any(|member| {
            member.artifacts.iter().any(|declared| {
                declared.name == artifact.name
                    && matches!(
                        declared.format,
                        mvm_core::image_set::ArtifactFormat::Json
                            | mvm_core::image_set::ArtifactFormat::Text
                    )
            })
        }) {
            let metadata = read_regular(&artifact.path)?;
            ensure!(
                metadata.len() as u64 == artifact.size
                    && Sha256Hex::from_bytes(&metadata) == artifact.sha256,
                "original local metadata {} changed after verification",
                artifact.name
            );
            mvm_core::util::atomic_io::atomic_write_durable(
                &proof.join(artifact.name.as_str()),
                &metadata,
            )?;
        }
    }
    mvm_core::util::atomic_io::atomic_write_durable(
        &proof.join(crate::image_source::ENTRY_RECORD_NAME),
        &record,
    )?;
    // Publishing the manifest last makes partial preparation fail closed.
    mvm_core::util::atomic_io::atomic_write_durable(
        &proof.join(mvm_core::image_set::LOCAL_SET_MANIFEST_NAME),
        &bytes,
    )
}

/// Verify retained provenance and the actual installed files. A cache entry
/// may be evicted after install; the retained declaration remains sufficient,
/// but an advisory sidecar or a source fingerprint alone never is.
pub fn verify_local_workload_proof(
    checkout: &LocalImageCheckout,
    mvm_root: &Path,
    key: &LocalImageCacheKey,
    directory: &Path,
    profile: WorkloadImageProfile,
) -> Result<LocalImageSet> {
    checkout.reverify()?;
    ensure!(
        checkout.identity() == &key.images,
        "selected local checkout no longer matches the installed key"
    );
    let proof = proof_directory(directory);
    ensure!(
        std::fs::symlink_metadata(&proof)?.file_type().is_dir(),
        "local proof directory is not a directory"
    );
    let bytes = read_regular(&proof.join(mvm_core::image_set::LOCAL_SET_MANIFEST_NAME))?;
    let record = read_regular(&proof.join(crate::image_source::ENTRY_RECORD_NAME))?;
    crate::image_source::verify_local_cache_entry_record(
        &record,
        key,
        &Sha256Hex::from_bytes(&bytes),
    )
    .map_err(anyhow::Error::msg)?;
    let manifest: ImageSetManifest = serde_json::from_slice(&bytes)?;
    mvm_core::image_set::validate_structure(&manifest)?;
    let current = if manifest.schema_version == mvm_core::image_set::IMAGE_SET_SCHEMA_VERSION {
        LocalCheckouts {
            images: checkout.identity().clone(),
            mvm: None,
        }
    } else {
        checkout.current_checkouts(mvm_root)?
    };
    let paths = installed_paths(&manifest, directory, &proof, key, profile)?;
    let roles = [
        ImageSetRole::WorkloadKernel(profile),
        ImageSetRole::WorkloadRootfs(profile),
    ];
    let host = crate::stage0_kernel::current_image_set_protocol_support();
    let request = LocalImageSetVerification::new(&bytes, &proof, &current, key.arch)
        .require_roles(&roles)
        .with_mvm_checkout_rule(key.mvm_checkout_rule())
        .with_artifact_paths(&paths);
    let request = if manifest.schema_version == mvm_core::image_set::IMAGE_SET_SCHEMA_VERSION {
        request.with_host_protocols(&host)
    } else {
        request
    };
    let set = mvm_core::image_set::verify_local_image_set(&request)?;
    super::verify_base_image_contract(&directory.join("rootfs.ext4"), &set.manifest.compatibility)?;
    Ok(set)
}

fn installed_paths(
    manifest: &ImageSetManifest,
    directory: &Path,
    proof: &Path,
    key: &LocalImageCacheKey,
    profile: WorkloadImageProfile,
) -> Result<BTreeMap<String, PathBuf>> {
    ensure!(
        key.target.role == crate::image_source::ImageBuildRole::for_workload_profile(profile),
        "local proof target selects another workload profile"
    );
    let contract = crate::image_source::contract_for(&key.target)?;
    let required_boot_files: BTreeSet<_> = contract
        .files
        .iter()
        .filter(|file| {
            !matches!(
                file.format,
                crate::image_source::OutputFormat::Fixed("json" | "text")
            )
        })
        .map(|file| file.name)
        .collect();
    let mut paths = BTreeMap::new();
    let mut installed = BTreeSet::new();
    for member in &manifest.members {
        ensure!(
            member.target == MemberTarget::Arch(key.arch),
            "local proof selects another architecture"
        );
        ensure!(
            member.role == ImageSetRole::WorkloadKernel(profile)
                || member.role == ImageSetRole::WorkloadRootfs(profile),
            "local proof selects another workload profile or role"
        );
        ensure!(
            member.build_mode.is_none()
                || (key.target.attr.as_str() == "dev"
                    && member.build_mode == Some(mvm_core::image_set::MemberBuildMode::Dev)),
            "local proof build mode does not match the requested target"
        );
        for artifact in &member.artifacts {
            let path = if let Some(name) =
                super::installed_workload_artifact_name(member.role, artifact)?
            {
                ensure!(
                    installed.insert(name),
                    "local proof declares ambiguous installed artifact {name}"
                );
                directory.join(name)
            } else {
                proof.join(artifact.name.as_str())
            };
            ensure!(
                paths.insert(artifact.name.to_string(), path).is_none(),
                "local proof declares an ambiguous artifact name"
            );
        }
    }
    ensure!(
        installed == required_boot_files,
        "local proof does not declare the requested target's exact boot artifact set"
    );
    Ok(paths)
}
