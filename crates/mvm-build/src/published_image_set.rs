//! Acquisition boundary for the signed, locked `mvm-images` release.
//!
//! Every remote image consumer enters here before requesting a member. The
//! root manifest is digest-pinned, verified under the exact release identity,
//! parsed only afterwards, held to the complete-train and protocol contracts,
//! and finally used as the sole source of member artifact digests.

use std::path::Path;

use anyhow::{Context, Result, bail};
use mvm_core::arch::GuestArch;
use mvm_core::image_set::{
    ImageSetManifest, ImageSetRequirement, ImageSetRole, ImageTrainLock, MemberArtifact,
    MemberBuildMode, MemberTarget, ReleaseTag, WorkloadImageProfile, check_against_lock,
    check_protocol_compatibility, require_complete, validate_structure,
};
use mvm_core::packs::Sha256Hex;
use thiserror::Error;

#[cfg(any(test, feature = "test-support"))]
pub mod fixture;
mod local_proof;
mod member_cache;
pub use local_proof::{
    local_workload_proof_path, retain_local_workload_proof, verify_local_workload_proof,
};

pub use member_cache::{
    IMAGE_SET_MEMBER_CACHE_DIR, MemberVersion, SetMemberCache, SetMemberCacheError,
};

#[cfg(test)]
mod tests;

/// Download `url` to `dest`. A transport is trusted for delivery only: every
/// byte it hands back is checked against the lock or the signed root.
pub type Download = fn(&str, &Path) -> Result<()>;

/// Base URL for GitHub release-asset downloads.
///
/// Defaults to `https://github.com`. `MVM_UPDATE_DOWNLOAD_URL` overrides it for
/// hermetic tests and mirrors. Moving the host moves nothing the pins trust:
/// the root is still held to its locked digest and its signing identity.
pub fn github_download_base() -> String {
    if let Ok(base) = std::env::var("MVM_UPDATE_DOWNLOAD_URL")
        && !base.trim().is_empty()
    {
        eprintln!("[mvm] MVM_UPDATE_DOWNLOAD_URL set; using {base} (test path).");
        return base.trim().trim_end_matches('/').to_string();
    }
    String::from("https://github.com")
}

/// Where one image set is acquired from: the lock it must satisfy, the release
/// directory its assets are published under, and how bytes are fetched.
pub struct ImageSetSource {
    train: ImageTrainLock,
    base_url: String,
    download: Download,
}

impl ImageSetSource {
    /// The set this build pins, from its published release.
    pub fn locked() -> Self {
        let train = mvm_core::image_set::image_train_lock().clone();
        let base_url = format!(
            "{}/{}/releases/download/{}",
            github_download_base(),
            train.repository,
            train.image_set.release_tag
        );
        Self::new(train, base_url)
    }

    /// A set held to `train`, served from `base_url`.
    pub fn new(train: ImageTrainLock, base_url: String) -> Self {
        Self {
            train,
            base_url,
            download: curl,
        }
    }

    /// Fetch through `download` instead of the default quiet `curl`, e.g. a
    /// resumable transfer that reports progress on a terminal.
    #[must_use]
    pub fn with_download(mut self, download: Download) -> Self {
        self.download = download;
        self
    }
}

fn curl(url: &str, dest: &Path) -> Result<()> {
    crate::runtime_overlay::curl_download(url, dest).map_err(anyhow::Error::from)
}

/// Why one member artifact of a verified set could not be delivered.
#[derive(Debug, Error)]
pub enum ImageSetMemberError {
    /// The signed root declares no member for this role and target. The root
    /// is pinned, so this holds for as long as the build's lock does.
    #[error("signed image set {release_tag} has no {role}/{target} member")]
    NoMember {
        release_tag: ReleaseTag,
        role: ImageSetRole,
        target: MemberTarget,
    },
    /// The member exists but does not carry the artifact asked for.
    #[error("signed image set {release_tag} {role}/{target} has no artifact {name}")]
    NoArtifact {
        release_tag: ReleaseTag,
        role: ImageSetRole,
        target: MemberTarget,
        name: String,
    },
    #[error("download {url}: {reason}")]
    Download { url: String, reason: String },
    #[error("downloaded {name} is {actual} bytes, not the signed manifest's {expected}")]
    SizeMismatch {
        name: String,
        expected: u64,
        actual: u64,
    },
    #[error("downloaded {name} hashes to {actual}, not the signed manifest's {expected}")]
    DigestMismatch {
        name: String,
        expected: String,
        actual: String,
    },
    #[error("base-image contract refused for {name}: {reason}")]
    BaseImageContract { name: String, reason: String },
    #[error("workload acquisition does not authorize builder selection")]
    WorkloadOnly,
    #[error("io error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// A root manifest whose digest, publisher, completeness and compatibility
/// have all been verified. Member bytes are still untrusted until
/// [`Self::fetch_artifact`] checks them against their declaration.
pub struct PublishedImageSet {
    manifest: ImageSetManifest,
    manifest_bytes: Vec<u8>,
    root: Sha256Hex,
    release_tag: ReleaseTag,
    base_url: String,
    download: Download,
    workload_only: bool,
}

/// Original publisher and applied-feed evidence from one export preparation.
/// This authenticates the Linux root, not selected kernel bytes or a launch.
#[derive(Debug)]
pub struct RetainedPublisherProof {
    root: mvm_core::image_set::RetainedImageSetRootProof,
    revocations: mvm_core::image_set_revocation::RetainedImageSetRevocationProof,
}

impl RetainedPublisherProof {
    pub fn root(&self) -> &mvm_core::image_set::RetainedImageSetRootProof {
        &self.root
    }

    pub fn revocations(&self) -> &mvm_core::image_set_revocation::RetainedImageSetRevocationProof {
        &self.revocations
    }
}

impl PublishedImageSet {
    /// Acquire and verify the root object pinned by this build.
    pub fn acquire() -> Result<Self> {
        Self::acquire_from(ImageSetSource::locked())
    }

    /// Acquire and verify the root object `source` pins.
    pub fn acquire_from(source: ImageSetSource) -> Result<Self> {
        Self::acquire_scoped(source, false)
    }

    /// Acquire the pinned Linux set for workloads without requiring builder payload support.
    /// This does not grant authority to select builder artifacts.
    pub fn acquire_workload() -> Result<Self> {
        Self::acquire_workload_from(ImageSetSource::locked())
    }

    /// Acquire a workload-compatible root through the same authenticated acquisition pipeline.
    pub fn acquire_workload_from(source: ImageSetSource) -> Result<Self> {
        Self::acquire_scoped(source, true)
    }

    fn acquire_scoped(source: ImageSetSource, workload_only: bool) -> Result<Self> {
        let ImageSetSource {
            train,
            base_url,
            download,
        } = source;
        let lock = &train.image_set;
        let host = crate::stage0_kernel::current_image_set_protocol_support();
        if workload_only {
            mvm_core::image_set::check_workload_protocol_compatibility(&train.compatibility, &host)
        } else {
            mvm_core::image_set::check_declared_protocol_compatibility(&train.compatibility, &host)
        }
        .context("refuse an image lock incompatible with this host before acquisition")?;
        let staged = tempfile::NamedTempFile::new().context("create image-set manifest staging")?;
        let manifest_url = format!("{base_url}/{}", lock.manifest_asset);
        download(&manifest_url, staged.path())
            .with_context(|| format!("download locked image-set manifest from {manifest_url}"))?;
        let bytes = std::fs::read(staged.path()).context("read staged image-set manifest")?;

        let actual = Sha256Hex::from_bytes(&bytes);
        if actual != lock.manifest_sha256 {
            bail!(
                "locked image-set manifest digest mismatch: expected {}, got {}",
                lock.manifest_sha256.as_str(),
                actual.as_str()
            );
        }

        let signature_bundle = crate::release_signature::verify_release_archive_signature(
            &crate::release_signature::ReleaseSignatureRequest {
                base_url: &base_url,
                asset: lock.manifest_asset.as_str(),
                archive_path: staged.path(),
                version: lock.release_tag.version().as_str(),
                train: crate::release_signature::ReleaseTrain::ImageSet,
            },
        )
        .context("verify the locked image-set publisher identity")?;

        let manifest: ImageSetManifest = serde_json::from_slice(&bytes)
            .context("the signed image-set root is not a supported manifest")?;
        validate_structure(&manifest).context("validate signed image-set structure")?;
        check_against_lock(&manifest, &actual, lock).context("match signed image set to lock")?;
        require_complete(&manifest, &ImageSetRequirement::current_train())
            .context("refuse a partial image-set release")?;
        if workload_only {
            mvm_core::image_set::check_workload_protocol_compatibility(
                &manifest.compatibility,
                &host,
            )
        } else {
            check_protocol_compatibility(&manifest, &host)
        }
        .context("refuse an image set incompatible with this host")?;
        if !manifest.compatibility.same_contract(&train.compatibility) {
            bail!(
                "images.lock compatibility does not match the signed image-set manifest; run the pin-update workflow"
            );
        }

        if let Some(bundle) = signature_bundle {
            let requirement = ImageSetRequirement::current_train();
            let proof_cache = mvm_core::image_set::image_set_root_proof_cache();
            let request =
                mvm_core::image_set::ImageSetVerification::new(&bytes, &bundle, lock, &proof_cache)
                    .require(&requirement);
            let request = if workload_only {
                request.with_workload_protocols(&host)
            } else {
                request.with_host_protocols(&host)
            };
            mvm_core::image_set::cache_image_set_root(&proof_cache, &request)
                .context("retain authenticated image-set root for offline admission")?;
        }

        Ok(Self {
            manifest,
            manifest_bytes: bytes,
            root: actual,
            release_tag: lock.release_tag.clone(),
            base_url,
            download,
            workload_only,
        })
    }

    /// The cache members of this set are installed into, keyed by the digest
    /// of the root they were verified against.
    /// The verified root manifest. Read-only: every consumer that selects
    /// members goes through this type's methods so production selection
    /// rules (build mode, target) live in one place.
    pub fn manifest(&self) -> &ImageSetManifest {
        &self.manifest
    }

    /// Original authenticated manifest bytes, preserving the pinned digest.
    ///
    /// Portable bundles must embed these bytes rather than serialize the parsed
    /// manifest again: even a whitespace change would create a different root.
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    /// Capture the original canonical publisher proof for portable export.
    ///
    /// Re-reads the bounded proof cache, authenticates against the compiled
    /// lock and currently applied signed revocation feed, and owns those exact
    /// bytes. This does not select or authenticate a kernel stream and does
    /// not authorize a consumer launch.
    pub fn retained_publisher_proof(&self) -> Result<RetainedPublisherProof> {
        let revocations = mvm_core::image_set_revocation::ImageSetRevocationStore::in_mvm_home()
            .capture_applied_proof(chrono::Utc::now())
            .context("current signed image-set revocations required for portable kernel proof")?;
        let read_proof = if self.workload_only {
            mvm_core::image_set::read_cached_workload_image_set_root_proof
        } else {
            mvm_core::image_set::read_cached_image_set_root_proof
        };
        let proof = read_proof(
            &mvm_core::image_set::image_set_root_proof_cache(),
            &mvm_core::image_set::image_train_lock().image_set,
            &crate::stage0_kernel::current_image_set_protocol_support(),
            Some(revocations.verified()),
        )?;
        anyhow::ensure!(
            proof.root().manifest_sha256() == &self.root
                && proof.manifest_bytes() == self.manifest_bytes,
            "retained canonical publisher proof differs from the acquired Linux image set"
        );
        Ok(RetainedPublisherProof {
            root: proof,
            revocations,
        })
    }

    pub fn member_cache(&self) -> SetMemberCache {
        SetMemberCache::for_root(self.root.clone())
    }

    /// Materialize the curated default workload from members of the verified
    /// set. The root manifest is acquired and protocol-checked before this
    /// method can be called, so no member request can precede compatibility.
    pub fn fetch_default_workload(&self, arch: GuestArch, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create default image cache {}", dir.display()))?;
        let target = MemberTarget::Arch(arch);
        let roles = [
            ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant),
            ImageSetRole::WorkloadRootfs(WorkloadImageProfile::DefaultTenant),
        ];
        // Production build only: a set that also publishes the dev variant of
        // this base carries it as a second member per role/target with
        // `build_mode: dev`, and the dev slot selects it explicitly, never
        // through this fetch.
        let members: Vec<_> = self
            .manifest
            .members
            .iter()
            .filter(|member| {
                member.build_mode.is_none()
                    && roles.contains(&member.role)
                    && member.target == target
            })
            .collect();
        let artifact_count: usize = members.iter().map(|member| member.artifacts.len()).sum();
        if artifact_count != 4 {
            bail!(
                "signed image set declares {} default-workload artifacts for {arch}, expected 4",
                artifact_count
            );
        }
        for member in members {
            for artifact in &member.artifacts {
                let name = artifact.name.as_str();
                let destination = if self.manifest.schema_version
                    == mvm_core::image_set::IMAGE_SET_SCHEMA_VERSION
                {
                    dir.join(
                        installed_workload_artifact_name(member.role, artifact)?
                            .context("production workload contains unexpected advisory metadata")?,
                    )
                } else if name.contains("vmlinux") {
                    dir.join("vmlinux")
                } else if name.ends_with(".ext4") {
                    dir.join("rootfs.ext4")
                } else if name.ends_with(".verity") {
                    dir.join("rootfs.verity")
                } else if name.ends_with(".roothash") {
                    dir.join("rootfs.roothash")
                } else {
                    bail!("signed default-workload member contains unexpected artifact {name}");
                };
                self.fetch_artifact(artifact, &destination)?;
            }
        }

        // A base image provides no evidence about the separately attached runtime.
        let (protocol_version, init_system, agent_binary) = (0, "cli-initramfs", "");
        crate::builder_vm::GuestSidecar {
            name: "mvm-default-microvm".to_string(),
            accessible: false,
            sealed: true,
            entrypoint_kind: "command".to_string(),
            entrypoint_argv: Vec::new(),
            init_system: init_system.to_string(),
            expected_boot_ms: 300,
            agent_binary: agent_binary.to_string(),
            rootless_entrypoint: true,
            hypervisor: "firecracker".to_string(),
            overlay_aware: true,
            runtime_lean: true,
            image_tag: String::new(),
            source: String::new(),
            built_at: String::new(),
            protocol_version,
            generator_rev: self
                .manifest
                .mvm_source_commit
                .as_ref()
                .map_or_else(String::new, |commit| commit.as_str().to_string()),
            libc: Default::default(),
        }
        .write_to_dir(dir)
        .context("write default image sidecar derived from signed manifest")?;
        Ok(())
    }

    /// The `image-set/v*` release tag these members were published under.
    pub fn release_tag(&self) -> &ReleaseTag {
        &self.release_tag
    }

    /// Fetch the dev (accessible) variant of the default workload into `dir`
    /// — the dev-slot install a pair build produces: kernel, rootfs, and the
    /// meta sidecar. Only `build_mode: dev` members are selected; sets that
    /// predate the dev members, or whose dev rootfs member omits the meta
    /// artifact, refuse with [`ImageSetMemberError`] so the caller falls back
    /// to a local build.
    pub fn fetch_dev_workload(&self, arch: GuestArch, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create dev image cache {}", dir.display()))?;
        let target = MemberTarget::Arch(arch);
        let member = |role: ImageSetRole| {
            self.manifest
                .members
                .iter()
                .find(|member| {
                    member.build_mode == Some(MemberBuildMode::Dev)
                        && member.role == role
                        && member.target == target
                })
                .ok_or_else(|| ImageSetMemberError::NoMember {
                    release_tag: self.release_tag.clone(),
                    role,
                    target,
                })
        };
        let kernel = member(ImageSetRole::WorkloadKernel(
            WorkloadImageProfile::DefaultTenant,
        ))?;
        let rootfs = member(ImageSetRole::WorkloadRootfs(
            WorkloadImageProfile::DefaultTenant,
        ))?;
        let kernel_artifact =
            kernel
                .artifacts
                .first()
                .ok_or_else(|| ImageSetMemberError::NoArtifact {
                    release_tag: self.release_tag.clone(),
                    role: kernel.role,
                    target,
                    name: "dev kernel".to_string(),
                })?;
        let rootfs_artifact = rootfs
            .artifacts
            .iter()
            .find(|artifact| {
                artifact.format == mvm_core::image_set::ArtifactFormat::Ext4
                    || (self.manifest.schema_version
                        == mvm_core::image_set::LEGACY_IMAGE_SET_SCHEMA_VERSION
                        && artifact.name.as_str().ends_with(".ext4"))
            })
            .ok_or_else(|| ImageSetMemberError::NoArtifact {
                release_tag: self.release_tag.clone(),
                role: rootfs.role,
                target,
                name: "dev rootfs".to_string(),
            })?;
        let meta_artifact = rootfs
            .artifacts
            .iter()
            .find(|artifact| artifact.name.as_str().ends_with(".json"))
            .ok_or_else(|| ImageSetMemberError::NoArtifact {
                release_tag: self.release_tag.clone(),
                role: rootfs.role,
                target,
                name: "dev meta sidecar".to_string(),
            })?;
        self.fetch_artifact(kernel_artifact, &dir.join("vmlinux"))?;
        self.fetch_artifact(rootfs_artifact, &dir.join("rootfs.ext4"))?;
        self.fetch_artifact(meta_artifact, &dir.join("mvm-meta.json"))?;
        Ok(())
    }

    /// Find one artifact under its exact role and target.
    pub fn artifact(
        &self,
        role: ImageSetRole,
        target: MemberTarget,
        name: &str,
    ) -> Result<&MemberArtifact, ImageSetMemberError> {
        if self.workload_only && role == ImageSetRole::BuilderVm {
            return Err(ImageSetMemberError::WorkloadOnly);
        }
        let member = self
            .manifest
            .members
            .iter()
            .find(|member| {
                member.build_mode.is_none() && member.role == role && member.target == target
            })
            .ok_or_else(|| ImageSetMemberError::NoMember {
                release_tag: self.release_tag.clone(),
                role,
                target,
            })?;
        member
            .artifacts
            .iter()
            .find(|artifact| artifact.name.as_str() == name)
            .ok_or_else(|| ImageSetMemberError::NoArtifact {
                release_tag: self.release_tag.clone(),
                role,
                target,
                name: name.to_string(),
            })
    }

    /// Fetch the artifact `name` of the `role` member built for `arch` to
    /// `dest`, held to the signed root.
    pub fn fetch_member_artifact(
        &self,
        role: ImageSetRole,
        arch: GuestArch,
        name: &str,
        dest: &Path,
    ) -> Result<(), ImageSetMemberError> {
        let artifact = self.artifact(role, MemberTarget::Arch(arch), name)?;
        self.fetch_artifact(artifact, dest)
    }

    /// Download one declared artifact and hold both its size and digest to the
    /// signed root before returning its path to a caller.
    pub fn fetch_artifact(
        &self,
        artifact: &MemberArtifact,
        dest: &Path,
    ) -> Result<(), ImageSetMemberError> {
        if self.workload_only
            && self.manifest.members.iter().any(|member| {
                member.role == ImageSetRole::BuilderVm
                    && member
                        .artifacts
                        .iter()
                        .any(|candidate| candidate.name == artifact.name)
            })
        {
            return Err(ImageSetMemberError::WorkloadOnly);
        }
        let url = format!("{}/{}", self.base_url, artifact.name);
        (self.download)(&url, dest).map_err(|error| ImageSetMemberError::Download {
            url: url.clone(),
            reason: format!("{error:#}"),
        })?;
        let io_error = |source| ImageSetMemberError::Io {
            path: dest.display().to_string(),
            source,
        };
        let size = std::fs::metadata(dest).map_err(io_error)?.len();
        if size != artifact.size {
            let _ = std::fs::remove_file(dest);
            return Err(ImageSetMemberError::SizeMismatch {
                name: artifact.name.to_string(),
                expected: artifact.size,
                actual: size,
            });
        }
        let actual = mvm_core::crypto::image_verify::sha256_file(dest).map_err(io_error)?;
        if actual != artifact.sha256.as_str() {
            let _ = std::fs::remove_file(dest);
            return Err(ImageSetMemberError::DigestMismatch {
                name: artifact.name.to_string(),
                expected: artifact.sha256.as_str().to_string(),
                actual,
            });
        }
        if self.manifest.members.iter().any(|member| {
            matches!(member.role, ImageSetRole::WorkloadRootfs(_))
                && member.artifacts.contains(artifact)
                && artifact.format == mvm_core::image_set::ArtifactFormat::Ext4
        }) && let Err(error) = verify_base_image_contract(dest, &self.manifest.compatibility)
        {
            let _ = std::fs::remove_file(dest);
            return Err(ImageSetMemberError::BaseImageContract {
                name: artifact.name.to_string(),
                reason: format!("{error:#}"),
            });
        }
        Ok(())
    }
}

/// Check the root marker against the authenticated Linux-base declaration.
/// Legacy sets predate this marker; their retired guest range is not runtime evidence.
/// Reads the ext4 directly: no mount, extraction or guest symlink resolution.
pub use crate::base_image_contract::verify_base_image_contract;

/// Recheck an installed workload against the pinned authenticated root without
/// acquiring anything. Historical caches retain their legacy boot behavior.
pub fn verify_cached_default_workload(
    directory: &Path,
    arch: GuestArch,
    build_mode: Option<MemberBuildMode>,
) -> Result<()> {
    let train = mvm_core::image_set::image_train_lock();
    if train.compatibility.base_image_contract.is_none() {
        return Ok(());
    }
    let host = crate::stage0_kernel::current_image_set_protocol_support();
    mvm_core::image_set::check_workload_protocol_compatibility(&train.compatibility, &host)?;
    let root = mvm_core::image_set::read_cached_workload_image_set_root(
        &mvm_core::image_set::image_set_root_proof_cache(),
        &train.image_set,
        &host,
        None,
    )?;
    verify_cached_compatibility_binding(&train.compatibility, &root.manifest().compatibility)?;
    verify_installed_workload_files(
        root.manifest(),
        directory,
        arch,
        WorkloadImageProfile::DefaultTenant,
        build_mode,
    )
}

fn verify_cached_compatibility_binding(
    expected: &mvm_core::image_set::ImageSetCompatibility,
    actual: &mvm_core::image_set::ImageSetCompatibility,
) -> Result<()> {
    if !actual.same_contract(expected) {
        bail!("cached authenticated image-set compatibility does not match images.lock");
    }
    Ok(())
}

fn installed_workload_artifact_name(
    role: ImageSetRole,
    artifact: &MemberArtifact,
) -> Result<Option<&'static str>> {
    use mvm_core::image_set::ArtifactFormat;
    if matches!(role, ImageSetRole::WorkloadKernel(_)) {
        anyhow::ensure!(
            matches!(artifact.format, ArtifactFormat::Kernel(_)),
            "workload kernel is not a kernel artifact"
        );
        return Ok(Some("vmlinux"));
    }
    anyhow::ensure!(
        matches!(role, ImageSetRole::WorkloadRootfs(_)),
        "selected artifact is not a workload root"
    );
    match artifact.format {
        ArtifactFormat::Ext4 => Ok(Some("rootfs.ext4")),
        ArtifactFormat::VerityHashTree => Ok(Some("rootfs.verity")),
        ArtifactFormat::VerityRootHash => Ok(Some("rootfs.roothash")),
        ArtifactFormat::Json | ArtifactFormat::Text => Ok(None),
        ArtifactFormat::Kernel(_) | ArtifactFormat::TarGz => {
            bail!("unexpected workload root artifact format")
        }
    }
}

fn verify_installed_workload_files(
    manifest: &ImageSetManifest,
    directory: &Path,
    arch: GuestArch,
    profile: WorkloadImageProfile,
    build_mode: Option<MemberBuildMode>,
) -> Result<()> {
    let mut kernel_seen = false;
    let mut root_seen = false;
    for member in manifest.members.iter().filter(|member| {
        member.target == MemberTarget::Arch(arch) && member.build_mode == build_mode
            && matches!(member.role, ImageSetRole::WorkloadKernel(p) | ImageSetRole::WorkloadRootfs(p) if p == profile)
    }) {
        for artifact in &member.artifacts {
            let Some(installed) = installed_workload_artifact_name(member.role, artifact)? else {
                // Acquisition stamps advisory metadata; rewritten fields
                // are not authenticated boot bytes.
                continue;
            };
            if installed == "vmlinux" {
                anyhow::ensure!(!kernel_seen, "selected workload declares more than one kernel artifact");
                kernel_seen = true;
            } else if installed == "rootfs.ext4" {
                anyhow::ensure!(!root_seen, "selected workload declares more than one root filesystem");
                root_seen = true;
            }
            let path = directory.join(installed);
            let metadata = std::fs::symlink_metadata(&path)?;
            if !metadata.file_type().is_file() || metadata.len() != artifact.size {
                bail!("installed workload artifact {installed} is not the declared regular file");
            }
            // Plain digest sidecars are mutable and cannot authorize bytes.
            // Until an integrity-bound receipt exists, warm hits hash directly.
            let actual = mvm_core::crypto::image_verify::sha256_file(&path)?;
            if actual != artifact.sha256.as_str() {
                bail!("installed workload artifact {installed} differs from its authenticated digest");
            }
        }
    }
    if !kernel_seen || !root_seen {
        bail!("image set has no complete {profile} workload for {arch} and {build_mode:?}");
    }
    verify_base_image_contract(&directory.join("rootfs.ext4"), &manifest.compatibility)
}
