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
    MemberTarget, ReleaseTag, WorkloadImageProfile, check_against_lock,
    check_protocol_compatibility, require_complete, validate_structure,
};
use mvm_core::packs::Sha256Hex;
use thiserror::Error;

#[cfg(any(test, feature = "test-support"))]
pub mod fixture;

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
    release_tag: ReleaseTag,
    base_url: String,
    download: Download,
}

impl PublishedImageSet {
    /// Acquire and verify the root object pinned by this build.
    pub fn acquire() -> Result<Self> {
        Self::acquire_from(ImageSetSource::locked())
    }

    /// Acquire and verify the root object `source` pins.
    pub fn acquire_from(source: ImageSetSource) -> Result<Self> {
        let ImageSetSource {
            train,
            base_url,
            download,
        } = source;
        let lock = &train.image_set;
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

        crate::release_signature::verify_release_archive_signature(
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
        let host = crate::stage0_kernel::current_image_set_protocol_support();
        check_protocol_compatibility(&manifest, &host)
            .context("refuse an image set incompatible with this host")?;
        if manifest.compatibility != train.compatibility {
            bail!(
                "images.lock compatibility does not match the signed image-set manifest; run the pin-update workflow"
            );
        }

        Ok(Self {
            manifest,
            release_tag: lock.release_tag.clone(),
            base_url,
            download,
        })
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
        let artifacts: Vec<MemberArtifact> = self
            .manifest
            .members
            .iter()
            .filter(|member| roles.contains(&member.role) && member.target == target)
            .flat_map(|member| member.artifacts.iter().cloned())
            .collect();
        if artifacts.len() != 4 {
            bail!(
                "signed image set declares {} default-workload artifacts for {arch}, expected 4",
                artifacts.len()
            );
        }
        for artifact in &artifacts {
            let name = artifact.name.as_str();
            let destination = if name.contains("vmlinux") {
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

        let protocol_version = u8::try_from(self.manifest.compatibility.guest_agent_protocol.max())
            .context("signed guest-agent protocol does not fit the runtime sidecar")?;
        crate::builder_vm::GuestSidecar {
            name: "mvm-default-microvm".to_string(),
            accessible: false,
            sealed: true,
            entrypoint_kind: "command".to_string(),
            entrypoint_argv: Vec::new(),
            init_system: "busybox".to_string(),
            expected_boot_ms: 300,
            agent_binary: "real".to_string(),
            rootless_entrypoint: true,
            hypervisor: "firecracker".to_string(),
            overlay_aware: true,
            runtime_lean: true,
            image_tag: String::new(),
            source: String::new(),
            built_at: String::new(),
            protocol_version,
            generator_rev: self.manifest.mvm_source_commit.as_str().to_string(),
            libc: Default::default(),
        }
        .write_to_dir(dir)
        .context("write default image sidecar derived from signed manifest")?;
        Ok(())
    }

    /// Find one artifact under its exact role and target.
    pub fn artifact(
        &self,
        role: ImageSetRole,
        target: MemberTarget,
        name: &str,
    ) -> Result<&MemberArtifact, ImageSetMemberError> {
        let member = self
            .manifest
            .members
            .iter()
            .find(|member| member.role == role && member.target == target)
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
        Ok(())
    }
}
