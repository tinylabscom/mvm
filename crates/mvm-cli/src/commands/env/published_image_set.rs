//! Acquisition boundary for the signed, locked `mvm-images` release.
//!
//! Every remote image consumer enters here before requesting a member. The
//! root manifest is digest-pinned, verified under the exact release identity,
//! parsed only afterwards, held to the complete-train and protocol contracts,
//! and finally used as the sole source of member artifact digests.

use std::path::Path;

use anyhow::{Context, Result, bail};
use mvm_core::image_set::{
    ImageSetManifest, ImageSetRequirement, ImageSetRole, MemberArtifact, MemberTarget,
    WorkloadImageProfile, check_against_lock, check_protocol_compatibility, require_complete,
    validate_structure,
};
use mvm_core::packs::Sha256Hex;

use super::artifact_verify::download_file;

/// A root manifest whose digest, publisher, completeness and compatibility
/// have all been verified. Member bytes are still untrusted until
/// [`Self::fetch_artifact`] checks them against their declaration.
pub(crate) struct PublishedImageSet {
    manifest: ImageSetManifest,
    base_url: String,
}

impl PublishedImageSet {
    /// Acquire and verify the root object pinned by this build.
    pub(crate) fn acquire() -> Result<Self> {
        let train = mvm_core::image_set::image_train_lock();
        let lock = &train.image_set;
        let base_url = crate::update::image_set_asset_base_url(lock.release_tag.as_str());
        let staged = tempfile::NamedTempFile::new().context("create image-set manifest staging")?;
        let staged_path = staged.path().to_string_lossy().to_string();
        let manifest_url = format!("{base_url}/{}", lock.manifest_asset);
        download_file(&manifest_url, &staged_path)
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

        mvm_build::release_signature::verify_release_archive_signature(
            &mvm_build::release_signature::ReleaseSignatureRequest {
                base_url: &base_url,
                asset: lock.manifest_asset.as_str(),
                archive_path: staged.path(),
                version: lock.release_tag.version().as_str(),
                train: mvm_build::release_signature::ReleaseTrain::ImageSet,
            },
        )
        .context("verify the locked image-set publisher identity")?;

        let manifest: ImageSetManifest = serde_json::from_slice(&bytes)
            .context("the signed image-set root is not a supported manifest")?;
        validate_structure(&manifest).context("validate signed image-set structure")?;
        check_against_lock(&manifest, &actual, lock).context("match signed image set to lock")?;
        require_complete(&manifest, &ImageSetRequirement::current_train())
            .context("refuse a partial image-set release")?;
        let host = mvm_build::stage0_kernel::current_image_set_protocol_support();
        check_protocol_compatibility(&manifest, &host)
            .context("refuse an image set incompatible with this host")?;
        if manifest.compatibility != train.compatibility {
            bail!(
                "images.lock compatibility does not match the signed image-set manifest; run the pin-update workflow"
            );
        }

        Ok(Self { manifest, base_url })
    }

    /// Materialize the curated default workload from members of the verified
    /// set. The root manifest is acquired and protocol-checked before this
    /// method can be called, so no member request can precede compatibility.
    pub(crate) fn fetch_default_workload(
        &self,
        arch: mvm_core::arch::GuestArch,
        dir: &Path,
    ) -> Result<()> {
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
        mvm_build::builder_vm::GuestSidecar {
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
    pub(crate) fn artifact(
        &self,
        role: ImageSetRole,
        target: MemberTarget,
        name: &str,
    ) -> Result<&MemberArtifact> {
        let member = self
            .manifest
            .members
            .iter()
            .find(|member| member.role == role && member.target == target)
            .with_context(|| format!("signed image set has no {role}/{target} member"))?;
        member
            .artifacts
            .iter()
            .find(|artifact| artifact.name.as_str() == name)
            .with_context(|| format!("signed image set {role}/{target} has no artifact {name}"))
    }

    /// Download one declared artifact and hold both its size and digest to the
    /// signed root before returning its path to a caller.
    pub(crate) fn fetch_artifact(&self, artifact: &MemberArtifact, dest: &Path) -> Result<()> {
        let dest_text = dest.to_string_lossy().to_string();
        let url = format!("{}/{}", self.base_url, artifact.name);
        download_file(&url, &dest_text).with_context(|| format!("download {url}"))?;
        let metadata = std::fs::metadata(dest)
            .with_context(|| format!("stat downloaded artifact {}", dest.display()))?;
        if metadata.len() != artifact.size {
            let _ = std::fs::remove_file(dest);
            bail!(
                "downloaded {} is {} bytes, not the signed manifest's {}",
                artifact.name,
                metadata.len(),
                artifact.size
            );
        }
        let actual = mvm_core::crypto::image_verify::sha256_file(dest)
            .with_context(|| format!("hash downloaded artifact {}", dest.display()))?;
        if actual != artifact.sha256.as_str() {
            let _ = std::fs::remove_file(dest);
            bail!(
                "downloaded {} hashes to {}, not the signed manifest's {}",
                artifact.name,
                actual,
                artifact.sha256.as_str()
            );
        }
        Ok(())
    }
}
