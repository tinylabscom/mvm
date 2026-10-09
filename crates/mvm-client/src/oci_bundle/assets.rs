//! Acquiring boot assets from the existing authenticated image-set pin.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_build::oci_runtime_inject::MvmRuntimeBinaries;
use mvm_build::published_image_set::PublishedImageSet;
use mvm_core::arch::GuestArch;
use mvm_core::crypto::image_verify::sha256_file;
use mvm_core::image_set::{ImageSetRole, MemberTarget, WorkloadImageProfile};
use mvm_core::plan::bundle::select_boot_asset_members;

pub(super) struct BootAssets {
    _directory: tempfile::TempDir,
    pub image_set: PublishedImageSet,
    pub kernel: PathBuf,
    pub runtime_overlay: PathBuf,
    pub initramfs_archive: PathBuf,
    pub initrd: PathBuf,
    pub binaries: MvmRuntimeBinaries,
    bindings: Vec<(PathBuf, String)>,
}

impl BootAssets {
    pub fn acquire(arch: GuestArch) -> Result<Self> {
        Self::from_set(PublishedImageSet::acquire()?, arch)
    }

    fn from_set(image_set: PublishedImageSet, arch: GuestArch) -> Result<Self> {
        let directory = tempfile::tempdir().context("stage portable OCI boot assets")?;
        let root = directory.path();
        let [overlay_member, initramfs_member] =
            select_boot_asset_members(image_set.manifest(), arch)?;
        let overlay = single_artifact(overlay_member)?;
        let initramfs = single_artifact(initramfs_member)?;
        let kernel_member = image_set
            .manifest()
            .members
            .iter()
            .find(|member| {
                member.role == ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant)
                    && member.target == MemberTarget::Arch(arch)
                    && member.build_mode.is_none()
            })
            .context(
                "signed image set has no production workload kernel for requested architecture",
            )?;
        let kernel_artifact = single_artifact(kernel_member)?;
        let kernel = root.join("vmlinux");
        let runtime_overlay = root.join(overlay.name.as_str());
        let initramfs_archive = root.join(initramfs.name.as_str());
        for (artifact, path) in [
            (kernel_artifact, &kernel),
            (overlay, &runtime_overlay),
            (initramfs, &initramfs_archive),
        ] {
            image_set.fetch_artifact(artifact, path)?;
        }
        let mut bindings = vec![
            (kernel.clone(), kernel_artifact.sha256.as_str().to_owned()),
            (runtime_overlay.clone(), overlay.sha256.as_str().to_owned()),
            (
                initramfs_archive.clone(),
                initramfs.sha256.as_str().to_owned(),
            ),
        ];

        // This private cache contains only members authenticated by this set.
        // Neither source-checkout artifacts nor the running CLI's cache win.
        let cache = root.join("runtime-cache");
        let set = image_set.member_cache();
        let runtime_key = set.root().as_str();
        mvm_build::runtime_overlay::install_image_set_runtime_overlay_archive(
            &runtime_overlay,
            &set,
            runtime_key,
            arch,
            &cache,
        )?;
        let binaries = mvm_build::guest_agent_build::cached_guest_binaries(
            &cache.join("oci"),
            runtime_key,
            arch,
        )
        .context("authenticated runtime overlay did not supply OCI entrypoint binaries")?;
        let initrd = mvm_build::initramfs::install_image_set_initramfs_archive(
            &initramfs_archive,
            &set,
            arch,
            &cache.join("initramfs"),
        )?
        .image_path;
        bindings.push((initrd.clone(), sha256_file(&initrd)?));
        bindings.push((
            binaries.entrypoint_runner.clone(),
            sha256_file(&binaries.entrypoint_runner)?,
        ));
        Ok(Self {
            _directory: directory,
            image_set,
            kernel,
            runtime_overlay,
            initramfs_archive,
            initrd,
            binaries,
            bindings,
        })
    }

    pub fn verify_integrity(&self) -> Result<()> {
        for (path, expected) in &self.bindings {
            if !std::fs::symlink_metadata(path)?.file_type().is_file()
                || sha256_file(path)? != *expected
            {
                bail!("authenticated boot asset changed: {}", path.display());
            }
        }
        Ok(())
    }
}

fn single_artifact(
    member: &mvm_core::image_set::ImageSetMember,
) -> Result<&mvm_core::image_set::MemberArtifact> {
    let [artifact] = member.artifacts.as_slice() else {
        bail!(
            "portable OCI boot requires one artifact for image-set role {:?}",
            member.role
        );
    };
    Ok(artifact)
}

pub(super) fn utf8(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("artifact path {} is not valid UTF-8", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_build::boot_asset_fixture;
    use mvm_build::published_image_set::fixture::ImageSetFixture;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn acquired_assets_use_the_pinned_runtime_cache_and_detect_mutation() {
        let mut env = TestEnv::new();
        // The fixture pins exact local bytes but does not ship a Sigstore proof.
        env.set("MVM_SKIP_COSIGN_VERIFY", "1");
        let served = tempfile::tempdir().unwrap();
        let arch = GuestArch::host();
        let target = MemberTarget::Arch(arch);
        let overlay = boot_asset_fixture::runtime_overlay_archive_bytes(
            arch,
            &boot_asset_fixture::valid_overlay_ext4_bytes(),
            b"synthetic verity",
            "a".repeat(64).as_bytes(),
            b"0.14.0",
        );
        let (image, hash, size) = boot_asset_fixture::initramfs_fixture(b"synthetic cpio");
        let initramfs = boot_asset_fixture::initramfs_archive_bytes(
            &image,
            hash.as_bytes(),
            size.as_bytes(),
            b"0.14.0",
        );
        let fixture = ImageSetFixture::complete()
            .publish(
                ImageSetRole::RuntimeOverlay,
                target,
                "overlay.tar.gz",
                overlay,
            )
            .publish(
                ImageSetRole::Initramfs,
                target,
                "initramfs.tar.gz",
                initramfs,
            )
            .publish(
                ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant),
                target,
                "vmlinux",
                b"synthetic kernel".to_vec(),
            );
        let set = PublishedImageSet::acquire_from(fixture.serve_from(served.path())).unwrap();
        let pin = set.member_cache().root().clone();
        let assets = BootAssets::from_set(set, arch).unwrap();

        assets.verify_integrity().unwrap();
        assert!(
            assets
                .binaries
                .entrypoint_runner
                .starts_with(assets._directory.path().join("runtime-cache/oci"))
        );
        assert_eq!(
            mvm_core::packs::Sha256Hex::from_bytes(assets.image_set.manifest_bytes()),
            pin
        );
        std::fs::write(&assets.binaries.entrypoint_runner, b"changed").unwrap();
        assert!(assets.verify_integrity().is_err());
    }
}
