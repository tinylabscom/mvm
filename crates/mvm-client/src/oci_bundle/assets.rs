//! Original Linux image-set assets paired with the signed CLI guest runtime.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_build::guest_runtime::evidence::{
    RuntimeArtifactSelection, VerifiedRuntimeArtifacts, verify_runtime_release_proof,
};
use mvm_build::oci_runtime_inject::MvmRuntimeBinaries;
use mvm_build::published_image_set::PublishedImageSet;
use mvm_core::arch::GuestArch;
use mvm_core::crypto::image_verify::sha256_file;
use mvm_core::plan::bundle::EmbeddedCliBootAssets;
use mvm_core::protocol::runtime_release::RuntimeReleaseProof;

pub(super) struct BootAssets {
    _directory: tempfile::TempDir,
    pub image_set: PublishedImageSet,
    pub kernel: PathBuf,
    pub runtime_overlay: PathBuf,
    pub runtime_overlay_verity: PathBuf,
    pub initrd: PathBuf,
    pub binaries: MvmRuntimeBinaries,
    pub release_proof: RuntimeReleaseProof,
    pub checksum_signature_bundle: PathBuf,
    pub runtime: EmbeddedCliBootAssets,
    _prepared: VerifiedRuntimeArtifacts,
    bindings: Vec<(PathBuf, String)>,
}

impl BootAssets {
    pub fn acquire(arch: GuestArch) -> Result<Self> {
        let image_set = PublishedImageSet::acquire()?;
        let cache = PathBuf::from(mvm_core::config::mvm_cache_dir());
        let runtime = mvm_build::guest_runtime::resolve_or_download_guest_runtime_quartet(
            &cache,
            env!("CARGO_PKG_VERSION"),
            arch,
        )?;
        let proof = runtime
            .release_proof
            .context("portable creation requires a signed CLI runtime release")?;
        Self::from_set(image_set, arch, &proof)
    }

    fn from_set(
        image_set: PublishedImageSet,
        arch: GuestArch,
        source_proof: &RuntimeReleaseProof,
    ) -> Result<Self> {
        anyhow::ensure!(
            source_proof.version == env!("CARGO_PKG_VERSION") && source_proof.arch == arch,
            "portable runtime proof differs from the selected CLI version or architecture"
        );
        let directory = tempfile::tempdir().context("stage portable OCI boot assets")?;
        let root = directory.path();
        let kernel_member =
            mvm_core::plan::bundle::select_cli_boot_kernel(image_set.manifest(), arch)?;
        let kernel_artifact = single_artifact(kernel_member)?;
        let kernel = root.join("vmlinux");
        image_set.fetch_artifact(kernel_artifact, &kernel)?;
        let archive = root.join("guest-runtime.tar.gz");
        let checksum = root.join("guest-runtime.sha256");
        let signature_bundle = root.join("guest-runtime.bundle");
        let checksum_signature_bundle = root.join("guest-runtime.sha256.bundle");
        let source_checksum_bundle =
            mvm_build::guest_runtime::evidence::checksum_bundle_path(&source_proof.checksum);
        for (source, target) in [
            (&source_proof.archive, &archive),
            (&source_proof.checksum, &checksum),
            (&source_proof.signature_bundle, &signature_bundle),
            (&source_checksum_bundle, &checksum_signature_bundle),
        ] {
            std::fs::copy(source, target).with_context(|| {
                format!("retain signed runtime release input {}", source.display())
            })?;
        }
        let release_proof = RuntimeReleaseProof {
            archive,
            checksum,
            signature_bundle,
            ..source_proof.clone()
        };
        let verified = verify_runtime_release_proof(&release_proof, &source_proof.version, arch)?;
        let cache = root.join("runtime-cache");
        let guest_runtime = mvm_build::guest_runtime::install_signed_guest_runtime_archive(
            &cache,
            &release_proof.archive,
            &release_proof.checksum,
            &release_proof.signature_bundle,
            &release_proof.version,
            arch,
        )?;
        let overlay = mvm_build::runtime_overlay::build_runtime_overlay_from_guest_runtime(
            &cache,
            &release_proof.version,
            arch,
            &guest_runtime,
        )?;
        let initramfs = mvm_build::initramfs::build_initramfs_from_guest_runtime(
            &cache,
            &release_proof.version,
            arch,
            &guest_runtime,
        )?;
        let prepared = verified.snapshot_artifacts(&RuntimeArtifactSelection {
            arch,
            overlay: &overlay.overlay_ext4,
            overlay_verity: &overlay.sidecar,
            overlay_roothash: &overlay.roothash,
            initramfs: &initramfs.image_path,
            minimum_protocol: mvm_runtime::runtime_evidence::MIN_GUEST_RPC_PROTOCOL_VERSION,
            host_protocol: mvm_runtime::runtime_evidence::GUEST_RPC_PROTOCOL_VERSION,
        })?;
        let runtime_overlay = prepared.overlay_path();
        let runtime_overlay_verity = prepared.overlay_verity_path();
        let initrd = prepared.initramfs_path();
        let declaration = prepared.declaration();
        let runtime = EmbeddedCliBootAssets {
            manifest_artifact: "boot-image-set.json".into(),
            version: release_proof.version.clone(),
            arch: arch.to_string(),
            archive_artifact: "guest-runtime.tar.gz".into(),
            checksum_artifact: "guest-runtime.sha256".into(),
            signature_bundle_artifact: "guest-runtime.bundle".into(),
            checksum_signature_bundle_artifact: "guest-runtime.sha256.bundle".into(),
            overlay_artifact: "runtime-overlay.ext4".into(),
            overlay_verity_artifact: "runtime-overlay.verity".into(),
            initramfs_artifact: "initrd".into(),
            overlay_roothash: declaration.overlay_roothash.clone(),
            protocol_version: declaration.protocol_version,
            min_supported_protocol_version: declaration.min_supported_protocol_version,
        };
        let bin = guest_runtime.root.join(arch.to_string()).join("bin");
        let binaries = MvmRuntimeBinaries {
            agent: bin.join("mvm-guest-agent"),
            netinit: bin.join("mvm-guest-netinit"),
            egress_client: bin.join("mvm-egress-client"),
            entrypoint_runner: bin.join("mvm-oci-entrypoint"),
        };
        let mut bindings = vec![(kernel.clone(), kernel_artifact.sha256.as_str().to_owned())];
        for path in [
            &runtime_overlay,
            &runtime_overlay_verity,
            &initrd,
            &release_proof.archive,
            &release_proof.checksum,
            &release_proof.signature_bundle,
            &checksum_signature_bundle,
        ]
        .into_iter()
        .map(PathBuf::as_path)
        .chain(binaries.artifacts().into_iter().map(|(_, path)| path))
        {
            bindings.push((path.to_owned(), sha256_file(path)?));
        }
        Ok(Self {
            _directory: directory,
            image_set,
            kernel,
            runtime_overlay,
            runtime_overlay_verity,
            initrd,
            binaries,
            release_proof,
            checksum_signature_bundle,
            runtime,
            _prepared: prepared,
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
    use mvm_core::image_set::{ImageSetRole, MemberTarget, WorkloadImageProfile};
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn pinned_linux_assets_do_not_substitute_for_a_missing_runtime_release_proof() {
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
                mvm_core::plan::bundle::BOOT_ASSET_OVERLAY_ROLE,
                target,
                "overlay.tar.gz",
                overlay,
            )
            .publish(
                mvm_core::plan::bundle::BOOT_ASSET_INITRAMFS_ROLE,
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
        let proof = RuntimeReleaseProof {
            archive: served.path().join("missing-runtime.tar.gz"),
            checksum: served.path().join("missing-runtime.sha256"),
            signature_bundle: served.path().join("missing-runtime.bundle"),
            archive_sha256: "a".repeat(64),
            version: env!("CARGO_PKG_VERSION").into(),
            arch,
        };
        let error = BootAssets::from_set(set, arch, &proof)
            .err()
            .expect("missing release proof must fail");
        assert!(format!("{error:#}").contains("missing-runtime"));
    }
}
