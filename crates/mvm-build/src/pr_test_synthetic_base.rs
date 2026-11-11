//! PR-signed synthetic Linux inputs, admitted only through local development composition.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use mvm_core::arch::GuestArch;
use mvm_core::image_set::{ImageSetManifest, WorkloadImageProfile};

const ISSUER: &str = "https://token.actions.githubusercontent.com";
const MAX_BUNDLE_BYTES: u64 = 1024 * 1024;

/// A fixture selection, not a release image-set proof or a boot capability.
#[derive(Debug)]
pub struct PrTestSyntheticBase {
    directory: PathBuf,
    pull_request: u64,
}

/// Paths and exact manifest bytes checked against the PR workflow signature.
#[derive(Debug)]
pub struct VerifiedSyntheticBase {
    pub manifest: Vec<u8>,
    pub manifest_path: PathBuf,
    pub kernel: PathBuf,
    pub tar: PathBuf,
}

impl PrTestSyntheticBase {
    /// PR number pinned to the exact workflow signing identity.
    pub fn pull_request(&self) -> u64 {
        self.pull_request
    }

    /// Select a private PR fixture; verification is repeated before every use.
    ///
    /// # Errors
    /// Refuses an absent PR number or a non-directory/symlink fixture.
    pub fn new(directory: &Path, pull_request: u64) -> Result<Self> {
        ensure!(
            pull_request > 0,
            "synthetic base requires a positive PR number"
        );
        ensure!(
            std::fs::symlink_metadata(directory)?.file_type().is_dir(),
            "synthetic base fixture must be a real directory"
        );
        Ok(Self {
            directory: std::fs::canonicalize(directory)?,
            pull_request,
        })
    }

    /// Authenticate the exact local schema-3 root and selected regular kernel/tar.
    ///
    /// # Errors
    /// Refuses changed bytes, the wrong PR signer, an invalid set or incompatible inputs.
    pub fn verify(&self, arch: GuestArch) -> Result<VerifiedSyntheticBase> {
        self.verify_with(arch, |manifest, bundle, identity| {
            mvm_core::crypto::image_verify::verify_signed_payload(
                manifest, bundle, identity, ISSUER,
            )
            .map_err(Into::into)
        })
    }

    fn verify_with(
        &self,
        arch: GuestArch,
        verify_signature: impl FnOnce(&[u8], &[u8], &str) -> Result<()>,
    ) -> Result<VerifiedSyntheticBase> {
        let manifest_path = self.directory.join("image-set.json");
        let bundle_path = self.directory.join("image-set.bundle");
        let manifest = bounded_regular(
            &manifest_path,
            mvm_core::plan::bundle::MAX_IMAGE_SET_MANIFEST_BYTES,
        )?;
        let bundle = bounded_regular(&bundle_path, MAX_BUNDLE_BYTES)?;
        let identity = format!(
            "https://github.com/tinylabscom/mvm/.github/workflows/composable-python-layer-smoke.yml@refs/pull/{}/merge",
            self.pull_request
        );
        verify_signature(&manifest, &bundle, &identity)
            .context("synthetic base manifest is not signed by the exact PR workflow")?;
        let declared: ImageSetManifest =
            serde_json::from_slice(&manifest).context("parse signed synthetic base manifest")?;
        ensure!(
            declared.schema_version == mvm_core::image_set::IMAGE_SET_SCHEMA_VERSION,
            "synthetic base requires schema 3"
        );
        mvm_core::image_set::check_workload_protocol_compatibility(
            &declared.compatibility,
            &crate::stage0_kernel::current_image_set_protocol_support(),
        )?;
        let (kernel, tar) = mvm_core::plan::bundle::select_local_development_source(
            &declared,
            arch,
            WorkloadImageProfile::DefaultTenant,
        )?;
        let selected = [(kernel, 256 * 1024 * 1024), (tar, 2 * 1024 * 1024 * 1024)];
        let mut paths = Vec::with_capacity(2);
        for (artifact, maximum) in selected {
            ensure!(
                artifact.size <= maximum,
                "synthetic base artifact exceeds capture bound"
            );
            let path = self.directory.join(artifact.name.as_str());
            let metadata = std::fs::symlink_metadata(&path)?;
            ensure!(
                metadata.file_type().is_file() && metadata.len() == artifact.size,
                "synthetic base artifact is missing, linked or changed"
            );
            ensure!(
                mvm_core::crypto::image_verify::sha256_file(&path)? == artifact.sha256.as_str(),
                "synthetic base artifact digest changed"
            );
            paths.push(path);
        }
        let [kernel, tar] = paths
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected kernel and tar"))?;
        Ok(VerifiedSyntheticBase {
            manifest,
            manifest_path,
            kernel,
            tar,
        })
    }
}

fn bounded_regular(path: &Path, max: u64) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("synthetic base input missing: {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file() && metadata.len() <= max,
        "synthetic base input must be a bounded regular file"
    );
    let bytes = std::fs::read(path)?;
    ensure!(
        bytes.len() as u64 <= max,
        "synthetic base input grew while reading"
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::published_image_set::fixture::ImageSetFixture;
    use mvm_core::image_set::{
        ArtifactFormat, BaseImageContract, GuestDeviceRequirement, ImageSetRole, MemberArtifact,
        MemberTarget,
    };
    use mvm_core::packs::Sha256Hex;

    fn local_fixture(dir: &Path) -> ImageSetManifest {
        let arch = GuestArch::host();
        let profile = WorkloadImageProfile::DefaultTenant;
        let target = MemberTarget::Arch(arch);
        let kernel = b"synthetic kernel";
        let tar = b"synthetic tar";
        let mut manifest = ImageSetFixture::complete()
            .with_base_image_contract(Some(BaseImageContract::LINUX_LAYER))
            .publish(
                ImageSetRole::WorkloadKernel(profile),
                target,
                "kernel",
                kernel.to_vec(),
            )
            .publish(
                ImageSetRole::WorkloadRootfs(profile),
                target,
                "rootfs.ext4",
                b"ext4".to_vec(),
            )
            .into_manifest();
        manifest.members.retain(|member| {
            member.target == target
                && matches!(
                    member.role,
                    ImageSetRole::WorkloadKernel(_) | ImageSetRole::WorkloadRootfs(_)
                )
        });
        manifest.producer = serde_json::from_value(serde_json::json!({
            "local_checkouts": {
                "images": {
                    "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "worktree": {"state": "clean"}
                }
            }
        }))
        .unwrap();
        manifest.revocation_channel = None;
        manifest.mvm_source_commit = None;
        for member in &mut manifest.members {
            member.pack_hash = None;
            member.sbom = None;
            match member.role {
                ImageSetRole::WorkloadKernel(_) => {
                    member.required_capabilities = vec![GuestDeviceRequirement::VirtioVsock];
                }
                ImageSetRole::WorkloadRootfs(_) => {
                    member.required_capabilities = vec![GuestDeviceRequirement::VirtioBlk];
                    member.artifacts.push(MemberArtifact {
                        name: mvm_core::image_set::ArtifactName::new("rootfs.tar.gz").unwrap(),
                        format: ArtifactFormat::TarGz,
                        sha256: Sha256Hex::from_bytes(tar),
                        size: tar.len() as u64,
                    });
                }
                _ => unreachable!("only selected workload members are retained"),
            }
        }
        std::fs::write(dir.join("kernel"), kernel).unwrap();
        std::fs::write(dir.join("rootfs.tar.gz"), tar).unwrap();
        std::fs::write(
            dir.join("image-set.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join("image-set.bundle"), b"signed bundle").unwrap();
        manifest
    }

    #[test]
    fn exact_pr_identity_and_selected_bytes_are_required() {
        let dir = tempfile::tempdir().unwrap();
        let mut manifest = local_fixture(dir.path());
        let release_producer = ImageSetFixture::complete().into_manifest().producer;
        let fixture = PrTestSyntheticBase::new(dir.path(), 42).unwrap();
        let verify = || {
            fixture.verify_with(GuestArch::host(), |bytes, bundle, identity| {
                assert_eq!(bytes, std::fs::read(dir.path().join("image-set.json")).unwrap());
                assert_eq!(bundle, b"signed bundle");
                assert_eq!(
                    identity,
                    "https://github.com/tinylabscom/mvm/.github/workflows/composable-python-layer-smoke.yml@refs/pull/42/merge"
                );
                Ok(())
            })
        };
        assert!(verify().is_ok());
        let foreign_arch = match GuestArch::host() {
            GuestArch::X86_64 => GuestArch::Aarch64,
            GuestArch::Aarch64 => GuestArch::X86_64,
        };
        assert!(fixture.verify_with(foreign_arch, |_, _, _| Ok(())).is_err());
        std::fs::write(dir.path().join("kernel"), b"tampered kernel").unwrap();
        assert!(verify().is_err());
        std::fs::write(dir.path().join("kernel"), b"synthetic kernel").unwrap();
        std::fs::write(dir.path().join("rootfs.tar.gz"), b"changed tar").unwrap();
        assert!(verify().is_err());
        std::fs::write(dir.path().join("rootfs.tar.gz"), b"synthetic tar").unwrap();
        manifest.schema_version = 2;
        std::fs::write(
            dir.path().join("image-set.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(verify().is_err());
        manifest.schema_version = mvm_core::image_set::IMAGE_SET_SCHEMA_VERSION;
        manifest.producer = release_producer;
        std::fs::write(
            dir.path().join("image-set.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(
            verify().is_err(),
            "release producer cannot become a PR-local base"
        );
    }

    #[test]
    fn absent_partial_or_unsigned_fixture_never_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        assert!(PrTestSyntheticBase::new(dir.path(), 0).is_err());
        let fixture = PrTestSyntheticBase::new(dir.path(), 42).unwrap();
        assert!(fixture.verify(GuestArch::host()).is_err());
        std::fs::write(dir.path().join("image-set.json"), b"{}").unwrap();
        std::fs::write(dir.path().join("image-set.bundle"), b"{}").unwrap();
        assert!(fixture.verify(GuestArch::host()).is_err());
        std::fs::remove_file(dir.path().join("image-set.bundle")).unwrap();
        assert!(fixture.verify(GuestArch::host()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn linked_manifest_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("real"), b"{}").unwrap();
        std::os::unix::fs::symlink("real", dir.path().join("image-set.json")).unwrap();
        assert!(
            PrTestSyntheticBase::new(dir.path(), 42)
                .unwrap()
                .verify(GuestArch::host())
                .is_err()
        );
    }

    #[test]
    #[ignore = "writes nonbootable synthetic fixture to MVM_PR_TEST_BASE_DIR for PR signing"]
    fn write_synthetic_pr_base_fixture_for_ci() {
        let path = PathBuf::from(std::env::var_os("MVM_PR_TEST_BASE_DIR").unwrap());
        std::fs::create_dir(&path).unwrap();
        local_fixture(&path);
    }

    #[test]
    #[ignore = "requires a real PR-workflow cosign bundle in MVM_PR_TEST_BASE_DIR"]
    fn real_pr_signature_accepts_only_unchanged_exact_identity() {
        let path = PathBuf::from(std::env::var_os("MVM_PR_TEST_BASE_DIR").unwrap());
        let number: u64 = std::env::var("MVM_PR_TEST_PULL_REQUEST")
            .unwrap()
            .parse()
            .unwrap();
        let arch = GuestArch::host();
        let base = PrTestSyntheticBase::new(&path, number).unwrap();
        let checked = base
            .verify(arch)
            .expect("same-PR fixture must authenticate");
        assert!(
            PrTestSyntheticBase::new(&path, number + 1)
                .unwrap()
                .verify(arch)
                .is_err(),
            "another PR must not authenticate the fixture"
        );

        let copied = tempfile::tempdir().unwrap();
        let bundle = path.join("image-set.bundle");
        for input in [
            checked.manifest_path.as_path(),
            bundle.as_path(),
            checked.kernel.as_path(),
            checked.tar.as_path(),
        ] {
            std::fs::copy(input, copied.path().join(input.file_name().unwrap())).unwrap();
        }
        let local = PrTestSyntheticBase::new(copied.path(), number).unwrap();
        assert!(local.verify(arch).is_ok());
        std::fs::write(copied.path().join("image-set.json"), b"{}").unwrap();
        assert!(local.verify(arch).is_err(), "changed manifest must fail");
        std::fs::write(copied.path().join("image-set.json"), &checked.manifest).unwrap();
        std::fs::write(
            copied.path().join(checked.kernel.file_name().unwrap()),
            b"changed",
        )
        .unwrap();
        assert!(local.verify(arch).is_err(), "changed kernel must fail");
        std::fs::copy(
            &checked.kernel,
            copied.path().join(checked.kernel.file_name().unwrap()),
        )
        .unwrap();
        std::fs::remove_file(copied.path().join(checked.tar.file_name().unwrap())).unwrap();
        assert!(local.verify(arch).is_err(), "missing tar must fail");
    }
}
