//! Verify the legacy CLI-release mirror of a canonical image set.
//!
//! The mirror exists only for clients that still compose image URLs below the
//! CLI release. It is never another producer: every mirrored byte must already
//! exist in the signed canonical release and must remain byte-for-byte equal.

use std::path::Path;

use anyhow::{Context, Result, bail};
use mvm_core::image_set::{ImageSetManifest, validate_structure};
use mvm_core::packs::Sha256Hex;

pub(crate) fn run(args: &[String]) -> Result<()> {
    let [manifest, canonical_dir, mirror_dir] = args else {
        bail!("usage: image-mirror <manifest> <canonical-dir> <mirror-dir>");
    };
    verify(
        Path::new(manifest),
        Path::new(canonical_dir),
        Path::new(mirror_dir),
    )
}

fn verify(manifest_path: &Path, canonical_dir: &Path, mirror_dir: &Path) -> Result<()> {
    let manifest_bytes = std::fs::read(manifest_path)
        .with_context(|| format!("read canonical manifest {}", manifest_path.display()))?;
    let manifest: ImageSetManifest = serde_json::from_slice(&manifest_bytes)
        .with_context(|| format!("parse canonical manifest {}", manifest_path.display()))?;
    validate_structure(&manifest).context("validate canonical image-set structure")?;

    let declared = manifest
        .members
        .iter()
        .flat_map(|member| member.artifacts.iter())
        .map(|artifact| (artifact.name.as_str(), artifact))
        .collect::<std::collections::BTreeMap<_, _>>();

    verify_assets(&declared, canonical_dir, mirror_dir)
}

fn verify_assets(
    declared: &std::collections::BTreeMap<&str, &mvm_core::image_set::MemberArtifact>,
    canonical_dir: &Path,
    mirror_dir: &Path,
) -> Result<()> {
    for name in super::release_boot_image::required_assets() {
        let canonical = read_regular_file(&canonical_dir.join(&name), "canonical")?;
        let mirrored = read_regular_file(&mirror_dir.join(&name), "mirrored")?;
        let canonical_digest = Sha256Hex::from_bytes(&canonical);
        let mirrored_digest = Sha256Hex::from_bytes(&mirrored);
        if canonical_digest != mirrored_digest {
            bail!(
                "legacy mirror drift for {name}: canonical {}, mirrored {}",
                canonical_digest.as_str(),
                mirrored_digest.as_str()
            );
        }
        if let Some(artifact) = declared.get(name.as_str()) {
            let actual_size = u64::try_from(canonical.len())
                .context("canonical mirrored asset size does not fit u64")?;
            if canonical_digest != artifact.sha256 || actual_size != artifact.size {
                bail!(
                    "canonical {name} disagrees with signed root: expected {} bytes / {}, got {} bytes / {}",
                    artifact.size,
                    artifact.sha256.as_str(),
                    actual_size,
                    canonical_digest.as_str()
                );
            }
        }
    }

    eprintln!(
        "image-mirror: canonical and legacy bytes match for {} required assets",
        super::release_boot_image::required_assets().len()
    );
    Ok(())
}

fn read_regular_file(path: &Path, side: &str) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("read {side} mirror asset metadata {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 {
        bail!(
            "{side} mirror asset {} must be a non-empty regular file",
            path.display()
        );
    }
    std::fs::read(path).with_context(|| format!("read {side} mirror asset {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::image_set::{ArtifactFormat, ArtifactName, MemberArtifact};
    use std::path::PathBuf;

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().expect("create fixture");
        let canonical = root.path().join("canonical");
        let mirror = root.path().join("mirror");
        std::fs::create_dir_all(&canonical).expect("create canonical dir");
        std::fs::create_dir_all(&mirror).expect("create mirror dir");
        for name in super::super::release_boot_image::required_assets() {
            std::fs::write(canonical.join(&name), name.as_bytes()).expect("write canonical asset");
            std::fs::write(mirror.join(&name), name.as_bytes()).expect("write mirror asset");
        }

        (root, canonical, mirror)
    }

    #[test]
    fn identical_required_assets_pass() {
        let (_root, canonical, mirror) = fixture();
        verify_assets(&std::collections::BTreeMap::new(), &canonical, &mirror)
            .expect("identical mirror passes");
    }

    #[test]
    fn a_changed_mirror_asset_is_refused_by_name() {
        let (_root, canonical, mirror) = fixture();
        let name = "runtime-overlay-x86_64.tar.gz";
        std::fs::write(mirror.join(name), b"different bytes").expect("mutate mirror");
        let error = verify_assets(&std::collections::BTreeMap::new(), &canonical, &mirror)
            .expect_err("drift must fail");
        assert!(
            error.to_string().contains(name),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn canonical_bytes_must_match_the_signed_root_when_declared() {
        let (_root, canonical, mirror) = fixture();
        let name = "builder-vm-vmlinux-aarch64";
        let bytes = name.as_bytes();
        let artifact = MemberArtifact {
            name: ArtifactName::new(name).expect("valid name"),
            format: ArtifactFormat::Kernel(mvm_core::kernel_format::KernelFormat::Image),
            sha256: Sha256Hex::from_bytes(bytes),
            size: u64::try_from(bytes.len()).expect("fixture length fits u64"),
        };
        let declared = std::collections::BTreeMap::from([(name, &artifact)]);
        std::fs::write(canonical.join(name), b"same wrong bytes").expect("mutate canonical");
        std::fs::write(mirror.join(name), b"same wrong bytes").expect("mutate mirror");
        let error =
            verify_assets(&declared, &canonical, &mirror).expect_err("root drift must fail");
        assert!(
            error.to_string().contains("disagrees with signed root"),
            "unexpected error: {error:#}"
        );
    }
}
