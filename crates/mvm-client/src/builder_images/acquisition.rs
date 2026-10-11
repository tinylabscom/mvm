//! Explicit acquisition adapters over the signed, locked image set.
use anyhow::{Context, Result};
use mvm_build::builder_vm::GuestSidecar;
use std::path::Path;

pub struct AcquiredProvenance {
    pub image_tag: String,
    pub source: &'static str,
    pub acquired_at: String,
}

impl AcquiredProvenance {
    pub fn fetched(tag: &str) -> Self {
        Self {
            image_tag: tag.to_owned(),
            source: "fetched",
            acquired_at: mvm_core::util::time::utc_now(),
        }
    }
}

/// Stamp only acquisition facts; preserve every producer-authored build fact.
pub fn stamp_provenance(dir: &Path, provenance: &AcquiredProvenance) -> Result<()> {
    let mut sidecar = GuestSidecar::read_from_dir(dir)
        .with_context(|| format!("read the sidecar in {}", dir.display()))?
        .with_context(|| format!(
            "{} carries no {} sidecar; refusing to boot-tag an image that did not declare what it is",
            dir.display(), mvm_build::builder_vm::SIDECAR_FILENAME
        ))?;
    sidecar.image_tag = provenance.image_tag.clone();
    sidecar.source = provenance.source.to_owned();
    sidecar.built_at = provenance.acquired_at.clone();
    sidecar
        .write_to_dir(dir)
        .with_context(|| format!("write the stamped sidecar to {}", dir.display()))?;
    Ok(())
}

pub fn acquire_image_set() -> Result<mvm_build::published_image_set::PublishedImageSet> {
    mvm_build::published_image_set::PublishedImageSet::acquire_from(
        mvm_build::published_image_set::ImageSetSource::locked()
            .with_download(download_locked_artifact),
    )
}

pub(super) fn download_locked_artifact(url: &str, dest: &Path) -> Result<()> {
    mvm_build::artifact_download::download(url, dest)
}

pub fn download_kernel(arch: &str, variant: &str, dest: &Path) -> Result<()> {
    let (image, role) = match variant {
        "workload" => (
            "default-microvm",
            mvm_core::image_set::ImageSetRole::WorkloadKernel(
                mvm_core::image_set::WorkloadImageProfile::DefaultTenant,
            ),
        ),
        "builder" => ("builder-vm", mvm_core::image_set::ImageSetRole::BuilderVm),
        other => anyhow::bail!(
            "unknown kernel variant {other:?}: the boot image publishes only the \
             workload (default-microvm) and builder (builder-vm) kernels"
        ),
    };
    let asset = format!("{image}-vmlinux-{arch}");
    let arch = arch.parse::<mvm_core::arch::GuestArch>()?;
    let parent = dest
        .parent()
        .with_context(|| format!("kernel destination has no parent: {}", dest.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating kernel cache dir {}", parent.display()))?;
    let download = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| {
            format!(
                "creating kernel download staging file in {}",
                parent.display()
            )
        })?
        .into_temp_path();
    let set = acquire_image_set()?;
    let artifact = set.artifact(role, mvm_core::image_set::MemberTarget::Arch(arch), &asset)?;
    set.fetch_artifact(artifact, &download)
        .with_context(|| format!("download {asset} from the locked image set"))?;
    publish_downloaded_kernel(download, dest)
}

pub fn publish_downloaded_kernel(download: tempfile::TempPath, dest: &Path) -> Result<()> {
    download
        .persist(dest)
        .map_err(|error| error.error)
        .with_context(|| format!("publishing downloaded kernel to {}", dest.display()))?;
    if let Err(error) = mvm_build::kernel_fetch::record_kernel_digest(dest) {
        let _ = std::fs::remove_file(dest);
        let _ = std::fs::remove_file(mvm_build::kernel_fetch::kernel_digest_sidecar(dest));
        return Err(error).context("recording downloaded kernel digest");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_kernel_is_resolved_from_real_cache_and_tampering_is_refused() {
        let cache = tempfile::tempdir().unwrap();
        let arch = mvm_core::arch::GuestArch::host().to_string();
        let dest = mvm_build::kernel_fetch::cached_kernel_path(cache.path(), &arch, "workload");
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        let staged = tempfile::NamedTempFile::new_in(dest.parent().unwrap()).unwrap();
        std::fs::write(staged.path(), b"verified kernel fixture").unwrap();
        publish_downloaded_kernel(staged.into_temp_path(), &dest).unwrap();
        assert!(matches!(
            mvm_build::kernel_fetch::resolve_kernel(cache.path(), &arch, "workload", false),
            mvm_build::kernel_fetch::KernelResolution::Cached(_)
        ));
        std::fs::write(&dest, b"tampered kernel fixture").unwrap();
        assert!(!matches!(
            mvm_build::kernel_fetch::resolve_kernel(cache.path(), &arch, "workload", false),
            mvm_build::kernel_fetch::KernelResolution::Cached(_)
        ));
    }

    #[test]
    fn unknown_variant_is_refused_before_creating_cache_state() {
        let cache = tempfile::tempdir().unwrap();
        let dest = cache.path().join("missing/vmlinux");
        let error = download_kernel("aarch64", "untrusted", &dest).unwrap_err();
        assert!(error.to_string().contains("unknown kernel variant"));
        assert!(!dest.parent().unwrap().exists());
    }
}
