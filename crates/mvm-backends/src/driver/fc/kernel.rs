//! Firecracker kernel recipes: ordinary paths and held producer descriptors.
//!
//! Descriptor startup deliberately accepts only already-loadable images. The
//! ordinary boot machinery remains responsible for all non-kernel setup.

use std::path::PathBuf;

use anyhow::{Result, bail};
use mvm_vmm::driver::spec::{KernelImage, VmmSpec};

/// Resolve the explicit host kernel path from the spec, rejecting a bundled
/// kernel. Firecracker has no bundled kernel, so a `Bundled` spec must not
/// reach the API.
pub(super) fn resolve_fc_kernel_path(spec: &VmmSpec) -> Result<PathBuf> {
    match &spec.kernel {
        KernelImage::Path(p) => Ok(p.clone()),
        KernelImage::Bundled => {
            bail!(
                "the Firecracker driver requires an explicit kernel Image; VmmSpec.kernel is Bundled"
            )
        }
    }
}

/// Firecracker opens its boot source during the synchronous boot-source PUT.
/// Give it a reference to the caller's held, unlinked file, not the original
/// slot pathname. The caller must keep `kernel` alive until boot returns.
///
/// This producer continuity seam is not canonical bundle admission or an
/// enduring runtime measurement. In particular, the reported procfs path is
/// not evidence that a later observer can reopen after this borrow ends.
#[cfg(any(target_os = "linux", all(test, unix)))]
pub(super) fn fc_descriptor_recipe(
    spec: &VmmSpec,
    kernel: &mvm_vmm::host::restore_image::VerifiedRestoreFile,
) -> Result<VmmSpec> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::FileExt;

    resolve_fc_kernel_path(spec)?;
    let mut header = [0_u8; 64];
    let len = kernel.len().min(header.len() as u64) as usize;
    kernel.file().read_exact_at(&mut header[..len], 0)?;
    anyhow::ensure!(
        mvm_vmm::host::fc_kernel::is_elf(&header[..len])
            || mvm_vmm::host::fc_kernel::is_arm64_image(&header[..len]),
        "held Firecracker kernel must already be ELF or arm64 Image; descriptor startup cannot extract or use sibling caches"
    );
    let mut recipe = spec.clone();
    recipe.kernel = KernelImage::Path(PathBuf::from(format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        kernel.file().as_raw_fd()
    )));
    Ok(recipe)
}

#[cfg(unix)]
pub(super) fn boot_descriptor_custodied(
    driver: &super::FcDriver,
    spec: &VmmSpec,
    kernel: &mvm_vmm::host::restore_image::VerifiedRestoreFile,
    handoff: mvm_vmm::driver::prepared_disks::SudoWritableHandoff,
) -> Result<Box<dyn mvm_vmm::driver::traits::RunningVm>> {
    #[cfg(any(target_os = "linux", all(test, unix)))]
    {
        let recipe = fc_descriptor_recipe(spec, kernel)?;
        driver.boot_with_handoff(&recipe, Some(handoff))
    }
    #[cfg(not(any(target_os = "linux", all(test, unix))))]
    {
        let _ = (driver, spec, kernel, handoff);
        bail!("Firecracker descriptor startup requires the same Linux host")
    }
}

#[cfg(unix)]
pub(super) fn boot_descriptor(
    driver: &super::FcDriver,
    spec: &VmmSpec,
    kernel: &mvm_vmm::host::restore_image::VerifiedRestoreFile,
) -> Result<Box<dyn mvm_vmm::driver::traits::RunningVm>> {
    #[cfg(target_os = "linux")]
    {
        // This cannot cross the macOS -> builder shell boundary: procfs
        // must name the process holding this exact descriptor. No FD
        // inheritance through sudo or filename fallback is involved.
        let recipe = fc_descriptor_recipe(spec, kernel)?;
        mvm_vmm::driver::traits::VmmDriver::boot(driver, &recipe)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (driver, spec, kernel);
        bail!("Firecracker descriptor startup requires the same Linux host")
    }
}
