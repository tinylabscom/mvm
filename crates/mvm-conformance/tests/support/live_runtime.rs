//! Assemble both boot artifacts from the same independently verified runtime.

use std::path::Path;

use anyhow::Result;
use mvm_build::guest_runtime::GuestRuntime;
use mvm_core::arch::GuestArch;
use mvm_fs::{initramfs::InitramfsArtifact, overlay::RuntimeOverlayArtifact};

pub(crate) fn prepare(
    cache: &Path,
    runtime: &GuestRuntime,
) -> Result<(RuntimeOverlayArtifact, InitramfsArtifact)> {
    let version = env!("CARGO_PKG_VERSION");
    let arch = GuestArch::host();
    let initramfs = mvm_build::initramfs::build_initramfs_from_guest_runtime(
        &cache.join("initramfs"),
        version,
        arch,
        runtime,
    )?;
    let overlay = mvm_build::runtime_overlay::build_runtime_overlay_from_guest_runtime(
        cache, version, arch, runtime,
    )?;
    Ok((overlay, initramfs))
}
