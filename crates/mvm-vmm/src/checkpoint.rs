//! Backend-agnostic host-side control over a running VM's memory + disk.
//!
//! The [`VmFullControl`] trait abstracts pause/save-memory/resume so the
//! checkpoint capture orchestration in `mvm-runtime` is testable without a live
//! hypervisor. Concrete drivers (Firecracker, HVF, ...) implement this trait
//! and hand it back through [`crate::driver::VmmDriver::vm_full_control`].

use std::path::{Path, PathBuf};

use anyhow::Result;

/// Host-side control over a running VM's memory + disk, abstracted so the
/// capture orchestration is testable without a live hypervisor.
pub trait VmFullControl {
    /// Pause vCPUs (idempotent if already paused).
    fn pause(&self) -> Result<()>;
    /// Save machine memory state to `memory_path` while paused; also writes a
    /// `<memory_path>.machine-id` sidecar when the backend has a machine
    /// identifier (e.g. Vz). Backends that do not have a separate machine-id
    /// concept (e.g. Firecracker) may skip the sidecar — the caller only
    /// promotes it to a content blob when the file exists.
    fn save_memory(&self, memory_path: &Path) -> Result<()>;
    /// Resume vCPUs.
    fn resume(&self) -> Result<()>;
    /// Keep the paused VMM resident after a successful capture so a driver can
    /// hand its machine instance directly to the next claim.
    fn retain_paused_after_capture(&self) -> bool {
        false
    }
    /// Absolute path to the VM's live rootfs image.
    fn rootfs_path(&self) -> Result<PathBuf>;
    /// Optional extra content blobs written alongside `save_memory` that this
    /// backend's capture produces. The default returns nothing; backends that
    /// write additional files (e.g. Firecracker's `vmstate.bin`) override this
    /// to hash and return them so they are included in the checkpoint manifest.
    /// Called after `save_memory` has been called and the files are on disk.
    fn extra_content(&self, content_dir: &Path) -> Result<Vec<mvm_core::checkpoint::ContentBlob>> {
        let _ = content_dir;
        Ok(vec![])
    }

    /// Optional backend launch configuration required to recreate a fresh VMM
    /// around a captured machine state.
    fn supervisor_config_path(&self) -> Result<Option<PathBuf>> {
        Ok(None)
    }

    /// Absolute host paths the snapshot embeds and a fork restore must remap.
    fn device_anchors(&self) -> Result<mvm_core::checkpoint::DeviceAnchors>;
}
