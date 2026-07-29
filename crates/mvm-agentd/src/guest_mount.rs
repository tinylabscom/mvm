//! Guest-side mount library for PID-1 initramfs boot (Plan 270).
//!
//! This module owns the transition from the tiny initramfs to the
//! provisioned workload environment: dm-verity rootfs, dm-verity runtime
//! overlay, optional virtio-fs custom volumes, and the privilege drop that
//! follows.  It is intentionally separate from the runtime virtio-fs volume
//! handler (`crate::volume`) because the boot-time mounts run as root before
//! the agent drops privilege, use raw syscalls rather than `mount(8)`, and
//! must fail closed on roothash mismatch.

use std::path::{Path, PathBuf};

use crate::vsock::{RootfsConfig, RuntimeOverlayConfig, VolumeConfig};

/// Boot-time mount error.  Every failure path is terminal: PID 1 has no
/// init to fall back to, so the agent logs and exits non-zero.
#[derive(Debug, thiserror::Error)]
pub enum MountError {
    /// A syscall (mount, mkdir, pivot_root, setuid, ...) failed.
    #[error("syscall failed: {context}")]
    Syscall {
        context: String,
        source: std::io::Error,
    },
    /// The requested mountpoint or device path was rejected by policy.
    #[error("path policy denied: {0}")]
    PathPolicyDenied(String),
    /// dm-verity roothash mismatch or malformed hash.
    #[error("verity setup failed: {0}")]
    VeritySetup(String),
    /// A required filesystem type is unavailable.
    #[error("unsupported filesystem: {0}")]
    UnsupportedFilesystem(String),
}

impl MountError {
    /// Convenience constructor for libc wrappers.
    pub fn syscall(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Syscall {
            context: context.into(),
            source,
        }
    }
}

/// Result type for boot-time mount operations.
pub type Result<T> = std::result::Result<T, MountError>;

/// Basic early-boot filesystems the PID-1 agent needs before it can
/// receive `ActivateEnvironment` over vsock.
#[cfg(target_os = "linux")]
const MS_NOSUID: libc::c_ulong = 0x0000_0002;
#[cfg(target_os = "linux")]
const MS_NOEXEC: libc::c_ulong = 0x0000_0008;
#[cfg(target_os = "linux")]
const MS_NODEV: libc::c_ulong = 0x0000_0040;

/// Mount early-boot pseudo-filesystems.  Linux-only; other platforms
/// have no PID-1 initramfs path.
#[cfg(target_os = "linux")]
pub fn mount_early_filesystems() -> Result<()> {
    mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV)?;
    mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NOEXEC | MS_NODEV)?;
    // devtmpfs gives us /dev/console, /dev/null, etc. without a static
    // device table in the initramfs.  The workload kernel enables
    // CONFIG_DEVTMPFS_MOUNT; if it didn't, we mount it explicitly here.
    if Path::new("/dev/console").exists() {
        return Ok(());
    }
    mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn mount_early_filesystems() -> Result<()> {
    Ok(())
}

/// Mount the dm-verity rootfs, returning the path to the mounted tree
/// (a temporary location under `/mnt` before pivot_root/switch_root).
///
/// For now this is a structural stub: the full dm-verity ioctl setup
/// from `mvm-verity-init.rs` will be ported here in the next pass.
pub fn mount_rootfs(_rootfs: &RootfsConfig) -> Result<PathBuf> {
    // TODO: implement dm-verity rootfs mount.
    // 1. Validate roothash format.
    // 2. Create `/mnt/root` and `/mnt/overlay` workdirs.
    // 3. dmsetup create `mvm-root` from data_dev + hash_dev + roothash.
    // 4. mount ext4 `/dev/mapper/mvm-root` at `/mnt/root`.
    // 5. Return `/mnt/root`.
    ensure_dir("/mnt/root")?;
    Ok(PathBuf::from("/mnt/root"))
}

/// Mount the dm-verity runtime overlay inside the new root tree.
pub fn mount_runtime_overlay(_runtime: &RuntimeOverlayConfig, _root: &Path) -> Result<()> {
    // TODO: implement runtime-overlay mount at `<root>/mvm/runtime`.
    // 1. dmsetup create `mvm-runtime` from data_dev + hash_dev + roothash.
    // 2. mount ext4 `/dev/mapper/mvm-runtime` at `<root>/mvm/runtime` read-only.
    Ok(())
}

/// Mount any custom virtio-fs volumes inside the new root tree.
pub fn mount_volumes(_volumes: &[VolumeConfig], _root: &Path) -> Result<()> {
    // TODO: implement virtio-fs volume mounting after pivot.
    // Each volume is a separate virtio-fs tag mounted at `<root>/<mountpoint>`.
    Ok(())
}

/// Pivot into the mounted rootfs, making it the active `/` and moving the
/// old initramfs tree to a fallback path.
///
/// For now this is a structural stub.  The real implementation will use
/// `pivot_root` or `switch_root` semantics and is tightly coupled to the
/// overlay/workdir layout chosen in `mount_rootfs`.
pub fn pivot_to_root(_new_root: &Path) -> Result<()> {
    // TODO: implement pivot_root/switch_root.
    // 1. mount --bind new_root new_root
    // 2. chdir(new_root)
    // 3. pivot_root(new_root, "initrd")
    // 4. umount old root (lazy)
    // 5. chdir("/")
    Ok(())
}

/// Drop root privilege to the fixed workload UID (901).  Must run after
/// all root-only mounts are complete.
pub fn drop_privilege(uid: u32, gid: u32) -> Result<()> {
    // Order matters: setgid before setuid so the saved gid stays usable.
    setgid(gid)?;
    setuid(uid)?;
    // Paranoia: confirm we cannot regain root.
    if unsafe { libc::getuid() } == 0 {
        return Err(MountError::Syscall {
            context: "privilege drop failed: still uid 0".to_string(),
            source: std::io::Error::from_raw_os_error(libc::EPERM),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Low-level syscall wrappers
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn mount(source: &str, target: &str, fstype: &str, flags: libc::c_ulong) -> Result<()> {
    let source = std::ffi::CString::new(source).map_err(|e| MountError::Syscall {
        context: "mount source contains nul".to_string(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, e),
    })?;
    let target = std::ffi::CString::new(target).map_err(|e| MountError::Syscall {
        context: "mount target contains nul".to_string(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, e),
    })?;
    let fstype = std::ffi::CString::new(fstype).map_err(|e| MountError::Syscall {
        context: "mount fstype contains nul".to_string(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, e),
    })?;
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            flags,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(MountError::syscall(
            format!("mount({source:?}, {target:?}, {fstype:?})"),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn ensure_dir(path: &str) -> Result<()> {
    match std::fs::create_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(MountError::syscall(format!("mkdir {path}"), e)),
    }
}

fn setuid(uid: u32) -> Result<()> {
    let rc = unsafe { libc::setuid(uid) };
    if rc != 0 {
        return Err(MountError::syscall(
            format!("setuid({uid})"),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn setgid(gid: u32) -> Result<()> {
    let rc = unsafe { libc::setgid(gid) };
    if rc != 0 {
        return Err(MountError::syscall(
            format!("setgid({gid})"),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}
