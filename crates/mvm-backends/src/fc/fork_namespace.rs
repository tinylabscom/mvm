//! Per-child mount-namespace remapping for Firecracker `vm_full` fork restore.
//!
//! Firecracker snapshots encode absolute host paths for block devices and the
//! vsock UDS. A forked child must make those recorded parent paths resolve to
//! its own copies. The remapping is done in a private mount namespace so the
//! parent VM's live mounts are untouched.

use std::path::PathBuf;

use anyhow::Result;

#[cfg(target_os = "linux")]
use anyhow::Context;
#[cfg(target_os = "linux")]
use std::path::Path;

/// Make every `parent_path` from the snapshot resolve to the corresponding
/// `child_path` inside a new private mount namespace.
///
/// This function must be called in the process that will launch the child
/// Firecracker; all spawned children inherit the namespace. The caller must
/// have privileges to create a mount namespace and perform bind mounts
/// (CAP_SYS_ADMIN, or root on most distributions).
#[cfg(target_os = "linux")]
pub fn remap_paths_for_fork(mappings: &[(PathBuf, PathBuf)]) -> Result<()> {
    if mappings.is_empty() {
        return Ok(());
    }

    enter_private_mount_namespace()
        .context("entering private mount namespace for fork remapping")?;

    for (parent_path, child_path) in mappings {
        ensure_parent_target(parent_path, child_path)
            .with_context(|| format!("preparing remap target {}", parent_path.display()))?;
        nix::mount::mount(
            Some(child_path.as_path()),
            parent_path.as_path(),
            Option::<&str>::None,
            nix::mount::MsFlags::MS_BIND,
            Option::<&str>::None,
        )
        .with_context(|| {
            format!(
                "bind mounting {} -> {}",
                child_path.display(),
                parent_path.display()
            )
        })?;
    }

    Ok(())
}

/// Non-Linux stub: Firecracker fork restore only runs on Linux hosts, but the
/// orchestration code compiles everywhere. Calling this on a non-Linux host is
/// a runtime error because the snapshot paths cannot be remapped without
/// Linux-specific mount namespace support.
#[cfg(not(target_os = "linux"))]
pub fn remap_paths_for_fork(_mappings: &[(PathBuf, PathBuf)]) -> Result<()> {
    anyhow::bail!("Firecracker vm_full fork remapping requires Linux")
}

#[cfg(target_os = "linux")]
fn enter_private_mount_namespace() -> Result<()> {
    // Unshare the mount namespace so subsequent bind mounts are isolated.
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS)
        .context("unsharing mount namespace")?;

    // Make all mounts private recursively so nothing we do propagates back to
    // the host namespace.
    nix::mount::mount(
        Some("none"),
        Path::new("/"),
        Option::<&str>::None,
        nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
        Option::<&str>::None,
    )
    .context("marking root mount as private")?;

    Ok(())
}

/// Create the parent-side path that the snapshot references, so bind-mounting
/// over it succeeds. Directories are mkdir-p'd; files are touched.
#[cfg(target_os = "linux")]
fn ensure_parent_target(parent_path: &Path, child_path: &Path) -> Result<()> {
    if let Some(parent) = parent_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating parent dir {}", parent.display()))?;
    }

    if parent_path.exists() {
        return Ok(());
    }

    if child_path.is_dir() {
        std::fs::create_dir_all(parent_path)
            .with_context(|| format!("creating directory placeholder {}", parent_path.display()))?;
    } else {
        std::fs::File::create(parent_path)
            .with_context(|| format!("creating file placeholder {}", parent_path.display()))?;
    }

    Ok(())
}
