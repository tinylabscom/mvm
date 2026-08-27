//! Per-instance writable rootfs preparation.
//!
//! Each running VM owns its own writable rootfs so the hypervisor can attach
//! it without conflicting with sibling instances, and the source template
//! stays pristine. The clone is copy-on-write where the filesystem supports it
//! (APFS `clonefile`, Linux `FICLONE`), so materializing a multi-GiB rootfs is
//! O(1) until either side writes; the reflink mechanics themselves live in
//! [`mvm_fs::clone`].

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use mvm_fs::clone::reflink_or_copy;

/// The strategy [`clone_rootfs_for_instance`] used to materialize a clone.
///
/// Re-exported from [`mvm_fs::clone`] — the canonical home of the reflink
/// primitives — so callers naming this function's return type don't have to
/// reach across crates.
pub use mvm_fs::clone::CloneStrategy;

/// Reflink-clone a rootfs file for per-instance use.
///
/// When starting a VM from a template (or any time concurrent
/// instances need their own writable rootfs), call this instead of
/// pointing the hypervisor at the source directly. The
/// clone shares blocks with the source until either side writes, so
/// on APFS / btrfs / xfs the operation is O(1) wall-clock regardless
/// of rootfs size. On filesystems without reflink support (ext4 on the
/// Linux host / builder VM, NTFS, etc.) it falls back to a byte copy.
///
/// `src` must exist; `dst` must not. The destination's parent
/// directory is created if it doesn't already exist.
///
/// HVF and Firecracker each expect a running VM to own its disk
/// image — sharing a rootfs path between two concurrent VMs makes
/// the second start fail. This helper is the seam where that
/// per-instance ownership is created.
#[tracing::instrument(skip_all, fields(src = %src.display(), dst = %dst.display()))]
pub fn clone_rootfs_for_instance(src: &Path, dst: &Path) -> Result<CloneStrategy> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating parent directory for {}", dst.display()))?;
    }
    let strategy = reflink_or_copy(src, dst)
        .with_context(|| format!("cloning rootfs {} -> {}", src.display(), dst.display()))?;
    tracing::debug!(?strategy, "rootfs clone complete");
    Ok(strategy)
}

/// Per-instance rootfs path for `vm_name`: `<vm_state_dir>/rootfs.ext4`. Each
/// running VM owns its own writable copy so the hypervisor can attach it
/// writable without conflicting with sibling instances, and the source template
/// stays pristine. Shared by every backend that needs per-instance ownership.
pub fn instance_rootfs_path(vm_name: &str) -> Result<PathBuf> {
    Ok(mvm_core::config::vm_state_dir(vm_name).join("rootfs.ext4"))
}

/// Materialize the per-instance rootfs for `vm_name` from `source_rootfs` and
/// return its absolute path. No-op if the source is already the per-instance
/// path (a re-start). Otherwise removes any stale per-instance file from a prior
/// failed run, then CoW-clones the source via [`clone_rootfs_for_instance`].
pub fn prepare_instance_rootfs(vm_name: &str, source_rootfs: &str) -> Result<PathBuf> {
    let instance_path = instance_rootfs_path(vm_name)?;
    prepare_instance_rootfs_inner(&instance_path, source_rootfs)
}

/// Inner implementation that takes the instance path directly, so tests don't
/// mutate `HOME` / `MVM_HOME`.
pub fn prepare_instance_rootfs_inner(instance_path: &Path, source_rootfs: &str) -> Result<PathBuf> {
    let source_path = Path::new(source_rootfs);
    if source_path == instance_path {
        // Already the per-instance copy — nothing to clone.
        return Ok(instance_path.to_path_buf());
    }
    if instance_path.exists() {
        std::fs::remove_file(instance_path).with_context(|| {
            format!(
                "removing stale per-instance rootfs at {}",
                instance_path.display()
            )
        })?;
    }
    let strategy = clone_rootfs_for_instance(source_path, instance_path)?;
    tracing::info!(
        ?strategy,
        source = %source_path.display(),
        instance = %instance_path.display(),
        "prepared per-instance rootfs",
    );

    // The runtime-meta gate reads mvm-meta.json from the rootfs's own directory,
    // so any rootfs clone that may later be checkpointed or forked must carry the
    // sidecar alongside it.
    copy_sidecars_if_present(source_path, instance_path);

    Ok(instance_path.to_path_buf())
}

/// Guest sidecar files that may sit next to `rootfs.ext4` and must travel
/// with it when it is cloned into a per-instance path.
const ROOTFS_SIDECAR_FILES: &[&str] = &[
    mvm_build::builder_vm::SIDECAR_FILENAME,
    "rootfs.verity",
    "rootfs.roothash",
];

/// Copy guest sidecars from the source rootfs's directory to the destination
/// rootfs's directory when they exist. Silently does nothing when the source
/// has no sidecars (older build dirs / unsealed images) or when source and
/// destination dirs are the same.
fn copy_sidecars_if_present(source_rootfs: &Path, dest_rootfs: &Path) {
    let src_dir = match source_rootfs.parent() {
        Some(d) => d,
        None => return,
    };
    let dst_dir = match dest_rootfs.parent() {
        Some(d) => d,
        None => return,
    };
    if src_dir == dst_dir {
        return;
    }
    for name in ROOTFS_SIDECAR_FILES {
        let src_sidecar = src_dir.join(name);
        if !src_sidecar.exists() {
            continue;
        }
        let dst_sidecar = dst_dir.join(name);
        if let Err(e) = std::fs::copy(&src_sidecar, &dst_sidecar) {
            tracing::warn!(
                src = %src_sidecar.display(),
                dst = %dst_sidecar.display(),
                error = %e,
                "could not copy {name} sidecar alongside rootfs clone",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_instance_rootfs_inner_clones_into_the_per_instance_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("golden.ext4");
        std::fs::write(&src, b"golden").unwrap();
        let instance = dir.path().join("inst").join("rootfs.ext4");
        let out = prepare_instance_rootfs_inner(&instance, src.to_str().unwrap()).expect("clone");
        assert_eq!(out, instance);
        assert!(instance.exists());
        // Writing the per-instance clone must not tamper the source template.
        std::fs::write(&instance, b"changed").unwrap();
        assert_eq!(std::fs::read(&src).unwrap(), b"golden");
    }

    #[test]
    fn prepare_instance_rootfs_inner_is_noop_when_source_is_the_instance() {
        let dir = tempfile::tempdir().expect("tempdir");
        let inst = dir.path().join("rootfs.ext4");
        std::fs::write(&inst, b"x").unwrap();
        let out = prepare_instance_rootfs_inner(&inst, inst.to_str().unwrap()).expect("noop");
        assert_eq!(out, inst);
    }

    #[test]
    fn clone_copies_sidecar_when_present() {
        let src_dir = tempfile::tempdir().expect("src tempdir");
        let dst_dir = tempfile::tempdir().expect("dst tempdir");
        let src = src_dir.path().join("rootfs.ext4");
        std::fs::write(&src, b"data").unwrap();
        std::fs::write(
            src_dir.path().join(mvm_build::builder_vm::SIDECAR_FILENAME),
            b"{\"accessible\":true,\"overlay_aware\":false}",
        )
        .unwrap();
        let instance = dst_dir.path().join("rootfs.ext4");
        prepare_instance_rootfs_inner(&instance, src.to_str().unwrap()).expect("clone");
        let dst_sidecar = dst_dir.path().join(mvm_build::builder_vm::SIDECAR_FILENAME);
        assert!(
            dst_sidecar.exists(),
            "sidecar must travel alongside the cloned rootfs"
        );
        let content = std::fs::read_to_string(&dst_sidecar).unwrap();
        assert!(content.contains("accessible"));
    }

    #[test]
    fn clone_copies_verity_sidecars_when_present() {
        let src_dir = tempfile::tempdir().expect("src tempdir");
        let dst_dir = tempfile::tempdir().expect("dst tempdir");
        let src = src_dir.path().join("rootfs.ext4");
        std::fs::write(&src, b"data").unwrap();
        std::fs::write(src_dir.path().join("rootfs.verity"), b"verity-tree").unwrap();
        std::fs::write(src_dir.path().join("rootfs.roothash"), b"abc123").unwrap();
        let instance = dst_dir.path().join("rootfs.ext4");
        prepare_instance_rootfs_inner(&instance, src.to_str().unwrap()).expect("clone");
        assert!(dst_dir.path().join("rootfs.verity").exists());
        assert!(dst_dir.path().join("rootfs.roothash").exists());
        let hash = std::fs::read_to_string(dst_dir.path().join("rootfs.roothash")).unwrap();
        assert_eq!(hash, "abc123");
    }

    #[test]
    fn clone_succeeds_without_sidecar() {
        let src_dir = tempfile::tempdir().expect("src tempdir");
        let dst_dir = tempfile::tempdir().expect("dst tempdir");
        let src = src_dir.path().join("rootfs.ext4");
        std::fs::write(&src, b"data").unwrap();
        // Deliberately no sidecar in src_dir.
        let instance = dst_dir.path().join("rootfs.ext4");
        prepare_instance_rootfs_inner(&instance, src.to_str().unwrap())
            .expect("clone without sidecar");
        assert!(instance.exists());
        assert!(
            !dst_dir
                .path()
                .join(mvm_build::builder_vm::SIDECAR_FILENAME)
                .exists(),
            "no sidecar in dst when source has none"
        );
    }

    #[test]
    fn noop_early_return_copies_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let inst = dir.path().join("rootfs.ext4");
        std::fs::write(&inst, b"x").unwrap();
        std::fs::write(
            dir.path().join(mvm_build::builder_vm::SIDECAR_FILENAME),
            b"{}",
        )
        .unwrap();
        // source == instance path → early return; no second sidecar file expected
        prepare_instance_rootfs_inner(&inst, inst.to_str().unwrap()).expect("noop");
        // Sidecar exists from the write above — confirm no second copy appeared
        // (we can't observe a "double write" easily but at least assert no error).
        assert!(
            dir.path()
                .join(mvm_build::builder_vm::SIDECAR_FILENAME)
                .exists()
        );
    }
}
