//! Snapshot-upper volume — copy-on-write over a read-only base.
//!
//! A `SnapshotUpper` presents a base directory plus a writable upper:
//! reads prefer the upper and fall back to the base; writes always land in
//! the upper, so the base is never mutated and the upper holds only the
//! delta. This is the userspace model of the warm-start diff-snapshot
//! (plan 123 B3 → Phase C): on Linux the production path is an overlayfs /
//! dm-snapshot mount, but the COW semantics — base immutable, upper carries
//! the changes — are the same, and modelling them here keeps the storage
//! half testable without a kernel mount.

use std::path::{Path, PathBuf};

use mvm_core::volume::{VolumeError, VolumePath};

/// Copy-on-write view: `base` is read-only, `upper` collects the delta.
pub struct SnapshotUpper {
    base: PathBuf,
    upper: PathBuf,
}

impl SnapshotUpper {
    /// Open a COW view over `base`, creating `upper` if absent. `base` is
    /// never written through this type.
    pub fn new(base: impl Into<PathBuf>, upper: impl Into<PathBuf>) -> Result<Self, VolumeError> {
        let upper = upper.into();
        std::fs::create_dir_all(&upper)?;
        Ok(Self {
            base: base.into(),
            upper,
        })
    }

    /// Read `rel`: the upper shadows the base.
    pub fn read(&self, rel: &str) -> Result<Vec<u8>, VolumeError> {
        let up = safe_join(&self.upper, rel)?;
        if up.exists() {
            return Ok(std::fs::read(up)?);
        }
        Ok(std::fs::read(safe_join(&self.base, rel)?)?)
    }

    /// Materialize a private, writable boot image from a single base file,
    /// leaving the golden base untouched. Returns the upper-side path, ready
    /// to boot from for a disk-only warm-start (libkrun, plan 123 C4): the
    /// base stays immutable, per-instance writes land in the clone, and a
    /// re-resume reuses the existing clone rather than clobbering it.
    ///
    /// NOTE: a plain byte copy today — on a reflink-capable FS (APFS
    /// `clonefile`, Linux `FICLONE`) this should be a CoW clone so warm-start
    /// stays O(1); tracked as a follow-up. The COW *semantics* (immutable
    /// base) hold regardless.
    pub fn materialize_image(&self, rel: &str) -> Result<PathBuf, VolumeError> {
        let base = safe_join(&self.base, rel)?;
        let target = safe_join(&self.upper, rel)?;
        if !target.exists() {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&base, &target)?;
        }
        Ok(target)
    }

    /// Write `rel` into the upper (copy-up). The base is untouched.
    pub fn write(&self, rel: &str, bytes: &[u8]) -> Result<(), VolumeError> {
        let target = safe_join(&self.upper, rel)?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(target, bytes)?;
        Ok(())
    }
}

/// Join `rel` under `root`, rejecting anything that could escape the overlay.
/// `VolumePath` enforces relative-only, no `..`, no NUL (claim 1: a volume
/// must not reach host fs outside itself).
fn safe_join(root: &Path, rel: &str) -> Result<PathBuf, VolumeError> {
    let rel = VolumePath::new(rel).map_err(|e| VolumeError::InvalidPath(e.to_string()))?;
    Ok(root.join(rel.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_upper_writes_only_delta_over_readonly_base() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("base");
        let upper = tmp.path().join("upper");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("a.txt"), b"BASE_A").unwrap();

        let snap = SnapshotUpper::new(&base, &upper).unwrap();

        // Read falls through to the base.
        assert_eq!(snap.read("a.txt").unwrap(), b"BASE_A");

        // A new file is written to the upper only — the base never sees it.
        snap.write("b.txt", b"DELTA_B").unwrap();
        assert_eq!(snap.read("b.txt").unwrap(), b"DELTA_B");
        assert!(
            !base.join("b.txt").exists(),
            "base must not carry the delta"
        );
        assert!(upper.join("b.txt").exists(), "delta lives in the upper");

        // Overwriting a base file copies up: the upper shadows it, the base
        // bytes stay original.
        snap.write("a.txt", b"OVERRIDDEN_A").unwrap();
        assert_eq!(snap.read("a.txt").unwrap(), b"OVERRIDDEN_A");
        assert_eq!(
            std::fs::read(base.join("a.txt")).unwrap(),
            b"BASE_A",
            "base file must remain immutable"
        );
    }

    #[test]
    fn materialize_image_clones_base_into_a_private_writable_upper() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("base");
        let upper = tmp.path().join("upper");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("rootfs.ext4"), b"GOLDEN").unwrap();

        let snap = SnapshotUpper::new(&base, &upper).unwrap();
        let warm = snap.materialize_image("rootfs.ext4").unwrap();

        // The warm rootfs lives in the upper and carries the base bytes.
        assert_eq!(warm, upper.join("rootfs.ext4"));
        assert_eq!(std::fs::read(&warm).unwrap(), b"GOLDEN");

        // Writing through the warm clone never touches the golden base.
        std::fs::write(&warm, b"DIRTY_INSTANCE").unwrap();
        assert_eq!(
            std::fs::read(base.join("rootfs.ext4")).unwrap(),
            b"GOLDEN",
            "golden base must stay immutable"
        );

        // A second resume reuses the existing warm clone (no re-copy that
        // would clobber instance state).
        let warm2 = snap.materialize_image("rootfs.ext4").unwrap();
        assert_eq!(warm2, warm);
        assert_eq!(std::fs::read(&warm2).unwrap(), b"DIRTY_INSTANCE");
    }

    #[test]
    fn materialize_image_rejects_traversal_and_missing_base() {
        let tmp = tempfile::tempdir().unwrap();
        let snap = SnapshotUpper::new(tmp.path().join("base"), tmp.path().join("upper")).unwrap();
        assert!(snap.materialize_image("../escape.ext4").is_err());
        // Base image absent → error, not a silent empty rootfs.
        assert!(snap.materialize_image("nope.ext4").is_err());
    }

    #[test]
    fn snapshot_upper_rejects_path_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let snap = SnapshotUpper::new(tmp.path().join("base"), tmp.path().join("upper")).unwrap();
        assert!(snap.write("../escape", b"x").is_err());
        assert!(snap.read("../../etc/passwd").is_err());
    }
}
