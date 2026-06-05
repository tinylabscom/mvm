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
    fn snapshot_upper_rejects_path_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let snap = SnapshotUpper::new(tmp.path().join("base"), tmp.path().join("upper")).unwrap();
        assert!(snap.write("../escape", b"x").is_err());
        assert!(snap.read("../../etc/passwd").is_err());
    }
}
