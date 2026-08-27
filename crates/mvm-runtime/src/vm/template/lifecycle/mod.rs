//! Template lifecycle: legacy name-keyed CRUD, manifest-keyed slots,
//! artifact resolution/installation, dev builds, vsock health polling,
//! and registry push/pull/verify. Split by concern across the
//! submodules below; every `pub` item in each submodule is re-exported
//! here so `crate::vm::template::lifecycle::<name>` keeps resolving
//! exactly as it did when this was a single file.

mod artifacts;
mod build;
mod build_image;
mod health;
mod registry_sync;
mod slots;
mod snapshot;

pub use artifacts::*;
pub use build::*;
pub use build_image::*;
pub use health::*;
pub use registry_sync::*;
pub use slots::*;
pub use snapshot::*;

use anyhow::Result;

// `clone_rootfs_for_instance` moved to `crate::base::cow`.
// Re-exported here so existing
// `crate::vm::template::lifecycle::clone_rootfs_for_instance` callers
// keep resolving without each one having to migrate.
pub use crate::base::cow::clone_rootfs_for_instance;

// `seal_snapshot_artifacts` + `verify_snapshot_artifacts` moved to
// `crate::base::snapshot_integrity`. Re-exported below so
// the local `create_snapshot` call site keeps resolving without
// renaming.
pub use crate::base::snapshot_integrity::{seal_snapshot_artifacts, verify_snapshot_artifacts};

/// Wire-format string for a [`BuildMode`] when it lands on disk in
/// the revision record. Matches the CLI's `--dev`/`--prod` flag
/// names so the round-trip user-facing.
fn build_mode_label(mode: mvm_build::pipeline::BuildMode) -> &'static str {
    match mode {
        mvm_build::pipeline::BuildMode::Dev => "dev",
        mvm_build::pipeline::BuildMode::Prod => "prod",
    }
}

fn require_local_template_fs() -> Result<()> {
    // Registry push/pull needs direct file access to ~/.mvm/templates.
    // With Lima gone the host always has direct access; no-op.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::cow::CloneStrategy;

    #[test]
    fn clone_rootfs_creates_independent_per_instance_copy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("template.ext4");
        let dst = dir.path().join("vms/instance-1/rootfs.ext4");
        std::fs::write(&src, b"template payload").expect("write src");

        // Parent of dst doesn't exist yet — helper must create it.
        let strategy = clone_rootfs_for_instance(&src, &dst).expect("clone");
        assert!(matches!(
            strategy,
            CloneStrategy::Reflink | CloneStrategy::Copied
        ));
        assert_eq!(std::fs::read(&dst).unwrap(), b"template payload");

        // Writing to the per-instance copy must not mutate the template.
        std::fs::write(&dst, b"instance-only writes").expect("write dst");
        assert_eq!(std::fs::read(&src).unwrap(), b"template payload");
    }

    #[test]
    fn clone_rootfs_refuses_to_overwrite_existing_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("template.ext4");
        let dst = dir.path().join("instance.ext4");
        std::fs::write(&src, b"src").expect("write src");
        std::fs::write(&dst, b"existing").expect("write dst");
        // Existing destination must error — reflink_or_copy refuses
        // to overwrite to keep template/instance state honest.
        assert!(clone_rootfs_for_instance(&src, &dst).is_err());
    }
}
