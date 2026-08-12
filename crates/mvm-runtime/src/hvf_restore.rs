//! The HVF end of the checkpoint restore seams.
//!
//! Both seams the checkpoint orchestration owns —
//! the [`ForkRestore`](crate::checkpoint::ForkRestore) callback for a fork into
//! a fresh identity and [`VmFullRestore`](crate::checkpoint::VmFullRestore) for
//! a same-identity resume — reduce to one operation on HVF: start a supervisor
//! that maps the saved RAM privately and restores the captured vCPU and device
//! frame. The mechanics live one layer down in
//! [`mvm_backends::driver::hvf_restore`]; this module is the thin adapter that
//! keeps the checkpoint layer free of supervisor-config knowledge.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_backends::driver::hvf_restore::restore_hvf_vm;

pub use mvm_backends::driver::hvf_restore::{
    HvfRestoreRequest, RestoredHvfVm, hvf_child_restore_config,
};

/// Boots a forked child from an HVF checkpoint cloned into its state dir.
///
/// An inherent method rather than a trait impl, matching `FcForkRestorer`: the
/// fork walk takes a [`crate::checkpoint::ForkRestore`] callback, so the two
/// VMMs need no shared trait and neither has to be named where the other is.
pub struct HvfForkRestorer;

impl HvfForkRestorer {
    pub fn restore_fork(&self, child: &crate::checkpoint::RestoredChild<'_>) -> Result<()> {
        restore_hvf_vm(&HvfRestoreRequest {
            vm_name: child.vm_name,
            state_dir: child.state_dir,
            cpu_grant: child.cpu_grant,
        })
        .with_context(|| format!("HVF warm-restore for forked child '{}'", child.vm_name))?;
        Ok(())
    }
}

/// Resumes a VM under its own identity from an HVF vm_full checkpoint.
pub struct HvfVmFullRestore;

impl crate::checkpoint::VmFullRestore for HvfVmFullRestore {
    /// The path arguments describe the checkpoint's content dir, which is
    /// immutable; a restore must never boot a VMM against it, because a
    /// resumed guest writes through to its rootfs and would corrupt the sealed
    /// bytes every later fork of this checkpoint depends on. Instead the whole
    /// content dir is cloned into the target's state dir and the VM boots from
    /// that copy — the same "child boots its OWN copies" rule a fork follows.
    fn restore(
        &self,
        target_vm: &str,
        rootfs_src: &Path,
        _memory: &Path,
        _machine_id: &Path,
        _config_src: Option<&Path>,
    ) -> Result<()> {
        let content_dir = rootfs_src
            .parent()
            .ok_or_else(|| anyhow::anyhow!("checkpoint rootfs path has no content directory"))?;
        let state_dir = mvm_core::config::vm_state_dir(target_vm);
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("creating {}", state_dir.display()))?;
        clone_content_into(content_dir, &state_dir)?;
        restore_hvf_vm(&HvfRestoreRequest {
            vm_name: target_vm,
            state_dir: &state_dir,
            // A same-identity resume admits no plan of its own — it is the VM
            // that was already admitted, coming back — so there is no grant here
            // to bind. Inventing one from the checkpoint record would be a bound
            // nobody signed for this run.
            cpu_grant: None,
        })
        .with_context(|| format!("HVF restore of '{target_vm}'"))?;
        Ok(())
    }
}

/// Copy-on-write clone every file in a checkpoint's content dir into `dst`.
fn clone_content_into(content_dir: &Path, dst: &Path) -> Result<()> {
    let entries = std::fs::read_dir(content_dir)
        .with_context(|| format!("reading checkpoint content {}", content_dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("reading {}", content_dir.display()))?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        crate::base::cow::clone_rootfs_for_instance(&entry.path(), &dst.join(&name))
            .with_context(|| format!("cloning checkpoint blob {}", name.to_string_lossy()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::VmFullRestore as _;

    #[test]
    fn clone_content_copies_every_blob_and_skips_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("content");
        let dst = tmp.path().join("state");
        std::fs::create_dir_all(src.join("nested")).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("memory.bin"), b"ram").unwrap();
        std::fs::write(src.join("rootfs.ext4"), b"root").unwrap();

        clone_content_into(&src, &dst).unwrap();

        assert_eq!(std::fs::read(dst.join("memory.bin")).unwrap(), b"ram");
        assert_eq!(std::fs::read(dst.join("rootfs.ext4")).unwrap(), b"root");
        assert!(!dst.join("nested").exists(), "directories are not cloned");
    }

    /// A restore must never point a VMM at the sealed checkpoint content: the
    /// resumed guest writes through to its rootfs, and the bytes under
    /// `content/` are what every later fork of this checkpoint verifies
    /// against. The refusal here is structural — the restore always clones
    /// first — so the assertion is that a content dir with no saved state
    /// fails before any process is spawned.
    #[test]
    fn restore_refuses_before_spawning_when_the_checkpoint_has_no_saved_state() {
        let tmp = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(tmp.path());
        let content = tmp.path().join("content");
        std::fs::create_dir_all(&content).unwrap();
        std::fs::write(content.join("rootfs.ext4"), b"root").unwrap();

        let error = HvfVmFullRestore
            .restore(
                "hvf-restore-missing-state-vm",
                &content.join("rootfs.ext4"),
                &content.join("memory.bin"),
                &content.join("machine-id"),
                None,
            )
            .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("launch config"),
            "expected the missing launch-config refusal, got: {rendered}"
        );
    }
}
