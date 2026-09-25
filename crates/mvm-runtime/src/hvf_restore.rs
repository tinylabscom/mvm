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
use mvm_backends::driver::hvf_restore::{VERIFIED_ON_LOAD, restore_hvf_vm};
use mvm_core::checkpoint::ContentBlob;

pub use mvm_backends::driver::hvf_restore::{
    HvfRestoreRequest, RestoredHvfVm, hvf_child_restore_config,
};

/// Boots a forked child from an HVF checkpoint cloned into its state dir.
///
/// Verifies the saved RAM and frame itself, on the private copies it maps, so
/// the fork walk leaves those two blobs to it.
pub struct HvfForkRestorer;

impl crate::checkpoint::ForkRestorer for HvfForkRestorer {
    fn verifies_on_load(&self) -> &'static [&'static str] {
        VERIFIED_ON_LOAD
    }

    fn restore(&self, child: &crate::checkpoint::RestoredChild<'_>) -> Result<()> {
        restore_hvf_vm(&HvfRestoreRequest {
            vm_name: child.vm_name,
            state_dir: child.state_dir,
            cpu_grant: child.cpu_grant,
            content: child.content,
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
        memory: &Path,
        _machine_id: &Path,
        config_src: Option<&Path>,
        content: &[ContentBlob],
    ) -> Result<()> {
        let state_dir = mvm_core::config::vm_state_dir(target_vm);
        stage_restore_state_dir(
            &RestoreSources {
                config_src,
                rootfs: rootfs_src,
                memory,
            },
            &state_dir,
        )?;
        restore_hvf_vm(&HvfRestoreRequest {
            vm_name: target_vm,
            state_dir: &state_dir,
            // A same-identity resume admits no plan of its own — it is the VM
            // that was already admitted, coming back — so there is no grant here
            // to bind. Inventing one from the checkpoint record would be a bound
            // nobody signed for this run.
            cpu_grant: None,
            content,
        })
        .with_context(|| format!("HVF restore of '{target_vm}'"))?;
        Ok(())
    }

    fn verifies_on_load(&self) -> &'static [&'static str] {
        VERIFIED_ON_LOAD
    }
}

/// Where a same-identity restore reads the checkpoint from.
///
/// `rootfs` and `memory` are not necessarily in the checkpoint's content dir: a
/// chunked blob is materialized into a scratch dir first, and only those two
/// files are there. Everything else the restore needs — the launch config, the
/// device frame, the verity sidecars, the device anchors — stays in the content
/// dir, which is the directory `config_src` names.
struct RestoreSources<'a> {
    config_src: Option<&'a Path>,
    rootfs: &'a Path,
    memory: &'a Path,
}

impl RestoreSources<'_> {
    /// The checkpoint's content dir. A checkpoint that carries a launch config
    /// names it; one captured before configs were persisted stores whole blobs,
    /// so its rootfs sits in the content dir itself.
    fn content_dir(&self) -> Result<&Path> {
        self.config_src
            .and_then(Path::parent)
            .or_else(|| self.rootfs.parent())
            .ok_or_else(|| anyhow::anyhow!("checkpoint rootfs path has no content directory"))
    }
}

/// Build the target's state dir from a checkpoint: every file in the content
/// dir, then the rootfs and memory blobs wherever they were materialized.
fn stage_restore_state_dir(sources: &RestoreSources<'_>, state_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("creating {}", state_dir.display()))?;
    let content_dir = sources.content_dir()?;
    clone_content_into(content_dir, state_dir)?;
    for blob in [sources.rootfs, sources.memory] {
        if blob.parent() == Some(content_dir) {
            // A whole blob: already cloned with the content dir.
            continue;
        }
        let name = blob
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("checkpoint blob {} has no name", blob.display()))?;
        crate::base::cow::clone_rootfs_for_instance(blob, &state_dir.join(name))
            .with_context(|| format!("cloning checkpoint blob {}", name.to_string_lossy()))?;
    }
    Ok(())
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
                &[],
            )
            .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("launch config"),
            "expected the missing launch-config refusal, got: {rendered}"
        );
    }

    /// A chunked checkpoint's rootfs and memory are materialized into a
    /// scratch dir that holds nothing else. The state dir must still get the
    /// launch config, the device frame and every other file from the content
    /// dir, or the restore cannot find its launch config.
    #[test]
    fn a_chunked_checkpoint_stages_the_content_dir_and_the_materialized_blobs() {
        let tmp = tempfile::tempdir().unwrap();
        let content = tmp.path().join("content");
        let scratch = tmp.path().join(".restore-scratch");
        let state = tmp.path().join("state");
        std::fs::create_dir_all(&content).unwrap();
        std::fs::create_dir_all(&scratch).unwrap();
        std::fs::write(content.join("supervisor-config.json"), b"{}").unwrap();
        std::fs::write(content.join("memory.bin.hvf-frame"), b"frame").unwrap();
        std::fs::write(content.join("device-anchors.json"), b"[]").unwrap();
        std::fs::write(content.join("rootfs.ext4.chunks.json"), b"{}").unwrap();
        std::fs::write(scratch.join("rootfs.ext4"), b"root").unwrap();
        std::fs::write(scratch.join("memory.bin"), b"ram").unwrap();

        stage_restore_state_dir(
            &RestoreSources {
                config_src: Some(&content.join("supervisor-config.json")),
                rootfs: &scratch.join("rootfs.ext4"),
                memory: &scratch.join("memory.bin"),
            },
            &state,
        )
        .unwrap();

        for name in [
            "supervisor-config.json",
            "memory.bin.hvf-frame",
            "device-anchors.json",
        ] {
            assert!(state.join(name).is_file(), "{name} was not staged");
        }
        assert_eq!(std::fs::read(state.join("rootfs.ext4")).unwrap(), b"root");
        assert_eq!(std::fs::read(state.join("memory.bin")).unwrap(), b"ram");
    }

    /// A checkpoint captured before launch configs were persisted stores whole
    /// blobs and names no config: the rootfs's own directory is the content dir.
    #[test]
    fn a_whole_blob_checkpoint_without_a_config_stages_its_content_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let content = tmp.path().join("content");
        let state = tmp.path().join("state");
        std::fs::create_dir_all(&content).unwrap();
        std::fs::write(content.join("rootfs.ext4"), b"root").unwrap();
        std::fs::write(content.join("memory.bin"), b"ram").unwrap();
        std::fs::write(content.join("memory.bin.hvf-frame"), b"frame").unwrap();

        stage_restore_state_dir(
            &RestoreSources {
                config_src: None,
                rootfs: &content.join("rootfs.ext4"),
                memory: &content.join("memory.bin"),
            },
            &state,
        )
        .unwrap();

        assert_eq!(std::fs::read(state.join("rootfs.ext4")).unwrap(), b"root");
        assert_eq!(std::fs::read(state.join("memory.bin")).unwrap(), b"ram");
        assert!(state.join("memory.bin.hvf-frame").is_file());
    }
}
