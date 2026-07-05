//! Run-path rootfs materialization: turn an unpacked OCI tree into the bootable
//! `rootfs.ext4`, in-process by default (the pure-Rust `mvm-ext4` writer — no
//! builder VM, no `mkfs`, no subprocess).
//!
//! Shared by the CLI's `run --image` path and the `mvm-client` local backend so
//! both drive one orchestration: resolve the guest-agent binaries, inject the
//! mvm runtime into the unpacked tree, materialize the ext4 image, and write the
//! overlay-aware guest sidecar beside it.

use std::path::Path;

use anyhow::{Context, Result};

use crate::rootfs::MaterializeExt4Input;

/// Inject the mvm runtime into `unpacked_root`, materialize it into `output` (a
/// `rootfs.ext4` path), and write the overlay-aware guest sidecar beside it.
/// `cache_root` holds the guest-agent binary cache; `label` names the image in
/// the sidecar.
///
/// The guest binaries are resolved via `guest_agent_build`, which cross-compiles
/// them from a source checkout — the same path the CLI uses (an end-user
/// binary that ships the runtime overlay is a separate, not-yet-wired path).
pub fn inject_and_materialize(
    cache_root: &Path,
    unpacked_root: &Path,
    output: &Path,
    label: &str,
) -> Result<()> {
    let arch = mvm_core::arch::GuestArch::host();
    // `CARGO_MANIFEST_DIR` is bound at this crate's compile time, so it always
    // points at `crates/mvm-build`; its grandparent is the workspace root.
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("cannot locate workspace root for guest-agent build"))?;
    let bins = crate::guest_agent_build::resolve_or_build_guest_binaries(
        cache_root,
        env!("CARGO_PKG_VERSION"),
        arch,
        workspace_root,
    )
    .context("obtain guest agent binaries for OCI run")?;
    crate::oci_runtime_inject::inject_mvm_runtime(unpacked_root, &bins)
        .context("inject mvm runtime into OCI rootfs")?;

    // Measure AFTER injection so the ext4 sizing covers the baked agent/netinit.
    let tree_size = unpacked_tree_size(unpacked_root)
        .with_context(|| format!("measure unpacked root {}", unpacked_root.display()))?;
    materialize_run_rootfs(&MaterializeExt4Input::new(
        unpacked_root.to_path_buf(),
        output.to_path_buf(),
        tree_size,
    ))?;

    // The sidecar lives next to rootfs.ext4 so the backend's admit_overlay_aware
    // gate reads it at start.
    let rootfs_dir = output
        .parent()
        .ok_or_else(|| anyhow::anyhow!("rootfs path has no parent dir: {}", output.display()))?;
    crate::builder_vm::GuestSidecar::for_oci_run(label)
        .write_to_dir(rootfs_dir)
        .with_context(|| format!("write OCI sidecar in {}", rootfs_dir.display()))?;
    Ok(())
}

/// Materialize a run-path rootfs from an already-complete unpacked tree.
///
/// Default: the pure in-process `mvm-ext4` writer. `MVM_MATERIALIZE_BUILDER_VM`
/// (any value) routes back through the builder-VM `mkfs` path for parity /
/// debugging. Verity is left off (no `rootfs.verity` / `rootfs.roothash`
/// sidecars), so the run path's `verity_path`/`roothash = None` boot config is
/// unchanged — this is a materialization *mechanism* choice, not a boot-semantics
/// change.
pub fn materialize_run_rootfs(input: &MaterializeExt4Input) -> Result<()> {
    #[cfg(feature = "pure-mkfs")]
    if std::env::var_os("MVM_MATERIALIZE_BUILDER_VM").is_none() {
        match crate::rootfs::materialize_ext4_pure(input) {
            Ok(_) => return Ok(()),
            // Auto-fallback: the in-process writer structurally can't emit a
            // faithful image — too large / too fragmented / a directory over one
            // block, or the tree carries an xattr the writer can't represent — so
            // retry via the builder VM, which has no such limits and whose
            // `cp -a` preserves xattrs. Logged, never silent.
            Err(e) if e.pure_should_fall_back() => {
                tracing::warn!(
                    error = %e,
                    "in-process rootfs materialize needs the builder VM; falling back"
                );
                // fall through to the builder-VM path below
            }
            // A malformed tree or I/O failure is genuine — surface it, no retry.
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("materialize {} in-process", input.output.display()));
            }
        }
    }
    materialize_run_rootfs_builder_vm(input)
}

#[cfg(feature = "builder-vm")]
fn materialize_run_rootfs_builder_vm(input: &MaterializeExt4Input) -> Result<()> {
    crate::rootfs::materialize_ext4(input, &crate::rootfs::MaterializeExt4Options::default())
        .map(|_| ())
        .with_context(|| format!("materialize {} via builder VM", input.output.display()))
}

#[cfg(not(feature = "builder-vm"))]
fn materialize_run_rootfs_builder_vm(_input: &MaterializeExt4Input) -> Result<()> {
    anyhow::bail!(
        "no rootfs materializer compiled in: enable the `pure-mkfs` or `builder-vm` feature"
    )
}

/// Sum of regular-file sizes under `root` (symlink-aware, never follows) — the
/// ext4 sizing input.
pub fn unpacked_tree_size(root: &Path) -> Result<u64> {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("stat unpacked path {}", path.display()))?;
        if metadata.is_dir() {
            for entry in
                std::fs::read_dir(&path).with_context(|| format!("read {}", path.display()))?
            {
                stack.push(entry?.path());
            }
        } else if metadata.is_file() {
            total = total.saturating_add(metadata.len());
        }
    }
    Ok(total)
}
