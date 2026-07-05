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

use crate::oci_runtime_inject::MvmRuntimeBinaries;
use crate::rootfs::MaterializeExt4Input;

/// Guest-agent binaries (`mvm-guest-agent` + `mvm-guest-netinit`) embedded in
/// the host binary at build time — the end-user fallback for a shipped mvmctl
/// with no source checkout to cross-compile from.
pub struct PrebuiltGuestBinaries<'a> {
    pub agent: &'a [u8],
    pub netinit: &'a [u8],
}

/// Inject the mvm runtime into `unpacked_root`, materialize it into `output` (a
/// `rootfs.ext4` path), and write the overlay-aware guest sidecar beside it.
/// `cache_root` holds the guest-agent binary cache; `label` names the image in
/// the sidecar.
///
/// Guest binaries resolve in order: a cache hit, then a source-checkout
/// cross-compile (contributors get their local edits), then the `prebuilt`
/// bytes embedded in the host binary (the shipped-mvmctl end-user path). A
/// caller with no embedded binaries passes `None`.
pub fn inject_and_materialize(
    cache_root: &Path,
    unpacked_root: &Path,
    output: &Path,
    label: &str,
    prebuilt: Option<PrebuiltGuestBinaries<'_>>,
) -> Result<()> {
    let bins = resolve_guest_binaries(cache_root, prebuilt)?;
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

/// Resolve the guest-agent binaries: cache hit → source-checkout cross-compile
/// → embedded prebuilt bytes.
fn resolve_guest_binaries(
    cache_root: &Path,
    prebuilt: Option<PrebuiltGuestBinaries<'_>>,
) -> Result<MvmRuntimeBinaries> {
    let arch = mvm_core::arch::GuestArch::host();
    let version = env!("CARGO_PKG_VERSION");

    if let Some(cached) = crate::guest_agent_build::cached_guest_binaries(cache_root, version, arch)
    {
        return Ok(cached);
    }

    // A source checkout cross-compiles fresh, so contributors editing `mvm-guest`
    // get their local changes. `CARGO_MANIFEST_DIR` is baked at this crate's
    // compile time and points at `crates/mvm-build`; on a shipped binary that
    // path doesn't exist on the end-user's host — which is exactly how we detect
    // "not a source checkout" and fall through to the embedded bytes.
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent());
    if let Some(ws) = workspace_root
        && ws.join("crates/mvm-guest").is_dir()
    {
        return crate::guest_agent_build::resolve_or_build_guest_binaries(
            cache_root, version, arch, ws,
        )
        .context("build guest agent binaries from the source checkout");
    }

    if let Some(p) = prebuilt {
        return crate::guest_agent_build::install_prebuilt_guest_binaries(
            p.agent, p.netinit, cache_root, version, arch,
        )
        .context("install the embedded guest agent binaries");
    }

    anyhow::bail!(
        "no guest agent binaries available: this build embeds none and there is no source \
         checkout to cross-compile from"
    )
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
