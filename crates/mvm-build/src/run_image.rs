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

use crate::guest_agent_build::GuestRuntimeBinaryBytes;
use crate::oci_runtime_inject::{MvmRuntimeBinaries, OciEntrypointConfig};
use crate::oci_to_rootfs::{
    MaterializedRootfs, OciUnpackError, VeritySealedRootfs, VeritysetupOptions, seal_with_verity,
};
use crate::rootfs::MaterializeExt4Input;

/// Guest runtime binaries embedded in the host binary at build time — the
/// end-user fallback for a shipped mvmctl with no source checkout to
/// cross-compile from.
pub struct PrebuiltGuestBinaries<'a> {
    pub oci_init: &'a [u8],
    pub agent: &'a [u8],
    pub netinit: &'a [u8],
    pub egress_client: &'a [u8],
    pub entrypoint_runner: &'a [u8],
    pub verity_init: &'a [u8],
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
    entrypoint: Option<&OciEntrypointConfig>,
    prebuilt: Option<PrebuiltGuestBinaries<'_>>,
) -> Result<()> {
    let bins = resolve_guest_binaries(cache_root, prebuilt)?;
    crate::oci_runtime_inject::inject_mvm_runtime(unpacked_root, &bins, entrypoint)
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
            GuestRuntimeBinaryBytes {
                oci_init: p.oci_init,
                agent: p.agent,
                netinit: p.netinit,
                egress_client: p.egress_client,
                entrypoint_runner: p.entrypoint_runner,
                verity_init: p.verity_init,
            },
            cache_root,
            version,
            arch,
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

/// Seal an already-materialized `rootfs.ext4` at `rootfs_ext4` into a dm-verity
/// artifact set, emitting the sibling `rootfs.verity` (Merkle hash tree) and
/// `rootfs.roothash` (lowercase-hex root hash) files. Those are the exact sibling
/// names the backend's boot-time sidecar probe reads to decide a sealed boot.
///
/// Delegates to [`seal_with_verity`], which pins the 1024-byte data block size
/// the verity initramfs requires. Do **not** reach for
/// `materialize_ext4_pure(..).with_verity()` in this role: its 4096-byte data
/// blocks disagree with the initramfs and the resulting image will not boot.
///
/// Linux-only at runtime. On macOS `veritysetup` is unavailable, so this returns
/// [`OciUnpackError::HostUnsupported`] rather than a fabricated hash — the seal
/// runs on Linux (or via the builder VM in a later slice). This is a
/// test-exercised capability and is **not** yet wired into the live `--prod` run
/// path; that lands atomically with the verity initramfs so no unsealed or
/// no-boot window is ever exposed.
pub fn seal_run_rootfs_with_verity(
    rootfs_ext4: &Path,
) -> Result<VeritySealedRootfs, OciUnpackError> {
    let size_bytes = std::fs::metadata(rootfs_ext4)?.len();
    // `seal_with_verity` only reads `path`; the descriptor's label/uuid are
    // metadata mirrored for diagnostics. Name them like the materialize path so
    // the two artifacts read together coherently.
    let descriptor = MaterializedRootfs {
        path: rootfs_ext4.to_path_buf(),
        size_bytes,
        label: "mvm-rootfs".to_string(),
        uuid: String::new(),
    };
    seal_with_verity(&descriptor, &VeritysetupOptions::default())
}

/// Which rootfs strategy the run path uses for a workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootStrategy {
    /// Serve the unpacked + injected tree directly over a read-only **virtiofs
    /// root** — the dev/local tier only. No ext4, no materialize. Carries the
    /// weaker virtiofs-root integrity contract and does **not** witness claim 3.
    VirtiofsRoot,
    /// Materialize a block ext4 image (the "Option B" path) — the prod, sealed,
    /// and Firecracker route. Witnesses claim 3 via dm-verity.
    BlockExt4,
}

/// Inputs to the root-strategy tier gate.
#[derive(Debug, Clone, Copy)]
pub struct RootStrategySelection {
    /// The chosen backend can attach a read-only virtiofs **root** device
    /// (`VmCapabilities::virtiofs_root`). Firecracker is always `false`.
    pub backend_virtiofs_root: bool,
    /// The workload is a prod / `--prod` deployment.
    pub prod: bool,
    /// The workload boots a sealed (dm-verity-sealed) image.
    pub sealed: bool,
}

/// Select the rootfs strategy per the tier gate.
///
/// Virtiofs-root is chosen **iff** the backend exposes a virtiofs root device
/// **and** the workload is neither prod nor sealed. Everything else — a prod or
/// sealed workload, or a non-virtiofs-capable backend (e.g. Firecracker) — takes
/// block+ext4, which witnesses claim 3. This makes "prod on virtiofs-root"
/// structurally unrepresentable: no combination of inputs yields `VirtiofsRoot`
/// for a prod or sealed workload.
pub fn select_root_strategy(s: RootStrategySelection) -> RootStrategy {
    if s.backend_virtiofs_root && !s.prod && !s.sealed {
        RootStrategy::VirtiofsRoot
    } else {
        RootStrategy::BlockExt4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn seal_run_rootfs_surfaces_host_unsupported_on_non_linux() {
        // On macOS the sealing capability is compiled and callable, but the
        // underlying `veritysetup` is Linux-only, so it must surface
        // `HostUnsupported` — never a fabricated roothash. The real seal runs on
        // Linux / via the builder VM.
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"ext4-bytes").unwrap();
        let err = seal_run_rootfs_with_verity(&rootfs).expect_err("veritysetup is Linux-only");
        assert!(
            matches!(err, OciUnpackError::HostUnsupported { .. }),
            "expected HostUnsupported on non-Linux, got {err:?}"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn seal_run_rootfs_errors_on_missing_input_file() {
        // A missing input surfaces the metadata I/O error before any host probe —
        // fail closed, never a silent success.
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("rootfs.ext4");
        let err = seal_run_rootfs_with_verity(&missing).expect_err("missing input must error");
        assert!(
            matches!(err, OciUnpackError::Io(_)),
            "expected Io error for missing input, got {err:?}"
        );
    }

    #[test]
    fn virtiofs_root_only_for_capable_non_prod_non_sealed() {
        // Exhaustive truth table over the three inputs: virtiofs-root is chosen
        // in exactly one cell (capable & !prod & !sealed); every other cell —
        // including every prod and every sealed combination — is block+ext4.
        for cap in [false, true] {
            for prod in [false, true] {
                for sealed in [false, true] {
                    let got = select_root_strategy(RootStrategySelection {
                        backend_virtiofs_root: cap,
                        prod,
                        sealed,
                    });
                    let want = if cap && !prod && !sealed {
                        RootStrategy::VirtiofsRoot
                    } else {
                        RootStrategy::BlockExt4
                    };
                    assert_eq!(got, want, "cap={cap} prod={prod} sealed={sealed}");
                }
            }
        }
    }

    #[test]
    fn prod_and_sealed_never_reach_virtiofs_even_when_capable() {
        // The load-bearing safety property: claim-3 tiers can never be routed to
        // the weaker virtiofs path.
        for prod in [false, true] {
            for sealed in [false, true] {
                if !prod && !sealed {
                    continue;
                }
                assert_eq!(
                    select_root_strategy(RootStrategySelection {
                        backend_virtiofs_root: true,
                        prod,
                        sealed,
                    }),
                    RootStrategy::BlockExt4,
                    "prod={prod} sealed={sealed} must stay on block+ext4"
                );
            }
        }
    }

    #[test]
    fn non_virtiofs_backend_always_block() {
        // Firecracker (and any backend without the device) always materializes.
        for prod in [false, true] {
            for sealed in [false, true] {
                assert_eq!(
                    select_root_strategy(RootStrategySelection {
                        backend_virtiofs_root: false,
                        prod,
                        sealed,
                    }),
                    RootStrategy::BlockExt4,
                );
            }
        }
    }
}
