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

use crate::oci_runtime_inject::{ImageRuntimeConfig, MvmRuntimeBinaries};
use crate::rootfs::MaterializeExt4Input;
use mvm_fs::oci_to_rootfs::{
    MaterializedRootfs, OciUnpackError, VeritySealedRootfs, VeritysetupOptions, seal_with_verity,
};

pub struct InjectAndMaterializeRequest<'a> {
    cache_root: &'a Path,
    unpacked_root: &'a Path,
    output: &'a Path,
    label: &'a str,
    entrypoint: Option<&'a ImageRuntimeConfig>,
    sealed: bool,
    deferred_nodes: Vec<mvm_fs::ext4::Node>,
}

impl<'a> InjectAndMaterializeRequest<'a> {
    pub fn builder(
        cache_root: &'a Path,
        unpacked_root: &'a Path,
        output: &'a Path,
        label: &'a str,
    ) -> InjectAndMaterializeRequestBuilder<'a> {
        InjectAndMaterializeRequestBuilder {
            cache_root,
            unpacked_root,
            output,
            label,
            entrypoint: None,
            sealed: false,
            deferred_nodes: Vec::new(),
        }
    }
}

pub struct InjectAndMaterializeRequestBuilder<'a> {
    cache_root: &'a Path,
    unpacked_root: &'a Path,
    output: &'a Path,
    label: &'a str,
    entrypoint: Option<&'a ImageRuntimeConfig>,
    sealed: bool,
    deferred_nodes: Vec<mvm_fs::ext4::Node>,
}

impl<'a> InjectAndMaterializeRequestBuilder<'a> {
    pub fn entrypoint(mut self, entrypoint: Option<&'a ImageRuntimeConfig>) -> Self {
        self.entrypoint = entrypoint;
        self
    }

    pub fn sealed(mut self, sealed: bool) -> Self {
        self.sealed = sealed;
        self
    }

    /// Carry the OCI unpacker's deferred nodes — entries a case-folding
    /// host filesystem could not hold — into the materialized image.
    pub fn deferred_nodes(mut self, deferred_nodes: Vec<mvm_fs::ext4::Node>) -> Self {
        self.deferred_nodes = deferred_nodes;
        self
    }

    pub fn build(self) -> InjectAndMaterializeRequest<'a> {
        InjectAndMaterializeRequest {
            cache_root: self.cache_root,
            unpacked_root: self.unpacked_root,
            output: self.output,
            label: self.label,
            entrypoint: self.entrypoint,
            sealed: self.sealed,
            deferred_nodes: self.deferred_nodes,
        }
    }
}

/// Inject the mvm runtime into `unpacked_root`, materialize it into `output` (a
/// `rootfs.ext4` path), and write the overlay-aware guest sidecar beside it.
/// `cache_root` holds the guest-agent binary cache; `label` names the image in
/// the sidecar.
///
/// When `sealed` is set (the `--prod` OCI run), the materialized rootfs is
/// dm-verity-sealed (see [`seal_rootfs_for_run`]) and the sidecar is written
/// `sealed`, so the runtime routes the block+ext4 verity boot and refuses
/// interactive access.
///
/// Guest binaries resolve from the invoking source checkout's content-keyed
/// cache or an existing compatibility cache. The host executable does not carry
/// workload binaries.
pub fn inject_and_materialize(request: InjectAndMaterializeRequest<'_>) -> Result<()> {
    let InjectAndMaterializeRequest {
        cache_root,
        unpacked_root,
        output,
        label,
        entrypoint,
        sealed,
        deferred_nodes,
    } = request;
    let bins = resolve_guest_binaries(cache_root)?;
    crate::oci_runtime_inject::inject_mvm_runtime(unpacked_root, &bins, entrypoint, sealed)
        .context("inject mvm runtime into OCI rootfs")?;
    ensure_volume_mount_roots(unpacked_root)?;

    // Measure AFTER injection so the ext4 sizing covers everything injected.
    let tree_size = unpacked_tree_size(unpacked_root)
        .with_context(|| format!("measure unpacked root {}", unpacked_root.display()))?;
    materialize_run_rootfs(
        &MaterializeExt4Input::new(unpacked_root.to_path_buf(), output.to_path_buf(), tree_size)
            .with_deferred_nodes(deferred_nodes),
    )?;

    // `--prod`: seal the rootfs before the sidecar is written. If this fails we
    // surface it and never write a `sealed` sidecar over a rootfs that can't
    // verity-boot.
    if sealed {
        seal_rootfs_for_run(output)?;
    }

    // The sidecar lives next to rootfs.ext4 so the backend's admit_runtime_overlay_contract
    // gate reads it at start.
    let rootfs_dir = output
        .parent()
        .ok_or_else(|| anyhow::anyhow!("rootfs path has no parent dir: {}", output.display()))?;
    // Always runtime-lean: the overlay is the single source of the guest
    // binaries, so an injected rootfs never carries a copy of them.
    crate::builder_vm::GuestSidecar::for_oci_run(label, sealed, true)
        // The same argv baked into `etc/mvm/image-runtime.json` above, put where
        // the host can still read it: once this tree is an ext4 blob nothing on
        // the host opens it, and admission has to know what the image runs before
        // it decides whether anything may drive its stdin.
        .with_entrypoint_argv(entrypoint.map(|e| e.argv.clone()).unwrap_or_default())
        .write_to_dir(rootfs_dir)
        .with_context(|| format!("write OCI sidecar in {}", rootfs_dir.display()))?;
    Ok(())
}

/// Materialize the admitted top-level guest volume roots into every sealed OCI
/// image. The root becomes dm-verity read-only before PID 1 runs, so mountpoints
/// cannot be created lazily inside the guest.
fn ensure_volume_mount_roots(unpacked_root: &Path) -> Result<()> {
    for relative in ["data", "work", "mnt"] {
        let path = unpacked_root.join(relative);
        std::fs::create_dir_all(&path)
            .with_context(|| format!("create guest volume mount root {}", path.display()))?;
    }
    Ok(())
}

/// Seal an already-materialized `rootfs_ext4`, writing its dm-verity sidecars
/// (`rootfs.verity` + `rootfs.roothash`).
///
/// There is no longer a sibling `rootfs.initrd` to keep in step: the universal
/// initramfs is the only initramfs, it is attached from the shared cache rather
/// than assembled per rootfs, and the guest agent it boots sets up the
/// dm-verity target itself before pivoting. So this is a plain seal, with none
/// of the write-first/roll-back ordering the paired artifacts used to need.
fn seal_rootfs_for_run(rootfs_ext4: &Path) -> Result<()> {
    seal_run_rootfs_for_runtime(rootfs_ext4)
        .with_context(|| format!("dm-verity seal {}", rootfs_ext4.display()))
}

fn seal_run_rootfs_for_runtime(rootfs_ext4: &Path) -> Result<()> {
    seal_run_rootfs_for_runtime_with(
        rootfs_ext4,
        seal_run_rootfs_with_verity,
        seal_run_rootfs_with_verity_builder_vm,
    )
}

fn seal_run_rootfs_for_runtime_with(
    rootfs_ext4: &Path,
    seal_local: impl FnOnce(&Path) -> std::result::Result<VeritySealedRootfs, OciUnpackError>,
    seal_builder_vm: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    match seal_local(rootfs_ext4) {
        Ok(_) => Ok(()),
        Err(OciUnpackError::HostUnsupported { .. }) => seal_builder_vm(rootfs_ext4),
        Err(e) => Err(anyhow::Error::new(e)),
    }
}

#[cfg(feature = "builder-vm")]
fn seal_run_rootfs_with_verity_builder_vm(rootfs_ext4: &Path) -> Result<()> {
    use crate::builder_backend_select::BuilderBackendChoice;
    use crate::libkrun_builder::{BuilderShellJob, LibkrunBuilderVm};
    use crate::qemu_builder::QemuBuilderVm;

    let artifact_out = rootfs_ext4
        .parent()
        .ok_or_else(|| anyhow::anyhow!("rootfs path has no parent dir: {}", rootfs_ext4.display()))?
        .to_path_buf();
    let script = verity_seal_script(rootfs_ext4)?;
    let shell_job = BuilderShellJob {
        work_dir: artifact_out.clone(),
        artifact_out,
        script,
        extra_disks: vec![],
    };

    let selected = crate::builder_backend_select::resolve_choice();
    let explicit = crate::builder_backend_select::resolve_env_override().is_some();
    crate::builder_backend_select::run_with_builder_fallback(selected, explicit, |choice| {
        match choice {
            BuilderBackendChoice::Libkrun | BuilderBackendChoice::Hvf => {
                LibkrunBuilderVm::default()
                    .run_shell_script(&shell_job)
                    .map(|_| ())
            }
            BuilderBackendChoice::Qemu => QemuBuilderVm::new()
                .run_shell_script(&shell_job)
                .map(|_| ()),
            BuilderBackendChoice::WebLinux => Err(crate::builder_vm::BuilderVmError::VmmUnavailable {
                requested: "web-linux".into(),
                reason: "the web-linux builder is browser-only; select libkrun, qemu, or hvf on a native host".into(),
            }),
        }
    })?;
    Ok(())
}

#[cfg(not(feature = "builder-vm"))]
fn seal_run_rootfs_with_verity_builder_vm(rootfs_ext4: &Path) -> Result<()> {
    anyhow::bail!(
        "dm-verity sealing for {} requires the `builder-vm` feature on hosts without local veritysetup support",
        rootfs_ext4.display()
    )
}

#[cfg(any(test, feature = "builder-vm"))]
fn verity_seal_script(rootfs_ext4: &Path) -> Result<String> {
    let rootfs_name = rootfs_ext4
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "rootfs path has no UTF-8 file name: {}",
                rootfs_ext4.display()
            )
        })?;
    let stem = rootfs_ext4
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "rootfs path has no UTF-8 file stem: {}",
                rootfs_ext4.display()
            )
        })?;
    let sidecar_name = format!("{stem}.verity");
    let roothash_name = format!("{stem}.roothash");
    Ok(format!(
        r#"#!/bin/sh
set -eu

ROOTFS="/out/{rootfs_name}"
VERITY="/out/{sidecar_name}"
ROOTHASH="/out/{roothash_name}"

rm -f "$VERITY" "$ROOTHASH"
veritysetup_out="$(
  veritysetup format \
    --data-block-size={data_block_size} \
    --hash-block-size={hash_block_size} \
    --salt={salt} \
    --uuid={uuid} \
    --hash={algorithm} \
    "$ROOTFS" \
    "$VERITY"
)"
roothash="$(
  printf '%s\n' "$veritysetup_out" \
    | sed -n 's/^Root hash:[[:space:]]*//p' \
    | tr 'A-F' 'a-f' \
    | head -n1
)"
[ -n "$roothash" ] || {{
  echo "veritysetup format succeeded but produced no Root hash: line" >&2
  exit 1
}}
printf '%s\n' "$roothash" > "$ROOTHASH"
"#,
        rootfs_name = rootfs_name,
        sidecar_name = sidecar_name,
        roothash_name = roothash_name,
        data_block_size = mvm_fs::oci_to_rootfs::MVM_VERITY_DATA_BLOCK_SIZE,
        hash_block_size = mvm_fs::oci_to_rootfs::MVM_VERITY_HASH_BLOCK_SIZE,
        salt = mvm_fs::oci_to_rootfs::MVM_VERITY_PINNED_SALT,
        uuid = mvm_fs::oci_to_rootfs::verity::MVM_VERITY_PINNED_UUID,
        algorithm = mvm_fs::oci_to_rootfs::MVM_VERITY_HASH_ALGORITHM,
    ))
}

/// Resolve the guest-agent binaries.
///
/// A source checkout resolves the invoking checkout's guest sources through a
/// content-keyed cache, so local edits rebuild instead of serving a stale
/// version+arch entry. An installed caller may reuse a complete compatibility
/// cache, but the released workload path obtains guest code from the universal
/// initramfs and runtime overlay.
pub fn resolve_guest_binaries(cache_root: &Path) -> Result<MvmRuntimeBinaries> {
    let arch = mvm_core::arch::GuestArch::host();

    match crate::guest_agent_build::guest_binary_source()
        .context("resolve the guest-binary cache key for this host")?
    {
        crate::guest_agent_build::GuestBinarySource::SourceCheckout {
            workspace_root,
            cache_key,
        } => {
            return crate::guest_agent_build::resolve_or_build_guest_binaries(
                cache_root,
                &cache_key,
                arch,
                &workspace_root,
            )
            .context("build guest agent binaries from the source checkout");
        }
        crate::guest_agent_build::GuestBinarySource::EmbeddedVersion { cache_key } => {
            if let Some(cached) =
                crate::guest_agent_build::cached_guest_binaries(cache_root, &cache_key, arch)
            {
                return Ok(cached);
            }
        }
    }

    anyhow::bail!(
        "legacy rootfs guest-runtime injection is unavailable for mvmctl {} on {arch}; \
         run from a source checkout or use the universal initramfs/runtime-overlay path",
        env!("CARGO_PKG_VERSION")
    )
}

/// Materialize a run-path rootfs from an already-complete unpacked tree.
///
/// Default: the pure in-process `mvm-ext4` writer. `MVM_MATERIALIZE_BUILDER_VM`
/// (any value) routes back through the builder-VM `mkfs` path for parity /
/// debugging. Both paths emit `rootfs.verity` + `rootfs.roothash` beside the
/// image so block-backed OCI runs are sealed uniformly across backends.
pub fn materialize_run_rootfs(input: &MaterializeExt4Input) -> Result<()> {
    let input = input.clone().with_verity();

    #[cfg(feature = "pure-mkfs")]
    if std::env::var_os("MVM_MATERIALIZE_BUILDER_VM").is_none() {
        match crate::rootfs::materialize_ext4_pure(&input) {
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
    materialize_run_rootfs_builder_vm(&input)
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
/// Delegates to [`seal_with_verity`], which pins the 4096-byte data block size
/// the verity initramfs expects. Do **not** swap in a different dm-verity
/// geometry here: the initramfs probes the rootfs geometry at boot, so a
/// mismatched sidecar will fail closed before `/init` pivots into the real
/// rootfs.
///
/// Linux-only at runtime. On macOS `veritysetup` is unavailable, so this returns
/// [`OciUnpackError::HostUnsupported`] rather than a fabricated hash — the seal
/// runs on Linux or via the builder VM when the host cannot execute
/// `veritysetup` directly.
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

/// Identity of the guest runtime that [`resolve_guest_binaries`] would inject,
/// without building it.
///
/// This is the rootfs cache key. It is consulted on the cache-hit gate — before
/// anything has decided a materialization is needed — so it must never trigger
/// the cross-compile that `resolve_guest_binaries` performs on a cold cache.
///
/// When the artifacts are present, the identity is their content digest, read
/// through [`crate::runtime_identity`]'s sidecar so the steady-state cost is a
/// small read plus one stat per artifact.
///
/// When they are absent there are no bytes to digest and building them here
/// would cost a minute to answer a question asked on every invocation. The
/// cache generation is returned instead, marked so it can never collide with a
/// real digest. That case implies a build is imminent anyway (materialization
/// needs the artifacts), after which the identity becomes the artifact digest
/// and the rootfs re-materializes once.
pub fn resolve_guest_runtime_identity(cache_root: &Path) -> Result<String> {
    let arch = mvm_core::arch::GuestArch::host();
    let source = crate::guest_agent_build::guest_binary_source()
        .context("resolve the guest-binary cache key for this host")?;
    let layout =
        crate::guest_agent_build::GuestAgentLayout::under(cache_root, source.cache_key(), arch);

    if !layout.is_complete() {
        return Ok(format!("pending-{}", source.cache_key()));
    }

    crate::runtime_identity::identity_with_sidecar(&layout.binaries(), &layout.dir)
        .with_context(|| format!("identify the guest runtime in {}", layout.dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_oci_tree_contains_volume_mount_roots() {
        let root = tempfile::tempdir().unwrap();

        ensure_volume_mount_roots(root.path()).expect("create mount roots");

        for relative in ["data", "work", "mnt"] {
            assert!(root.path().join(relative).is_dir());
        }
    }

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

    /// A gzip stream starts with the two-byte magic `1f 8b`.

    #[test]
    fn verity_seal_script_uses_pinned_paths_and_parameters() {
        let script = verity_seal_script(Path::new("/tmp/build/rootfs.ext4")).expect("script");
        assert!(script.contains("ROOTFS=\"/out/rootfs.ext4\""));
        assert!(script.contains("VERITY=\"/out/rootfs.verity\""));
        assert!(script.contains("ROOTHASH=\"/out/rootfs.roothash\""));
        assert!(script.contains("veritysetup format"));
        assert!(script.contains(&format!(
            "--data-block-size={}",
            mvm_fs::oci_to_rootfs::MVM_VERITY_DATA_BLOCK_SIZE
        )));
        assert!(script.contains(&format!(
            "--hash-block-size={}",
            mvm_fs::oci_to_rootfs::MVM_VERITY_HASH_BLOCK_SIZE
        )));
        assert!(script.contains(&format!(
            "--salt={}",
            mvm_fs::oci_to_rootfs::MVM_VERITY_PINNED_SALT
        )));
        assert!(script.contains(&format!(
            "--uuid={}",
            mvm_fs::oci_to_rootfs::verity::MVM_VERITY_PINNED_UUID
        )));
        assert!(script.contains(&format!(
            "--hash={}",
            mvm_fs::oci_to_rootfs::MVM_VERITY_HASH_ALGORITHM
        )));
    }

    #[test]
    fn seal_run_rootfs_for_runtime_with_falls_back_on_host_unsupported() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"ext4-bytes").unwrap();
        let builder_called = std::cell::Cell::new(false);

        seal_run_rootfs_for_runtime_with(
            &rootfs,
            |_rootfs| {
                Err(OciUnpackError::HostUnsupported {
                    operation: "veritysetup",
                    reason: "test host lacks local verity support",
                })
            },
            |_rootfs| {
                builder_called.set(true);
                Ok(())
            },
        )
        .expect("host unsupported should fall back to the builder VM");

        assert!(builder_called.get());
    }

    #[test]
    fn seal_run_rootfs_for_runtime_with_keeps_local_success_local() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"ext4-bytes").unwrap();
        let builder_called = std::cell::Cell::new(false);

        seal_run_rootfs_for_runtime_with(
            &rootfs,
            |rootfs| {
                Ok(VeritySealedRootfs {
                    rootfs_path: rootfs.to_path_buf(),
                    sidecar_path: rootfs.with_extension("verity"),
                    roothash_path: rootfs.with_extension("roothash"),
                    roothash: "abcd".repeat(16),
                    algorithm: mvm_fs::oci_to_rootfs::MVM_VERITY_HASH_ALGORITHM.to_string(),
                    data_block_size: mvm_fs::oci_to_rootfs::MVM_VERITY_DATA_BLOCK_SIZE,
                })
            },
            |_rootfs| {
                builder_called.set(true);
                Ok(())
            },
        )
        .expect("local seal success should not need the builder VM");

        assert!(!builder_called.get());
    }

    #[test]
    fn seal_run_rootfs_for_runtime_with_propagates_non_host_unsupported_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"ext4-bytes").unwrap();
        let builder_called = std::cell::Cell::new(false);

        let err = seal_run_rootfs_for_runtime_with(
            &rootfs,
            |_rootfs| {
                Err(OciUnpackError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "stat rootfs: missing",
                )))
            },
            |_rootfs| {
                builder_called.set(true);
                Ok(())
            },
        )
        .expect_err("non-host-unsupported errors must surface");

        assert!(err.to_string().contains("stat rootfs"));
        assert!(!builder_called.get());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sealing_emits_both_verity_sidecars() {
        // The load-bearing `--prod` invariant: a sealed rootfs carries both
        // dm-verity sidecars. There is no longer a paired `rootfs.initrd` to
        // land with them — the universal initramfs is attached from the shared
        // cache and its agent sets the dm-verity target up itself.
        // Skips cleanly when `veritysetup` (cryptsetup) is not installed.
        if which::which("veritysetup").is_err() {
            eprintln!("skipped: veritysetup not on $PATH (install cryptsetup)");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        // veritysetup formats over the raw device bytes; a multiple of the
        // 1024-byte data-block size is enough (no real ext4 needed here).
        std::fs::write(&rootfs, vec![0u8; 4096]).unwrap();

        seal_rootfs_for_run(&rootfs).expect("seal");

        let roothash = tmp.path().join("rootfs.roothash");
        let verity = tmp.path().join("rootfs.verity");
        assert!(verity.is_file(), "rootfs.verity present");
        assert!(roothash.is_file(), "rootfs.roothash present");
        assert!(
            !tmp.path().join("rootfs.initrd").exists(),
            "no per-rootfs initrd is assembled any more"
        );
        let hash = std::fs::read_to_string(&roothash).unwrap();
        assert!(
            hash.trim().len() == 64 && hash.trim().bytes().all(|b| b.is_ascii_hexdigit()),
            "roothash is 64-hex: {hash:?}"
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
