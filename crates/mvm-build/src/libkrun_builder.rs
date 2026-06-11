//! Libkrun-backed builder VM.
//!
//! libkrun-direct (on macOS Apple Silicon / Intel) and Firecracker
//! (on Linux) replaced the older builder VM. This module is the
//! libkrun half.
//!
//! ## What `LibkrunBuilderVm` does
//!
//! Given a populated builder VM image cache and `mvm-libkrun-supervisor`
//! on PATH, `run_build` runs a one-shot `nix build` against the
//! caller's `BuilderJob` and returns `BuilderArtifacts`. The
//! pipeline (in [`BuilderVm::run_build`]):
//!
//! 1. Validate mounts + job (`validate_mounts`, `validate_job`).
//! 2. Check `libkrun_sys::is_available()` — bail with install hint
//!    if libkrun isn't on the host.
//! 3. Locate `mvm-libkrun-supervisor` (env override / next-to-exe /
//!    PATH).
//! 4. Read the builder VM image from
//!    `~/.cache/mvm/builder-vm/<arch>/` — vmlinux + rootfs.ext4 +
//!    cmdline.txt + manifest.json, the shape the builder-vm flake
//!    emits. Populated by `bootstrap_builder_vm_image`
//!    (`mvm-cli::commands::env::apple_container`).
//! 5. Allocate / reuse the persistent `/nix-store-<arch>.img`
//!    sparse virtio-blk image (64 GiB cap by default; idempotent
//!    across invocations so the warm Nix store survives).
//! 6. Stage `<job_dir>/cmd.sh` with the shell-escaped flake_ref +
//!    attr_path, plus the canonical `nix build` invocation.
//! 7. Build a `KrunContext`: kernel + rootfs + cmdline + per-VM
//!    vsock dir + virtio-blk (Nix store) + virtio-fs (work / out /
//!    job).
//! 8. Spawn `mvm-libkrun-supervisor`, pipe the `SupervisorConfig`
//!    JSON to stdin, **wait** for it to exit (unlike
//!    `LibkrunBackend::start` which returns after the PID file
//!    appears — the builder is a one-shot).
//! 9. Read `<job_dir>/result` (JSON: `{exit_code, stderr_tail}`)
//!    that `mvm-host-vm-init` wrote.
//! 10. Validate the artifact dir now contains `rootfs.ext4` (and
//!     optionally `vmlinux`); return `BuilderArtifacts`.
//!
//! ## Feature gate
//!
//! Gated behind `builder-vm`. Default-off until the cutover flips
//! `ensure_dev_image` to dispatch through `LibkrunBuilderVm`.
//! Library consumers that don't need the libkrun builder build with
//! `default-features = false`.
//!
//! ## Not the runtime backend
//!
//! `LibkrunBackend` (`crates/mvm-backend/src/libkrun.rs`) is for
//! running user microVMs; this module is for building them. The
//! two share `mvm-libkrun`'s FFI but compose differently — the
//! builder mounts a workspace + persistent `/nix`-store disk and
//! runs a one-shot `nix build`, while the runtime mounts the
//! user's rootfs and runs the user's entrypoint.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use libkrun_sys::{KrunContext, SupervisorConfig};

use crate::builder_vm::{
    BuilderArtifacts, BuilderJob, BuilderMounts, BuilderVm, BuilderVmDisk, BuilderVmError,
    BuilderVmExitInfo, BuilderVmMount, BuilderVmRunConfig, VmBackendForBuilder,
};
// These items previously lived in this file; they migrated to
// `builder_vm_runtime` so the future VzBuilderVm path can reuse the
// same logic without duplicating it. `INSTALL_SPEC_FILENAME` and
// `shell_single_quote_escape` are imported only inside the test
// module below.
use crate::builder_vm_runtime::{
    NixStoreImageLock, acquire_nix_store_image_lock, acquire_nix_store_image_lock_named,
    builder_vm_timeout, finalize_flake_job, finalize_install_job, read_job_result,
    shell_job_exit_error, stage_job_dir, supervisor_exit_error,
};

/// Default vCPU count for the builder VM. Nix builds are
/// embarrassingly parallel at the derivation level; 4 cores is the
/// sweet spot on M-series Macs without saturating the host.
pub const DEFAULT_VCPUS: u8 = 4;

/// Default RAM in MiB. Originally 8 GiB (in-VM nix builds peak
/// ~5-6 GiB). Raised to 16 GiB for headroom
/// when several derivations' build working sets overlap. Before the
/// persistent-store cutover this also had to cover a 14 GiB in-RAM
/// `/nix` tmpfs; the Stage 0 store now lives on a virtio-blk ext4 disk
/// (`nix-store-stage0-<arch>.img`), so this RAM only has to cover the
/// compiles themselves, not the store.
pub const DEFAULT_MEMORY_MIB: u32 = 16384;

/// Default size of the persistent `/nix`-store virtio-blk image,
/// in MiB. 64 GiB sparse — the file only consumes the bytes the
/// in-VM ext4 actually writes, but capacity caps growth so a
/// runaway build can't fill the host disk.
pub const DEFAULT_NIX_STORE_MIB: u32 = 65536;

/// Builder persistent /nix store auto-GC threshold (GiB of *used* space).
/// When the in-guest store exceeds this after a build, the build script runs
/// `nix-collect-garbage --delete-older-than 14d`. Override: MVM_BUILDER_STORE_GC_GIB.
/// Default 24 GiB (above doctor's 20 GiB warning, below the 64 GiB sparse cap).
///
/// Canonical definition lives in `builder_vm_runtime` (always compiled;
/// `render_flake_cmd_sh` bakes the resolved cap into the in-guest script).
/// Re-exported here next to [`DEFAULT_NIX_STORE_MIB`] for discoverability.
pub use crate::builder_vm_runtime::{DEFAULT_BUILDER_STORE_GC_GIB, builder_store_gc_cap_kib};

/// Where the workspace gets mounted inside the builder VM
/// (read-only virtio-fs).
pub const GUEST_WORK_DIR: &str = "/work";

/// Where artifacts get extracted inside the builder VM (read-write
/// virtio-fs).
pub const GUEST_OUT_DIR: &str = "/out";

/// Where the persistent Nix store lives inside the builder VM. The
/// `mvm-host-vm-init` PID-1 bind-mounts the virtio-blk device at
/// this path before exec-ing the build script.
pub const GUEST_NIX_DIR: &str = "/nix";

/// Where the per-build job spec lives inside the builder VM. The
/// host stages `cmd.sh`, `env`, and the eventual `result` file
/// under this path (read-write virtio-fs).
pub const GUEST_JOB_DIR: &str = "/job";

/// Caller-visible networking-backend preference. Read from
/// the `MVM_NETWORKING` env var at every VM-launch site.
///
/// `Passt` is virtio-net via the userspace passt gateway. `Gvproxy`
/// is for macOS, where passt does not build (`vmsplice`/namespace
/// primitives are Linux-only).
///
/// There is no `Tsi` variant: TSI bypasses virtio-net entirely,
/// which violates the claim-10 no-bypass invariant. Every builder VM
/// gets a real virtio-net device through one of the two gateways.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkingPreference {
    /// virtio-net via passt. Linux-only. Requires libkrun-sys + the
    /// `passt` binary on `$PATH`. The supervisor process spawns
    /// passt as a child and hands its fd to libkrun.
    Passt,
    /// virtio-net via gvproxy. macOS default; works on Linux too.
    /// Requires libkrun-sys + the `gvproxy` binary on `$PATH`. The
    /// supervisor spawns gvproxy with `-listen-vfkit unixgram://…`
    /// and libkrun connects to the listener path.
    Gvproxy,
}

/// Apply the resolved [`NetworkingPreference`] to a [`KrunContext`].
/// Dispatches `with_passt` or `with_gvproxy`. Each gateway uses
/// `<vm_state_dir>` for its log/socket scratch space. There is no
/// no-gateway path — claim-10 no-bypass.
fn apply_networking_mode(
    krun: KrunContext,
    vm_state_dir: &std::path::Path,
) -> Result<KrunContext, BuilderVmError> {
    let scratch = path_to_str(vm_state_dir, "vm_state_dir")?;
    Ok(match resolve_networking_mode() {
        NetworkingPreference::Passt => {
            krun.with_passt(libkrun_sys::passt::DEFAULT_GUEST_MAC, scratch)
        }
        NetworkingPreference::Gvproxy => {
            krun.with_gvproxy(libkrun_sys::gvproxy::DEFAULT_GUEST_MAC, scratch)
        }
    })
}

/// Per-host-OS default networking backend.
///
/// macOS → [`Gvproxy`](NetworkingPreference::Gvproxy) because passt
/// does not build there (the Homebrew formula refuses with "Linux is
/// required for this software"); everything else (Linux today) →
/// [`Passt`](NetworkingPreference::Passt).
pub fn default_networking_mode() -> NetworkingPreference {
    if cfg!(target_os = "macos") {
        NetworkingPreference::Gvproxy
    } else {
        NetworkingPreference::Passt
    }
}

/// Read `MVM_NETWORKING` from the env. Accepts `passt` and
/// `gvproxy` (case-insensitive); anything else falls back to the
/// per-OS default and emits a warning so a typo is visible without
/// aborting.
///
/// Per-OS dispatch is macOS → gvproxy, Linux → passt. TSI was
/// removed entirely — it bypassed virtio-net (no host fd to splice),
/// which violates the claim-10 no-bypass invariant.
/// `MVM_NETWORKING=tsi` is no longer accepted; the value is
/// treated as unknown and falls back to the per-OS gateway
/// default with a warning. Pin a specific gateway across OS via
/// `MVM_NETWORKING=passt` or `MVM_NETWORKING=gvproxy`.
pub fn resolve_networking_mode() -> NetworkingPreference {
    match std::env::var("MVM_NETWORKING")
        .ok()
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        // passt is Linux-only — the Homebrew formula refuses to build on macOS.
        // An explicit `MVM_NETWORKING=passt` on macOS can't be honoured (the
        // supervisor would fail to spawn the gateway), so fall back to gvproxy
        // with a warning rather than hand it an unspawnable gateway. On Linux,
        // passt is honoured. This keeps `resolve_networking_mode` safe to call
        // from every gateway-selection site, macOS included.
        Some("passt") => {
            if cfg!(target_os = "macos") {
                tracing::warn!(
                    "MVM_NETWORKING=passt is not supported on macOS \
                     (passt is Linux-only); falling back to gvproxy"
                );
                NetworkingPreference::Gvproxy
            } else {
                NetworkingPreference::Passt
            }
        }
        Some("gvproxy") => NetworkingPreference::Gvproxy,
        None | Some("") => default_networking_mode(),
        Some(other) => {
            let fallback = default_networking_mode();
            if other == "tsi" {
                tracing::warn!(
                    fallback = ?fallback,
                    "MVM_NETWORKING=tsi is no longer supported (Plan 102 W6.A: \
                     TSI bypasses virtio-net, violates claim-10 no-bypass invariant); \
                     falling back to per-OS default"
                );
            } else {
                tracing::warn!(
                    value = other,
                    fallback = ?fallback,
                    "MVM_NETWORKING unrecognised; falling back to per-OS default (accepted: passt, gvproxy)"
                );
            }
            fallback
        }
    }
}

/// Libkrun-backed builder VM driver.
///
/// Configuration only — `run_build` consumes it to spin a per-job
/// VM, runs `nix build` inside, extracts the artifacts via the
/// `/out` virtio-fs mount, and tears the VM down. No persistent
/// state on the struct; the `/nix`-store image lives on the host
/// filesystem and survives across invocations.
#[derive(Debug, Clone)]
pub struct LibkrunBuilderVm {
    /// Guest vCPU count. See [`DEFAULT_VCPUS`].
    pub vcpus: u8,
    /// Guest RAM in MiB. See [`DEFAULT_MEMORY_MIB`].
    pub memory_mib: u32,
    /// Persistent `/nix`-store image size in MiB (sparse cap).
    /// See [`DEFAULT_NIX_STORE_MIB`].
    pub nix_store_mib: u32,
    /// Optional caller-supplied bootstrap image. When set, `run_build`
    /// boots from this kernel/rootfs/cmdline instead of looking up the
    /// builder VM image in `~/.cache/mvm/builder-vm/<arch>/`.
    ///
    /// This is the Stage 0 escape from the chicken-and-egg on source
    /// checkouts: a local dev image that contains `/sbin/mvm-host-vm-init`
    /// can build the real builder VM image without downloading a
    /// published builder-VM artifact.
    pub image_override: Option<BuilderVmImage>,
    /// Stream the guest `console.log` to stderr as the build runs.
    /// Set by the CLI from `--verbose`. Default false (heartbeat only).
    pub verbose: bool,
}

/// Additional virtio-blk device passed to a one-shot builder shell
/// job. Devices appear after the builder VM's persistent Nix-store
/// disk; the first extra disk here is `/dev/vdc` in the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderExtraDisk {
    pub id: String,
    pub path: PathBuf,
    pub read_only: bool,
}

/// Generic builder-VM shell job.
///
/// This is intentionally narrower than [`BuilderJob`]: it is for
/// in-tree infrastructure commands that need the Linux builder
/// boundary but do not produce Nix build artifacts. The OCI image
/// runner uses it to run `mkfs.ext4` and copy an OCI-unpacked rootfs
/// into a writable virtio-blk image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderShellJob {
    pub work_dir: PathBuf,
    pub artifact_out: PathBuf,
    pub script: String,
    pub extra_disks: Vec<BuilderExtraDisk>,
}

/// Result metadata from a one-shot builder shell job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderShellResult {
    pub job_dir: PathBuf,
    pub vm_state_dir: PathBuf,
}

impl Default for LibkrunBuilderVm {
    fn default() -> Self {
        Self {
            vcpus: DEFAULT_VCPUS,
            memory_mib: DEFAULT_MEMORY_MIB,
            nix_store_mib: DEFAULT_NIX_STORE_MIB,
            image_override: None,
            verbose: false,
        }
    }
}

impl LibkrunBuilderVm {
    /// Override the default vCPU / RAM pair. Useful for CI runners
    /// or low-memory hosts that can't afford the 4 GiB default.
    pub fn with_resources(mut self, vcpus: u8, memory_mib: u32) -> Self {
        self.vcpus = vcpus;
        self.memory_mib = memory_mib;
        self
    }

    /// Override the default `/nix`-store image cap. Smaller for
    /// CI runners that build a known-small closure; larger for
    /// developer hosts that want to keep many tenants' artifacts
    /// in one warm store.
    pub fn with_nix_store_mib(mut self, mib: u32) -> Self {
        self.nix_store_mib = mib;
        self
    }

    /// Boot from a caller-supplied kernel/rootfs/cmdline instead of
    /// resolving the builder VM image from `~/.cache/mvm/builder-vm/`.
    pub fn with_image_override(mut self, image: BuilderVmImage) -> Self {
        self.image_override = Some(image);
        self
    }

    /// Stream guest console output to stderr during the build (`--verbose`).
    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// libkrun-side Stage 0 boot. Drives a self-contained `RootDir`
    /// guest — no `/job/cmd.sh` staging, no `/job/result` parsing. The
    /// guest's `/init` reads `/work` and writes the steady-state builder
    /// VM artifacts to `/out`, then powers off cleanly.
    ///
    /// Attaches a dedicated persistent `nix-store-stage0-<arch>.img` as
    /// the guest's only virtio-blk device (`/dev/vda` — Stage 0 has no
    /// block rootfs, its root is virtio-fs via `krun_set_root`). The
    /// guest mounts it at `/nix` (formatting on first boot), so the slim
    /// kernel + Rust host binaries are built once and reused across
    /// `dev up` runs instead of recompiled into a throwaway tmpfs every
    /// time. ext4 is case-sensitive, which is also why the old in-RAM
    /// tmpfs existed (APFS case-insensitivity breaks Nix substitution) —
    /// the disk keeps that property and adds persistence.
    ///
    /// On success the caller still validates that the expected artifacts
    /// (`vmlinux`, `rootfs.ext4`) landed in `artifact_out`; this only
    /// asserts the supervisor exited 0.
    ///
    /// Private impl behind `<Self as BuilderVm>::run_stage0`, which
    /// adapts the backend-agnostic `(root_dir, entry)` trait signature
    /// to libkrun's `BuilderVmImage`.
    fn run_stage0_impl(
        &self,
        image: BuilderVmImage,
        workspace_dir: &std::path::Path,
        artifact_out: &std::path::Path,
        host_bin_dir: &std::path::Path,
    ) -> Result<(), BuilderVmError> {
        ensure_utf8_path(workspace_dir, "workspace_dir")?;
        ensure_utf8_path(artifact_out, "artifact_out")?;
        ensure_utf8_path(host_bin_dir, "host_bin_dir")?;
        if !workspace_dir.is_dir() {
            return Err(BuilderVmError::ExtractionFailed(format!(
                "Stage 0 workspace_dir must be an existing directory: {}",
                workspace_dir.display()
            )));
        }
        // The builder-vm flake installs the pre-cross-compiled host-vm
        // binaries from this dir rather than building them with the guest's
        // nix; the Stage 0 nix build aborts without it.
        if !host_bin_dir.is_dir() {
            return Err(BuilderVmError::ExtractionFailed(format!(
                "Stage 0 host_bin_dir must be an existing directory: {}",
                host_bin_dir.display()
            )));
        }
        std::fs::create_dir_all(artifact_out).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating Stage 0 artifact_out {}: {e}",
                artifact_out.display()
            ))
        })?;

        if !libkrun_sys::is_available() {
            return Err(BuilderVmError::LibkrunUnavailable(format!(
                "libkrun shared library not found on host. {}",
                libkrun_sys::install_hint()
            )));
        }

        let supervisor_path = resolve_supervisor_path()?;

        // Persistent, host-locked Nix store for the image build. Sparse
        // image, formatted in-guest on first boot; survives across
        // `dev up` runs so the slim kernel + Rust toolchain closure are
        // built once. Dedicated filename (not the builder's
        // `nix-store-<arch>.img`) so the flock never contends with a
        // concurrent `mvmctl build`. The guard must outlive the
        // supervisor — bound here, dropped at function end.
        let nix_store_lock = acquire_nix_store_image_lock_named(
            &builder_vm_cache_dir(),
            &stage0_nix_store_image_name(),
            u64::from(self.nix_store_mib),
        )?;

        let job_id = unique_job_id();
        let vm_name = format!("mvm-stage0-{job_id}");
        let vm_state_dir = builder_vm_cache_dir().join("vms").join(&vm_name);
        std::fs::create_dir_all(&vm_state_dir).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating Stage 0 VM state dir {}: {e}",
                vm_state_dir.display()
            ))
        })?;
        let console_log = vm_state_dir.join("console.log");

        let mut krun = krun_context_for_image(&vm_name, &image)?
            .with_resources(self.vcpus, self.memory_mib)
            .with_console_output(path_to_str(&console_log, "console_log")?)
            .with_vsock_socket_dir(path_to_str(&vm_state_dir, "vm_state_dir")?)
            // Persistent /nix store disk — the only block device on a RootDir
            // guest, so it enumerates as /dev/vda. Attached for the production
            // persistent-store path; `stage0-init` currently copies the seed
            // closure into a tmpfs `/nix` (overlay-over-virtiofs writes fail in
            // libkrun), so the disk is a follow-up, not yet formatted.
            .add_disk(
                "nix-store",
                path_to_str(nix_store_lock.path(), "nix_store_img")?,
                false,
            )
            .add_virtio_fs("work", path_to_str(workspace_dir, "workspace_dir")?)
            .add_virtio_fs("out", path_to_str(artifact_out, "artifact_out")?)
            // /mvm-bins inside the guest — stage0-init sets MVM_HOST_BIN_DIR
            // to it so the flake picks up the pre-built host-vm binaries.
            .add_virtio_fs("mvm-bins", path_to_str(host_bin_dir, "host_bin_dir")?);

        krun = apply_networking_mode(krun, &vm_state_dir)?;

        let cfg = SupervisorConfig {
            krun,
            vm_state_dir: path_to_str(&vm_state_dir, "vm_state_dir")?.to_string(),
            pid_file_name: Some("stage0.pid".to_string()),
            tenant_id: None,
            audit_dir: None,
            gateway_audit_socket: None,
            gateway_events_socket: None,
            signing_key_path: None,
            plan: None,
            bundle: None,
            // Builder VMs are always hard-fail; they don't model
            // long-running user workloads where a restart policy would
            // apply.
            bridge_restart_policy: libkrun_sys::BridgeRestartPolicy::HardFail,
        };

        let exit_code =
            spawn_supervisor_and_wait(&supervisor_path, &cfg, &vm_state_dir, self.verbose)?;
        if exit_code != 0 {
            return Err(BuilderVmError::NixBuildFailed(format!(
                "Stage 0 supervisor exited with status {exit_code}; \
                 console log at {}",
                console_log.display()
            )));
        }
        Ok(())
    }

    /// Run an in-tree shell script inside the existing builder VM
    /// boundary. The script is staged as `/job/cmd.sh`; `/work`
    /// points at [`BuilderShellJob::work_dir`], `/out` points at
    /// [`BuilderShellJob::artifact_out`], and callers may attach
    /// additional writable or read-only virtio-blk disks.
    pub fn run_shell_script(
        &self,
        job: &BuilderShellJob,
    ) -> Result<BuilderShellResult, BuilderVmError> {
        self.validate_shell_job(job)?;

        if !libkrun_sys::is_available() {
            return Err(BuilderVmError::LibkrunUnavailable(format!(
                "libkrun shared library not found on host. {}",
                libkrun_sys::install_hint()
            )));
        }

        let supervisor_path = resolve_supervisor_path()?;
        let image = match &self.image_override {
            Some(image) => image.clone(),
            None => ensure_builder_vm_image()?,
        };
        let nix_store_lock = acquire_nix_store_image_lock(
            &builder_vm_cache_dir(),
            host_arch_tag(),
            u64::from(self.nix_store_mib),
        )?;

        let job_id = unique_job_id();
        let job_dir = builder_vm_cache_dir().join("jobs").join(&job_id);
        stage_shell_job_dir(&job_dir, &job.script)?;
        // Tell the operator up-front where the build's stderr will
        // land. `/job` is a virtio-fs share into the VM; the guest's
        // cmd.sh redirects `nix build` stderr into <job_dir>/nix-
        // stderr.log, which is this exact path on the host. A
        // contributor watching a long build can `tail -f` it without
        // waiting for the failure-path formatter (finalize_flake_job)
        // to surface the same path.
        tracing::info!(
            job_dir = %job_dir.display(),
            "builder VM job dir staged (nix-stderr.log streams here as the build runs)"
        );

        let vm_name = format!("mvm-builder-vm-{job_id}");
        let vm_state_dir = builder_vm_cache_dir().join("vms").join(&vm_name);
        std::fs::create_dir_all(&vm_state_dir).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating builder VM state dir {}: {e}",
                vm_state_dir.display()
            ))
        })?;
        let console_log = vm_state_dir.join("console.log");

        let mut krun = krun_context_for_image(&vm_name, &image)?
            .with_resources(self.vcpus, self.memory_mib)
            .with_console_output(path_to_str(&console_log, "console_log")?)
            .with_vsock_socket_dir(path_to_str(&vm_state_dir, "vm_state_dir")?)
            .add_disk(
                "nix-store",
                path_to_str(nix_store_lock.path(), "nix_store_img")?,
                false,
            )
            .add_virtio_fs("work", path_to_str(&job.work_dir, "work_dir")?)
            .add_virtio_fs("out", path_to_str(&job.artifact_out, "artifact_out")?)
            .add_virtio_fs("job", path_to_str(&job_dir, "job_dir")?)
            .add_vsock_port(mvm_guest::builder_agent::BUILDER_DISPATCH_PORT);

        for disk in &job.extra_disks {
            krun = krun.add_disk(
                disk.id.as_str(),
                path_to_str(&disk.path, "extra_disk")?,
                disk.read_only,
            );
        }

        krun = apply_networking_mode(krun, &vm_state_dir)?;

        let cfg = SupervisorConfig {
            krun,
            vm_state_dir: path_to_str(&vm_state_dir, "vm_state_dir")?.to_string(),
            pid_file_name: Some("builder.pid".to_string()),
            tenant_id: None,
            audit_dir: None,
            gateway_audit_socket: None,
            gateway_events_socket: None,
            signing_key_path: None,
            plan: None,
            bundle: None,
            // Builder VMs are always hard-fail; they don't model
            // long-running user workloads where a restart policy would
            // apply.
            bridge_restart_policy: libkrun_sys::BridgeRestartPolicy::HardFail,
        };
        // Spawn the vsock response listener BEFORE the supervisor so
        // it can connect as soon as libkrun creates the dispatch
        // socket. Drained after the supervisor exits — see
        // `log_vsock_response_outcome` for the cross-validation
        // contract.
        let vsock_rx = spawn_vsock_response_listener(&vm_state_dir);
        let exit_code =
            spawn_supervisor_and_wait(&supervisor_path, &cfg, &vm_state_dir, self.verbose)?;
        if exit_code != 0 {
            log_vsock_response_outcome(vsock_rx, None);
            return Err(supervisor_exit_error(exit_code, &vm_state_dir));
        }

        let result = read_job_result(&job_dir)?;
        log_vsock_response_outcome(vsock_rx, Some(result.exit_code));
        if result.exit_code != 0 {
            return Err(shell_job_exit_error(result.exit_code, &result.stderr_tail));
        }

        let result = BuilderShellResult {
            job_dir,
            vm_state_dir,
        };
        drop(nix_store_lock);
        Ok(result)
    }

    /// Validate caller-supplied mount paths early. Catches issues
    /// that would otherwise surface as opaque libkrun C-API
    /// failures: missing directories, non-UTF-8 paths (libkrun's
    /// FFI takes `*const c_char` and we'd hit `CString::new`
    /// failures inside `libkrun_sys::sys` otherwise), and
    /// uncreatable artifact dirs.
    ///
    /// Public-in-crate so unit tests can exercise it directly.
    pub(crate) fn validate_mounts(&self, mounts: &BuilderMounts) -> Result<(), BuilderVmError> {
        // Reject non-UTF-8 paths first — libkrun's C API takes
        // `*const c_char` and we want the error message pinned to
        // the offending field rather than at a CString conversion
        // deep inside the FFI. Cheap predicate; runs before any
        // I/O so a test can exercise it on a synthetic path
        // without filesystem support for non-UTF-8 names (APFS).
        ensure_utf8_path(&mounts.flake_src, "flake_src")?;
        ensure_utf8_path(&mounts.artifact_out, "artifact_out")?;
        ensure_utf8_path(&mounts.host_bin_dir, "host_bin_dir")?;
        if let Some(store) = &mounts.host_nix_store {
            ensure_utf8_path(store, "host_nix_store")?;
        }
        if !mounts.flake_src.exists() {
            return Err(BuilderVmError::ExtractionFailed(format!(
                "flake source path does not exist: {}",
                mounts.flake_src.display()
            )));
        }
        if !mounts.flake_src.is_dir() {
            return Err(BuilderVmError::ExtractionFailed(format!(
                "flake source must be a directory: {}",
                mounts.flake_src.display()
            )));
        }
        if !mounts.host_bin_dir.is_dir() {
            return Err(BuilderVmError::ExtractionFailed(format!(
                "host_bin_dir must be an existing directory: {}",
                mounts.host_bin_dir.display()
            )));
        }
        std::fs::create_dir_all(&mounts.artifact_out).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating artifact_out {}: {e}",
                mounts.artifact_out.display()
            ))
        })?;
        Ok(())
    }

    /// Validate the job description. For [`BuilderJob::Flake`] both
    /// fields must be non-empty strings (`flake_ref` may include a
    /// `path:` or `git+` prefix but the prefix-less form is also
    /// accepted — libkrun runs the command verbatim inside the
    /// builder VM). For [`BuilderJob::Install`] the spec path must
    /// exist on the host; B.2 will fill in the rest of the
    /// install-pipeline validation against the parsed spec.
    pub(crate) fn validate_job(&self, job: &BuilderJob) -> Result<(), BuilderVmError> {
        match job {
            BuilderJob::Flake {
                flake_ref,
                attr_path,
            } => {
                if flake_ref.trim().is_empty() {
                    return Err(BuilderVmError::NixBuildFailed(
                        "BuilderJob.flake_ref is empty".to_string(),
                    ));
                }
                if attr_path.trim().is_empty() {
                    return Err(BuilderVmError::NixBuildFailed(
                        "BuilderJob.attr_path is empty".to_string(),
                    ));
                }
            }
            BuilderJob::Install { spec_path } => {
                // Validate the file exists so a caller's typo
                // surfaces here rather than as an opaque
                // NotYetImplemented mid-pipeline.
                if !spec_path.is_file() {
                    return Err(BuilderVmError::ExtractionFailed(format!(
                        "BuilderJob::Install spec_path does not exist or is not a file: {}",
                        spec_path.display()
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_shell_job(&self, job: &BuilderShellJob) -> Result<(), BuilderVmError> {
        ensure_utf8_path(&job.work_dir, "work_dir")?;
        ensure_utf8_path(&job.artifact_out, "artifact_out")?;
        for disk in &job.extra_disks {
            ensure_utf8_path(&disk.path, "extra_disk")?;
            if disk.id.trim().is_empty() {
                return Err(BuilderVmError::ExtractionFailed(
                    "extra disk id is empty".to_string(),
                ));
            }
            if !disk.path.is_file() {
                return Err(BuilderVmError::ExtractionFailed(format!(
                    "extra disk path does not exist or is not a file: {}",
                    disk.path.display()
                )));
            }
        }
        if !job.work_dir.is_dir() {
            return Err(BuilderVmError::ExtractionFailed(format!(
                "shell job work_dir must be a directory: {}",
                job.work_dir.display()
            )));
        }
        std::fs::create_dir_all(&job.artifact_out).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating artifact_out {}: {e}",
                job.artifact_out.display()
            ))
        })?;
        if job.script.trim().is_empty() {
            return Err(BuilderVmError::NixBuildFailed(
                "builder shell script is empty".to_string(),
            ));
        }
        Ok(())
    }
}

/// Reject a path that isn't UTF-8 representable. Internal helper —
/// the libkrun FFI requires CString-convertible paths and we want
/// the failure pinned to the offending field with a useful name.
pub(crate) fn ensure_utf8_path(p: &std::path::Path, field: &str) -> Result<(), BuilderVmError> {
    p.to_str().ok_or_else(|| {
        BuilderVmError::ExtractionFailed(format!("{field} has non-UTF-8 bytes: {p:?}"))
    })?;
    Ok(())
}

impl BuilderVm for LibkrunBuilderVm {
    /// Adapt the backend-agnostic `(root_dir, entry)` Stage 0
    /// contract to libkrun's `BuilderVmImage::RootDir` and run it.
    fn run_stage0(
        &self,
        guest_root_dir: &std::path::Path,
        entry_path: &str,
        workspace_dir: &std::path::Path,
        artifact_out: &std::path::Path,
        host_bin_dir: &std::path::Path,
    ) -> Result<(), BuilderVmError> {
        let image = BuilderVmImage::new_root_dir(guest_root_dir.to_path_buf(), entry_path);
        self.run_stage0_impl(image, workspace_dir, artifact_out, host_bin_dir)
    }

    fn run_build(
        &self,
        job: &BuilderJob,
        mounts: &BuilderMounts,
    ) -> Result<BuilderArtifacts, BuilderVmError> {
        // 1. Validate caller-supplied inputs early; clearer
        //    errors than failing inside the libkrun FFI.
        self.validate_mounts(mounts)?;
        self.validate_job(job)?;

        // 2. Refuse to proceed on a host without libkrun. The
        //    `builder-vm` feature being compiled
        //    in doesn't imply the runtime library is installed.
        if !libkrun_sys::is_available() {
            return Err(BuilderVmError::LibkrunUnavailable(format!(
                "libkrun shared library not found on host. {}",
                libkrun_sys::install_hint()
            )));
        }

        // 3. Find the supervisor binary up front. Failing now is
        //    a much better UX than spawning the supervisor with a
        //    stale PATH and discovering at child-exit time.
        let supervisor_path = resolve_supervisor_path()?;

        // 4. Find or initialise the builder VM image (kernel +
        //    rootfs.ext4 + canonical cmdline) the builder-vm flake
        //    produces. Stage 0 callers can provide a bootstrap
        //    image so a fresh source checkout can build the builder
        //    image cache without first downloading it.
        let image = match &self.image_override {
            Some(image) => image.clone(),
            None => ensure_builder_vm_image()?,
        };

        // 5. Allocate / locate the persistent `/nix-store`
        //    virtio-blk image. First build on a host pays the
        //    sparse-allocate cost; subsequent builds reuse the
        //    warm Nix store.
        let nix_store_lock = acquire_nix_store_image_lock(
            &builder_vm_cache_dir(),
            host_arch_tag(),
            u64::from(self.nix_store_mib),
        )?;

        // 6. Stage the per-build job dir. Flake jobs get
        //    `cmd.sh`; install jobs get `install_spec.json`.
        //    `mvm-host-vm-init` dispatches based on which file it
        //    sees.
        let job_id = unique_job_id();
        let job_dir = builder_vm_cache_dir().join("jobs").join(&job_id);
        stage_job_dir(
            &job_dir,
            job,
            mounts.staged_user_flake.as_deref(),
            // Override mode (staged_user_flake = Some) mounts the workspace
            // at /work as `flake_src`; stage its filtered cargo tree so the
            // build can pin `mvm/mvm-workspace` to it.
            mounts
                .staged_user_flake
                .as_ref()
                .map(|_| mounts.flake_src.as_path()),
        )?;
        // Same announcement as the single-shot path — see the
        // identical block in `LibkrunBuilderVm::run_build`.
        tracing::info!(
            job_dir = %job_dir.display(),
            "builder VM job dir staged (nix-stderr.log streams here as the build runs)"
        );

        // 7. Build the `KrunContext` libkrun consumes. Three
        //    virtio-fs shares (work / out / job), one virtio-blk
        //    (Nix store), and the canonical cmdline pinned at the
        //    flake output. The mount layout is identical for
        //    flake + install jobs — the guest decides what to do
        //    with each share based on the staged job files.
        let vm_name = format!("mvm-builder-vm-{job_id}");
        let vm_state_dir = builder_vm_cache_dir().join("vms").join(&vm_name);
        std::fs::create_dir_all(&vm_state_dir).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating builder VM state dir {}: {e}",
                vm_state_dir.display()
            ))
        })?;

        // Route the guest's serial console to a per-VM log file so
        // failures of the in-VM cmd.sh / mvm-host-vm-init produce a
        // readable transcript. Without this, libkrun discards the
        // hvc0 output silently and "supervisor running, then exits 1"
        // is the only observable signal.
        let console_log = vm_state_dir.join("console.log");
        let mut krun = krun_context_for_image(&vm_name, &image)?
            .with_resources(self.vcpus, self.memory_mib)
            .with_console_output(path_to_str(&console_log, "console_log")?)
            .with_vsock_socket_dir(path_to_str(&vm_state_dir, "vm_state_dir")?)
            .add_disk(
                "nix-store",
                path_to_str(nix_store_lock.path(), "nix_store_img")?,
                false,
            )
            .add_virtio_fs("work", path_to_str(&mounts.flake_src, "flake_src")?)
            .add_virtio_fs("out", path_to_str(&mounts.artifact_out, "artifact_out")?)
            .add_virtio_fs("job", path_to_str(&job_dir, "job_dir")?)
            // Mount the extracted host-vm binaries at /mvm-bins inside
            // the builder VM (read-only). The cmd.sh sees
            // MVM_HOST_BIN_DIR=/mvm-bins so the flake can reference the
            // correct pre-compiled binaries without a host nix build.
            .add_virtio_fs(
                "mvm-bins",
                path_to_str(&mounts.host_bin_dir, "host_bin_dir")?,
            )
            .add_vsock_port(mvm_guest::builder_agent::BUILDER_DISPATCH_PORT);

        krun = apply_networking_mode(krun, &vm_state_dir)?;

        // 8. Drive the supervisor: pipe `SupervisorConfig` to
        //    stdin and **wait** for the child to exit. Unlike
        //    `LibkrunBackend::start` (returns immediately after
        //    the PID file appears), the builder is a one-shot —
        //    we want the supervisor to live until the guest
        //    powers off, then collect the result.
        let cfg = SupervisorConfig {
            krun,
            vm_state_dir: path_to_str(&vm_state_dir, "vm_state_dir")?.to_string(),
            pid_file_name: Some("builder.pid".to_string()),
            tenant_id: None,
            audit_dir: None,
            gateway_audit_socket: None,
            gateway_events_socket: None,
            signing_key_path: None,
            plan: None,
            bundle: None,
            // Builder VMs are always hard-fail; they don't model
            // long-running user workloads where a restart policy would
            // apply.
            bridge_restart_policy: libkrun_sys::BridgeRestartPolicy::HardFail,
        };
        // Same dispatch-listener wiring as `run_shell_script`.
        // Drained after the supervisor exits (or right before bailing
        // on supervisor failure) so the background thread always gets
        // a chance to log.
        let vsock_rx = spawn_vsock_response_listener(&vm_state_dir);
        let exit_code =
            spawn_supervisor_and_wait(&supervisor_path, &cfg, &vm_state_dir, self.verbose)?;
        if exit_code != 0 {
            log_vsock_response_outcome(vsock_rx, None);
            return Err(supervisor_exit_error(exit_code, &vm_state_dir));
        }
        // The flake / install finalize paths don't return a
        // structured exit_code from the file before they branch on
        // variant-specific shapes (Flake reads `/job/result`,
        // Install reads `/out/result.json`). We log without the file
        // cross-validation here; per-variant cross-validation is not
        // wired at this site.
        log_vsock_response_outcome(vsock_rx, None);

        // 9. Per-variant result parsing + artifact validation.
        //    Flake jobs read `<job_dir>/result` (legacy shape);
        //    install jobs read `<artifact_out>/result.json` and
        //    return a different artifact variant.
        let artifacts = match job {
            BuilderJob::Flake { .. } => finalize_flake_job(&job_dir, &mounts.artifact_out, &job_id),
            BuilderJob::Install { .. } => finalize_install_job(&mounts.artifact_out),
        }?;
        drop(nix_store_lock);
        Ok(artifacts)
    }

    fn cleanup(&self) -> Result<(), BuilderVmError> {
        // Hygiene: prune old job dirs under
        // `~/.cache/mvm/builder-vm/jobs/` past N days. No-op until a
        // retention policy is picked.
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────
// LibkrunBuilderBackend
//
// This is the hypervisor-agnostic seam's libkrun-flavored impl.
// Wraps `spawn_supervisor_in_background` + `wait_with_panic_detector_until`
// + the KrunContext-building pattern from `LibkrunBuilderVm::run_build`.
// Today nothing in production uses it — `LibkrunBuilderVm::run_build`
// stays as-is. The follow-up slice introduces a `BuilderVmRuntime`
// helper that takes `&dyn VmBackendForBuilder` and migrates
// `run_build` to use it; this struct is what plugs into that helper
// for the libkrun backend.
//
// Lives in the same file as the private helpers it calls
// (`resolve_supervisor_path`, `ensure_builder_vm_image`,
// `krun_context_for_image`, `apply_networking_mode`, `path_to_str`,
// `spawn_supervisor_in_background`, `wait_with_panic_detector_until`,
// `WaitOutcome`, `DEFAULT_PANIC_POLL_INTERVAL`). Putting it here
// avoids widening those helpers' visibility for a single new caller.
// ─────────────────────────────────────────────────────────────────

/// libkrun-flavored impl of the hypervisor-agnostic
/// [`VmBackendForBuilder`] primitive trait.
///
/// Holds the resolved supervisor binary path and the cached
/// builder VM image (kernel + rootfs + cmdline). Construction
/// eagerly resolves both so a missing prerequisite surfaces at
/// `new()`-time rather than mid-build.
///
/// `LibkrunBuilderVm::run_build` does not yet use this — a
/// follow-up slice introduces `BuilderVmRuntime` and flips the
/// migration. Today it exists so the `VzBuilderVm` work has a
/// worked example of how to wrap a hypervisor-specific supervisor
/// behind the seam.
pub struct LibkrunBuilderBackend {
    supervisor_path: PathBuf,
    image: BuilderVmImage,
}

impl LibkrunBuilderBackend {
    /// Resolve the supervisor binary + builder VM image eagerly.
    /// Surfaces "supervisor binary missing" / "builder image not
    /// installed" at the call site rather than at first run.
    pub fn new() -> Result<Self, BuilderVmError> {
        let supervisor_path = resolve_supervisor_path()?;
        let image = ensure_builder_vm_image()?;
        Ok(Self {
            supervisor_path,
            image,
        })
    }

    /// Test seam — caller supplies the supervisor path + image
    /// directly so unit tests can construct a backend without
    /// touching the host's libkrun install or the image cache.
    /// Used by the construction test below; the future
    /// `BuilderVmRuntime` test suite will reuse this pattern.
    pub fn with_supervisor_and_image(supervisor_path: PathBuf, image: BuilderVmImage) -> Self {
        Self {
            supervisor_path,
            image,
        }
    }
}

impl VmBackendForBuilder for LibkrunBuilderBackend {
    fn run_attached_with_mounts(
        &self,
        config: &BuilderVmRunConfig,
        mounts: &[BuilderVmMount],
        extra_disks: &[BuilderVmDisk],
        timeout: Duration,
    ) -> Result<BuilderVmExitInfo, BuilderVmError> {
        // Same refusal posture as run_build's step 2: a missing
        // shared library is the most-common failure mode and an
        // early surface keeps the supervisor spawn from producing
        // a confusing rc -2.
        if !libkrun_sys::is_available() {
            return Err(BuilderVmError::LibkrunUnavailable(format!(
                "libkrun shared library not found on host. {}",
                libkrun_sys::install_hint()
            )));
        }

        std::fs::create_dir_all(&config.vm_state_dir).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating builder VM state dir {}: {e}",
                config.vm_state_dir.display()
            ))
        })?;

        let console_log = self.console_log_path(&config.vm_state_dir);

        // KrunContext construction — same shape as run_build's
        // step 7, but parameterised on the trait's hypervisor-
        // agnostic config. Builds top-down (resources first, then
        // disks, then mounts, then vsock ports, then networking)
        // because libkrun's builder methods consume `self` by value.
        let mut krun = krun_context_for_image(&config.name, &self.image)?
            .with_resources(config.vcpus, config.memory_mib)
            .with_console_output(path_to_str(&console_log, "console_log")?)
            .with_vsock_socket_dir(path_to_str(&config.vm_state_dir, "vm_state_dir")?);
        for disk in extra_disks {
            krun = krun.add_disk(
                disk.id.clone(),
                path_to_str(&disk.host_path, "extra_disk_path")?,
                disk.read_only,
            );
        }
        for mount in mounts {
            // libkrun's add_virtio_fs takes only (tag, host_path) —
            // every share is RW from the guest's perspective. The
            // `BuilderVmMount::read_only` flag is currently ignored
            // on this backend; Vz's impl will honour it via
            // VZSharedDirectory's `readOnly:` parameter.
            krun = krun.add_virtio_fs(
                mount.tag.clone(),
                path_to_str(&mount.host_path, "mount_host_path")?,
            );
        }
        for port in &config.vsock_ports {
            krun = krun.add_vsock_port(*port);
        }
        krun = apply_networking_mode(krun, &config.vm_state_dir)?;

        let cfg = SupervisorConfig {
            krun,
            vm_state_dir: path_to_str(&config.vm_state_dir, "vm_state_dir")?.to_string(),
            pid_file_name: Some("builder.pid".to_string()),
            tenant_id: None,
            audit_dir: None,
            gateway_audit_socket: None,
            gateway_events_socket: None,
            signing_key_path: None,
            plan: None,
            bundle: None,
            // Builder VMs are always hard-fail; they don't model
            // long-running user workloads where a restart policy would
            // apply.
            bridge_restart_policy: libkrun_sys::BridgeRestartPolicy::HardFail,
        };

        let mut child = spawn_supervisor_in_background(&self.supervisor_path, &cfg)?;
        // Same wait + panic-detection shape `spawn_supervisor_and_wait`
        // uses, but we surface the panic line via the seam's exit
        // info instead of an Err so the future BuilderVmRuntime
        // helper can decide whether the job's expectations were
        // met.
        match wait_with_panic_detector_until(
            &mut child,
            Some(&console_log),
            DEFAULT_PANIC_POLL_INTERVAL,
            Some(timeout),
            false,
        ) {
            Ok(WaitOutcome::Clean(code)) => Ok(BuilderVmExitInfo {
                exit_code: Some(code),
                panic_line: None,
            }),
            Ok(WaitOutcome::KernelPanic { panic_line, .. }) => Ok(BuilderVmExitInfo {
                exit_code: None,
                panic_line: Some(panic_line),
            }),
            Ok(WaitOutcome::Timeout) => Err(BuilderVmError::NixBuildFailed(format!(
                "builder VM exceeded {} seconds wall-clock; killed. Console log at {}.",
                timeout.as_secs(),
                console_log.display(),
            ))),
            Err(e) => Err(BuilderVmError::ExtractionFailed(format!(
                "wait on supervisor child: {e}"
            ))),
        }
    }

    fn console_log_path(&self, vm_state_dir: &Path) -> PathBuf {
        vm_state_dir.join("console.log")
    }
}

// ─────────────────────────────────────────────────────────────────
// Helpers — kept in one place at the bottom of the file rather
// than scattered through `impl` blocks so the run_build pipeline
// reads top-down.
// ─────────────────────────────────────────────────────────────────

/// Resolved builder VM image. One of two boot shapes:
///
/// - **Rootfs**: kernel + rootfs.ext4 + cmdline. The steady-state
///   builder VM path produced by the builder-vm flake.
/// - **RootDir**: host directory + guest entrypoint. The Stage 0
///   bootstrap path. libkrun's bundled kernel boots transparently;
///   no host-built kernel involved.
#[derive(Debug, Clone)]
pub enum BuilderVmImage {
    /// Steady-state builder VM image.
    Rootfs {
        kernel_path: PathBuf,
        rootfs_path: PathBuf,
        cmdline: String,
    },
    /// Host directory libkrun mounts as the guest root via virtiofs.
    /// `entry_path` is the guest PID 1 (relative to `root_dir`).
    RootDir {
        root_dir: PathBuf,
        entry_path: String,
    },
}

impl BuilderVmImage {
    /// Image that boots from a rootfs ext4 disk + the supervisor's
    /// canonical `init=` cmdline.
    pub fn new(kernel_path: PathBuf, rootfs_path: PathBuf, cmdline: String) -> Self {
        Self::Rootfs {
            kernel_path,
            rootfs_path,
            cmdline,
        }
    }

    /// Image that hands a host directory to libkrun as the guest
    /// root via `krun_set_root`. libkrun's bundled kernel boots
    /// transparently. `entry_path` is the guest PID 1, relative to
    /// `root_dir`.
    pub fn new_root_dir(root_dir: PathBuf, entry_path: impl Into<String>) -> Self {
        Self::RootDir {
            root_dir,
            entry_path: entry_path.into(),
        }
    }
}

/// Build the right `KrunContext` flavor for a [`BuilderVmImage`],
/// pre-populated with the variant's kernel cmdline (where applicable).
/// `RootDir` images carry no cmdline — libkrun handles `set_root`
/// mode without one.
fn krun_context_for_image(
    vm_name: &str,
    image: &BuilderVmImage,
) -> Result<KrunContext, BuilderVmError> {
    match image {
        BuilderVmImage::Rootfs {
            kernel_path,
            rootfs_path,
            cmdline,
        } => Ok(KrunContext::new(
            vm_name,
            path_to_str(kernel_path, "kernel_path")?,
            path_to_str(rootfs_path, "rootfs_path")?,
        )
        .with_cmdline(cmdline.as_str())),
        BuilderVmImage::RootDir {
            root_dir,
            entry_path,
        } => Ok(KrunContext::new_root_dir(
            vm_name,
            path_to_str(root_dir, "root_dir")?,
            entry_path.as_str(),
        )),
    }
}

/// Host architecture tag used as a cache-key segment for
/// per-arch builder VM images. `aarch64` on Apple Silicon /
/// ARM Linux, `x86_64` everywhere else. The builder-vm flake
/// emits both per release.
pub(crate) fn host_arch_tag() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    }
}

/// `~/.cache/mvm/builder-vm/`. Wrapper around
/// `mvm_core::config::mvm_cache_dir()` to keep the per-arch
/// subdirs in one place. Created lazily by callers — this
/// function does not touch the filesystem.
pub(crate) fn builder_vm_cache_dir() -> PathBuf {
    crate::builder_vm::builder_vm_cache_dir()
}

/// Filename of Stage 0's dedicated persistent Nix-store image,
/// `nix-store-stage0-<arch>.img`. Distinct from the steady-state
/// builder's `nix-store-<arch>.img` so a `dev up` bootstrap and a
/// concurrent `mvmctl build` never contend on the same flock — see
/// [`acquire_nix_store_image_lock_named`]. Lives in
/// [`builder_vm_cache_dir`] and matches `cache info`'s
/// `nix-store-*.img` sparse-footprint report.
pub(crate) fn stage0_nix_store_image_name() -> String {
    format!("nix-store-stage0-{}.img", host_arch_tag())
}

/// Find the builder VM image (kernel + rootfs + cmdline) in
/// the host cache. The builder-vm flake's `packages.<system>.default`
/// produces exactly the `vmlinux` / `rootfs.ext4` / `cmdline.txt`
/// files this loads. The build-or-download step populates this
/// cache; today it errors when missing with an actionable hint.
pub(crate) fn ensure_builder_vm_image() -> Result<BuilderVmImage, BuilderVmError> {
    let arch_dir = builder_vm_cache_dir().join(host_arch_tag());
    let kernel_path = arch_dir.join("vmlinux");
    let rootfs_path = arch_dir.join("rootfs.ext4");
    let cmdline_path = arch_dir.join("cmdline.txt");

    if !kernel_path.is_file() || !rootfs_path.is_file() {
        return Err(BuilderVmError::ExtractionFailed(format!(
            "builder VM image not found at {}. \
             Populate the cache by running `nix build ./nix/images/builder-vm#packages.{}-linux.default` \
             on a host with Nix and copying `result/{{vmlinux,rootfs.ext4,cmdline.txt}}` to {}/.",
            arch_dir.display(),
            host_arch_tag(),
            arch_dir.display(),
        )));
    }

    let cmdline = std::fs::read_to_string(&cmdline_path)
        .map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "{} missing or unreadable ({e}). The builder VM cache is poisoned; delete {} and re-run `mvmctl dev up` to re-bootstrap.",
                cmdline_path.display(),
                arch_dir.display(),
            ))
        })?
        .trim()
        .to_string();

    Ok(BuilderVmImage::new(kernel_path, rootfs_path, cmdline))
}

/// Monotonic per-process job ID. Combines a UNIX timestamp
/// with the current PID so two concurrent invocations on one
/// host don't clobber each other's job dirs even if they hit
/// the same second.
///
/// `pub(crate)` so the parallel `vz_builder::VzBuilderVm`
/// driver can reuse the same per-job ID shape; the two backends
/// share a cache root, so collisions on it would corrupt each
/// other's job dirs.
pub(crate) fn unique_job_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let pid = std::process::id();
    format!("{now:013}-{pid}")
}

// `INSTALL_SPEC_FILENAME` moved to `crate::builder_vm_runtime`; the
// `use` at the top of this file pulls it back in for the existing
// callers.

// `stage_job_dir`, `shell_single_quote_escape`, `read_job_result`,
// `JobResult`, `INSTALL_RESULT_FILENAME`, `read_last_bytes_of`,
// `finalize_flake_job`, `read_revision_hash`, `extract_nix_store_hash`,
// `finalize_install_job`, and `InstallResultReport` all live in
// `crate::builder_vm_runtime` so the future VzBuilderVm path can reuse
// them.

fn stage_shell_job_dir(job_dir: &Path, script: &str) -> Result<(), BuilderVmError> {
    std::fs::create_dir_all(job_dir).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!("creating job dir {}: {e}", job_dir.display()))
    })?;
    let cmd_path = job_dir.join("cmd.sh");
    std::fs::write(&cmd_path, script).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!("writing {}: {e}", cmd_path.display()))
    })?;
    Ok(())
}

/// Locate the `mvm-libkrun-supervisor` binary. Mirrors the
/// resolver in `mvm-backend::libkrun::resolve_supervisor_path`
/// (kept local rather than re-exported to keep the dep graph
/// flat). Order: env override → next to current_exe → PATH.
fn resolve_supervisor_path() -> Result<PathBuf, BuilderVmError> {
    if let Some(p) = std::env::var_os("MVM_LIBKRUN_SUPERVISOR_PATH") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Ok(path);
        }
        return Err(BuilderVmError::LibkrunUnavailable(format!(
            "MVM_LIBKRUN_SUPERVISOR_PATH points at {} which is not a file",
            path.display()
        )));
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join("mvm-libkrun-supervisor");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    if let Ok(path) = which::which("mvm-libkrun-supervisor") {
        return Ok(path);
    }
    Err(BuilderVmError::LibkrunUnavailable(
        "mvm-libkrun-supervisor binary not found. \
         Looked for: $MVM_LIBKRUN_SUPERVISOR_PATH, alongside the current exe, and on $PATH. \
         Install via `cargo install --path crates/mvm-libkrun --features libkrun-sys` \
         or set MVM_LIBKRUN_SUPERVISOR_PATH=/abs/path/to/the/binary."
            .to_string(),
    ))
}

/// Spawn `mvm-libkrun-supervisor`, pipe a `SupervisorConfig`
/// JSON document to its stdin, then **wait** for it to exit.
/// Returns the child's exit code (0 on clean guest power-off
/// per libkrun's `start_enter` semantics; non-zero if the
/// supervisor errored before or during the guest run).
///
/// Spawn the supervisor with the given `cfg` piped to its stdin,
/// return the live `Child` *without* waiting on it. Persistent-VM
/// callers
/// ([`LibkrunPersistentHostVm::start`]) consume the child via
/// [`PersistentVmHandle`]; the single-shot
/// [`spawn_supervisor_and_wait`] calls this then runs the wait
/// loop on top.
fn spawn_supervisor_in_background(
    supervisor_path: &Path,
    cfg: &SupervisorConfig,
) -> Result<std::process::Child, BuilderVmError> {
    let json = serde_json::to_string(cfg).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!("serialize SupervisorConfig: {e}"))
    })?;

    let mut command = Command::new(supervisor_path);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // libkrun dlopens `libkrunfw.5.dylib` by short name when its
    // bundled-kernel path runs (e.g. `krun_set_root` mode without
    // an explicit `set_kernel`). macOS dyld's default search list
    // does not include /opt/homebrew/lib where Homebrew installs
    // libkrunfw, so the dlopen fails with "Couldn't find or load"
    // and the supervisor exits rc -2. Adding the Homebrew prefix
    // to DYLD_FALLBACK_LIBRARY_PATH unblocks the lookup without
    // overriding dyld's normal search order.
    #[cfg(target_os = "macos")]
    {
        let mut fallback = std::env::var("DYLD_FALLBACK_LIBRARY_PATH").unwrap_or_default();
        for path in ["/opt/homebrew/lib", "/usr/local/lib"] {
            if !fallback.split(':').any(|p| p == path) {
                if !fallback.is_empty() {
                    fallback.push(':');
                }
                fallback.push_str(path);
            }
        }
        command.env("DYLD_FALLBACK_LIBRARY_PATH", fallback);
    }
    let mut child = command.spawn().map_err(|e| {
        BuilderVmError::LibkrunUnavailable(format!("spawn {}: {e}", supervisor_path.display()))
    })?;
    child
        .stdin
        .take()
        .ok_or_else(|| {
            BuilderVmError::ExtractionFailed(
                "supervisor stdin was not piped (unreachable — Stdio::piped() requested)"
                    .to_string(),
            )
        })?
        .write_all(json.as_bytes())
        .map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "writing SupervisorConfig to supervisor stdin: {e}"
            ))
        })?;
    Ok(child)
}

/// Distinct from `mvm-backend::LibkrunBackend::start` which
/// only waits for the PID file to appear and then returns —
/// that consumer wants a long-lived background VM. The
/// builder VM is a one-shot; the caller can't make progress
/// until the build finishes.
fn spawn_supervisor_and_wait(
    supervisor_path: &Path,
    cfg: &SupervisorConfig,
    vm_state_dir: &Path,
    verbose: bool,
) -> Result<i32, BuilderVmError> {
    let mut child = spawn_supervisor_in_background(supervisor_path, cfg)?;

    let timeout = builder_vm_timeout()?;
    // Concurrent kernel-panic detector. The libkrun supervisor
    // blocks in `krun_start_enter` until the VM cleanly
    // exits; a kernel panic at PID 1 doesn't trigger a clean exit, so
    // a plain `child.wait()` would hang indefinitely. We tail the VM's
    // console log for the kernel's stable panic banner and kill the
    // supervisor on detection. When `console_output_path` is None
    // (callers that opted out of console capture), behavior is
    // unchanged — plain wait, plain exit code.
    let console_log = cfg.krun.console_output_path.as_deref().map(PathBuf::from);
    let outcome = wait_with_panic_detector_until(
        &mut child,
        console_log.as_deref(),
        DEFAULT_PANIC_POLL_INTERVAL,
        Some(timeout),
        verbose,
    );

    // The supervisor has now exited on every arm below — clean guest
    // poweroff (libkrun's internal `exit()`), or panic/timeout where we
    // SIGKILL'd it above. None of those run `GvproxyHandle::Drop` (no
    // unwind) or the supervisor's SIGTERM handler (SIGKILL is uncatchable,
    // exit() skips it), so the per-VM gvproxy is left "waiting for clients"
    // and reparented to launchd. Reap it here: we (the spawning host) have
    // observed the supervisor exit, so this is the one place teardown is
    // guaranteed regardless of how libkrun terminated. See
    // `gvproxy::reap_by_pid_file` (idempotent; no-op if already gone).
    libkrun_sys::gvproxy::reap_by_pid_file(vm_state_dir);

    match outcome {
        Ok(WaitOutcome::Clean(code)) => Ok(code),
        Ok(WaitOutcome::KernelPanic {
            panic_line,
            console_log_path,
        }) => Err(BuilderVmError::SeedKernelPanic {
            panic_line,
            console_log_path,
        }),
        Ok(WaitOutcome::Timeout) => Err(BuilderVmError::NixBuildFailed(format!(
            "builder VM exceeded {} seconds wall-clock; killed. Console log at {}/console.log.",
            timeout.as_secs(),
            vm_state_dir.display(),
        ))),
        Err(e) => Err(BuilderVmError::ExtractionFailed(format!(
            "wait on supervisor child: {e}"
        ))),
    }
}

/// Spawn a background thread that reads the
/// `HostVmResponse::Result` frame `mvm-host-vm-init` sends over
/// AF_VSOCK port [`mvm_guest::builder_agent::BUILDER_DISPATCH_PORT`]
/// right before reboot. Returns a `Receiver` the caller drains
/// after the supervisor exits via [`log_vsock_response_outcome`].
///
/// The thread starts BEFORE the supervisor so it can connect as
/// soon as libkrun creates `<vm_state_dir>/vsock-21471.sock` —
/// before the guest's listener exists, `UnixStream::connect` would
/// return `ENOENT`/`ECONNREFUSED`, hence the retry loop with a 60-second
/// outer deadline. Once connected, the thread reads with a 10-second
/// read deadline so an unresponsive guest doesn't leak the thread
/// indefinitely.
///
/// Older cached dev images won't send a response at all; the legacy
/// `<job_dir>/result` file path remains authoritative for the
/// build's exit code. This helper's job is purely
/// observational: log what arrives, warn on mismatch against the
/// file, never gate the build on the vsock outcome.
#[cfg(feature = "builder-vm")]
pub fn spawn_vsock_response_listener(
    vm_state_dir: &Path,
) -> std::sync::mpsc::Receiver<crate::builder_protocol::HostVmResponseRead> {
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use crate::builder_protocol::{HostVmResponseRead, read_host_vm_response};

    let (tx, rx) = mpsc::channel();
    let socket_path = vm_state_dir.join(mvm_core::config::vsock_socket_filename(
        mvm_guest::builder_agent::BUILDER_DISPATCH_PORT,
    ));

    std::thread::Builder::new()
        .name("vsock-builder-response".to_string())
        .spawn(move || {
            let connect_deadline = Duration::from_secs(60);
            let poll_interval = Duration::from_millis(100);
            let read_timeout = Duration::from_secs(10);
            let start = Instant::now();
            let result = loop {
                if start.elapsed() > connect_deadline {
                    break HostVmResponseRead::Timeout;
                }
                match UnixStream::connect(&socket_path) {
                    Ok(mut stream) => {
                        let _ = stream.set_read_timeout(Some(read_timeout));
                        break read_host_vm_response(&mut stream);
                    }
                    Err(_) => std::thread::sleep(poll_interval),
                }
            };
            // The receiver may have been dropped already (caller hit
            // its recv_timeout before the thread finished). That's
            // fine — the response was observational anyway.
            let _ = tx.send(result);
        })
        .expect("std::thread::Builder::spawn never fails on unix");

    rx
}

/// Drain the listener from [`spawn_vsock_response_listener`] with a
/// bounded wait and log the outcome. If `file_exit_code` is `Some`,
/// cross-validate against the vsock-reported exit code and warn on
/// mismatch (but never propagate as an error — the file is the
/// authoritative source for now).
///
/// The 5-second `recv_timeout` past supervisor exit is enough for
/// the read-deadline-bounded thread to deliver any in-flight
/// response; longer waits would hurt UX without buying meaningful
/// signal.
#[cfg(feature = "builder-vm")]
pub fn log_vsock_response_outcome(
    rx: std::sync::mpsc::Receiver<crate::builder_protocol::HostVmResponseRead>,
    file_exit_code: Option<i32>,
) {
    use crate::builder_protocol::{HostVmResponse, HostVmResponseRead};

    match rx.recv_timeout(std::time::Duration::from_secs(5)) {
        Ok(HostVmResponseRead::Frame(HostVmResponse::Result {
            exit_code,
            job_timings,
            boot_timings,
            ..
        })) => {
            tracing::info!(
                vsock_exit_code = exit_code,
                build_ms = job_timings.build_ms,
                boot_timings_present = boot_timings.is_some(),
                "received HostVmResponse::Result via vsock dispatch channel (W2 part 3)"
            );
            if let Some(file_code) = file_exit_code
                && file_code != exit_code
            {
                tracing::warn!(
                    file_exit_code = file_code,
                    vsock_exit_code = exit_code,
                    "vsock dispatch and <job_dir>/result disagree on exit_code; \
                     file value is authoritative pre-W3"
                );
            }
        }
        Ok(HostVmResponseRead::Frame(other)) => {
            tracing::debug!(
                ?other,
                "vsock dispatch: non-Result frame ignored in single-shot"
            );
        }
        Ok(HostVmResponseRead::EmptyEof) => {
            tracing::debug!(
                "vsock dispatch: guest closed without sending — \
                 pre-W2-part-3 image, expected"
            );
        }
        Ok(HostVmResponseRead::Timeout) => {
            tracing::debug!("vsock dispatch: receive thread timed out");
        }
        Err(_) => {
            tracing::debug!(
                "vsock dispatch: no response within 5s of supervisor exit \
                 (thread will self-terminate via read deadline)"
            );
        }
    }
}

/// Outcome of [`wait_with_panic_detector`]. `KernelPanic`
/// short-circuits the normal exit-code path with the captured banner
/// line so the caller can map it to [`BuilderVmError::SeedKernelPanic`]
/// without a separate side channel.
#[derive(Debug)]
enum WaitOutcome {
    Clean(i32),
    KernelPanic {
        panic_line: String,
        console_log_path: String,
    },
    Timeout,
}

/// Poll interval for the panic-detector watcher in production. Keeping
/// this short (100 ms) is what makes a panic surface in well under a
/// second — the kernel's panic banner is written via printk well
/// before the supervisor's blocking `start_enter` would have otherwise
/// noticed anything wrong.
const DEFAULT_PANIC_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Block on `child` while concurrently tailing `console_log` (if any)
/// for the kernel's stable panic banner `Kernel panic - not syncing`.
/// On detection, kill the child and return [`WaitOutcome::KernelPanic`]
/// with the captured line. When `console_log` is `None`, falls back to
/// a plain `child.wait`.
///
/// `poll_interval` is the watcher's sleep between log-tail polls;
/// production calls pass [`DEFAULT_PANIC_POLL_INTERVAL`]. Tests pass a
/// shorter interval (e.g. 10 ms) to keep wall-clock under control.
///
/// The watcher runs on its own thread. The main thread loops
/// `Child::try_wait` so it can break out either on child exit or on
/// the watcher signaling a panic. When the watcher signals a panic,
/// the main thread calls `Child::kill` to unblock the libkrun
/// supervisor (libkrun's `krun_start_enter` runs on the supervisor's
/// main thread inside `exit()` — SIGKILL is the only reliable
/// signal, which matches the gotcha documented in
/// `reference_libkrun_gotchas.md`).
#[cfg(test)]
fn wait_with_panic_detector(
    child: &mut Child,
    console_log: Option<&Path>,
    poll_interval: Duration,
    verbose: bool,
) -> std::io::Result<WaitOutcome> {
    wait_with_panic_detector_until(child, console_log, poll_interval, None, verbose)
}

fn wait_with_panic_detector_until(
    child: &mut Child,
    console_log: Option<&Path>,
    poll_interval: Duration,
    timeout: Option<Duration>,
    verbose: bool,
) -> std::io::Result<WaitOutcome> {
    let deadline = timeout.map(|duration| Instant::now() + duration);

    let panic_line: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let stop = Arc::new(AtomicBool::new(false));
    let watcher = console_log.map(|console_log| {
        let watcher_panic = Arc::clone(&panic_line);
        let watcher_stop = Arc::clone(&stop);
        let watcher_path = console_log.to_path_buf();
        std::thread::spawn(move || {
            panic_watcher(
                &watcher_path,
                &watcher_panic,
                &watcher_stop,
                poll_interval,
                verbose,
            );
        })
    });

    let wait_result = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => {}
            Err(e) => break Err(e),
        }
        if panic_line
            .lock()
            .expect("panic detector state lock poisoned")
            .is_some()
        {
            // Best-effort kill; the supervisor is wedged inside
            // libkrun's `start_enter` so SIGKILL is the only reliable
            // signal. If the kill itself fails (already exited, etc.),
            // fall through to `wait` so we still reap the zombie.
            let _ = child.kill();
            match child.wait() {
                Ok(status) => break Ok(status),
                Err(e) => break Err(e),
            }
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            let _ = child.kill();
            let _ = child.wait();
            stop.store(true, Ordering::SeqCst);
            if let Some(watcher) = watcher {
                let _ = watcher.join();
            }
            return Ok(WaitOutcome::Timeout);
        }
        let sleep = deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
            .map(|remaining| remaining.min(poll_interval))
            .unwrap_or(poll_interval);
        std::thread::sleep(sleep);
    };

    // Signal the watcher to exit and join it. Even on `Err` paths we
    // need the join — without it the spawned thread could outlive the
    // function with a live `&Path` to a tempdir the caller is about
    // to drop.
    stop.store(true, Ordering::SeqCst);
    if let Some(watcher) = watcher {
        let _ = watcher.join();
    }

    let status = wait_result?;
    let captured = panic_line
        .lock()
        .expect("panic detector state lock poisoned")
        .take();
    match captured {
        Some(line) => Ok(WaitOutcome::KernelPanic {
            panic_line: line,
            console_log_path: console_log
                .expect("panic line can only be captured when console log exists")
                .display()
                .to_string(),
        }),
        None => Ok(WaitOutcome::Clean(status.code().unwrap_or(-1))),
    }
}

/// The kernel's panic banner. Stable in upstream `kernel/panic.c` for
/// the last ~decade; substring match keeps us robust to colour codes,
/// log-level prefixes, and trailing detail.
const KERNEL_PANIC_BANNER: &str = "Kernel panic - not syncing";

/// Maximum bytes of unmatched tail we keep buffered between polls.
/// A panic line is short (~150 bytes) so 4 KiB is plenty of slack to
/// handle a partial last line spanning multiple reads.
const PANIC_WATCHER_BUFFER_CAP: usize = 4096;

/// Under `--verbose`, forward freshly-read console bytes to `sink`
/// (stderr in production). Extracted so the verbose-gating is unit
/// testable without capturing process stderr. Write errors are
/// silently dropped — the echo must never fail the build.
fn echo_console_chunk(sink: &mut impl Write, verbose: bool, chunk: &[u8]) {
    if verbose && !chunk.is_empty() {
        let _ = sink.write_all(chunk);
        let _ = sink.flush();
    }
}

/// Tail `console_log` for the kernel panic banner. On match, stores
/// the matching line into `panic_line` and returns. Polls every
/// `poll_interval` until either a match is found or `stop` is set.
///
/// Two robustness details that matter:
///
/// 1. **The console log doesn't exist when we start.** libkrun creates
///    the file on the first hvc0 byte the guest writes, ~100 ms after
///    `start_enter`. The watcher retries the `File::open` on every
///    poll until it succeeds — `console_log.exists()` is the cheap
///    pre-check.
///
/// 2. **Reads can split a line across polls.** A panic banner that
///    arrives at the same instant as the poll could be partially read
///    on one tick and completed on the next. We buffer unmatched tail
///    bytes (capped at [`PANIC_WATCHER_BUFFER_CAP`]) so the substring
///    match across reads still succeeds.
fn panic_watcher(
    console_log: &Path,
    panic_line: &Arc<Mutex<Option<String>>>,
    stop: &Arc<AtomicBool>,
    poll_interval: Duration,
    verbose: bool,
) {
    let mut file: Option<std::fs::File> = None;
    let mut buf: Vec<u8> = Vec::new();

    while !stop.load(Ordering::SeqCst) {
        if file.is_none() && console_log.exists() {
            file = std::fs::File::open(console_log).ok();
        }
        if let Some(ref mut f) = file {
            let mut chunk = Vec::new();
            // Best-effort; an IO error here just defers detection to
            // the next poll. The supervisor's eventual exit still
            // unblocks the main thread.
            if f.read_to_end(&mut chunk).is_ok() && !chunk.is_empty() {
                echo_console_chunk(&mut std::io::stderr(), verbose, &chunk);
                buf.extend_from_slice(&chunk);
                if let Some(line) = find_panic_line_in(&buf) {
                    *panic_line.lock().unwrap() = Some(line);
                    return;
                }
                // Trim buf to the last PANIC_WATCHER_BUFFER_CAP bytes
                // so a multi-minute build's console output doesn't
                // grow the watcher's memory without bound. The banner
                // is much shorter than the cap so a truncated buffer
                // never severs a pending match.
                if buf.len() > PANIC_WATCHER_BUFFER_CAP {
                    let start = buf.len() - PANIC_WATCHER_BUFFER_CAP;
                    buf.drain(0..start);
                }
            }
        }
        std::thread::sleep(poll_interval);
    }
}

/// Scan `buf` for the kernel panic banner. On match, return the
/// containing line decoded as a UTF-8 string (lossy decoding — kernel
/// log output is ASCII in practice but we don't want a stray non-UTF-8
/// byte to silently drop the panic detection).
fn find_panic_line_in(buf: &[u8]) -> Option<String> {
    // Cheap pre-check before the lossy UTF-8 conversion.
    let needle = KERNEL_PANIC_BANNER.as_bytes();
    let idx = buf.windows(needle.len()).position(|w| w == needle)?;
    // Walk back to the previous newline (or start of buffer) and
    // forward to the next newline so the returned line is the full
    // banner with its detail (the kernel writes
    // `Kernel panic - not syncing: Requested init ... failed (error N).`
    // on a single line).
    let line_start = buf[..idx]
        .iter()
        .rposition(|&b| b == b'\n')
        .map(|i| i + 1)
        .unwrap_or(0);
    let line_end = buf[idx..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|i| idx + i)
        .unwrap_or(buf.len());
    let line = String::from_utf8_lossy(&buf[line_start..line_end])
        .trim_end_matches('\r')
        .to_string();
    Some(line)
}

/// Render a Path as a `&str` or surface a clear error if it
/// contains non-UTF-8 bytes. libkrun's C API takes
/// `*const c_char`; rejecting non-UTF-8 here pins the failure
/// to the offending field rather than a CString conversion
/// deep inside the FFI.
fn path_to_str<'a>(p: &'a Path, field: &str) -> Result<&'a str, BuilderVmError> {
    p.to_str().ok_or_else(|| {
        BuilderVmError::ExtractionFailed(format!("{field} has non-UTF-8 bytes: {p:?}"))
    })
}

// ============================================================
// LibkrunPersistentHostVm
// ============================================================

/// Filename of the marker the host stages under `<job_dir>/` to
/// tell `mvm-host-vm-init` to enter its dispatch loop instead of
/// running the single-shot `cmd.sh` / `install_spec` flow. Same key
/// as the path the guest checks.
pub const DISPATCH_SOCK_MARKER: &str = "dispatch.sock.marker";

/// Spawn the long-lived builder VM that `mvm-host-vm-init`'s
/// dispatch loop runs inside.
///
/// Mirrors the config surface of [`LibkrunBuilderVm`] but
/// produces a different shape of dispatch: instead of running a
/// single cmd.sh / install_spec and powering off, the guest
/// detects `<job_dir>/<DISPATCH_SOCK_MARKER>` and enters the
/// dispatch loop that reads `HostVmRequest` frames over
/// AF_VSOCK port [`mvm_guest::builder_agent::BUILDER_DISPATCH_PORT`].
///
/// The caller pairs this with a `PersistentBuilderSupervisor`
/// constructed against [`PersistentVmHandle::dispatch_socket_path`].
///
/// ## Not yet wired
///
/// - `mvmctl dev up` integration is what actually constructs one of
///   these against the dev session's lifecycle.
/// - Per-job namespace isolation inside the dispatch loop.
#[cfg(feature = "builder-vm")]
#[derive(Debug, Clone)]
pub struct LibkrunPersistentHostVm {
    vcpus: u8,
    memory_mib: u32,
    nix_store_mib: u32,
    image_override: Option<BuilderVmImage>,
    /// Host directory bound at `/work` in the guest. Bound at VM
    /// start, not per-dispatch.
    workspace_root: PathBuf,
}

#[cfg(feature = "builder-vm")]
impl LibkrunPersistentHostVm {
    /// Construct a persistent builder VM rooted at `workspace_root`.
    /// Defaults match [`LibkrunBuilderVm::default`] for vCPUs / RAM /
    /// nix-store image size.
    pub fn new(workspace_root: impl Into<PathBuf>) -> Self {
        Self {
            vcpus: DEFAULT_VCPUS,
            memory_mib: DEFAULT_MEMORY_MIB,
            nix_store_mib: DEFAULT_NIX_STORE_MIB,
            image_override: None,
            workspace_root: workspace_root.into(),
        }
    }

    pub fn with_vcpus(mut self, vcpus: u8) -> Self {
        self.vcpus = vcpus;
        self
    }

    pub fn with_memory_mib(mut self, memory_mib: u32) -> Self {
        self.memory_mib = memory_mib;
        self
    }

    pub fn with_nix_store_mib(mut self, nix_store_mib: u32) -> Self {
        self.nix_store_mib = nix_store_mib;
        self
    }

    pub fn with_image_override(mut self, image: BuilderVmImage) -> Self {
        self.image_override = Some(image);
        self
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    /// Spawn the supervisor + libkrun VM in the background and
    /// return a handle whose `dispatch_socket_path` the supervisor
    /// connects to. The returned `Child` is alive
    /// until either the guest dispatch loop processes a
    /// `HostVmRequest::Shutdown` (clean exit) or the caller
    /// invokes [`PersistentVmHandle::kill`].
    pub fn start(&self) -> Result<PersistentVmHandle, BuilderVmError> {
        if !libkrun_sys::is_available() {
            return Err(BuilderVmError::LibkrunUnavailable(format!(
                "libkrun shared library not found on host. {}",
                libkrun_sys::install_hint()
            )));
        }

        if !self.workspace_root.is_dir() {
            return Err(BuilderVmError::ExtractionFailed(format!(
                "workspace_root {} is not a directory",
                self.workspace_root.display()
            )));
        }

        let supervisor_path = resolve_supervisor_path()?;
        let image = match &self.image_override {
            Some(image) => image.clone(),
            None => ensure_builder_vm_image()?,
        };
        // Acquire the cross-process flock on the nix-store image
        // for the persistent VM's lifetime. Concurrent
        // `mvmctl deps install` while a dev session's persistent VM
        // is up would otherwise corrupt the shared ext4. Held inside
        // the handle; released on drop / kill / wait_for_shutdown.
        let nix_store_lock = acquire_nix_store_image_lock(
            &builder_vm_cache_dir(),
            host_arch_tag(),
            u64::from(self.nix_store_mib),
        )?;

        let session_id = unique_job_id();
        let job_dir = builder_vm_cache_dir().join("jobs").join(&session_id);
        stage_persistent_job_dir(&job_dir)?;

        let vm_name = format!("mvm-persistent-builder-vm-{session_id}");
        let vm_state_dir = builder_vm_cache_dir().join("vms").join(&vm_name);
        std::fs::create_dir_all(&vm_state_dir).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating persistent builder VM state dir {}: {e}",
                vm_state_dir.display()
            ))
        })?;
        let console_log = vm_state_dir.join("console.log");

        let mut krun = krun_context_for_image(&vm_name, &image)?
            .with_resources(self.vcpus, self.memory_mib)
            .with_console_output(path_to_str(&console_log, "console_log")?)
            .with_vsock_socket_dir(path_to_str(&vm_state_dir, "vm_state_dir")?)
            .add_disk(
                "nix-store",
                path_to_str(nix_store_lock.path(), "nix_store_img")?,
                false,
            )
            .add_virtio_fs("work", path_to_str(&self.workspace_root, "workspace_root")?)
            .add_virtio_fs("out", path_to_str(&job_dir, "job_dir")?)
            .add_virtio_fs("job", path_to_str(&job_dir, "job_dir")?)
            .add_vsock_port(mvm_guest::builder_agent::BUILDER_DISPATCH_PORT)
            // The workload-vsock nesting hop. The in-host-VM forwarder
            // listens here; the outer host reaches a workload's
            // Firecracker vsock via `<vm_state_dir>/vsock-21472.sock`.
            // libkrun registers vsock ports at launch, so this must be
            // added up front even though workloads start later.
            .add_vsock_port(mvm_guest::builder_agent::WORKLOAD_FORWARD_PORT);

        krun = apply_networking_mode(krun, &vm_state_dir)?;

        let cfg = SupervisorConfig {
            krun,
            vm_state_dir: path_to_str(&vm_state_dir, "vm_state_dir")?.to_string(),
            pid_file_name: Some("builder.pid".to_string()),
            tenant_id: None,
            audit_dir: None,
            gateway_audit_socket: None,
            gateway_events_socket: None,
            signing_key_path: None,
            plan: None,
            bundle: None,
            // Builder VMs are always hard-fail; they don't model
            // long-running user workloads where a restart policy would
            // apply.
            bridge_restart_policy: libkrun_sys::BridgeRestartPolicy::HardFail,
        };

        let child = spawn_supervisor_in_background(&supervisor_path, &cfg)?;

        Ok(PersistentVmHandle {
            vm_state_dir,
            job_dir,
            session_id,
            supervisor: Some(child),
            _nix_store_lock: nix_store_lock,
        })
    }
}

/// Stage `<job_dir>/<DISPATCH_SOCK_MARKER>` so the in-guest
/// `mvm-host-vm-init` enters its dispatch loop instead of the
/// single-shot cmd.sh / install_spec flow. The marker
/// body is intentionally empty — its mere existence is the
/// signal.
#[cfg(feature = "builder-vm")]
fn stage_persistent_job_dir(job_dir: &Path) -> Result<(), BuilderVmError> {
    std::fs::create_dir_all(job_dir).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "creating persistent job dir {}: {e}",
            job_dir.display()
        ))
    })?;
    let marker_path = job_dir.join(DISPATCH_SOCK_MARKER);
    std::fs::write(&marker_path, b"").map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "staging dispatch marker {}: {e}",
            marker_path.display()
        ))
    })?;
    Ok(())
}

/// Handle to a live persistent builder VM. Owns the supervisor
/// `Child` for its lifetime; dropping without calling
/// [`Self::wait_for_shutdown`] or [`Self::kill`] leaks the
/// supervisor process (and the VM behind it) — callers should
/// always one of the two before dropping.
#[cfg(feature = "builder-vm")]
#[derive(Debug)]
pub struct PersistentVmHandle {
    vm_state_dir: PathBuf,
    job_dir: PathBuf,
    session_id: String,
    /// `None` after [`Self::wait_for_shutdown`] consumes it.
    supervisor: Option<std::process::Child>,
    /// Held to keep the cross-process flock on the shared
    /// nix-store image alive for the VM's lifetime. Drops
    /// (releasing the lock) when the handle drops, after
    /// `wait_for_shutdown`, or after `kill`. Underscore-prefixed
    /// because the type is opaque to consumers — it exists for
    /// its `Drop` side-effect.
    _nix_store_lock: NixStoreImageLock,
}

#[cfg(feature = "builder-vm")]
impl PersistentVmHandle {
    /// Path libkrun uses for the per-VM state (vsock sockets,
    /// console log, PID file). Pass this to
    /// `dispatch_socket_path` when constructing the
    /// `PersistentBuilderSupervisor`.
    pub fn vm_state_dir(&self) -> &Path {
        &self.vm_state_dir
    }

    /// Host-side path of the libkrun-managed Unix socket that
    /// proxies to AF_VSOCK [`mvm_guest::builder_agent::BUILDER_DISPATCH_PORT`]
    /// inside the guest. `PersistentBuilderSupervisor::new` takes
    /// this directly.
    pub fn dispatch_socket_path(&self) -> PathBuf {
        self.vm_state_dir
            .join(mvm_core::config::vsock_socket_filename(
                mvm_guest::builder_agent::BUILDER_DISPATCH_PORT,
            ))
    }

    /// Per-VM job directory bound at `/job` inside the guest.
    /// Hosts stage per-dispatch artifacts (`<job_dir_relpath>/cmd.sh`,
    /// per-dispatch install specs, etc.) here before sending the
    /// matching `HostVmRequest::Run`.
    pub fn job_dir(&self) -> &Path {
        &self.job_dir
    }

    /// Opaque session identifier — useful for logging /
    /// observability. Stable for the VM's lifetime.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Block until the supervisor child exits. Normal way to
    /// reach this is the supervisor sending `HostVmRequest::Shutdown`,
    /// the guest dispatch loop processing it + replying `Bye`,
    /// then `mvm-host-vm-init` calling `reboot(RB_POWER_OFF)`,
    /// then libkrun's `krun_start_enter` returning, then the
    /// supervisor exiting `main`. Consumes the child; subsequent
    /// calls return [`BuilderVmError::ExtractionFailed`].
    pub fn wait_for_shutdown(mut self) -> Result<i32, BuilderVmError> {
        let mut child = self.supervisor.take().ok_or_else(|| {
            BuilderVmError::ExtractionFailed(
                "PersistentVmHandle::wait_for_shutdown called twice".to_string(),
            )
        })?;
        let status = child.wait().map_err(|e| {
            BuilderVmError::ExtractionFailed(format!("waiting on persistent supervisor: {e}"))
        })?;
        Ok(status.code().unwrap_or(-1))
    }

    /// Forcibly terminate the supervisor child (SIGKILL via
    /// `Child::kill`). The VM goes down hard; in-flight builds
    /// are abandoned. Use only as a fallback after
    /// [`Self::wait_for_shutdown`] hangs.
    pub fn kill(&mut self) -> std::io::Result<()> {
        if let Some(child) = self.supervisor.as_mut() {
            child.kill()?;
            let _ = child.wait();
            self.supervisor = None;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder_vm_runtime::{INSTALL_SPEC_FILENAME, shell_single_quote_escape};
    use std::sync::{LazyLock, Mutex};
    use tempfile::TempDir;

    static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    fn ok_mounts(scratch: &TempDir) -> BuilderMounts {
        let flake = scratch.path().join("flake");
        std::fs::create_dir_all(&flake).unwrap();
        let out = scratch.path().join("out");
        let host_bins = scratch.path().join("host-bins");
        std::fs::create_dir_all(&host_bins).unwrap();
        BuilderMounts {
            flake_src: flake,
            host_nix_store: None,
            artifact_out: out,
            host_bin_dir: host_bins,
            staged_user_flake: None,
        }
    }

    fn ok_job() -> BuilderJob {
        BuilderJob::Flake {
            flake_ref: "path:/work".to_string(),
            attr_path: "packages.x86_64-linux.default".to_string(),
        }
    }

    #[test]
    fn defaults_match_plan_72_w1() {
        let vm = LibkrunBuilderVm::default();
        assert_eq!(vm.vcpus, 4);
        // 4 → 8 GiB (in-VM nix builds peak ~5-6 GiB; OOM at lower
        // default). Later raised to 16 GiB for overlapping build
        // working sets. Hardcoded so a regression on either side
        // fails fast.
        assert_eq!(vm.memory_mib, 16384);
        assert_eq!(vm.nix_store_mib, 65536);
    }

    #[test]
    fn resolve_networking_mode_parses_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: tests guarded by ENV_LOCK; env mutation in test
        // process is fine when serialized.
        unsafe {
            // Default is per-OS — macOS → Gvproxy, others → Passt.
            std::env::remove_var("MVM_NETWORKING");
            assert_eq!(resolve_networking_mode(), default_networking_mode());

            std::env::set_var("MVM_NETWORKING", " passt ");
            // passt is Linux-only (the Homebrew formula refuses to build it on
            // macOS), so an explicit passt pin is macOS-safe: resolve falls back
            // to gvproxy with a warning rather than handing the supervisor a
            // gateway it can't spawn.
            if cfg!(target_os = "macos") {
                assert_eq!(resolve_networking_mode(), NetworkingPreference::Gvproxy);
            } else {
                assert_eq!(resolve_networking_mode(), NetworkingPreference::Passt);
            }

            std::env::set_var("MVM_NETWORKING", "GVPROXY");
            assert_eq!(resolve_networking_mode(), NetworkingPreference::Gvproxy);

            std::env::set_var("MVM_NETWORKING", " gvproxy ");
            assert_eq!(resolve_networking_mode(), NetworkingPreference::Gvproxy);

            std::env::set_var("MVM_NETWORKING", "");
            assert_eq!(resolve_networking_mode(), default_networking_mode());

            // Unknown value falls back to the per-OS default without panic.
            std::env::set_var("MVM_NETWORKING", "vmnet-helper");
            assert_eq!(resolve_networking_mode(), default_networking_mode());

            std::env::remove_var("MVM_NETWORKING");
        }
    }

    #[test]
    fn tsi_no_longer_resolvable() {
        // TSI was removed. `MVM_NETWORKING=tsi` (any case) must NOT
        // resolve to a TSI mode — it falls back to the
        // per-OS gateway default with a warning. This guards the
        // claim-10 no-bypass invariant at the env-var surface.
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: ENV_LOCK serializes env mutation across tests.
        unsafe {
            for variant in ["tsi", "TSI", "Tsi", " tsi ", "tSi"] {
                std::env::set_var("MVM_NETWORKING", variant);
                assert_eq!(
                    resolve_networking_mode(),
                    default_networking_mode(),
                    "MVM_NETWORKING={variant} must fall back to per-OS default \
                     (TSI was removed in Plan 102 W6.A)"
                );
            }
            std::env::remove_var("MVM_NETWORKING");
        }
    }

    #[test]
    fn default_networking_mode_matches_host_os() {
        let expected = if cfg!(target_os = "macos") {
            NetworkingPreference::Gvproxy
        } else {
            NetworkingPreference::Passt
        };
        assert_eq!(default_networking_mode(), expected);
    }

    #[test]
    fn validate_mounts_rejects_missing_flake_src() {
        let scratch = TempDir::new().unwrap();
        let host_bins = scratch.path().join("host-bins");
        std::fs::create_dir_all(&host_bins).unwrap();
        let mounts = BuilderMounts {
            flake_src: scratch.path().join("does-not-exist"),
            host_nix_store: None,
            artifact_out: scratch.path().join("out"),
            host_bin_dir: host_bins,
            staged_user_flake: None,
        };
        let err = LibkrunBuilderVm::default()
            .validate_mounts(&mounts)
            .unwrap_err();
        assert!(matches!(err, BuilderVmError::ExtractionFailed(_)));
        assert!(format!("{err}").contains("does not exist"));
    }

    #[test]
    fn validate_mounts_rejects_flake_src_that_is_a_file() {
        let scratch = TempDir::new().unwrap();
        let file = scratch.path().join("not-a-dir");
        std::fs::write(&file, b"").unwrap();
        let host_bins = scratch.path().join("host-bins");
        std::fs::create_dir_all(&host_bins).unwrap();
        let mounts = BuilderMounts {
            flake_src: file,
            host_nix_store: None,
            artifact_out: scratch.path().join("out"),
            host_bin_dir: host_bins,
            staged_user_flake: None,
        };
        let err = LibkrunBuilderVm::default()
            .validate_mounts(&mounts)
            .unwrap_err();
        assert!(format!("{err}").contains("must be a directory"));
    }

    #[test]
    fn validate_mounts_creates_artifact_out_if_missing() {
        let scratch = TempDir::new().unwrap();
        let mounts = ok_mounts(&scratch);
        assert!(!mounts.artifact_out.exists());
        LibkrunBuilderVm::default()
            .validate_mounts(&mounts)
            .unwrap();
        assert!(mounts.artifact_out.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn validate_mounts_rejects_non_utf8_paths() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        use std::path::PathBuf;

        // Synthesize a PathBuf with non-UTF-8 bytes in memory.
        // 0xFF is invalid UTF-8 (RFC 3629 says the byte cannot
        // appear in a valid UTF-8 sequence). We don't touch the
        // filesystem because APFS refuses to create files with
        // non-UTF-8 names; the validator's UTF-8 check runs
        // before any I/O so this still exercises the right path.
        let raw = OsStr::from_bytes(b"/tmp/non-utf8-\xff");
        let bad_path = PathBuf::from(raw);
        let scratch = TempDir::new().unwrap();
        let host_bins = scratch.path().join("host-bins");
        std::fs::create_dir_all(&host_bins).unwrap();
        let mounts = BuilderMounts {
            flake_src: bad_path,
            host_nix_store: None,
            artifact_out: std::env::temp_dir().join("mvm-plan72-w1-utf8-test-out"),
            host_bin_dir: host_bins,
            staged_user_flake: None,
        };
        let err = LibkrunBuilderVm::default()
            .validate_mounts(&mounts)
            .unwrap_err();
        assert!(
            format!("{err}").contains("non-UTF-8 bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_job_rejects_empty_flake_ref() {
        let job = BuilderJob::Flake {
            flake_ref: "".to_string(),
            attr_path: "packages.x86_64-linux.default".to_string(),
        };
        let err = LibkrunBuilderVm::default().validate_job(&job).unwrap_err();
        assert!(format!("{err}").contains("flake_ref"));
    }

    #[test]
    fn validate_job_rejects_whitespace_only_attr_path() {
        let job = BuilderJob::Flake {
            flake_ref: "path:/work".to_string(),
            attr_path: "   ".to_string(),
        };
        let err = LibkrunBuilderVm::default().validate_job(&job).unwrap_err();
        assert!(format!("{err}").contains("attr_path"));
    }

    #[test]
    fn validate_job_rejects_install_with_missing_spec() {
        // The Install variant validates that spec_path actually
        // exists — the spec is read inside the VM, so the host needs
        // the file present before dispatch.
        let job = BuilderJob::Install {
            spec_path: PathBuf::from("/definitely/does/not/exist.json"),
        };
        let err = LibkrunBuilderVm::default().validate_job(&job).unwrap_err();
        assert!(
            matches!(err, BuilderVmError::ExtractionFailed(_)),
            "got {err:?}"
        );
        assert!(
            format!("{err}").contains("spec_path"),
            "expected spec_path in error: {err}"
        );
    }

    #[test]
    fn validate_job_accepts_install_with_existing_spec() {
        // Smoke-test the happy path of Install validation. We
        // don't construct a real spec — the parsing happens later.
        // We only check that a real file passes.
        let scratch = TempDir::new().unwrap();
        let spec_path = scratch.path().join("spec.json");
        std::fs::write(&spec_path, b"{}").unwrap();
        let job = BuilderJob::Install { spec_path };
        LibkrunBuilderVm::default().validate_job(&job).unwrap();
    }

    #[test]
    fn run_build_surfaces_environment_gaps_for_install_variant() {
        // The Install variant is wired — passing input validation no
        // longer trips NotYetImplemented. Two host shapes can hit
        // this code path:
        //
        // - CI runner without libkrun: `run_build` short-circuits at
        //   the supervisor-binary lookup with `LibkrunUnavailable`
        //   (or `ExtractionFailed` if an earlier I/O step fails).
        // - Contributor host with libkrun installed via Homebrew (per
        //   `CLAUDE.md` host-deps): the supervisor actually spawns
        //   against the stub `{}` install spec, which the in-VM
        //   pipeline rejects because the spec is missing required
        //   fields (`language`, …) — surfacing as `NixBuildFailed`.
        //
        // Both outcomes prove the wiring proceeds past validation
        // rather than short-circuiting on `NotYetImplemented`, which
        // is what this test exists to guarantee. The test must NOT
        // require a specific host environment.
        let scratch = TempDir::new().unwrap();
        let spec_path = scratch.path().join("spec.json");
        std::fs::write(&spec_path, b"{}").unwrap();
        let mounts = ok_mounts(&scratch);
        let err = LibkrunBuilderVm::default()
            .run_build(&BuilderJob::Install { spec_path }, &mounts)
            .unwrap_err();
        assert!(
            !matches!(err, BuilderVmError::NotYetImplemented),
            "Install variant must not short-circuit on NotYetImplemented: {err:?}"
        );
        assert!(
            matches!(
                err,
                BuilderVmError::LibkrunUnavailable(_)
                    | BuilderVmError::ExtractionFailed(_)
                    | BuilderVmError::NixBuildFailed(_)
            ),
            "unexpected error variant: {err:?}"
        );
    }

    #[test]
    fn stage_job_dir_install_copies_spec_into_job_dir() {
        // Install jobs stage `<job_dir>/install_spec.json` rather
        // than `cmd.sh`. The
        // guest's `mvm-host-vm-init` probes for that filename and
        // dispatches through the install pipeline.
        let scratch = TempDir::new().unwrap();
        let job_dir = scratch.path().join("job-1");
        let spec_path = scratch.path().join("spec.json");
        let spec_body = br#"{"language":"python","lockfile_relative_path":"uv.lock","source_mount":"/work","gate":"dev"}"#;
        std::fs::write(&spec_path, spec_body).unwrap();
        stage_job_dir(&job_dir, &BuilderJob::Install { spec_path }, None, None).expect("stage ok");
        let dst = job_dir.join(INSTALL_SPEC_FILENAME);
        assert!(dst.is_file(), "install_spec.json must be staged at {dst:?}");
        let on_disk = std::fs::read(&dst).unwrap();
        assert_eq!(on_disk, spec_body, "spec bytes must round-trip verbatim");
        // No cmd.sh is emitted for install jobs.
        assert!(
            !job_dir.join("cmd.sh").exists(),
            "install jobs must not stage cmd.sh"
        );
    }

    // `finalize_install_job_*` test coverage migrated to
    // `builder_vm_runtime` alongside the function itself.

    #[test]
    fn run_build_fails_validation_before_reaching_libkrun() {
        // Bad input → validation error from `validate_mounts` /
        // `validate_job`, before run_build reaches the libkrun
        // availability check or the image cache.
        let scratch = TempDir::new().unwrap();
        let host_bins = scratch.path().join("host-bins");
        std::fs::create_dir_all(&host_bins).unwrap();
        let mounts = BuilderMounts {
            flake_src: scratch.path().join("missing"),
            host_nix_store: None,
            artifact_out: scratch.path().join("out"),
            host_bin_dir: host_bins,
            staged_user_flake: None,
        };
        let err = LibkrunBuilderVm::default()
            .run_build(&ok_job(), &mounts)
            .unwrap_err();
        assert!(matches!(err, BuilderVmError::ExtractionFailed(_)));
    }

    #[test]
    fn run_build_surfaces_environment_gaps_on_clean_input() {
        // Input passes `validate_mounts` + `validate_job` (the dir
        // exists, the flake_ref/attr_path are well-shaped) but the
        // *environment* is missing one of the things `run_build`
        // needs to succeed. Which thing depends on host state, and
        // each yields a typed error variant — this test pins the
        // union so a regression that swaps in `Internal`/`Unknown`
        // or panics outright fails fast:
        //   - libkrun shared library missing → LibkrunUnavailable
        //   - builder VM image cache empty   → ExtractionFailed
        //   - mvm-libkrun-supervisor missing → LibkrunUnavailable
        //   - flake.nix missing inside the (empty) stub mount, on
        //     a host where libkrun + cache + supervisor are all
        //     present (fully-bootstrapped contributor host) →
        //     NixBuildFailed
        // All four are legitimate "environment gap" surfaces. The
        // fourth is what `mvmctl dev up` reports to operators with
        // a populated cache; the first three are what `mvmctl dev
        // up` reports before the Stage 0 bootstrap completes.
        let scratch = TempDir::new().unwrap();
        let mounts = ok_mounts(&scratch);
        let err = LibkrunBuilderVm::default()
            .run_build(&ok_job(), &mounts)
            .unwrap_err();
        assert!(
            matches!(
                err,
                BuilderVmError::LibkrunUnavailable(_)
                    | BuilderVmError::ExtractionFailed(_)
                    | BuilderVmError::NixBuildFailed(_)
            ),
            "unexpected error variant: {err:?}"
        );
    }

    #[test]
    fn shell_single_quote_escape_handles_apostrophes() {
        // `cmd.sh` embeds flake_ref + attr_path inside `'…'`
        // quoted shell variables. The only character that can't
        // appear verbatim is `'`. Standard escape: close-quote,
        // escape-via-backslash, reopen-quote.
        assert_eq!(shell_single_quote_escape("plain"), "plain");
        assert_eq!(shell_single_quote_escape("it's"), r"it'\''s");
        assert_eq!(shell_single_quote_escape("a'b'c"), r"a'\''b'\''c");
    }

    #[test]
    fn stage_job_dir_writes_cmd_sh_with_escaped_inputs() {
        let scratch = TempDir::new().unwrap();
        let job_dir = scratch.path().join("job-1");
        let job = BuilderJob::Flake {
            flake_ref: "path:/work/nix/images/foo".to_string(),
            attr_path: "packages.x86_64-linux.default".to_string(),
        };
        stage_job_dir(&job_dir, &job, None, None).unwrap();
        let cmd = std::fs::read_to_string(job_dir.join("cmd.sh")).unwrap();
        assert!(cmd.contains("FLAKE_REF='path:/work/nix/images/foo'"));
        assert!(cmd.contains("ATTR_PATH='packages.x86_64-linux.default'"));
        assert!(cmd.starts_with("#!/bin/sh"));
        assert!(cmd.contains("set -eu"));
        assert!(cmd.contains("cd /work"));
        assert!(cmd.contains("max-jobs = auto"));
        assert!(cmd.contains("cores = 0"));
        assert!(cmd.contains("auto-optimise-store = true"));
        assert!(cmd.contains("XDG_CACHE_HOME=/nix-store/.cache"));
        assert!(cmd.contains("printf '%s\\n' \"$NIX_OUT\" > /job/store-path"));
        // Legacy (no-override) mode never injects an mvm override.
        assert!(!cmd.contains("--override-input mvm"));
    }

    #[test]
    fn stage_job_dir_override_stages_user_flake_and_overrides_mvm() {
        // Source-checkout override mode stages the user flake into
        // the job dir and pins `mvm` to the local checkout
        // mounted at /work, so the workload builds against in-repo nix
        // rather than GitHub.
        let scratch = TempDir::new().unwrap();
        let job_dir = scratch.path().join("job-ovr");
        let user_flake = scratch.path().join("hello-app");
        std::fs::create_dir_all(user_flake.join("src")).unwrap();
        std::fs::write(user_flake.join("flake.nix"), "{ inputs.mvm.url = \"x\"; }").unwrap();
        std::fs::write(user_flake.join("launch.json"), "{}").unwrap();
        std::fs::write(user_flake.join("src/app.py"), "x").unwrap();

        // A stand-in mvm workspace: members + a build artifact and a
        // non-allowlisted top-level dir that must be pruned from the
        // staged snapshot.
        let workspace = scratch.path().join("mvm-ws");
        std::fs::create_dir_all(workspace.join("crates/mvm-guest/src")).unwrap();
        std::fs::create_dir_all(workspace.join("crates/mvm-guest/target/debug")).unwrap();
        std::fs::create_dir_all(workspace.join("public")).unwrap();
        std::fs::write(workspace.join("Cargo.toml"), "[workspace]").unwrap();
        std::fs::write(workspace.join("Cargo.lock"), "").unwrap();
        std::fs::write(workspace.join("crates/mvm-guest/Cargo.toml"), "x").unwrap();
        std::fs::write(workspace.join("crates/mvm-guest/src/lib.rs"), "x").unwrap();
        std::fs::write(workspace.join("crates/mvm-guest/target/debug/junk"), "x").unwrap();
        std::fs::write(workspace.join("public/index.html"), "x").unwrap();

        let job = BuilderJob::Flake {
            flake_ref: "/work".to_string(), // ignored in override mode
            attr_path: "packages.aarch64-linux.default".to_string(),
        };
        stage_job_dir(
            &job_dir,
            &job,
            Some(user_flake.as_path()),
            Some(workspace.as_path()),
        )
        .unwrap();

        // User flake copied beside cmd.sh, including the src tree.
        assert!(job_dir.join("workload/flake.nix").exists());
        assert!(job_dir.join("workload/src/app.py").exists());

        // Filtered mvm-workspace snapshot: members copied, build artifacts
        // and non-allowlisted top-level dirs pruned.
        assert!(job_dir.join("mvm-src/Cargo.lock").exists());
        assert!(job_dir.join("mvm-src/crates/mvm-guest/src/lib.rs").exists());
        assert!(
            !job_dir.join("mvm-src/crates/mvm-guest/target").exists(),
            "target/ must be pruned from the staged snapshot"
        );
        assert!(
            !job_dir.join("mvm-src/public").exists(),
            "non-allowlisted top-level dirs must not be staged"
        );

        let cmd = std::fs::read_to_string(job_dir.join("cmd.sh")).unwrap();
        // Builds the staged workload resolved relative to the script dir.
        assert!(cmd.contains(r#"FLAKE_REF="$(cd "$(dirname "$0")" && pwd)/workload""#));
        // Resolves the filtered workspace snapshot beside the script too.
        assert!(cmd.contains(r#"MVM_SRC="$(cd "$(dirname "$0")" && pwd)/mvm-src""#));
        // Pins mvm to the local checkout and mvm-workspace to the snapshot.
        assert!(cmd.contains("--override-input mvm path:/work/nix"));
        assert!(cmd.contains(r#"--override-input mvm/mvm-workspace "path:$MVM_SRC""#));
        assert!(cmd.contains("ATTR_PATH='packages.aarch64-linux.default'"));
        // The overrides ride both the build and the metadata eval.
        assert_eq!(
            cmd.matches("--override-input mvm path:/work/nix").count(),
            3
        );
        assert_eq!(
            cmd.matches(r#"--override-input mvm/mvm-workspace "path:$MVM_SRC""#)
                .count(),
            3
        );
    }

    #[test]
    fn host_arch_tag_is_one_of_two_known_values() {
        // The builder-vm flake outputs aarch64-linux and
        // x86_64-linux only; the cache-key segment must match
        // one of those.
        let tag = host_arch_tag();
        assert!(
            tag == "aarch64" || tag == "x86_64",
            "unexpected arch tag: {tag}"
        );
    }

    #[test]
    fn stage0_nix_store_image_name_is_arch_keyed_and_distinct_from_builder() {
        let name = stage0_nix_store_image_name();
        // `cache info` globs `nix-store-*.img` for its sparse report;
        // stay inside that glob so the Stage 0 store is surfaced too.
        assert!(name.starts_with("nix-store-stage0-"), "got {name}");
        assert!(name.ends_with(".img"), "got {name}");
        assert!(name.contains(host_arch_tag()), "got {name}");
        // Must NOT collide with the steady-state builder store filename,
        // or the two flocks would serialize against each other.
        assert_ne!(name, format!("nix-store-{}.img", host_arch_tag()));
    }

    // `read_job_result_*`, `extract_nix_store_hash_*`,
    // `finalize_flake_job_*`, `read_last_bytes_of_*`,
    // `acquire_nix_store_image_lock_*` test coverage migrated to
    // `builder_vm_runtime` alongside the functions themselves.

    #[test]
    fn ensure_builder_vm_image_requires_cmdline_txt() {
        let _lock = ENV_LOCK.lock().unwrap();
        let scratch = TempDir::new().unwrap();
        let old = std::env::var("XDG_CACHE_HOME").ok();
        unsafe {
            std::env::set_var("XDG_CACHE_HOME", scratch.path());
        }

        let arch_dir = scratch
            .path()
            .join("mvm")
            .join("builder-vm")
            .join(host_arch_tag());
        std::fs::create_dir_all(&arch_dir).unwrap();
        std::fs::write(arch_dir.join("vmlinux"), b"kernel").unwrap();
        std::fs::write(arch_dir.join("rootfs.ext4"), b"rootfs").unwrap();

        let err = ensure_builder_vm_image().unwrap_err();
        assert!(
            format!("{err}").contains("cmdline.txt missing or unreadable"),
            "got {err}"
        );

        unsafe {
            match old {
                Some(v) => std::env::set_var("XDG_CACHE_HOME", v),
                None => std::env::remove_var("XDG_CACHE_HOME"),
            }
        }
    }

    // `builder_vm_timeout_*` tests migrated to `builder_vm_runtime`
    // alongside the function.

    #[test]
    fn unique_job_id_includes_pid_and_timestamp() {
        let id = unique_job_id();
        let pid = std::process::id().to_string();
        assert!(id.ends_with(&pid), "id missing pid suffix: {id}");
        assert!(id.contains('-'), "id missing separator: {id}");
    }

    #[test]
    fn with_resources_overrides() {
        let vm = LibkrunBuilderVm::default().with_resources(2, 2048);
        assert_eq!(vm.vcpus, 2);
        assert_eq!(vm.memory_mib, 2048);
        assert_eq!(vm.nix_store_mib, 65536); // unchanged
    }

    #[test]
    fn with_nix_store_mib_overrides() {
        let vm = LibkrunBuilderVm::default().with_nix_store_mib(8192);
        assert_eq!(vm.nix_store_mib, 8192);
    }

    // ---------------------------------------------------------------
    // kernel-panic detector.
    //
    // `find_panic_line_in` is a pure scanner — tested directly. The
    // `wait_with_panic_detector` integration tests spawn `sleep` as a
    // stand-in for the libkrun supervisor (writes nothing on its own
    // to the console log, exits cleanly when killed or after its
    // configured duration). Tests run on Unix only because `sleep`
    // and `Child::kill` semantics are POSIX-specific.
    // ---------------------------------------------------------------

    #[test]
    fn find_panic_line_in_returns_none_when_banner_absent() {
        let buf = b"some boot log\nanother line\nfinal line\n";
        assert_eq!(find_panic_line_in(buf), None);
    }

    #[test]
    fn find_panic_line_in_extracts_full_line_when_banner_present() {
        let buf = b"[ 0.05 ] EXT4-fs: mounted\n\
                    [ 0.08 ] Kernel panic - not syncing: Requested init /sbin/foo failed (error -2).\n\
                    [ 0.09 ] more output\n";
        let line = find_panic_line_in(buf).expect("must match");
        assert!(line.contains("Kernel panic - not syncing"));
        assert!(line.contains("Requested init /sbin/foo failed"));
        assert!(!line.contains('\n'));
    }

    #[test]
    fn find_panic_line_in_handles_buffer_with_no_trailing_newline() {
        // Watcher may read partial output where the panic line is at
        // the end with no `\n` yet. The scanner still returns the
        // whole bufferred line so the watcher can fire immediately
        // instead of waiting for the next newline.
        let buf = b"[ 0.05 ] booting\n[ 0.08 ] Kernel panic - not syncing: detail";
        let line = find_panic_line_in(buf).expect("must match");
        assert!(line.contains("Kernel panic - not syncing: detail"));
    }

    #[test]
    fn find_panic_line_in_trims_trailing_carriage_return() {
        // Some console drivers emit `\r\n`; the line should be the
        // banner without the trailing `\r`.
        let buf = b"[ 0.08 ] Kernel panic - not syncing: oops\r\nnext line\n";
        let line = find_panic_line_in(buf).expect("must match");
        assert!(!line.ends_with('\r'), "got {line:?}");
        assert!(line.ends_with(": oops"));
    }

    #[test]
    fn find_panic_line_in_returns_match_at_start_of_buffer() {
        let buf = b"Kernel panic - not syncing: first thing\nsubsequent\n";
        let line = find_panic_line_in(buf).expect("must match");
        assert_eq!(line, "Kernel panic - not syncing: first thing");
    }

    #[cfg(unix)]
    #[test]
    fn wait_with_panic_detector_returns_clean_when_no_console_log() {
        // No console log → falls back to plain wait; clean exit code
        // is propagated as-is.
        let mut child = Command::new("sh")
            .args(["-c", "exit 7"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sh");
        let outcome = wait_with_panic_detector(&mut child, None, Duration::from_millis(10), false)
            .expect("ok");
        match outcome {
            WaitOutcome::Clean(7) => {}
            other => panic!("expected Clean(7), got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn wait_with_panic_detector_returns_clean_when_log_never_contains_banner() {
        let scratch = TempDir::new().unwrap();
        let console = scratch.path().join("console.log");
        // Write a few benign lines — the watcher sees them, finds no
        // banner, the child exits cleanly, outcome is Clean.
        std::fs::write(&console, b"[ 0.01 ] boot\n[ 0.02 ] hello\n").unwrap();
        let mut child = Command::new("sh")
            .args(["-c", "exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sh");
        let outcome =
            wait_with_panic_detector(&mut child, Some(&console), Duration::from_millis(10), false)
                .expect("ok");
        match outcome {
            WaitOutcome::Clean(0) => {}
            other => panic!("expected Clean(0), got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn wait_with_panic_detector_kills_child_when_banner_appears() {
        let scratch = TempDir::new().unwrap();
        let console = scratch.path().join("console.log");

        // Long-running child standing in for the wedged libkrun
        // supervisor. Without panic detection this would block the
        // wait for the full 30s; with detection we expect it to be
        // killed within ~poll_interval of the banner write.
        let mut child = Command::new("sh")
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sh");

        // Writer thread: after a short delay, drop the banner into
        // the console log. The watcher should pick it up on the next
        // poll and signal the main thread to kill the sleep.
        let console_writer = console.clone();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            std::fs::write(
                &console_writer,
                b"[ 0.01 ] booting\n[ 0.08 ] Kernel panic - not syncing: test banner\n",
            )
            .expect("write console log fixture");
        });

        let start = std::time::Instant::now();
        let outcome =
            wait_with_panic_detector(&mut child, Some(&console), Duration::from_millis(10), false)
                .expect("ok");
        let elapsed = start.elapsed();
        writer.join().expect("writer thread join");

        match outcome {
            WaitOutcome::KernelPanic {
                panic_line,
                console_log_path,
            } => {
                assert!(
                    panic_line.contains("Kernel panic - not syncing: test banner"),
                    "panic_line: {panic_line:?}"
                );
                assert_eq!(console_log_path, console.display().to_string());
            }
            other => panic!("expected KernelPanic, got {other:?}"),
        }

        // The full sleep is 30s; detection-and-kill must complete in
        // a small fraction of that. 5s is generous slack for the
        // slowest plausible CI runner. A regression that loses the
        // kill (i.e. falls back to the wait blocking for 30s) blows
        // this assertion well before it would hang the suite.
        assert!(
            elapsed < Duration::from_secs(5),
            "panic detector did not kill the child promptly: {elapsed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn wait_with_panic_detector_handles_late_console_log_creation() {
        let scratch = TempDir::new().unwrap();
        let console = scratch.path().join("console.log");
        // No console.log on disk yet — the watcher must poll for it.
        let mut child = Command::new("sh")
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sh");

        let console_writer = console.clone();
        let writer = std::thread::spawn(move || {
            // Sleep past several poll cycles so the watcher exercises
            // its "file doesn't exist yet, retry" branch before the
            // write lands.
            std::thread::sleep(Duration::from_millis(200));
            std::fs::write(
                &console_writer,
                b"Kernel panic - not syncing: delayed banner\n",
            )
            .expect("write console log fixture");
        });

        let outcome =
            wait_with_panic_detector(&mut child, Some(&console), Duration::from_millis(10), false)
                .expect("ok");
        writer.join().unwrap();

        match outcome {
            WaitOutcome::KernelPanic { panic_line, .. } => {
                assert!(panic_line.contains("delayed banner"));
            }
            other => panic!("expected KernelPanic, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn seed_kernel_panic_error_display_mentions_panic_line_and_log_path() {
        // Pin the error's Display output so callers (Stage 0 audit
        // emit, user-facing UI) get a stable, parseable message
        // shape.
        let err = BuilderVmError::SeedKernelPanic {
            panic_line: "Kernel panic - not syncing: example".to_string(),
            console_log_path: "/tmp/example/console.log".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("Stage 0 seed VM kernel-panicked"), "{msg}");
        assert!(msg.contains("Kernel panic - not syncing: example"), "{msg}");
        assert!(msg.contains("/tmp/example/console.log"), "{msg}");
    }

    // -----------------------------------------------------------
    // LibkrunPersistentHostVm
    // -----------------------------------------------------------

    #[test]
    fn dispatch_sock_marker_constant_is_filename_only() {
        // Must not contain `/`. The host joins it under <job_dir>;
        // a slash would break the path concatenation contract the
        // in-guest builder-init's marker probe assumes.
        assert!(!DISPATCH_SOCK_MARKER.contains('/'));
        assert!(!DISPATCH_SOCK_MARKER.is_empty());
        assert_eq!(DISPATCH_SOCK_MARKER, "dispatch.sock.marker");
    }

    #[test]
    fn stage_persistent_job_dir_creates_marker_in_fresh_dir() {
        // Hermetic — no libkrun, no VM. Validates the host's
        // side of the marker-file convention.
        let scratch = TempDir::new().expect("tempdir");
        let job_dir = scratch.path().join("job-dir");
        stage_persistent_job_dir(&job_dir).expect("stage");
        let marker = job_dir.join(DISPATCH_SOCK_MARKER);
        assert!(
            marker.is_file(),
            "marker should exist at {}",
            marker.display()
        );
        // Marker body is intentionally empty — its existence is
        // the signal. If the body grows non-empty in the future
        // the dispatch contract changes.
        let body = std::fs::read(&marker).expect("read marker");
        assert_eq!(body, b"");
    }

    #[test]
    fn stage_persistent_job_dir_is_idempotent() {
        // Re-staging into the same job dir must succeed (caller
        // may retry after a transient supervisor failure).
        let scratch = TempDir::new().expect("tempdir");
        let job_dir = scratch.path().join("job-dir");
        stage_persistent_job_dir(&job_dir).expect("stage 1");
        stage_persistent_job_dir(&job_dir).expect("stage 2");
        assert!(job_dir.join(DISPATCH_SOCK_MARKER).is_file());
    }

    #[test]
    fn persistent_vm_config_defaults_track_libkrun_builder_vm() {
        // Same vcpus / memory / nix-store defaults so users moving
        // from single-shot to persistent don't see surprise
        // resource shifts.
        let vm = LibkrunPersistentHostVm::new(std::env::temp_dir());
        assert_eq!(vm.vcpus, DEFAULT_VCPUS);
        assert_eq!(vm.memory_mib, DEFAULT_MEMORY_MIB);
        assert_eq!(vm.nix_store_mib, DEFAULT_NIX_STORE_MIB);
    }

    #[test]
    fn persistent_vm_with_setters_override_defaults() {
        let vm = LibkrunPersistentHostVm::new(std::env::temp_dir())
            .with_vcpus(2)
            .with_memory_mib(2048)
            .with_nix_store_mib(8192);
        assert_eq!(vm.vcpus, 2);
        assert_eq!(vm.memory_mib, 2048);
        assert_eq!(vm.nix_store_mib, 8192);
    }

    #[test]
    fn persistent_vm_start_rejects_missing_workspace() {
        // ExtractionFailed is the typed error variant for "host
        // input doesn't satisfy the precondition". Caller will
        // surface it directly.
        let nonexistent = std::env::temp_dir().join(format!(
            "no-such-workspace-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let vm = LibkrunPersistentHostVm::new(&nonexistent);
        match vm.start() {
            Err(BuilderVmError::ExtractionFailed(msg)) => {
                assert!(msg.contains("workspace_root"), "msg: {msg}");
                assert!(msg.contains("not a directory"), "msg: {msg}");
            }
            // libkrun may not be installed in CI; that's a
            // different error variant and also acceptable.
            Err(BuilderVmError::LibkrunUnavailable(_)) => {}
            other => panic!("expected ExtractionFailed or LibkrunUnavailable, got {other:?}"),
        }
    }

    // ---------------------------------------------------------------
    // vsock response listener
    // ---------------------------------------------------------------
    //
    // Live in `crates/mvm-build/tests/vsock_response_listener.rs`
    // (not here) so the server-binding pattern they need to simulate
    // libkrun's host-side proxy doesn't trip the `architecture.yml`
    // invariant grep against `crates/` source. The grep excludes
    // `**/tests/**` by design — that's where mock-server patterns
    // for test scaffolding belong.

    // ---------------------------------------------------------------
    // LibkrunBuilderBackend impl
    //
    // Construction-shape tests only. Exercising `run_attached_with_mounts`
    // requires libkrun + the builder image + an actual supervisor
    // child, which is the integration-test surface; unit-level
    // assertions cover the trait wiring + the `console_log_path`
    // contract.
    // ---------------------------------------------------------------

    #[test]
    fn libkrun_builder_backend_with_supervisor_and_image_stores_paths() {
        let supervisor = PathBuf::from("/tmp/mvm-test-supervisor");
        let image = BuilderVmImage::Rootfs {
            kernel_path: PathBuf::from("/tmp/vmlinux"),
            rootfs_path: PathBuf::from("/tmp/rootfs.ext4"),
            cmdline: "console=hvc0".to_string(),
        };
        let backend = LibkrunBuilderBackend::with_supervisor_and_image(supervisor.clone(), image);
        assert_eq!(backend.supervisor_path, supervisor);
        match &backend.image {
            BuilderVmImage::Rootfs { kernel_path, .. } => {
                assert_eq!(kernel_path, &PathBuf::from("/tmp/vmlinux"));
            }
            other => panic!("expected Rootfs variant, got {other:?}"),
        }
    }

    #[test]
    fn libkrun_builder_backend_console_log_lives_under_vm_state_dir() {
        let backend = LibkrunBuilderBackend::with_supervisor_and_image(
            PathBuf::from("/tmp/supervisor"),
            BuilderVmImage::Rootfs {
                kernel_path: PathBuf::from("/tmp/k"),
                rootfs_path: PathBuf::from("/tmp/r"),
                cmdline: String::new(),
            },
        );
        let dir = PathBuf::from("/tmp/state/builder-foo");
        let log = backend.console_log_path(&dir);
        assert_eq!(log, dir.join("console.log"));
        // Trait-object safety: confirm the impl satisfies `&dyn ...`.
        let _erased: &dyn VmBackendForBuilder = &backend;
    }

    #[test]
    fn echo_console_chunk_writes_only_when_verbose() {
        let mut sink: Vec<u8> = Vec::new();
        echo_console_chunk(&mut sink, false, b"hello");
        assert!(sink.is_empty(), "quiet mode must not echo");
        echo_console_chunk(&mut sink, true, b"hello");
        assert_eq!(sink, b"hello", "verbose mode echoes the chunk verbatim");
        echo_console_chunk(&mut sink, true, b"");
        assert_eq!(sink, b"hello", "empty chunk is a no-op");
    }

    #[test]
    fn libkrun_builder_vm_with_verbose_sets_flag() {
        let vm = LibkrunBuilderVm::default();
        assert!(!vm.verbose, "default is quiet");
        let vm = LibkrunBuilderVm::default().with_verbose(true);
        assert!(vm.verbose, "with_verbose(true) flips the flag");
    }
}
