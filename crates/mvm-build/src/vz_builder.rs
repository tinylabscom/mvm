//! Apple Virtualization.framework (Vz) backend for the builder VM,
//! parallel to [`crate::libkrun_builder::LibkrunBuilderBackend`].
//!
//! Second `VmBackendForBuilder` impl. Owns the
//! Vz-specific spawn (`mvm-vz-supervisor` binary with
//! [`crate::vz::SupervisorConfig`] JSON on stdin) and surfaces the
//! resulting `BuilderVmExitInfo` back to the seam.
//!
//! ## Scope
//!
//! This module is the **trait impl only**. The high-level
//! `VzBuilderVm` driver that wraps `BuilderVmRuntime` around this
//! backend (mirroring `LibkrunBuilderVm`) lands in a follow-up.
//!
//! ## Why no panic detector
//!
//! The libkrun panic detector exists because
//! `krun_start_enter` blocks indefinitely on a panicked guest —
//! `Child::wait()` never returns, so a host-side console-log watcher
//! has to kill the supervisor. The Vz Swift supervisor uses
//! `VZVirtualMachine.start()` instead and exits cleanly when the guest
//! powers off or panics (`main.swift` contract: 0
//! clean / 1 guest error / 2 config parse / 3 supervisor startup).
//! So the Vz path can rely on `Child::wait()` plus a wall-clock
//! timeout — no console-log polling needed.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::thread;
use std::time::Duration;

use crate::builder_vm::{
    BuilderArtifacts, BuilderJob, BuilderMounts, BuilderVm, BuilderVmDisk, BuilderVmError,
    BuilderVmExitInfo, BuilderVmMount, BuilderVmRunConfig, VmBackendForBuilder,
};
use crate::builder_vm_runtime::{
    NixStoreImageLock, acquire_nix_store_image_lock, builder_vm_timeout, finalize_flake_job,
    finalize_install_job, stage_job_dir, supervisor_exit_error,
};
use crate::host_gvproxy;
use crate::libkrun_builder::{
    BuilderVmImage, DISPATCH_SOCK_MARKER, builder_vm_cache_dir, ensure_builder_vm_image,
    ensure_utf8_path, host_arch_tag, unique_job_id,
};

/// Standard kernel cmdline the Vz supervisor pairs with the builder
/// VM's rootfs. Matches `mvm_backend::vz::DEFAULT_CMDLINE`'s shape —
/// console on the virtio-hvc port (so `Self::console_log_path`
/// captures it), rootfs as the first virtio-blk device, builder VM
/// init at `/init`.
///
/// The cmdline from [`BuilderVmImage::Rootfs::cmdline`] takes
/// precedence when non-empty; this constant is the fallback so
/// callers that pass an empty cmdline get a sensible boot.
pub const DEFAULT_VZ_BUILDER_CMDLINE: &str = "console=hvc0 root=/dev/vda ro init=/init panic=1";

/// Tear-down guard for the host-side gvproxy the Vz builder VM uses
/// for egress. Stops the detached gvproxy via its PID-sidecar file on
/// `Drop` so a build that times out or errors out doesn't leak the
/// daemon. Mirrors `mvm_backend::vz::AttachedGvproxyGuard`.
struct BuilderGvproxyGuard {
    state_dir: PathBuf,
}

impl BuilderGvproxyGuard {
    /// Disarm the guard so it does NOT reap gvproxy on drop. Used by
    /// the persistent VM's `start` once the supervisor is spawned: the
    /// detached gvproxy must outlive the CLI and is reaped later,
    /// cross-process, by `stop_persistent_vz_by_pid_file`.
    fn defuse(self) {
        std::mem::forget(self);
    }
}

impl Drop for BuilderGvproxyGuard {
    fn drop(&mut self) {
        if let Err(e) = host_gvproxy::stop_by_pid_file(&self.state_dir) {
            tracing::warn!(
                state_dir = %self.state_dir.display(),
                error = %e,
                "BuilderGvproxyGuard: host_gvproxy stop failed on drop"
            );
        }
    }
}

/// Vz parallel of [`crate::libkrun_builder::LibkrunBuilderBackend`]. Holds
/// the resolved supervisor binary path + cached builder VM image so
/// a missing prerequisite surfaces at `new()`-time, not mid-build.
///
/// Only the [`BuilderVmImage::Rootfs`] variant is supported — Vz has
/// no analog of libkrun's `krun_set_root` directory-as-rootfs path.
/// [`Self::new_with_rootfs_image`] enforces the variant at
/// construction so `run_attached_with_mounts` can't be reached with
/// an incompatible image.
#[derive(Debug)]
pub struct VzBuilderBackend {
    supervisor_path: PathBuf,
    image: BuilderVmImage,
}

impl VzBuilderBackend {
    /// Construct over an already-resolved supervisor path + image.
    /// Refuses [`BuilderVmImage::RootDir`] — that variant is
    /// libkrun-only. Used by `Self::new` and by tests that want to
    /// inject a fake supervisor without touching the filesystem.
    pub fn new_with_rootfs_image(
        supervisor_path: PathBuf,
        image: BuilderVmImage,
    ) -> Result<Self, BuilderVmError> {
        match &image {
            BuilderVmImage::Rootfs { .. } => {}
            BuilderVmImage::RootDir { .. } => {
                return Err(BuilderVmError::ExtractionFailed(
                    "VzBuilderBackend requires a Rootfs image; RootDir is libkrun-specific \
                     (krun_set_root has no Vz analog)"
                        .to_string(),
                ));
            }
        }
        Ok(Self {
            supervisor_path,
            image,
        })
    }
}

impl VzBuilderBackend {
    /// `run_attached_with_mounts` with an optional host-side gvproxy.
    /// The trait method delegates here with `None`; `run_build` calls
    /// it with `Some` so the Vz builder VM gets egress for cold
    /// `nix build`s. Kept inherent (not on the trait) so the libkrun
    /// backend — which spawns gvproxy in-process via
    /// `libkrun_sys::gvproxy::spawn` — doesn't inherit a param it
    /// can't use.
    fn run_attached_with_mounts_gvproxy(
        &self,
        config: &BuilderVmRunConfig,
        mounts: &[BuilderVmMount],
        extra_disks: &[BuilderVmDisk],
        timeout: Duration,
        gvproxy: Option<&host_gvproxy::HostGvproxyInfo>,
    ) -> Result<BuilderVmExitInfo, BuilderVmError> {
        if !mvm_core::platform::current().has_vz() {
            return Err(BuilderVmError::ExtractionFailed(
                "Apple Virtualization.framework is not available on this host. \
                 Requires macOS 13 or later."
                    .to_string(),
            ));
        }

        std::fs::create_dir_all(&config.vm_state_dir).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating builder VM state dir {}: {e}",
                config.vm_state_dir.display()
            ))
        })?;

        let cfg = build_vz_supervisor_config(config, &self.image, mounts, extra_disks, gvproxy)?;
        let json = cfg.to_json().map_err(|e| {
            BuilderVmError::ExtractionFailed(format!("serialize SupervisorConfig: {e}"))
        })?;

        let mut child = Command::new(&self.supervisor_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| {
                BuilderVmError::ExtractionFailed(format!(
                    "spawn mvm-vz-supervisor at {}: {e}",
                    self.supervisor_path.display()
                ))
            })?;
        child
            .stdin
            .take()
            .ok_or_else(|| {
                BuilderVmError::ExtractionFailed(
                    "mvm-vz-supervisor stdin was not piped after spawn".to_string(),
                )
            })?
            .write_all(json.as_bytes())
            .map_err(|e| {
                BuilderVmError::ExtractionFailed(format!(
                    "pipe SupervisorConfig JSON to mvm-vz-supervisor stdin: {e}"
                ))
            })?;

        match wait_with_timeout(child, timeout) {
            Ok(Some(code)) => Ok(BuilderVmExitInfo {
                exit_code: Some(code),
                panic_line: None,
            }),
            Ok(None) => Err(BuilderVmError::NixBuildFailed(format!(
                "builder VM exceeded {} seconds wall-clock; killed. Console log at {}.",
                timeout.as_secs(),
                self.console_log_path(&config.vm_state_dir).display(),
            ))),
            Err(e) => Err(BuilderVmError::ExtractionFailed(format!(
                "wait on mvm-vz-supervisor child: {e}"
            ))),
        }
    }
}

impl VmBackendForBuilder for VzBuilderBackend {
    fn run_attached_with_mounts(
        &self,
        config: &BuilderVmRunConfig,
        mounts: &[BuilderVmMount],
        extra_disks: &[BuilderVmDisk],
        timeout: Duration,
    ) -> Result<BuilderVmExitInfo, BuilderVmError> {
        // No gvproxy via the bare trait path — offline / cached
        // builds only. `run_build` calls the inherent _gvproxy variant
        // with a live gateway.
        self.run_attached_with_mounts_gvproxy(config, mounts, extra_disks, timeout, None)
    }

    fn console_log_path(&self, vm_state_dir: &Path) -> PathBuf {
        // Same path the libkrun backend uses + the Vz supervisor
        // already captures into via `console_output_path`. Both
        // backends keep the file at the same relative location so
        // operators don't have to know which backend produced a
        // given run.
        vm_state_dir.join("console.log")
    }
}

/// Build the Vz [`crate::vz::SupervisorConfig`] from the trait's
/// hypervisor-agnostic inputs. Pulled out of
/// `run_attached_with_mounts` so unit tests can exercise the mapping
/// without spawning a supervisor.
fn build_vz_supervisor_config(
    config: &BuilderVmRunConfig,
    image: &BuilderVmImage,
    mounts: &[BuilderVmMount],
    extra_disks: &[BuilderVmDisk],
    gvproxy: Option<&host_gvproxy::HostGvproxyInfo>,
) -> Result<crate::vz::SupervisorConfig, BuilderVmError> {
    let BuilderVmImage::Rootfs {
        kernel_path,
        rootfs_path,
        cmdline,
    } = image
    else {
        // Guarded at construction; double-check so this stays sound
        // if a future refactor exposes a builder that skips the
        // variant check.
        return Err(BuilderVmError::ExtractionFailed(
            "VzBuilderBackend reached run with non-Rootfs image".to_string(),
        ));
    };

    let kernel = path_to_string(kernel_path, "kernel_path")?;
    let rootfs = path_to_string(rootfs_path, "rootfs_path")?;
    let state_dir = path_to_string(&config.vm_state_dir, "vm_state_dir")?;
    let vsock_dir = config
        .vm_state_dir
        .join("vsock")
        .to_string_lossy()
        .into_owned();
    let console_log = config
        .vm_state_dir
        .join("console.log")
        .to_string_lossy()
        .into_owned();

    let effective_cmdline = if cmdline.is_empty() {
        DEFAULT_VZ_BUILDER_CMDLINE.to_string()
    } else {
        cmdline.clone()
    };

    let mut disks = vec![crate::vz::DiskConfig {
        id: "rootfs".to_string(),
        path: rootfs,
        // Rootfs is RO at boot (matches the verified-boot model
        // + every other backend's posture). Writes go to overlays
        // / extra disks.
        read_only: true,
    }];
    for d in extra_disks {
        disks.push(crate::vz::DiskConfig {
            id: d.id.clone(),
            path: path_to_string(&d.host_path, "extra_disk")?,
            read_only: d.read_only,
        });
    }

    let mut virtio_fs = Vec::with_capacity(mounts.len());
    for m in mounts {
        virtio_fs.push(crate::vz::VirtioFsShare {
            tag: m.tag.clone(),
            host_path: path_to_string(&m.host_path, "mount_host_path")?,
            read_only: m.read_only,
        });
    }

    let initrd_path = match &config.initrd_path {
        Some(p) => Some(path_to_string(p, "initrd_path")?),
        None => None,
    };

    Ok(crate::vz::SupervisorConfig {
        name: config.name.clone(),
        vm_state_dir: state_dir,
        pid_file_name: Some("builder.pid".to_string()),
        kernel: crate::vz::KernelConfig {
            path: kernel,
            cmdline: effective_cmdline,
            initrd_path,
        },
        resources: crate::vz::ResourceConfig {
            // BuilderVmRunConfig.vcpus is u8 (caller-bound by host
            // cap checks); crate::vz::ResourceConfig.cpu_count is u32.
            cpu_count: u32::from(config.vcpus),
            memory_mib: u64::from(config.memory_mib),
        },
        disks,
        virtio_fs,
        vsock: crate::vz::VsockConfig {
            ports: config.vsock_ports.clone(),
            socket_dir: vsock_dir,
            // The builder VM has no egress-substitution endpoint; no host-listen
            // ports.
            host_listen_ports: vec![],
        },
        console_output_path: Some(console_log),
        // gvproxy gives a cold `nix build` egress to fetch nixpkgs.
        // `None` keeps the offline / cached-derivation path (the
        // caller passes `None` to opt out).
        //
        // events_ingest_socket_path stays None on purpose: the builder
        // VM is a TRUSTED dev-tier build VM whose only egress is
        // fetching nixpkgs — NOT a workload subject to the claim-10
        // gateway flow-audit. So no flow-audit drainer; plain gvproxy.
        network: gvproxy.map(|g| crate::vz::NetworkConfig::Gvproxy {
            socket_path: g.socket_path.to_string_lossy().into_owned(),
            mac: host_gvproxy::derive_mac(&config.name),
            events_ingest_socket_path: None,
        }),
        balloon: None,
        control_socket_path: None,
        startup_mode: crate::vz::StartupMode::Boot,
        // Builder VMs are trusted dev-tier — no claim-10 flow audit.
        tenant_id: None,
        plan: None,
        bundle: None,
        audit_dir: None,
        gateway_audit_socket: None,
        signing_key_path: None,
    })
}

/// Block on `child` until it exits or `timeout` elapses. On timeout,
/// kill the supervisor and return `Ok(None)` so the caller can format
/// a wall-clock error pointing at the console log. Thread-based
/// because `std::process::Child` has no async wait on stable.
fn wait_with_timeout(mut child: Child, timeout: Duration) -> std::io::Result<Option<i32>> {
    let id = child.id();
    let (tx, rx) = channel();
    // The wait happens in a separate thread so the main thread can
    // arm the wall-clock timer with a `recv_timeout`. The child
    // handle is moved into the thread so its `Drop` (which would
    // otherwise reap the process unconditionally) runs there only
    // on the success path.
    let join = thread::spawn(move || {
        let status = child.wait();
        let _ = tx.send((child, status));
    });

    match rx.recv_timeout(timeout) {
        Ok((_child, status)) => {
            let _ = join.join();
            // The supervisor's exit code matches the guest's exit
            // per the main.swift contract. None for
            // signal-terminated supervisors (rare but possible
            // under SIGKILL).
            Ok(status?.code())
        }
        Err(RecvTimeoutError::Timeout) => {
            // Drop the receiver before killing so the spawned
            // thread's send doesn't block on a dead channel.
            drop(rx);
            // Kill by pid — the thread still owns the `Child`
            // handle, so we can't call `.kill()` directly. SIGKILL
            // because the supervisor is supposed to be a
            // well-behaved child; if it ignored SIGTERM we'd be
            // waiting on a wedged process anyway.
            //
            // Safety: `id` is the pid we got from `Child::id()`,
            // which is guaranteed valid until the OS reaps the
            // process. The spawned thread's `Child::wait()` is what
            // does the reaping, and it's still running, so this
            // kill races safely with that wait.
            #[cfg(unix)]
            unsafe {
                libc::kill(id as i32, libc::SIGKILL);
            }
            #[cfg(not(unix))]
            {
                // No portable cross-platform pid-kill; on non-unix
                // we wait for the watcher thread to surface the
                // child and kill via its handle. Drops the timeout
                // contract slightly, but Vz is macOS-only so this
                // path is unreachable in practice.
                let _ = id;
            }
            let _ = join.join();
            Ok(None)
        }
        Err(RecvTimeoutError::Disconnected) => {
            let _ = join.join();
            Err(std::io::Error::other(
                "wait-with-timeout thread panicked before sending exit status",
            ))
        }
    }
}

fn path_to_string(p: &Path, field: &str) -> Result<String, BuilderVmError> {
    p.to_str().map(str::to_string).ok_or_else(|| {
        BuilderVmError::ExtractionFailed(format!(
            "{field} path {} is not valid UTF-8 (Swift supervisor JSON requires UTF-8 strings)",
            p.display()
        ))
    })
}

// ─────────────────────────────────────────────────────────────────
// VzBuilderVm — high-level driver, parallel to LibkrunBuilderVm.
//
// Wraps `VzBuilderBackend` (the seam impl) with the same
// orchestration LibkrunBuilderVm performs: validate, acquire the
// shared `/nix-store` virtio-blk image lock, stage the per-job dir,
// dispatch through the seam, then finalize per job variant. The
// shared bits (NixStoreImageLock, stage_job_dir, finalize_flake_job,
// finalize_install_job, builder_vm_timeout, supervisor_exit_error)
// all live in `builder_vm_runtime`; this driver is just the
// Vz-specific glue.
// ─────────────────────────────────────────────────────────────────

/// Default vCPU count for Vz builder VM runs. Same value as
/// [`crate::libkrun_builder::DEFAULT_VCPUS`] — nix builds parallelise at
/// the derivation level, so 4 cores keeps a build saturated without
/// pinning the host.
pub const VZ_BUILDER_DEFAULT_VCPUS: u8 = crate::libkrun_builder::DEFAULT_VCPUS;

/// Default guest RAM (MiB) for Vz builder VM runs. Same value as
/// [`crate::libkrun_builder::DEFAULT_MEMORY_MIB`] for parity with the
/// libkrun path; the Stage 0 tmpfs cap inside the builder VM rootfs
/// is what actually limits build memory, not the VM-level cap.
pub const VZ_BUILDER_DEFAULT_MEMORY_MIB: u32 = crate::libkrun_builder::DEFAULT_MEMORY_MIB;

/// Default persistent `/nix-store` sparse-image cap (MiB) for Vz
/// builder VM runs. Same value as
/// [`crate::libkrun_builder::DEFAULT_NIX_STORE_MIB`] so swapping backends
/// doesn't change the on-disk cache footprint.
pub const VZ_BUILDER_DEFAULT_NIX_STORE_MIB: u32 = crate::libkrun_builder::DEFAULT_NIX_STORE_MIB;

/// Vz parallel of [`crate::libkrun_builder::LibkrunBuilderVm`]. Implements
/// [`BuilderVm::run_build`] against the [`VzBuilderBackend`] seam,
/// sharing every bit of substrate orchestration with the libkrun
/// driver via the shared `builder_vm_runtime` helpers.
///
/// Field shape mirrors `LibkrunBuilderVm` so a caller switching
/// backends at the env-var level finds the same knobs.
/// `supervisor_path_override`
/// is Vz-only — useful in tests + the `MVM_VZ_SUPERVISOR_PATH`
/// override path.
#[derive(Debug, Clone, Default)]
pub struct VzBuilderVm {
    /// Guest vCPU count. See [`VZ_BUILDER_DEFAULT_VCPUS`].
    pub vcpus: u8,
    /// Guest RAM in MiB. See [`VZ_BUILDER_DEFAULT_MEMORY_MIB`].
    pub memory_mib: u32,
    /// Persistent `/nix-store` sparse cap. See
    /// [`VZ_BUILDER_DEFAULT_NIX_STORE_MIB`].
    pub nix_store_mib: u32,
    /// Optional caller-supplied bootstrap image. When set,
    /// [`Self::run_build`] boots from this kernel/rootfs/cmdline
    /// instead of resolving the builder VM image from
    /// `~/.cache/mvm/builder-vm/<arch>/`. Same shape as the libkrun
    /// driver's [`crate::libkrun_builder::LibkrunBuilderVm::image_override`].
    pub image_override: Option<BuilderVmImage>,
    /// Optional supervisor binary path override. When `None`,
    /// [`resolve_vz_supervisor_path`] is consulted. Useful for tests
    /// that inject a fake supervisor.
    pub supervisor_path_override: Option<PathBuf>,
}

impl VzBuilderVm {
    /// Construct with the canonical defaults.
    pub fn new() -> Self {
        Self {
            vcpus: VZ_BUILDER_DEFAULT_VCPUS,
            memory_mib: VZ_BUILDER_DEFAULT_MEMORY_MIB,
            nix_store_mib: VZ_BUILDER_DEFAULT_NIX_STORE_MIB,
            image_override: None,
            supervisor_path_override: None,
        }
    }

    /// Override the default vCPU / RAM pair.
    pub fn with_resources(mut self, vcpus: u8, memory_mib: u32) -> Self {
        self.vcpus = vcpus;
        self.memory_mib = memory_mib;
        self
    }

    /// Override the default `/nix-store` image cap.
    pub fn with_nix_store_mib(mut self, mib: u32) -> Self {
        self.nix_store_mib = mib;
        self
    }

    /// Boot from a caller-supplied kernel/rootfs/cmdline instead of
    /// resolving the builder VM image from
    /// `~/.cache/mvm/builder-vm/<arch>/`. The Vz path only supports
    /// [`BuilderVmImage::Rootfs`]; [`Self::run_build`] returns an
    /// `ExtractionFailed` error if the override is a `RootDir`
    /// variant (Vz has no `krun_set_root` analog).
    pub fn with_image_override(mut self, image: BuilderVmImage) -> Self {
        self.image_override = Some(image);
        self
    }

    /// Override the supervisor binary path. Mostly for tests; the
    /// production path uses [`resolve_vz_supervisor_path`].
    pub fn with_supervisor_path_override(mut self, path: PathBuf) -> Self {
        self.supervisor_path_override = Some(path);
        self
    }

    /// Mirror of [`crate::libkrun_builder::LibkrunBuilderVm::validate_mounts`].
    /// Same shape — the validation is hypervisor-agnostic so we
    /// reuse the wording but keep the function private so each
    /// backend can evolve its own surface (e.g. Vz refusing a
    /// `host_nix_store` field that we never consume).
    fn validate_mounts(&self, mounts: &BuilderMounts) -> Result<(), BuilderVmError> {
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

    /// Same shape as
    /// [`crate::libkrun_builder::LibkrunBuilderVm::validate_job`].
    fn validate_job(&self, job: &BuilderJob) -> Result<(), BuilderVmError> {
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
}

impl BuilderVm for VzBuilderVm {
    fn run_build(
        &self,
        job: &BuilderJob,
        mounts: &BuilderMounts,
    ) -> Result<BuilderArtifacts, BuilderVmError> {
        // 1. Caller-supplied input validation — same shape as
        //    LibkrunBuilderVm. Surfacing this here keeps the error
        //    pinned to the offending field rather than failing
        //    inside the Vz supervisor.
        self.validate_mounts(mounts)?;
        self.validate_job(job)?;

        // 2. Refuse on a host without Vz. The runtime detector
        //    (`mvm_core::platform`) honestly reports `false` on
        //    Linux / Windows / pre-macOS-13. The seam impl checks
        //    this again, but we fail fast here for clearer errors.
        if !mvm_core::platform::current().has_vz() {
            return Err(BuilderVmError::ExtractionFailed(
                "Apple Virtualization.framework is not available on this host. \
                 Requires macOS 13 or later (Plan 97 §\"Minimum macOS version\")."
                    .to_string(),
            ));
        }

        // 3. Resolve the supervisor binary up front so a missing
        //    binary surfaces here, not after kernel / image / lock
        //    resolution does I/O.
        let supervisor_path = match &self.supervisor_path_override {
            Some(p) => p.clone(),
            None => resolve_vz_supervisor_path()?,
        };

        // 4. Find or initialise the builder VM image. The Vz path
        //    reuses the same image cache layout as libkrun — the
        //    kernel + rootfs are hypervisor-agnostic (booted via
        //    direct-kernel VZLinuxBootLoader / libkrun's KrunContext
        //    respectively). Vz refuses [`BuilderVmImage::RootDir`]:
        //    that variant boots via `krun_set_root` and has no Vz
        //    analog.
        let image = match &self.image_override {
            Some(image) => image.clone(),
            None => ensure_builder_vm_image()?,
        };
        if let BuilderVmImage::RootDir { .. } = image {
            return Err(BuilderVmError::ExtractionFailed(
                "VzBuilderVm requires a Rootfs builder image; RootDir is libkrun-specific \
                 (krun_set_root has no Vz analog)"
                    .to_string(),
            ));
        }

        // 5. Allocate / locate the persistent `/nix-store` image,
        //    holding the cross-process flock for the whole VM
        //    lifetime. Shared cache layout with libkrun — both
        //    backends key on the same `<cache>/nix-store-<arch>.img`
        //    so a warm store survives across backend switches.
        let nix_store_lock = acquire_nix_store_image_lock(
            &builder_vm_cache_dir(),
            host_arch_tag(),
            u64::from(self.nix_store_mib),
        )?;

        // 6. Stage the per-build job dir under the shared cache
        //    root. Same convention as the libkrun side; both
        //    backends pass `/job` as a virtio-fs share so the
        //    in-guest `mvm-host-vm-init` finds cmd.sh /
        //    install_spec.json regardless of which hypervisor
        //    booted it.
        let job_id = unique_job_id();
        let job_dir = builder_vm_cache_dir().join("jobs").join(&job_id);
        stage_job_dir(
            &job_dir,
            job,
            mounts.staged_user_flake.as_deref(),
            // Override mode mounts the workspace at /work as `flake_src`;
            // stage its filtered cargo tree for the `mvm/mvm-workspace` pin.
            mounts
                .staged_user_flake
                .as_ref()
                .map(|_| mounts.flake_src.as_path()),
        )?;
        tracing::info!(
            job_dir = %job_dir.display(),
            "Vz builder VM job dir staged (nix-stderr.log streams here as the build runs)"
        );

        // 7. Per-VM state directory under the shared cache root.
        //    Naming: `mvm-builder-vz-<job_id>` so concurrent
        //    libkrun + Vz runs on the same host don't collide
        //    (libkrun uses `mvm-builder-vm-<job_id>`).
        let vm_name = format!("mvm-builder-vz-{job_id}");
        let vm_state_dir = builder_vm_cache_dir().join("vms").join(&vm_name);
        std::fs::create_dir_all(&vm_state_dir).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating Vz builder VM state dir {}: {e}",
                vm_state_dir.display()
            ))
        })?;

        // 7b. Spawn host-side gvproxy so the builder VM has egress for a
        //     cold `nix build` (fetching nixpkgs). The guard stops it on
        //     every exit path below — including the timeout/error arms —
        //     so a failed build doesn't leak the daemon.
        let gvproxy = host_gvproxy::spawn_detached(&vm_state_dir).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!("spawn gvproxy for Vz builder VM: {e}"))
        })?;
        let _gvproxy_guard = BuilderGvproxyGuard {
            state_dir: vm_state_dir.clone(),
        };

        // 8. Hand the resolved supervisor + image to the seam.
        //    Construction enforces the Rootfs-only invariant a
        //    second time (defense in depth — we already checked
        //    above).
        let backend = VzBuilderBackend::new_with_rootfs_image(supervisor_path, image.clone())?;

        // 9. Build the hypervisor-agnostic run config. Kernel +
        //    cmdline come from the resolved image; the seam impl
        //    threads them onto the Swift supervisor's
        //    `KernelConfig`. `vsock_ports` is empty for one-shot
        //    flake / install jobs (the guest communicates results
        //    via the `/job` virtio-fs share, not vsock); the
        //    dispatch port is a persistent-VM concern
        //    that lives on the long-lived `LibkrunPersistentHostVm`
        //    path and doesn't apply here.
        let (kernel_path, kernel_cmdline) = match &image {
            BuilderVmImage::Rootfs {
                kernel_path,
                cmdline,
                ..
            } => (kernel_path.clone(), cmdline.clone()),
            // Unreachable per the earlier check.
            BuilderVmImage::RootDir { .. } => unreachable!(),
        };
        let run_config = BuilderVmRunConfig {
            name: vm_name.clone(),
            kernel_path,
            kernel_cmdline,
            initrd_path: None,
            vcpus: self.vcpus,
            memory_mib: self.memory_mib,
            vsock_ports: Vec::new(),
            vm_state_dir: vm_state_dir.clone(),
        };

        // 10. Mount layout matches what `mvm-host-vm-init` /
        //     `cmd.sh` expect:
        //     - `/work` (flake source) is read-only — the in-guest
        //       script uses `--no-write-lock-file` to avoid EROFS.
        //     - `/out` (artifacts) is read-write — kernel + rootfs
        //       land here.
        //     - `/job` is read-write — the guest writes
        //       `nix-stderr.log`, `nix-stdout.log`, `result`, and
        //       `store-path` here for the host-side finalize step.
        let virtio_mounts = vec![
            BuilderVmMount {
                tag: "work".to_string(),
                host_path: mounts.flake_src.clone(),
                read_only: true,
            },
            BuilderVmMount {
                tag: "out".to_string(),
                host_path: mounts.artifact_out.clone(),
                read_only: false,
            },
            BuilderVmMount {
                tag: "job".to_string(),
                host_path: job_dir.clone(),
                read_only: false,
            },
            // Mount the extracted host-vm binaries at /mvm-bins inside
            // the builder VM (read-only). The cmd.sh
            // sees MVM_HOST_BIN_DIR=/mvm-bins so the flake can reference
            // the correct pre-compiled binaries.
            BuilderVmMount {
                tag: "mvm-bins".to_string(),
                host_path: mounts.host_bin_dir.clone(),
                read_only: true,
            },
        ];

        // 11. The persistent `/nix-store` image rides as the second
        //     virtio-blk device (the rootfs is the first). The
        //     in-guest `mvm-host-vm-init` mounts it at `/nix-store`
        //     before invoking cmd.sh.
        let extra_disks = vec![BuilderVmDisk {
            id: "nix-store".to_string(),
            host_path: nix_store_lock.path().to_path_buf(),
            read_only: false,
        }];

        // 12. Wall-clock timeout — same env-var-overridable budget
        //     both backends share. The seam kills the supervisor on
        //     timeout and surfaces the elapsed budget in the error.
        let timeout = builder_vm_timeout()?;

        // 13. Hand off to the seam. The backend spawns the
        //     `mvm-vz-supervisor`, pipes the JSON config to stdin,
        //     and blocks until the supervisor exits.
        let exit_info = backend.run_attached_with_mounts_gvproxy(
            &run_config,
            &virtio_mounts,
            &extra_disks,
            timeout,
            Some(&gvproxy),
        )?;

        // 14. Branch on the exit info. The Vz supervisor exits 0
        //     for clean guest power-off, 1 for guest error, 2 for
        //     config parse error, 3 for supervisor startup error
        //     (per the supervisor's `main.swift` contract). Anything
        //     non-zero is fatal; the panic_line arm is defensive —
        //     today the Vz seam never sets it because the supervisor
        //     exits cleanly even on guest kernel panic, but if a
        //     future iteration starts emitting it we want a clean
        //     surface rather than the supervisor exit branch
        //     swallowing the diagnostic.
        if let Some(panic_line) = exit_info.panic_line {
            return Err(BuilderVmError::SeedKernelPanic {
                panic_line,
                console_log_path: backend
                    .console_log_path(&vm_state_dir)
                    .display()
                    .to_string(),
            });
        }
        match exit_info.exit_code {
            Some(0) => {}
            Some(other) => {
                return Err(supervisor_exit_error(other, &vm_state_dir));
            }
            None => {
                return Err(BuilderVmError::NixBuildFailed(format!(
                    "Vz supervisor exited without a status code. \
                     Console log at {}.",
                    backend.console_log_path(&vm_state_dir).display(),
                )));
            }
        }

        // 15. Per-variant finalize. `finalize_flake_job` reads
        //     `<job_dir>/result` + validates rootfs / kernel landed
        //     in `artifact_out`; `finalize_install_job` reads
        //     `<artifact_out>/result.json` + validates the sealed
        //     volume sidecars. Both functions live in
        //     `builder_vm_runtime` so the Vz path reuses the
        //     libkrun-equivalent finalize logic verbatim.
        let artifacts = match job {
            BuilderJob::Flake { .. } => finalize_flake_job(&job_dir, &mounts.artifact_out, &job_id),
            BuilderJob::Install { .. } => finalize_install_job(&mounts.artifact_out),
        }?;

        // 16. Drop the lock now that artifact reads are done so a
        //     subsequent build on the same host can proceed.
        drop(nix_store_lock);
        Ok(artifacts)
    }

    fn cleanup(&self) -> Result<(), BuilderVmError> {
        // Stateless cleanup today. Prune of stale job dirs lives in
        // the shared `mvmctl cache prune` path, which already
        // handles the libkrun + Vz convention together (both
        // backends share `~/.cache/mvm/builder-vm/jobs/`).
        Ok(())
    }
}

/// Resolve the absolute path to the `mvm-vz-supervisor` binary.
///
/// Mirrors `mvm_backend::vz::resolve_supervisor_path` (which is
/// private to that crate) in the four lookup sources it consults:
///
/// 1. `MVM_VZ_SUPERVISOR_PATH` — explicit override for tests +
///    `cargo run` workflows. If set but pointing at a non-file,
///    fails loudly so a typo doesn't fall through to the other
///    sources.
/// 2. A binary named `mvm-vz-supervisor` adjacent to the current
///    exe — the layout produced by `cargo install` + Homebrew
///    bottles that ship `mvmctl` alongside it.
/// 3. The source-checkout build output via
///    [`crate::vz::source_tree_binary_path`] — CLAUDE.md "Source-checkout
///    builds never depend on mvm-published artifacts".
/// 4. The version-pinned release layout
///    `~/.mvm/bin/mvm-vz-supervisor-<version>` via
///    [`crate::vz::supervisor_binary_path`].
///
/// Returned errors are
/// `BuilderVmError::ExtractionFailed` rather than a Vz-specific
/// variant; the supervisor-missing case is just an environment-gap
/// the operator needs to install around, not a hypervisor failure
/// per se.
pub fn resolve_vz_supervisor_path() -> Result<PathBuf, BuilderVmError> {
    if let Some(p) = std::env::var_os("MVM_VZ_SUPERVISOR_PATH") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Ok(path);
        }
        return Err(BuilderVmError::ExtractionFailed(format!(
            "MVM_VZ_SUPERVISOR_PATH points at {} which is not a file",
            path.display()
        )));
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join("mvm-vz-supervisor");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    if let Some(workspace_root) = workspace_root_from_manifest_dir() {
        let candidate = crate::vz::source_tree_binary_path(&workspace_root);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        let candidate =
            crate::vz::supervisor_binary_path(Path::new(&home), env!("CARGO_PKG_VERSION"));
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(BuilderVmError::ExtractionFailed(format!(
        "mvm-vz-supervisor binary not found. Looked for: \
         $MVM_VZ_SUPERVISOR_PATH, alongside the current exe, \
         <workspace>/target/debug/mvm-vz-supervisor (source-checkout), and \
         ~/.mvm/bin/mvm-vz-supervisor-{} (release-installed). Build it with \
         `cargo build -p mvm-vm-host --bin mvm-vz-supervisor`.",
        env!("CARGO_PKG_VERSION")
    )))
}

/// Compute the workspace root from `CARGO_MANIFEST_DIR` so a
/// `cargo run` from anywhere in the workspace can find the
/// source-checkout supervisor. Returns `None` when the manifest
/// isn't laid out as `<root>/crates/<name>/Cargo.toml` (e.g. a
/// flattened build or a vendored layout).
fn workspace_root_from_manifest_dir() -> Option<PathBuf> {
    workspace_root_from_crate_manifest_dir(Path::new(env!("CARGO_MANIFEST_DIR")))
}

fn workspace_root_from_crate_manifest_dir(manifest_dir: &Path) -> Option<PathBuf> {
    // <root>/crates/mvm-build → two `..` is <root>.
    let crates_dir = manifest_dir.parent()?;
    let workspace_root = crates_dir.parent()?;
    Some(workspace_root.to_path_buf())
}

// ──────────────────────────────────────────────────────────────────
// VzPersistentBuilderVm
// ──────────────────────────────────────────────────────────────────
//
// Parallel of [`crate::libkrun_builder::LibkrunPersistentHostVm`]. Same
// dispatch-loop semantics (vsock-framed `HostVmRequest::Run` from the
// host-side [`crate::persistent_builder::PersistentBuilderSupervisor`]
// → in-guest `mvm-host-vm-init` runs cmd.sh / install_spec.json →
// `HostVmResponse::Result` back over the same vsock), only the host
// VMM differs. The drivers are kept parallel rather than collapsed
// behind a trait — mirrors the one-shot pattern.
//
// State-dir layout is shared with libkrun under
// `~/.cache/mvm/builder-vm/vms/`, distinguished by name prefix
// (`mvm-persistent-builder-vm-*` for libkrun, `mvm-persistent-builder-vz-*`
// for Vz). The Stage 0 reaper is prefix-agnostic so both backends
// participate in cleanup without code changes.

/// Persistent-VM parallel of [`VzBuilderVm`]. Boots a long-lived
/// builder guest and returns a handle pointing at the dispatch
/// socket — used by `mvmctl dev up` to keep a warm-pool VM alive
/// across multiple `mvmctl build` / `mvmctl up --prod` invocations.
///
/// The supervisor / vsock dispatch protocol is identical to libkrun's
/// (`crate::builder_protocol` wire types); only the host VMM and
/// supervisor binary differ.
#[derive(Debug, Clone)]
pub struct VzPersistentBuilderVm {
    vcpus: u8,
    memory_mib: u32,
    nix_store_mib: u32,
    image_override: Option<BuilderVmImage>,
    supervisor_path_override: Option<PathBuf>,
    /// Host directory bound at `/work` in the guest. Bound at VM
    /// start, not per-dispatch.
    workspace_root: PathBuf,
    /// Caller-chosen session id. `None` mints a random one per start
    /// (the warm-pool default). A stable id gives a stable state dir
    /// so a *separate* process — `mvmctl dev down` — can find the PID
    /// file and reap the supervisor without holding the in-memory
    /// handle.
    session_id: Option<String>,
    /// Also open the guest-agent vsock port (5252) alongside the
    /// builder-dispatch port. The warm-pool path only needs dispatch;
    /// the long-lived dev VM additionally serves `mvmctl dev shell` /
    /// `console` / `status` over the guest agent.
    expose_guest_agent: bool,
}

impl VzPersistentBuilderVm {
    /// Construct a persistent Vz builder rooted at `workspace_root`.
    /// Defaults match the one-shot [`VzBuilderVm`] (which itself
    /// inherits libkrun's defaults) so resource ceilings stay
    /// parallel across backends.
    pub fn new(workspace_root: impl Into<PathBuf>) -> Self {
        Self {
            vcpus: VZ_BUILDER_DEFAULT_VCPUS,
            memory_mib: VZ_BUILDER_DEFAULT_MEMORY_MIB,
            nix_store_mib: VZ_BUILDER_DEFAULT_NIX_STORE_MIB,
            image_override: None,
            supervisor_path_override: None,
            workspace_root: workspace_root.into(),
            session_id: None,
            expose_guest_agent: false,
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

    pub fn with_supervisor_path_override(mut self, path: PathBuf) -> Self {
        self.supervisor_path_override = Some(path);
        self
    }

    /// Pin the session id so the per-VM state dir is stable across
    /// processes. Callers that need cross-process reap (the dev VM)
    /// pass a fixed value; everything else lets `start` mint a random
    /// one. The id flows straight into the `mvm-persistent-builder-vz-<id>`
    /// state-dir name — keep it filesystem-safe.
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Open the guest-agent vsock port (5252) in addition to the
    /// builder-dispatch port, so the guest agent is reachable for
    /// interactive `dev shell` / `console` / `status`.
    pub fn with_guest_agent_port(mut self, expose: bool) -> Self {
        self.expose_guest_agent = expose;
        self
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    /// Spawn the `mvm-vz-supervisor` and Vz guest in the background.
    /// Returns once the supervisor process is launched (the guest may
    /// still be booting); the caller observes guest-side readiness
    /// through the dispatch socket that
    /// [`VzPersistentVmHandle::dispatch_socket_path`] points at.
    ///
    /// Layered like `LibkrunPersistentHostVm::start`:
    /// pre-flight checks (Vz available, workspace dir exists,
    /// supervisor binary resolvable) → image + nix-store lock
    /// acquisition → state dir + job dir staging →
    /// `crate::vz::SupervisorConfig` build → `mvm-vz-supervisor` spawn.
    /// The nix-store flock is held inside the returned handle for
    /// the VM's lifetime so a concurrent `mvmctl up --prod` Install
    /// dispatch on the same host can't corrupt the shared ext4.
    pub fn start(&self) -> Result<VzPersistentVmHandle, BuilderVmError> {
        if !mvm_core::platform::current().has_vz() {
            return Err(BuilderVmError::ExtractionFailed(
                "Apple Virtualization.framework is not available on this host. \
                 Requires macOS 13 or later (Plan 97 §\"Minimum macOS version\")."
                    .to_string(),
            ));
        }

        if !self.workspace_root.is_dir() {
            return Err(BuilderVmError::ExtractionFailed(format!(
                "workspace_root {} is not a directory",
                self.workspace_root.display()
            )));
        }

        let supervisor_path = match &self.supervisor_path_override {
            Some(p) => p.clone(),
            None => resolve_vz_supervisor_path()?,
        };

        let image = match &self.image_override {
            Some(image) => image.clone(),
            None => ensure_builder_vm_image()?,
        };
        if let BuilderVmImage::RootDir { .. } = image {
            return Err(BuilderVmError::ExtractionFailed(
                "VzPersistentBuilderVm requires a Rootfs builder image; RootDir is libkrun-specific \
                 (krun_set_root has no Vz analog)"
                    .to_string(),
            ));
        }

        // Acquire the cross-process flock on the nix-store image for
        // the persistent VM's lifetime. Same key libkrun uses
        // (`<cache>/nix-store-<arch>.img`) so a warm store survives
        // across backend switches.
        let nix_store_lock = acquire_nix_store_image_lock(
            &builder_vm_cache_dir(),
            host_arch_tag(),
            u64::from(self.nix_store_mib),
        )?;

        let session_id = self.session_id.clone().unwrap_or_else(unique_job_id);
        let job_dir = builder_vm_cache_dir().join("jobs").join(&session_id);
        stage_persistent_vz_job_dir(&job_dir)?;

        // Name-prefix isolation under the shared cache root.
        // libkrun uses `mvm-persistent-builder-vm-{session}`; Vz uses
        // `mvm-persistent-builder-vz-{session}`. The Stage 0 reaper is
        // prefix-agnostic so both participate in cleanup without code changes.
        let vm_name = format!("mvm-persistent-builder-vz-{session_id}");
        let vm_state_dir = builder_vm_cache_dir().join("vms").join(&vm_name);
        std::fs::create_dir_all(&vm_state_dir).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "creating Vz persistent builder VM state dir {}: {e}",
                vm_state_dir.display()
            ))
        })?;

        // Spawn host-side gvproxy so the long-lived dev VM has egress
        // (a cold `nix build` from `dev shell` fetches nixpkgs). The
        // guard reaps it if any fallible step below (config build,
        // supervisor spawn) returns early; on success we `defuse()` so
        // the detached gvproxy outlives the CLI — it's reaped later,
        // cross-process, by `stop_persistent_vz_by_pid_file`.
        let gvproxy = host_gvproxy::spawn_detached(&vm_state_dir).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "spawn gvproxy for Vz persistent builder VM: {e}"
            ))
        })?;
        let gvproxy_guard = BuilderGvproxyGuard {
            state_dir: vm_state_dir.clone(),
        };

        let cfg = build_vz_persistent_supervisor_config(VzPersistentConfigParams {
            vm_name: &vm_name,
            vm_state_dir: &vm_state_dir,
            image: &image,
            workspace_root: &self.workspace_root,
            job_dir: &job_dir,
            nix_store_img: nix_store_lock.path(),
            vcpus: self.vcpus,
            memory_mib: self.memory_mib,
            expose_guest_agent: self.expose_guest_agent,
            gvproxy: Some(&gvproxy),
        })?;

        let child = spawn_vz_supervisor_in_background(&supervisor_path, &cfg)?;

        // Supervisor is up; hand gvproxy's lifetime to the detached VM.
        gvproxy_guard.defuse();

        Ok(VzPersistentVmHandle {
            vm_state_dir,
            job_dir,
            session_id,
            supervisor: Some(child),
            _nix_store_lock: nix_store_lock,
        })
    }
}

/// Stage `<job_dir>/<DISPATCH_SOCK_MARKER>` so the in-guest
/// `mvm-host-vm-init` enters the dispatch loop instead of the
/// single-shot cmd.sh / install_spec flow. The marker body is
/// intentionally empty — its mere presence is the signal. Same shape
/// libkrun's `stage_persistent_job_dir` uses.
fn stage_persistent_vz_job_dir(job_dir: &Path) -> Result<(), BuilderVmError> {
    std::fs::create_dir_all(job_dir).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "creating Vz persistent job dir {}: {e}",
            job_dir.display()
        ))
    })?;
    let marker_path = job_dir.join(DISPATCH_SOCK_MARKER);
    std::fs::write(&marker_path, b"").map_err(|e| {
        BuilderVmError::ExtractionFailed(format!(
            "staging Vz dispatch marker {}: {e}",
            marker_path.display()
        ))
    })?;
    Ok(())
}

/// Inputs to [`build_vz_persistent_supervisor_config`]. A struct
/// rather than a long positional arg list — the fields carry distinct
/// borrow lifetimes and one optional toggle.
#[derive(Clone, Copy)]
struct VzPersistentConfigParams<'a> {
    vm_name: &'a str,
    vm_state_dir: &'a Path,
    image: &'a BuilderVmImage,
    workspace_root: &'a Path,
    job_dir: &'a Path,
    nix_store_img: &'a Path,
    vcpus: u8,
    memory_mib: u32,
    /// Open the guest-agent port (5252) alongside the dispatch port.
    expose_guest_agent: bool,
    /// Host-side gvproxy giving the VM egress. `None` keeps the VM
    /// offline (the cached-derivation path). A shared ref — `Copy`-safe.
    gvproxy: Option<&'a host_gvproxy::HostGvproxyInfo>,
}

/// Build a [`crate::vz::SupervisorConfig`] for the persistent VM.
/// Distinct from [`build_vz_supervisor_config`] because the
/// persistent path doesn't come through the
/// [`VmBackendForBuilder`] seam — `BuilderVmRunConfig` would force
/// a one-shot mounts/disks shape that doesn't carry the dispatch
/// port. Lifted out so unit tests can exercise the mapping without
/// spawning a supervisor.
fn build_vz_persistent_supervisor_config(
    params: VzPersistentConfigParams<'_>,
) -> Result<crate::vz::SupervisorConfig, BuilderVmError> {
    let VzPersistentConfigParams {
        vm_name,
        vm_state_dir,
        image,
        workspace_root,
        job_dir,
        nix_store_img,
        vcpus,
        memory_mib,
        expose_guest_agent,
        gvproxy,
    } = params;
    let BuilderVmImage::Rootfs {
        kernel_path,
        rootfs_path,
        cmdline,
    } = image
    else {
        return Err(BuilderVmError::ExtractionFailed(
            "VzPersistentBuilderVm reached config-build with non-Rootfs image".to_string(),
        ));
    };

    let kernel = path_to_string(kernel_path, "kernel_path")?;
    let rootfs = path_to_string(rootfs_path, "rootfs_path")?;
    let nix_store = path_to_string(nix_store_img, "nix_store_img")?;
    let work = path_to_string(workspace_root, "workspace_root")?;
    let job = path_to_string(job_dir, "job_dir")?;
    let state_dir = path_to_string(vm_state_dir, "vm_state_dir")?;
    let vsock_dir = vm_state_dir.join("vsock").to_string_lossy().into_owned();
    let console_log = vm_state_dir
        .join("console.log")
        .to_string_lossy()
        .into_owned();

    let effective_cmdline = if cmdline.is_empty() {
        DEFAULT_VZ_BUILDER_CMDLINE.to_string()
    } else {
        cmdline.clone()
    };

    Ok(crate::vz::SupervisorConfig {
        name: vm_name.to_string(),
        vm_state_dir: state_dir,
        pid_file_name: Some("builder.pid".to_string()),
        kernel: crate::vz::KernelConfig {
            path: kernel,
            cmdline: effective_cmdline,
            initrd_path: None,
        },
        resources: crate::vz::ResourceConfig {
            cpu_count: u32::from(vcpus),
            memory_mib: u64::from(memory_mib),
        },
        disks: vec![
            crate::vz::DiskConfig {
                id: "rootfs".to_string(),
                path: rootfs,
                read_only: true,
            },
            // `/nix-store` rides as the second virtio-blk; the
            // in-guest `mvm-host-vm-init` mounts it before invoking
            // cmd.sh. Same layout libkrun uses.
            crate::vz::DiskConfig {
                id: "nix-store".to_string(),
                path: nix_store,
                read_only: false,
            },
        ],
        virtio_fs: vec![
            // `/work` is the workspace bind. Bound at VM start, not
            // per-dispatch.
            crate::vz::VirtioFsShare {
                tag: "work".to_string(),
                host_path: work,
                // Builder writes into the workspace under
                // `result/` symlinks etc. Same RW posture libkrun
                // exposes for the persistent path.
                read_only: false,
            },
            // `/out` and `/job` both point at the per-VM job dir.
            // The in-guest `mvm-host-vm-init` reads cmd.sh /
            // install_spec.json from `/job`, writes artifacts to
            // `/out`. Two shares (same host path) match libkrun's
            // convention; the dispatch protocol assumes that
            // shape.
            crate::vz::VirtioFsShare {
                tag: "out".to_string(),
                host_path: job.clone(),
                read_only: false,
            },
            crate::vz::VirtioFsShare {
                tag: "job".to_string(),
                host_path: job,
                read_only: false,
            },
        ],
        vsock: crate::vz::VsockConfig {
            ports: {
                let mut ports = vec![mvm_guest::builder_agent::BUILDER_DISPATCH_PORT];
                // The long-lived dev VM additionally serves the guest
                // agent so `dev shell` / `console` / `status` can reach
                // it; the warm-pool builder leaves it closed.
                if expose_guest_agent {
                    ports.push(mvm_guest::vsock::GUEST_AGENT_PORT);
                }
                ports
            },
            socket_dir: vsock_dir,
            // The builder VM has no egress-substitution endpoint; no host-listen
            // ports.
            host_listen_ports: vec![],
        },
        console_output_path: Some(console_log),
        // Host-side gvproxy gives the long-lived dev VM egress (a cold
        // `nix build` from `dev shell` fetches nixpkgs). `None` keeps
        // the offline / cached-derivation path (the caller passes
        // `None` to opt out). The builder VM is a TRUSTED dev-tier build
        // VM, not a workload subject to the claim-10 gateway flow-audit,
        // so it gets plain gvproxy with no flow-audit drainer
        // (events_ingest_socket_path stays None).
        network: gvproxy.map(|g| crate::vz::NetworkConfig::Gvproxy {
            socket_path: g.socket_path.to_string_lossy().into_owned(),
            mac: host_gvproxy::derive_mac(vm_name),
            events_ingest_socket_path: None,
        }),
        balloon: None,
        control_socket_path: None,
        startup_mode: crate::vz::StartupMode::Boot,
        // Builder VMs are trusted dev-tier — no claim-10 flow audit.
        tenant_id: None,
        plan: None,
        bundle: None,
        audit_dir: None,
        gateway_audit_socket: None,
        signing_key_path: None,
    })
}

/// Spawn `mvm-vz-supervisor` in the background with the
/// `SupervisorConfig` JSON piped to its stdin. Same shape libkrun's
/// `spawn_supervisor_in_background` uses for the persistent VM;
/// returns the live `Child` so the caller can `wait()` or `kill()`.
fn spawn_vz_supervisor_in_background(
    supervisor_path: &Path,
    cfg: &crate::vz::SupervisorConfig,
) -> Result<Child, BuilderVmError> {
    let cfg_json = serde_json::to_string(cfg).map_err(|e| {
        BuilderVmError::ExtractionFailed(format!("serialising Vz SupervisorConfig: {e}"))
    })?;

    let mut child = Command::new(supervisor_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "spawning mvm-vz-supervisor at {}: {e}",
                supervisor_path.display()
            ))
        })?;

    {
        let stdin = child.stdin.as_mut().ok_or_else(|| {
            BuilderVmError::ExtractionFailed(
                "mvm-vz-supervisor child had no stdin handle".to_string(),
            )
        })?;
        stdin.write_all(cfg_json.as_bytes()).map_err(|e| {
            BuilderVmError::ExtractionFailed(format!(
                "writing SupervisorConfig JSON to mvm-vz-supervisor stdin: {e}"
            ))
        })?;
    }
    // Close stdin so the supervisor knows the config is complete.
    drop(child.stdin.take());

    Ok(child)
}

/// Handle to a live persistent Vz builder VM. Owns the supervisor
/// `Child` for its lifetime; dropping without [`Self::wait_for_shutdown`]
/// or [`Self::kill`] leaks the supervisor process. Same Drop posture
/// as libkrun's `PersistentVmHandle` — callers always reach one of the
/// two before dropping.
#[derive(Debug)]
pub struct VzPersistentVmHandle {
    vm_state_dir: PathBuf,
    job_dir: PathBuf,
    session_id: String,
    /// `None` after [`Self::wait_for_shutdown`] consumes it.
    supervisor: Option<Child>,
    /// Held to keep the cross-process flock on the shared nix-store
    /// image alive for the VM's lifetime. Underscore-prefixed
    /// because it's opaque to consumers — exists for its `Drop`
    /// side-effect.
    _nix_store_lock: NixStoreImageLock,
}

impl VzPersistentVmHandle {
    /// Per-VM state directory under
    /// `~/.cache/mvm/builder-vm/vms/mvm-persistent-builder-vz-<session>/`.
    /// Hosts the vsock socket dir, console log, PID file.
    pub fn vm_state_dir(&self) -> &Path {
        &self.vm_state_dir
    }

    /// Host-side path of the Vz-supervisor-managed Unix socket that
    /// proxies to AF_VSOCK
    /// [`mvm_guest::builder_agent::BUILDER_DISPATCH_PORT`] inside the
    /// guest. `PersistentBuilderSupervisor::new` takes this directly.
    pub fn dispatch_socket_path(&self) -> PathBuf {
        self.vm_state_dir
            .join("vsock")
            .join(mvm_core::config::vsock_socket_filename(
                mvm_guest::builder_agent::BUILDER_DISPATCH_PORT,
            ))
    }

    /// Directory the Vz supervisor exposes per-port vsock sockets in
    /// (`<vm_state_dir>/vsock/`). Pair with
    /// [`mvm_core::config::vsock_socket_filename`] to reach a specific
    /// port — the dev VM connects the guest agent here.
    pub fn vsock_dir(&self) -> PathBuf {
        self.vm_state_dir.join("vsock")
    }

    /// Per-VM job directory bound at `/job` (and `/out`) inside the
    /// guest. Hosts stage per-dispatch artifacts here before
    /// sending the matching `HostVmRequest::Run`.
    pub fn job_dir(&self) -> &Path {
        &self.job_dir
    }

    /// Opaque session identifier — useful for logging /
    /// observability. Stable for the VM's lifetime.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Block until the supervisor child exits. Normal way to reach
    /// this is the supervisor receiving `HostVmRequest::Shutdown`,
    /// the guest dispatch loop processing it + replying `Bye`, then
    /// `mvm-host-vm-init` calling `reboot(RB_POWER_OFF)`, then the
    /// Vz supervisor exiting `main`. Consumes the child; subsequent
    /// calls return [`BuilderVmError::ExtractionFailed`].
    pub fn wait_for_shutdown(mut self) -> Result<i32, BuilderVmError> {
        let mut child = self.supervisor.take().ok_or_else(|| {
            BuilderVmError::ExtractionFailed(
                "VzPersistentVmHandle::wait_for_shutdown called twice".to_string(),
            )
        })?;
        let status = child.wait().map_err(|e| {
            BuilderVmError::ExtractionFailed(format!("waiting on Vz persistent supervisor: {e}"))
        })?;
        Ok(status.code().unwrap_or(-1))
    }

    /// Forcibly terminate the supervisor child (SIGKILL via
    /// `Child::kill`). The VM goes down hard; in-flight builds are
    /// abandoned. Use only as a fallback after
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

/// PID-file name the persistent Vz supervisor writes inside its state
/// dir (mirrors the value passed in [`build_vz_persistent_supervisor_config`]).
const PERSISTENT_VZ_PID_FILE: &str = "builder.pid";

/// State dir for a [`VzPersistentBuilderVm`] booted with a known
/// `session_id`. Same layout `start` derives, lifted out so a separate
/// process (e.g. `mvmctl dev down`) can locate the VM without the
/// in-memory handle.
pub fn persistent_vz_state_dir(session_id: &str) -> PathBuf {
    builder_vm_cache_dir()
        .join("vms")
        .join(format!("mvm-persistent-builder-vz-{session_id}"))
}

/// Vsock socket dir for a persistent Vz VM started with `session_id`.
/// Pair with [`mvm_core::config::vsock_socket_filename`] to reach a
/// specific guest port.
pub fn persistent_vz_vsock_dir(session_id: &str) -> PathBuf {
    persistent_vz_state_dir(session_id).join("vsock")
}

/// Read the supervisor PID file under `state_dir` and SIGTERM the
/// process, escalating to SIGKILL after `PERSISTENT_VZ_STOP_TIMEOUT`.
/// Idempotent: a missing PID file or an already-dead process is a
/// clean no-op (the file is unlinked either way). Returns whether a
/// live supervisor was actually signalled. Mirrors the
/// `VzBackend::stop` reap ladder without depending on its private
/// helpers across the crate boundary.
pub fn stop_persistent_vz_by_pid_file(state_dir: &Path) -> bool {
    // Best-effort reap of the VM's host-side gvproxy. The supervisor
    // detaches it, so `dev down` owns its teardown. Idempotent (a
    // missing PID sidecar is a clean no-op), so it's safe even on the
    // early-return paths below.
    let _ = host_gvproxy::stop_by_pid_file(state_dir);

    let pid_path = state_dir.join(PERSISTENT_VZ_PID_FILE);
    let Some(pid) = read_pid_file(&pid_path) else {
        return false;
    };
    if !pid_alive(pid) {
        let _ = std::fs::remove_file(&pid_path);
        return false;
    }
    // SAFETY: pid was just probed alive; a SIGTERM that races a natural
    // exit returns ESRCH, which is benign.
    unsafe { libc::kill(pid, libc::SIGTERM) };
    let deadline = std::time::Instant::now() + PERSISTENT_VZ_STOP_TIMEOUT;
    while std::time::Instant::now() < deadline {
        if !pid_alive(pid) {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    if pid_alive(pid) {
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    let _ = std::fs::remove_file(&pid_path);
    true
}

/// Whether a persistent Vz VM's supervisor PID file points at a live
/// process. Cheap liveness probe for `dev status` / re-entrant
/// `dev up`.
pub fn persistent_vz_supervisor_alive(state_dir: &Path) -> bool {
    read_pid_file(&state_dir.join(PERSISTENT_VZ_PID_FILE)).is_some_and(pid_alive)
}

const PERSISTENT_VZ_STOP_TIMEOUT: Duration = Duration::from_secs(5);

fn read_pid_file(pid_path: &Path) -> Option<i32> {
    std::fs::read_to_string(pid_path)
        .ok()?
        .trim()
        .parse::<i32>()
        .ok()
}

fn pid_alive(pid: i32) -> bool {
    // kill(pid, 0) probes existence without delivering a signal.
    unsafe { libc::kill(pid, 0) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rootfs_image() -> BuilderVmImage {
        BuilderVmImage::Rootfs {
            kernel_path: PathBuf::from("/tmp/vmlinux"),
            rootfs_path: PathBuf::from("/tmp/rootfs.ext4"),
            cmdline: "console=hvc0 root=/dev/vda".to_string(),
        }
    }

    fn rundir_image() -> BuilderVmImage {
        BuilderVmImage::RootDir {
            root_dir: PathBuf::from("/tmp/root"),
            entry_path: "/init".to_string(),
        }
    }

    fn run_config() -> BuilderVmRunConfig {
        BuilderVmRunConfig {
            name: "builder-vz-test".to_string(),
            kernel_path: PathBuf::from("/tmp/unused-vmlinux"),
            kernel_cmdline: String::new(),
            initrd_path: None,
            vcpus: 4,
            memory_mib: 8192,
            vsock_ports: vec![5252, 5253],
            vm_state_dir: PathBuf::from("/tmp/mvm-test/builder-vz"),
        }
    }

    #[test]
    fn rejects_root_dir_image_at_construction() {
        let err = VzBuilderBackend::new_with_rootfs_image(
            PathBuf::from("/tmp/supervisor"),
            rundir_image(),
        )
        .expect_err("RootDir variant must be rejected");
        assert!(
            format!("{err}").contains("RootDir is libkrun-specific"),
            "got: {err}"
        );
    }

    #[test]
    fn console_log_lives_under_vm_state_dir() {
        let backend = VzBuilderBackend::new_with_rootfs_image(
            PathBuf::from("/tmp/supervisor"),
            rootfs_image(),
        )
        .expect("Rootfs accepted");
        let dir = PathBuf::from("/tmp/state/builder-vz-foo");
        let log = backend.console_log_path(&dir);
        assert_eq!(log, dir.join("console.log"));
        // Trait-object safety check — pins object-safety for the
        // future BuilderVmRuntime caller that holds `&dyn`.
        let _erased: &dyn VmBackendForBuilder = &backend;
    }

    #[test]
    fn build_supervisor_config_maps_run_config_fields() {
        let cfg = build_vz_supervisor_config(&run_config(), &rootfs_image(), &[], &[], None)
            .expect("build supervisor config");
        assert_eq!(cfg.name, "builder-vz-test");
        assert_eq!(cfg.resources.cpu_count, 4);
        assert_eq!(cfg.resources.memory_mib, 8192);
        assert_eq!(cfg.kernel.path, "/tmp/vmlinux");
        assert_eq!(cfg.kernel.cmdline, "console=hvc0 root=/dev/vda");
        assert_eq!(cfg.disks.len(), 1);
        assert_eq!(cfg.disks[0].id, "rootfs");
        assert!(cfg.disks[0].read_only, "rootfs always RO at boot");
        assert_eq!(cfg.vsock.ports, vec![5252, 5253]);
        assert!(cfg.console_output_path.is_some());
        // pid_file_name must be set so concurrent builder VMs don't
        // race on a shared PID file inside the state dir.
        assert_eq!(cfg.pid_file_name.as_deref(), Some("builder.pid"));
        // No gvproxy passed → offline / cached-build posture.
        assert!(cfg.network.is_none());
    }

    #[test]
    fn build_supervisor_config_wires_gvproxy_without_flow_audit() {
        // Passing a gvproxy info turns on virtio-net so a cold
        // `nix build` can fetch nixpkgs. The builder VM is a
        // TRUSTED dev-tier build VM (only egress is fetching nixpkgs),
        // NOT a claim-10 workload, so events_ingest_socket_path stays
        // None: plain gvproxy, no flow-audit drainer.
        let gvproxy = host_gvproxy::HostGvproxyInfo {
            socket_path: PathBuf::from("/tmp/mvm-test/builder-vz/gvproxy.sock"),
            pid: 4242,
        };
        let cfg =
            build_vz_supervisor_config(&run_config(), &rootfs_image(), &[], &[], Some(&gvproxy))
                .expect("build supervisor config");
        match cfg.network {
            Some(crate::vz::NetworkConfig::Gvproxy {
                socket_path,
                mac,
                events_ingest_socket_path,
            }) => {
                assert_eq!(socket_path, "/tmp/mvm-test/builder-vz/gvproxy.sock");
                assert_eq!(mac, host_gvproxy::derive_mac("builder-vz-test"));
                assert_eq!(
                    events_ingest_socket_path, None,
                    "trusted builder VM gets no flow-audit drainer"
                );
            }
            other => panic!("expected Gvproxy network, got {other:?}"),
        }
    }

    #[test]
    fn build_supervisor_config_falls_back_to_default_cmdline_when_image_cmdline_empty() {
        let image = BuilderVmImage::Rootfs {
            kernel_path: PathBuf::from("/tmp/vmlinux"),
            rootfs_path: PathBuf::from("/tmp/rootfs.ext4"),
            cmdline: String::new(),
        };
        let cfg = build_vz_supervisor_config(&run_config(), &image, &[], &[], None)
            .expect("build with empty");
        assert_eq!(cfg.kernel.cmdline, DEFAULT_VZ_BUILDER_CMDLINE);
        assert!(
            cfg.kernel.cmdline.contains("init=/init"),
            "default must wire builder VM init: {}",
            cfg.kernel.cmdline
        );
    }

    #[test]
    fn build_supervisor_config_threads_extra_disks_and_mounts() {
        let mounts = vec![
            BuilderVmMount {
                tag: "work".into(),
                host_path: PathBuf::from("/host/work"),
                read_only: true,
            },
            BuilderVmMount {
                tag: "out".into(),
                host_path: PathBuf::from("/host/out"),
                read_only: false,
            },
        ];
        let disks = vec![BuilderVmDisk {
            id: "nix-store".into(),
            host_path: PathBuf::from("/host/nix-store.img"),
            read_only: false,
        }];
        let cfg = build_vz_supervisor_config(&run_config(), &rootfs_image(), &mounts, &disks, None)
            .expect("build supervisor config");

        // Rootfs is disks[0]; nix-store rides as disks[1] with the
        // caller-supplied read_only flag.
        assert_eq!(cfg.disks.len(), 2);
        assert_eq!(cfg.disks[1].id, "nix-store");
        assert!(!cfg.disks[1].read_only);

        // virtio_fs preserves order + read_only — read-only by default
        // for /work and /job; /out is the only writable share.
        assert_eq!(cfg.virtio_fs.len(), 2);
        assert_eq!(cfg.virtio_fs[0].tag, "work");
        assert!(cfg.virtio_fs[0].read_only);
        assert_eq!(cfg.virtio_fs[1].tag, "out");
        assert!(!cfg.virtio_fs[1].read_only);
    }

    // ─────────────────────────────────────────────────────────────
    // VzBuilderVm driver tests — high-level driver
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn vz_builder_vm_defaults_match_libkrun_constants() {
        // Cross-backend parity check: a contributor reading either
        // driver's defaults sees the same VM shape. The constants
        // are deliberately equal, not coincidentally equal.
        let vm = VzBuilderVm::new();
        assert_eq!(vm.vcpus, crate::libkrun_builder::DEFAULT_VCPUS);
        assert_eq!(vm.memory_mib, crate::libkrun_builder::DEFAULT_MEMORY_MIB);
        assert_eq!(
            vm.nix_store_mib,
            crate::libkrun_builder::DEFAULT_NIX_STORE_MIB
        );
        assert!(vm.image_override.is_none());
        assert!(vm.supervisor_path_override.is_none());
    }

    #[test]
    fn vz_builder_vm_builder_methods_chain() {
        let custom = BuilderVmImage::Rootfs {
            kernel_path: PathBuf::from("/tmp/k"),
            rootfs_path: PathBuf::from("/tmp/r"),
            cmdline: "console=hvc0".into(),
        };
        let vm = VzBuilderVm::new()
            .with_resources(2, 1024)
            .with_nix_store_mib(4096)
            .with_image_override(custom.clone())
            .with_supervisor_path_override(PathBuf::from("/tmp/fake-supervisor"));
        assert_eq!(vm.vcpus, 2);
        assert_eq!(vm.memory_mib, 1024);
        assert_eq!(vm.nix_store_mib, 4096);
        assert!(vm.image_override.is_some());
        assert_eq!(
            vm.supervisor_path_override.as_deref(),
            Some(Path::new("/tmp/fake-supervisor"))
        );
    }

    #[test]
    fn vz_builder_vm_validate_mounts_rejects_missing_flake_src() {
        let scratch = tempfile::TempDir::new().unwrap();
        let host_bins = scratch.path().join("host-bins");
        std::fs::create_dir_all(&host_bins).unwrap();
        let mounts = BuilderMounts {
            flake_src: scratch.path().join("does-not-exist"),
            host_nix_store: None,
            artifact_out: scratch.path().join("out"),
            host_bin_dir: host_bins,
            staged_user_flake: None,
        };
        let err = VzBuilderVm::new().validate_mounts(&mounts).unwrap_err();
        assert!(
            matches!(err, BuilderVmError::ExtractionFailed(ref msg) if msg.contains("does not exist")),
            "got: {err:?}"
        );
    }

    #[test]
    fn vz_builder_vm_validate_mounts_rejects_flake_src_as_file() {
        let scratch = tempfile::TempDir::new().unwrap();
        let flake = scratch.path().join("flake-file");
        std::fs::write(&flake, b"not a dir").unwrap();
        let host_bins = scratch.path().join("host-bins");
        std::fs::create_dir_all(&host_bins).unwrap();
        let mounts = BuilderMounts {
            flake_src: flake,
            host_nix_store: None,
            artifact_out: scratch.path().join("out"),
            host_bin_dir: host_bins,
            staged_user_flake: None,
        };
        let err = VzBuilderVm::new().validate_mounts(&mounts).unwrap_err();
        assert!(
            matches!(err, BuilderVmError::ExtractionFailed(ref msg) if msg.contains("must be a directory")),
            "got: {err:?}"
        );
    }

    #[test]
    fn vz_builder_vm_validate_mounts_creates_artifact_out() {
        let scratch = tempfile::TempDir::new().unwrap();
        let flake = scratch.path().join("flake");
        std::fs::create_dir(&flake).unwrap();
        let artifact_out = scratch.path().join("nested").join("out");
        let host_bins = scratch.path().join("host-bins");
        std::fs::create_dir_all(&host_bins).unwrap();
        let mounts = BuilderMounts {
            flake_src: flake,
            host_nix_store: None,
            artifact_out: artifact_out.clone(),
            host_bin_dir: host_bins,
            staged_user_flake: None,
        };
        VzBuilderVm::new().validate_mounts(&mounts).unwrap();
        assert!(artifact_out.is_dir(), "artifact_out must be created");
    }

    #[test]
    fn vz_builder_vm_validate_job_rejects_empty_flake_ref() {
        let err = VzBuilderVm::new()
            .validate_job(&BuilderJob::Flake {
                flake_ref: "  ".into(),
                attr_path: "x".into(),
            })
            .unwrap_err();
        assert!(
            matches!(err, BuilderVmError::NixBuildFailed(ref msg) if msg.contains("flake_ref")),
            "got: {err:?}"
        );
    }

    #[test]
    fn vz_builder_vm_validate_job_rejects_empty_attr_path() {
        let err = VzBuilderVm::new()
            .validate_job(&BuilderJob::Flake {
                flake_ref: "path:/work".into(),
                attr_path: "".into(),
            })
            .unwrap_err();
        assert!(
            matches!(err, BuilderVmError::NixBuildFailed(ref msg) if msg.contains("attr_path")),
            "got: {err:?}"
        );
    }

    #[test]
    fn vz_builder_vm_validate_job_rejects_missing_install_spec() {
        let scratch = tempfile::TempDir::new().unwrap();
        let err = VzBuilderVm::new()
            .validate_job(&BuilderJob::Install {
                spec_path: scratch.path().join("missing-spec.json"),
            })
            .unwrap_err();
        assert!(
            matches!(err, BuilderVmError::ExtractionFailed(ref msg) if msg.contains("does not exist")),
            "got: {err:?}"
        );
    }

    #[test]
    fn vz_builder_vm_run_build_refuses_root_dir_image_override() {
        // The override path lets a caller hand us any BuilderVmImage
        // variant; the run pipeline must refuse RootDir before any
        // I/O happens since Vz has no krun_set_root analog.
        //
        // We can't reach the full pipeline on a Linux CI runner
        // (`has_vz()` returns false), so this test runs the pipeline
        // far enough to surface either the RootDir refusal (macOS)
        // or the has_vz refusal (non-macOS) — either is a valid
        // refusal. Pin both to guard against silent skips.
        let scratch = tempfile::TempDir::new().unwrap();
        let flake = scratch.path().join("flake");
        std::fs::create_dir(&flake).unwrap();
        let host_bins = scratch.path().join("host-bins");
        std::fs::create_dir_all(&host_bins).unwrap();
        let mounts = BuilderMounts {
            flake_src: flake,
            host_nix_store: None,
            artifact_out: scratch.path().join("out"),
            host_bin_dir: host_bins,
            staged_user_flake: None,
        };
        let job = BuilderJob::Flake {
            flake_ref: "path:.".into(),
            attr_path: "packages.x86_64-linux.default".into(),
        };
        let vm = VzBuilderVm::new()
            .with_supervisor_path_override(PathBuf::from("/dev/null"))
            .with_image_override(BuilderVmImage::RootDir {
                root_dir: PathBuf::from("/tmp/root"),
                entry_path: "/init".into(),
            });
        let err = vm.run_build(&job, &mounts).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("Apple Virtualization.framework is not available")
                || msg.contains("RootDir is libkrun-specific"),
            "expected has_vz or RootDir refusal, got: {msg}"
        );
    }

    #[test]
    fn vz_builder_vm_run_build_surfaces_environment_gaps_on_clean_input() {
        // Mirrors `libkrun_builder::tests::run_build_surfaces_environment_gaps_on_clean_input`
        // shape. Clean inputs hit one of these in order:
        //   - macOS / Vz unavailable     → ExtractionFailed
        //   - supervisor binary missing  → ExtractionFailed
        //   - builder image cache empty  → ExtractionFailed
        //   - supervisor exits non-zero  → NixBuildFailed
        //     (`supervisor_exit_error`; the libkrun builder image's
        //      kernel won't direct-boot under Vz, so on a fully-
        //      configured dev box we trip this branch instead)
        // Any of those is a valid pre-cutover state.
        let scratch = tempfile::TempDir::new().unwrap();
        let mut process_env = mvm_core::util::test_env::TestEnv::new();
        process_env.set("MVM_CACHE_DIR", scratch.path().join(".cache"));
        process_env.set("MVM_DATA_DIR", scratch.path().join(".mvm"));
        let flake = scratch.path().join("flake");
        std::fs::create_dir(&flake).unwrap();
        let host_bins = scratch.path().join("host-bins");
        std::fs::create_dir_all(&host_bins).unwrap();
        let mounts = BuilderMounts {
            flake_src: flake,
            host_nix_store: None,
            artifact_out: scratch.path().join("out"),
            host_bin_dir: host_bins,
            staged_user_flake: None,
        };
        let job = BuilderJob::Flake {
            flake_ref: "path:.".into(),
            attr_path: "packages.x86_64-linux.default".into(),
        };
        let err = VzBuilderVm::new().run_build(&job, &mounts).unwrap_err();
        assert!(
            matches!(
                err,
                BuilderVmError::ExtractionFailed(_) | BuilderVmError::NixBuildFailed(_)
            ),
            "unexpected error variant: {err:?}"
        );
    }

    fn with_supervisor_env<F: FnOnce() -> R, R>(value: Option<&Path>, f: F) -> R {
        // `TestEnv` serializes env-mutating tests behind a shared lock and
        // restores MVM_VZ_SUPERVISOR_PATH on drop (after `f` returns).
        let mut env = mvm_core::util::test_env::TestEnv::new();
        match value {
            Some(v) => env.set("MVM_VZ_SUPERVISOR_PATH", v),
            None => env.remove("MVM_VZ_SUPERVISOR_PATH"),
        }
        f()
    }

    #[test]
    fn resolve_vz_supervisor_path_honors_env_override_when_present() {
        // Hermetic: write a file to a TempDir, point the env at it,
        // assert resolution finds it. Avoids touching the operator's
        // real `~/.mvm/bin/` layout.
        let scratch = tempfile::TempDir::new().unwrap();
        let candidate = scratch.path().join("fake-vz-supervisor");
        std::fs::write(&candidate, b"fake").unwrap();

        with_supervisor_env(Some(&candidate), || {
            let resolved = resolve_vz_supervisor_path().expect("env override must resolve");
            assert_eq!(resolved, candidate);
        });
    }

    #[test]
    fn resolve_vz_supervisor_path_rejects_env_override_pointing_at_nonfile() {
        // A typo in `MVM_VZ_SUPERVISOR_PATH` should fail loudly
        // rather than fall through to PATH-style resolution and
        // pick up an unintended binary.
        let scratch = tempfile::TempDir::new().unwrap();
        let bogus = scratch.path().join("nonexistent-supervisor");

        with_supervisor_env(Some(&bogus), || {
            let err = resolve_vz_supervisor_path().expect_err("missing file must reject");
            assert!(format!("{err}").contains("not a file"), "got: {err:?}");
        });
    }

    #[test]
    fn workspace_root_from_manifest_dir_uses_compile_time_crate_layout() {
        let manifest_dir = Path::new("/tmp/ws/crates/mvm-build");
        let root = workspace_root_from_crate_manifest_dir(manifest_dir)
            .expect("crate-style manifest dir resolves");
        assert_eq!(root, PathBuf::from("/tmp/ws"));
    }

    #[test]
    fn build_supervisor_config_rejects_non_utf8_paths() {
        // Construct a non-UTF-8 PathBuf via OsStr. On macOS APFS this
        // is APFS-illegal but PathBuf still accepts it; the Vz
        // supervisor JSON shape requires UTF-8, so we must fail
        // closed before spawning.
        #[cfg(unix)]
        {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;
            let bad = PathBuf::from(OsStr::from_bytes(&[0xff, 0xfe, b'/', b'x']));
            let image = BuilderVmImage::Rootfs {
                kernel_path: bad,
                rootfs_path: PathBuf::from("/tmp/rootfs"),
                cmdline: "x".to_string(),
            };
            let err = build_vz_supervisor_config(&run_config(), &image, &[], &[], None)
                .expect_err("non-UTF-8 path must reject");
            assert!(format!("{err}").contains("not valid UTF-8"), "got: {err}");
        }
    }

    // ──────────────────────────────────────────────────────────────
    // VzPersistentBuilderVm
    // ──────────────────────────────────────────────────────────────

    fn persistent_workspace() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir for persistent workspace")
    }

    #[test]
    fn vz_persistent_defaults_match_vz_one_shot_constants() {
        let scratch = persistent_workspace();
        let vm = VzPersistentBuilderVm::new(scratch.path());
        assert_eq!(vm.vcpus, VZ_BUILDER_DEFAULT_VCPUS);
        assert_eq!(vm.memory_mib, VZ_BUILDER_DEFAULT_MEMORY_MIB);
        assert_eq!(vm.nix_store_mib, VZ_BUILDER_DEFAULT_NIX_STORE_MIB);
        assert!(vm.image_override.is_none());
        assert!(vm.supervisor_path_override.is_none());
        assert_eq!(vm.workspace_root(), scratch.path());
    }

    #[test]
    fn vz_persistent_builder_methods_chain() {
        let scratch = persistent_workspace();
        let vm = VzPersistentBuilderVm::new(scratch.path())
            .with_vcpus(2)
            .with_memory_mib(2048)
            .with_nix_store_mib(8192)
            .with_supervisor_path_override(PathBuf::from("/tmp/supervisor"));
        assert_eq!(vm.vcpus, 2);
        assert_eq!(vm.memory_mib, 2048);
        assert_eq!(vm.nix_store_mib, 8192);
        assert_eq!(
            vm.supervisor_path_override.as_deref(),
            Some(Path::new("/tmp/supervisor"))
        );
    }

    #[test]
    fn stage_persistent_vz_job_dir_writes_dispatch_marker() {
        let scratch = tempfile::tempdir().unwrap();
        let job_dir = scratch.path().join("job-xyz");
        stage_persistent_vz_job_dir(&job_dir).expect("staging succeeds");
        assert!(job_dir.is_dir(), "job dir created");
        let marker = job_dir.join(DISPATCH_SOCK_MARKER);
        assert!(marker.is_file(), "dispatch marker file exists");
        let body = std::fs::read(&marker).unwrap();
        assert!(
            body.is_empty(),
            "marker body is intentionally empty — its existence is the signal"
        );
    }

    #[test]
    fn build_vz_persistent_supervisor_config_rejects_root_dir_image() {
        let scratch = tempfile::tempdir().unwrap();
        let vm_state_dir = scratch
            .path()
            .join("vms")
            .join("mvm-persistent-builder-vz-abc");
        let workspace = scratch.path().join("work");
        let job_dir = scratch.path().join("job");
        let nix_store = scratch.path().join("nix-store.img");
        let err = build_vz_persistent_supervisor_config(VzPersistentConfigParams {
            vm_name: "mvm-persistent-builder-vz-abc",
            vm_state_dir: &vm_state_dir,
            image: &rundir_image(),
            workspace_root: &workspace,
            job_dir: &job_dir,
            nix_store_img: &nix_store,
            vcpus: VZ_BUILDER_DEFAULT_VCPUS,
            memory_mib: VZ_BUILDER_DEFAULT_MEMORY_MIB,
            expose_guest_agent: false,
            gvproxy: None,
        })
        .expect_err("non-Rootfs image must reject");
        assert!(format!("{err}").contains("non-Rootfs image"), "got: {err}");
    }

    #[test]
    fn build_vz_persistent_supervisor_config_assembles_expected_shape() {
        let scratch = tempfile::tempdir().unwrap();
        let vm_name = "mvm-persistent-builder-vz-test";
        let vm_state_dir = scratch.path().join("vms").join(vm_name);
        let workspace = scratch.path().join("work");
        let job_dir = scratch.path().join("job");
        let nix_store = scratch.path().join("nix-store.img");
        let cfg = build_vz_persistent_supervisor_config(VzPersistentConfigParams {
            vm_name,
            vm_state_dir: &vm_state_dir,
            image: &rootfs_image(),
            workspace_root: &workspace,
            job_dir: &job_dir,
            nix_store_img: &nix_store,
            vcpus: 4,
            memory_mib: 8192,
            expose_guest_agent: false,
            gvproxy: None,
        })
        .expect("config builds");

        assert_eq!(cfg.name, vm_name);
        assert_eq!(cfg.pid_file_name.as_deref(), Some("builder.pid"));
        assert_eq!(cfg.resources.cpu_count, 4);
        assert_eq!(cfg.resources.memory_mib, 8192);

        // Two disks: rootfs RO + nix-store RW.
        assert_eq!(cfg.disks.len(), 2);
        assert_eq!(cfg.disks[0].id, "rootfs");
        assert!(cfg.disks[0].read_only);
        assert_eq!(cfg.disks[1].id, "nix-store");
        assert!(!cfg.disks[1].read_only);

        // Three virtio-fs shares: work (RW), out (RW), job (RW) —
        // matches the libkrun convention the dispatch protocol
        // assumes.
        let tags: Vec<&str> = cfg.virtio_fs.iter().map(|m| m.tag.as_str()).collect();
        assert_eq!(tags, vec!["work", "out", "job"]);
        assert!(cfg.virtio_fs.iter().all(|m| !m.read_only));

        // Vsock carries the dispatch port; socket dir lives under
        // the per-VM state directory.
        assert_eq!(
            cfg.vsock.ports,
            vec![mvm_guest::builder_agent::BUILDER_DISPATCH_PORT]
        );
        assert!(cfg.vsock.socket_dir.ends_with("vsock"));

        // No gvproxy passed → VM stays offline (cached-derivation path).
        assert!(cfg.network.is_none());
        // Boot startup; persistent Vz doesn't yet restore from a saved
        // snapshot.
        assert!(matches!(cfg.startup_mode, crate::vz::StartupMode::Boot));
    }

    #[test]
    fn build_vz_persistent_supervisor_config_wires_gvproxy_when_present() {
        let scratch = tempfile::tempdir().unwrap();
        let vm_name = "mvm-persistent-builder-vz-net";
        let vm_state_dir = scratch.path().join("vms").join(vm_name);
        let gvproxy = host_gvproxy::HostGvproxyInfo {
            socket_path: scratch.path().join("gvproxy.sock"),
            pid: 4242,
        };
        let cfg = build_vz_persistent_supervisor_config(VzPersistentConfigParams {
            vm_name,
            vm_state_dir: &vm_state_dir,
            image: &rootfs_image(),
            workspace_root: &scratch.path().join("work"),
            job_dir: &scratch.path().join("job"),
            nix_store_img: &scratch.path().join("nix-store.img"),
            vcpus: 2,
            memory_mib: 1024,
            expose_guest_agent: false,
            gvproxy: Some(&gvproxy),
        })
        .expect("config builds");

        // gvproxy present → trusted-builder plain Gvproxy (no flow-audit
        // drainer), MAC derived from the VM name, socket pointed at the
        // spawned listener.
        match cfg.network.expect("network wired when gvproxy is present") {
            crate::vz::NetworkConfig::Gvproxy {
                socket_path,
                mac,
                events_ingest_socket_path,
            } => {
                assert_eq!(socket_path, gvproxy.socket_path.to_string_lossy());
                assert_eq!(mac, host_gvproxy::derive_mac(vm_name));
                assert!(
                    events_ingest_socket_path.is_none(),
                    "trusted dev-tier builder has no claim-10 flow-audit drainer"
                );
            }
        }
    }

    #[test]
    fn build_vz_persistent_supervisor_config_falls_back_to_default_cmdline_when_image_cmdline_empty()
     {
        let scratch = tempfile::tempdir().unwrap();
        let image = BuilderVmImage::Rootfs {
            kernel_path: PathBuf::from("/tmp/vmlinux"),
            rootfs_path: PathBuf::from("/tmp/rootfs.ext4"),
            cmdline: String::new(),
        };
        let cfg = build_vz_persistent_supervisor_config(VzPersistentConfigParams {
            vm_name: "vm",
            vm_state_dir: &scratch.path().join("state"),
            image: &image,
            workspace_root: &scratch.path().join("work"),
            job_dir: &scratch.path().join("job"),
            nix_store_img: &scratch.path().join("nix-store.img"),
            vcpus: 2,
            memory_mib: 1024,
            expose_guest_agent: false,
            gvproxy: None,
        })
        .expect("config builds");
        assert_eq!(cfg.kernel.cmdline, DEFAULT_VZ_BUILDER_CMDLINE);
    }

    #[test]
    fn build_vz_persistent_supervisor_config_console_path_under_state_dir() {
        let scratch = tempfile::tempdir().unwrap();
        let vm_state_dir = scratch
            .path()
            .join("vms")
            .join("mvm-persistent-builder-vz-abc");
        let cfg = build_vz_persistent_supervisor_config(VzPersistentConfigParams {
            vm_name: "mvm-persistent-builder-vz-abc",
            vm_state_dir: &vm_state_dir,
            image: &rootfs_image(),
            workspace_root: &scratch.path().join("work"),
            job_dir: &scratch.path().join("job"),
            nix_store_img: &scratch.path().join("nix-store.img"),
            vcpus: 2,
            memory_mib: 1024,
            expose_guest_agent: false,
            gvproxy: None,
        })
        .expect("config builds");
        let console = cfg.console_output_path.expect("console path set");
        assert!(
            console.starts_with(vm_state_dir.to_string_lossy().as_ref()),
            "console must live under vm_state_dir; got {console}"
        );
        assert!(console.ends_with("console.log"));
    }

    #[test]
    fn vz_persistent_supervisor_config_vsock_socket_dir_matches_handle_dispatch_path_shape() {
        // The `VzPersistentVmHandle::dispatch_socket_path()` method
        // and `build_vz_persistent_supervisor_config()`'s
        // `vsock.socket_dir` must agree on layout — the supervisor
        // creates sockets under `socket_dir`, the host-side dispatcher
        // dials `dispatch_socket_path()`. A divergence here means a
        // hung `mvmctl dev shell` in production. Assert the shape
        // matches without constructing a fake handle (NixStoreImageLock
        // has no public test constructor and a real lock acquires a
        // file lock we don't want in unit tests).
        let scratch = tempfile::tempdir().unwrap();
        let vm_state_dir = scratch
            .path()
            .join("vms")
            .join("mvm-persistent-builder-vz-test");
        let cfg = build_vz_persistent_supervisor_config(VzPersistentConfigParams {
            vm_name: "mvm-persistent-builder-vz-test",
            vm_state_dir: &vm_state_dir,
            image: &rootfs_image(),
            workspace_root: &scratch.path().join("work"),
            job_dir: &scratch.path().join("job"),
            nix_store_img: &scratch.path().join("nix-store.img"),
            vcpus: 2,
            memory_mib: 1024,
            expose_guest_agent: false,
            gvproxy: None,
        })
        .expect("config builds");
        let socket_dir = std::path::Path::new(&cfg.vsock.socket_dir);
        // The handle joins `vsock-<port>.sock` onto this dir; both
        // sides agree the supervisor places sockets here.
        assert_eq!(
            socket_dir,
            vm_state_dir.join("vsock"),
            "vsock socket_dir must equal <vm_state_dir>/vsock for handle.dispatch_socket_path() to find the socket"
        );
    }

    #[test]
    fn guest_agent_port_opens_only_when_requested() {
        let scratch = tempfile::tempdir().unwrap();
        let base = VzPersistentConfigParams {
            vm_name: "vm",
            vm_state_dir: &scratch.path().join("state"),
            image: &rootfs_image(),
            workspace_root: &scratch.path().join("work"),
            job_dir: &scratch.path().join("job"),
            nix_store_img: &scratch.path().join("nix-store.img"),
            vcpus: 2,
            memory_mib: 1024,
            expose_guest_agent: false,
            gvproxy: None,
        };
        let dispatch_only = build_vz_persistent_supervisor_config(VzPersistentConfigParams {
            expose_guest_agent: false,
            ..base
        })
        .expect("config builds");
        assert_eq!(
            dispatch_only.vsock.ports,
            vec![mvm_guest::builder_agent::BUILDER_DISPATCH_PORT]
        );

        let with_agent = build_vz_persistent_supervisor_config(VzPersistentConfigParams {
            expose_guest_agent: true,
            ..base
        })
        .expect("config builds");
        assert_eq!(
            with_agent.vsock.ports,
            vec![
                mvm_guest::builder_agent::BUILDER_DISPATCH_PORT,
                mvm_guest::vsock::GUEST_AGENT_PORT,
            ]
        );
    }

    #[test]
    fn persistent_vz_paths_derive_from_session_id() {
        let state = persistent_vz_state_dir("dev");
        assert!(state.ends_with("mvm-persistent-builder-vz-dev"));
        assert_eq!(persistent_vz_vsock_dir("dev"), state.join("vsock"));
    }

    #[test]
    fn stop_by_pid_file_is_noop_when_missing_or_dead() {
        let scratch = tempfile::tempdir().unwrap();
        // No PID file at all.
        assert!(!stop_persistent_vz_by_pid_file(scratch.path()));
        assert!(!persistent_vz_supervisor_alive(scratch.path()));

        // A PID file pointing at a definitely-dead process. PID 2^31-1
        // is outside any live range on the platforms we run on.
        std::fs::write(scratch.path().join(PERSISTENT_VZ_PID_FILE), "2147483647").unwrap();
        assert!(!stop_persistent_vz_by_pid_file(scratch.path()));
        // The stale file is unlinked on the dead-pid path.
        assert!(!scratch.path().join(PERSISTENT_VZ_PID_FILE).exists());
    }
}
