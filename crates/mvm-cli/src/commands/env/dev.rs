//! `mvmctl dev` — manage the development environment.
//!
//! Supported local development hosts:
//!
//! - **macOS Apple Silicon with libkrun** → boots the dev VM via
//!   libkrun on Hypervisor.framework and exposes a PTY-over-vsock
//!   console.
//! - **macOS 26+ Apple Silicon without libkrun** →
//!   `super::apple_container` boots a dev VM via Apple
//!   Virtualization.framework and exposes a PTY-over-vsock console.
//! - **native Linux + KVM** → `super::linux_native` treats the host shell as
//!   the dev environment, installs Firecracker + downloads kernel/
//!   rootfs assets, and optionally spawns an interactive subshell.
//!   This is the W8.C path — replaces the W7-deleted Lima
//!   `dev_up`/`dev_down`/`dev_status` helpers.
//!
//! macOS Intel, macOS pre-26, Linux without KVM, WSL2, and native
//! Windows bail with a clear unsupported-platform message. WSL2 with
//! nested KVM and a Hyper-V managed Linux builder are future backend
//! projects, not supported local paths today.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use crate::ui;

use crate::commands::shared::{
    clap_volume_spec, materialize_disk_volumes, merge_volume_specs, parse_volume_spec,
    vm_volume_from_spec_validated,
};
use mvm_backend::{LibkrunBackend, VzBackend};
use mvm_core::platform::{self, Platform};
use mvm_core::user_config::MvmConfig;
use mvm_core::vm_backend::{VmBackend, VmId, VmStartConfig, VmStatus, VmVolume};

use super::super::vm::console;
use super::Cli;
use super::apple_container;
use super::linux_native;

/// Which `mvmctl dev` backend the current host uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DevBackend {
    /// macOS with libkrun — Hypervisor.framework-backed dev VM.
    Libkrun,
    /// macOS 13+ with Apple Virtualization.framework — Vz-backed
    /// dev VM. Plan 98 Slice 2B: selected when the builder backend
    /// resolves to Vz (auto-detect on macOS 26+ Apple Silicon, or
    /// explicit override via `--builder vz` / `MVM_BUILDER_BACKEND=vz`)
    /// so the dev VM rides the same VMM as the build path.
    Vz,
    /// macOS 26+ Apple Silicon — Apple Container dev VM.
    AppleContainer,
    /// Native Linux with `/dev/kvm` — host shell is the dev environment;
    /// Firecracker runs natively.
    LinuxKvm,
    /// Neither path is wired today — macOS Intel, macOS pre-26,
    /// Linux without KVM, WSL2, and native Windows.
    Unsupported,
}

/// Which hypervisor currently owns the dev VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DevVmBackend {
    Libkrun,
    Vz,
}

impl DevVmBackend {
    fn name(self) -> &'static str {
        match self {
            Self::Libkrun => "libkrun",
            Self::Vz => "vz",
        }
    }
}

/// Pure platform-decision predicate. Lifted out of [`current_backend`]
/// so unit tests can exercise the dispatch without spoofing the live
/// platform / env / flag. The two callers (`current_backend` for the
/// real runtime; tests for hermetic coverage) agree on this single
/// source of truth.
///
/// Selection order:
///   1. Builder override prefers Vz **and** Vz is available → `Vz`.
///      Catches both `--builder vz` (folded into the env at startup by
///      `commands::run`) and a bare `MVM_BUILDER_BACKEND=vz`. Vz on
///      macOS 13-25 stays opt-in — auto-detect won't pick it because
///      the deployment baseline is macOS 26+.
///   2. Builder override *explicitly* prefers libkrun **and** libkrun
///      is available on macOS → `Libkrun`. The symmetric counterpart
///      to rule 1: an operator who asks for libkrun gets the dev VM on
///      libkrun even on a macOS 26+ box where Apple Container would
///      otherwise win rule 3.
///   3. macOS 26+ Apple Silicon with Apple Containers → AppleContainer.
///   4. macOS with libkrun → Libkrun (legacy fallback).
///   5. Linux with KVM → LinuxKvm.
///   6. Otherwise → Unsupported.
///
/// On the *auto-detect* path (no explicit override) Apple Container
/// still wins over Libkrun (rule 3 vs 4) per the CLAUDE.md "Dev mode"
/// rationale: AC is the documented Stage 0 boundary AND the build
/// boundary `RuntimeBuildEnv::shell_exec_visible` routes through.
/// Splitting the dev VM (Libkrun) from the build boundary
/// (`AppleContainerEnv`) would leave each under a runtime the other
/// never starts. An explicit `prefers_libkrun` is the one signal that
/// overrides this — because it also moves the build boundary onto
/// libkrun, keeping both halves on the same VMM.
fn select_dev_backend(
    plat: Platform,
    prefers_vz: bool,
    prefers_libkrun: bool,
    has_vz: bool,
    has_apple_containers: bool,
    has_libkrun: bool,
    has_kvm: bool,
) -> DevBackend {
    // 1. Builder override picked Vz AND Vz is actually usable.
    if prefers_vz && has_vz {
        return DevBackend::Vz;
    }
    // 2. Explicit libkrun override on macOS — run the dev VM on libkrun
    //    even where Apple Container would win auto-detect, so the dev VM
    //    rides the same VMM the build path uses. This is the path that's
    //    wired end-to-end today.
    if prefers_libkrun && has_libkrun && matches!(plat, Platform::MacOS) {
        return DevBackend::Libkrun;
    }
    // 3-6. Standard auto-detect tree.
    if has_apple_containers {
        DevBackend::AppleContainer
    } else if matches!(plat, Platform::MacOS) && has_libkrun {
        DevBackend::Libkrun
    } else if has_kvm && matches!(plat, Platform::LinuxNative) {
        DevBackend::LinuxKvm
    } else {
        DevBackend::Unsupported
    }
}

#[cfg(feature = "builder-vm")]
fn builder_prefers_vz() -> bool {
    use mvm_build::builder_backend_select::{BuilderBackendChoice, resolve_choice};

    matches!(resolve_choice(), BuilderBackendChoice::Vz)
}

#[cfg(not(feature = "builder-vm"))]
fn builder_prefers_vz() -> bool {
    false
}

// True only when the operator *explicitly* asked for libkrun: the
// `--builder libkrun` flag (folded into the env at startup) or a bare
// `MVM_BUILDER_BACKEND=libkrun`. We read the explicit env override here
// rather than `resolve_choice()` on purpose — libkrun is also the silent
// auto-detect fallback on every macOS box that isn't 26+ Apple Silicon,
// so keying off the resolved choice would drag all of them off the
// Apple Container default. Only an explicit ask should do that.
#[cfg(feature = "builder-vm")]
fn builder_prefers_libkrun() -> bool {
    use mvm_build::builder_backend_select::{BuilderBackendChoice, resolve_env_override};

    matches!(resolve_env_override(), Some(BuilderBackendChoice::Libkrun))
}

#[cfg(not(feature = "builder-vm"))]
fn builder_prefers_libkrun() -> bool {
    false
}

fn current_backend() -> DevBackend {
    let plat = platform::current();
    select_dev_backend(
        plat,
        builder_prefers_vz(),
        builder_prefers_libkrun(),
        plat.has_vz(),
        plat.has_apple_containers(),
        plat.has_libkrun(),
        plat.has_kvm(),
    )
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: Option<DevAction>,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum DevAction {
    /// Bootstrap and start the dev environment.
    Up {
        /// Number of vCPUs for the dev VM (Apple Container).
        #[arg(long, default_value = "8")]
        cpus: u32,
        /// Memory (GiB) for the dev VM (Apple Container).
        #[arg(long, default_value = "16")]
        memory: u32,
        /// Project directory to cd into inside the VM.
        #[arg(long)]
        project: Option<String>,
        /// Bind a Prometheus metrics endpoint on this port (0 = disabled).
        #[arg(long, default_value = "0")]
        metrics_port: u16,
        /// Reload ~/.mvm/config.toml automatically when it changes.
        #[arg(long)]
        watch_config: bool,
        /// Open an interactive shell after starting.
        ///
        /// Default behavior for `mvmctl dev up`; retained as an
        /// explicit spelling for compatibility.
        #[arg(long, short = 's', conflicts_with = "no_shell")]
        shell: bool,
        /// Start the dev VM without attaching an interactive shell.
        #[arg(long, conflicts_with = "shell")]
        no_shell: bool,
        /// Attach a custom volume (repeatable). Appends to `MVM_VOLUMES`.
        /// `host:/guest` shares a host dir (virtio-fs); `host:/guest:SIZE`
        /// attaches an ext4 disk image. Read-only by default — append
        /// `:rw` to grant writes. Guest path must be under /data, /work,
        /// or /mnt (system mounts stay read-only).
        #[arg(long, short = 'v', value_parser = clap_volume_spec)]
        volume: Vec<String>,
    },
    /// Stop the development VM.
    Down {
        /// Also delete the cached dev image (vmlinux + rootfs.ext4) so the
        /// next `dev up` rebuilds from local source.
        #[arg(long)]
        reset: bool,
    },
    /// Open a shell in the running dev VM.
    Shell {
        /// Project directory to cd into inside the VM.
        #[arg(long)]
        project: Option<String>,
    },
    /// Show dev environment status.
    Status,
    /// Inspect dev caches without rebuilding or booting.
    Cache {
        #[command(subcommand)]
        action: DevCacheAction,
    },
    /// Rebuild the dev environment (down + clear cache + up).
    Rebuild {
        /// Number of vCPUs for the dev VM (Apple Container).
        #[arg(long, default_value = "8")]
        cpus: u32,
        /// Memory (GiB) for the dev VM (Apple Container).
        #[arg(long, default_value = "16")]
        memory: u32,
        /// Open an interactive shell after rebuilding.
        #[arg(long, short = 's')]
        shell: bool,
        /// Attach a custom volume (repeatable). Appends to `MVM_VOLUMES`.
        /// See `mvmctl dev up --help` for the spec grammar.
        #[arg(long, short = 'v', value_parser = clap_volume_spec)]
        volume: Vec<String>,
    },
    /// Import a dev image from local files (air-gapped install).
    ///
    /// Plan 36 §"Air-gapped install path": runs the same cosign sig +
    /// SHA-256 + version-pin + max-age + revocation verification
    /// pipeline as the network path, against local files. On success
    /// the verified artifacts are deposited into the version-namespaced
    /// cache (`~/.cache/mvm/dev/prebuilt/v{version}/`) and the next
    /// `mvmctl dev up` boots from them without re-downloading.
    ///
    /// The trusted path for operators in regulated/gov/air-gapped
    /// environments. Without this, the only option to run an
    /// unreachable-network host was `MVM_SKIP_HASH_VERIFY=1`, which
    /// disables the supply-chain check entirely.
    ImportImage {
        /// Path to the cosign-signed manifest JSON
        /// (`dev-image-{arch}.manifest.json`).
        #[arg(long, value_name = "FILE")]
        manifest: String,
        /// Path to the manifest's cosign bundle
        /// (`dev-image-{arch}.manifest.json.bundle`).
        #[arg(long, value_name = "FILE")]
        bundle: String,
        /// Path to the kernel binary (`dev-vmlinux-{arch}`).
        #[arg(long, value_name = "FILE")]
        vmlinux: String,
        /// Path to the rootfs (`dev-rootfs-{arch}.ext4`).
        #[arg(long, value_name = "FILE")]
        rootfs: String,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum DevCacheAction {
    /// Show sanitized dev-cache readiness.
    Inspect {
        /// Emit structured JSON.
        #[arg(long)]
        json: bool,
    },
}

/// Error shown on hosts where `mvmctl dev` can't run today.
fn bail_no_dev_backend() -> Result<()> {
    anyhow::bail!(
        "`mvmctl dev` requires either:\n  \
           - macOS Apple Silicon with libkrun (Hypervisor.framework dev VM),\n  \
           - macOS 26+ Apple Silicon (Apple Container dev VM), or\n  \
           - native Linux with /dev/kvm (Firecracker runs on the host).\n\
         This host has neither. WSL2 with nested KVM and a Hyper-V \
         managed Linux builder are future backend work, not supported \
         local dev paths today. Run on an M-series Mac or a Linux KVM \
         host for the supported local workflow."
    );
}

/// Plan 98 §2.5 — cross-backend coexistence helpers.
///
/// Both `LibkrunBackend` and `VzBackend` boot a runtime VM named
/// `apple_container::DEV_VM_NAME` ("mvm-dev"). Their status probes
/// only see their *own* state — VzBackend's `status("mvm-dev")`
/// returns `Stopped` even if libkrun has a live VM by the same name.
/// Without an explicit cross-check, switching backends without `dev
/// down` would silently start a second dev VM under the new backend
/// while the old one keeps running.
///
/// The helpers below probe both backends and let `cmd_dev_*` refuse
/// the new boot when the other backend's dev VM is already alive.
/// `dev status` reports both sides; `dev down` is best-effort over
/// both so the user can switch backends cleanly without remembering
/// which one is up.
///
/// Returns `Some("libkrun"|"vz")` when the *other* backend's dev VM
/// is currently running, otherwise `None`. Errors propagated — a
/// status probe failure shouldn't be silently swallowed (it may
/// mean the backend is wedged, which is its own kind of "running").
fn other_backend_dev_vm_running(current: DevVmBackend) -> Result<Option<&'static str>> {
    let id = VmId(apple_container::DEV_VM_NAME.to_string());
    match current {
        DevVmBackend::Libkrun => {
            if matches!(
                VzBackend.status(&id)?,
                VmStatus::Running | VmStatus::Starting
            ) {
                Ok(Some("vz"))
            } else {
                Ok(None)
            }
        }
        DevVmBackend::Vz => {
            if matches!(
                LibkrunBackend.status(&id)?,
                VmStatus::Running | VmStatus::Starting
            ) {
                Ok(Some("libkrun"))
            } else {
                Ok(None)
            }
        }
    }
}

/// Pure: the info line to print when switching backends (None = stay quiet).
/// Lifted out for hermetic unit tests; the caller passes the probe result so
/// the test doesn't need to spoof the live host.
fn switch_notice(current: DevVmBackend, other_running: Option<&str>) -> Option<String> {
    other_running.map(|other| {
        format!(
            "Switching dev builder backend {other} → {}.",
            current.name()
        )
    })
}

/// Plan 98 §2.5 (revised) — when the *other* backend's `mvm-dev` is up, stop
/// it and take over instead of refusing. The dev VM is an ephemeral builder;
/// both backends share the `mvm-dev` name + dev network and so can't coexist,
/// making "switch" the only sensible outcome. Mirrors the best-effort
/// cross-stop already in `cmd_dev_*_down`.
fn take_over_from_other_backend(current: DevVmBackend) -> Result<()> {
    let probe = other_backend_dev_vm_running(current)?;
    if let Some(line) = switch_notice(current, probe) {
        ui::info(&line);
        let id = VmId(apple_container::DEV_VM_NAME.to_string());
        let stop = match current {
            DevVmBackend::Vz => LibkrunBackend.stop(&id),
            DevVmBackend::Libkrun => VzBackend.stop(&id),
        };
        if let Err(e) = stop {
            // Don't block the new boot on a stale-VM stop failure; surface it.
            ui::warn(&format!(
                "Could not stop the stale dev VM cleanly: {e}. Continuing."
            ));
        }
    }
    Ok(())
}

/// Resolve the dev VM's custom volumes: `MVM_VOLUMES` env baseline +
/// `--volume` flags, parsed and validated (reserved-mount + encryption
/// gates) into backend-agnostic [`VmVolume`]s. The dev VM is the
/// dev-tier builder (not the hardened workload tier), so these are a
/// host-side convenience — but the same path-safety validation still
/// applies (a stray `-v ~/.mvm/keys:/x` must not silently expose host
/// secrets to the builder).
fn resolve_dev_volumes(flag: &[String]) -> Result<Vec<VmVolume>> {
    let volumes: Vec<VmVolume> = merge_volume_specs(flag)
        .iter()
        .map(|v| {
            let spec = parse_volume_spec(v)?;
            vm_volume_from_spec_validated(&spec).map_err(|e| anyhow::anyhow!("volume '{v}': {e}"))
        })
        .collect::<Result<_>>()?;
    // Sparse-create any disk-image volumes so the hypervisor can attach
    // them (dir shares need nothing).
    materialize_disk_volumes(&volumes)?;
    Ok(volumes)
}

/// Custom dev volumes are wired for the libkrun + Vz dev VMs only. The
/// Apple Container and native-Linux dev paths don't thread them yet —
/// warn loudly rather than silently dropping the user's `-v` request.
fn warn_dev_volumes_unsupported(volumes: &[VmVolume], backend: &str) {
    if !volumes.is_empty() {
        ui::warn(&format!(
            "Ignoring {} custom volume(s): the {backend} dev backend doesn't support \
             --volume yet (libkrun and Vz do).",
            volumes.len()
        ));
    }
}

fn cmd_dev_libkrun(
    cpus: u32,
    memory_gib: u32,
    open_shell: bool,
    volumes: &[VmVolume],
) -> Result<()> {
    let backend = LibkrunBackend;
    let id = VmId(apple_container::DEV_VM_NAME.to_string());

    // Plan 98 §2.5 — take over a stale Vz dev VM rather than refusing.
    take_over_from_other_backend(DevVmBackend::Libkrun)?;

    if matches!(backend.status(&id)?, VmStatus::Running) {
        ui::success("libkrun dev VM already running.");
        if open_shell {
            console::console_interactive(apple_container::DEV_VM_NAME)?;
        }
        return Ok(());
    }

    ui::progress("Starting dev environment via libkrun...");
    let (kernel, rootfs) = apple_container::ensure_dev_image()?;
    let memory_mib = memory_gib.saturating_mul(1024);
    let config = VmStartConfig {
        name: apple_container::DEV_VM_NAME.to_string(),
        rootfs_path: rootfs,
        kernel_path: Some(kernel),
        cpus,
        memory_mib,
        flake_ref: "mvm-dev".into(),
        profile: Some("dev".into()),
        volumes: volumes.to_vec(),
        ..Default::default()
    };
    backend.start(&config)?;
    ui::success("Dev environment ready (libkrun).");
    if open_shell {
        console::console_interactive(apple_container::DEV_VM_NAME)?;
    }
    Ok(())
}

/// Plan 98 §2.5 — `dev down` is best-effort over both backends so
/// a user who switched backends without `dev down` first can still
/// recover cleanly. The current-backend stop is the primary
/// surface; the other-backend stop is best-effort (logged but not
/// surfaced as a hard error).
fn cmd_dev_libkrun_down() -> Result<()> {
    let id = VmId(apple_container::DEV_VM_NAME.to_string());
    // Best-effort stop of the Vz side too (no-op if not running;
    // status check + stop is cheap).
    if let Ok(VmStatus::Running | VmStatus::Starting | VmStatus::Paused) = VzBackend.status(&id)
        && let Err(e) = VzBackend.stop(&id)
    {
        tracing::warn!(error = %e, "best-effort Vz dev VM stop failed during libkrun dev down");
    }
    LibkrunBackend.stop(&id)
}

fn cmd_dev_libkrun_status() -> Result<()> {
    let id = VmId(apple_container::DEV_VM_NAME.to_string());
    let status = LibkrunBackend.status(&id)?;
    let state = match status {
        VmStatus::Starting => "starting",
        VmStatus::Running => "running",
        VmStatus::Stopped => "stopped",
        VmStatus::Paused => "paused",
        VmStatus::Failed { .. } => "failed",
    };
    ui::info("Backend:  libkrun (Hypervisor.framework)");
    ui::info(&format!("VM:       {}", apple_container::DEV_VM_NAME));
    ui::info(&format!("Status:   {state}"));
    // Plan 98 §2.5 — surface the other backend's state too.
    if let Ok(Some(other)) = other_backend_dev_vm_running(DevVmBackend::Libkrun) {
        ui::info(&format!(
            "Note: a {other} dev VM is also running. The next `mvmctl dev up` \
             switches to this backend automatically; `mvmctl dev down` stops both."
        ));
    }
    Ok(())
}

/// Plan 98 Slice 2B — Vz-backed dev VM. Parallel to
/// [`cmd_dev_libkrun`]; same `VmStartConfig` surface, only the
/// concrete `VmBackend` impl differs. The dev VM image (kernel +
/// rootfs) is built by `apple_container::ensure_dev_image()` which
/// already honours `MVM_BUILDER_BACKEND` through the Phase 1
/// selection layer — so the same flake produces the same artifacts
/// regardless of which dev backend boots them.
fn cmd_dev_vz(cpus: u32, memory_gib: u32, open_shell: bool, volumes: &[VmVolume]) -> Result<()> {
    let backend = VzBackend;
    let id = VmId(apple_container::DEV_VM_NAME.to_string());

    // Plan 98 §2.5 — take over a stale libkrun dev VM rather than refusing.
    take_over_from_other_backend(DevVmBackend::Vz)?;

    if matches!(backend.status(&id)?, VmStatus::Running) {
        ui::success("Vz dev VM already running.");
        if open_shell {
            console::console_interactive(apple_container::DEV_VM_NAME)?;
        }
        return Ok(());
    }

    ui::progress("Starting dev environment via Vz (Virtualization.framework)...");
    let (kernel, rootfs) = apple_container::ensure_dev_image()?;
    let memory_mib = memory_gib.saturating_mul(1024);
    let config = VmStartConfig {
        name: apple_container::DEV_VM_NAME.to_string(),
        rootfs_path: rootfs,
        kernel_path: Some(kernel),
        cpus,
        memory_mib,
        flake_ref: "mvm-dev".into(),
        profile: Some("dev".into()),
        volumes: volumes.to_vec(),
        ..Default::default()
    };
    backend.start(&config)?;
    ui::success("Dev environment ready (Vz).");
    if open_shell {
        console::console_interactive(apple_container::DEV_VM_NAME)?;
    }
    Ok(())
}

fn cmd_dev_vz_down() -> Result<()> {
    let id = VmId(apple_container::DEV_VM_NAME.to_string());
    // Plan 98 §2.5 — best-effort stop of the libkrun side too.
    if let Ok(VmStatus::Running | VmStatus::Starting | VmStatus::Paused) =
        LibkrunBackend.status(&id)
        && let Err(e) = LibkrunBackend.stop(&id)
    {
        tracing::warn!(error = %e, "best-effort libkrun dev VM stop failed during Vz dev down");
    }
    VzBackend.stop(&id)
}

fn cmd_dev_vz_status() -> Result<()> {
    let id = VmId(apple_container::DEV_VM_NAME.to_string());
    let status = VzBackend.status(&id)?;
    let state = match status {
        VmStatus::Starting => "starting",
        VmStatus::Running => "running",
        VmStatus::Stopped => "stopped",
        VmStatus::Paused => "paused",
        VmStatus::Failed { .. } => "failed",
    };
    ui::info("Backend:  Vz (Apple Virtualization.framework)");
    ui::info(&format!("VM:       {}", apple_container::DEV_VM_NAME));
    ui::info(&format!("Status:   {state}"));
    // Plan 98 §2.5 — surface the other backend's state too.
    if let Ok(Some(other)) = other_backend_dev_vm_running(DevVmBackend::Vz) {
        ui::info(&format!(
            "Note: a {other} dev VM is also running. The next `mvmctl dev up` \
             switches to this backend automatically; `mvmctl dev down` stops both."
        ));
    }
    Ok(())
}

fn effective_up_shell(shell: bool, no_shell: bool) -> bool {
    shell || !no_shell
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    let action = args.action.unwrap_or(DevAction::Up {
        cpus: 8,
        memory: 16,
        project: None,
        metrics_port: 0,
        watch_config: false,
        shell: true,
        no_shell: false,
        volume: Vec::new(),
    });

    // Plan 98 Slice 2B — §2.C1 grace guard removed. `current_backend()`
    // now honours `MVM_BUILDER_BACKEND=vz` / `--builder vz` (folded into
    // env at startup by `commands::run`) directly, routing the dev VM
    // through `VzBackend` instead of bailing.
    let backend = current_backend();
    match action {
        DevAction::Up {
            cpus,
            memory,
            project: _project,
            metrics_port: _metrics_port,
            watch_config: _watch_config,
            shell,
            no_shell,
            volume,
        } => {
            // CLI flag wins; otherwise fall back to per-user config defaults.
            let effective_cpus = if cpus == 8 { cfg.dev_vm_cpus } else { cpus };
            let effective_mem = if memory == 16 {
                cfg.dev_vm_mem_gib
            } else {
                memory
            };
            let open_shell = effective_up_shell(shell, no_shell);
            let dev_volumes = resolve_dev_volumes(&volume)?;

            // Reap helpers (gvproxy/supervisor) leaked by a prior killed
            // run before booting a fresh builder VM. Kill-only, quiet,
            // non-fatal — see `sweep_orphaned_vm_helpers_on_startup`.
            apple_container::sweep_orphaned_vm_helpers_on_startup();

            match backend {
                DevBackend::Libkrun => {
                    cmd_dev_libkrun(effective_cpus, effective_mem, open_shell, &dev_volumes)
                }
                DevBackend::Vz => {
                    cmd_dev_vz(effective_cpus, effective_mem, open_shell, &dev_volumes)
                }
                DevBackend::AppleContainer => {
                    warn_dev_volumes_unsupported(&dev_volumes, "Apple Container");
                    apple_container::cmd_dev_apple_container(
                        effective_cpus,
                        effective_mem,
                        open_shell,
                    )
                }
                DevBackend::LinuxKvm => {
                    warn_dev_volumes_unsupported(&dev_volumes, "native Linux/KVM");
                    linux_native::cmd_dev_linux_native(open_shell)
                }
                DevBackend::Unsupported => bail_no_dev_backend(),
            }
        }
        DevAction::Down { reset } => {
            let result = match backend {
                DevBackend::Libkrun => cmd_dev_libkrun_down(),
                DevBackend::Vz => cmd_dev_vz_down(),
                DevBackend::AppleContainer => apple_container::cmd_dev_apple_container_down(),
                DevBackend::LinuxKvm => linux_native::cmd_dev_linux_native_down(),
                // Nothing to stop on unsupported hosts. The gc-root
                // cleanup below still runs.
                DevBackend::Unsupported => Ok(()),
            };
            if reset {
                // `--reset` additionally drops the host-backed Nix
                // store overlay disk. Useful for "make `dev up` start
                // from a truly empty store" — e.g. after a corrupting
                // crash, or to reproduce a first-boot scenario.
                // Without this flag, the build cache survives `down`,
                // which is the right default (rebuilds are cheap, the
                // closure isn't).
                let nix_disk = format!("{}/dev/nix-store.img", mvm_core::config::mvm_data_dir());
                match std::fs::remove_file(&nix_disk) {
                    Ok(()) => {
                        ui::info(
                            "Cleared host-backed Nix store; next `dev up` will mkfs a fresh one.",
                        );
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        ui::warn(&format!("Could not remove {nix_disk}: {e}"));
                    }
                }
            }
            result
        }
        DevAction::Shell { project: _project } => match backend {
            DevBackend::Libkrun => {
                if !matches!(
                    LibkrunBackend.status(&VmId(apple_container::DEV_VM_NAME.to_string()))?,
                    VmStatus::Running
                ) {
                    anyhow::bail!("Dev VM is not running. Start it with: mvmctl dev up");
                }
                console::console_interactive(apple_container::DEV_VM_NAME)
            }
            DevBackend::Vz => {
                if !matches!(
                    VzBackend.status(&VmId(apple_container::DEV_VM_NAME.to_string()))?,
                    VmStatus::Running
                ) {
                    anyhow::bail!("Dev VM is not running. Start it with: mvmctl dev up");
                }
                console::console_interactive(apple_container::DEV_VM_NAME)
            }
            DevBackend::AppleContainer => {
                if !apple_container::is_apple_container_dev_running() {
                    anyhow::bail!("Dev VM is not running. Start it with: mvmctl dev up");
                }
                // Try connecting — the VM may be in another process
                match console::console_interactive("mvm-dev") {
                    Ok(()) => Ok(()),
                    Err(_) => anyhow::bail!(
                        "Dev VM is running but owned by another process.\n\
                         Use the terminal where you ran 'mvmctl dev up',\n\
                         or restart with: mvmctl dev down && mvmctl dev up"
                    ),
                }
            }
            DevBackend::LinuxKvm => linux_native::cmd_dev_linux_native_shell(),
            DevBackend::Unsupported => bail_no_dev_backend(),
        },
        DevAction::Status => match backend {
            DevBackend::Libkrun => cmd_dev_libkrun_status(),
            DevBackend::Vz => cmd_dev_vz_status(),
            DevBackend::AppleContainer => apple_container::cmd_dev_apple_container_status(),
            DevBackend::LinuxKvm => linux_native::cmd_dev_linux_native_status(),
            DevBackend::Unsupported => {
                ui::info(
                    "Dev environment: not configured on this host (Apple Container \
                     unavailable and native /dev/kvm missing). WSL2 nested KVM and \
                     Hyper-V managed Linux builders are future backend work.",
                );
                Ok(())
            }
        },
        DevAction::Cache {
            action: DevCacheAction::Inspect { json },
        } => apple_container::cmd_dev_cache_inspect(json),
        DevAction::ImportImage {
            manifest,
            bundle,
            vmlinux,
            rootfs,
        } => apple_container::cmd_dev_import_image(&manifest, &bundle, &vmlinux, &rootfs),
        DevAction::Rebuild {
            cpus,
            memory,
            shell,
            volume,
        } => {
            // Down (best-effort — Rebuild semantics is "discard and
            // start over," so a stop failure here shouldn't block the
            // re-up).
            let _ = match backend {
                DevBackend::Libkrun => cmd_dev_libkrun_down(),
                DevBackend::Vz => cmd_dev_vz_down(),
                DevBackend::AppleContainer => apple_container::cmd_dev_apple_container_down(),
                DevBackend::LinuxKvm => linux_native::cmd_dev_linux_native_down(),
                DevBackend::Unsupported => Ok(()),
            };

            // Clear cached dev image
            let cache_dir = format!("{}/dev", mvm_core::config::mvm_cache_dir());
            let _ = std::fs::remove_dir_all(&cache_dir);

            // Up
            let effective_cpus = if cpus == 8 { cfg.dev_vm_cpus } else { cpus };
            let effective_mem = if memory == 16 {
                cfg.dev_vm_mem_gib
            } else {
                memory
            };
            let dev_volumes = resolve_dev_volumes(&volume)?;
            match backend {
                DevBackend::Libkrun => {
                    cmd_dev_libkrun(effective_cpus, effective_mem, shell, &dev_volumes)
                }
                DevBackend::Vz => cmd_dev_vz(effective_cpus, effective_mem, shell, &dev_volumes),
                DevBackend::AppleContainer => {
                    warn_dev_volumes_unsupported(&dev_volumes, "Apple Container");
                    apple_container::cmd_dev_apple_container(effective_cpus, effective_mem, shell)
                }
                DevBackend::LinuxKvm => {
                    warn_dev_volumes_unsupported(&dev_volumes, "native Linux/KVM");
                    linux_native::cmd_dev_linux_native(shell)
                }
                DevBackend::Unsupported => bail_no_dev_backend(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DevBackend, DevVmBackend, effective_up_shell, select_dev_backend, switch_notice};
    use mvm_core::platform::Platform;

    // ──────────────────────────────────────────────────────────────
    // Slice §2.5 — cross-backend coexistence dispatch.
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn switch_notice_libkrun_takes_over_vz() {
        let line = switch_notice(DevVmBackend::Libkrun, Some("vz"))
            .expect("a running vz VM must yield a switch notice");
        assert!(line.contains("vz → libkrun"), "got: {line}");
        assert!(
            !line.contains("--builder"),
            "must not leak --builder: {line}"
        );
    }

    #[test]
    fn switch_notice_vz_takes_over_libkrun() {
        let line = switch_notice(DevVmBackend::Vz, Some("libkrun"))
            .expect("a running libkrun VM must yield a switch notice");
        assert!(line.contains("libkrun → vz"), "got: {line}");
        assert!(
            !line.contains("--builder"),
            "must not leak --builder: {line}"
        );
    }

    #[test]
    fn switch_notice_silent_when_no_other_backend() {
        // No leftover VM in either direction → nothing to announce, boot proceeds.
        assert!(switch_notice(DevVmBackend::Libkrun, None).is_none());
        assert!(switch_notice(DevVmBackend::Vz, None).is_none());
    }

    #[test]
    fn dev_up_opens_shell_by_default() {
        assert!(effective_up_shell(false, false));
        assert!(effective_up_shell(true, false));
    }

    #[test]
    fn dev_up_no_shell_opt_out_wins() {
        assert!(!effective_up_shell(false, true));
    }

    // ──────────────────────────────────────────────────────────────
    // Slice 2B — `select_dev_backend` priority. Hermetic; injects
    // platform + builder choice + per-capability bools so the
    // dispatch is testable without touching the live host.
    // ──────────────────────────────────────────────────────────────

    // ──────────────────────────────────────────────────────────────
    // Slice 2B — `select_dev_backend` priority. Hermetic; injects
    // platform + builder choice + per-capability bools so the
    // dispatch is testable without touching the live host.
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn builder_vz_with_vz_available_picks_vz_dev_backend() {
        // §2.S11 regression test: after Slice 2B removes the §2.C1
        // grace guard, `MVM_BUILDER_BACKEND=vz` (or `--builder vz`)
        // must actually route the dev VM through `VzBackend`. The
        // earlier guard silently rejected; this asserts the new
        // path actually selects Vz when the host supports it.
        assert_eq!(
            select_dev_backend(
                Platform::MacOS,
                /* prefers_vz */ true,
                /* prefers_libkrun */ false,
                /* has_vz */ true,
                /* has_apple_containers */ false,
                /* has_libkrun */ true,
                /* has_kvm */ false,
            ),
            DevBackend::Vz,
        );
    }

    #[test]
    fn builder_vz_on_apple_containers_host_still_picks_vz() {
        // Vz override wins over Apple Container auto-detect when the
        // user explicitly chose Vz. AC is rule 2; the Vz override is
        // rule 1, so the override should win even on macOS 26+.
        assert_eq!(
            select_dev_backend(Platform::MacOS, true, false, true, true, true, false,),
            DevBackend::Vz,
        );
    }

    #[test]
    fn builder_vz_without_vz_available_falls_through() {
        // Selection layer should refuse Vz on Linux already, but the
        // dev dispatch defends in depth: if somehow Vz was chosen but
        // `has_vz()` is false, fall through to the standard tree
        // instead of returning a Vz backend that can't run.
        assert_eq!(
            select_dev_backend(
                Platform::LinuxNative,
                true,
                /* prefers_libkrun */ false,
                /* has_vz */ false,
                false,
                false,
                /* has_kvm */ true,
            ),
            DevBackend::LinuxKvm,
        );
    }

    #[test]
    fn builder_libkrun_picks_apple_containers_when_available() {
        // Auto-detect tree (no explicit override): AC wins over libkrun
        // on macOS 26+ even though both are present (CLAUDE.md "Dev mode"
        // rationale). The regression guard that auto-detect libkrun does
        // *not* divert off AC — only an explicit ask does (next test).
        assert_eq!(
            select_dev_backend(
                Platform::MacOS,
                /* prefers_vz */ false,
                /* prefers_libkrun */ false,
                true,
                true,
                true,
                false,
            ),
            DevBackend::AppleContainer,
        );
    }

    #[test]
    fn explicit_libkrun_overrides_apple_containers() {
        // The symmetric counterpart to the Vz override: an operator who
        // sets MVM_BUILDER_BACKEND=libkrun on a macOS 26+ box (AC present)
        // gets the dev VM on libkrun, not Apple Container.
        assert_eq!(
            select_dev_backend(
                Platform::MacOS,
                /* prefers_vz */ false,
                /* prefers_libkrun */ true,
                /* has_vz */ true,
                /* has_apple_containers */ true,
                /* has_libkrun */ true,
                /* has_kvm */ false,
            ),
            DevBackend::Libkrun,
        );
    }

    #[test]
    fn explicit_libkrun_without_libkrun_falls_through() {
        // Defend in depth (mirrors the Vz fall-through): if libkrun was
        // asked for but isn't actually installed, don't return a Libkrun
        // backend that can't run — fall through to the auto-detect tree.
        assert_eq!(
            select_dev_backend(
                Platform::MacOS,
                /* prefers_vz */ false,
                /* prefers_libkrun */ true,
                /* has_vz */ false,
                /* has_apple_containers */ true,
                /* has_libkrun */ false,
                /* has_kvm */ false,
            ),
            DevBackend::AppleContainer,
        );
    }

    #[test]
    fn builder_libkrun_falls_back_to_libkrun_on_older_macos() {
        // macOS 13-25 without Apple Containers + libkrun installed.
        assert_eq!(
            select_dev_backend(
                Platform::MacOS,
                /* prefers_vz */ false,
                /* prefers_libkrun */ false,
                true,
                false,
                true,
                false,
            ),
            DevBackend::Libkrun,
        );
    }

    #[test]
    fn builder_libkrun_falls_through_to_linux_kvm() {
        assert_eq!(
            select_dev_backend(
                Platform::LinuxNative,
                /* prefers_vz */ false,
                /* prefers_libkrun */ false,
                false,
                false,
                false,
                true,
            ),
            DevBackend::LinuxKvm,
        );
    }

    #[test]
    fn unsupported_host_returns_unsupported() {
        // macOS without AC and without libkrun (Intel macOS, macOS
        // pre-13), Linux without KVM, etc.
        assert_eq!(
            select_dev_backend(
                Platform::MacOS,
                /* prefers_vz */ false,
                /* prefers_libkrun */ false,
                false,
                false,
                false,
                false,
            ),
            DevBackend::Unsupported,
        );
    }
}
