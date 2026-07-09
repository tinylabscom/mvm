//! `mvmctl dev` — manage the development environment.
//!
//! Supported local development hosts:
//!
//! - **macOS Apple Silicon with libkrun** → boots the dev VM via
//!   libkrun on Hypervisor.framework and exposes a PTY-over-vsock
//!   console. This is the macOS dev path on every tier, including
//!   macOS 26+ Apple Silicon (the in-house HVF dev VM boot is not wired
//!   yet, so macOS 26 falls back to libkrun here).
//! - **native Linux + KVM** → `super::linux_native` treats the host shell as
//!   the dev environment, installs Firecracker + downloads kernel/
//!   rootfs assets, and optionally spawns an interactive subshell.
//!
//! macOS without libkrun, Linux without KVM, WSL2, and native
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
use mvm_backend::LibkrunBackend;
use mvm_core::platform::{self, Platform};
use mvm_core::user_config::MvmConfig;
use mvm_core::vm_backend::{VmBackend, VmId, VmStartConfig, VmStatus, VmVolume};

use super::super::vm::console;
use super::Cli;
use super::dev_vz;
use super::linux_native;

/// Which `mvmctl dev` backend the current host uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DevBackend {
    /// macOS with libkrun — Hypervisor.framework-backed dev VM. The macOS
    /// dev path on every tier: macOS 13-25 and, until the in-house HVF dev
    /// VM boot is wired, macOS 26+ Apple Silicon fall back here too.
    Libkrun,
    /// Native Linux with `/dev/kvm` — host shell is the dev environment;
    /// Firecracker runs natively.
    LinuxKvm,
    /// Neither path is wired today — macOS without libkrun,
    /// Linux without KVM, WSL2, and native Windows.
    Unsupported,
}

/// Pure platform-decision predicate. Lifted out of [`current_backend`]
/// so unit tests can exercise the dispatch without spoofing the live
/// platform / env / flag. The two callers (`current_backend` for the
/// real runtime; tests for hermetic coverage) agree on this single
/// source of truth.
///
/// Selection order:
///   1. macOS with libkrun → Libkrun (every macOS tier — the in-house
///      HVF dev VM boot is not wired yet, so macOS 26+ Apple Silicon
///      falls back to libkrun here).
///   2. Linux with KVM → LinuxKvm.
///   3. Otherwise → Unsupported.
fn select_dev_backend(plat: Platform, has_libkrun: bool, has_kvm: bool) -> DevBackend {
    if matches!(plat, Platform::MacOS) && has_libkrun {
        DevBackend::Libkrun
    } else if has_kvm && matches!(plat, Platform::LinuxNative) {
        DevBackend::LinuxKvm
    } else {
        DevBackend::Unsupported
    }
}

fn current_backend() -> DevBackend {
    let plat = platform::current();
    select_dev_backend(plat, plat.has_libkrun(), plat.has_kvm())
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
        /// Number of vCPUs for the dev VM.
        #[arg(long, default_value = "8")]
        cpus: u32,
        /// Memory (GiB) for the dev VM.
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
        /// Emit a machine-readable JSON result after boot instead of text.
        /// Implies non-interactive (`--no-shell`); chrome goes to stderr.
        #[arg(long, conflicts_with = "shell")]
        json: bool,
    },
    /// Stop the development VM.
    Down {
        /// Also delete the cached dev image (vmlinux + rootfs.ext4) so the
        /// next `dev up` rebuilds from local source.
        #[arg(long)]
        reset: bool,
        /// Emit a machine-readable JSON result instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Open a shell in the running dev VM.
    Shell {
        /// Project directory to cd into inside the VM.
        #[arg(long)]
        project: Option<String>,
    },
    /// Show dev environment status.
    Status {
        /// Emit a machine-readable JSON report instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Inspect dev caches without rebuilding or booting.
    Cache {
        #[command(subcommand)]
        action: DevCacheAction,
    },
    /// Rebuild the dev environment (down + clear cache + up).
    Rebuild {
        /// Number of vCPUs for the dev VM.
        #[arg(long, default_value = "8")]
        cpus: u32,
        /// Memory (GiB) for the dev VM.
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
    /// Runs the same cosign sig + SHA-256 + version-pin + max-age +
    /// revocation verification
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
           - macOS Apple Silicon with libkrun (Hypervisor.framework dev VM), or\n  \
           - native Linux with /dev/kvm (Firecracker runs on the host).\n\
         This host has neither. WSL2 with nested KVM and a Hyper-V \
         managed Linux builder are future backend work, not supported \
         local dev paths today. Run on an M-series Mac or a Linux KVM \
         host for the supported local workflow."
    );
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

/// Custom dev volumes are wired for the libkrun dev VM only. The Vz
/// builder VM (which wires its own `/dev/vdb` overlay + `/work` share)
/// and the native-Linux dev path don't thread them yet — warn loudly
/// rather than silently dropping the user's `-v` request.
fn warn_dev_volumes_unsupported(volumes: &[VmVolume], backend: &str) {
    if !volumes.is_empty() {
        ui::warn(&format!(
            "Ignoring {} custom volume(s): the {backend} dev backend doesn't support \
             --volume yet (libkrun does).",
            volumes.len()
        ));
    }
}

fn cmd_dev_libkrun(
    cpus: u32,
    memory_gib: u32,
    open_shell: bool,
    volumes: &[VmVolume],
) -> Result<&'static str> {
    let backend = LibkrunBackend;
    let id = VmId(dev_vz::DEV_VM_NAME.to_string());

    if matches!(backend.status(&id)?, VmStatus::Running) {
        ui::success("libkrun dev VM already running.");
        if open_shell {
            console::console_interactive(dev_vz::DEV_VM_NAME)?;
        }
        return Ok("already-running");
    }

    ui::progress("Starting dev environment via libkrun...");
    let (kernel, rootfs) = dev_vz::ensure_dev_image()?;
    let memory_mib = memory_gib.saturating_mul(1024);
    let config = VmStartConfig {
        name: dev_vz::DEV_VM_NAME.to_string(),
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
        console::console_interactive(dev_vz::DEV_VM_NAME)?;
    }
    Ok("started")
}

/// `dev down` stops the libkrun dev VM.
fn cmd_dev_libkrun_down(json: bool) -> Result<bool> {
    let id = VmId(dev_vz::DEV_VM_NAME.to_string());
    let was_running = matches!(
        LibkrunBackend.status(&id),
        Ok(VmStatus::Running | VmStatus::Starting | VmStatus::Paused)
    );
    LibkrunBackend.stop(&id)?;
    if !json && was_running {
        ui::success("Dev VM stopped.");
    }
    Ok(was_running)
}

/// Stable backend identifier for the JSON lifecycle reports.
fn dev_backend_report_name(backend: DevBackend) -> &'static str {
    match backend {
        DevBackend::Libkrun => "libkrun",
        DevBackend::LinuxKvm => "linux-native",
        DevBackend::Unsupported => "unsupported",
    }
}

/// `dev down --reset`: drop the host-backed Nix-store overlay disk so the
/// next `dev up` starts from an empty store. Returns whether a disk was
/// actually removed. Prints human notes only when `!json`.
fn reset_nix_store_overlay(json: bool) -> bool {
    let nix_disk = format!("{}/dev/nix-store.img", mvm_core::config::mvm_data_dir());
    match std::fs::remove_file(&nix_disk) {
        Ok(()) => {
            if !json {
                ui::info("Cleared host-backed Nix store; next `dev up` will mkfs a fresh one.");
            }
            true
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            if !json {
                ui::warn(&format!("Could not remove {nix_disk}: {e}"));
            }
            false
        }
    }
}

fn cmd_dev_libkrun_status(json: bool) -> Result<()> {
    let id = VmId(dev_vz::DEV_VM_NAME.to_string());
    let status = LibkrunBackend.status(&id)?;
    let state = match status {
        VmStatus::Starting => "starting",
        VmStatus::Running => "running",
        VmStatus::Stopped => "stopped",
        VmStatus::Paused => "paused",
        VmStatus::Failed { .. } => "failed",
    };
    if json {
        // libkrun has no in-guest kernel probe here; the dev-image +
        // builder caches are backend-agnostic, so report them too.
        return crate::json_out::emit_json(&dev_vz::build_dev_status_json("libkrun", state, None));
    }
    ui::info("Backend:  libkrun (Hypervisor.framework)");
    ui::info(&format!("VM:       {}", dev_vz::DEV_VM_NAME));
    ui::info(&format!("Status:   {state}"));
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
        json: false,
    });

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
            json,
        } => {
            // `--json` emits a machine-readable result on stdout, so route
            // all `[mvm]` chrome (incl. the deep build progress) to stderr
            // and never open an interactive shell.
            if json {
                // Process-global flag; both `mvm::ui` and the `crate::ui`
                // mirror honor it, so all chrome routes to stderr.
                mvm::ui::set_chrome_to_stderr(true);
            }
            // CLI flag wins; otherwise fall back to per-user config defaults.
            let effective_cpus = if cpus == 8 { cfg.dev_vm_cpus } else { cpus };
            let effective_mem = if memory == 16 {
                cfg.dev_vm_mem_gib
            } else {
                memory
            };
            // The interactive shell bridges the guest console over a PTY,
            // which needs a real terminal. Without one (CI, scripts, the
            // core_demo test — stdin is redirected) `console_interactive`'s
            // openpty() fails. Boot the VM and return instead; `dev shell`
            // attaches later once a TTY is present. `--json` forces this off.
            let want_shell = !json && effective_up_shell(shell, no_shell);
            let open_shell = want_shell && std::io::IsTerminal::is_terminal(&std::io::stdin());
            if want_shell && !open_shell {
                ui::info(
                    "No interactive terminal detected; dev VM is up — run \
                     `mvmctl dev shell` to attach.",
                );
            }
            let dev_volumes = resolve_dev_volumes(&volume)?;

            // Reap helpers (legacy gateway/supervisor) leaked by a prior killed
            // run before booting a fresh builder VM. Kill-only, quiet,
            // non-fatal — see `sweep_orphaned_vm_helpers_on_startup`.
            dev_vz::sweep_orphaned_vm_helpers_on_startup();

            let outcome = match backend {
                DevBackend::Libkrun => {
                    cmd_dev_libkrun(effective_cpus, effective_mem, open_shell, &dev_volumes)
                }
                DevBackend::LinuxKvm => {
                    warn_dev_volumes_unsupported(&dev_volumes, "native Linux/KVM");
                    linux_native::cmd_dev_linux_native(open_shell)
                }
                DevBackend::Unsupported => return bail_no_dev_backend(),
            }?;
            if json {
                return crate::json_out::emit_json(&dev_vz::build_dev_up_json(
                    dev_backend_report_name(backend),
                    outcome,
                ));
            }
            Ok(())
        }
        DevAction::Down { reset, json } => {
            let was_running = match backend {
                DevBackend::Libkrun => cmd_dev_libkrun_down(json),
                DevBackend::LinuxKvm => linux_native::cmd_dev_linux_native_down(json),
                // Nothing to stop on unsupported hosts. The gc-root
                // cleanup below still runs.
                DevBackend::Unsupported => Ok(false),
            }?;
            let reset_done = if reset {
                reset_nix_store_overlay(json)
            } else {
                false
            };
            if json {
                return crate::json_out::emit_json(&dev_vz::build_dev_down_json(
                    dev_backend_report_name(backend),
                    was_running,
                    reset_done,
                ));
            }
            Ok(())
        }
        DevAction::Shell { project: _project } => match backend {
            DevBackend::Libkrun => {
                if !matches!(
                    LibkrunBackend.status(&VmId(dev_vz::DEV_VM_NAME.to_string()))?,
                    VmStatus::Running
                ) {
                    anyhow::bail!("Dev VM is not running. Start it with: mvmctl dev up");
                }
                console::console_interactive(dev_vz::DEV_VM_NAME)
            }
            DevBackend::LinuxKvm => linux_native::cmd_dev_linux_native_shell(),
            DevBackend::Unsupported => bail_no_dev_backend(),
        },
        DevAction::Status { json } => match backend {
            DevBackend::Libkrun => cmd_dev_libkrun_status(json),
            DevBackend::LinuxKvm => linux_native::cmd_dev_linux_native_status(json),
            DevBackend::Unsupported => {
                if json {
                    return crate::json_out::emit_json(&dev_vz::build_dev_status_json_vmless(
                        "unsupported",
                        "unsupported",
                    ));
                }
                ui::info(
                    "Dev environment: not configured on this host (no libkrun dev VM \
                     and native /dev/kvm missing). WSL2 nested KVM and \
                     Hyper-V managed Linux builders are future backend work.",
                );
                Ok(())
            }
        },
        DevAction::Cache {
            action: DevCacheAction::Inspect { json },
        } => dev_vz::cmd_dev_cache_inspect(json),
        DevAction::ImportImage {
            manifest,
            bundle,
            vmlinux,
            rootfs,
        } => dev_vz::cmd_dev_import_image(&manifest, &bundle, &vmlinux, &rootfs),
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
                DevBackend::Libkrun => cmd_dev_libkrun_down(false),
                DevBackend::LinuxKvm => linux_native::cmd_dev_linux_native_down(false),
                DevBackend::Unsupported => Ok(false),
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
                    cmd_dev_libkrun(effective_cpus, effective_mem, shell, &dev_volumes).map(|_| ())
                }
                DevBackend::LinuxKvm => {
                    warn_dev_volumes_unsupported(&dev_volumes, "native Linux/KVM");
                    linux_native::cmd_dev_linux_native(shell).map(|_| ())
                }
                DevBackend::Unsupported => bail_no_dev_backend(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DevBackend, effective_up_shell, select_dev_backend};
    use mvm_core::platform::Platform;

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
    // `select_dev_backend` priority. Hermetic; injects platform +
    // per-capability bools so the dispatch is testable without touching
    // the live host.
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn macos_with_libkrun_picks_libkrun_dev_backend() {
        // Every macOS tier — including macOS 26+ Apple Silicon, which
        // falls back to libkrun until the in-house HVF dev VM boot lands.
        assert_eq!(
            select_dev_backend(
                Platform::MacOS,
                /* has_libkrun */ true,
                /* has_kvm */ false
            ),
            DevBackend::Libkrun,
        );
    }

    #[test]
    fn macos_without_libkrun_is_unsupported() {
        assert_eq!(
            select_dev_backend(
                Platform::MacOS,
                /* has_libkrun */ false,
                /* has_kvm */ false
            ),
            DevBackend::Unsupported,
        );
    }

    #[test]
    fn linux_with_kvm_picks_linux_kvm() {
        assert_eq!(
            select_dev_backend(
                Platform::LinuxNative,
                /* has_libkrun */ false,
                /* has_kvm */ true
            ),
            DevBackend::LinuxKvm,
        );
    }

    #[test]
    fn unsupported_host_returns_unsupported() {
        // Linux without KVM, Windows, etc.
        assert_eq!(
            select_dev_backend(
                Platform::LinuxNative,
                /* has_libkrun */ false,
                /* has_kvm */ false
            ),
            DevBackend::Unsupported,
        );
    }
}
