//! `mvmctl dev` — manage the Lima / Apple Container development environment.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use crate::bootstrap;
use crate::shell_init;
use crate::ui;

use mvm_core::user_config::MvmConfig;
use mvm_runtime::config;
use mvm_runtime::shell;
use mvm_runtime::vm::{firecracker, lima};

use super::super::vm::console;
use super::Cli;
use super::apple_container;
use super::bootstrap::run_steps as bootstrap_steps;
use super::setup::run_setup_steps;
use super::shell::open_shell;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: Option<DevAction>,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum DevAction {
    /// Bootstrap and start the dev environment
    Up {
        /// Number of vCPUs for the Lima VM
        #[arg(long, default_value = "8")]
        lima_cpus: u32,
        /// Memory (GiB) for the Lima VM
        #[arg(long, default_value = "16")]
        lima_mem: u32,
        /// Project directory to cd into inside the VM
        #[arg(long)]
        project: Option<String>,
        /// Bind a Prometheus metrics endpoint on this port (0 = disabled)
        #[arg(long, default_value = "0")]
        metrics_port: u16,
        /// Reload ~/.mvm/config.toml automatically when it changes
        #[arg(long)]
        watch_config: bool,
        /// Force Lima backend even on macOS 26+ (where Apple Container is default)
        #[arg(long)]
        lima: bool,
        /// Open an interactive shell after starting
        #[arg(long, short = 's')]
        shell: bool,
    },
    /// Stop the Lima development VM
    Down {
        /// Also delete the cached dev image (vmlinux + rootfs.ext4) so the
        /// next `dev up` rebuilds from local source.
        #[arg(long)]
        reset: bool,
    },
    /// Open a shell in the running Lima VM
    Shell {
        /// Project directory to cd into inside the VM (Lima maps ~ → ~)
        #[arg(long)]
        project: Option<String>,
    },
    /// Show dev environment status (Lima VM, Firecracker, Nix)
    Status,
    /// Rebuild the dev environment (down + clear cache + up)
    Rebuild {
        /// Number of vCPUs for the Lima VM
        #[arg(long, default_value = "8")]
        lima_cpus: u32,
        /// Memory (GiB) for the Lima VM
        #[arg(long, default_value = "16")]
        lima_mem: u32,
        /// Force Lima backend even on macOS 26+
        #[arg(long)]
        lima: bool,
        /// Open an interactive shell after rebuilding
        #[arg(long, short = 's')]
        shell: bool,
    },
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    let action = args.action.unwrap_or(DevAction::Up {
        lima_cpus: 8,
        lima_mem: 16,
        project: None,
        metrics_port: 0,
        watch_config: false,
        lima: false,
        shell: false,
    });

    match action {
        DevAction::Up {
            lima_cpus,
            lima_mem,
            project,
            metrics_port,
            watch_config,
            lima,
            shell,
        } => {
            // CLI flag wins; otherwise fall back to per-user config defaults.
            let effective_cpus = if lima_cpus == 8 {
                cfg.lima_cpus
            } else {
                lima_cpus
            };
            let effective_mem = if lima_mem == 16 {
                cfg.lima_mem_gib
            } else {
                lima_mem
            };

            let use_apple_container = !lima && mvm_core::platform::current().has_apple_containers();
            if use_apple_container {
                apple_container::cmd_dev_apple_container(effective_cpus, effective_mem, shell)
            } else {
                dev_up(
                    effective_cpus,
                    effective_mem,
                    project.as_deref(),
                    metrics_port,
                    watch_config,
                )
            }
        }
        DevAction::Down { reset } => {
            let result = if mvm_core::platform::current().has_apple_containers() {
                apple_container::cmd_dev_apple_container_down()
            } else {
                dev_down()
            };
            // Always drop the dev-image GC root on `down`. It exists to
            // pin the rootfs/kernel store paths *while the VM is using
            // them*; once the VM is stopped, holding the root just
            // blocks `nix-collect-garbage` from reclaiming superseded
            // images. The next `dev up` re-resolves the path via
            // `nix build --out-link`, which is a no-op against a fresh
            // closure (cache hit) and a re-realise against a changed
            // closure — either way, the symlink is recreated cleanly.
            let gc_root = format!("{}/dev/current", mvm_core::config::mvm_data_dir());
            if let Err(e) = std::fs::remove_file(&gc_root)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                ui::warn(&format!("Could not remove {gc_root}: {e}"));
            }

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
        DevAction::Shell { project } => {
            if mvm_core::platform::current().has_apple_containers() {
                if !apple_container::is_apple_container_dev_running() {
                    anyhow::bail!("Dev VM is not running. Start it with: mvmctl dev up");
                }
                // Try connecting — the VM may be in another process
                match console::console_interactive("mvm-dev") {
                    Ok(()) => Ok(()),
                    Err(_) => anyhow::bail!(
                        "Dev VM is running but owned by another process.\n\
                         Use the terminal where you ran 'mvmctl dev up',\n\
                         or restart with: mvmctl dev down && mvmctl dev up --shell"
                    ),
                }
            } else {
                open_shell(project.as_deref())
            }
        }
        DevAction::Status => {
            if mvm_core::platform::current().has_apple_containers() {
                apple_container::cmd_dev_apple_container_status()
            } else {
                dev_status()
            }
        }
        DevAction::Rebuild {
            lima_cpus,
            lima_mem,
            lima,
            shell,
        } => {
            // Down
            if mvm_core::platform::current().has_apple_containers() {
                let _ = apple_container::cmd_dev_apple_container_down();
            } else {
                let _ = dev_down();
            }

            // Clear cached dev image
            let cache_dir = format!("{}/dev", mvm_core::config::mvm_cache_dir());
            let _ = std::fs::remove_dir_all(&cache_dir);

            // Up
            let effective_cpus = if lima_cpus == 8 {
                cfg.lima_cpus
            } else {
                lima_cpus
            };
            let effective_mem = if lima_mem == 16 {
                cfg.lima_mem_gib
            } else {
                lima_mem
            };
            let use_apple_container = !lima && mvm_core::platform::current().has_apple_containers();
            if use_apple_container {
                apple_container::cmd_dev_apple_container(effective_cpus, effective_mem, shell)
            } else {
                dev_up(effective_cpus, effective_mem, None, 0, false)
            }
        }
    }
}

fn dev_up(
    lima_cpus: u32,
    lima_mem: u32,
    project: Option<&str>,
    metrics_port: u16,
    watch_config: bool,
) -> Result<()> {
    let _metrics_server = if metrics_port > 0 {
        Some(crate::metrics_server::MetricsServer::start(metrics_port)?)
    } else {
        None
    };

    // Start config watcher before setup so any reload during bootstrap is captured.
    let _config_watcher = if watch_config {
        let config_path = {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            std::path::PathBuf::from(home)
                .join(".mvm")
                .join("config.toml")
        };
        if config_path.exists() {
            match crate::config_watcher::ConfigWatcher::start(&config_path) {
                Ok(w) => {
                    tracing::info!("Watching ~/.mvm/config.toml for changes");
                    Some(w)
                }
                Err(e) => {
                    tracing::warn!("Could not start config watcher: {e}");
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    ui::info("Launching development environment...\n");

    if bootstrap::is_lima_required() {
        // macOS or Linux without KVM — need Lima
        if which::which("limactl").is_err() {
            ui::info("Lima not found. Running bootstrap...\n");
            bootstrap_steps(false)?;
        } else {
            // W7.2: warn if there's a legacy `mvm` Lima VM from before the
            // builder VM rename. We don't auto-migrate (limactl can't
            // rename in-place and the user may have running tenant work).
            bootstrap::warn_if_legacy_lima_vm()?;
            let lima_status = lima::get_status()?;
            match lima_status {
                lima::LimaStatus::NotFound => {
                    ui::info("Lima VM not found. Running setup...\n");
                    run_setup_steps(false, lima_cpus, lima_mem)?;
                }
                lima::LimaStatus::Stopped => {
                    ui::info("Lima VM is stopped. Starting...");
                    lima::start()?;
                }
                lima::LimaStatus::Running => {}
            }
        }
    }

    // Install Firecracker binary if not present
    if !firecracker::is_installed()? {
        ui::info("Firecracker not installed. Installing...\n");
        firecracker::install()?;
    }

    // Download kernel + squashfs only if missing
    if !firecracker::has_base_assets()? {
        ui::info("Downloading kernel and rootfs...\n");
        firecracker::download_assets()?;
        firecracker::prepare_rootfs()?;
        firecracker::write_state()?;
    }

    // Ensure shell completions and dev aliases are in ~/.zshrc
    shell_init::ensure_shell_init()?;

    // Drop into the Lima VM shell (the development environment)
    open_shell(project)
}

fn dev_down() -> Result<()> {
    if !bootstrap::is_lima_required() {
        ui::info("Lima is not required on this platform (native KVM available).");
        return Ok(());
    }

    if which::which("limactl").is_err() {
        anyhow::bail!("Lima is not installed. Run 'mvmctl dev up' to bootstrap first.");
    }

    let status = lima::get_status()?;
    match status {
        lima::LimaStatus::Running => {
            ui::info("Stopping Lima development VM...");
            lima::stop()?;
            ui::success("Development VM stopped.");
            Ok(())
        }
        lima::LimaStatus::Stopped => {
            ui::info("Development VM is already stopped.");
            Ok(())
        }
        lima::LimaStatus::NotFound => {
            anyhow::bail!(
                "Lima VM '{}' does not exist. Run 'mvmctl dev up' first.",
                config::VM_NAME
            );
        }
    }
}

fn dev_status() -> Result<()> {
    if !bootstrap::is_lima_required() {
        ui::info("Lima is not required on this platform (native KVM available).");
        return Ok(());
    }

    if which::which("limactl").is_err() {
        ui::warn("Lima is not installed. Run 'mvmctl dev up' to bootstrap.");
        return Ok(());
    }

    let status = lima::get_status()?;
    let status_str = match status {
        lima::LimaStatus::Running => "Running",
        lima::LimaStatus::Stopped => "Stopped",
        lima::LimaStatus::NotFound => "Not found",
    };

    ui::info(&format!("Lima VM '{}': {status_str}", config::VM_NAME));

    if matches!(status, lima::LimaStatus::Running) {
        let fc_ver = shell::run_in_vm_stdout("firecracker --version 2>/dev/null | head -1")
            .unwrap_or_default();
        let nix_ver = shell::run_in_vm_stdout("nix --version 2>/dev/null").unwrap_or_default();

        ui::info(&format!(
            "  Firecracker: {}",
            if fc_ver.trim().is_empty() {
                "not installed"
            } else {
                fc_ver.trim()
            }
        ));
        ui::info(&format!(
            "  Nix:         {}",
            if nix_ver.trim().is_empty() {
                "not installed"
            } else {
                nix_ver.trim()
            }
        ));

        let mvm_in_vm =
            shell::run_in_vm_stdout("test -f /usr/local/bin/mvmctl && echo yes || echo no")
                .unwrap_or_default();
        if mvm_in_vm.trim() == "yes" {
            let mvm_ver = shell::run_in_vm_stdout("/usr/local/bin/mvmctl --version 2>/dev/null")
                .unwrap_or_default();
            ui::info(&format!(
                "  mvmctl:      {}",
                if mvm_ver.trim().is_empty() {
                    "installed"
                } else {
                    mvm_ver.trim()
                }
            ));
        } else {
            ui::warn("  mvmctl not installed in VM. Run 'mvmctl sync' to build and install it.");
        }
    }

    Ok(())
}
