mod apple_container;
mod audit;
mod bootstrap_cmd;
mod build;
mod cache_cmd;
mod cleanup;
mod completions;
mod config_cmd;
mod console;
mod dev;
mod diff;
mod doctor;
mod down;
mod exec_cmd;
mod flake_cmd;
mod forward;
mod image_cmd;
mod init_cmd;
mod logs;
mod ls;
mod metrics;
mod network;
mod run;
mod security;
mod setup;
mod shared;
mod shell;
mod template_run;
mod uninstall;
mod update_cmd;

#[cfg(test)]
mod tests;

pub(crate) use apple_container::ensure_default_microvm_image;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use std::sync::Arc;

use crate::logging::{self, LogFormat};
use crate::shell_init;

use mvm_core::util::parse_human_size;

use audit::AuditCmd;
use cache_cmd::CacheCmd;
use config_cmd::ConfigAction;
use dev::DevCmd;
use flake_cmd::FlakeCmd;
use image_cmd::ImageCmd;
use network::NetworkCmd;
use security::SecurityCmd;
use template_run::TemplateCmd;

use shared::{
    CHILD_PIDS, IN_CONSOLE_MODE, clap_flake_ref, clap_port_spec, clap_vm_name, clap_volume_spec,
    with_hints,
};

#[derive(Parser)]
#[command(name = "mvmctl", version, about = "Lightweight VM development tool")]
struct Cli {
    /// Log format: human (default) or json (structured)
    #[arg(long, global = true)]
    log_format: Option<String>,

    /// Override Firecracker version (e.g., v1.14.0)
    #[arg(long, global = true)]
    fc_version: Option<String>,

    /// Show verbose `[mvm]` progress messages. Implied when `RUST_LOG` is set.
    #[arg(long, global = true, alias = "debug")]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // Up variant has many CLI fields; boxing breaks Clap derive
enum Commands {
    /// Full environment setup from scratch
    Bootstrap {
        /// Production mode (skip Homebrew, assume Linux with apt)
        #[arg(long)]
        production: bool,
    },
    /// Create Lima VM, install Firecracker, download kernel/rootfs (requires limactl)
    Setup {
        /// Delete the existing rootfs and rebuild it from scratch
        #[arg(long)]
        recreate: bool,
        /// Re-run all setup steps even if already complete
        #[arg(long)]
        force: bool,
        /// Number of vCPUs for the Lima VM
        #[arg(long, default_value = "8")]
        lima_cpus: u32,
        /// Memory (GiB) for the Lima VM
        #[arg(long, default_value = "16")]
        lima_mem: u32,
    },
    /// Manage the Lima development environment (up, down, shell, status)
    Dev {
        #[command(subcommand)]
        action: Option<DevCmd>,
    },
    /// Remove old dev-build artifacts and run Nix garbage collection
    Cleanup {
        /// Number of newest build revisions to keep
        #[arg(long)]
        keep: Option<usize>,
        /// Remove all cached build revisions
        #[arg(long)]
        all: bool,
        /// Print each cached build path that gets removed
        #[arg(long)]
        verbose: bool,
    },
    /// Show console logs from a running microVM
    Logs {
        /// Name of the VM
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Follow log output (like tail -f)
        #[arg(long, short = 'f')]
        follow: bool,
        /// Number of lines to show (default 50)
        #[arg(long, short = 'n', default_value = "50")]
        lines: u32,
        /// Show Firecracker hypervisor logs instead of guest console output
        #[arg(long)]
        hypervisor: bool,
    },
    /// Forward a port from a running microVM to localhost
    Forward {
        /// Name of the VM
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Port mapping(s): GUEST_PORT or LOCAL_PORT:GUEST_PORT
        #[arg(short, long, value_name = "PORT", value_parser = clap_port_spec)]
        port: Vec<String>,
        /// Port mapping(s) (positional, same as --port)
        #[arg(trailing_var_arg = true, hide = true)]
        ports: Vec<String>,
    },
    /// List running VMs
    #[command(alias = "ls", alias = "status")]
    Ps {
        /// Show all VMs (including stopped)
        #[arg(short, long)]
        all: bool,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Check for and install the latest version of mvmctl
    Update {
        /// Only check, don't install
        #[arg(long)]
        check: bool,
        /// Force re-install even if already up to date
        #[arg(long)]
        force: bool,
        /// Skip checksum verification
        #[arg(long)]
        skip_verify: bool,
    },
    /// System diagnostics and dependency checks
    Doctor {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Manage global templates (shared base images)
    Template {
        #[command(subcommand)]
        action: TemplateCmd,
    },
    /// Build a microVM image from a Mvmfile.toml config or Nix flake
    Build {
        /// Image name (built-in like "openclaw") or path to directory with Mvmfile.toml
        #[arg(default_value = ".")]
        path: String,
        /// Output path for the built .elf image
        #[arg(short, long)]
        output: Option<String>,
        /// Nix flake reference (enables flake build mode)
        #[arg(long, value_parser = clap_flake_ref)]
        flake: Option<String>,
        /// Flake package variant (e.g. worker, gateway). Omit to use flake default
        #[arg(long)]
        profile: Option<String>,
        /// Watch flake.lock and rebuild on change (flake mode)
        #[arg(long)]
        watch: bool,
        /// Output structured JSON events instead of human-readable output
        #[arg(long)]
        json: bool,
    },
    /// Build and run a VM from a Nix flake, a template, or the bundled default image.
    ///
    /// If neither `--flake` nor `--template` is supplied, the bundled
    /// `nix/default-microvm/` image is used (built via Nix on first use,
    /// cached at `~/.cache/mvm/default-microvm/`).
    #[command(alias = "start", alias = "run")]
    Up {
        /// Nix flake reference (local path or remote URI)
        #[arg(long, value_parser = clap_flake_ref, conflicts_with = "template")]
        flake: Option<String>,
        /// Run from a pre-built template (skip build)
        #[arg(long)]
        template: Option<String>,
        /// VM name (auto-generated if omitted)
        #[arg(long, value_parser = clap_vm_name)]
        name: Option<String>,
        /// Flake package variant (e.g. worker, gateway). Omit to use flake default
        #[arg(long)]
        profile: Option<String>,
        /// vCPU cores
        #[arg(long)]
        cpus: Option<u32>,
        /// Memory (supports human-readable sizes: 512M, 4G, 1024K, or plain MB)
        #[arg(long)]
        memory: Option<String>,
        /// Runtime config (TOML) for persistent resources/volumes
        #[arg(long)]
        config: Option<String>,
        /// Volume (host_dir:/guest/path or host:/guest/path:size). Repeatable
        #[arg(short, long, value_parser = clap_volume_spec)]
        volume: Vec<String>,
        /// Hypervisor backend (firecracker, qemu, apple-container, docker). Default: auto-detect
        #[arg(long, default_value = "firecracker")]
        hypervisor: String,
        /// Port mapping (format: HOST:GUEST or PORT). Repeatable
        #[arg(short, long, value_parser = clap_port_spec)]
        port: Vec<String>,
        /// Environment variable to inject (format: KEY=VALUE). Repeatable
        #[arg(short, long)]
        env: Vec<String>,
        /// Auto-forward declared ports after boot (blocks until Ctrl-C)
        #[arg(long)]
        forward: bool,
        /// Bind a Prometheus metrics endpoint on this port (0 = disabled)
        #[arg(long, default_value = "0")]
        metrics_port: u16,
        /// Reload ~/.mvm/config.toml automatically when it changes
        #[arg(long)]
        watch_config: bool,
        /// Watch the flake for changes and auto-rebuild + reboot (requires local --flake)
        #[arg(long)]
        watch: bool,
        /// Run in background (detached mode, like docker run -d)
        #[arg(short, long)]
        detach: bool,
        /// Network preset (unrestricted, none, registries, dev)
        #[arg(long)]
        network_preset: Option<String>,
        /// Network allowlist entry (format: HOST:PORT). Repeatable
        #[arg(long)]
        network_allow: Vec<String>,
        /// Seccomp profile tier (essential, minimal, standard, network, unrestricted)
        #[arg(long, default_value = "unrestricted")]
        seccomp: String,
        /// Secret binding (format: KEY:host, KEY:host:header, or KEY=value:host). Repeatable
        #[arg(short, long)]
        secret: Vec<String>,
        /// Named dev network to attach VM to (default: "default")
        #[arg(long, default_value = "default")]
        network: String,
    },
    /// Stop microVMs (from mvm.toml, by name, or all)
    Down {
        /// VM name to stop (or all VMs if omitted)
        name: Option<String>,
        /// Path to fleet config (stops only VMs defined in config)
        #[arg(short = 'f', long)]
        config: Option<String>,
    },
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: clap_complete::Shell,
    },
    /// Print shell configuration (completions + dev aliases) to stdout
    ShellInit,
    /// Show runtime metrics (Prometheus text format by default)
    Metrics {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Read or write global operator config (~/.mvm/config.toml)
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Remove Lima VM, Firecracker binary, and all mvm state (clean uninstall)
    Uninstall {
        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
        /// Also remove ~/.mvm/ and the mvmctl binary
        #[arg(long)]
        all: bool,
        /// Print actions without performing them
        #[arg(long)]
        dry_run: bool,
    },
    /// View the local audit log (~/.mvm/log/audit.jsonl)
    Audit {
        #[command(subcommand)]
        action: AuditCmd,
    },
    /// Validate a Nix flake before building
    Flake {
        #[command(subcommand)]
        action: FlakeCmd,
    },
    /// Show filesystem changes in a running VM (files created/modified/deleted since boot)
    Diff {
        /// Name of the VM
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Manage named dev networks
    Network {
        #[command(subcommand)]
        action: NetworkCmd,
    },
    /// Browse and fetch images from the Nix-based image catalog
    Image {
        #[command(subcommand)]
        action: ImageCmd,
    },
    /// Interactive console (PTY-over-vsock) to a running VM
    Console {
        /// Name of the VM
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Run a single command instead of an interactive shell
        #[arg(long)]
        command: Option<String>,
    },
    /// Manage the XDG cache directory (~/.cache/mvm)
    Cache {
        #[command(subcommand)]
        action: CacheCmd,
    },
    /// First-time setup wizard — installs deps, creates Lima VM, sets up default network
    Init {
        /// Skip interactive prompts, use defaults
        #[arg(long)]
        non_interactive: bool,
        /// Number of vCPUs for the Lima VM
        #[arg(long, default_value = "8")]
        lima_cpus: u32,
        /// Memory (GiB) for the Lima VM
        #[arg(long, default_value = "16")]
        lima_mem: u32,
    },
    /// Show security posture and status
    Security {
        #[command(subcommand)]
        action: SecurityCmd,
    },
    /// Boot a transient microVM, run a single command, and tear down (dev-mode only).
    ///
    /// Inspired by cco — same one-command UX, but with a Firecracker microVM as the sandbox.
    /// Use `--add-dir host:guest[:mode]` to share a host directory (default `:ro`; pass `:rw`
    /// to rsync writes back to the host on exit). Use `--` to separate the argv from
    /// `mvmctl exec` flags. Alternatively, pass `--launch-plan ./launch.json` to invoke an
    /// mvmforge-emitted entrypoint instead of an inline argv.
    Exec {
        /// Pre-built template to boot. If omitted, the bundled
        /// `nix/default-microvm/` image is used (built via Nix on first use,
        /// cached at `~/.cache/mvm/default-microvm/`). Each invocation boots a
        /// fresh transient microVM — never the long-running `mvmctl dev` VM.
        #[arg(long)]
        template: Option<String>,
        /// vCPU cores (default: 2)
        #[arg(long, default_value = "2")]
        cpus: u32,
        /// Memory (supports human-readable: 512M, 1G, …)
        #[arg(long, default_value = "512M")]
        memory: String,
        /// Share a host directory into the guest. Format: `HOST_PATH:/GUEST_PATH[:MODE]`
        /// where MODE is `ro` (default, writes are discarded) or `rw` (writes are
        /// rsynced back to the host directory after the command exits — see ADR-002). Repeatable
        #[arg(short = 'd', long)]
        add_dir: Vec<String>,
        /// Environment variable to inject (KEY=VALUE). Repeatable. Overrides any env vars
        /// carried by `--launch-plan`.
        #[arg(short, long)]
        env: Vec<String>,
        /// Per-command timeout in seconds (default: 60)
        #[arg(long, default_value = "60")]
        timeout: u64,
        /// Path to an mvmforge `launch.json`. The first app's `entrypoint`
        /// (command, working_dir, env) is invoked instead of a trailing argv.
        /// Mutually exclusive with the trailing `<ARGV>...`.
        #[arg(long, value_name = "PATH", conflicts_with = "argv")]
        launch_plan: Option<String>,
        /// Argv to run inside the guest (use `--` to separate). Required unless
        /// `--launch-plan` is supplied.
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            required_unless_present = "launch_plan"
        )]
        argv: Vec<String>,
    },
}

// ============================================================================
// Entry point
// ============================================================================

/// Return the Clap `Command` tree for `mvmctl`.
///
/// Used by the `xtask` crate to generate man pages without duplicating the
/// command definition.
pub fn cli_command() -> clap::Command {
    Cli::command()
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    // Apply FC version override before anything reads it.
    // SAFETY: called once at startup before any threads are spawned.
    if let Some(ref version) = cli.fc_version {
        unsafe { std::env::set_var("MVM_FC_VERSION", version) };
    }

    // Verbose `[mvm]` chatter: explicit flag, or any RUST_LOG set.
    let verbose = cli.verbose || std::env::var_os("RUST_LOG").is_some();
    mvm_runtime::ui::set_verbose(verbose);

    // Initialize logging
    let log_format = match cli.log_format.as_deref() {
        Some("json") => LogFormat::Json,
        Some("human") => LogFormat::Human,
        Some(other) => {
            eprintln!(
                "Unknown --log-format '{}', using 'human'. Valid: human, json",
                other
            );
            LogFormat::Human
        }
        None => LogFormat::Human,
    };
    logging::init(log_format);

    // Install Ctrl-C / SIGTERM handler for graceful shutdown.
    let pids = Arc::clone(&CHILD_PIDS);
    if let Err(e) = ctrlc::set_handler(move || {
        // In console mode, Ctrl-C is forwarded as a raw byte to the guest.
        if IN_CONSOLE_MODE.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        eprintln!("\nInterrupted, cleaning up...");
        // Kill any tracked child processes (e.g., socat port-forwarders).
        if let Ok(pids) = pids.lock() {
            for &pid in pids.iter() {
                unsafe {
                    libc::kill(pid as libc::pid_t, libc::SIGTERM);
                }
            }
        }
        std::process::exit(130);
    }) {
        tracing::warn!("failed to install signal handler: {e}");
    }

    // Load operator config once; used as fallback for lima_cpus, lima_mem, cpus, memory.
    let cfg = mvm_core::user_config::load(None);

    let result = match cli.command {
        Commands::Bootstrap { production } => bootstrap_cmd::cmd_bootstrap(production),
        Commands::Setup {
            recreate,
            force,
            lima_cpus,
            lima_mem,
        } => {
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
            setup::cmd_setup(recreate, force, effective_cpus, effective_mem)
        }
        Commands::Dev { action } => {
            let action = action.unwrap_or(DevCmd::Up {
                lima_cpus: 8,
                lima_mem: 16,
                project: None,
                metrics_port: 0,
                watch_config: false,
                lima: false,
                shell: false,
            });
            match action {
                DevCmd::Up {
                    lima_cpus,
                    lima_mem,
                    project,
                    metrics_port,
                    watch_config,
                    lima,
                    shell,
                } => {
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

                    let use_apple_container =
                        !lima && mvm_core::platform::current().has_apple_containers();

                    if use_apple_container {
                        apple_container::cmd_dev_apple_container(
                            effective_cpus,
                            effective_mem,
                            shell,
                        )
                    } else {
                        dev::cmd_dev(
                            effective_cpus,
                            effective_mem,
                            project.as_deref(),
                            metrics_port,
                            watch_config,
                        )
                    }
                }
                DevCmd::Down => {
                    if mvm_core::platform::current().has_apple_containers() {
                        apple_container::cmd_dev_apple_container_down()
                    } else {
                        dev::cmd_dev_down()
                    }
                }
                DevCmd::Shell { project } => {
                    if mvm_core::platform::current().has_apple_containers() {
                        if !apple_container::is_apple_container_dev_running() {
                            anyhow::bail!("Dev VM is not running. Start it with: mvmctl dev up");
                        }
                        // Try connecting — the VM may be in another process
                        match console::console_interactive("mvm-dev") {
                            Ok(()) => Ok(()),
                            Err(_) => {
                                anyhow::bail!(
                                    "Dev VM is running but owned by another process.\n\
                                     Use the terminal where you ran 'mvmctl dev up',\n\
                                     or restart with: mvmctl dev down && mvmctl dev up --shell"
                                )
                            }
                        }
                    } else {
                        shell::cmd_shell(project.as_deref())
                    }
                }
                DevCmd::Status => {
                    if mvm_core::platform::current().has_apple_containers() {
                        apple_container::cmd_dev_apple_container_status()
                    } else {
                        dev::cmd_dev_status()
                    }
                }
                DevCmd::Rebuild {
                    lima_cpus,
                    lima_mem,
                    lima,
                    shell,
                } => {
                    // Down
                    if mvm_core::platform::current().has_apple_containers() {
                        let _ = apple_container::cmd_dev_apple_container_down();
                    } else {
                        let _ = dev::cmd_dev_down();
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
                    let use_apple_container =
                        !lima && mvm_core::platform::current().has_apple_containers();
                    if use_apple_container {
                        apple_container::cmd_dev_apple_container(
                            effective_cpus,
                            effective_mem,
                            shell,
                        )
                    } else {
                        dev::cmd_dev(effective_cpus, effective_mem, None, 0, false)
                    }
                }
            }
        }
        Commands::Cleanup { keep, all, verbose } => cleanup::cmd_cleanup(keep, all, verbose),
        Commands::Logs {
            name,
            follow,
            lines,
            hypervisor,
        } => logs::cmd_logs(&name, follow, lines, hypervisor),
        Commands::Forward { name, port, ports } => {
            let mut all_ports = port;
            all_ports.extend(ports);
            forward::cmd_forward(&name, &all_ports)
        }

        Commands::Ps { all, json } => ls::cmd_ls(all, json),
        Commands::Update {
            check,
            force,
            skip_verify,
        } => update_cmd::cmd_update(check, force, skip_verify),
        Commands::Doctor { json } => doctor::cmd_doctor(json),
        Commands::Build {
            path,
            output,
            flake,
            profile,
            watch,
            json,
        } => {
            if let Some(flake_ref) = flake {
                build::cmd_build_flake(&flake_ref, profile.as_deref(), watch, json)
            } else {
                build::cmd_build(&path, output.as_deref())
            }
        }
        Commands::Up {
            flake,
            template,
            name,
            profile,
            cpus,
            memory,
            config,
            volume,
            hypervisor,
            port,
            env,
            forward,
            metrics_port,
            watch_config,
            watch,
            detach,
            network_preset,
            network_allow,
            seccomp,
            secret,
            network,
        } => {
            let memory_mb = memory
                .as_ref()
                .map(|s| parse_human_size(s))
                .transpose()
                .context("Invalid memory size")?;
            // CLI flag takes precedence; fall back to per-user config defaults.
            let effective_cpus = cpus.or(Some(cfg.default_cpus));
            let effective_memory = memory_mb.or(Some(cfg.default_memory_mib));

            let network_policy =
                shared::resolve_network_policy(network_preset.as_deref(), &network_allow)?;
            let seccomp_tier: mvm_security::seccomp::SeccompTier =
                seccomp.parse().context("Invalid --seccomp value")?;
            let secret_bindings: Vec<mvm_core::secret_binding::SecretBinding> = secret
                .iter()
                .map(|s| s.parse())
                .collect::<Result<Vec<_>>>()
                .context("Invalid --secret value")?;

            run::cmd_run(run::RunParams {
                flake_ref: flake.as_deref(),
                template_name: template.as_deref(),
                name: name.as_deref(),
                profile: profile.as_deref(),
                cpus: effective_cpus,
                memory: effective_memory,
                config_path: config.as_deref(),
                volumes: &volume,
                hypervisor: &hypervisor,
                ports: &port,
                env_vars: &env,
                forward,
                metrics_port,
                watch_config,
                watch,
                detach,
                network_policy,
                network_name: &network,
                seccomp_tier,
                secret_bindings,
            })
        }
        Commands::Down { name, config } => down::cmd_down(name.as_deref(), config.as_deref()),
        Commands::Completions { shell } => completions::cmd_completions(shell),
        Commands::ShellInit => shell_init::print_shell_init(),
        Commands::Metrics { json } => metrics::cmd_metrics(json),
        Commands::Template { action } => template_run::cmd_template(action),
        Commands::Config { action } => config_cmd::cmd_config(action),
        Commands::Uninstall { yes, all, dry_run } => uninstall::cmd_uninstall(yes, all, dry_run),
        Commands::Audit { action } => audit::cmd_audit(action),
        Commands::Diff { name, json } => diff::cmd_diff(&name, json),
        Commands::Flake { action } => flake_cmd::cmd_flake(action),
        Commands::Network { action } => network::cmd_network(action),
        Commands::Image { action } => image_cmd::cmd_image(action),
        Commands::Console { name, command } => console::cmd_console(&name, command.as_deref()),
        Commands::Cache { action } => cache_cmd::cmd_cache(action),
        Commands::Init {
            non_interactive,
            lima_cpus,
            lima_mem,
        } => init_cmd::cmd_init(non_interactive, lima_cpus, lima_mem),
        Commands::Security { action } => security::cmd_security(action),
        Commands::Exec {
            template,
            cpus,
            memory,
            add_dir,
            env,
            timeout,
            launch_plan,
            argv,
        } => exec_cmd::run_oneshot(exec_cmd::OneshotParams {
            template,
            cpus,
            memory: &memory,
            add_dir: &add_dir,
            env: &env,
            timeout,
            launch_plan,
            argv,
        }),
    };

    with_hints(result)
}

// ============================================================================
// Tests
// ============================================================================
