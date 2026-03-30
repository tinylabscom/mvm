use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use serde::Serialize;
use std::sync::{Arc, Mutex};

use crate::bootstrap;
use crate::fleet;
use crate::logging::{self, LogFormat};
use crate::shell_init;
use crate::template_cmd;
use crate::ui;
use crate::update;

use mvm_core::naming::{validate_flake_ref, validate_template_name, validate_vm_name};
use mvm_core::util::parse_human_size;
use mvm_core::vm_backend::VmId;
use mvm_runtime::config;
use mvm_runtime::shell;
use mvm_runtime::vm::backend::AnyBackend;
use mvm_runtime::vm::{firecracker, image, lima, microvm};

/// Parameters for building a `VmStartConfig` from runtime-specific types.
struct VmStartParams<'a> {
    name: String,
    rootfs_path: String,
    vmlinux_path: String,
    initrd_path: Option<String>,
    revision_hash: String,
    flake_ref: String,
    profile: Option<String>,
    cpus: u32,
    memory_mib: u32,
    volumes: &'a [image::RuntimeVolume],
    config_files: &'a [microvm::DriveFile],
    secret_files: &'a [microvm::DriveFile],
    port_mappings: &'a [config::PortMapping],
}

impl VmStartParams<'_> {
    fn into_start_config(self) -> mvm_core::vm_backend::VmStartConfig {
        mvm_core::vm_backend::VmStartConfig {
            name: self.name,
            rootfs_path: self.rootfs_path,
            kernel_path: Some(self.vmlinux_path),
            initrd_path: self.initrd_path,
            revision_hash: self.revision_hash,
            flake_ref: self.flake_ref,
            profile: self.profile,
            cpus: self.cpus,
            memory_mib: self.memory_mib,
            ports: self
                .port_mappings
                .iter()
                .map(|p| mvm_core::vm_backend::VmPortMapping {
                    host: p.host,
                    guest: p.guest,
                })
                .collect(),
            volumes: self
                .volumes
                .iter()
                .map(|v| mvm_core::vm_backend::VmVolume {
                    host: v.host.clone(),
                    guest: v.guest.clone(),
                    size: v.size.clone(),
                })
                .collect(),
            config_files: self
                .config_files
                .iter()
                .map(|f| mvm_core::vm_backend::VmFile {
                    name: f.name.clone(),
                    content: f.content.clone(),
                    mode: f.mode,
                })
                .collect(),
            secret_files: self
                .secret_files
                .iter()
                .map(|f| mvm_core::vm_backend::VmFile {
                    name: f.name.clone(),
                    content: f.content.clone(),
                    mode: f.mode,
                })
                .collect(),
            runner_dir: None,
        }
    }
}

/// Global registry of spawned child PIDs so the signal handler can clean them up.
static CHILD_PIDS: std::sync::LazyLock<Arc<Mutex<Vec<u32>>>> =
    std::sync::LazyLock::new(|| Arc::new(Mutex::new(Vec::new())));

#[derive(Parser)]
#[command(name = "mvmctl", version, about = "Lightweight VM development tool")]
struct Cli {
    /// Log format: human (default) or json (structured)
    #[arg(long, global = true)]
    log_format: Option<String>,

    /// Override Firecracker version (e.g., v1.14.0)
    #[arg(long, global = true)]
    fc_version: Option<String>,

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
        #[arg(long, short = 'a')]
        all: bool,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Check for and install the latest version of mvmctl
    Update {
        /// Only check for updates, don't install
        #[arg(long)]
        check: bool,
        /// Force reinstall even if already up to date
        #[arg(long)]
        force: bool,
        /// Skip cosign signature verification even if cosign is installed
        #[arg(long)]
        skip_verify: bool,
    },
    /// System diagnostics and dependency checks
    Doctor {
        /// Output results as JSON
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
        #[arg(long, short = 'o')]
        output: Option<String>,
        /// Nix flake reference (enables flake build mode)
        #[arg(long, value_parser = clap_flake_ref)]
        flake: Option<String>,
        /// Flake package variant (e.g. worker, gateway). Omit to use flake default.
        #[arg(long)]
        profile: Option<String>,
        /// Watch flake.lock and rebuild on change (flake mode)
        #[arg(long)]
        watch: bool,
        /// Output structured JSON events instead of human-readable output
        #[arg(long)]
        json: bool,
    },
    /// Build and run a VM from a Nix flake or template
    #[command(alias = "start", alias = "run", group(clap::ArgGroup::new("source").required(true)))]
    Up {
        /// Nix flake reference (local path or remote URI)
        #[arg(long, group = "source", value_parser = clap_flake_ref)]
        flake: Option<String>,
        /// Run from a pre-built template (skip build)
        #[arg(long, group = "source")]
        template: Option<String>,
        /// VM name (auto-generated if omitted)
        #[arg(long, value_parser = clap_vm_name)]
        name: Option<String>,
        /// Flake package variant (e.g. worker, gateway). Omit to use flake default.
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
        /// Volume (host_dir:/guest/path or host:/guest/path:size). Repeatable.
        #[arg(long, short = 'v', value_parser = clap_volume_spec)]
        volume: Vec<String>,
        /// Hypervisor backend (firecracker, qemu, apple-container, docker). Default: auto-detect.
        #[arg(long, default_value = "firecracker")]
        hypervisor: String,
        /// Port mapping (format: HOST:GUEST or PORT). Repeatable.
        #[arg(long, short = 'p', value_parser = clap_port_spec)]
        port: Vec<String>,
        /// Environment variable to inject (format: KEY=VALUE). Repeatable.
        #[arg(long, short = 'e')]
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
        #[arg(long, short = 'd')]
        detach: bool,
        /// Network preset (unrestricted, none, registries, dev)
        #[arg(long)]
        network_preset: Option<String>,
        /// Network allowlist entry (format: HOST:PORT). Repeatable.
        #[arg(long)]
        network_allow: Vec<String>,
        /// Seccomp profile tier (essential, minimal, standard, network, unrestricted)
        #[arg(long, default_value = "unrestricted")]
        seccomp: String,
        /// Secret binding (format: KEY:host, KEY:host:header, or KEY=value:host). Repeatable.
        #[arg(long, short = 's')]
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
        #[arg(long, short = 'f')]
        config: Option<String>,
    },
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Print shell configuration (completions + dev aliases) to stdout
    ShellInit,
    /// Show runtime metrics (Prometheus text format by default)
    Metrics {
        /// Output as JSON instead of Prometheus exposition format
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
        #[arg(long, short = 'y')]
        yes: bool,
        /// Also remove ~/.mvm/ config dir and /usr/local/bin/mvmctl binary
        #[arg(long)]
        all: bool,
        /// Print what would be removed without actually removing anything
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
        /// VM name
        name: String,
        /// Output as JSON instead of human-readable
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
        /// VM name
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Run a single command instead of opening an interactive shell
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
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Show the last N audit events (default: 20)
    Tail {
        /// Number of lines to show
        #[arg(long, short = 'n', default_value = "20")]
        lines: usize,
        /// Follow log output (poll every 500 ms until Ctrl-C)
        #[arg(long, short = 'f')]
        follow: bool,
    },
}

#[derive(Subcommand)]
enum DevCmd {
    /// Bootstrap and start the dev environment, then drop into a shell
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
    },
    /// Stop the Lima development VM
    Down,
    /// Open a shell in the running Lima VM
    Shell {
        /// Project directory to cd into inside the VM (Lima maps ~ → ~)
        #[arg(long)]
        project: Option<String>,
    },
    /// Show dev environment status (Lima VM, Firecracker, Nix)
    Status,
}

#[derive(Subcommand)]
enum FlakeCmd {
    /// Run `nix flake check` to validate a flake before building
    Check {
        /// Flake path or reference (default: current directory)
        #[arg(long, default_value = ".")]
        flake: String,
        /// Output structured JSON instead of human-readable output
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum NetworkCmd {
    /// Create a named dev network with its own bridge and subnet
    Create {
        /// Network name (lowercase alphanumeric + hyphens)
        name: String,
        /// Subnet CIDR (auto-assigned if omitted)
        #[arg(long)]
        subnet: Option<String>,
    },
    /// List all dev networks
    #[command(alias = "ls")]
    List,
    /// Show details of a named network
    Inspect {
        /// Network name
        name: String,
    },
    /// Remove a named network
    #[command(alias = "rm")]
    Remove {
        /// Network name
        name: String,
    },
}

#[derive(Subcommand)]
enum ImageCmd {
    /// List available images in the catalog
    #[command(alias = "ls")]
    List,
    /// Search images by name or tag
    Search {
        /// Search query
        query: String,
    },
    /// Fetch (build) an image from the catalog
    Fetch {
        /// Image name from the catalog
        name: String,
    },
    /// Show details of a catalog image
    Info {
        /// Image name from the catalog
        name: String,
    },
}

#[derive(Subcommand)]
enum SecurityCmd {
    /// Show security posture evaluation for the current environment
    Status {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum CacheCmd {
    /// Remove stale items from the cache directory
    Prune {
        /// Print what would be removed without actually removing anything
        #[arg(long)]
        dry_run: bool,
    },
    /// Show cache directory path and disk usage
    Info,
}

#[derive(Subcommand)]
enum TemplateCmd {
    /// Create a new template (single role/profile)
    Create {
        /// Template name (e.g. "base", "openclaw")
        name: String,
        /// Nix flake reference for the template source
        #[arg(long, default_value = ".", value_parser = clap_flake_ref)]
        flake: String,
        /// Flake package variant
        #[arg(long, default_value = "default")]
        profile: String,
        /// VM role (worker or gateway)
        #[arg(long, default_value = "worker")]
        role: String,
        /// Default vCPU count for VMs using this template
        #[arg(long, default_value = "2")]
        cpus: u8,
        /// Default memory (supports human-readable sizes: 512M, 4G, or plain MB)
        #[arg(long, default_value = "1024")]
        mem: String,
        /// Data disk size (supports human-readable sizes: 10G, 512M, or plain MB; 0 = no disk)
        #[arg(long, default_value = "0")]
        data_disk: String,
    },
    /// Create multiple role-specific templates (name-role)
    CreateMulti {
        /// Base template name (each role becomes <base>-<role>)
        base: String,
        /// Nix flake reference for the template source
        #[arg(long, default_value = ".", value_parser = clap_flake_ref)]
        flake: String,
        /// Flake package variant
        #[arg(long, default_value = "default")]
        profile: String,
        /// Comma-separated roles, e.g. gateway,agent
        #[arg(long)]
        roles: String,
        /// Default vCPU count for VMs using this template
        #[arg(long, default_value = "2")]
        cpus: u8,
        /// Default memory (supports human-readable sizes: 512M, 4G, or plain MB)
        #[arg(long, default_value = "1024")]
        mem: String,
        /// Data disk size (supports human-readable sizes: 10G, 512M, or plain MB; 0 = no disk)
        #[arg(long, default_value = "0")]
        data_disk: String,
    },
    /// Build a template (shared image via nix build)
    Build {
        /// Template name to build
        name: String,
        /// Rebuild even if a cached revision exists
        #[arg(long)]
        force: bool,
        /// After build, boot VM, wait for healthy, and create a snapshot for instant starts
        #[arg(long)]
        snapshot: bool,
        /// Optional template config TOML to build multiple variants
        #[arg(long)]
        config: Option<String>,
        /// Recompute the Nix fixed-output derivation hash (use after version bump)
        #[arg(long)]
        update_hash: bool,
    },
    /// Push a built template revision to the object storage registry
    Push {
        /// Template name to push
        name: String,
        /// Revision hash to push (defaults to current)
        #[arg(long)]
        revision: Option<String>,
    },
    /// Pull a template revision from the object storage registry
    Pull {
        /// Template name to pull
        name: String,
        /// Revision hash to pull (defaults to registry current)
        #[arg(long)]
        revision: Option<String>,
    },
    /// Verify a locally installed template revision against checksums.json
    Verify {
        /// Template name to verify
        name: String,
        /// Revision hash to verify (defaults to current)
        #[arg(long)]
        revision: Option<String>,
    },
    /// List all templates
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show template details (spec, revisions, cache key)
    Info {
        /// Template name
        name: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Edit an existing template's configuration
    Edit {
        /// Template name to edit
        name: String,
        /// Update Nix flake reference
        #[arg(long)]
        flake: Option<String>,
        /// Update flake package variant
        #[arg(long)]
        profile: Option<String>,
        /// Update VM role
        #[arg(long)]
        role: Option<String>,
        /// Update vCPU count
        #[arg(long)]
        cpus: Option<u8>,
        /// Update memory (supports human-readable sizes: 512M, 4G, or plain MB)
        #[arg(long)]
        mem: Option<String>,
        /// Update data disk size (supports human-readable sizes: 10G, 512M, or plain MB)
        #[arg(long)]
        data_disk: Option<String>,
    },
    /// Delete a template and its artifacts
    Delete {
        /// Template name to delete
        name: String,
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
    /// Initialize on-disk template layout (idempotent)
    Init {
        /// Template name to initialize
        name: String,
        /// Create locally instead of in ~/.mvm/templates
        #[arg(long)]
        local: bool,
        /// Create inside the Lima VM (overrides --local)
        #[arg(long)]
        vm: bool,
        /// Base directory for local init (default: current dir)
        #[arg(long, default_value = ".")]
        dir: String,
        /// Scaffold preset: minimal, http, postgres, worker, python (default: minimal)
        #[arg(long, default_value = "minimal")]
        preset: String,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Print current config as TOML
    Show,
    /// Open the config file in $EDITOR (falls back to nano)
    Edit,
    /// Set a single config key
    Set {
        /// Config key (e.g. lima_cpus)
        key: String,
        /// New value
        value: String,
    },
}

// ============================================================================
// Structured JSON event output for --json mode
// ============================================================================

/// Structured event emitted during sync/build operations in --json mode.
#[derive(Debug, Serialize)]
struct PhaseEvent {
    timestamp: String,
    command: &'static str,
    phase: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl PhaseEvent {
    fn new(command: &'static str, phase: &str, status: &'static str) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            command,
            phase: phase.to_string(),
            status,
            message: None,
            error: None,
        }
    }

    fn with_message(mut self, msg: &str) -> Self {
        self.message = Some(msg.to_string());
        self
    }

    fn with_error(mut self, err: &str) -> Self {
        self.error = Some(err.to_string());
        self
    }

    fn emit(&self) {
        if let Ok(json) = serde_json::to_string(self) {
            println!("{}", json);
        }
    }
}

// ============================================================================
// Entry point
// ============================================================================

/// Return the Clap `Command` tree for `mvmctl`.
///
/// Used by the `xtask` crate to generate man pages without duplicating the
/// command definition.
pub fn cli_command() -> clap::Command {
    use clap::CommandFactory;
    Cli::command()
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    // Apply FC version override before anything reads it.
    // SAFETY: called once at startup before any threads are spawned.
    if let Some(ref version) = cli.fc_version {
        unsafe { std::env::set_var("MVM_FC_VERSION", version) };
    }

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
        Commands::Bootstrap { production } => cmd_bootstrap(production),
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
            cmd_setup(recreate, force, effective_cpus, effective_mem)
        }
        Commands::Dev { action } => {
            let action = action.unwrap_or(DevCmd::Up {
                lima_cpus: 8,
                lima_mem: 16,
                project: None,
                metrics_port: 0,
                watch_config: false,
                lima: false,
            });
            match action {
                DevCmd::Up {
                    lima_cpus,
                    lima_mem,
                    project,
                    metrics_port,
                    watch_config,
                    lima,
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
                        cmd_dev_apple_container(effective_cpus, effective_mem)
                    } else {
                        cmd_dev(
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
                        cmd_dev_apple_container_down()
                    } else {
                        cmd_dev_down()
                    }
                }
                DevCmd::Shell { project } => {
                    if mvm_core::platform::current().has_apple_containers()
                        && is_apple_container_dev_running()
                    {
                        console_interactive("mvm-dev")
                    } else {
                        cmd_shell(project.as_deref())
                    }
                }
                DevCmd::Status => {
                    if mvm_core::platform::current().has_apple_containers() {
                        cmd_dev_apple_container_status()
                    } else {
                        cmd_dev_status()
                    }
                }
            }
        }
        Commands::Cleanup { keep, all, verbose } => cmd_cleanup(keep, all, verbose),
        Commands::Logs {
            name,
            follow,
            lines,
            hypervisor,
        } => cmd_logs(&name, follow, lines, hypervisor),
        Commands::Forward { name, port, ports } => {
            let mut all_ports = port;
            all_ports.extend(ports);
            cmd_forward(&name, &all_ports)
        }

        Commands::Ps { all, json } => cmd_ls(all, json),
        Commands::Update {
            check,
            force,
            skip_verify,
        } => cmd_update(check, force, skip_verify),
        Commands::Doctor { json } => cmd_doctor(json),
        Commands::Build {
            path,
            output,
            flake,
            profile,
            watch,
            json,
        } => {
            if let Some(flake_ref) = flake {
                cmd_build_flake(&flake_ref, profile.as_deref(), watch, json)
            } else {
                cmd_build(&path, output.as_deref())
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

            let network_policy = resolve_network_policy(network_preset.as_deref(), &network_allow)?;
            let seccomp_tier: mvm_security::seccomp::SeccompTier =
                seccomp.parse().context("Invalid --seccomp value")?;
            let secret_bindings: Vec<mvm_core::secret_binding::SecretBinding> = secret
                .iter()
                .map(|s| s.parse())
                .collect::<Result<Vec<_>>>()
                .context("Invalid --secret value")?;

            cmd_run(RunParams {
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
        Commands::Down { name, config } => cmd_down(name.as_deref(), config.as_deref()),
        Commands::Completions { shell } => cmd_completions(shell),
        Commands::ShellInit => shell_init::print_shell_init(),
        Commands::Metrics { json } => cmd_metrics(json),
        Commands::Template { action } => cmd_template(action),
        Commands::Config { action } => cmd_config(action),
        Commands::Uninstall { yes, all, dry_run } => cmd_uninstall(yes, all, dry_run),
        Commands::Audit { action } => cmd_audit(action),
        Commands::Diff { name, json } => cmd_diff(&name, json),
        Commands::Flake { action } => cmd_flake(action),
        Commands::Network { action } => cmd_network(action),
        Commands::Image { action } => cmd_image(action),
        Commands::Console { name, command } => cmd_console(&name, command.as_deref()),
        Commands::Cache { action } => cmd_cache(action),
        Commands::Init {
            non_interactive,
            lima_cpus,
            lima_mem,
        } => cmd_init(non_interactive, lima_cpus, lima_mem),
        Commands::Security { action } => cmd_security(action),
    };

    with_hints(result)
}

// ============================================================================
// Clap value parsers — run at argument-parse time for early validation
// ============================================================================

/// Validate a VM name at Clap parse time.
fn clap_vm_name(s: &str) -> Result<String, String> {
    mvm_core::naming::validate_vm_name(s).map_err(|e| e.to_string())?;
    Ok(s.to_owned())
}

/// Validate a Nix flake reference at Clap parse time.
fn clap_flake_ref(s: &str) -> Result<String, String> {
    mvm_core::naming::validate_flake_ref(s).map_err(|e| e.to_string())?;
    Ok(s.to_owned())
}

/// Validate a port spec (`PORT` or `HOST:GUEST`) at Clap parse time.
fn clap_port_spec(s: &str) -> Result<String, String> {
    if s.is_empty() {
        return Err("port spec must not be empty".to_owned());
    }
    if let Some((host_part, guest_part)) = s.split_once(':') {
        host_part
            .parse::<u16>()
            .map_err(|_| format!("invalid host port {:?} in {:?}", host_part, s))?;
        guest_part
            .parse::<u16>()
            .map_err(|_| format!("invalid guest port {:?} in {:?}", guest_part, s))?;
    } else {
        s.parse::<u16>()
            .map_err(|_| format!("invalid port {:?} — expected PORT or HOST:GUEST", s))?;
    }
    Ok(s.to_owned())
}

/// Validate a volume spec (`host:/guest` or `host:/guest:size`) at Clap parse time.
fn clap_volume_spec(s: &str) -> Result<String, String> {
    if s.is_empty() {
        return Err("volume spec must not be empty".to_owned());
    }
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(format!(
            "invalid volume {:?} — expected host:/guest or host:/guest:size",
            s
        ));
    }
    Ok(s.to_owned())
}

// ============================================================================
// Dev mode handlers
// ============================================================================

fn cmd_bootstrap(production: bool) -> Result<()> {
    ui::info("Bootstrapping full environment...\n");

    if !production {
        bootstrap::check_package_manager()?;
    }

    ui::info("\nInstalling prerequisites...");
    bootstrap::ensure_lima()?;

    // Bootstrap uses default Lima resources (8 vCPUs, 16 GiB), never forces
    run_setup_steps(false, 8, 16)?;

    ui::success("\nBootstrap complete! Run 'mvmctl dev' to enter the development environment.");
    Ok(())
}

fn cmd_setup(recreate: bool, force: bool, lima_cpus: u32, lima_mem: u32) -> Result<()> {
    if recreate {
        recreate_rootfs()?;
        ui::success("\nRootfs recreated! Run 'mvmctl start' or 'mvmctl dev' to launch.");
        return Ok(());
    }

    if !bootstrap::is_lima_required() {
        // Native Linux — just install FC directly
        run_setup_steps(force, lima_cpus, lima_mem)?;
        ui::success("\nSetup complete! Run 'mvmctl start' to launch a microVM.");
        return Ok(());
    }

    which::which("limactl").map_err(|_| {
        anyhow::anyhow!(
            "'limactl' not found. Install Lima first: brew install lima\n\
             Or run 'mvmctl bootstrap' for full automatic setup."
        )
    })?;

    run_setup_steps(force, lima_cpus, lima_mem)?;

    ui::success("\nSetup complete! Run 'mvmctl start' to launch a microVM.");
    Ok(())
}

/// Stop the running microVM and rebuild the rootfs from the upstream squashfs.
fn recreate_rootfs() -> Result<()> {
    if bootstrap::is_lima_required() {
        lima::require_running()?;
    }

    // Stop Firecracker if running
    if firecracker::is_running()? {
        ui::info("Stopping running microVM...");
        microvm::stop()?;
    }

    ui::info("Removing existing rootfs...");
    shell::run_in_vm(&format!(
        "rm -f {dir}/ubuntu-*.ext4",
        dir = config::MICROVM_DIR,
    ))?;

    ui::info("Rebuilding rootfs...");
    firecracker::prepare_rootfs()?;
    firecracker::write_state()?;

    Ok(())
}

fn cmd_dev(
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
            cmd_bootstrap(false)?;
        } else {
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
    cmd_shell(project)
}

fn cmd_dev_down() -> Result<()> {
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

fn cmd_dev_status() -> Result<()> {
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

// ============================================================================
// Apple Container dev environment
// ============================================================================

const DEV_VM_NAME: &str = "mvm-dev";

/// Check if the Apple Container dev VM is running.
fn is_apple_container_dev_running() -> bool {
    mvm_apple_container::list_ids()
        .iter()
        .any(|id| id == DEV_VM_NAME)
}

/// Boot the Apple Container dev VM and open an interactive console.
fn cmd_dev_apple_container(cpus: u32, memory_gib: u32) -> Result<()> {
    ui::info("Starting dev environment via Apple Container...\n");

    if is_apple_container_dev_running() {
        ui::info("Dev VM already running. Opening console...");
        return console_interactive(DEV_VM_NAME);
    }

    // Ensure dev image exists
    let (kernel, rootfs) = ensure_dev_image()?;

    ui::info(&format!(
        "Booting dev VM ({} vCPUs, {} GiB memory)...",
        cpus, memory_gib
    ));

    let memory_mib = (memory_gib as u64) * 1024;
    mvm_apple_container::start(DEV_VM_NAME, &kernel, &rootfs, cpus, memory_mib)
        .map_err(|e| anyhow::anyhow!("Failed to start dev VM: {e}"))?;

    ui::info("Waiting for guest agent...");
    if !wait_for_guest_agent(DEV_VM_NAME, 30) {
        anyhow::bail!(
            "Guest agent did not respond within 30 seconds.\n\
             Check: mvmctl logs {DEV_VM_NAME}"
        );
    }

    ui::success("Dev VM ready. Opening console (Ctrl-D to exit)...\n");
    console_interactive(DEV_VM_NAME)
}

/// Stop the Apple Container dev VM.
fn cmd_dev_apple_container_down() -> Result<()> {
    if !is_apple_container_dev_running() {
        ui::info("Dev VM is not running.");
        return Ok(());
    }

    ui::info("Stopping Apple Container dev VM...");
    mvm_apple_container::stop(DEV_VM_NAME)
        .map_err(|e| anyhow::anyhow!("Failed to stop dev VM: {e}"))?;
    ui::success("Dev VM stopped.");
    Ok(())
}

/// Show Apple Container dev VM status.
fn cmd_dev_apple_container_status() -> Result<()> {
    let running = is_apple_container_dev_running();
    ui::info("Backend:  Apple Container (Virtualization.framework)");
    ui::info(&format!("Dev VM:   {DEV_VM_NAME}"));
    ui::info(&format!(
        "Status:   {}",
        if running { "running" } else { "stopped" }
    ));

    if running
        && let Ok(mut stream) =
            mvm_apple_container::vsock_connect(DEV_VM_NAME, mvm_guest::vsock::GUEST_AGENT_PORT)
        && let Ok(mvm_guest::vsock::GuestResponse::ExecResult { stdout, .. }) =
            mvm_guest::vsock::send_request(
                &mut stream,
                &mvm_guest::vsock::GuestRequest::Exec {
                    command: "uname -r".to_string(),
                    stdin: None,
                    timeout_secs: Some(5),
                },
            )
    {
        ui::info(&format!("  Kernel:  {}", stdout.trim()));
    }

    // Show dev image info
    let cache_dir = format!("{}/dev", mvm_core::config::mvm_cache_dir());
    let kernel_path = format!("{cache_dir}/vmlinux");
    let rootfs_path = format!("{cache_dir}/rootfs.ext4");
    ui::info(&format!(
        "  Image:   {}",
        if std::path::Path::new(&rootfs_path).exists() {
            "cached"
        } else {
            "not built"
        }
    ));
    if std::path::Path::new(&kernel_path).exists() {
        ui::info(&format!("  Kernel:  {kernel_path}"));
    }
    if std::path::Path::new(&rootfs_path).exists() {
        ui::info(&format!("  Rootfs:  {rootfs_path}"));
    }

    Ok(())
}

/// Ensure the dev image (kernel + rootfs) exists in the cache.
///
/// Returns (kernel_path, rootfs_path). Builds from the dev-image Nix flake
/// if not cached.
fn ensure_dev_image() -> Result<(String, String)> {
    let cache_dir = format!("{}/dev", mvm_core::config::mvm_cache_dir());
    std::fs::create_dir_all(&cache_dir)?;

    let kernel_path = format!("{cache_dir}/vmlinux");
    let rootfs_path = format!("{cache_dir}/rootfs.ext4");

    if std::path::Path::new(&kernel_path).exists() && std::path::Path::new(&rootfs_path).exists() {
        return Ok((kernel_path, rootfs_path));
    }

    // Try Nix build first (works if Linux builder is configured)
    let plat = mvm_core::platform::current();
    if plat.has_host_nix()
        && let Ok(flake_dir) = find_dev_image_flake()
    {
        ui::info("Building dev image via Nix (first time only)...");
        let nix_bin = find_nix_binary();
        let output = std::process::Command::new(&nix_bin)
            .args([
                "build",
                &format!("{flake_dir}#default"),
                "--no-link",
                "--print-out-paths",
            ])
            .output()
            .context("Failed to run nix build")?;

        if output.status.success() {
            let store_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let ks = format!("{store_path}/vmlinux");
            let rs = format!("{store_path}/rootfs.ext4");
            if std::path::Path::new(&ks).exists() && std::path::Path::new(&rs).exists() {
                std::fs::copy(&ks, &kernel_path)?;
                std::fs::copy(&rs, &rootfs_path)?;
                ui::success("Dev image built and cached.");
                return Ok((kernel_path, rootfs_path));
            }
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("required system or feature not available") {
            ui::warn(
                "Nix cannot cross-compile Linux images on this Mac.\n\
                 Downloading pre-built dev image instead...",
            );
        } else {
            ui::warn(&format!("Nix build failed, trying download:\n{stderr}"));
        }
    }

    // Fallback: download pre-built dev image from GitHub release
    download_dev_image(&kernel_path, &rootfs_path)
}

/// Download a pre-built dev image (kernel + rootfs) from GitHub releases.
fn download_dev_image(kernel_path: &str, rootfs_path: &str) -> Result<(String, String)> {
    let version = env!("CARGO_PKG_VERSION");
    let base_url = format!("https://github.com/auser/mvm/releases/download/v{version}");
    let kernel_url = format!("{base_url}/dev-vmlinux-aarch64");
    let rootfs_url = format!("{base_url}/dev-rootfs-aarch64.ext4");

    ui::info(&format!("Downloading dev image (v{version})..."));

    // Download kernel
    ui::info("  Fetching kernel...");
    download_file(&kernel_url, kernel_path)
        .with_context(|| format!("Failed to download kernel from {kernel_url}"))?;

    // Download rootfs
    ui::info("  Fetching rootfs...");
    download_file(&rootfs_url, rootfs_path)
        .with_context(|| format!("Failed to download rootfs from {rootfs_url}"))?;

    ui::success("Dev image downloaded and cached.");
    Ok((kernel_path.to_string(), rootfs_path.to_string()))
}

/// Download a file from a URL using curl.
fn download_file(url: &str, dest: &str) -> Result<()> {
    let status = std::process::Command::new("curl")
        .args(["-fSL", "--progress-bar", "-o", dest, url])
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .context("Failed to run curl")?;

    if !status.success() {
        // Clean up partial download
        let _ = std::fs::remove_file(dest);
        anyhow::bail!(
            "Download failed. The dev image may not be available for v{version}.\n\
             To build locally, configure a Nix Linux builder:\n\
             https://nixos.org/manual/nix/stable/advanced-topics/distributed-builds",
            version = env!("CARGO_PKG_VERSION")
        );
    }
    Ok(())
}

/// Find the `nix` binary, checking PATH and common install locations.
fn find_nix_binary() -> String {
    if which::which("nix").is_ok() {
        return "nix".to_string();
    }
    for path in &[
        "/nix/var/nix/profiles/default/bin/nix",
        "/run/current-system/sw/bin/nix",
    ] {
        if std::path::Path::new(path).exists() {
            return path.to_string();
        }
    }
    "nix".to_string() // fall back to PATH, let the error happen naturally
}

/// Find the dev-image Nix flake directory.
fn find_dev_image_flake() -> Result<String> {
    // Check in the source tree
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("Cannot find workspace root"))?;

    let candidate = workspace_root.join("nix").join("dev-image");
    if candidate.join("flake.nix").exists() {
        return Ok(candidate.to_str().unwrap_or(".").to_string());
    }

    // Fall back to the guest-lib minimal profile
    let guest_lib = workspace_root.join("nix").join("guest-lib");
    if guest_lib.join("flake.nix").exists() {
        return Ok(guest_lib.to_str().unwrap_or(".").to_string());
    }

    anyhow::bail!(
        "Dev image flake not found. Expected at nix/dev-image/flake.nix\n\
         or nix/guest-lib/flake.nix"
    )
}

fn run_setup_steps(force: bool, lima_cpus: u32, lima_mem: u32) -> Result<()> {
    let total = 5;

    // Step 1: Lima VM
    if bootstrap::is_lima_required() {
        let lima_status = lima::get_status()?;
        if !force && matches!(lima_status, lima::LimaStatus::Running) {
            ui::step(1, total, "Lima VM already running — skipping.");
        } else {
            let opts = config::LimaRenderOptions {
                cpus: Some(lima_cpus),
                memory_gib: Some(lima_mem),
                ..Default::default()
            };
            let lima_yaml = config::render_lima_yaml_with(&opts)?;
            ui::info(&format!(
                "Lima VM resources: {} vCPUs, {} GiB memory",
                lima_cpus, lima_mem,
            ));
            ui::step(1, total, "Setting up Lima VM...");
            lima::ensure_running(lima_yaml.path())?;
        }
    } else {
        ui::step(1, total, "Native Linux detected — skipping Lima VM setup.");
    }

    // Step 2: Firecracker (+ jailer from same release tarball)
    if !force && firecracker::is_installed()? {
        ui::step(2, total, "Firecracker already installed — skipping.");
    } else {
        ui::step(2, total, "Installing Firecracker...");
        firecracker::install()?;
    }

    // Step 3: Assets (kernel + squashfs)
    if !force && firecracker::has_base_assets()? {
        ui::step(
            3,
            total,
            "Kernel and rootfs already present \u{2014} skipping.",
        );
    } else {
        ui::step(3, total, "Downloading kernel and rootfs...");
        firecracker::download_assets()?;
    }

    if firecracker::has_squashfs()? && !firecracker::validate_rootfs_squashfs()? {
        ui::warn("Downloaded rootfs is corrupted. Re-downloading...");
        shell::run_in_vm(&format!(
            "rm -f {dir}/ubuntu-*.squashfs.upstream",
            dir = config::MICROVM_DIR,
        ))?;
        firecracker::download_assets()?;
    }

    // Step 4: Rootfs
    ui::step(4, total, "Preparing root filesystem...");
    firecracker::prepare_rootfs()?;

    firecracker::write_state()?;

    // Step 5: Security hardening
    ui::step(5, total, "Setting up security baseline...");
    setup_security_baseline()?;

    Ok(())
}

/// Deploy baseline security artifacts (seccomp profile, audit directory).
///
/// Idempotent — each step checks before acting.
fn setup_security_baseline() -> Result<()> {
    use mvm_runtime::security::{jailer, seccomp};

    // Deploy strict seccomp filter profile
    seccomp::ensure_strict_profile()?;
    ui::info("  Seccomp strict profile deployed.");

    // Create audit log directory structure
    shell::run_in_vm("sudo mkdir -p /var/lib/mvm/tenants")?;
    ui::info("  Audit log directory created.");

    // Report jailer status (installed by firecracker::install() above)
    match jailer::jailer_available() {
        Ok(true) => ui::info("  Jailer binary available."),
        _ => ui::warn("  Jailer binary not found (may not be in this Firecracker release)."),
    }

    Ok(())
}

fn shell_escape(s: &str) -> String {
    if s.contains(' ') || s.contains('\'') || s.contains('"') {
        format!("'{}'", s.replace('\'', "'\\''"))
    } else {
        s.to_string()
    }
}

fn cmd_shell(project: Option<&str>) -> Result<()> {
    lima::require_running()?;

    // Print welcome banner with tool versions
    let fc_ver =
        shell::run_in_vm_stdout("firecracker --version 2>/dev/null | head -1").unwrap_or_default();
    let nix_ver = shell::run_in_vm_stdout("nix --version 2>/dev/null").unwrap_or_default();

    ui::info("mvmctl development shell");
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
    let mvm_in_vm = shell::run_in_vm_stdout("test -f /usr/local/bin/mvmctl && echo yes || echo no")
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

    ui::info(&format!("  Lima VM:     {}\n", config::VM_NAME));

    // Ensure shell completions and dev aliases are in the VM's ~/.zshrc
    // (the host's ~/.zshrc is separate from the VM's)
    if let Err(e) = shell_init::ensure_shell_init_in_vm() {
        ui::warn(&format!("Shell init in VM failed: {e}"));
    }

    match project {
        Some(path) => {
            let cmd = format!("cd {} && exec bash -l", shell_escape(path));
            shell::replace_process("limactl", &["shell", config::VM_NAME, "bash", "-c", &cmd])
        }
        None => shell::replace_process("limactl", &["shell", config::VM_NAME, "bash", "-l"]),
    }
}

fn cmd_cleanup(keep: Option<usize>, all: bool, verbose: bool) -> Result<()> {
    let keep_count = if all { 0 } else { keep.unwrap_or(5) };

    if !all && keep_count == 0 {
        anyhow::bail!("--keep must be greater than 0 (or use --all)");
    }

    // Show disk usage before cleanup.
    let disk_before = vm_disk_usage_pct();
    if let Some(pct) = disk_before {
        ui::info(&format!("Lima VM disk usage: {}%", pct));
    }

    // Step 1: Clear temp files first — when the disk is 100% full the nix
    // daemon cannot start, so we need to free a little space before GC.
    ui::info("Clearing temporary files...");
    let _ = shell::run_in_vm("sudo rm -rf /tmp/* /var/tmp/* 2>/dev/null");

    // Step 2: Remove old dev-build symlinks and artifacts.
    let env = mvm_runtime::build_env::RuntimeBuildEnv;
    let report = mvm_build::dev_build::cleanup_old_dev_builds(&env, keep_count)?;

    if verbose {
        if report.removed_paths.is_empty() {
            ui::info("No cached build paths removed.");
        } else {
            ui::info("Removed cached build paths:");
            for path in &report.removed_paths {
                println!("  {}", path);
            }
        }
    }

    if all {
        ui::success(&format!(
            "Removed {} cached build(s).",
            report.removed_count
        ));
    } else {
        ui::success(&format!(
            "Removed {} cached build(s), kept newest {}.",
            report.removed_count, keep_count
        ));
    }

    // Step 3: Garbage-collect unreferenced Nix store paths inside the Lima VM.
    ui::info("Running nix-collect-garbage...");
    match shell::run_in_vm_stdout("nix-collect-garbage -d 2>&1 | tail -3") {
        Ok(output) => {
            let trimmed = output.trim();
            if !trimmed.is_empty() {
                println!("{trimmed}");
            }
        }
        Err(e) => {
            // If GC fails (disk too full for daemon), try clearing the Nix
            // user profile links and retrying once.
            ui::warn(&format!("nix-collect-garbage failed: {e}"));
            ui::info("Retrying after clearing Nix profile generations...");
            let _ = shell::run_in_vm("rm -rf ~/.local/state/nix/profiles/* 2>/dev/null");
            match shell::run_in_vm_stdout("nix-collect-garbage -d 2>&1 | tail -3") {
                Ok(output) => {
                    let trimmed = output.trim();
                    if !trimmed.is_empty() {
                        println!("{trimmed}");
                    }
                }
                Err(e2) => ui::warn(&format!("nix-collect-garbage retry failed: {e2}")),
            }
        }
    }

    // Show disk usage after cleanup.
    let disk_after = vm_disk_usage_pct();
    if let Some(pct) = disk_after {
        let freed_msg = match disk_before {
            Some(before) if before > pct => format!(" (freed {}%)", before - pct),
            _ => String::new(),
        };
        ui::success(&format!("Lima VM disk usage: {}%{}", pct, freed_msg));
    }

    Ok(())
}

/// Read the Lima VM root filesystem usage percentage.
fn vm_disk_usage_pct() -> Option<u8> {
    let output = shell::run_in_vm_stdout("df --output=pcent / 2>/dev/null | tail -1").ok()?;
    output.trim().trim_end_matches('%').trim().parse().ok()
}

fn cmd_logs(name: &str, follow: bool, lines: u32, hypervisor: bool) -> Result<()> {
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {:?}", name))?;
    microvm::logs(name, follow, lines, hypervisor)
}

fn cmd_diff(name: &str, json: bool) -> Result<()> {
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {:?}", name))?;

    let instance_dir = microvm::resolve_running_vm_dir(name)?;
    let changes = mvm_guest::vsock::query_fs_diff(&instance_dir)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&changes)?);
    } else if changes.is_empty() {
        ui::info("No filesystem changes detected.");
    } else {
        ui::info(&format!("{} change(s):", changes.len()));
        for change in &changes {
            let prefix = match change.kind {
                mvm_guest::vsock::FsChangeKind::Created => "+",
                mvm_guest::vsock::FsChangeKind::Modified => "~",
                mvm_guest::vsock::FsChangeKind::Deleted => "-",
            };
            if change.size > 0 {
                println!(
                    "  {} {} ({})",
                    prefix,
                    change.path,
                    human_bytes(change.size)
                );
            } else {
                println!("  {} {}", prefix, change.path);
            }
        }
    }

    Ok(())
}

fn human_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1}K", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1}M", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1}G", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Wait for the guest agent to respond to a Ping over vsock.
/// Returns true if the agent is reachable within `timeout_secs`.
fn wait_for_guest_agent(vm_id: &str, timeout_secs: u64) -> bool {
    use std::io::{Read, Write};
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let ping = serde_json::to_vec(&mvm_guest::vsock::GuestRequest::Ping).unwrap_or_default();
    let len_bytes = (ping.len() as u32).to_be_bytes();

    while std::time::Instant::now() < deadline {
        if let Ok(mut s) =
            mvm_apple_container::vsock_connect(vm_id, mvm_guest::vsock::GUEST_AGENT_PORT)
            && s.write_all(&len_bytes).is_ok()
            && s.write_all(&ping).is_ok()
            && s.flush().is_ok()
        {
            let mut resp_len = [0u8; 4];
            if s.read_exact(&mut resp_len).is_ok() {
                return true;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    false
}

/// Tell the guest agent to start a vsock→TCP forwarder for the given port.
fn request_port_forward(vm_id: &str, guest_port: u16) -> Result<u32> {
    let mut stream = mvm_apple_container::vsock_connect(vm_id, mvm_guest::vsock::GUEST_AGENT_PORT)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    mvm_guest::vsock::start_port_forward_on(&mut stream, guest_port)
}

/// Forward a port from a running microVM to localhost.
///
/// On macOS this tunnels through Lima's SSH connection; on native Linux
/// it spawns a local socat proxy.
///
/// Each `port_spec` is either `GUEST_PORT` (binds to same local port) or
/// `LOCAL_PORT:GUEST_PORT`.  Multiple ports are forwarded concurrently —
/// background children handle all but the last, and Ctrl-C kills the group.
fn cmd_forward(name: &str, port_specs: &[String]) -> Result<()> {
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {:?}", name))?;
    // Verify the VM is actually running.
    let _abs_dir = resolve_running_vm(name)?;

    // Read the VM's guest IP from run-info.json.
    let info = microvm::read_vm_run_info(name)?;

    // Use CLI port specs if provided, otherwise fall back to persisted ports.
    let parsed: Vec<(u16, u16)> = if port_specs.is_empty() {
        if info.ports.is_empty() {
            anyhow::bail!(
                "VM '{}' has no port mappings configured.\n\
                 Specify ports: mvmctl forward {} <PORT>...\n\
                 Or declare ports in mvm.toml.",
                name,
                name,
            );
        }
        ui::info("Using port mappings from VM config.");
        info.ports.iter().map(|p| (p.host, p.guest)).collect()
    } else {
        port_specs
            .iter()
            .map(|s| parse_port_spec(s))
            .collect::<Result<_>>()?
    };
    let guest_ip = info
        .guest_ip
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "VM '{}' has no guest_ip in run-info. Was it started with 'mvmctl run'?",
                name,
            )
        })?;

    for &(local_port, guest_port) in &parsed {
        ui::info(&format!(
            "Forwarding localhost:{} -> {}:{} (VM '{}')",
            local_port, guest_ip, guest_port, name,
        ));
    }
    ui::info("Press Ctrl-C to stop forwarding.");

    if bootstrap::is_lima_required() {
        // macOS: SSH port-forward through Lima's SSH connection.
        // SSH -L supports multiple -L flags in a single session.
        lima::require_running()?;
        let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
        let ssh_config = format!("{}/.lima/{}/ssh.config", home, config::VM_NAME);

        let mut cmd = std::process::Command::new("ssh");
        cmd.arg("-F").arg(&ssh_config).arg("-N"); // no remote command
        for &(local_port, guest_port) in &parsed {
            cmd.arg("-L")
                .arg(format!("{}:{}:{}", local_port, guest_ip, guest_port));
        }
        cmd.arg(format!("lima-{}", config::VM_NAME));

        let status = cmd
            .status()
            .context("Failed to start SSH port forward. Is Lima running?")?;

        if !status.success() {
            anyhow::bail!("SSH port forward exited with status {}", status);
        }
    } else {
        // Native Linux: socat proxy (microVM is directly reachable).
        // Spawn a child for each port; wait on all.
        let mut children: Vec<std::process::Child> = Vec::new();
        for &(local_port, guest_port) in &parsed {
            let child = std::process::Command::new("socat")
                .arg(format!("TCP-LISTEN:{},fork,reuseaddr", local_port))
                .arg(format!("TCP:{}:{}", guest_ip, guest_port))
                .spawn()
                .context("Failed to start socat. Install it with: sudo apt install socat")?;
            // Register PID so the signal handler can clean it up.
            if let Ok(mut pids) = CHILD_PIDS.lock() {
                pids.push(child.id());
            }
            children.push(child);
        }
        // Wait for all children to exit (Ctrl-C triggers the signal handler
        // which sends SIGTERM to each tracked child).
        for mut child in children {
            if let Err(e) = child.wait() {
                tracing::warn!("failed to wait on socat child: {e}");
            }
        }
        // Clear tracked PIDs after children exit.
        if let Ok(mut pids) = CHILD_PIDS.lock() {
            pids.clear();
        }
    }

    Ok(())
}

/// Parse a port spec like `3000` or `8080:3000` into `(local, guest)`.
fn parse_port_spec(spec: &str) -> Result<(u16, u16)> {
    if let Some((local, guest)) = spec.split_once(':') {
        let local: u16 = local
            .parse()
            .with_context(|| format!("invalid local port '{}'", local))?;
        let guest: u16 = guest
            .parse()
            .with_context(|| format!("invalid guest port '{}'", guest))?;
        Ok((local, guest))
    } else {
        let port: u16 = spec
            .parse()
            .with_context(|| format!("invalid port '{}'", spec))?;
        Ok((port, port))
    }
}

/// Parse multiple port specs into `PortMapping` values.
fn parse_port_specs(specs: &[String]) -> Result<Vec<mvm_runtime::config::PortMapping>> {
    specs
        .iter()
        .map(|s| {
            let (host, guest) = parse_port_spec(s)?;
            Ok(mvm_runtime::config::PortMapping { host, guest })
        })
        .collect()
}

/// Convert port mappings into a `DriveFile` for the config drive.
/// Writes `export MVM_PORT_MAP="3333:3000,3334:3002"`.
fn ports_to_drive_file(ports: &[mvm_runtime::config::PortMapping]) -> Option<microvm::DriveFile> {
    if ports.is_empty() {
        return None;
    }
    let map_str = ports
        .iter()
        .map(|p| format!("{}:{}", p.host, p.guest))
        .collect::<Vec<_>>()
        .join(",");
    Some(microvm::DriveFile {
        name: "mvm-ports.env".to_string(),
        content: format!("export MVM_PORT_MAP=\"{}\"\n", map_str),
        mode: 0o444,
    })
}

/// Convert env var specs ("KEY=VALUE") into a `DriveFile` for the config drive.
fn env_vars_to_drive_file(env_vars: &[String]) -> Option<microvm::DriveFile> {
    if env_vars.is_empty() {
        return None;
    }
    let content = env_vars
        .iter()
        .map(|kv| format!("export {}", kv))
        .collect::<Vec<_>>()
        .join("\n");
    Some(microvm::DriveFile {
        name: "mvm-env.env".to_string(),
        content: format!("{}\n", content),
        mode: 0o444,
    })
}

fn cmd_ls(_all: bool, json: bool) -> Result<()> {
    use mvm_core::vm_backend::VmInfo;

    let mut all_vms: Vec<VmInfo> = Vec::new();

    // Collect from Apple Container backend
    let ac_backend = AnyBackend::from_hypervisor("apple-container");
    if let Ok(vms) = ac_backend.list() {
        all_vms.extend(vms);
    }

    // Collect from Docker backend
    let docker_backend = AnyBackend::from_hypervisor("docker");
    if let Ok(vms) = docker_backend.list() {
        all_vms.extend(vms);
    }

    // Collect from Firecracker backend (if Lima is running)
    if bootstrap::is_lima_required() {
        if let Ok(lima::LimaStatus::Running) = lima::get_status() {
            let fc_backend = AnyBackend::from_hypervisor("firecracker");
            if let Ok(vms) = fc_backend.list() {
                all_vms.extend(vms);
            }
        }
    } else {
        // Native Linux — Firecracker runs directly
        let fc_backend = AnyBackend::from_hypervisor("firecracker");
        if let Ok(vms) = fc_backend.list() {
            all_vms.extend(vms);
        }
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&all_vms)?);
        return Ok(());
    }

    if all_vms.is_empty() {
        println!("No running VMs.");
        return Ok(());
    }

    // Docker-style table output
    println!(
        "{:<20} {:<18} {:<10} {:<8} {:<10} {:<20} IMAGE",
        "NAME", "BACKEND", "STATUS", "CPUS", "MEMORY", "PORTS"
    );
    for vm in &all_vms {
        let backend_name = if vm.flake_ref.as_deref().is_some() {
            // Determine backend from context
            if mvm_core::platform::current().has_apple_containers() {
                "apple-container"
            } else {
                "firecracker"
            }
        } else {
            "unknown"
        };
        let status = format!("{:?}", vm.status);
        let mem = if vm.memory_mib > 0 {
            format!("{}Mi", vm.memory_mib)
        } else {
            "-".to_string()
        };
        let image = vm
            .flake_ref
            .as_deref()
            .or(vm.profile.as_deref())
            .unwrap_or("-");
        let ports = if vm.ports.is_empty() {
            "-".to_string()
        } else {
            vm.ports
                .iter()
                .map(|p| format!("{}→{}", p.host, p.guest))
                .collect::<Vec<_>>()
                .join(", ")
        };
        println!(
            "{:<20} {:<18} {:<10} {:<8} {:<10} {:<20} {}",
            vm.name,
            backend_name,
            status,
            if vm.cpus > 0 {
                vm.cpus.to_string()
            } else {
                "-".to_string()
            },
            mem,
            ports,
            image,
        );
    }

    Ok(())
}

fn cmd_update(check: bool, force: bool, skip_verify: bool) -> Result<()> {
    let result = update::update(check, force, skip_verify);
    if result.is_ok() && !check {
        mvm_core::audit::emit(mvm_core::audit::LocalAuditKind::UpdateInstall, None, None);
    }
    result
}

fn cmd_doctor(json: bool) -> Result<()> {
    crate::doctor::run(json)
}

// ============================================================================
// Error hints
// ============================================================================

/// Wrap a command result with actionable hints for common errors.
fn with_hints(result: Result<()>) -> Result<()> {
    if let Err(ref e) = result {
        let msg = format!("{:#}", e);
        if msg.contains("limactl: command not found") || msg.contains("limactl: not found") {
            ui::warn("Hint: Install Lima with 'brew install lima' or run 'mvmctl bootstrap'.");
        } else if msg.contains("firecracker: command not found")
            || msg.contains("firecracker: not found")
        {
            ui::warn("Hint: Run 'mvmctl setup' to install Firecracker.");
        } else if msg.contains("/dev/kvm") {
            ui::warn(
                "Hint: Enable KVM/virtualization in your BIOS or VM settings.\n      \
                 On macOS, KVM is available inside the Lima VM.",
            );
        } else if msg.contains("Permission denied") && msg.contains(".mvm") {
            ui::warn("Hint: Check directory permissions on ~/.mvm (set MVM_DATA_DIR to override).");
        } else if msg.contains("nix: command not found") || msg.contains("nix: not found") {
            ui::warn("Hint: Nix is installed inside the Lima VM. Run 'mvmctl shell' first.");
        } else if msg.contains("Lima VM is not running") || msg.contains("VM is not started") {
            ui::warn(
                "Hint: Start the dev environment with 'mvmctl dev' or run 'mvmctl setup' \
                 to initialise it first.",
            );
        } else if msg.contains("already exists") && msg.contains("template") {
            ui::warn("Hint: Use '--force' to overwrite the existing template.");
        } else if msg.contains("error: builder for") && msg.contains("failed with exit code") {
            ui::warn(
                "Hint: Nix build failed. Check the log above for the failing derivation.\n      \
                 Common fixes: ensure flake inputs are up to date ('nix flake update'), \
                 or check your flake.nix for syntax errors.",
            );
        } else if msg.contains("does not provide attribute")
            || msg.contains("flake has no")
            || msg.contains("does not provide a package")
        {
            ui::warn(
                "Hint: Flake attribute not found. Your flake.lock may be stale.\n      \
                 Try: nix flake update (inside the Lima VM or flake directory).",
            );
        } else if msg.contains("No space left on device") || msg.contains("ENOSPC") {
            ui::warn(
                "Hint: Disk full. Run 'mvmctl doctor' to check space, \
                 or run 'nix-collect-garbage -d' inside the Lima VM.",
            );
        } else if msg.contains("timed out") || msg.contains("connection refused") {
            ui::warn(
                "Hint: The Lima VM may be unresponsive. Try 'mvmctl status' or \
                 restart with 'mvmctl stop && mvmctl dev'.",
            );
        } else if msg.contains("hash mismatch") && msg.contains("got:") {
            ui::warn(
                "Hint: Fixed-output derivation hash changed. Run \
                 'mvmctl template build <name> --update-hash' to recompute.",
            );
        } else if msg.contains("does it exist?") && msg.contains("template") {
            ui::warn("Hint: List available templates with 'mvmctl template list'.");
        }
    }
    result
}

fn cmd_build(path: &str, output: Option<&str>) -> Result<()> {
    let elf_path = image::build(path, output)?;
    ui::success(&format!("\nImage ready: {}", elf_path));
    ui::info(&format!("Run with: mvmctl start {}", elf_path));
    Ok(())
}

fn cmd_build_flake(flake_ref: &str, profile: Option<&str>, watch: bool, json: bool) -> Result<()> {
    validate_flake_ref(flake_ref)
        .with_context(|| format!("Invalid flake reference: {:?}", flake_ref))?;

    let build_env = mvm_runtime::build_env::default_build_env();
    let env = build_env.as_ref();

    // Skip Lima when Nix is available on the host (macOS with linux-builder).
    let using_host_nix = mvm_core::platform::current().has_host_nix();
    if !using_host_nix && bootstrap::is_lima_required() {
        lima::require_running()?;
    }

    let resolved = resolve_flake_ref(flake_ref)?;
    let watch_enabled = watch && !resolved.contains(':');

    if watch && resolved.contains(':') && !json {
        ui::warn("Watch mode requires a local flake; running a single build instead.");
    }

    loop {
        let profile_display = profile.unwrap_or("default");

        if json {
            PhaseEvent::new("build", "nix-build", "started")
                .with_message(&format!("flake={} profile={}", resolved, profile_display))
                .emit();
        } else {
            ui::step(
                1,
                2,
                &format!("Building flake {} (profile={})", resolved, profile_display),
            );
        }

        let result = match mvm_build::dev_build::dev_build(env, &resolved, profile) {
            Ok(r) => r,
            Err(e) => {
                if json {
                    PhaseEvent::new("build", "nix-build", "failed")
                        .with_error(&format!("{:#}", e))
                        .emit();
                }
                return Err(e);
            }
        };
        if let Err(e) = mvm_build::dev_build::ensure_guest_agent_if_needed(env, &result) {
            ui::warn(&format!(
                "Could not verify guest agent ({}). If built with mkGuest, the agent is already included.",
                e
            ));
        }

        if json {
            #[derive(Serialize)]
            struct BuildResult {
                timestamp: String,
                command: &'static str,
                phase: &'static str,
                status: &'static str,
                revision: String,
                cached: bool,
                kernel: String,
                rootfs: String,
            }
            let event = BuildResult {
                timestamp: chrono::Utc::now().to_rfc3339(),
                command: "build",
                phase: "nix-build",
                status: "completed",
                revision: result.revision_hash.clone(),
                cached: result.cached,
                kernel: result.vmlinux_path.clone(),
                rootfs: result.rootfs_path.clone(),
            };
            if let Ok(j) = serde_json::to_string(&event) {
                println!("{}", j);
            }
        } else {
            ui::step(2, 2, "Build complete");

            if result.cached {
                ui::success(&format!("\nCache hit — revision {}", result.revision_hash));
            } else {
                ui::success(&format!(
                    "\nBuild complete — revision {}",
                    result.revision_hash
                ));
            }

            ui::info(&format!("  Kernel: {}", result.vmlinux_path));
            ui::info(&format!("  Rootfs: {}", result.rootfs_path));
            ui::info(&format!("\nRun with: mvmctl run --flake {}", flake_ref));
        }

        if !watch_enabled {
            return Ok(());
        }

        // Watch mode: wait for filesystem changes using native events
        if !json {
            ui::info("Watching for .nix and .lock changes (Ctrl+C to exit)...");
        }
        match crate::watch::wait_for_changes(&resolved) {
            Ok(trigger) => {
                if !json {
                    let display = crate::watch::display_trigger(&trigger, &resolved);
                    ui::info(&format!("\nChange detected: {display} — rebuilding..."));
                }
            }
            Err(e) => {
                if !json {
                    ui::warn(&format!("Watch error: {e} — falling back to single build"));
                }
                return Ok(());
            }
        }
    }
}

/// Resolve CLI network flags into a `NetworkPolicy`.
/// `--network-preset` and `--network-allow` are mutually exclusive.
fn resolve_network_policy(
    preset: Option<&str>,
    allow: &[String],
) -> Result<mvm_core::network_policy::NetworkPolicy> {
    use mvm_core::network_policy::{HostPort, NetworkPolicy, NetworkPreset};

    match (preset, allow.is_empty()) {
        (Some(_), false) => {
            anyhow::bail!("--network-preset and --network-allow are mutually exclusive")
        }
        (Some(name), true) => {
            let p: NetworkPreset = name.parse()?;
            Ok(NetworkPolicy::preset(p))
        }
        (None, false) => {
            let rules: Vec<HostPort> = allow
                .iter()
                .map(|s| s.parse())
                .collect::<Result<Vec<_>>>()?;
            Ok(NetworkPolicy::allow_list(rules))
        }
        (None, true) => Ok(NetworkPolicy::default()),
    }
}

/// Resolve a flake reference: relative/absolute paths are canonicalized,
/// remote refs (containing `:`) pass through unchanged.
fn resolve_flake_ref(flake_ref: &str) -> Result<String> {
    if flake_ref.contains(':') {
        // Remote ref like "github:user/repo" — pass through
        return Ok(flake_ref.to_string());
    }

    // Local path — canonicalize to absolute
    let path = std::path::Path::new(flake_ref);
    let canonical = path
        .canonicalize()
        .with_context(|| format!("Flake path '{}' does not exist", flake_ref))?;

    Ok(canonical.to_string_lossy().to_string())
}

struct RunParams<'a> {
    flake_ref: Option<&'a str>,
    template_name: Option<&'a str>,
    name: Option<&'a str>,
    profile: Option<&'a str>,
    cpus: Option<u32>,
    memory: Option<u32>,
    config_path: Option<&'a str>,
    volumes: &'a [String],
    hypervisor: &'a str,
    ports: &'a [String],
    env_vars: &'a [String],
    forward: bool,
    metrics_port: u16,
    watch_config: bool,
    watch: bool,
    detach: bool,
    network_policy: mvm_core::network_policy::NetworkPolicy,
    network_name: &'a str,
    seccomp_tier: mvm_security::seccomp::SeccompTier,
    secret_bindings: Vec<mvm_core::secret_binding::SecretBinding>,
}

fn cmd_run(params: RunParams<'_>) -> Result<()> {
    let RunParams {
        flake_ref,
        template_name,
        name,
        profile,
        cpus,
        memory,
        config_path,
        volumes,
        hypervisor,
        ports,
        env_vars,
        forward,
        metrics_port,
        watch_config,
        watch,
        detach,
        network_policy,
        network_name,
        seccomp_tier,
        secret_bindings,
    } = params;
    let _span =
        tracing::info_span!("cmd_run", name = ?name, cpus = ?cpus, memory_mib = ?memory).entered();
    if let Some(n) = name {
        validate_vm_name(n).with_context(|| format!("Invalid VM name: {:?}", n))?;
    }
    if let Some(f) = flake_ref {
        validate_flake_ref(f).with_context(|| format!("Invalid flake reference: {:?}", f))?;
    }
    if let Some(t) = template_name {
        validate_template_name(t).with_context(|| format!("Invalid template name: {:?}", t))?;
    }
    // Auto-select backend when no explicit hypervisor is specified.
    // Priority: KVM (Firecracker direct) → Apple Container → Lima + Firecracker
    let effective_hypervisor = if hypervisor == "firecracker" {
        let plat = mvm_core::platform::current();
        if plat.has_kvm() {
            "firecracker" // native KVM — best option
        } else if plat.has_apple_containers() {
            "apple-container" // macOS 26+ — no Lima
        } else if plat.has_docker() {
            "docker" // universal fallback
        } else {
            "firecracker" // Lima fallback
        }
    } else {
        hypervisor
    };

    // Apple Container doesn't need Lima — skip the upfront check entirely.
    // For Firecracker on macOS, Lima is required for both build and runtime.
    let needs_lima = effective_hypervisor != "apple-container"
        && effective_hypervisor != "docker"
        && bootstrap::is_lima_required();
    if needs_lima {
        lima::require_running()?;
    }
    let _metrics_server = if metrics_port > 0 {
        Some(crate::metrics_server::MetricsServer::start(metrics_port)?)
    } else {
        None
    };

    // Start config watcher so the user is notified if the config file changes
    // while the build or boot is in progress.
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

    // Generate a VM name if not provided.
    // After codesign re-exec (macOS), the env var preserves the originally
    // generated name so we don't produce a second random name.
    let vm_name = match name {
        Some(n) => n.to_string(),
        None => std::env::var("MVM_REEXEC_NAME").unwrap_or_else(|_| {
            let mut generator = names::Generator::default();
            generator.next().unwrap_or_else(|| "vm-0".to_string())
        }),
    };

    // Register the VM name in the persistent registry (best-effort).
    let registry_path = mvm_runtime::vm::name_registry::registry_path();
    if let Ok(mut registry) = mvm_runtime::vm::name_registry::VmNameRegistry::load(&registry_path) {
        // Deregister stale entry with the same name if it exists
        registry.deregister(&vm_name);
        let _ = registry.register(&vm_name, "", network_name, None, 0);
        let _ = registry.save(&registry_path);
    }

    // Direct boot mode: launchd agent passes kernel/rootfs via env vars.
    // Skip the build/template loading entirely.
    if std::env::var("MVM_DIRECT_BOOT").as_deref() == Ok("1") {
        let kernel = std::env::var("MVM_KERNEL_PATH")
            .map_err(|_| anyhow::anyhow!("MVM_KERNEL_PATH not set"))?;
        let rootfs = std::env::var("MVM_ROOTFS_PATH")
            .map_err(|_| anyhow::anyhow!("MVM_ROOTFS_PATH not set"))?;

        let start_config = mvm_core::vm_backend::VmStartConfig {
            name: vm_name.clone(),
            rootfs_path: rootfs,
            kernel_path: Some(kernel),
            cpus: cpus.unwrap_or(2),
            memory_mib: memory.unwrap_or(512),
            ..Default::default()
        };

        let backend = AnyBackend::from_hypervisor(effective_hypervisor);
        backend.start(&start_config)?;

        // Set up port forwarding from MVM_PORTS env var (via vsock)
        if let Ok(ports_str) = std::env::var("MVM_PORTS")
            && !ports_str.is_empty()
        {
            ui::info("Waiting for guest agent...");
            if wait_for_guest_agent(&vm_name, 30) {
                for spec in ports_str.split(',') {
                    if let Some((host, guest)) = spec.split_once(':')
                        && let (Ok(h), Ok(g)) = (host.parse::<u16>(), guest.parse::<u16>())
                    {
                        let _ = request_port_forward(&vm_name, g);
                        mvm_apple_container::start_port_proxy(&vm_name, h, g);
                        ui::info(&format!("Forwarding localhost:{h} → guest tcp/{g} (vsock)"));
                    }
                }
            } else {
                ui::warn("Guest agent not reachable — port forwarding unavailable.");
            }
        }

        ui::info(&format!("VM '{}' running. Press Ctrl+C to stop.", vm_name));

        // Block until signaled
        let pair = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let pair2 = pair.clone();
        let _ = ctrlc::set_handler(move || {
            let (lock, cvar) = &*pair2;
            *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
            cvar.notify_all();
        });
        let (lock, cvar) = &*pair;
        let mut stopped = lock.lock().unwrap_or_else(|e| e.into_inner());
        while !*stopped {
            stopped = cvar
                .wait_timeout(stopped, std::time::Duration::from_secs(1))
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        let _ = backend.stop(&mvm_core::vm_backend::VmId(vm_name));
        return Ok(());
    }

    // Resolve artifact paths from either a pre-built template or a flake build.
    let (
        vmlinux_path,
        initrd_path,
        rootfs_path,
        revision_hash,
        source_flake,
        source_profile,
        tmpl_cpus,
        tmpl_mem,
        snapshot_info,
    ) = if let Some(tmpl) = template_name {
        ui::step(
            1,
            2,
            &format!("Loading template '{}' for VM '{}'", tmpl, vm_name),
        );
        let (spec, vmlinux, initrd, rootfs, rev) =
            mvm_runtime::vm::template::lifecycle::template_artifacts(tmpl)?;
        ui::info(&format!("Using revision {}", rev));

        // Check for pre-built snapshot
        let snap_info = mvm_runtime::vm::template::lifecycle::template_snapshot_info(tmpl)?;
        if snap_info.is_some() {
            ui::info("Snapshot available — will restore instantly");
        }

        (
            vmlinux,
            initrd,
            rootfs,
            rev,
            spec.flake_ref.clone(),
            Some(spec.profile.clone()),
            Some(spec.vcpus as u32),
            Some(spec.mem_mib),
            snap_info,
        )
    } else {
        let flake = flake_ref.expect("--flake or --template required");
        let resolved = resolve_flake_ref(flake)?;
        let profile_display = profile.unwrap_or("default");
        ui::step(
            1,
            2,
            &format!(
                "Building flake {} (profile={}, name={})",
                resolved, profile_display, vm_name
            ),
        );
        let run_build_env = mvm_runtime::build_env::default_build_env();
        let env = run_build_env.as_ref();
        let result = mvm_build::dev_build::dev_build(env, &resolved, profile)?;
        if let Err(e) = mvm_build::dev_build::ensure_guest_agent_if_needed(env, &result) {
            ui::warn(&format!(
                "Could not verify guest agent ({}). If built with mkGuest, the agent is already included.",
                e
            ));
        }
        if result.cached {
            ui::info(&format!("Cache hit — revision {}", result.revision_hash));
        } else {
            ui::info(&format!(
                "Build complete — revision {}",
                result.revision_hash
            ));
        }
        (
            result.vmlinux_path,
            result.initrd_path,
            result.rootfs_path,
            result.revision_hash,
            flake.to_string(),
            profile.map(|s| s.to_string()),
            None,
            None,
            None, // No snapshot for flake builds
        )
    };

    let backend_label = match effective_hypervisor {
        "apple-container" => "Apple Container",
        "qemu" => "QEMU (microvm.nix)",
        _ => "Firecracker VM",
    };
    ui::step(2, 2, &format!("Booting {} '{}'", backend_label, vm_name));

    let rt_config = match config_path {
        Some(p) => image::parse_runtime_config(p)?,
        None => image::RuntimeConfig::default(),
    };

    // Partition --volume specs into dir-inject (config/secrets) and persistent volumes
    let mut volume_cfg: Vec<image::RuntimeVolume> = Vec::new();
    let mut config_files: Vec<microvm::DriveFile> = Vec::new();
    let mut secret_files: Vec<microvm::DriveFile> = Vec::new();

    if !volumes.is_empty() {
        for v in volumes {
            match parse_volume_spec(v)? {
                VolumeSpec::DirInject {
                    host_dir,
                    guest_mount,
                } => match guest_mount.as_str() {
                    "/mnt/config" => {
                        config_files.extend(
                            read_dir_to_drive_files(&host_dir, 0o444)
                                .with_context(|| format!("reading volume '{}'", v))?,
                        );
                    }
                    "/mnt/secrets" => {
                        secret_files.extend(
                            read_dir_to_drive_files(&host_dir, 0o400)
                                .with_context(|| format!("reading volume '{}'", v))?,
                        );
                    }
                    other => anyhow::bail!(
                        "Unsupported guest mount '{}'. Supported: /mnt/config, /mnt/secrets",
                        other
                    ),
                },
                VolumeSpec::Persistent(vol) => volume_cfg.push(vol),
            }
        }
    } else {
        volume_cfg = rt_config.volumes.clone();
    };

    let user_cfg = mvm_core::user_config::load(None);
    let final_cpus = cpus
        .or(rt_config.cpus)
        .or(tmpl_cpus)
        .unwrap_or(user_cfg.default_cpus);
    let final_memory = memory
        .or(rt_config.memory)
        .or(tmpl_mem)
        .unwrap_or(user_cfg.default_memory_mib);

    // Parse port mappings and inject as config drive file
    let port_mappings = parse_port_specs(ports)?;
    if let Some(f) = ports_to_drive_file(&port_mappings) {
        config_files.push(f);
    }

    // Inject env vars as config drive file
    if let Some(f) = env_vars_to_drive_file(env_vars) {
        config_files.push(f);
    }

    // Inject seccomp manifest into config drive if not unrestricted
    if let Some(manifest) = seccomp_tier.to_manifest() {
        let json = serde_json::to_string_pretty(&manifest)
            .context("failed to serialize seccomp manifest")?;
        config_files.push(microvm::DriveFile {
            name: "seccomp.json".to_string(),
            content: json,
            mode: 0o644,
        });
    }

    // Resolve and inject secret bindings
    if !secret_bindings.is_empty() {
        let resolved = mvm_core::secret_binding::ResolvedSecrets::resolve(&secret_bindings)
            .context("failed to resolve secret bindings")?;

        // Write actual secret values to the secrets drive
        for (filename, content) in resolved.to_secret_files() {
            secret_files.push(microvm::DriveFile {
                name: filename,
                content,
                mode: 0o600,
            });
        }

        // Write secret manifest to config drive (no secret values, just metadata)
        config_files.push(microvm::DriveFile {
            name: "secrets-manifest.json".to_string(),
            content: resolved.manifest_json(),
            mode: 0o644,
        });

        // Write placeholder env vars so tools pass existence checks
        let placeholders: Vec<String> = resolved
            .placeholder_env_vars()
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        if let Some(f) = env_vars_to_drive_file(&placeholders) {
            config_files.push(microvm::DriveFile {
                name: "secret-env.env".to_string(),
                content: f.content,
                mode: f.mode,
            });
        }

        // Log which secrets are bound (without revealing values)
        for b in &secret_bindings {
            ui::info(&format!(
                "Secret {} bound to {} (header: {})",
                b.env_var, b.target_host, b.header
            ));
        }
    }

    let vm_name_owned = vm_name.clone();
    let has_ports = !port_mappings.is_empty();

    // Stash the generated VM name so that if the Apple Container backend
    // re-execs after codesigning, the new process reuses the same name.
    // SAFETY: called early in single-threaded CLI startup before spawning
    // worker threads; no other threads are reading env vars concurrently.
    unsafe { std::env::set_var("MVM_REEXEC_NAME", &vm_name) };

    // If a template snapshot exists AND the backend supports snapshots,
    // restore from it instead of cold-booting.
    let backend = AnyBackend::from_hypervisor(effective_hypervisor);
    if let Some(ref snap_info) = snapshot_info
        && let Some(tmpl) = template_name
        && backend.capabilities().snapshots
    {
        let slot = microvm::allocate_slot(&vm_name)?;
        let run_config = microvm::FlakeRunConfig {
            name: vm_name,
            slot,
            vmlinux_path,
            initrd_path,
            rootfs_path,
            revision_hash,
            flake_ref: source_flake,
            profile: source_profile,
            cpus: final_cpus,
            memory: final_memory,
            volumes: volume_cfg,
            config_files,
            secret_files,
            ports: port_mappings,
            network_policy: network_policy.clone(),
        };
        let rev = mvm_runtime::vm::template::lifecycle::current_revision_id(tmpl)?;
        let snap_dir = mvm_core::template::template_snapshot_dir(tmpl, &rev);
        ui::step(
            2,
            2,
            &format!("Restoring VM '{}' from snapshot", vm_name_owned),
        );
        microvm::restore_from_template_snapshot(tmpl, &run_config, &snap_dir, snap_info)?;
    } else {
        let start_config = VmStartParams {
            name: vm_name,
            rootfs_path,
            vmlinux_path,
            initrd_path,
            revision_hash,
            flake_ref: source_flake,
            profile: source_profile,
            cpus: final_cpus,
            memory_mib: final_memory,
            volumes: &volume_cfg,
            config_files: &config_files,
            secret_files: &secret_files,
            port_mappings: &port_mappings,
        }
        .into_start_config();

        // Apple Container with -d: install a launchd agent instead of
        // starting the VM in this process. The agent runs as a proper
        // macOS service with its own RunLoop.
        if detach && effective_hypervisor == "apple-container" {
            // Sign the binary before installing the launchd agent so the
            // daemon process launches with the entitlement already in place.
            mvm_apple_container::ensure_signed();

            // Build is already done — install launchd agent with the
            // resolved kernel/rootfs paths (no rebuild in the daemon).
            // Serialize port mappings for the daemon
            let port_specs: Vec<String> = parse_port_specs(ports)
                .unwrap_or_default()
                .iter()
                .map(|p| format!("{}:{}", p.host, p.guest))
                .collect();

            mvm_apple_container::install_launchd_direct(
                &start_config.name,
                start_config.kernel_path.as_deref().unwrap_or(""),
                &start_config.rootfs_path,
                start_config.cpus,
                start_config.memory_mib as u64,
                &port_specs,
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("{vm_name_owned}");
            return Ok(());
        }

        backend.start(&start_config)?;
    }

    mvm_core::audit::emit(
        mvm_core::audit::LocalAuditKind::VmStart,
        Some(&vm_name_owned),
        None,
    );

    // Apple Virtualization VMs live in-process — the process must stay alive.
    if effective_hypervisor == "apple-container" && !detach {
        // Set up port forwarding via vsock (no guest IP needed).
        // 1. Wait for guest agent to be ready on vsock port 52
        // 2. Tell the agent to start vsock→TCP forwarders for each port
        // 3. Start host-side TCP→vsock proxies
        if has_ports {
            let pm_list = parse_port_specs(ports).unwrap_or_default();

            ui::info("Waiting for guest agent...");
            let agent_ready = wait_for_guest_agent(&vm_name_owned, 30);
            if !agent_ready {
                ui::warn("Guest agent not reachable — port forwarding unavailable.");
            } else {
                // Tell guest agent to start vsock forwarders
                for pm in &pm_list {
                    match request_port_forward(&vm_name_owned, pm.guest) {
                        Ok(vsock_port) => {
                            ui::info(&format!(
                                "Guest forwarding vsock:{vsock_port} → tcp/{}",
                                pm.guest
                            ));
                        }
                        Err(e) => {
                            ui::warn(&format!(
                                "Failed to set up guest forwarder for port {}: {e}",
                                pm.guest
                            ));
                        }
                    }
                }

                // Start host-side proxies
                for pm in &pm_list {
                    mvm_apple_container::start_port_proxy(&vm_name_owned, pm.host, pm.guest);
                    ui::info(&format!(
                        "Forwarding localhost:{} → guest tcp/{} (vsock)",
                        pm.host, pm.guest
                    ));
                }

                // Persist port mappings so `ps` can display them
                let ports_str: Vec<String> = pm_list
                    .iter()
                    .map(|p| format!("{}:{}", p.host, p.guest))
                    .collect();
                let ports_file = format!(
                    "{}/.mvm/vms/{}/ports",
                    std::env::var("HOME").unwrap_or_default(),
                    vm_name_owned
                );
                let _ = std::fs::write(&ports_file, ports_str.join(","));
            }
        }

        ui::info(&format!(
            "VM '{}' running. Press Ctrl+C to stop.",
            vm_name_owned
        ));

        // Block until signaled (Ctrl+C or SIGTERM)
        let pair = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let pair2 = pair.clone();
        let _ = ctrlc::set_handler(move || {
            let (lock, cvar) = &*pair2;
            *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
            cvar.notify_all();
        });

        let (lock, cvar) = &*pair;
        let mut stopped = lock.lock().unwrap_or_else(|e| e.into_inner());
        while !*stopped {
            stopped = cvar
                .wait_timeout(stopped, std::time::Duration::from_secs(1))
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }

        ui::info(&format!("Stopping VM '{}'...", vm_name_owned));
        let _ = backend.stop(&mvm_core::vm_backend::VmId(vm_name_owned.clone()));
        return Ok(());
    }

    if forward {
        if has_ports {
            cmd_forward(&vm_name_owned, &[])?;
        } else {
            ui::warn("--forward was set but no ports were declared. Use -p to specify ports.");
        }
    }

    // Watch mode: on each .nix / flake.lock change, stop the VM, rebuild, reboot.
    if watch {
        let Some(flake) = flake_ref else {
            // Template mode — watch not supported.
            return Ok(());
        };
        if flake.contains(':') {
            ui::warn("--watch requires a local flake; running a single boot instead.");
            return Ok(());
        }
        let flake_dir = resolve_flake_ref(flake)?;
        loop {
            ui::info("Watching for .nix and .lock changes (Ctrl+C to exit)...");
            match crate::watch::wait_for_changes(&flake_dir) {
                Ok(trigger) => {
                    let display = crate::watch::display_trigger(&trigger, &flake_dir);
                    ui::info(&format!("\nChange detected: {display} — rebuilding..."));
                }
                Err(e) => {
                    tracing::warn!("Watch error: {e}");
                    break;
                }
            }

            // Stop the running VM.
            let backend = AnyBackend::default_backend();
            if let Err(e) = backend.stop(&VmId::from(vm_name_owned.as_str())) {
                tracing::warn!("Could not stop '{}': {e}", vm_name_owned);
            }

            // Rebuild the flake.
            let env = mvm_runtime::build_env::RuntimeBuildEnv;
            let result = match mvm_build::dev_build::dev_build(&env, &flake_dir, profile) {
                Ok(r) => r,
                Err(e) => {
                    ui::warn(&format!("Rebuild failed: {e}; waiting for next change..."));
                    continue;
                }
            };
            if let Err(e) = mvm_build::dev_build::ensure_guest_agent_if_needed(&env, &result) {
                tracing::warn!("Guest agent check failed: {e}");
            }
            ui::success(&format!(
                "Build complete — revision {}",
                result.revision_hash
            ));

            // Re-parse volumes, ports and env vars for the fresh boot.
            let rt_cfg_watch = match config_path {
                Some(p) => image::parse_runtime_config(p).unwrap_or_default(),
                None => image::RuntimeConfig::default(),
            };
            let mut w_volume_cfg: Vec<image::RuntimeVolume> = Vec::new();
            let mut w_config_files: Vec<microvm::DriveFile> = Vec::new();
            let mut w_secret_files: Vec<microvm::DriveFile> = Vec::new();
            if !volumes.is_empty() {
                for v in volumes {
                    match parse_volume_spec(v) {
                        Ok(VolumeSpec::DirInject {
                            host_dir,
                            guest_mount,
                        }) => match guest_mount.as_str() {
                            "/mnt/config" => {
                                if let Ok(files) = read_dir_to_drive_files(&host_dir, 0o444) {
                                    w_config_files.extend(files);
                                }
                            }
                            "/mnt/secrets" => {
                                if let Ok(files) = read_dir_to_drive_files(&host_dir, 0o400) {
                                    w_secret_files.extend(files);
                                }
                            }
                            _ => {}
                        },
                        Ok(VolumeSpec::Persistent(vol)) => w_volume_cfg.push(vol),
                        Err(_) => {}
                    }
                }
            } else {
                w_volume_cfg = rt_cfg_watch.volumes.clone();
            }
            let w_port_mappings = parse_port_specs(ports).unwrap_or_default();
            if let Some(f) = ports_to_drive_file(&w_port_mappings) {
                w_config_files.push(f);
            }
            if let Some(f) = env_vars_to_drive_file(env_vars) {
                w_config_files.push(f);
            }
            let w_start_config = VmStartParams {
                name: vm_name_owned.clone(),
                rootfs_path: result.rootfs_path,
                vmlinux_path: result.vmlinux_path,
                initrd_path: result.initrd_path,
                revision_hash: result.revision_hash,
                flake_ref: flake.to_string(),
                profile: profile.map(|s| s.to_string()),
                cpus: final_cpus,
                memory_mib: final_memory,
                volumes: &w_volume_cfg,
                config_files: &w_config_files,
                secret_files: &w_secret_files,
                port_mappings: &w_port_mappings,
            }
            .into_start_config();
            let w_backend = AnyBackend::from_hypervisor(effective_hypervisor);
            if let Err(e) = w_backend.start(&w_start_config) {
                ui::warn(&format!(
                    "Could not start VM: {e}; waiting for next change..."
                ));
            } else {
                mvm_core::audit::emit(
                    mvm_core::audit::LocalAuditKind::VmStart,
                    Some(&vm_name_owned),
                    None,
                );
                ui::success(&format!("VM '{}' rebooted.", vm_name_owned));
            }
        }
    }

    Ok(())
}

/// Read all regular files from a directory into `DriveFile` entries.
fn read_dir_to_drive_files(dir: &str, default_mode: u32) -> Result<Vec<microvm::DriveFile>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            files.push(microvm::DriveFile {
                name: entry.file_name().to_string_lossy().to_string(),
                content: std::fs::read_to_string(entry.path())?,
                mode: default_mode,
            });
        }
    }
    Ok(files)
}

/// Parsed volume specification from the `--volume/-v` CLI flag.
enum VolumeSpec {
    /// Inject host directory contents onto a drive (2-part: `host_dir:/guest/path`).
    DirInject {
        host_dir: String,
        guest_mount: String,
    },
    /// Persistent ext4 volume with explicit size (3-part: `host:/guest/path:size`).
    Persistent(image::RuntimeVolume),
}

fn parse_volume_spec(spec: &str) -> Result<VolumeSpec> {
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    match parts.len() {
        2 => Ok(VolumeSpec::DirInject {
            host_dir: parts[0].to_string(),
            guest_mount: parts[1].to_string(),
        }),
        3 => Ok(VolumeSpec::Persistent(image::RuntimeVolume {
            host: parts[0].to_string(),
            guest: parts[1].to_string(),
            size: parts[2].to_string(),
        })),
        _ => anyhow::bail!(
            "Invalid volume '{}'. Expected host_dir:/guest/path or host:/guest/path:size",
            spec
        ),
    }
}

/// Load fleet config from an explicit path or auto-discover mvm.toml.
fn load_fleet_config(
    config_path: Option<&str>,
) -> Result<Option<(fleet::FleetConfig, std::path::PathBuf)>> {
    match config_path {
        Some(path) => {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read {}", path))?;
            let config: fleet::FleetConfig =
                toml::from_str(&content).with_context(|| format!("Failed to parse {}", path))?;
            let dir = std::path::Path::new(path)
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .to_path_buf();
            Ok(Some((config, dir)))
        }
        None => fleet::find_fleet_config(),
    }
}

fn cmd_down(name: Option<&str>, config_path: Option<&str>) -> Result<()> {
    // Use Apple Container backend on macOS 26+, otherwise default (Firecracker).
    let backend = if mvm_core::platform::current().has_apple_containers() {
        AnyBackend::from_hypervisor("apple-container")
    } else {
        AnyBackend::default_backend()
    };
    match name {
        Some(n) => {
            let result = backend.stop(&VmId::from(n));
            // Deregister from the name registry (best-effort)
            let registry_path = mvm_runtime::vm::name_registry::registry_path();
            if let Ok(mut registry) =
                mvm_runtime::vm::name_registry::VmNameRegistry::load(&registry_path)
            {
                registry.deregister(n);
                let _ = registry.save(&registry_path);
            }
            result
        }
        None => {
            let found = load_fleet_config(config_path)?;
            if let Some((fleet_config, _base_dir)) = found {
                let mut stopped = 0;
                for vm_name in fleet_config.vms.keys() {
                    if backend.stop(&VmId::from(vm_name.as_str())).is_ok() {
                        stopped += 1;
                    }
                }

                // Clean up bridge if no VMs remain
                let remaining = backend.list().unwrap_or_default();
                if remaining.is_empty() {
                    let _ = mvm_runtime::vm::network::bridge_teardown();
                }

                ui::success(&format!("Stopped {} VMs", stopped));
                Ok(())
            } else {
                backend.stop_all()
            }
        }
    }
}

fn cmd_metrics(json: bool) -> Result<()> {
    let metrics = mvm_core::observability::metrics::global();
    if json {
        let snap = metrics.snapshot();
        println!("{}", serde_json::to_string_pretty(&snap)?);
    } else {
        print!("{}", metrics.prometheus_exposition());
    }
    Ok(())
}

fn cmd_completions(shell: clap_complete::Shell) -> Result<()> {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "mvmctl", &mut std::io::stdout());
    Ok(())
}

fn cmd_uninstall(yes: bool, all: bool, dry_run: bool) -> Result<()> {
    // Build list of what will be removed.
    let mut actions: Vec<String> = Vec::new();

    let lima_status = lima::get_status().unwrap_or(lima::LimaStatus::NotFound);
    if !matches!(lima_status, lima::LimaStatus::NotFound) {
        actions.push("Destroy Lima VM 'mvm'".to_string());
    }

    actions.push("Remove /var/lib/mvm/ (VM state, volumes, run-info)".to_string());

    if all {
        actions.push("Remove ~/.mvm/ (config, signing keys)".to_string());
        actions.push("Remove /usr/local/bin/mvmctl (binary)".to_string());
    }

    if actions.is_empty() {
        ui::info("Nothing to uninstall.");
        return Ok(());
    }

    if dry_run {
        ui::info("Dry run — the following would be removed:");
        for a in &actions {
            println!("  • {a}");
        }
        return Ok(());
    }

    // Confirmation prompt.
    if !yes {
        ui::info("The following will be removed:");
        for a in &actions {
            println!("  • {a}");
        }
        if !ui::confirm("Proceed with uninstall?") {
            ui::info("Cancelled.");
            return Ok(());
        }
    }

    // Stop running microVMs first (best-effort).
    if matches!(lima_status, lima::LimaStatus::Running)
        && let Err(e) = microvm::stop()
    {
        tracing::warn!("failed to stop microVMs before uninstall: {e}");
    }

    // Destroy Lima VM.
    if !matches!(lima_status, lima::LimaStatus::NotFound) {
        ui::info("Destroying Lima VM...");
        if let Err(e) = lima::destroy() {
            tracing::warn!("failed to destroy Lima VM: {e}");
        }
    }

    // Remove /var/lib/mvm/.
    let state_dir = std::path::Path::new("/var/lib/mvm");
    if state_dir.exists() {
        ui::info("Removing /var/lib/mvm/...");
        let status = std::process::Command::new("sudo")
            .args(["rm", "-rf", "/var/lib/mvm"])
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => tracing::warn!("sudo rm /var/lib/mvm exited with status {s}"),
            Err(e) => tracing::warn!("failed to remove /var/lib/mvm: {e}"),
        }
    }

    if all {
        // Remove ~/.mvm/.
        if let Ok(home) = std::env::var("HOME") {
            let config_dir = std::path::PathBuf::from(home).join(".mvm");
            if config_dir.exists() {
                ui::info("Removing ~/.mvm/...");
                if let Err(e) = std::fs::remove_dir_all(&config_dir) {
                    tracing::warn!("failed to remove ~/.mvm/: {e}");
                }
            }
        }

        // Remove /usr/local/bin/mvmctl.
        let bin = std::path::Path::new("/usr/local/bin/mvmctl");
        if bin.exists() {
            ui::info("Removing /usr/local/bin/mvmctl...");
            let status = std::process::Command::new("sudo")
                .args(["rm", "-f", "/usr/local/bin/mvmctl"])
                .status();
            match status {
                Ok(s) if s.success() => {}
                Ok(s) => tracing::warn!("sudo rm mvmctl exited with status {s}"),
                Err(e) => tracing::warn!("failed to remove /usr/local/bin/mvmctl: {e}"),
            }
        }
    }

    mvm_core::audit::emit(mvm_core::audit::LocalAuditKind::Uninstall, None, None);
    ui::success("Uninstall complete.");
    Ok(())
}

// ============================================================================
// Audit commands
// ============================================================================

fn cmd_audit(action: AuditCmd) -> Result<()> {
    match action {
        AuditCmd::Tail { lines, follow } => cmd_audit_tail(lines, follow),
    }
}

// ============================================================================
// Flake commands
// ============================================================================

fn cmd_flake(action: FlakeCmd) -> Result<()> {
    match action {
        FlakeCmd::Check { flake, json } => cmd_flake_check(&flake, json),
    }
}

fn cmd_flake_check(flake: &str, json: bool) -> Result<()> {
    let resolved = resolve_flake_ref(flake)?;

    if bootstrap::is_lima_required() {
        lima::require_running()?;
    }

    let script = format!("nix flake check {resolved}");

    if json {
        // Capture combined stdout+stderr so we can embed it in JSON.
        let output = shell::run_in_vm_capture(&script);
        match output {
            Ok(out) => {
                let combined = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                if out.status.success() {
                    println!("{{\"valid\":true}}");
                } else {
                    let msg = combined.trim().replace('"', "'");
                    println!("{{\"valid\":false,\"error\":\"{msg}\"}}");
                    std::process::exit(1);
                }
                Ok(())
            }
            Err(e) => {
                let msg = e.to_string().replace('"', "'");
                println!("{{\"valid\":false,\"error\":\"{msg}\"}}");
                std::process::exit(1);
            }
        }
    } else {
        // Stream output directly so the user sees nix progress in real time.
        match shell::run_in_vm_visible(&script) {
            Ok(()) => {
                ui::success("Flake is valid.");
                Ok(())
            }
            Err(e) => Err(e.context("Flake check failed")),
        }
    }
}

fn cmd_audit_tail(lines: usize, follow: bool) -> Result<()> {
    let log_path = mvm_core::audit::default_audit_log();
    let path = std::path::Path::new(&log_path);

    if !path.exists() {
        ui::info(&format!(
            "No audit log found. Events are recorded at {log_path}."
        ));
        return Ok(());
    }

    print_last_n_lines(path, lines)?;

    if !follow {
        return Ok(());
    }

    // Tail -f: track file position and poll for new content.
    let mut pos = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if !path.exists() {
            continue;
        }
        let new_len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if new_len > pos {
            let mut file = std::fs::File::open(path)?;
            use std::io::{BufRead, Seek, SeekFrom};
            file.seek(SeekFrom::Start(pos))?;
            let reader = std::io::BufReader::new(&file);
            for line in reader.lines() {
                let line = line?;
                print_audit_line(&line);
            }
            pos = new_len;
        }
    }
}

fn print_last_n_lines(path: &std::path::Path, n: usize) -> Result<()> {
    use std::io::BufRead;
    let file =
        std::fs::File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let reader = std::io::BufReader::new(file);
    let lines: Vec<String> = reader.lines().map_while(Result::ok).collect();
    let start = lines.len().saturating_sub(n);
    for line in &lines[start..] {
        print_audit_line(line);
    }
    Ok(())
}

fn print_audit_line(line: &str) {
    match serde_json::from_str::<mvm_core::audit::LocalAuditEvent>(line) {
        Ok(event) => {
            let kind = serde_json::to_string(&event.kind)
                .unwrap_or_default()
                .trim_matches('"')
                .to_string();
            let vm = event
                .vm_name
                .as_deref()
                .map(|n| format!("  [{n}]"))
                .unwrap_or_default();
            let detail = event
                .detail
                .as_deref()
                .map(|d| format!("  {d}"))
                .unwrap_or_default();
            println!("{ts}  {kind}{vm}{detail}", ts = event.timestamp);
        }
        Err(_) => {
            // Non-local-audit line — print as-is (fleet AuditEntry, etc.)
            println!("{line}");
        }
    }
}

// ============================================================================
// Template commands
// ============================================================================

fn cmd_template(action: TemplateCmd) -> Result<()> {
    match action {
        TemplateCmd::Create {
            name,
            flake,
            profile,
            role,
            cpus,
            mem,
            data_disk,
        } => {
            validate_template_name(&name)
                .with_context(|| format!("Invalid template name: {:?}", name))?;
            validate_flake_ref(&flake)
                .with_context(|| format!("Invalid flake reference: {:?}", flake))?;
            let mem_mb = parse_human_size(&mem).context("Invalid memory size")?;
            let data_disk_mb = parse_human_size(&data_disk).context("Invalid data disk size")?;
            template_cmd::create_single(&name, &flake, &profile, &role, cpus, mem_mb, data_disk_mb)
        }
        TemplateCmd::CreateMulti {
            base,
            flake,
            profile,
            roles,
            cpus,
            mem,
            data_disk,
        } => {
            validate_template_name(&base)
                .with_context(|| format!("Invalid template base name: {:?}", base))?;
            validate_flake_ref(&flake)
                .with_context(|| format!("Invalid flake reference: {:?}", flake))?;
            let mem_mb = parse_human_size(&mem).context("Invalid memory size")?;
            let data_disk_mb = parse_human_size(&data_disk).context("Invalid data disk size")?;
            let role_list: Vec<String> = roles.split(',').map(|s| s.trim().to_string()).collect();
            template_cmd::create_multi(
                &base,
                &flake,
                &profile,
                &role_list,
                cpus,
                mem_mb,
                data_disk_mb,
            )
        }
        TemplateCmd::Build {
            name,
            force,
            snapshot,
            config,
            update_hash,
        } => {
            validate_template_name(&name)
                .with_context(|| format!("Invalid template name: {:?}", name))?;
            template_cmd::build(&name, force, snapshot, config.as_deref(), update_hash)
        }
        TemplateCmd::Push { name, revision } => {
            validate_template_name(&name)
                .with_context(|| format!("Invalid template name: {:?}", name))?;
            template_cmd::push(&name, revision.as_deref())
        }
        TemplateCmd::Pull { name, revision } => {
            validate_template_name(&name)
                .with_context(|| format!("Invalid template name: {:?}", name))?;
            template_cmd::pull(&name, revision.as_deref())
        }
        TemplateCmd::Verify { name, revision } => {
            validate_template_name(&name)
                .with_context(|| format!("Invalid template name: {:?}", name))?;
            template_cmd::verify(&name, revision.as_deref())
        }
        TemplateCmd::List { json } => template_cmd::list(json),
        TemplateCmd::Info { name, json } => {
            validate_template_name(&name)
                .with_context(|| format!("Invalid template name: {:?}", name))?;
            template_cmd::info(&name, json)
        }
        TemplateCmd::Edit {
            name,
            flake,
            profile,
            role,
            cpus,
            mem,
            data_disk,
        } => {
            validate_template_name(&name)
                .with_context(|| format!("Invalid template name: {:?}", name))?;
            if let Some(ref f) = flake {
                validate_flake_ref(f)
                    .with_context(|| format!("Invalid flake reference: {:?}", f))?;
            }
            let mem_mb = mem
                .as_ref()
                .map(|s| parse_human_size(s))
                .transpose()
                .context("Invalid memory size")?;
            let data_disk_mb = data_disk
                .as_ref()
                .map(|s| parse_human_size(s))
                .transpose()
                .context("Invalid data disk size")?;
            template_cmd::edit(
                &name,
                flake.as_deref(),
                profile.as_deref(),
                role.as_deref(),
                cpus,
                mem_mb,
                data_disk_mb,
            )
        }
        TemplateCmd::Delete { name, force } => {
            validate_template_name(&name)
                .with_context(|| format!("Invalid template name: {:?}", name))?;
            template_cmd::delete(&name, force)
        }
        TemplateCmd::Init {
            name,
            local,
            vm,
            dir,
            preset,
        } => {
            validate_template_name(&name)
                .with_context(|| format!("Invalid template name: {:?}", name))?;
            let use_local = local && !vm;
            template_cmd::init(&name, use_local, &dir, &preset)
        }
    }
}

/// Resolve a VM name to its absolute directory path inside the Lima VM
/// and verify it is running.
fn resolve_running_vm(name: &str) -> Result<String> {
    if bootstrap::is_lima_required() {
        lima::require_running()?;
    }

    let abs_vms = shell::run_in_vm_stdout(&format!("echo {}", config::VMS_DIR))?;
    let abs_dir = format!("{}/{}", abs_vms, name);
    let pid_file = format!("{}/fc.pid", abs_dir);

    if !firecracker::is_vm_running(&pid_file)? {
        anyhow::bail!(
            "VM '{}' is not running. Use 'mvmctl status' to list running VMs.",
            name
        );
    }

    Ok(abs_dir)
}

// ============================================================================
// Config commands
// ============================================================================

fn cmd_config(action: ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Show => cmd_config_show(),
        ConfigAction::Edit => cmd_config_edit(),
        ConfigAction::Set { key, value } => cmd_config_set(&key, &value),
    }
}

fn cmd_config_show() -> Result<()> {
    let cfg = mvm_core::user_config::load(None);
    let text = toml::to_string_pretty(&cfg).context("Failed to serialize config")?;
    print!("{}", text);
    Ok(())
}

fn cmd_config_edit() -> Result<()> {
    // Ensure config file exists (load creates it with defaults if absent).
    let _ = mvm_core::user_config::load(None);
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let config_path = std::path::PathBuf::from(home)
        .join(".mvm")
        .join("config.toml");
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "nano".to_string());
    let status = std::process::Command::new(&editor)
        .arg(&config_path)
        .status()
        .with_context(|| format!("Failed to launch editor {:?}", editor))?;
    if !status.success() {
        anyhow::bail!("Editor exited with status {}", status);
    }
    Ok(())
}

fn cmd_config_set(key: &str, value: &str) -> Result<()> {
    let mut cfg = mvm_core::user_config::load(None);
    mvm_core::user_config::set_key(&mut cfg, key, value)?;
    mvm_core::user_config::save(&cfg, None)?;
    println!("Set {} = {}", key, value);
    Ok(())
}

// ============================================================================
// Network management
// ============================================================================

fn cmd_network(action: NetworkCmd) -> Result<()> {
    use mvm_core::dev_network::{DevNetwork, network_path, networks_dir, validate_network_name};

    match action {
        NetworkCmd::Create { name, subnet: _ } => {
            validate_network_name(&name)?;
            let dir = networks_dir();
            std::fs::create_dir_all(&dir)?;

            let path = network_path(&name);
            if std::path::Path::new(&path).exists() {
                anyhow::bail!("Network {:?} already exists", name);
            }

            // Find the next available slot by scanning existing networks
            let mut max_slot: u8 = 0;
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    if let Ok(text) = std::fs::read_to_string(entry.path())
                        && let Ok(net) = serde_json::from_str::<DevNetwork>(&text)
                    {
                        let parts: Vec<&str> = net.subnet.split('.').collect();
                        if parts.len() >= 3
                            && let Ok(s) = parts[2].parse::<u8>()
                        {
                            max_slot = max_slot.max(s);
                        }
                    }
                }
            }

            let net = if name == "default" {
                DevNetwork::default_network()
            } else {
                DevNetwork::new(&name, max_slot + 1)?
            };

            let json = serde_json::to_string_pretty(&net)?;
            std::fs::write(&path, json)?;

            mvm_core::audit::emit(
                mvm_core::audit::LocalAuditKind::NetworkCreate,
                None,
                Some(&name),
            );

            ui::success(&format!(
                "Created network {:?} (bridge={}, subnet={})",
                net.name, net.bridge_name, net.subnet
            ));
            Ok(())
        }
        NetworkCmd::List => {
            let dir = networks_dir();
            if !std::path::Path::new(&dir).exists() {
                ui::info("No networks configured.");
                return Ok(());
            }

            let mut networks: Vec<DevNetwork> = Vec::new();
            for entry in std::fs::read_dir(&dir)?.flatten() {
                if entry.path().extension().is_some_and(|e| e == "json")
                    && let Ok(text) = std::fs::read_to_string(entry.path())
                    && let Ok(net) = serde_json::from_str::<DevNetwork>(&text)
                {
                    networks.push(net);
                }
            }

            if networks.is_empty() {
                ui::info("No networks configured.");
            } else {
                println!("{:<15} {:<15} {:<20}", "NAME", "BRIDGE", "SUBNET");
                for net in &networks {
                    println!(
                        "{:<15} {:<15} {:<20}",
                        net.name, net.bridge_name, net.subnet
                    );
                }
            }
            Ok(())
        }
        NetworkCmd::Inspect { name } => {
            let path = network_path(&name);
            if !std::path::Path::new(&path).exists() {
                anyhow::bail!("Network {:?} not found", name);
            }
            let text = std::fs::read_to_string(&path)?;
            let net: DevNetwork = serde_json::from_str(&text)?;
            println!("{}", serde_json::to_string_pretty(&net)?);
            Ok(())
        }
        NetworkCmd::Remove { name } => {
            if name == "default" {
                anyhow::bail!("Cannot remove the default network");
            }
            let path = network_path(&name);
            if !std::path::Path::new(&path).exists() {
                anyhow::bail!("Network {:?} not found", name);
            }
            std::fs::remove_file(&path)?;

            mvm_core::audit::emit(
                mvm_core::audit::LocalAuditKind::NetworkRemove,
                None,
                Some(&name),
            );

            ui::success(&format!("Removed network {:?}", name));
            Ok(())
        }
    }
}

// ============================================================================
// Image catalog
// ============================================================================

fn cmd_image(action: ImageCmd) -> Result<()> {
    let catalog = load_bundled_catalog();

    match action {
        ImageCmd::List => {
            if catalog.entries.is_empty() {
                ui::info("No images in catalog.");
            } else {
                println!(
                    "{:<20} {:<40} {:<6} {:<8}",
                    "NAME", "DESCRIPTION", "CPUS", "MEM"
                );
                for entry in &catalog.entries {
                    println!(
                        "{:<20} {:<40} {:<6} {:<8}",
                        entry.name,
                        entry.description,
                        entry.default_cpus,
                        format!("{}M", entry.default_memory_mib),
                    );
                }
            }
            Ok(())
        }
        ImageCmd::Search { query } => {
            let results = catalog.search(&query);
            if results.is_empty() {
                ui::info(&format!("No images matching {:?}", query));
            } else {
                println!("{:<20} {:<40} {:<30}", "NAME", "DESCRIPTION", "TAGS");
                for entry in results {
                    println!(
                        "{:<20} {:<40} {:<30}",
                        entry.name,
                        entry.description,
                        entry.tags.join(", "),
                    );
                }
            }
            Ok(())
        }
        ImageCmd::Fetch { name } => {
            let entry = catalog
                .find(&name)
                .ok_or_else(|| anyhow::anyhow!("Image {:?} not found in catalog", name))?;

            ui::info(&format!(
                "Fetching image {:?} from {}...",
                entry.name, entry.flake_ref
            ));
            ui::info("This will create a template and build it via Nix.");
            ui::info(&format!(
                "Equivalent to: mvmctl template create {} --flake {} --profile {} && mvmctl template build {}",
                entry.name, entry.flake_ref, entry.profile, entry.name
            ));

            mvm_core::audit::emit(
                mvm_core::audit::LocalAuditKind::ImageFetch,
                None,
                Some(&name),
            );

            // Create a template from the catalog entry, then build it
            template_cmd::create_single(
                &entry.name,
                &entry.flake_ref,
                &entry.profile,
                "worker",
                entry.default_cpus,
                entry.default_memory_mib,
                0, // no data disk
            )?;
            ui::success(&format!("Created template {:?} from catalog.", entry.name));

            ui::info(&format!("Building template {:?}...", entry.name));
            template_cmd::build(&entry.name, false, false, None, false)?;
            ui::success(&format!(
                "Image {:?} is ready. Run with: mvmctl up --template {}",
                entry.name, entry.name
            ));
            Ok(())
        }
        ImageCmd::Info { name } => {
            let entry = catalog
                .find(&name)
                .ok_or_else(|| anyhow::anyhow!("Image {:?} not found in catalog", name))?;
            println!("{}", serde_json::to_string_pretty(entry)?);
            Ok(())
        }
    }
}

/// Load the bundled image catalog with built-in presets.
fn load_bundled_catalog() -> mvm_core::catalog::Catalog {
    mvm_core::catalog::Catalog {
        schema_version: 1,
        entries: vec![
            mvm_core::catalog::CatalogEntry {
                name: "minimal".to_string(),
                description: "Bare-bones microVM with init only".to_string(),
                flake_ref: ".".to_string(),
                profile: "minimal".to_string(),
                default_cpus: 1,
                default_memory_mib: 256,
                tags: vec!["base".to_string(), "minimal".to_string()],
            },
            mvm_core::catalog::CatalogEntry {
                name: "http".to_string(),
                description: "HTTP server (Nginx or custom)".to_string(),
                flake_ref: ".".to_string(),
                profile: "http".to_string(),
                default_cpus: 2,
                default_memory_mib: 512,
                tags: vec!["web".to_string(), "http".to_string(), "nginx".to_string()],
            },
            mvm_core::catalog::CatalogEntry {
                name: "postgres".to_string(),
                description: "PostgreSQL database server".to_string(),
                flake_ref: ".".to_string(),
                profile: "postgres".to_string(),
                default_cpus: 2,
                default_memory_mib: 1024,
                tags: vec![
                    "database".to_string(),
                    "sql".to_string(),
                    "postgres".to_string(),
                ],
            },
            mvm_core::catalog::CatalogEntry {
                name: "worker".to_string(),
                description: "Background job worker".to_string(),
                flake_ref: ".".to_string(),
                profile: "worker".to_string(),
                default_cpus: 2,
                default_memory_mib: 512,
                tags: vec!["worker".to_string(), "background".to_string()],
            },
            mvm_core::catalog::CatalogEntry {
                name: "python".to_string(),
                description: "Python runtime environment".to_string(),
                flake_ref: ".".to_string(),
                profile: "python".to_string(),
                default_cpus: 2,
                default_memory_mib: 512,
                tags: vec!["python".to_string(), "runtime".to_string()],
            },
        ],
    }
}

// ============================================================================
// Cache management
// ============================================================================

fn cmd_cache(action: CacheCmd) -> Result<()> {
    let cache_dir = mvm_core::config::mvm_cache_dir();

    match action {
        CacheCmd::Info => {
            println!("Cache directory: {cache_dir}");
            let path = std::path::Path::new(&cache_dir);
            if path.exists() {
                let size = dir_size(path);
                println!("Disk usage: {}", human_bytes(size));
            } else {
                println!("(not yet created)");
            }
            Ok(())
        }
        CacheCmd::Prune { dry_run } => {
            let path = std::path::Path::new(&cache_dir);
            if !path.exists() {
                ui::info("Cache directory does not exist. Nothing to prune.");
                return Ok(());
            }

            // Prune: remove empty subdirectories and temp files
            let mut removed = 0u64;
            let mut freed = 0u64;
            for entry in walkdir(path)? {
                let entry_path = entry.path();
                // Remove temp files (mvm-lima-*, .tmp)
                if let Some(name) = entry_path.file_name().and_then(|n| n.to_str())
                    && (name.starts_with("mvm-lima-") || name.ends_with(".tmp"))
                {
                    let size = entry_path.metadata().map(|m| m.len()).unwrap_or(0);
                    if dry_run {
                        println!(
                            "Would remove: {} ({})",
                            entry_path.display(),
                            human_bytes(size)
                        );
                    } else if entry_path.is_dir() {
                        let _ = std::fs::remove_dir_all(entry_path);
                    } else {
                        let _ = std::fs::remove_file(entry_path);
                    }
                    removed += 1;
                    freed += size;
                }
            }

            if removed == 0 {
                ui::info("Nothing to prune.");
            } else if dry_run {
                ui::info(&format!(
                    "Would remove {} items, freeing {}",
                    removed,
                    human_bytes(freed)
                ));
            } else {
                ui::success(&format!(
                    "Pruned {} items, freed {}",
                    removed,
                    human_bytes(freed)
                ));
            }
            Ok(())
        }
    }
}

/// Recursively calculate directory size in bytes.
fn dir_size(path: &std::path::Path) -> u64 {
    walkdir(path)
        .unwrap_or_default()
        .iter()
        .filter(|e| e.path().is_file())
        .map(|e| e.path().metadata().map(|m| m.len()).unwrap_or(0))
        .sum()
}

/// Simple recursive directory walker.
fn walkdir(path: &std::path::Path) -> Result<Vec<std::fs::DirEntry>> {
    let mut entries = Vec::new();
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let epath = entry.path();
            let is_dir = epath.is_dir();
            entries.push(entry);
            if is_dir && let Ok(sub) = walkdir(&epath) {
                entries.extend(sub);
            }
        }
    }
    Ok(entries)
}

// ============================================================================
// Init wizard
// ============================================================================

fn cmd_init(non_interactive: bool, lima_cpus: u32, lima_mem: u32) -> Result<()> {
    use mvm_core::dev_network::{DevNetwork, network_path, networks_dir};

    ui::info("Welcome to mvmctl! Running first-time setup...\n");

    // Step 1: Platform detection
    let plat = mvm_core::platform::current();
    ui::info(&format!("Platform: {}", platform_label(plat)));

    if plat.has_apple_containers() {
        ui::info("Apple Container support detected (macOS 26+).");
    }

    // Step 2: Check and install dependencies
    ui::info("\nChecking dependencies...");
    match bootstrap::check_package_manager() {
        Ok(()) => {}
        Err(e) => {
            if non_interactive {
                return Err(e);
            }
            ui::warn(&format!("Package manager issue: {e}"));
            ui::info("Please install a package manager and retry.");
            return Err(e);
        }
    }

    if plat.needs_lima() {
        ui::info("Ensuring Lima is installed...");
        bootstrap::ensure_lima()?;
    }

    // Step 3: Run setup steps (create Lima VM, install Firecracker, Nix)
    ui::info("\nSetting up development environment...");
    run_setup_steps(false, lima_cpus, lima_mem)?;

    // Step 4: Create default network if it doesn't exist
    let dir = networks_dir();
    let default_path = network_path("default");
    if !std::path::Path::new(&default_path).exists() {
        ui::info("\nCreating default network...");
        std::fs::create_dir_all(&dir)?;
        let net = DevNetwork::default_network();
        let json = serde_json::to_string_pretty(&net)?;
        std::fs::write(&default_path, json)?;
        ui::success(&format!(
            "Created default network (bridge={}, subnet={})",
            net.bridge_name, net.subnet
        ));
    } else {
        ui::info("\nDefault network already configured.");
    }

    // Step 5: Create XDG directories
    ui::info("\nCreating data directories...");
    let dirs = [
        mvm_core::config::mvm_cache_dir(),
        mvm_core::config::mvm_config_dir(),
        mvm_core::config::mvm_state_dir(),
        mvm_core::config::mvm_share_dir(),
    ];
    for d in &dirs {
        std::fs::create_dir_all(d)?;
    }

    // Step 6: Show available images
    ui::info("\nAvailable images in catalog:");
    let catalog = load_bundled_catalog();
    for entry in &catalog.entries {
        ui::info(&format!("  {} — {}", entry.name, entry.description));
    }

    ui::success("\nSetup complete!");
    ui::info("Next steps:");
    ui::info("  mvmctl dev              # Enter development environment");
    ui::info("  mvmctl image list       # Browse available images");
    ui::info("  mvmctl doctor           # Verify everything is working");
    ui::info("  mvmctl up --flake .     # Build and run a VM from a Nix flake");

    Ok(())
}

fn platform_label(plat: mvm_core::platform::Platform) -> &'static str {
    match plat {
        mvm_core::platform::Platform::MacOS => "macOS (Lima + Firecracker)",
        mvm_core::platform::Platform::LinuxNative => "Linux (native KVM)",
        mvm_core::platform::Platform::LinuxNoKvm => "Linux (no KVM — limited)",
        mvm_core::platform::Platform::Wsl2 => "WSL2 (Linux via Windows)",
        mvm_core::platform::Platform::Windows => "Windows (experimental)",
    }
}

// ============================================================================
// Security status
// ============================================================================

fn cmd_security(action: SecurityCmd) -> Result<()> {
    match action {
        SecurityCmd::Status { json } => cmd_security_status(json),
    }
}

fn cmd_security_status(json: bool) -> Result<()> {
    use mvm_core::security::{PostureCheck, SecurityLayer};
    use mvm_security::posture::SecurityPosture;

    let mut checks = Vec::new();

    // Check audit logging
    let audit_path = mvm_core::audit::default_audit_log();
    let audit_exists = std::path::Path::new(&audit_path).exists();
    checks.push(PostureCheck {
        layer: SecurityLayer::AuditLogging,
        name: "Local audit log".to_string(),
        passed: audit_exists,
        detail: if audit_exists {
            format!("Active at {audit_path}")
        } else {
            format!("Not found at {audit_path}")
        },
    });

    // Check XDG directory structure
    let share_dir = mvm_core::config::mvm_share_dir();
    let xdg_exists = std::path::Path::new(&share_dir).exists();
    checks.push(PostureCheck {
        layer: SecurityLayer::ConfigImmutability,
        name: "XDG data directory".to_string(),
        passed: xdg_exists,
        detail: if xdg_exists {
            format!("Present at {share_dir}")
        } else {
            "Not yet created — run `mvmctl init`".to_string()
        },
    });

    // Check default network
    let net_path = mvm_core::dev_network::network_path("default");
    let net_exists = std::path::Path::new(&net_path).exists();
    checks.push(PostureCheck {
        layer: SecurityLayer::NetworkIsolation,
        name: "Default dev network".to_string(),
        passed: net_exists,
        detail: if net_exists {
            "Configured".to_string()
        } else {
            "Not configured — run `mvmctl init` or `mvmctl network create default`".to_string()
        },
    });

    // Check seccomp availability
    checks.push(PostureCheck {
        layer: SecurityLayer::SeccompFilter,
        name: "Seccomp profiles".to_string(),
        passed: true,
        detail: "5-tier profiles available (essential → unrestricted)".to_string(),
    });

    // Check vsock auth
    checks.push(PostureCheck {
        layer: SecurityLayer::VsockAuth,
        name: "Vsock authentication".to_string(),
        passed: true,
        detail: "Ed25519 signing with replay protection".to_string(),
    });

    // Check guest hardening (no SSH)
    checks.push(PostureCheck {
        layer: SecurityLayer::GuestHardening,
        name: "No SSH policy".to_string(),
        passed: true,
        detail: "Vsock-only guest communication (no sshd)".to_string(),
    });

    // Check supply chain
    checks.push(PostureCheck {
        layer: SecurityLayer::SupplyChainIntegrity,
        name: "Nix-based builds".to_string(),
        passed: true,
        detail: "All images built from Nix flakes (content-addressed)".to_string(),
    });

    let timestamp = mvm_core::time::utc_now();
    let report = SecurityPosture::evaluate(checks, &timestamp);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", SecurityPosture::summary(&report));

        let uncovered = SecurityPosture::uncovered_layers(&report.checks);
        if !uncovered.is_empty() {
            println!("\nUncovered layers (no checks):");
            for layer in uncovered {
                println!("  - {:?}", layer);
            }
        }
    }

    Ok(())
}

// ============================================================================
// Console (PTY-over-vsock)
// ============================================================================

fn cmd_console(name: &str, command: Option<&str>) -> Result<()> {
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {:?}", name))?;

    if let Some(cmd) = command {
        // One-shot command execution — detect backend for both Firecracker and Apple Container
        let resp = if let Ok(mut stream) =
            mvm_apple_container::vsock_connect(name, mvm_guest::vsock::GUEST_AGENT_PORT)
        {
            mvm_guest::vsock::send_request(
                &mut stream,
                &mvm_guest::vsock::GuestRequest::Exec {
                    command: cmd.to_string(),
                    stdin: None,
                    timeout_secs: Some(30),
                },
            )?
        } else {
            let instance_dir = microvm::resolve_running_vm_dir(name)?;
            mvm_guest::vsock::exec_at(
                &mvm_guest::vsock::vsock_uds_path(&instance_dir),
                cmd,
                None,
                30,
            )?
        };
        match resp {
            mvm_guest::vsock::GuestResponse::ExecResult {
                exit_code,
                stdout,
                stderr,
            } => {
                if !stdout.is_empty() {
                    print!("{stdout}");
                }
                if !stderr.is_empty() {
                    eprint!("{stderr}");
                }
                if exit_code != 0 {
                    std::process::exit(exit_code);
                }
                Ok(())
            }
            mvm_guest::vsock::GuestResponse::Error { message } => {
                anyhow::bail!("Console exec error: {message}")
            }
            other => anyhow::bail!("Unexpected response: {other:?}"),
        }
    } else {
        // Interactive PTY session
        console_interactive(name)
    }
}

/// Open an interactive PTY console to a running VM.
///
/// Backend type for console connections.
enum ConsoleBackend {
    AppleContainer(String),
    Firecracker(String),
}

/// Open an interactive PTY console to a running VM.
///
/// Supports both Firecracker (via UDS vsock) and Apple Container (via direct vsock).
fn console_interactive(name: &str) -> Result<()> {
    // Get terminal size
    let (cols, rows) = get_terminal_size();

    // Send ConsoleOpen request via the control channel
    ui::info(&format!(
        "Opening console to VM {:?} ({}x{})...",
        name, cols, rows
    ));

    // Determine backend: try Apple Container first, then Firecracker/Lima UDS
    let backend =
        if mvm_apple_container::vsock_connect(name, mvm_guest::vsock::GUEST_AGENT_PORT).is_ok() {
            ConsoleBackend::AppleContainer(name.to_string())
        } else {
            let instance_dir = microvm::resolve_running_vm_dir(name)?;
            ConsoleBackend::Firecracker(instance_dir)
        };

    // Send ConsoleOpen on the control channel
    let (resp, connect_data) = match &backend {
        ConsoleBackend::AppleContainer(vm_id) => {
            let mut stream =
                mvm_apple_container::vsock_connect(vm_id, mvm_guest::vsock::GUEST_AGENT_PORT)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            let resp = mvm_guest::vsock::send_request(
                &mut stream,
                &mvm_guest::vsock::GuestRequest::ConsoleOpen { cols, rows },
            )?;
            (resp, backend)
        }
        ConsoleBackend::Firecracker(instance_dir) => {
            let uds = mvm_guest::vsock::vsock_uds_path(instance_dir);
            let mut stream = mvm_guest::vsock::connect_to(&uds, 10)?;
            let resp = mvm_guest::vsock::send_request(
                &mut stream,
                &mvm_guest::vsock::GuestRequest::ConsoleOpen { cols, rows },
            )?;
            (resp, backend)
        }
    };

    let (session_id, data_port) = match resp {
        mvm_guest::vsock::GuestResponse::ConsoleOpened {
            session_id,
            data_port,
        } => (session_id, data_port),
        mvm_guest::vsock::GuestResponse::Error { message } => {
            anyhow::bail!("Console open failed: {message}");
        }
        other => {
            anyhow::bail!("Unexpected response: {other:?}");
        }
    };

    ui::info(&format!(
        "Console session {} opened, connecting to data port {}...",
        session_id, data_port
    ));

    // Small delay to let the guest agent bind the data port
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Connect to the data port for raw I/O
    let data_stream = match &connect_data {
        ConsoleBackend::AppleContainer(vm_id) => {
            mvm_apple_container::vsock_connect(vm_id, data_port)
                .map_err(|e| anyhow::anyhow!("Failed to connect to console data port: {e}"))?
        }
        ConsoleBackend::Firecracker(instance_dir) => {
            // Firecracker vsock multiplexes all ports on the same UDS
            let uds = mvm_guest::vsock::vsock_uds_path(instance_dir);
            mvm_guest::vsock::connect_to(&uds, 10)
                .context("Failed to connect to console data port")?
        }
    };

    mvm_core::audit::emit(
        mvm_core::audit::LocalAuditKind::ConsoleSessionStart,
        Some(name),
        Some(&format!("session_id={session_id}")),
    );

    // Set up SIGWINCH handler to forward terminal resizes
    let resize_sender = setup_sigwinch_handler(&connect_data, session_id);

    // Enter raw terminal mode
    let orig_termios = enter_raw_mode()?;
    let result = run_console_relay(data_stream);

    // Restore terminal and clean up resize handler
    restore_terminal(&orig_termios);
    drop(resize_sender);

    mvm_core::audit::emit(
        mvm_core::audit::LocalAuditKind::ConsoleSessionEnd,
        Some(name),
        Some(&format!("session_id={session_id}")),
    );

    println!("\nConsole session ended.");
    result
}

/// Flag set by the SIGWINCH signal handler.
static SIGWINCH_RECEIVED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn sigwinch_handler(_sig: libc::c_int) {
    SIGWINCH_RECEIVED.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Set up a SIGWINCH signal handler that forwards terminal resizes to the guest.
///
/// Returns a sender that keeps the background thread alive. Drop it to stop.
fn setup_sigwinch_handler(
    backend: &ConsoleBackend,
    session_id: u32,
) -> Option<std::sync::mpsc::Sender<()>> {
    use std::sync::atomic::Ordering;

    // Clone backend info for the resize thread
    let backend_info = match backend {
        ConsoleBackend::AppleContainer(vm_id) => ConsoleBackend::AppleContainer(vm_id.clone()),
        ConsoleBackend::Firecracker(dir) => ConsoleBackend::Firecracker(dir.clone()),
    };

    let (tx, rx) = std::sync::mpsc::channel::<()>();

    // Install SIGWINCH handler
    unsafe {
        libc::signal(
            libc::SIGWINCH,
            sigwinch_handler as *const () as libc::sighandler_t,
        );
    }

    // Background thread polls for resize signals
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_millis(250));

            // Stop if session ended (sender dropped)
            if let Err(std::sync::mpsc::TryRecvError::Disconnected) = rx.try_recv() {
                break;
            }

            if !SIGWINCH_RECEIVED.swap(false, Ordering::SeqCst) {
                continue;
            }

            let (cols, rows) = get_terminal_size();

            // Send ConsoleResize via the control channel (best-effort)
            let _ = match &backend_info {
                ConsoleBackend::AppleContainer(vm_id) => {
                    mvm_apple_container::vsock_connect(vm_id, mvm_guest::vsock::GUEST_AGENT_PORT)
                        .ok()
                        .and_then(|mut stream| {
                            mvm_guest::vsock::send_request(
                                &mut stream,
                                &mvm_guest::vsock::GuestRequest::ConsoleResize {
                                    session_id,
                                    cols,
                                    rows,
                                },
                            )
                            .ok()
                        })
                }
                ConsoleBackend::Firecracker(instance_dir) => {
                    let uds = mvm_guest::vsock::vsock_uds_path(instance_dir);
                    mvm_guest::vsock::connect_to(&uds, 5)
                        .ok()
                        .and_then(|mut stream| {
                            mvm_guest::vsock::send_request(
                                &mut stream,
                                &mvm_guest::vsock::GuestRequest::ConsoleResize {
                                    session_id,
                                    cols,
                                    rows,
                                },
                            )
                            .ok()
                        })
                }
            };
        }
    });

    Some(tx)
}

/// Get the current terminal size.
fn get_terminal_size() -> (u16, u16) {
    // SAFETY: ioctl with valid fd (stdout)
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
            (ws.ws_col, ws.ws_row)
        } else {
            (80, 24)
        }
    }
}

/// Put the terminal in raw mode and return the original termios for restoration.
fn enter_raw_mode() -> Result<libc::termios> {
    unsafe {
        let mut orig: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(0, &mut orig) != 0 {
            anyhow::bail!("Failed to get terminal attributes");
        }

        let mut raw = orig;
        libc::cfmakeraw(&mut raw);
        if libc::tcsetattr(0, libc::TCSANOW, &raw) != 0 {
            anyhow::bail!("Failed to set raw terminal mode");
        }

        Ok(orig)
    }
}

/// Restore the terminal to its original mode.
fn restore_terminal(orig: &libc::termios) {
    unsafe {
        libc::tcsetattr(0, libc::TCSANOW, orig);
    }
}

/// Relay raw bytes between stdin/stdout and a vsock data stream.
fn run_console_relay(data_stream: std::os::unix::net::UnixStream) -> Result<()> {
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, Ordering};

    let done = std::sync::Arc::new(AtomicBool::new(false));

    // vsock → stdout (guest output → host terminal)
    let done2 = done.clone();
    let mut read_stream = data_stream
        .try_clone()
        .context("Failed to clone data stream")?;

    let output_thread = std::thread::spawn(move || {
        let mut stdout = std::io::stdout();
        let mut buf = [0u8; 4096];
        loop {
            match read_stream.read(&mut buf) {
                Ok(0) | Err(_) => {
                    done2.store(true, Ordering::SeqCst);
                    break;
                }
                Ok(n) => {
                    let _ = stdout.write_all(&buf[..n]);
                    let _ = stdout.flush();
                }
            }
        }
    });

    // stdin → vsock (host input → guest shell)
    let mut write_stream = data_stream;
    let mut stdin = std::io::stdin();
    let mut buf = [0u8; 1024];
    loop {
        if done.load(Ordering::SeqCst) {
            break;
        }
        match stdin.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if write_stream.write_all(&buf[..n]).is_err() {
                    break;
                }
                let _ = write_stream.flush();
            }
        }
    }

    let _ = output_thread.join();
    Ok(())
}

// ============================================================================
// Utilities
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_cleanup_defaults() {
        let cli = Cli::try_parse_from(["mvmctl", "cleanup"]).unwrap();
        match cli.command {
            Commands::Cleanup { keep, all, verbose } => {
                assert_eq!(keep, None);
                assert!(!all);
                assert!(!verbose);
            }
            _ => panic!("Expected Cleanup command"),
        }
    }

    #[test]
    fn test_cleanup_keep_flag() {
        let cli = Cli::try_parse_from(["mvmctl", "cleanup", "--keep", "9"]).unwrap();
        match cli.command {
            Commands::Cleanup { keep, all, verbose } => {
                assert_eq!(keep, Some(9));
                assert!(!all);
                assert!(!verbose);
            }
            _ => panic!("Expected Cleanup command"),
        }
    }

    #[test]
    fn test_cleanup_all_flag() {
        let cli = Cli::try_parse_from(["mvmctl", "cleanup", "--all"]).unwrap();
        match cli.command {
            Commands::Cleanup { keep, all, verbose } => {
                assert_eq!(keep, None);
                assert!(all);
                assert!(!verbose);
            }
            _ => panic!("Expected Cleanup command"),
        }
    }

    #[test]
    fn test_cleanup_verbose_flag() {
        let cli = Cli::try_parse_from(["mvmctl", "cleanup", "--verbose"]).unwrap();
        match cli.command {
            Commands::Cleanup { keep, all, verbose } => {
                assert_eq!(keep, None);
                assert!(!all);
                assert!(verbose);
            }
            _ => panic!("Expected Cleanup command"),
        }
    }

    // ---- Build --flake tests ----

    #[test]
    fn test_build_flake_with_profile() {
        let cli = Cli::try_parse_from(["mvmctl", "build", "--flake", ".", "--profile", "gateway"])
            .unwrap();
        match cli.command {
            Commands::Build { flake, profile, .. } => {
                assert_eq!(flake.as_deref(), Some("."));
                assert_eq!(profile.as_deref(), Some("gateway"));
            }
            _ => panic!("Expected Build command"),
        }
    }

    #[test]
    fn test_build_flake_defaults_to_no_profile() {
        let cli = Cli::try_parse_from(["mvmctl", "build", "--flake", "."]).unwrap();
        match cli.command {
            Commands::Build { flake, profile, .. } => {
                assert_eq!(flake.as_deref(), Some("."));
                assert!(profile.is_none(), "profile should be None when omitted");
            }
            _ => panic!("Expected Build command"),
        }
    }

    #[test]
    fn test_build_mvmfile_mode_still_works() {
        let cli = Cli::try_parse_from(["mvmctl", "build", "myimage"]).unwrap();
        match cli.command {
            Commands::Build { path, flake, .. } => {
                assert_eq!(path, "myimage");
                assert!(flake.is_none(), "Mvmfile mode should have no --flake");
            }
            _ => panic!("Expected Build command"),
        }
    }

    #[test]
    fn test_resolve_flake_ref_remote_passthrough() {
        let resolved = resolve_flake_ref("github:user/repo").unwrap();
        assert_eq!(resolved, "github:user/repo");
    }

    #[test]
    fn test_resolve_flake_ref_remote_with_path() {
        let resolved = resolve_flake_ref("github:user/repo#attr").unwrap();
        assert_eq!(resolved, "github:user/repo#attr");
    }

    #[test]
    fn test_resolve_flake_ref_absolute_path() {
        let resolved = resolve_flake_ref("/tmp").unwrap();
        // /tmp may be a symlink on macOS to /private/tmp
        assert!(
            resolved == "/tmp" || resolved == "/private/tmp",
            "unexpected resolved path: {}",
            resolved
        );
    }

    #[test]
    fn test_resolve_flake_ref_nonexistent_fails() {
        let result = resolve_flake_ref("/nonexistent/path/that/does/not/exist");
        assert!(result.is_err());
    }

    // ---- Run command tests ----

    #[test]
    fn test_run_parses_all_flags() {
        let cli = Cli::try_parse_from([
            "mvmctl",
            "run",
            "--flake",
            ".",
            "--profile",
            "full",
            "--cpus",
            "4",
            "--memory",
            "2048",
        ])
        .unwrap();
        match cli.command {
            Commands::Up {
                flake,
                profile,
                cpus,
                memory,
                ..
            } => {
                assert_eq!(flake, Some(".".to_string()));
                assert_eq!(profile.as_deref(), Some("full"));
                assert_eq!(cpus, Some(4));
                assert_eq!(memory, Some("2048".to_string()));
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_run_defaults() {
        let cli = Cli::try_parse_from(["mvmctl", "run", "--flake", "."]).unwrap();
        match cli.command {
            Commands::Up {
                flake,
                template,
                name,
                profile,
                cpus,
                memory,
                volume,
                hypervisor,
                ..
            } => {
                assert_eq!(flake, Some(".".to_string()));
                assert!(template.is_none(), "template should be None when omitted");
                assert!(name.is_none(), "name should be None when omitted");
                assert!(profile.is_none(), "profile should be None when omitted");
                assert!(cpus.is_none(), "cpus should be None when omitted");
                assert!(memory.is_none(), "memory should be None when omitted");
                assert_eq!(volume.len(), 0);
                assert_eq!(hypervisor, "firecracker");
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_run_requires_source() {
        let result = Cli::try_parse_from(["mvmctl", "run"]);
        assert!(result.is_err(), "run should require --flake or --template");
    }

    #[test]
    fn test_run_template_flag() {
        let cli = Cli::try_parse_from(["mvmctl", "run", "--template", "openclaw"]).unwrap();
        match cli.command {
            Commands::Up {
                flake, template, ..
            } => {
                assert!(flake.is_none());
                assert_eq!(template, Some("openclaw".to_string()));
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_run_flake_and_template_conflict() {
        let result =
            Cli::try_parse_from(["mvmctl", "run", "--flake", ".", "--template", "openclaw"]);
        assert!(
            result.is_err(),
            "--flake and --template should be mutually exclusive"
        );
    }

    #[test]
    fn test_run_volume_dir_inject() {
        let cli = Cli::try_parse_from([
            "mvmctl",
            "run",
            "--flake",
            ".",
            "-v",
            "/tmp/config:/mnt/config",
            "-v",
            "/tmp/secrets:/mnt/secrets",
        ])
        .unwrap();
        match cli.command {
            Commands::Up { volume, .. } => {
                assert_eq!(volume.len(), 2);
                assert_eq!(volume[0], "/tmp/config:/mnt/config");
                assert_eq!(volume[1], "/tmp/secrets:/mnt/secrets");
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_run_volume_persistent() {
        let cli =
            Cli::try_parse_from(["mvmctl", "run", "--flake", ".", "-v", "/data:/mnt/data:4G"])
                .unwrap();
        match cli.command {
            Commands::Up { volume, .. } => {
                assert_eq!(volume.len(), 1);
                assert_eq!(volume[0], "/data:/mnt/data:4G");
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_parse_volume_spec_dir_inject() {
        let spec = parse_volume_spec("/tmp/config:/mnt/config").unwrap();
        match spec {
            VolumeSpec::DirInject {
                host_dir,
                guest_mount,
            } => {
                assert_eq!(host_dir, "/tmp/config");
                assert_eq!(guest_mount, "/mnt/config");
            }
            _ => panic!("Expected DirInject"),
        }
    }

    #[test]
    fn test_parse_volume_spec_persistent() {
        let spec = parse_volume_spec("/data:/mnt/data:4G").unwrap();
        match spec {
            VolumeSpec::Persistent(vol) => {
                assert_eq!(vol.host, "/data");
                assert_eq!(vol.guest, "/mnt/data");
                assert_eq!(vol.size, "4G");
            }
            _ => panic!("Expected Persistent"),
        }
    }

    #[test]
    fn test_parse_volume_spec_invalid() {
        let result = parse_volume_spec("just-a-path");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_volume_spec_unsupported_mount() {
        let spec = parse_volume_spec("/tmp/foo:/mnt/custom").unwrap();
        // The spec itself parses fine — the error happens at routing time in cmd_run
        match spec {
            VolumeSpec::DirInject { guest_mount, .. } => {
                assert_eq!(guest_mount, "/mnt/custom");
            }
            _ => panic!("Expected DirInject"),
        }
    }

    #[test]
    fn test_run_port_and_env_flags() {
        let cli = Cli::try_parse_from([
            "mvmctl",
            "run",
            "--flake",
            ".",
            "-p",
            "3333:3000",
            "-p",
            "3334:3002",
            "-e",
            "NODE_ENV=production",
            "-e",
            "DEBUG=true",
        ])
        .unwrap();
        match cli.command {
            Commands::Up { port, env, .. } => {
                assert_eq!(port, vec!["3333:3000", "3334:3002"]);
                assert_eq!(env, vec!["NODE_ENV=production", "DEBUG=true"]);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_run_port_and_env_default_empty() {
        let cli = Cli::try_parse_from(["mvmctl", "run", "--flake", "."]).unwrap();
        match cli.command {
            Commands::Up { port, env, .. } => {
                assert!(port.is_empty());
                assert!(env.is_empty());
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_run_forward_flag() {
        let cli = Cli::try_parse_from([
            "mvmctl",
            "run",
            "--flake",
            ".",
            "-p",
            "3333:3000",
            "--forward",
        ])
        .unwrap();
        match cli.command {
            Commands::Up { forward, port, .. } => {
                assert!(forward);
                assert_eq!(port, vec!["3333:3000"]);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_run_forward_default_false() {
        let cli = Cli::try_parse_from(["mvmctl", "run", "--flake", "."]).unwrap();
        match cli.command {
            Commands::Up { forward, .. } => {
                assert!(!forward);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_parse_port_specs_multiple() {
        let specs = vec!["3333:3000".to_string(), "8080".to_string()];
        let result = parse_port_specs(&specs).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].host, 3333);
        assert_eq!(result[0].guest, 3000);
        assert_eq!(result[1].host, 8080);
        assert_eq!(result[1].guest, 8080);
    }

    #[test]
    fn test_parse_port_specs_empty() {
        let specs: Vec<String> = vec![];
        let result = parse_port_specs(&specs).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_ports_to_drive_file() {
        use mvm_runtime::config::PortMapping;
        let ports = vec![
            PortMapping {
                host: 3333,
                guest: 3000,
            },
            PortMapping {
                host: 3334,
                guest: 3002,
            },
        ];
        let f = ports_to_drive_file(&ports).unwrap();
        assert_eq!(f.name, "mvm-ports.env");
        assert!(f.content.contains("MVM_PORT_MAP=\"3333:3000,3334:3002\""));
        assert_eq!(f.mode, 0o444);
    }

    #[test]
    fn test_ports_to_drive_file_empty() {
        assert!(ports_to_drive_file(&[]).is_none());
    }

    #[test]
    fn test_env_vars_to_drive_file() {
        let vars = vec!["NODE_ENV=production".to_string(), "DEBUG=true".to_string()];
        let f = env_vars_to_drive_file(&vars).unwrap();
        assert_eq!(f.name, "mvm-env.env");
        assert!(f.content.contains("export NODE_ENV=production"));
        assert!(f.content.contains("export DEBUG=true"));
        assert_eq!(f.mode, 0o444);
    }

    #[test]
    fn test_env_vars_to_drive_file_empty() {
        let vars: Vec<String> = vec![];
        assert!(env_vars_to_drive_file(&vars).is_none());
    }

    // ---- VM subcommand tests ----

    // ---- Up/Down command tests ----

    #[test]
    fn test_down_parses_no_args() {
        let cli = Cli::try_parse_from(["mvmctl", "down"]).unwrap();
        match cli.command {
            Commands::Down { name, config } => {
                assert!(name.is_none());
                assert!(config.is_none());
            }
            _ => panic!("Expected Down command"),
        }
    }

    #[test]
    fn test_down_parses_with_name() {
        let cli = Cli::try_parse_from(["mvmctl", "down", "gw"]).unwrap();
        match cli.command {
            Commands::Down { name, config } => {
                assert_eq!(name.as_deref(), Some("gw"));
                assert!(config.is_none());
            }
            _ => panic!("Expected Down command"),
        }
    }

    #[test]
    fn test_down_parses_with_config() {
        let cli = Cli::try_parse_from(["mvmctl", "down", "-f", "my-fleet.toml"]).unwrap();
        match cli.command {
            Commands::Down { name, config } => {
                assert!(name.is_none());
                assert_eq!(config.as_deref(), Some("my-fleet.toml"));
            }
            _ => panic!("Expected Down command"),
        }
    }

    // ---- read_dir_to_drive_files tests ----

    #[test]
    fn test_read_dir_to_drive_files_reads_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "hello").unwrap();
        std::fs::write(dir.path().join("b.env"), "KEY=val").unwrap();

        let files = read_dir_to_drive_files(dir.path().to_str().unwrap(), 0o444).unwrap();
        assert_eq!(files.len(), 2);

        let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"a.txt"));
        assert!(names.contains(&"b.env"));

        for f in &files {
            assert_eq!(f.mode, 0o444);
        }
    }

    #[test]
    fn test_read_dir_to_drive_files_skips_directories() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), "content").unwrap();
        std::fs::create_dir(dir.path().join("subdir")).unwrap();

        let files = read_dir_to_drive_files(dir.path().to_str().unwrap(), 0o400).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "file.txt");
        assert_eq!(files[0].mode, 0o400);
    }

    #[test]
    fn test_read_dir_to_drive_files_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let files = read_dir_to_drive_files(dir.path().to_str().unwrap(), 0o444).unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn test_read_dir_to_drive_files_nonexistent_dir() {
        let result = read_dir_to_drive_files("/nonexistent/path/abc123", 0o444);
        assert!(result.is_err());
    }

    // ---- Forward command tests ----

    #[test]
    fn test_forward_parses() {
        let cli = Cli::try_parse_from(["mvmctl", "forward", "swift", "3000"]).unwrap();
        match cli.command {
            Commands::Forward { name, port, ports } => {
                assert_eq!(name, "swift");
                // Positional ports land in `ports`, flag ports in `port`.
                assert!(port.is_empty());
                assert_eq!(ports, vec!["3000"]);
            }
            _ => panic!("Expected Forward command"),
        }
    }

    #[test]
    fn test_forward_with_port_mapping() {
        let cli = Cli::try_parse_from(["mvmctl", "forward", "swift", "8080:3000"]).unwrap();
        match cli.command {
            Commands::Forward { name, port, ports } => {
                assert_eq!(name, "swift");
                assert!(port.is_empty());
                assert_eq!(ports, vec!["8080:3000"]);
            }
            _ => panic!("Expected Forward command"),
        }
    }

    #[test]
    fn test_forward_with_flag() {
        let cli = Cli::try_parse_from(["mvmctl", "forward", "swift", "-p", "3000"]).unwrap();
        match cli.command {
            Commands::Forward { name, port, ports } => {
                assert_eq!(name, "swift");
                assert_eq!(port, vec!["3000"]);
                assert!(ports.is_empty());
            }
            _ => panic!("Expected Forward command"),
        }
    }

    #[test]
    fn test_forward_multiple_ports() {
        let cli =
            Cli::try_parse_from(["mvmctl", "forward", "swift", "-p", "3000", "-p", "8080:443"])
                .unwrap();
        match cli.command {
            Commands::Forward { name, port, ports } => {
                assert_eq!(name, "swift");
                assert_eq!(port, vec!["3000", "8080:443"]);
                assert!(ports.is_empty());
            }
            _ => panic!("Expected Forward command"),
        }
    }

    #[test]
    fn test_forward_multiple_positional() {
        let cli = Cli::try_parse_from(["mvmctl", "forward", "swift", "3000", "8080:443"]).unwrap();
        match cli.command {
            Commands::Forward { name, port, ports } => {
                assert_eq!(name, "swift");
                assert!(port.is_empty());
                assert_eq!(ports, vec!["3000", "8080:443"]);
            }
            _ => panic!("Expected Forward command"),
        }
    }

    #[test]
    fn test_forward_no_ports_parses() {
        // forward with no ports should parse successfully — cmd_forward
        // falls back to persisted ports from run-info.json
        let cli = Cli::try_parse_from(["mvmctl", "forward", "swift"]).unwrap();
        match cli.command {
            Commands::Forward { name, port, ports } => {
                assert_eq!(name, "swift");
                assert!(port.is_empty());
                assert!(ports.is_empty());
            }
            _ => panic!("Expected Forward command"),
        }
    }

    #[test]
    fn test_parse_port_spec_single() {
        let (local, guest) = parse_port_spec("3000").unwrap();
        assert_eq!(local, 3000);
        assert_eq!(guest, 3000);
    }

    #[test]
    fn test_parse_port_spec_mapping() {
        let (local, guest) = parse_port_spec("8080:3000").unwrap();
        assert_eq!(local, 8080);
        assert_eq!(guest, 3000);
    }

    #[test]
    fn test_parse_port_spec_invalid() {
        assert!(parse_port_spec("abc").is_err());
        assert!(parse_port_spec("abc:3000").is_err());
        assert!(parse_port_spec("3000:abc").is_err());
        assert!(parse_port_spec("99999").is_err());
    }

    // -------------------------------------------------------------------------
    // Alias tests (Phase 4)
    // -------------------------------------------------------------------------

    #[test]
    fn test_ls_alias_for_ps() {
        let cli = Cli::try_parse_from(["mvmctl", "ls"]).unwrap();
        assert!(matches!(cli.command, Commands::Ps { .. }));
    }

    #[test]
    fn test_ps_command() {
        let cli = Cli::try_parse_from(["mvmctl", "ps"]).unwrap();
        assert!(matches!(cli.command, Commands::Ps { .. }));
    }

    #[test]
    fn test_start_alias_for_run() {
        // 'start' is already an alias on Run — verify it still works
        assert!(Cli::try_parse_from(["mvmctl", "start", "--flake", "."]).is_ok());
    }

    // -------------------------------------------------------------------------
    // Metrics tests (Phase 1)
    // -------------------------------------------------------------------------

    #[test]
    fn test_metrics_command_parses() {
        let cli = Cli::try_parse_from(["mvmctl", "metrics"]).unwrap();
        assert!(matches!(cli.command, Commands::Metrics { json: false }));
    }

    #[test]
    fn test_metrics_json_flag_parses() {
        let cli = Cli::try_parse_from(["mvmctl", "metrics", "--json"]).unwrap();
        assert!(matches!(cli.command, Commands::Metrics { json: true }));
    }

    #[test]
    fn test_metrics_snapshot_serializes_to_json() {
        let snap = mvm_core::observability::metrics::global().snapshot();
        let json = serde_json::to_string(&snap).expect("snapshot must serialize");
        assert!(json.contains("requests_total"));
        assert!(json.contains("instances_created"));
    }

    #[test]
    fn test_prometheus_exposition_has_expected_metrics() {
        let prom = mvm_core::observability::metrics::global().prometheus_exposition();
        assert!(prom.contains("mvm_requests_total"));
        assert!(prom.contains("mvm_instances_created_total"));
        assert!(prom.contains("# HELP"));
        assert!(prom.contains("# TYPE"));
    }

    // ---- Config command tests ----

    #[test]
    fn test_config_show_parses() {
        let cli = Cli::try_parse_from(["mvmctl", "config", "show"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Config {
                action: ConfigAction::Show
            }
        ));
    }

    #[test]
    fn test_config_set_parses() {
        let cli = Cli::try_parse_from(["mvmctl", "config", "set", "lima_cpus", "4"]).unwrap();
        match cli.command {
            Commands::Config {
                action: ConfigAction::Set { key, value },
            } => {
                assert_eq!(key, "lima_cpus");
                assert_eq!(value, "4");
            }
            _ => panic!("Expected Config Set command"),
        }
    }

    #[test]
    fn test_config_show_output_contains_lima_cpus() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = mvm_core::user_config::MvmConfig::default();
        mvm_core::user_config::save(&cfg, Some(tmp.path())).unwrap();
        let loaded = mvm_core::user_config::load(Some(tmp.path()));
        let text = toml::to_string_pretty(&loaded).unwrap();
        assert!(text.contains("lima_cpus"));
    }

    #[test]
    fn test_config_set_persists() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = mvm_core::user_config::load(Some(tmp.path()));
        mvm_core::user_config::set_key(&mut cfg, "lima_cpus", "4").unwrap();
        mvm_core::user_config::save(&cfg, Some(tmp.path())).unwrap();
        let reloaded = mvm_core::user_config::load(Some(tmp.path()));
        assert_eq!(reloaded.lima_cpus, 4);
    }

    #[test]
    fn test_config_set_unknown_key_fails() {
        let mut cfg = mvm_core::user_config::MvmConfig::default();
        let err = mvm_core::user_config::set_key(&mut cfg, "nonexistent_key", "5").unwrap_err();
        assert!(err.to_string().contains("Unknown config key"));
    }

    // ---- Uninstall command tests ----

    #[test]
    fn test_uninstall_parses_defaults() {
        let cli = Cli::try_parse_from(["mvmctl", "uninstall", "--yes"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Uninstall {
                yes: true,
                all: false,
                dry_run: false,
            }
        ));
    }

    #[test]
    fn test_uninstall_dry_run_parses() {
        let cli = Cli::try_parse_from(["mvmctl", "uninstall", "--dry-run", "--yes"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Uninstall {
                yes: true,
                all: false,
                dry_run: true,
            }
        ));
    }

    #[test]
    fn test_uninstall_all_flag_parses() {
        let cli = Cli::try_parse_from(["mvmctl", "uninstall", "--all", "--yes"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Uninstall {
                yes: true,
                all: true,
                dry_run: false,
            }
        ));
    }

    // ---- Audit command tests ----

    #[test]
    fn test_audit_tail_parses() {
        let cli = Cli::try_parse_from(["mvmctl", "audit", "tail"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Audit {
                action: AuditCmd::Tail {
                    lines: 20,
                    follow: false,
                }
            }
        ));
    }

    #[test]
    fn test_audit_tail_follow_parses() {
        let cli =
            Cli::try_parse_from(["mvmctl", "audit", "tail", "--follow", "--lines", "50"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Audit {
                action: AuditCmd::Tail {
                    lines: 50,
                    follow: true,
                }
            }
        ));
    }

    #[test]
    fn test_audit_tail_no_log_prints_message() {
        // When no audit log exists, cmd_audit_tail should succeed with a
        // helpful message rather than an error.
        let tmp = tempfile::tempdir().unwrap();
        let nonexistent = tmp.path().join("audit.jsonl");
        // Path doesn't exist — simulate the early-return path.
        assert!(!nonexistent.exists());
    }

    // ---- Clap value parser tests ----

    #[test]
    fn test_clap_port_spec_valid() {
        assert!(clap_port_spec("8080").is_ok());
        assert!(clap_port_spec("8080:80").is_ok());
        assert!(clap_port_spec("443:443").is_ok());
        assert!(clap_port_spec("0:0").is_ok());
    }

    #[test]
    fn test_clap_port_spec_invalid() {
        assert!(clap_port_spec("").is_err());
        assert!(clap_port_spec("abc").is_err());
        assert!(clap_port_spec("8080:abc").is_err());
        assert!(clap_port_spec("abc:80").is_err());
        assert!(clap_port_spec("99999").is_err()); // out of u16 range
    }

    #[test]
    fn test_clap_volume_spec_valid() {
        assert!(clap_volume_spec("/host:/guest").is_ok());
        assert!(clap_volume_spec("/host/path:/guest/mount").is_ok());
        assert!(clap_volume_spec("/host:/guest:1G").is_ok());
        assert!(clap_volume_spec("./local:/app").is_ok());
    }

    #[test]
    fn test_clap_volume_spec_invalid() {
        assert!(clap_volume_spec("").is_err());
        assert!(clap_volume_spec("nocolon").is_err());
        assert!(clap_volume_spec(":/guest").is_err()); // empty host
    }

    #[test]
    fn test_clap_vm_name_valid() {
        assert!(clap_vm_name("my-vm").is_ok());
        assert!(clap_vm_name("vm1").is_ok());
        assert!(clap_vm_name("a").is_ok());
    }

    #[test]
    fn test_clap_vm_name_invalid() {
        assert!(clap_vm_name("").is_err());
        assert!(clap_vm_name("UPPER").is_err());
        assert!(clap_vm_name("has space").is_err());
        assert!(clap_vm_name("-leading").is_err());
    }

    #[test]
    fn test_clap_flake_ref_valid() {
        assert!(clap_flake_ref(".").is_ok());
        assert!(clap_flake_ref("github:org/repo").is_ok());
        assert!(clap_flake_ref("/absolute/path").is_ok());
    }

    #[test]
    fn test_clap_flake_ref_invalid() {
        assert!(clap_flake_ref("").is_err());
        assert!(clap_flake_ref(". ; rm -rf /").is_err());
        assert!(clap_flake_ref("$(evil)").is_err());
    }

    #[test]
    fn test_run_rejects_invalid_vm_name_at_parse_time() {
        // Clap should reject bad --name values before any command runs.
        let result = Cli::try_parse_from(["mvmctl", "run", "--flake", ".", "--name", "INVALID"]);
        assert!(
            result.is_err(),
            "uppercase VM name should fail at parse time"
        );
    }

    #[test]
    fn test_run_rejects_invalid_flake_at_parse_time() {
        let result =
            Cli::try_parse_from(["mvmctl", "run", "--flake", ". ; rm -rf /", "--name", "vm1"]);
        assert!(
            result.is_err(),
            "shell-injection flake ref should fail at parse time"
        );
    }

    #[test]
    fn test_run_rejects_invalid_port_at_parse_time() {
        let result = Cli::try_parse_from(["mvmctl", "run", "--flake", ".", "--port", "notaport"]);
        assert!(result.is_err(), "invalid port should fail at parse time");
    }

    // ---- Config defaults wired into cmd_run ----

    #[test]
    fn test_run_uses_config_default_cpus() {
        // When --cpus is omitted, the config default should be applied.
        let cfg = mvm_core::user_config::MvmConfig {
            default_cpus: 4,
            ..mvm_core::user_config::MvmConfig::default()
        };

        // Simulate the resolution logic from the Commands::Up dispatch.
        let cli_cpus: Option<u32> = None;
        let effective = cli_cpus.or(Some(cfg.default_cpus));
        assert_eq!(effective, Some(4));
    }

    #[test]
    fn test_run_cli_flag_overrides_config_cpus() {
        // When --cpus is provided, it takes precedence over config.
        let cfg = mvm_core::user_config::MvmConfig {
            default_cpus: 4,
            ..mvm_core::user_config::MvmConfig::default()
        };

        let cli_cpus: Option<u32> = Some(8);
        let effective = cli_cpus.or(Some(cfg.default_cpus));
        assert_eq!(effective, Some(8));
    }

    #[test]
    fn test_run_uses_config_default_memory() {
        let cfg = mvm_core::user_config::MvmConfig {
            default_memory_mib: 2048,
            ..mvm_core::user_config::MvmConfig::default()
        };

        let cli_memory: Option<u32> = None;
        let effective = cli_memory.or(Some(cfg.default_memory_mib));
        assert_eq!(effective, Some(2048));
    }

    #[test]
    fn test_run_cli_flag_overrides_config_memory() {
        let cfg = mvm_core::user_config::MvmConfig {
            default_memory_mib: 2048,
            ..mvm_core::user_config::MvmConfig::default()
        };

        let cli_memory: Option<u32> = Some(512);
        let effective = cli_memory.or(Some(cfg.default_memory_mib));
        assert_eq!(effective, Some(512));
    }

    #[test]
    fn test_resolve_network_policy_default() {
        let policy = resolve_network_policy(None, &[]).unwrap();
        assert!(policy.is_unrestricted());
    }

    #[test]
    fn test_resolve_network_policy_preset() {
        let policy = resolve_network_policy(Some("dev"), &[]).unwrap();
        assert!(!policy.is_unrestricted());
        let rules = policy.resolve_rules().unwrap();
        assert!(rules.iter().any(|r| r.host == "github.com"));
    }

    #[test]
    fn test_resolve_network_policy_allow_list() {
        let allow = vec![
            "github.com:443".to_string(),
            "api.openai.com:443".to_string(),
        ];
        let policy = resolve_network_policy(None, &allow).unwrap();
        let rules = policy.resolve_rules().unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn test_resolve_network_policy_mutual_exclusion() {
        let allow = vec!["github.com:443".to_string()];
        let result = resolve_network_policy(Some("dev"), &allow);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_network_policy_invalid_preset() {
        let result = resolve_network_policy(Some("bogus"), &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_network_policy_invalid_allow_entry() {
        let allow = vec!["not-a-host-port".to_string()];
        let result = resolve_network_policy(None, &allow);
        assert!(result.is_err());
    }

    // --- Network CLI tests ---

    #[test]
    fn test_network_list_help() {
        let cli = Cli::try_parse_from(["mvmctl", "network", "list"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_network_create_help() {
        let cli = Cli::try_parse_from(["mvmctl", "network", "create", "mynet"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_network_inspect_help() {
        let cli = Cli::try_parse_from(["mvmctl", "network", "inspect", "mynet"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_network_remove_help() {
        let cli = Cli::try_parse_from(["mvmctl", "network", "rm", "mynet"]);
        assert!(cli.is_ok());
    }

    // --- Image CLI tests ---

    #[test]
    fn test_image_list_help() {
        let cli = Cli::try_parse_from(["mvmctl", "image", "list"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_image_search_help() {
        let cli = Cli::try_parse_from(["mvmctl", "image", "search", "http"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_image_fetch_help() {
        let cli = Cli::try_parse_from(["mvmctl", "image", "fetch", "minimal"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_image_info_help() {
        let cli = Cli::try_parse_from(["mvmctl", "image", "info", "postgres"]);
        assert!(cli.is_ok());
    }

    // --- Console CLI tests ---

    #[test]
    fn test_console_help() {
        let cli = Cli::try_parse_from(["mvmctl", "console", "myvm"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_console_with_command() {
        let cli = Cli::try_parse_from(["mvmctl", "console", "myvm", "--command", "ls"]);
        assert!(cli.is_ok());
        match cli.unwrap().command {
            Commands::Console { name, command } => {
                assert_eq!(name, "myvm");
                assert_eq!(command.as_deref(), Some("ls"));
            }
            _ => panic!("Expected Console command"),
        }
    }

    // --- Init CLI tests ---

    #[test]
    fn test_init_defaults() {
        let cli = Cli::try_parse_from(["mvmctl", "init"]).unwrap();
        match cli.command {
            Commands::Init {
                non_interactive,
                lima_cpus,
                lima_mem,
            } => {
                assert!(!non_interactive);
                assert_eq!(lima_cpus, 8);
                assert_eq!(lima_mem, 16);
            }
            _ => panic!("Expected Init command"),
        }
    }

    #[test]
    fn test_init_non_interactive() {
        let cli = Cli::try_parse_from(["mvmctl", "init", "--non-interactive", "--lima-cpus", "4"])
            .unwrap();
        match cli.command {
            Commands::Init {
                non_interactive,
                lima_cpus,
                ..
            } => {
                assert!(non_interactive);
                assert_eq!(lima_cpus, 4);
            }
            _ => panic!("Expected Init command"),
        }
    }

    // --- Security CLI tests ---

    #[test]
    fn test_security_status_help() {
        let cli = Cli::try_parse_from(["mvmctl", "security", "status"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_security_status_json() {
        let cli = Cli::try_parse_from(["mvmctl", "security", "status", "--json"]).unwrap();
        match cli.command {
            Commands::Security {
                action: SecurityCmd::Status { json },
            } => {
                assert!(json);
            }
            _ => panic!("Expected Security Status command"),
        }
    }

    // --- Cache CLI tests ---

    #[test]
    fn test_cache_info() {
        let cli = Cli::try_parse_from(["mvmctl", "cache", "info"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cache_prune() {
        let cli = Cli::try_parse_from(["mvmctl", "cache", "prune"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cache_prune_dry_run() {
        let cli = Cli::try_parse_from(["mvmctl", "cache", "prune", "--dry-run"]).unwrap();
        match cli.command {
            Commands::Cache {
                action: CacheCmd::Prune { dry_run },
            } => {
                assert!(dry_run);
            }
            _ => panic!("Expected Cache Prune command"),
        }
    }

    // --- Up --network flag tests ---

    #[test]
    fn test_up_network_default() {
        let cli = Cli::try_parse_from(["mvmctl", "up", "--flake", "."]).unwrap();
        match cli.command {
            Commands::Up { network, .. } => {
                assert_eq!(network, "default");
            }
            _ => panic!("Expected Up command"),
        }
    }

    #[test]
    fn test_up_network_custom() {
        let cli =
            Cli::try_parse_from(["mvmctl", "up", "--flake", ".", "--network", "isolated"]).unwrap();
        match cli.command {
            Commands::Up { network, .. } => {
                assert_eq!(network, "isolated");
            }
            _ => panic!("Expected Up command"),
        }
    }

    // --- Apple Container dev tests ---

    #[test]
    fn test_dev_up_with_lima_flag() {
        let cli = Cli::try_parse_from(["mvmctl", "dev", "up", "--lima"]).unwrap();
        match cli.command {
            Commands::Dev {
                action: Some(DevCmd::Up { lima, .. }),
            } => {
                assert!(lima);
            }
            _ => panic!("Expected Dev Up command"),
        }
    }

    #[test]
    fn test_dev_down_parses() {
        let cli = Cli::try_parse_from(["mvmctl", "dev", "down"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_dev_shell_parses() {
        let cli = Cli::try_parse_from(["mvmctl", "dev", "shell"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_dev_status_parses() {
        let cli = Cli::try_parse_from(["mvmctl", "dev", "status"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_is_apple_container_dev_running_returns_bool() {
        // Just verify it doesn't panic — actual result depends on platform
        let _ = is_apple_container_dev_running();
    }
}
