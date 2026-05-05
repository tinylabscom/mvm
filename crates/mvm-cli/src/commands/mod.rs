mod build;
mod catalog;
mod env;
mod manifest;
mod ops;
mod shared;
mod vm;

#[cfg(test)]
mod tests;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use std::sync::Arc;

use crate::logging::{self, LogFormat};

use shared::{CHILD_PIDS, IN_CONSOLE_MODE, with_hints};

#[derive(Parser, Debug, Clone)]
#[command(name = "mvmctl", version, about = "Lightweight VM development tool")]
pub(in crate::commands) struct Cli {
    /// Log format: human (default) or json (structured)
    #[arg(long, global = true)]
    pub log_format: Option<String>,

    /// Override Firecracker version (e.g., v1.14.0)
    #[arg(long, global = true)]
    pub fc_version: Option<String>,

    /// Show verbose `[mvm]` progress messages. Implied when `RUST_LOG` is set.
    #[arg(long, global = true, alias = "debug")]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)] // Up variant has many CLI fields; boxing breaks Clap derive
pub(in crate::commands) enum Commands {
    /// Full environment setup from scratch
    Bootstrap(env::bootstrap::Args),
    /// Manage the Lima development environment (up, down, shell, status)
    Dev(env::dev::Args),
    /// Remove old dev-build artifacts and run Nix garbage collection
    Cleanup(env::cleanup::Args),
    /// Show console logs from a running microVM
    Logs(vm::logs::Args),
    /// Forward a port from a running microVM to localhost
    Forward(vm::forward::Args),
    /// List running VMs
    Ls(vm::ps::Args),
    /// Check for and install the latest version of mvmctl
    Update(env::update::Args),
    /// System diagnostics and dependency checks
    Doctor(env::doctor::Args),
    /// Manage built manifest slots (list, info, remove). Plan 38 §4.
    Manifest(manifest::Args),
    /// Build a microVM image from a Mvmfile.toml config or Nix flake
    Build(build::build::Args),
    /// Build and run a VM from a Nix flake, a manifest path, or the bundled default image.
    ///
    /// If neither `--flake` nor `--manifest` is supplied, the bundled
    /// `nix/images/default-tenant/` image is used (built via Nix on first use,
    /// cached at `~/.cache/mvm/default-microvm/`).
    Up(vm::up::Args),
    /// Stop microVMs (from mvm.toml, by name, or all)
    Down(vm::down::Args),
    /// Print shell configuration (completions + dev aliases) to stdout
    ShellInit(env::shell_init::Args),
    /// Show runtime metrics (Prometheus text format by default)
    Metrics(ops::metrics::Args),
    /// Read or write global operator config (~/.mvm/config.toml)
    Config(ops::config::Args),
    /// Remove Lima VM, Firecracker binary, and all mvm state (clean uninstall)
    Uninstall(env::uninstall::Args),
    /// View the local audit log (~/.mvm/log/audit.jsonl)
    Audit(ops::audit::Args),
    /// Validate a Nix flake before building (runs `nix flake check`)
    Validate(build::validate::Args),
    /// Show filesystem changes in a running VM (files created/modified/deleted since boot)
    Diff(vm::diff::Args),
    /// Manage named dev networks
    Network(ops::network::Args),
    /// Browse the bundled image catalog
    Catalog(catalog::Args),
    /// Interactive console (PTY-over-vsock) to a running VM
    Console(vm::console::Args),
    /// Manage the XDG cache directory (~/.cache/mvm)
    Cache(ops::cache::Args),
    /// Scaffold a project (`mvm.toml` + `flake.nix`). Use `mvmctl bootstrap` for first-time environment setup.
    Init(env::init::Args),
    /// Boot a transient microVM, run a single command, and tear down (dev-mode only).
    ///
    /// Inspired by cco — same one-command UX, but with a Firecracker microVM as the sandbox.
    /// Use `--add-dir host:guest[:mode]` to share a host directory (default `:ro`; pass `:rw`
    /// to rsync writes back to the host on exit). Use `--` to separate the argv from
    /// `mvmctl exec` flags. Alternatively, pass `--launch-plan ./launch.json` to invoke an
    /// mvmforge-emitted entrypoint instead of an inline argv.
    Exec(vm::exec::Args),
    /// Boot a microVM and call its baked entrypoint (production-safe).
    ///
    /// Distinct from `mvmctl exec` (dev-only, arbitrary shell). `invoke` dispatches the
    /// `RunEntrypoint` vsock verb, which the guest agent serves only by spawning the
    /// program named in `/etc/mvm/entrypoint`. No shell, no argv override, no env
    /// injection beyond what the wrapper template defined at image build time. Stdin
    /// from `--stdin <PATH>` (or `-` for mvmctl's own stdin); stdout/stderr stream back
    /// to mvmctl's own streams. ADR-007 / plan 41.
    Invoke(vm::invoke::Args),
    /// Speak Model Context Protocol — exposes mvmctl as a sandbox surface for LLM clients.
    ///
    /// Single parameterized `run` tool whose `env` parameter selects from `mvmctl template list`.
    /// Each call boots a transient microVM, runs the supplied code, and tears down. Like
    /// `mvmctl exec`, the dispatch path requires a dev-feature guest agent (ADR-002 §W4.3);
    /// against a production guest the call returns "exec not available" gracefully. ADR-003
    /// documents the threat model and design.
    Mcp(ops::mcp::Args),
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

    // Initialize logging.
    //
    // The MCP stdio subcommand needs *exclusive* control of stdout so
    // JSON-RPC framing isn't corrupted by stray log lines (cross-cutting
    // "A: stdout-only-JSON-RPC discipline" — plan 32 §"Cross-cutting
    // considerations"). Skip the default `logging::init` (which installs
    // a stdout-writing subscriber) for `mvmctl mcp` and let
    // `mvm_mcp::init_stderr_tracing` install its own stderr-only one.
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
    if !matches!(cli.command, Commands::Mcp(_)) {
        logging::init(log_format);
    }

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

    let result = match cli.command.clone() {
        Commands::Bootstrap(a) => env::bootstrap::run(&cli, a, &cfg),
        Commands::Dev(a) => env::dev::run(&cli, a, &cfg),
        Commands::Cleanup(a) => env::cleanup::run(&cli, a, &cfg),
        Commands::Logs(a) => vm::logs::run(&cli, a, &cfg),
        Commands::Forward(a) => vm::forward::run(&cli, a, &cfg),
        Commands::Ls(a) => vm::ps::run(&cli, a, &cfg),
        Commands::Update(a) => env::update::run(&cli, a, &cfg),
        Commands::Doctor(a) => env::doctor::run(&cli, a, &cfg),
        Commands::Manifest(a) => manifest::run(&cli, a, &cfg),
        Commands::Build(a) => build::build::run(&cli, a, &cfg),
        Commands::Up(a) => vm::up::run(&cli, a, &cfg),
        Commands::Down(a) => vm::down::run(&cli, a, &cfg),
        Commands::ShellInit(a) => env::shell_init::run(&cli, a, &cfg),
        Commands::Metrics(a) => ops::metrics::run(&cli, a, &cfg),
        Commands::Config(a) => ops::config::run(&cli, a, &cfg),
        Commands::Uninstall(a) => env::uninstall::run(&cli, a, &cfg),
        Commands::Audit(a) => ops::audit::run(&cli, a, &cfg),
        Commands::Validate(a) => build::validate::run(&cli, a, &cfg),
        Commands::Diff(a) => vm::diff::run(&cli, a, &cfg),
        Commands::Network(a) => ops::network::run(&cli, a, &cfg),
        Commands::Catalog(a) => catalog::run(&cli, a, &cfg),
        Commands::Console(a) => vm::console::run(&cli, a, &cfg),
        Commands::Cache(a) => ops::cache::run(&cli, a, &cfg),
        Commands::Init(a) => env::init::run(&cli, a, &cfg),
        Commands::Exec(a) => vm::exec::run(&cli, a, &cfg),
        Commands::Invoke(a) => vm::invoke::run(&cli, a, &cfg),
        Commands::Mcp(a) => ops::mcp::run(&cli, a, &cfg),
    };

    with_hints(result)
}
