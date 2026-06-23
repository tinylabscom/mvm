mod bootstrap;
mod build;
mod bundle;
mod catalog;
mod cmd_audit;
mod deps;
mod env;
mod image;
mod machine;
mod manifest;
mod ops;
/// Supervisor warm-pool: the `mvmctl pool warm/status` command + the launch glue
/// (`try_warm_claim`/`replenish_after_launch`) the transient `machine run` path
/// (`crate::exec::run_inner`) calls to claim a warm standby (auto-named,
/// bridge-admitted launches) and top the pool back up. `pub(crate)` so the
/// crate-root `exec` runner can reach the glue.
pub(crate) mod pool;
mod qemu_bridge;
mod shared;
mod ssh_agent_proxy;
mod storage;
mod trust;
pub(crate) mod vm;

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

    /// Override which hypervisor drives the builder VM.
    /// Highest priority — beats `MVM_BUILDER_BACKEND`
    /// env and the platform-default auto-detect (macOS 26+ Apple
    /// Silicon → vz; everywhere else → libkrun).
    #[arg(long, global = true, value_parser = ["libkrun", "vz", "qemu"])]
    pub builder: Option<String>,

    /// Where the builder VM's kernel comes from when its image is
    /// (re)built: `compile` (default — build it in-image via Stage 0),
    /// `download` (boot on a published, hash-verified kernel — skips the
    /// kernel compile), or `auto` (download if available, else compile).
    #[arg(long, global = true, value_parser = ["compile", "download", "auto"])]
    pub kernel_source: Option<String>,

    /// Increase log verbosity: -v (info), -vv (debug), -vvv (trace).
    /// Default is quiet (errors only). `RUST_LOG=<filter>` overrides.
    /// Place before the subcommand, e.g. `mvmctl -vv run -- …`.
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)] // Up variant has many CLI fields; boxing breaks Clap derive
pub(in crate::commands) enum Commands {
    /// Beginner microVM workflows (run an OCI image and more)
    #[command(display_order = 1)]
    Machine(machine::Args),
    /// Manage the local dev VM
    #[command(display_order = 2)]
    Dev(env::dev::Args),
    /// Build-time commands (image, compile, validate, kernel)
    #[command(display_order = 3)]
    Build(build::group::Args),
    /// Scaffold a new project
    #[command(display_order = 4)]
    Init(env::init::Args),
    /// System diagnostics and dependency checks
    #[command(display_order = 5)]
    Doctor(env::doctor::Args),
    /// List running VMs
    Ls(vm::ps::Args),
    /// SDK transport surface (`run --mode live/plan`). Hidden: the user-facing
    /// transient-run role folded into `machine run`; `run` survives only as the
    /// SDK Sandbox launcher the Python/TS SDKs shell to, so it stays hidden
    /// rather than break that transport.
    #[command(hide = true)]
    Run(vm::exec::RunArgs),
    /// Internal SDK host-dispatch transport for `MVM_NO_VM=1`.
    #[command(name = "__sdk-no-vm", hide = true)]
    SdkNoVm(vm::sdk_no_vm::Args),
    /// Prepare the environment + pre-fetch the builder VM image
    ///
    /// Runs host-tooling setup and pre-acquires the builder VM image so the
    /// first `dev up` is fast. Run automatically by install.sh unless
    /// `MVM_SKIP_BUILDER_PREFETCH=1`.
    Bootstrap(bootstrap::Args),
    /// Environment / install lifecycle (bootstrap, update, sign, …)
    #[command(hide = true)]
    Env(env::group::Args),
    /// Manage built manifest slots
    #[command(hide = true)]
    Manifest(manifest::Args),
    /// Inspect cached OCI images
    #[command(hide = true)]
    Image(image::Args),
    /// Inspect the dm-thin storage pool
    #[command(hide = true)]
    Storage(storage::Args),
    /// Print shell configuration (completions + dev aliases) to stdout
    #[command(hide = true)]
    ShellInit(env::shell_init::Args),
    /// Operational / observability commands (metrics, bench, config, mcp)
    #[command(hide = true)]
    Ops(ops::group::Args),
    /// Manage named dev networks
    #[command(hide = true)]
    Network(ops::network::Args),
    /// Browse the bundled image catalog
    #[command(hide = true)]
    Catalog(catalog::Args),
    /// Manage the XDG cache directory (~/.cache/mvm)
    #[command(hide = true)]
    Cache(ops::cache::Args),
    /// Manage the supervisor warm pool (pre-spawned standbys for fast `up`)
    #[command(hide = true)]
    Pool(pool::Args),
    /// Converge the VM name registry with on-disk runtime state
    #[command(hide = true)]
    Reconcile(ops::reconcile::Args),
    /// Manage local secret namespaces
    #[command(hide = true)]
    Secret(ops::secret::Args),
    /// Seal or verify portable VM bundles
    #[command(hide = true)]
    Bundle(bundle::Args),
    /// Manage trusted bundle publishers
    #[command(hide = true)]
    Trust(trust::Args),
    /// Inspect cached application dependencies
    #[command(hide = true)]
    Deps(deps::Args),
    /// Pack or verify signed `.mvm` artifacts
    #[command(hide = true)]
    Artifact(vm::artifact::Args),
    /// Manage the persistent builder VM
    #[cfg(feature = "builder-vm")]
    #[command(name = "persistent-builder", hide = true)]
    PersistentBuilder(build::persistent_builder::Args),
    /// Internal: host-side AF_VSOCK↔UNIX bridge for the QEMU workload
    /// backend. Spawned detached by `mvm_backend::qemu`; not a
    /// user-facing command.
    #[command(name = "__qemu-vsock-bridge", hide = true)]
    QemuVsockBridge(qemu_bridge::Args),
    /// Internal: per-machine SSH_AUTH_SOCK proxy for dev-tier machines.
    #[command(name = "__ssh-agent-proxy", hide = true)]
    SshAgentProxy(ssh_agent_proxy::Args),
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

    // Apply builder-backend override before any subcommand reads it.
    // Plumbing the flag through every call site that consults
    // `resolve_builder_backend()` would touch a lot of files for
    // little value; setting the env here makes the existing env-var
    // dispatch in `mvm_build::builder_backend_select` honour the
    // flag transparently. Same single-threaded-startup invariant as
    // the `fc_version` block above.
    if let Some(ref backend) = cli.builder {
        unsafe { std::env::set_var("MVM_BUILDER_BACKEND", backend) };
    }

    // Kernel-acquisition override for the builder VM image bootstrap.
    // Read by `resolve_kernel_source()` in the Stage 0 path. Same
    // single-threaded-startup invariant as the blocks above.
    if let Some(ref source) = cli.kernel_source {
        unsafe { std::env::set_var("MVM_KERNEL_SOURCE", source) };
    }

    // Verbose `[mvm]` chatter: explicit flag, or any RUST_LOG set.
    let verbose = cli.verbose > 0 || std::env::var_os("RUST_LOG").is_some();
    mvm::ui::set_verbose(verbose);

    // Propagate the chosen verbosity to spawned child processes (drainer,
    // supervisor, …) which read RUST_LOG. Only when the user asked for more
    // than the quiet default and hasn't set RUST_LOG themselves.
    // SAFETY: set at startup before any worker threads are spawned.
    if cli.verbose > 0 && std::env::var_os("RUST_LOG").is_none() {
        unsafe {
            std::env::set_var("RUST_LOG", logging::filter_for_verbosity(cli.verbose));
        }
    }

    // Initialize logging.
    //
    // The MCP stdio subcommand needs *exclusive* control of stdout so
    // JSON-RPC framing isn't corrupted by stray log lines (stdout-only
    // JSON-RPC discipline). Skip the default `logging::init` (which installs
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
    // `mvmctl ops mcp` needs stdout reserved for JSON-RPC framing — skip the
    // default stdout subscriber and let `mvm_mcp` install its stderr-only one.
    let is_mcp = matches!(&cli.command, Commands::Ops(a) if a.action.is_mcp());
    if !is_mcp {
        logging::init(log_format, cli.verbose);
    }

    // The internal QEMU vsock bridge is a detached, long-running helper
    // (spawned by `mvm_backend::qemu`), not a user command.
    // Short-circuit before the ctrl-c handler, operator-config
    // load, and the cmd-audit envelope — none of which apply to it.
    if let Commands::QemuVsockBridge(a) = &cli.command {
        return qemu_bridge::run(a);
    }
    if let Commands::SshAgentProxy(a) = &cli.command {
        return ssh_agent_proxy::run(a);
    }

    // Commands that promise a machine-readable stdout payload must reserve
    // stdout before any pre-dispatch side effects (notably reconcile-on-entry
    // and dev-VM hints) can emit friendly `[mvm]` chrome.
    if cli.command.emits_machine_readable_stdout() {
        mvm::ui::set_chrome_to_stderr(true);
    }

    // Install Ctrl-C / SIGTERM handler for graceful shutdown.
    let pids = Arc::clone(&CHILD_PIDS);
    if let Err(e) = ctrlc::set_handler(move || {
        // In console mode, Ctrl-C is forwarded as a raw byte to the guest.
        if IN_CONSOLE_MODE.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        eprintln!("\nInterrupted, cleaning up...");
        // Handle registry: walk Attached-mode libkrun VMs and
        // gracefully stop each. Best-effort; failures get logged. Runs
        // before the child-pid sweep so SIGTERM-on-children doesn't
        // race the sandbox's own teardown ordering.
        let _ = mvm_backend::handle_registry::stop_all_attached();
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

    // Reconcile-on-entry convergence. For any
    // state-touching command, cheaply (registry read + pid-liveness stat
    // only) heal registry/runtime drift before dispatch, so stale records
    // self-heal instead of surfacing as a confusing failure three layers
    // down. Fail-open: `converge` never returns an error and we drop the
    // report — `mvmctl reconcile` is the observable entry point.
    // `MVM_SKIP_RECONCILE=1` opts out (never set in CI).
    maybe_converge_on_entry(&cli.command);

    // Load operator config once; used as fallback for dev_vm_cpus, dev_vm_mem_gib, cpus, memory.
    let cfg = mvm_core::user_config::load(None);

    // Wrap dispatch in cmd.<verb>.{invoked,completed,failed}
    // audit envelope. Best-effort: a recorder failure logs a warning and the
    // command runs without cmd-level audit.
    let cmd_recorder = cmd_audit::build_cmd_recorder();
    let verb = cli.command.verb_name();
    cmd_audit::emit_cmd_invoked(cmd_recorder.as_ref(), verb);

    let result = match cli.command.clone() {
        Commands::Env(a) => env::group::run(&cli, a, &cfg),
        Commands::Bootstrap(a) => bootstrap::run(&cli, a, &cfg),
        Commands::Dev(a) => env::dev::run(&cli, a, &cfg),
        Commands::Ls(a) => vm::ps::run(&cli, a, &cfg),
        Commands::Run(a) => vm::exec::run_secure(&cli, a, &cfg),
        Commands::SdkNoVm(a) => vm::sdk_no_vm::run(&a),
        Commands::Doctor(a) => env::doctor::run(&cli, a, &cfg),
        Commands::Build(a) => build::group::run(&cli, a, &cfg),
        Commands::Manifest(a) => manifest::run(&cli, a, &cfg),
        Commands::Image(a) => image::run(&cli, a, &cfg),
        Commands::Machine(a) => machine::run(&cli, a, &cfg),
        Commands::Storage(a) => storage::run(&cli, a, &cfg),
        Commands::ShellInit(a) => env::shell_init::run(&cli, a, &cfg),
        Commands::Ops(a) => ops::group::run(&cli, a, &cfg),
        Commands::Network(a) => ops::network::run(&cli, a, &cfg),
        Commands::Catalog(a) => catalog::run(&cli, a, &cfg),
        Commands::Cache(a) => ops::cache::run(&cli, a, &cfg),
        Commands::Pool(a) => pool::run(&cli, a, &cfg),
        Commands::Reconcile(a) => ops::reconcile::run(&cli, a, &cfg),
        Commands::Init(a) => env::init::run(&cli, a, &cfg),
        Commands::Secret(a) => ops::secret::run(&cli, a, &cfg),
        Commands::Bundle(a) => bundle::run(&cli, a, &cfg),
        Commands::Trust(a) => trust::run(&cli, a, &cfg),
        Commands::Deps(a) => deps::run(&cli, a, &cfg),
        Commands::Artifact(a) => vm::artifact::run(&cli, a, &cfg),
        #[cfg(feature = "builder-vm")]
        Commands::PersistentBuilder(a) => build::persistent_builder::run(&cli, a),
        // Handled by the early return above (before ctrl-c / config /
        // cmd-audit setup); this arm only satisfies match exhaustiveness.
        Commands::QemuVsockBridge(_) => unreachable!("qemu vsock bridge short-circuits in run()"),
        Commands::SshAgentProxy(_) => unreachable!("ssh-agent proxy short-circuits in run()"),
    };

    cmd_audit::emit_cmd_outcome(cmd_recorder.as_ref(), verb, &result);

    with_hints(result)
}

/// Run the cheap reconcile-on-entry convergence for state-touching
/// commands, unless `MVM_SKIP_RECONCILE=1`.
/// Fail-open: `converge` collects errors internally and never returns an
/// `Err`, so this can never block the requested command.
fn maybe_converge_on_entry(command: &Commands) {
    if !command.touches_vm_state() {
        return;
    }
    if std::env::var("MVM_SKIP_RECONCILE").as_deref() == Ok("1") {
        return;
    }
    let _ = mvm::vm::reconcile::converge(&mvm::vm::reconcile::ConvergeOpts::default());
}
