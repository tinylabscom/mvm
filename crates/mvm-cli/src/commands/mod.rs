mod build;
mod bundle;
mod catalog;
mod cmd_audit;
mod deps;
mod env;
mod image;
mod kernel;
mod manifest;
mod ops;
/// Plan 118 WS-1 1b — supervisor warm-pool: the `mvmctl pool warm/status` command + the
/// launch glue (`try_warm_claim`/`replenish_after_launch`) the `up` path calls to claim a
/// warm standby (auto-named, bridge-admitted launches) and top the pool back up.
mod pool;
mod qemu_bridge;
mod shared;
mod storage;
mod trust;
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

    /// Override which hypervisor drives the builder VM
    /// (Plan 98). Highest priority — beats `MVM_BUILDER_BACKEND`
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
    /// Manage the local dev VM
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
    /// Re-sign mvmctl + supervisors with VZ entitlements (macOS)
    Sign(env::sign::Args),
    /// Build the custom microVM kernels (builder / workload)
    Kernel(kernel::Args),
    /// Manage built manifest slots
    Manifest(manifest::Args),
    /// Inspect cached OCI images
    Image(image::Args),
    /// Inspect the dm-thin storage pool
    Storage(storage::Args),
    /// Build a microVM image from a Mvmfile.toml config or Nix flake
    Build(build::build::Args),
    /// Compile Workload IR into build artifacts
    Compile(build::compile::Args),
    /// Build and run a VM
    ///
    /// If neither `--flake` nor `--manifest` is supplied, the bundled
    /// `nix/images/default-tenant/` image is used (built via Nix on first use,
    /// cached at `~/.cache/mvm/default-microvm/`).
    Up(vm::up::Args),
    /// Stop microVMs (from mvm.toml, by name, or all)
    Down(vm::down::Args),
    /// Print shell configuration (completions + dev aliases) to stdout
    #[command(hide = true)]
    ShellInit(env::shell_init::Args),
    /// Show runtime metrics (Prometheus text format by default)
    Metrics(ops::metrics::Args),
    /// Benchmark microVM operations (e.g. cold launch latency)
    Bench(ops::bench::Args),
    /// Read or write global operator config (~/.mvm/config.toml)
    Config(ops::config::Args),
    /// Remove local mvm state
    Uninstall(env::uninstall::Args),
    /// View the local audit log (~/.mvm/log/audit.jsonl)
    Audit(ops::audit::Args),
    /// Validate a Nix flake before building (runs `nix flake check`)
    Validate(build::validate::Args),
    /// Show filesystem changes in a running VM
    Diff(vm::diff::Args),
    /// Manage named dev networks
    Network(ops::network::Args),
    /// Browse the bundled image catalog
    Catalog(catalog::Args),
    /// Interactive console (PTY-over-vsock) to a running VM
    Console(vm::console::Args),
    /// Manage the XDG cache directory (~/.cache/mvm)
    Cache(ops::cache::Args),
    /// Manage the supervisor warm pool (pre-spawned standbys for fast `up`)
    Pool(pool::Args),
    /// Converge the VM name registry with on-disk runtime state
    #[command(hide = true)]
    Reconcile(ops::reconcile::Args),
    /// Scaffold a new project
    Init(env::init::Args),
    /// Run one command in a transient microVM
    Run(vm::exec::RunArgs),
    /// Verify signed execution receipts emitted by `mvmctl run --receipt`.
    Receipt(vm::exec::ReceiptArgs),
    /// Inspect and clean sandbox lifecycle state.
    Sandbox(vm::sandbox::Args),
    /// Copy one file between the host and a running VM.
    Cp(vm::cp::Args),
    /// Run one dev command in a transient microVM
    Exec(vm::exec::Args),
    /// Call a VM's baked entrypoint
    Invoke(vm::invoke::Args),
    /// Manage long-running VM sessions
    Session(vm::session::Args),
    /// Expose mvmctl over Model Context Protocol
    Mcp(ops::mcp::Args),
    /// Set or clear a sandbox TTL
    #[command(name = "set-ttl")]
    SetTtl(vm::set_ttl::Args),
    /// Run filesystem RPC against a VM
    Fs(vm::fs::Args),
    /// Run process-control RPC against a VM
    Proc(vm::proc::Args),
    /// Pause and seal a running VM
    Pause(vm::pause::PauseArgs),
    /// Verify and resume a sealed snapshot
    Resume(vm::pause::ResumeArgs),
    /// Manage sealed instance snapshots (`ls`, `rm`).
    Snapshot(vm::pause::SnapshotArgs),
    /// Manage virtio-fs volume mounts
    Volume(vm::volume::Args),
    /// Manage local secret namespaces
    Secret(ops::secret::Args),
    /// Emit or verify host attestation reports
    Attest(ops::attest::Args),
    /// Seal or verify portable VM bundles
    Bundle(bundle::Args),
    /// Manage trusted bundle publishers
    Trust(trust::Args),
    /// Inspect cached application dependencies
    Deps(deps::Args),
    /// Wait for guest readiness
    Wait(vm::wait::WaitArgs),
    /// Print guest readiness and boot timings
    BootReport(vm::wait::BootReportArgs),
    /// Pack or verify signed `.mvm` artifacts
    Artifact(vm::artifact::Args),
    /// Manage the persistent builder VM
    #[cfg(feature = "builder-vm")]
    #[command(name = "persistent-builder", hide = true)]
    PersistentBuilder(build::persistent_builder::Args),
    /// Internal: host-side AF_VSOCK↔UNIX bridge for the QEMU workload
    /// backend (Plan 166 Phase 2). Spawned detached by
    /// `mvm_backend::qemu`; not a user-facing command.
    #[command(name = "__qemu-vsock-bridge", hide = true)]
    QemuVsockBridge(qemu_bridge::Args),
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
    let verbose = cli.verbose || std::env::var_os("RUST_LOG").is_some();
    mvm::ui::set_verbose(verbose);

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

    // Plan 166 Phase 2 — the internal QEMU vsock bridge is a detached,
    // long-running helper (spawned by `mvm_backend::qemu`), not a user
    // command. Short-circuit before the ctrl-c handler, operator-config
    // load, and the cmd-audit envelope — none of which apply to it.
    if let Commands::QemuVsockBridge(a) = &cli.command {
        return qemu_bridge::run(a);
    }

    // Install Ctrl-C / SIGTERM handler for graceful shutdown.
    let pids = Arc::clone(&CHILD_PIDS);
    if let Err(e) = ctrlc::set_handler(move || {
        // In console mode, Ctrl-C is forwarded as a raw byte to the guest.
        if IN_CONSOLE_MODE.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        eprintln!("\nInterrupted, cleaning up...");
        // W7 handle registry: walk Attached-mode libkrun VMs and
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

    // Plan 170 WS-A / ADR-074 — reconcile-on-entry convergence. For any
    // state-touching command, cheaply (registry read + pid-liveness stat
    // only) heal registry/runtime drift before dispatch, so stale records
    // self-heal instead of surfacing as a confusing failure three layers
    // down. Fail-open: `converge` never returns an error and we drop the
    // report — `mvmctl reconcile` is the observable entry point.
    // `MVM_SKIP_RECONCILE=1` opts out (never set in CI).
    maybe_converge_on_entry(&cli.command);

    // Load operator config once; used as fallback for dev_vm_cpus, dev_vm_mem_gib, cpus, memory.
    let cfg = mvm_core::user_config::load(None);

    // Plan 60 Phase 4 — wrap dispatch in cmd.<verb>.{invoked,completed,failed}
    // audit envelope. Best-effort: a recorder failure logs a warning and the
    // command runs without cmd-level audit.
    let cmd_recorder = cmd_audit::build_cmd_recorder();
    let verb = cli.command.verb_name();
    cmd_audit::emit_cmd_invoked(cmd_recorder.as_ref(), verb);

    let result = match cli.command.clone() {
        Commands::Bootstrap(a) => env::bootstrap::run(&cli, a, &cfg),
        Commands::Dev(a) => env::dev::run(&cli, a, &cfg),
        Commands::Cleanup(a) => env::cleanup::run(&cli, a, &cfg),
        Commands::Logs(a) => vm::logs::run(&cli, a, &cfg),
        Commands::Forward(a) => vm::forward::run(&cli, a, &cfg),
        Commands::Ls(a) => vm::ps::run(&cli, a, &cfg),
        Commands::Update(a) => env::update::run(&cli, a, &cfg),
        Commands::Doctor(a) => env::doctor::run(&cli, a, &cfg),
        Commands::Sign(a) => env::sign::run(&cli, a, &cfg),
        Commands::Kernel(a) => kernel::run(&cli, a, &cfg),
        Commands::Manifest(a) => manifest::run(&cli, a, &cfg),
        Commands::Image(a) => image::run(&cli, a, &cfg),
        Commands::Storage(a) => storage::run(&cli, a, &cfg),
        Commands::Build(a) => build::build::run(&cli, a, &cfg),
        Commands::Compile(a) => build::compile::run(&cli, a, &cfg),
        Commands::Up(a) => vm::up::run(&cli, a, &cfg),
        Commands::Down(a) => vm::down::run(&cli, a, &cfg),
        Commands::ShellInit(a) => env::shell_init::run(&cli, a, &cfg),
        Commands::Metrics(a) => ops::metrics::run(&cli, a, &cfg),
        Commands::Bench(a) => ops::bench::run(&cli, a, &cfg),
        Commands::Config(a) => ops::config::run(&cli, a, &cfg),
        Commands::Uninstall(a) => env::uninstall::run(&cli, a, &cfg),
        Commands::Audit(a) => ops::audit::run(&cli, a, &cfg),
        Commands::Validate(a) => build::validate::run(&cli, a, &cfg),
        Commands::Diff(a) => vm::diff::run(&cli, a, &cfg),
        Commands::Network(a) => ops::network::run(&cli, a, &cfg),
        Commands::Catalog(a) => catalog::run(&cli, a, &cfg),
        Commands::Console(a) => vm::console::run(&cli, a, &cfg),
        Commands::Cache(a) => ops::cache::run(&cli, a, &cfg),
        Commands::Pool(a) => pool::run(&cli, a, &cfg),
        Commands::Reconcile(a) => ops::reconcile::run(&cli, a, &cfg),
        Commands::Init(a) => env::init::run(&cli, a, &cfg),
        Commands::Run(a) => vm::exec::run_secure(&cli, a, &cfg),
        Commands::Receipt(a) => vm::exec::run_receipt(&cli, a, &cfg),
        Commands::Sandbox(a) => vm::sandbox::run(&cli, a, &cfg),
        Commands::Cp(a) => vm::cp::run(&cli, a, &cfg),
        Commands::Exec(a) => vm::exec::run(&cli, a, &cfg),
        Commands::Invoke(a) => vm::invoke::run(&cli, a, &cfg),
        Commands::Session(a) => vm::session::run(&cli, a, &cfg),
        Commands::Mcp(a) => ops::mcp::run(&cli, a, &cfg),
        Commands::SetTtl(a) => vm::set_ttl::run(&cli, a, &cfg),
        Commands::Fs(a) => vm::fs::run(&cli, a, &cfg),
        Commands::Proc(a) => vm::proc::run(&cli, a, &cfg),
        Commands::Pause(a) => vm::pause::run_pause(&cli, a, &cfg),
        Commands::Resume(a) => vm::pause::run_resume(&cli, a, &cfg),
        Commands::Snapshot(a) => vm::pause::run_snapshot(&cli, a, &cfg),
        Commands::Volume(a) => vm::volume::run(&cli, a, &cfg),
        Commands::Secret(a) => ops::secret::run(&cli, a, &cfg),
        Commands::Attest(a) => ops::attest::run(&cli, a, &cfg),
        Commands::Bundle(a) => bundle::run(&cli, a, &cfg),
        Commands::Trust(a) => trust::run(&cli, a, &cfg),
        Commands::Deps(a) => deps::run(&cli, a, &cfg),
        Commands::Wait(a) => vm::wait::run_wait(&cli, a, &cfg),
        Commands::BootReport(a) => vm::wait::run_boot_report(&cli, a, &cfg),
        Commands::Artifact(a) => vm::artifact::run(&cli, a, &cfg),
        #[cfg(feature = "builder-vm")]
        Commands::PersistentBuilder(a) => build::persistent_builder::run(&cli, a),
        // Handled by the early return above (before ctrl-c / config /
        // cmd-audit setup); this arm only satisfies match exhaustiveness.
        Commands::QemuVsockBridge(_) => unreachable!("qemu vsock bridge short-circuits in run()"),
    };

    cmd_audit::emit_cmd_outcome(cmd_recorder.as_ref(), verb, &result);

    with_hints(result)
}

/// Run the cheap reconcile-on-entry convergence for state-touching
/// commands (Plan 170 WS-A / ADR-074), unless `MVM_SKIP_RECONCILE=1`.
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
