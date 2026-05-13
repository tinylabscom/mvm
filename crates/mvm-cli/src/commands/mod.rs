mod build;
mod bundle;
mod catalog;
mod cmd_audit;
mod env;
mod manifest;
mod ops;
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
    /// Inspect the dm-thin storage pool (info, gc). Plan 47 / ADR-008.
    Storage(storage::Args),
    /// Build a microVM image from a Mvmfile.toml config or Nix flake
    Build(build::build::Args),
    /// Render a Workload IR into `flake.nix` + `launch.json` + bundled
    /// source (mvm-sdk compile pipeline).
    ///
    /// v1 accepts a pre-rendered IR JSON via `--from-ir <path>` or `-`
    /// for stdin; the decorator-script (`@mvm.app`) and runtime-script
    /// (`Sandbox`) entry forms land with SDK-port Phases 4 and 7
    /// respectively. Output ending in `.tar.gz`/`.tgz` writes a
    /// deterministic archive; otherwise a directory.
    ///
    /// Mode resolution: `--mode {live|plan|record}` is the explicit
    /// form; `--prod` is the alias for `record` (the default for
    /// compile); `--dev` is refused (use `mvmctl run` for live).
    /// `MVM_SDK_MODE` env var overrides flags.
    Compile(build::compile::Args),
    /// Compile a workload and ship the resulting signed archive to
    /// mvmd. v1 stub end: builds the single `.tar.gz` (compile output
    /// plus an embedded `mvmd-spec.json` per mvmd ADR-0020) and logs
    /// what the real HTTP client would `POST /v1/workloads`. The real
    /// shipping path lands with mvmd Plan 48 Phase 1090.
    Deploy(build::deploy::Args),
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
    /// Manage the lifecycle of a long-running session — list, inspect, kill, set idle timeout.
    ///
    /// A session is one microVM the substrate keeps warm across multiple
    /// `mvmctl invoke` calls. Phase 3 of the upstream-mvm coordination
    /// (`specs/upstream-mvm-prompt.md` deliverable D); the SDK-facing
    /// surface for `mvmforge`'s `Session` class.
    Session(vm::session::Args),
    /// Speak Model Context Protocol — exposes mvmctl as a sandbox surface for LLM clients.
    ///
    /// Single parameterized `run` tool whose `env` parameter selects from `mvmctl template list`.
    /// Each call boots a transient microVM, runs the supplied code, and tears down. Like
    /// `mvmctl exec`, the dispatch path requires a dev-feature guest agent (ADR-002 §W4.3);
    /// against a production guest the call returns "exec not available" gracefully. ADR-003
    /// documents the threat model and design.
    Mcp(ops::mcp::Args),
    /// Set or clear a sandbox's TTL. The supervisor reaper tears down
    /// VMs whose `expires_at` has elapsed.
    #[command(name = "set-ttl")]
    SetTtl(vm::set_ttl::Args),
    /// Filesystem RPC against a running VM (read/write/ls/stat/mkdir/rm/mv).
    /// Production-safe — every path runs through the agent's
    /// `mvm_security::policy::PathPolicy` deny-list and per-call
    /// resource caps.
    Fs(vm::fs::Args),
    /// Process control RPC against a running VM (start/ls/signal/kill/stdin/wait).
    /// Dev-only — production guest agents strip the handler module
    /// per ADR-002 §W4.3, returning `UnsupportedInProduction` for
    /// every verb.
    Proc(vm::proc::Args),
    /// Quiesce a running VM, seal its memory image to
    /// `~/.mvm/instances/<vm>/snapshot/`, and stop the VM.
    /// Production-safe; HMAC + monotonic-epoch envelope refuses
    /// replayed older state.
    Pause(vm::pause::PauseArgs),
    /// Verify a sealed snapshot and resume the VM. Refuses to
    /// load a tampered or replayed snapshot.
    Resume(vm::pause::ResumeArgs),
    /// Manage sealed instance snapshots (`ls`, `rm`).
    Snapshot(vm::pause::SnapshotArgs),
    /// Manage virtio-fs volume mounts on a VM (`mount`, `ls`,
    /// `unmount`). Plan 45 §D5 (Path C) — renamed from `share`.
    /// Mount paths are validated by
    /// `mvm_security::policy::MountPathPolicy` so a host can't
    /// shadow verity-protected files. `--remote` proxies through
    /// mvmd's REST API for provider-backed buckets.
    Volume(vm::volume::Args),
    /// Manage tenant secrets (put / get / ls / rm). Values are
    /// stored in the OS-native keystore when reachable, else in
    /// mode-0600 files under `~/.mvm/secrets/<tenant>/`. Every
    /// put/get/delete/list emits an audit entry to
    /// `~/.mvm/audit/secrets.jsonl` — values are never logged.
    /// Plan 63 W4.
    Secret(ops::secret::Args),
    /// Emit or verify a host attestation report (`export`, `verify`,
    /// `status`). The report carries an Ed25519-signed body with the
    /// boot measurement, identity public key, and an optional
    /// hardware quote when a `attestation-{tpm2,sev-snp,tdx}` feature
    /// is wired in. Plan 60 Phase 6.
    Attest(ops::attest::Args),
    /// Inspect a tenant policy bundle on disk (`show`, `verify`).
    /// Operator-facing surface over the parsed-but-not-yet-enforced
    /// bundles at `~/.mvm/policies/<tenant>/<workload>.toml`.
    /// `mvmctl policy update` is stubbed in v0 — production updates
    /// require an mvmd-signed plan (Phase 8). Plan 60 Phase 3 Slice D.
    Policy(ops::policy::Args),
    /// Seal a built template into a portable, signed `.mvmpkg`
    /// archive — or verify one against the local trust store.
    /// Sprint 52 W2 close-out. Bundles are content-addressed and
    /// signed by the host signer; consumers verify via
    /// `mvmctl trust`-managed publisher pubkeys.
    Bundle(bundle::Args),
    /// Manage the bundle-publisher trust store at
    /// `~/.mvm/trusted-publishers/`. `mvmctl bundle fetch` looks
    /// pubkeys up via this store before verifying signatures.
    Trust(trust::Args),
    /// Tenant lifecycle: destroy a tenant's overlays + emit signed
    /// destruction certificates. Plan 60 Phase 7a Slices A + D.
    /// Hosted-cloud operators use this to satisfy the "provably
    /// erased" deprovisioning contract.
    Tenant(ops::tenant::Args),
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

    // Install Ctrl-C / SIGTERM handler for graceful shutdown.
    let pids = Arc::clone(&CHILD_PIDS);
    if let Err(e) = ctrlc::set_handler(move || {
        // In console mode, Ctrl-C is forwarded as a raw byte to the guest.
        if IN_CONSOLE_MODE.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        eprintln!("\nInterrupted, cleaning up...");
        // W7 handle registry: walk Attached-mode microsandbox VMs and
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

    // Load operator config once; used as fallback for lima_cpus, lima_mem, cpus, memory.
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
        Commands::Manifest(a) => manifest::run(&cli, a, &cfg),
        Commands::Storage(a) => storage::run(&cli, a, &cfg),
        Commands::Build(a) => build::build::run(&cli, a, &cfg),
        Commands::Compile(a) => build::compile::run(&cli, a, &cfg),
        Commands::Deploy(a) => build::deploy::run(&cli, a, &cfg),
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
        Commands::Policy(a) => ops::policy::run(&cli, a, &cfg),
        Commands::Bundle(a) => bundle::run(&cli, a, &cfg),
        Commands::Trust(a) => trust::run(&cli, a, &cfg),
        Commands::Tenant(a) => ops::tenant::run(&cli, a, &cfg),
    };

    cmd_audit::emit_cmd_outcome(cmd_recorder.as_ref(), verb, &result);

    with_hints(result)
}
