mod bootstrap;
mod build;
mod bundle;
mod catalog;
mod cmd_audit;
mod deps;
mod dispatch;
pub(crate) mod env;
mod image;
mod machine;
mod manifest;
mod ops;
mod pack;
/// Supervisor warm-pool: the `mvmctl pool warm/status` command + the launch glue
/// (`try_warm_claim`/`replenish_after_launch`) the transient `machine run` path
/// (`crate::exec::run_inner`) calls to claim a warm standby (auto-named,
/// bridge-admitted launches) and top the pool back up. `pub(crate)` so the
/// crate-root `exec` runner can reach the glue.
pub(crate) mod pool;
mod qemu_bridge;
mod runtime_overlay;
mod shared;
mod storage;
mod trust;
pub(crate) mod vm;

#[cfg(test)]
mod tests;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use std::sync::Arc;

use crate::logging::{self, LogFormat};
use dispatch::TopLevelCommand;

use shared::{CHILD_PIDS, IN_CONSOLE_MODE, with_hints};

#[derive(Parser, Debug, Clone)]
#[command(name = "mvmctl", version, about = "Lightweight VM development tool")]
pub(in crate::commands) struct Cli {
    /// Output format
    #[arg(long, global = true)]
    pub log_format: Option<String>,

    /// Firecracker version
    #[arg(long, global = true)]
    pub fc_version: Option<String>,

    /// Builder VMM: libkrun, qemu, or hvf
    #[arg(
        long,
        global = true,
        value_parser = ["libkrun", "qemu", "hvf"],
        hide_possible_values = true
    )]
    pub builder: Option<String>,

    /// Kernel source: compile, download, or auto
    #[arg(
        long,
        global = true,
        value_parser = ["compile", "download", "auto"],
        hide_possible_values = true
    )]
    pub kernel_source: Option<String>,

    /// Increase verbosity
    #[arg(
        short = 'v',
        long = "verbose",
        visible_alias = "debug",
        global = true,
        action = clap::ArgAction::Count
    )]
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
    /// Build-time commands (image, compile, validate, kernel)
    #[command(display_order = 3)]
    Build(build::group::Args),
    /// Build the custom microVM kernels (builder / workload)
    #[command(display_order = 3)]
    Kernel(build::kernel::Args),
    /// Scaffold a new project
    #[command(display_order = 4)]
    Init(env::init::Args),
    /// System diagnostics and dependency checks
    #[command(display_order = 5)]
    Doctor(env::doctor::Args),
    /// Report whether a verified runtime pack is ready for instant launch
    #[command(display_order = 6)]
    Prepare(vm::prepare::Args),
    /// List running VMs
    Ls(vm::ps::Args),
    /// Explain a run after the fact from the chain-signed audit log
    #[command(display_order = 7)]
    Explain(vm::explain::Args),
    /// Manage the versioned pack cache (list/rollback/prune/download/update)
    #[command(display_order = 8)]
    Pack(pack::Args),
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
    /// first build is fast. Run automatically by install.sh unless
    /// `MVM_SKIP_BUILDER_PREFETCH=1`.
    Bootstrap(bootstrap::Args),
    /// Internal: bootstrap only the builder VM image cache.
    #[command(name = "__builder-vm-bootstrap", hide = true)]
    BuilderVmBootstrap(bootstrap::BuilderVmBootstrapArgs),
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
    /// Manage the cache directory (~/.mvm/cache)
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
    /// backend. Spawned detached by `mvm_runtime::qemu`; not a
    /// user-facing command.
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
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    apply_startup_env(&cli);
    register_inhouse_builder();
    configure_runtime_logging(&cli);

    if let Some(result) = cli.command.try_run_early() {
        return result;
    }

    if cli.command.emits_machine_readable_stdout() {
        mvm_runtime::ui::set_chrome_to_stderr(true);
    }

    install_signal_handler();
    maybe_converge_on_entry(&cli.command);

    let cfg = mvm_core::user_config::load(None);
    let cmd_recorder = cmd_audit::build_cmd_recorder();
    let verb = cli.command.verb_name();
    cmd_audit::emit_cmd_invoked(cmd_recorder.as_ref(), verb);

    let result = cli.command.clone().run(&cli, &cfg);

    cmd_audit::emit_cmd_outcome(cmd_recorder.as_ref(), verb, &result);

    with_hints(result)
}

/// Set a process-global environment variable from the CLI.
///
/// mvmctl uses the environment as its config-propagation channel: these values
/// are read both in-process (`fc_version()`, the backend/kernel resolvers) and,
/// crucially, by re-exec'd child `mvmctl` helpers — e.g. the builder-VM
/// bootstrap — which receive the resolved CLI choice only by inheriting this
/// environment. That rules out a `OnceCell` or a threaded parameter.
pub(in crate::commands) fn set_cli_env(key: &str, value: impl AsRef<std::ffi::OsStr>) {
    // SAFETY: every caller runs on the main thread before mvmctl creates any
    // worker threads or async runtime — at CLI startup and at the very top of a
    // command handler. The only thread alive by then is the SIGINT servicer
    // (`crate::signal`), which blocks on a pipe read and never touches the
    // environment, so no `getenv` can race this `setenv`.
    unsafe { std::env::set_var(key, value) };
}

fn apply_startup_env(cli: &Cli) {
    if let Some(ref version) = cli.fc_version {
        set_cli_env("MVM_FC_VERSION", version);
    }
    if let Some(ref backend) = cli.builder {
        set_cli_env("MVM_BUILDER_BACKEND", backend);
    }
    if let Some(dir) = aux_bin_dir_to_apply(
        env!("MVM_AUX_BIN_DIR"),
        std::env::var_os("MVM_AUX_BIN_DIR").is_some(),
    ) {
        set_cli_env("MVM_AUX_BIN_DIR", dir);
    }
    if let Some(ref source) = cli.kernel_source {
        set_cli_env("MVM_KERNEL_SOURCE", source);
    }
}

/// The value to write to `MVM_AUX_BIN_DIR`, or `None` to leave the env alone.
/// The build script bakes in the dir where it compiled the per-VM helpers; we
/// surface it to mvm-backend's resolver unless the caller already set it (an
/// explicit override wins) or the build produced no path.
fn aux_bin_dir_to_apply(baked: &str, already_set: bool) -> Option<String> {
    if already_set || baked.is_empty() {
        return None;
    }
    Some(baked.to_string())
}

fn register_inhouse_builder() {
    // Wire the HVF builder constructor so that
    // `mvm_build::builder_backend_select` can create it when the
    // resolved choice is `BuilderBackendChoice::Hvf`. This is a
    // one-time registration at startup; `mvm-build` cannot reach
    // `mvm-backend` or `mvm-cli` directly (dependency direction), so
    // the CLI bridges the gap here.
    #[cfg(feature = "builder-vm")]
    mvm_build::builder_backend_select::register_hvf_builder(Box::new(|| {
        let (kernel, rootfs, closure_nar) =
            crate::commands::build::hvf_builder_image::resolve_hvf_builder_image()?;
        Ok(Box::new(
            mvm_runtime::builder_runner::hvf_builder::HvfBuilderVm::new(kernel, rootfs)
                .with_closure_nar(closure_nar),
        ) as Box<dyn mvm_build::builder_vm::BuilderVm>)
    }));
}

fn configure_runtime_logging(cli: &Cli) {
    let verbose = cli.verbose > 0 || std::env::var_os("RUST_LOG").is_some();
    mvm_runtime::ui::set_verbose(verbose);
    if cli.verbose > 0 && std::env::var_os("RUST_LOG").is_none() {
        set_cli_env("RUST_LOG", logging::filter_for_verbosity(cli.verbose));
    }
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
    let is_mcp = matches!(&cli.command, Commands::Ops(a) if a.action.is_mcp());
    if !is_mcp {
        logging::init(log_format, cli.verbose);
    }
}

fn install_signal_handler() {
    let pids = Arc::clone(&CHILD_PIDS);
    if let Err(e) = crate::signal::set_ctrlc_handler(move || {
        if IN_CONSOLE_MODE.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        eprintln!("\nInterrupted, cleaning up...");
        let _ = mvm_runtime::handle_registry::stop_all_attached();
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
    let _ =
        mvm_runtime::vm::reconcile::converge(&mvm_runtime::vm::reconcile::ConvergeOpts::default());
}

#[cfg(test)]
mod aux_bin_dir_tests {
    #[test]
    fn aux_bin_dir_applied_only_when_unset_and_nonempty() {
        assert_eq!(
            super::aux_bin_dir_to_apply("/x/aux/debug", false),
            Some("/x/aux/debug".to_string())
        );
        assert_eq!(super::aux_bin_dir_to_apply("/x/aux/debug", true), None);
        assert_eq!(super::aux_bin_dir_to_apply("", false), None);
    }
}
