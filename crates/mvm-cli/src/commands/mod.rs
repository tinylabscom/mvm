mod bootstrap;
mod build;
mod bundle;
pub mod catalog;
mod cmd_audit;
mod deploy;
mod deps;
mod dispatch;
pub(crate) mod env;
mod generate;
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
mod seccomp_audit;
mod shared;
mod storage;
mod template;
mod trust;
pub(crate) mod vm;
mod watch;

/// Source-resolution and worker-construction surface used by the resident
/// warm-artifact service. It is separate from foreground launch commands so
/// image resolution cannot re-enter the sub-300ms claim path.
pub mod warm_artifact_source {
    pub use super::machine::prewarm::{
        resolve_warm_artifact_plan, warm_artifact_worker, warm_artifact_worker_with_factory,
    };
}

pub(in crate::commands) use build::ir_input::load_ir_json_workload;
pub(crate) use shared::{DirShareSpec, parse_dir_share_spec};

#[cfg(test)]
mod tests;

use anyhow::Result;
use clap::error::ErrorKind;
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use std::sync::Arc;

use crate::logging::{self, LogFormat};
use dispatch::TopLevelCommand;

use shared::{CHILD_PIDS, IN_CONSOLE_MODE, with_hints};

#[derive(Parser, Debug, Clone)]
#[command(
    name = "mvmctl",
    version,
    about = "Lightweight VM development tool",
    term_width = 80
)]
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
    /// Build, seal, and record a workload locally; optionally ship it to mvmd
    #[command(display_order = 4)]
    Deploy(deploy::Args),
    /// Build the custom microVM kernels (builder / workload)
    #[command(display_order = 3)]
    Kernel(build::kernel::Args),
    /// Generate a runnable microVM project from SDK, template, or prompt
    #[command(display_order = 4)]
    Generate(generate::Args),
    /// Browse bundled and remote microVM templates
    #[command(display_order = 5)]
    Template(template::Args),
    /// Scaffold a new project
    #[command(display_order = 5)]
    Init(env::init::Args),
    /// System diagnostics and dependency checks
    #[command(display_order = 5)]
    Doctor(env::doctor::Args),
    /// Report whether a verified runtime pack is ready for instant launch
    #[command(display_order = 6)]
    Prepare(vm::prepare::Args),
    /// Explain a run after the fact from the chain-signed audit log
    #[command(display_order = 7)]
    Explain(vm::explain::Args),
    /// Rebuild a workload when its local inputs change
    #[command(display_order = 8)]
    Watch(watch::Args),
    /// Manage the versioned pack cache (list/rollback/prune/download/update)
    #[command(display_order = 9)]
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
    /// Internal: keep a persistent builder's egress endpoint alive.
    #[command(name = "__builder-egress-supervisor", hide = true)]
    BuilderEgressSupervisor(bootstrap::BuilderEgressSupervisorArgs),
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
    /// Operational / observability commands (metrics, config)
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
    /// Host-side seccomp syscall audit (developer tooling).
    #[command(name = "seccomp-audit", hide = true)]
    SeccompAudit(seccomp_audit::Args),
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
    constrain_help_width(Cli::command())
}

pub fn run() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = match cli_command().try_get_matches_from(std::env::args_os()) {
        Ok(matches) => Cli::from_arg_matches(&matches)
            .expect("generated CLI arguments must convert into the typed command"),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            print!("{}", constrain_help_output(&error.to_string()));
            return Ok(());
        }
        Err(error) => error.exit(),
    };
    apply_startup_env(&cli);
    register_inhouse_builder();
    register_stream_plane();
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

fn constrain_help_width(command: clap::Command) -> clap::Command {
    let mut command = command.term_width(80).max_term_width(80);
    if let Some(usage) = command
        .clone()
        .render_help()
        .to_string()
        .lines()
        .find(|line| line.starts_with("Usage:"))
        && usage.chars().count() > 80
    {
        command = command.override_usage(wrap_usage(usage));
    }
    command.mut_subcommands(constrain_help_width)
}

fn wrap_usage(usage: &str) -> String {
    let body = usage.strip_prefix("Usage: ").unwrap_or(usage);
    let continuation_indent = "       ";
    let line_limit = 80 - continuation_indent.chars().count();
    let mut wrapped = String::new();
    let mut line_width = 0;

    for word in body.split_whitespace() {
        let word_width = word.chars().count();
        let separator_width = usize::from(line_width > 0);
        if line_width > 0 && line_width + separator_width + word_width > line_limit {
            wrapped.push('\n');
            wrapped.push_str(continuation_indent);
            line_width = continuation_indent.chars().count();
        }
        if line_width > continuation_indent.chars().count() {
            wrapped.push(' ');
            line_width += 1;
        }
        wrapped.push_str(word);
        line_width += word_width;
    }
    wrapped
}

fn constrain_help_output(help: &str) -> String {
    let trailing_newline = help.ends_with('\n');
    let mut constrained = help
        .lines()
        .map(|line| wrap_help_line(line, 80))
        .collect::<Vec<_>>()
        .join("\n");
    if trailing_newline {
        constrained.push('\n');
    }
    constrained
}

fn wrap_help_line(line: &str, width: usize) -> String {
    if line.chars().count() <= width {
        return line.to_owned();
    }

    let indentation = line
        .chars()
        .take_while(|character| character.is_whitespace())
        .count();
    let prefix = &line[..line.len() - line.trim_start().len()];
    let continuation = if line.trim_start().starts_with("Usage:") {
        "       "
    } else {
        prefix
    };
    let mut current = String::new();
    let mut current_limit = width.saturating_sub(indentation);
    let mut wrapped = Vec::new();

    for word in line.split_whitespace() {
        let word_width = word.chars().count();
        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word_width <= current_limit {
            current.push(' ');
            current.push_str(word);
        } else {
            wrapped.push(current);
            current = word.to_owned();
            current_limit = width.saturating_sub(continuation.chars().count());
        }
    }
    if !current.is_empty() {
        wrapped.push(current);
    }

    wrapped
        .into_iter()
        .enumerate()
        .map(|(index, text)| {
            if index == 0 {
                format!("{prefix}{text}")
            } else {
                format!("{continuation}{text}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
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

/// Give the workload runner a real per-VM output-stream plane.
///
/// Unconditional and before any command runs, because the hook it registers
/// is what makes a workload's output followable at all: registering it per
/// command, or only for the commands that obviously start VMs, would leave
/// whichever path was missed silently falling back to an unchained console
/// tail. `mvm-runtime` cannot reach `mvm-hostd` (dependency direction), so the
/// CLI bridges the gap here — the same shape as
/// [`register_inhouse_builder`] above.
fn register_stream_plane() {
    mvm_hostd::stream::install_host_console_streamer();
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
    logging::init(log_format, cli.verbose);
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
