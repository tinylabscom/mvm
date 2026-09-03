mod agent_session;
mod bench;
mod bootstrap;
mod build;
#[cfg(feature = "builder-vm")]
mod builder_shell_job;
mod bundle;
mod capture;
pub mod catalog;
mod cmd_audit;
mod completions;
mod dashboard;
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
mod plugin;
/// Supervisor warm-pool: the `mvmctl pool warm/status` command + the launch glue
/// (`try_warm_claim`) the transient `machine run` path
/// (`crate::exec::run_inner`) calls to claim a warm standby (auto-named,
/// bridge-admitted launches) and top the pool back up. `pub(crate)` so the
/// crate-root `exec` runner can reach the glue.
pub(crate) mod pool;
mod qemu_bridge;
mod runtime_overlay;
mod seccomp_audit;
pub(crate) mod shared;
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
pub(crate) use vm::exec::RunProfile;

#[cfg(test)]
mod tests;

use anyhow::Result;
use clap::error::ErrorKind;
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use std::sync::Arc;

use crate::logging::{self, LogFormat};
use dispatch::TopLevelCommand;

use shared::{CHILD_PIDS, IN_CONSOLE_MODE, with_hints};

const CLI_HELP_WIDTH: usize = 79;
const CLAP_RENDER_WIDTH: usize = 4096;

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

    /// Kernel source: compile, download, auto
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

/// The security profile a run lands in when the user names none.
///
/// Read from the parsed default rather than named again, so `doctor` cannot
/// report a posture the CLI does not actually apply.
pub(crate) fn default_run_profile() -> RunProfile {
    vm::exec::RunArgs::default().profile
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
    /// Build, seal, and record a workload; optionally ship it to mvmd
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
    /// Check the local mvm-studio dashboard install (dev surface; hidden until
    /// the server handshake is frozen upstream)
    #[command(display_order = 20, hide = true)]
    Dashboard(dashboard::Args),
    /// Report whether a verified runtime pack is ready for instant launch
    #[command(display_order = 6)]
    Prepare(vm::prepare::Args),
    /// Explain a run after the fact from the chain-signed audit log
    #[command(display_order = 7)]
    Explain(vm::explain::Args),
    /// Measure this host's launch latency against the published budgets
    #[command(display_order = 7)]
    Bench(bench::Args),
    /// Emit the integration files a coding agent needs to reach for mvm
    #[command(display_order = 8)]
    Plugin(plugin::Args),
    /// Print a shell completion script
    #[command(display_order = 8)]
    Completions(completions::Args),
    /// Rebuild a workload when its local inputs change
    #[command(display_order = 8)]
    Watch(watch::Args),
    /// Manage versioned packs (list/rollback/prune/download/update)
    #[command(display_order = 9)]
    Pack(pack::Args),
    /// Run one command in a fresh transient microVM, then tear it down
    ///
    /// The argument surface still differs from `machine run` in both
    /// directions; consolidating the two into one struct is the next step.
    #[command(display_order = 2)]
    Run(vm::exec::TransientRunArgs),
    /// Internal SDK host-dispatch transport for `MVM_NO_VM=1`.
    #[command(name = "__sdk-no-vm", hide = true)]
    SdkNoVm(vm::sdk_no_vm::Args),
    /// Prepare the environment and machine infrastructure
    ///
    /// Runs host-tooling setup and pre-acquires the builder VM image plus the
    /// verified workload kernel. Run automatically by install.sh unless
    /// `MVM_SKIP_BOOTSTRAP=1`.
    Bootstrap(bootstrap::Args),
    /// Internal: bootstrap only the builder VM image cache.
    #[command(name = "__builder-vm-bootstrap", hide = true)]
    BuilderVmBootstrap(bootstrap::BuilderVmBootstrapArgs),
    /// Internal: keep a persistent builder's egress endpoint alive.
    #[command(name = "__builder-egress-supervisor", hide = true)]
    BuilderEgressSupervisor(bootstrap::BuilderEgressSupervisorArgs),
    /// Internal: run a shell script inside the Linux builder VM.
    #[command(name = "__builder-shell-job", hide = true)]
    #[cfg(feature = "builder-vm")]
    BuilderShellJob(builder_shell_job::Args),
    /// Environment / install lifecycle (bootstrap, update, sign, …)
    #[command(display_order = 10)]
    Env(env::group::Args),
    /// Manage built manifest slots
    #[command(display_order = 10)]
    Manifest(manifest::Args),
    /// Inspect cached OCI images
    #[command(display_order = 11)]
    Image(image::Args),
    /// Inspect the dm-thin storage pool
    #[command(hide = true)]
    Storage(storage::Args),
    /// Print shell configuration (completions + dev aliases) to stdout
    #[command(display_order = 14)]
    ShellInit(env::shell_init::Args),
    /// Operational / observability commands (metrics, config, MCP)
    #[command(display_order = 14)]
    Ops(ops::group::Args),
    /// Manage named dev networks
    #[command(display_order = 12)]
    Network(ops::network::Args),
    /// Browse the bundled image catalog
    #[command(display_order = 11)]
    Catalog(catalog::Args),
    /// Manage the cache directory (~/.mvm/cache)
    #[command(display_order = 12)]
    Cache(ops::cache::Args),
    /// Manage the supervisor warm pool (pre-spawned standbys for a fast `run`)
    #[command(display_order = 12)]
    Pool(pool::Args),
    /// Converge the VM name registry with on-disk runtime state
    #[command(hide = true)]
    Reconcile(ops::reconcile::Args),
    /// Manage local secret namespaces
    #[command(display_order = 13)]
    Secret(ops::secret::Args),
    /// Seal or verify portable VM bundles
    #[command(display_order = 13)]
    Bundle(bundle::Args),
    /// Manage trusted bundle publishers
    #[command(display_order = 13)]
    Trust(trust::Args),
    /// Inspect, park, and resume durable agent sessions
    #[command(name = "agent-session", display_order = 12)]
    AgentSession(agent_session::Args),
    /// Inspect cached application dependencies
    #[command(display_order = 14)]
    Deps(deps::Args),
    /// Capture a project environment and resolve it to MVM IR
    #[command(display_order = 14)]
    Capture(capture::Args),
    /// Pack or verify signed `.mvm` artifacts
    #[command(display_order = 13)]
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
    let result = run_command();
    // Emitted after the command settles so the profile covers teardown as well.
    // A no-op unless MVM_SPAN_TIMINGS is set.
    mvm_core::observability::span_timing::emit_report();
    result
}

fn run_command() -> Result<()> {
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
        Err(error) => {
            let exit_code = error.exit_code();
            eprint!("{}", constrain_help_output(&error.to_string()));
            std::process::exit(exit_code);
        }
    };
    apply_startup_env(&cli);
    declare_embedded_host_binaries();
    register_inhouse_builder();
    register_builder_session_starter();
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
    let cmd_audit = cmd_audit::build_cmd_recorder();
    let cmd_recorder = cmd_audit.as_ref().map(cmd_audit::CommandAudit::recorder);
    let verb = cli.command.verb_name();
    cmd_audit::emit_cmd_invoked(cmd_recorder, verb);

    let result = cli.command.clone().run(&cli, &cfg);

    cmd_audit::emit_cmd_outcome(cmd_recorder, verb, &result);

    with_hints(result)
}

fn constrain_help_width(command: clap::Command) -> clap::Command {
    let mut command = command
        .disable_help_flag(true)
        .arg(
            clap::Arg::new("help")
                .short('h')
                .long("help")
                .action(clap::ArgAction::HelpShort)
                .help("Print help"),
        )
        .term_width(CLAP_RENDER_WIDTH)
        .max_term_width(CLAP_RENDER_WIDTH);
    if let Some(usage) = command
        .clone()
        .render_help()
        .to_string()
        .lines()
        .find(|line| line.starts_with("Usage:"))
        && usage.chars().count() > CLI_HELP_WIDTH
    {
        command = command.override_usage(wrap_usage(usage));
    }
    command.mut_subcommands(constrain_help_width)
}

fn wrap_usage(usage: &str) -> String {
    let body = usage.strip_prefix("Usage: ").unwrap_or(usage);
    let continuation_indent = "       ";
    let line_limit = CLI_HELP_WIDTH - continuation_indent.chars().count();
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
    let mut constrained = compact_help_items(help)
        .iter()
        .map(|line| truncate_help_line(line, CLI_HELP_WIDTH))
        .collect::<Vec<_>>()
        .join("\n");
    if trailing_newline {
        constrained.push('\n');
    }
    constrained
}

#[derive(Clone, Copy)]
enum HelpItemSection {
    Arguments,
    Commands,
    Options,
}

fn compact_help_items(help: &str) -> Vec<String> {
    let mut compacted = Vec::new();
    let mut section = None;
    let mut item = None;
    let mut pending_blank = false;

    for line in help.lines() {
        let trimmed = line.trim();
        let heading = match trimmed {
            "Arguments:" => Some(HelpItemSection::Arguments),
            "Commands:" => Some(HelpItemSection::Commands),
            "Options:" => Some(HelpItemSection::Options),
            _ => None,
        };

        if let Some(heading) = heading {
            flush_help_item(&mut compacted, &mut item);
            if pending_blank && compacted.last().is_some_and(|line| !line.is_empty()) {
                compacted.push(String::new());
            }
            compacted.push(line.to_owned());
            section = Some(heading);
            pending_blank = false;
            continue;
        }

        if trimmed.is_empty() {
            if section.is_some() {
                pending_blank = true;
            } else if compacted.last().is_some_and(|line| !line.is_empty()) {
                compacted.push(String::new());
            }
            continue;
        }

        if section.is_some() && !line.starts_with(char::is_whitespace) {
            flush_help_item(&mut compacted, &mut item);
            if pending_blank && compacted.last().is_some_and(|line| !line.is_empty()) {
                compacted.push(String::new());
            }
            compacted.push(line.to_owned());
            section = None;
            pending_blank = false;
            continue;
        }

        let indentation = line
            .chars()
            .take_while(|character| character.is_whitespace())
            .count();
        let starts_item = match section {
            Some(HelpItemSection::Arguments) => {
                matches!(trimmed.chars().next(), Some('<' | '['))
            }
            Some(HelpItemSection::Commands) => indentation <= 2,
            Some(HelpItemSection::Options) => indentation <= 6 && trimmed.starts_with('-'),
            None => false,
        };

        if starts_item {
            flush_help_item(&mut compacted, &mut item);
            item = Some(line.to_owned());
        } else if let Some(current) = item.as_mut() {
            current.push_str("  ");
            current.push_str(trimmed);
        } else {
            compacted.push(line.to_owned());
        }
        pending_blank = false;
    }

    flush_help_item(&mut compacted, &mut item);
    compacted
}

fn flush_help_item(compacted: &mut Vec<String>, item: &mut Option<String>) {
    if let Some(item) = item.take() {
        compacted.push(item);
    }
}

fn truncate_help_line(line: &str, width: usize) -> String {
    if line.chars().count() <= width {
        return line.to_owned();
    }

    let mut truncated = line
        .chars()
        .take(width.saturating_sub(1))
        .collect::<String>();
    truncated.push('…');
    truncated
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
    if let Some(ref source) = cli.kernel_source {
        set_cli_env("MVM_KERNEL_SOURCE", source);
    }
}

/// Let a build start a persistent builder when it finds the store image busy.
///
/// `mvm-build` decides *when* sharing beats queueing; it cannot start a session
/// itself, because host-binary extraction, builder-image resolution and the
/// session record all live up here. Same inversion as the hvf builder ctor
/// below.
#[cfg(feature = "builder-vm")]
fn register_builder_session_starter() {
    mvm_build::persistent_builder::register_session_starter(Box::new(|| {
        crate::commands::build::persistent_builder::start_session_for_contended_build()
    }));
}

#[cfg(not(feature = "builder-vm"))]
fn register_builder_session_starter() {}

/// Tell `mvm-build` whether this binary carries the embedded Linux host
/// binaries.
///
/// It cannot see the embed table itself — that lives here, above it — and on a
/// source checkout it otherwise assumes it must compile a second `mvmctl` to
/// get one. When this binary already has the payload, it *is* the bootstrap
/// helper, and the compile is minutes spent reproducing what is already loaded.
#[cfg(feature = "builder-vm")]
fn declare_embedded_host_binaries() {
    mvm_build::builder_vm_bootstrap::declare_current_exe_carries_host_binaries(
        !crate::host_binaries::embedded::EMBEDDED.is_empty(),
    );
}

#[cfg(not(feature = "builder-vm"))]
fn declare_embedded_host_binaries() {}

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
    if cli.verbose > 0 {
        set_cli_env(mvm_build::guest_agent_build::GUEST_BUILD_VERBOSE_ENV, "1");
    }
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
        let stage0_active = env::builder_vm::stage0_active_in_process();
        eprintln!("\n{}", interrupt_cleanup_message(stage0_active));
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

fn interrupt_cleanup_message(stage0_active: bool) -> &'static str {
    if stage0_active {
        "Stage 0 build interrupted; no incomplete artifact was cached. The persistent Nix build store was preserved for retry. Cleaning up..."
    } else {
        "Interrupted, cleaning up..."
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
mod interrupt_message_tests {
    use super::interrupt_cleanup_message;

    #[test]
    fn stage0_interrupt_explains_cache_and_retry_state() {
        let message = interrupt_cleanup_message(true);
        assert!(message.contains("Stage 0 build interrupted"));
        assert!(message.contains("incomplete artifact was cached"));
        assert!(message.contains("Nix build store was preserved"));
    }

    #[test]
    fn ordinary_interrupt_keeps_the_generic_cleanup_message() {
        assert_eq!(
            interrupt_cleanup_message(false),
            "Interrupted, cleaning up..."
        );
    }
}
