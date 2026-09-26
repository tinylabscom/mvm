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
mod deployments;
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
use std::io::Write as _;
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

    /// Builder: hvf, firecracker, qemu, libkrun
    #[arg(
        long,
        global = true,
        value_parser = ["libkrun", "qemu", "hvf", "firecracker"],
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
    /// Inventory of recorded local deployments
    #[command(display_order = 4)]
    Deployments(deployments::Args),
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

/// The exact text `mvmctl <args>` would print for a help invocation, produced
/// without running `mvmctl`.
///
/// This is [`run_command`]'s help arm with the process removed: the same clap
/// tree parses the same argv, the same `DisplayHelp` error is stringified, and
/// the same `constrain_help_output` is applied. Because clap does the argv
/// handling, the *entry point* is still exercised — `<path> --help`,
/// `<path> -h` and `help <path>` each dispatch the way they really do, and
/// each can still render differently.
///
/// It exists for the help-width conformance scenarios, which asserted this by
/// spawning one `mvmctl` per command path. A debug `mvmctl` is over 100 MB and
/// the CLI has enough paths that the scenario dominated the suite's runtime and
/// read as a hang. Rendering in-process is the same assertion in microseconds.
///
/// `argv` is the user's arguments *without* the binary name. Returns `None`
/// when the invocation is not a help request — an unknown command, or a real
/// parse error — so a caller cannot mistake an error page for help text.
#[must_use]
pub fn help_text_for(argv: &[String]) -> Option<String> {
    let full = std::iter::once("mvmctl".to_string()).chain(argv.iter().cloned());
    match cli_command().try_get_matches_from(full) {
        // A successful parse is not a help invocation; there is no help to
        // render and reporting one would invent output the binary never emits.
        Ok(_) => None,
        Err(error) if error.kind() == ErrorKind::DisplayHelp => {
            Some(constrain_help_output(&error.to_string()))
        }
        Err(_) => None,
    }
}

/// Return the Clap `Command` tree for `mvmctl`.
///
/// Used by the `xtask` crate to generate man pages without duplicating the
/// command definition.
pub fn cli_command() -> clap::Command {
    constrain_help_width(Cli::command())
}

pub fn run() -> Result<()> {
    // The qemu vsock bridge re-execs this binary as a per-VM host helper, so
    // mvmctl answers the host-helper contract probe like every other helper —
    // before clap sees the unknown flag.
    mvm_vmm::host::helper_contract::exit_with_probe_answer_if_requested("mvmctl");
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
            mvm_observability::exit(exit_code);
        }
    };
    apply_startup_env(&cli);
    refuse_local_image_source_in_release_build(
        mvm_build::artifact_acquisition::compiled_channel(),
        &cli.command,
        mvm_build::image_source::configured_images_dir().as_deref(),
    )?;
    crate::host_binaries::source::allow_payload_from_source();
    declare_embedded_host_binaries();
    register_inhouse_builder();
    register_builder_session_starter();
    register_stream_plane();
    // Bound for the rest of the command so queued trace spans are flushed as
    // it returns. A verb that ends early goes through `mvm_observability::exit`,
    // which flushes the same export first.
    let _observability = configure_runtime_logging(&cli);

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

/// A release build refuses a configured local image checkout before any verb
/// runs, so nothing a release binary acquires or boots can come from one.
/// `doctor` is exempt so it can report the refusal instead of failing with it.
fn refuse_local_image_source_in_release_build(
    channel: mvm_build::artifact_acquisition::DistributionChannel,
    command: &Commands,
    configured: Option<&std::path::Path>,
) -> Result<()> {
    if matches!(command, Commands::Doctor(_)) {
        return Ok(());
    }
    mvm_build::image_source::refuse_in_release_build(channel, configured)?;
    Ok(())
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

/// Tell `mvm-build` whether this binary can supply the Linux host binaries a
/// builder VM bootstrap needs.
///
/// It cannot see the payload itself — that lives here, above it. A binary that
/// carries the payload, or can produce it from its source checkout, *is* the
/// bootstrap helper.
#[cfg(feature = "builder-vm")]
fn declare_embedded_host_binaries() {
    mvm_build::builder_vm_image::register_source_fingerprint_resolver(
        crate::commands::env::builder_vm::current_builder_vm_source_fingerprint,
    );
    mvm_build::builder_vm_bootstrap::declare_current_exe_provides_host_binaries(
        crate::host_binaries::source::payload_available(),
    );
    // Every builder boot carries this binary's own builder binaries as its
    // boot payload, whether the image bakes older copies or none at all.
    mvm_build::builder_boot::register_boot_payload_source(Box::new(
        crate::host_binaries::extract::EmbeddedBootPayload,
    ));
}

#[cfg(not(feature = "builder-vm"))]
fn declare_embedded_host_binaries() {}

fn register_inhouse_builder() {
    // Wire the driver-backed builder constructors so that
    // `mvm_build::builder_backend_select` can create them when the resolved
    // choice is HVF or Firecracker. This is a one-time registration at
    // startup; `mvm-build` cannot reach `mvm-backends` or `mvm-cli` directly
    // (dependency direction), so the CLI bridges the gap here. The two arms
    // differ only in the driver and in how the image is resolved.
    #[cfg(feature = "builder-vm")]
    mvm_build::builder_backend_select::register_driver_builders(Box::new(|choice| {
        use mvm_build::builder_backend_select::BuilderBackendChoice as Choice;
        use mvm_runtime::builder_runner::DriverBuilderVm;
        type Boxed = Box<dyn mvm_build::builder_vm::BuilderVm>;
        match choice {
            Choice::Hvf => Some(
                crate::commands::build::driver_builder_image::resolve_driver_builder_image().map(
                    |image| {
                        Box::new(
                            DriverBuilderVm::new(
                                mvm_backends::driver::hvf::HvfDriver::new(),
                                image.kernel,
                                image.rootfs,
                            )
                            .with_closure_nar(image.closure_nar),
                        ) as Boxed
                    },
                ),
            ),
            Choice::Firecracker => Some(
                crate::commands::build::driver_builder_image::resolve_driver_builder_image().map(
                    |image| {
                        Box::new(
                            DriverBuilderVm::new(
                                mvm_backends::driver::fc::FcDriver::new(),
                                image.kernel,
                                image.rootfs,
                            )
                            .with_closure_nar(image.closure_nar),
                        ) as Boxed
                    },
                ),
            ),
            Choice::Libkrun | Choice::Qemu | Choice::WebLinux => None,
        }
    }));

    // Stage 0 is a separate registration because it is a separate type: it
    // runs in the window before a builder image exists, so unlike the builder
    // above it resolves no image. `Stage0Vm` is generic over the driver, so
    // each backend costs one line here rather than an implementation.
    #[cfg(feature = "builder-vm")]
    mvm_build::builder_backend_select::register_stage0_builders(Box::new(|choice| {
        use mvm_build::builder_backend_select::BuilderBackendChoice as Choice;
        use mvm_runtime::builder_runner::Stage0Vm;
        type Boxed = Box<dyn mvm_build::builder_vm::BuilderVm>;
        match choice {
            Choice::Hvf => {
                Some(Box::new(Stage0Vm::new(mvm_backends::driver::hvf::HvfDriver::new())) as Boxed)
            }
            Choice::Firecracker => {
                Some(Box::new(Stage0Vm::new(mvm_backends::driver::fc::FcDriver::new())) as Boxed)
            }
            // libkrun, qemu and web-linux are resolved by `mvm-build` itself;
            // it can name those without reaching up a layer.
            Choice::Libkrun | Choice::Qemu | Choice::WebLinux => None,
        }
    }));

    // Stage 0's bootstrap kernel is pinned in source and verified in
    // `mvm-build`; this crate supplies only the transport. It has to be curl:
    // the pinned URL is a GitHub release asset, which redirects, and
    // `mvm-http` follows no redirects. Deliberately not `download_kernel`,
    // whose signed-manifest check needs `manifest-verify`, a feature an
    // ordinary `just embed` build does not carry.
    #[cfg(feature = "builder-vm")]
    mvm_build::stage0_kernel::register_bootstrap_kernel_fetcher(Box::new(
        |url: &str, dest: &std::path::Path| {
            let dest = dest
                .to_str()
                .ok_or_else(|| format!("destination is not UTF-8: {}", dest.display()))?;
            crate::commands::env::artifact_verify::download_file(url, dest)
                .map_err(|e| format!("{e:#}"))
        },
    ));
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

fn configure_runtime_logging(cli: &Cli) -> logging::ObservabilityGuard {
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
    logging::init(log_format, cli.verbose)
}

fn install_signal_handler() {
    let handler = termination_handler(Arc::clone(&CHILD_PIDS), |code| {
        mvm_observability::exit_after_interrupt(code)
    });
    if let Err(e) = crate::signal::set_ctrlc_handler(handler) {
        tracing::warn!("failed to install signal handler: {e}");
    }
}

/// The closure the signal servicer runs on SIGINT, SIGTERM or SIGHUP: report
/// the interrupt, run every registered interrupt cleanup (a resume's refusal of
/// its unadmitted guest, a restore's decrypted staging), signal tracked child
/// processes, and exit through `exit` with `128 + signal`.
///
/// The exit runs no destructors, so the cleanups must run here or not at all.
/// Output is written without `eprintln!`: after SIGHUP from a closed terminal
/// stderr can fail with EIO, and a panic here would skip every cleanup.
fn termination_handler(
    pids: Arc<std::sync::Mutex<Vec<u32>>>,
    exit: impl Fn(i32) + Send + 'static,
) -> impl FnMut(libc::c_int) + Send + 'static {
    move |signal| {
        // The console forwards Ctrl-C to the guest; a request to terminate
        // still terminates.
        if signal == libc::SIGINT && IN_CONSOLE_MODE.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let stage0_active = env::builder_vm::stage0_active_in_process();
        let _ = writeln!(
            std::io::stderr(),
            "\n{}",
            interrupt_cleanup_message(stage0_active)
        );
        let ran = mvm_runtime::interrupt_cleanup::run_all();
        if !ran.is_empty() {
            // A cleanup that could not settle its work (an unkillable VMM, a
            // failed registry write) leaves only this line behind.
            tracing::warn!(cleanups = ?ran, "ran interrupt cleanups before exiting");
        }
        if let Ok(pids) = pids.lock() {
            for &pid in pids.iter() {
                unsafe {
                    libc::kill(pid as libc::pid_t, libc::SIGTERM);
                }
            }
        }
        exit(128 + signal);
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
mod image_source_gate_tests {
    use super::{Cli, refuse_local_image_source_in_release_build};
    use clap::Parser;
    use mvm_build::artifact_acquisition::DistributionChannel;
    use std::path::Path;

    fn command(args: &[&str]) -> super::Commands {
        Cli::try_parse_from(std::iter::once("mvmctl").chain(args.iter().copied()))
            .expect("the test argv parses")
            .command
    }

    #[test]
    fn a_release_build_refuses_a_configured_checkout_before_any_verb() {
        let checkout = Some(Path::new("/nonexistent/mvm-images"));
        let err = refuse_local_image_source_in_release_build(
            DistributionChannel::Release,
            &command(&["cache", "info"]),
            checkout,
        )
        .expect_err("a release build must refuse MVM_IMAGES_DIR");
        assert!(err.to_string().contains("release build"), "{err:#}");
    }

    #[test]
    fn doctor_still_runs_so_it_can_report_the_refusal() {
        refuse_local_image_source_in_release_build(
            DistributionChannel::Release,
            &command(&["doctor"]),
            Some(Path::new("/nonexistent/mvm-images")),
        )
        .expect("doctor reports the refusal rather than failing with it");
    }

    #[test]
    fn a_contributor_build_or_an_unset_variable_passes() {
        let cmd = command(&["cache", "info"]);
        refuse_local_image_source_in_release_build(
            DistributionChannel::Source,
            &cmd,
            Some(Path::new("/nonexistent/mvm-images")),
        )
        .unwrap();
        refuse_local_image_source_in_release_build(DistributionChannel::Release, &cmd, None)
            .unwrap();
    }
}

#[cfg(test)]
mod termination_handler_tests {
    use super::termination_handler;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::{Arc, Mutex};

    /// The handler the CLI installs runs the registered interrupt cleanups
    /// before it exits, and exits with 128 plus the signal. Driven through
    /// the same closure `install_signal_handler` hands the signal servicer.
    #[test]
    fn a_termination_signal_runs_the_interrupt_cleanups_then_exits() {
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            let cleaned = Arc::new(AtomicI32::new(0));
            let observed = Arc::clone(&cleaned);
            let _armed = mvm_runtime::interrupt_cleanup::on_interrupt("test cleanup", move || {
                observed.fetch_add(1, Ordering::SeqCst);
            });
            let exit_code = Arc::new(AtomicI32::new(0));
            let exited = Arc::clone(&exit_code);
            let mut handler = termination_handler(Arc::new(Mutex::new(Vec::new())), move |code| {
                exited.store(code, Ordering::SeqCst);
            });
            handler(signal);
            assert_eq!(cleaned.load(Ordering::SeqCst), 1, "signal {signal}");
            assert_eq!(exit_code.load(Ordering::SeqCst), 128 + signal);
        }
    }
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
