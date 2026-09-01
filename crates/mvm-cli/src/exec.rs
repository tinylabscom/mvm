//! `mvmctl exec` — boot a transient microVM, run one command, tear down.
//!
//! Composes existing primitives: template artifact resolution → backend
//! start → vsock guest agent → backend stop. The "what to run" is modeled
//! as a tagged enum so future variants (mvmforge `launch.json`, baked-in
//! template entrypoint) can be added without churning the inline-command
//! surface.
//!
//! Dev-mode only: the guest agent's Exec handler is gated at compile time
//! by the `interactive` Cargo feature. Production guest binaries are built
//! without `interactive`, so the handler is not present and `exec` returns
//! "exec not available" regardless of any runtime configuration.

use anyhow::{Context, Result, anyhow};
use mvm_core::launch_trace::PhaseTimingMode;
use mvm_core::vm_backend::{
    RequiredCapabilities, SnapshotCapability, VmId, VmStartConfig, VmVolume,
};
use mvm_runtime::backend::AnyBackend;
use mvm_runtime::vsock_transport;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

use crate::commands::DirShareSpec;
use crate::ui;

mod either;
/// Exit code the CLI returns when a guest command exceeds its `--timeout`.
/// Matches GNU `timeout(1)` so scripts can branch on it.
mod guest_run;
mod launch_plan;
mod mounts;
use either::Either;
use mounts::refuse_unloadable_sidecar;
mod session;
mod transient;

pub use launch_plan::load_launch_plan;

use guest_run::{emit_guest_console_diagnostic, run_in_guest, run_wasm_module};
use session::wait_for_agent_timed;
pub use session::{
    AdmitInputs, SessionAdmit, SessionAuditSubstrate, SessionVm, boot_session_vm,
    dispatch_in_session, tear_down_session_vm, wait_for_agent,
};
use transient::{BootAttempt, boot_transient_vm, install_ctrlc_teardown, teardown_transient_vm};

pub const EXEC_TIMEOUT_EXIT_CODE: i32 = 124;

/// Human-facing message for a command killed by its `--timeout`. `None`
/// timeout ⇒ no duration suffix (e.g. the interactive console path).
pub(crate) fn timeout_exit_message(timeout_secs: Option<u64>) -> String {
    let suffix = timeout_secs
        .map(|s| format!(" after {s}s"))
        .unwrap_or_default();
    format!("error: command timed out{suffix}")
}

/// Where to source the command that runs inside the transient microVM.
///
/// Marked `non_exhaustive` so future variants (e.g. baked-in template
/// entrypoint) can be added without breaking match arms in callers outside
/// this crate.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ExecTarget {
    /// Argv supplied directly on the CLI.
    Inline { argv: Vec<String> },
    /// Entrypoint sourced from an mvmforge `launch.json` workload IR.
    ///
    /// v1 supports single-app workloads only. Multi-app workloads require
    /// orchestration that's out of scope for `mvmctl exec`.
    LaunchPlan { entrypoint: LaunchEntrypoint },
    // Future variants (do not implement until needed):
    // TemplateEntrypoint,               // entrypoint baked into template metadata
}

/// Resolved entrypoint extracted from an mvmforge `launch.json`.
///
/// Mirrors the subset of the v0 IR that `mvmctl exec` needs:
///   - `command` — argv to exec inside the guest.
///   - `working_dir` — optional `cd` target before exec.
///   - `env` — merged from `apps[].env` (lower precedence) and
///     `apps[].entrypoint.env` (higher precedence), per mvmforge semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchEntrypoint {
    pub command: Vec<String>,
    pub working_dir: Option<String>,
    pub env: BTreeMap<String, String>,
}

/// Where the VM's disk image and kernel come from.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ImageSource {
    /// A registered template (resolved via `template::lifecycle::template_artifacts`).
    Template(String),
    /// A specific stored revision in a manifest-keyed slot. This is used by
    /// content-addressed image restore so the boot cannot follow `current`.
    PinnedTemplate {
        slot_hash: String,
        revision_hash: String,
    },
    /// Pre-built kernel + rootfs paths (e.g., the cached dev image).
    Prebuilt {
        kernel_path: String,
        rootfs_path: String,
        initrd_path: Option<String>,
        /// Display label used in messages and `flake_ref` (no functional effect).
        label: String,
        /// The unpacked+injected OCI tree behind this image, when it came from
        /// one. Carried because it is what distinguishes an OCI-derived
        /// prebuilt from the cached dev image, which take different initrds.
        ///
        /// It used to be a virtiofs-root *candidate*, and the tier gate read it
        /// to decide whether to serve the tree over virtio-fs. That gate is
        /// gone; the fact it recorded is not.
        unpacked_oci_root: Option<String>,
    },
    /// Pre-built `wasm32-wasip1` module run directly under the wasm backend.
    /// No kernel, initrd, or rootfs — the module path is the workload.
    WasmModule { module_path: String, label: String },
}

fn effective_transient_initrd(
    image: &ImageSource,
    explicit_initrd: Option<&str>,
    rootfs_path: &str,
    root_strategy: mvm_build::run_image::RootStrategy,
) -> Result<Option<String>> {
    if let Some(path) = explicit_initrd {
        return Ok(Some(path.to_string()));
    }
    if root_strategy != mvm_build::run_image::RootStrategy::BlockExt4 {
        return Ok(None);
    }
    let ImageSource::Prebuilt {
        unpacked_oci_root: Some(_),
        ..
    } = image
    else {
        return Ok(None);
    };
    crate::commands::vm::up::persistent_oci_effective_initrd(std::path::Path::new(rootfs_path))
}

/// Boot inputs consumed by [`resolve_launch`], excluding guest command details.
/// This lets `pool warm` resolve the same verity and policy-bearing config as a
/// real launch without fabricating an empty [`ExecRequest`].
pub struct LaunchShape<'a> {
    /// Explicit VM name, or `None` to generate a throwaway one.
    pub name: Option<&'a str>,
    pub image: &'a ImageSource,
    pub cpus: u32,
    pub memory_mib: u32,
    pub mem_initial_mib: Option<u32>,
    pub dir_shares: &'a [DirShareSpec],
    /// Block-device mounts supplied by transient `--mount` disk syntax.
    pub disk_volumes: &'a [VmVolume],
    pub pty: bool,
    pub network_policy: &'a mvm_core::network_policy::NetworkPolicy,
    pub warm_pool_size: u32,
    /// SDK-served host services the signed plan will bind, if any.
    ///
    /// The *bindings*, not a resolved attachment: which of the two sidecar
    /// artifacts they need depends on the guest's libc, and the guest does not
    /// exist until this shape has been resolved into an image.
    /// [`resolve_launch`] makes the choice once the rootfs is materialized and
    /// hands the single result to both the launch config and admission.
    pub sdk_host_services: &'a [mvm_contract::protocol::broker::ServiceId],
    /// The libc a catalogued runtime *declares*, or `Unknown` for an image
    /// this host has no declaration for. Cross-checked against what the
    /// materialized rootfs turns out to record; it never selects.
    pub declared_libc: mvm_contract::guest_libc::GuestLibc,
    pub hypervisor: Option<&'a str>,
}

/// All inputs to the orchestrator.
#[derive(Debug, Clone)]
pub struct ExecRequest {
    /// Optional VM identity for a foreground transient run. Absent generates a
    /// throwaway name.
    pub name: Option<String>,
    pub image: ImageSource,
    pub cpus: u32,
    pub memory_mib: u32,
    /// Opt into virtio-balloon. `None` keeps the legacy "commit
    /// memory_mib at boot" behaviour; `Some(n)` commits only `n` MiB
    /// initially and lets the host-side reclaim controller adjust.
    /// See [`VmStartConfig::mem_initial_mib`].
    ///
    /// [`VmStartConfig::mem_initial_mib`]:
    ///     mvm_core::vm_backend::VmStartConfig::mem_initial_mib
    pub mem_initial_mib: Option<u32>,
    /// Live read-only host-directory shares requested by `machine run --mount`.
    pub dir_shares: Vec<DirShareSpec>,
    /// Materialized disk-image volumes requested by `machine run --mount`.
    pub disk_volumes: Vec<VmVolume>,
    pub env: Vec<(String, String)>,
    pub target: ExecTarget,
    /// Timeout for the in-guest command in seconds. `None` ⇒ no per-command
    /// kill (the default for interactive/ad-hoc exec).
    pub timeout_secs: Option<u64>,
    /// Run the command attached to a PTY instead of pipe-streamed stdio.
    pub pty: bool,
    /// Effective egress policy for the transient VM. Defaults to
    /// `deny_all`; `--net` / `--allow-host` widen it. Threaded onto
    /// `VmStartConfig.network_policy` so every backend enforces the same
    /// value.
    pub network_policy: mvm_core::network_policy::NetworkPolicy,
    /// Warm-pool size for this transient run. `> 0` makes the run
    /// eligible to claim a pre-booted standby (skipping cold boot) and to
    /// replenish the pool after teardown; `0` always cold-boots. Resolved from
    /// `MachineRunMode::warm_pool_size` — nonzero only for throwaway auto-named
    /// transient/interactive-transient runs.
    pub warm_pool_size: u32,
    /// Bytes to forward to the guest `Exec` frame's stdin field. Empty ⇒ no
    /// stdin (`GuestRequest::Exec.stdin = None`). Set from piped host stdin
    /// when the host is not a TTY; always empty for PTY / interactive modes.
    pub stdin: Vec<u8>,
    /// Recorded liveness declaration (phase A: presence only). Persisted with a
    /// persistent machine so it survives + is inspectable; not yet probed.
    pub healthcheck: Option<mvm_contract::ir::HealthCheck>,
    /// Resolved SDK-sidecar attachment for this run, or `None` when the
    /// workload binds no SDK-served host service. Resolved (and verified)
    /// before admission so the signed plan's grant and the launch config's
    /// volume describe the same bytes; the shared admission gate refuses the
    /// launch if they ever disagree.
    /// SDK-served host services this run binds, or empty.
    ///
    /// The sidecar they imply is resolved inside [`resolve_launch`], after the
    /// image is materialized: there is one artifact per guest libc, and nothing
    /// before materialization knows which libc an arbitrary `--image` has. One
    /// resolution feeds both the signed plan's grant and the launch config's
    /// volume, so they cannot describe different bytes; the shared admission
    /// gate refuses the launch if they ever do.
    pub sdk_host_services: Vec<mvm_contract::protocol::broker::ServiceId>,
    /// The libc a catalogued runtime declared for this image, or `Unknown`.
    /// A cross-check against the materialized image, never the selector.
    pub declared_libc: mvm_contract::guest_libc::GuestLibc,
    /// Requested workload hypervisor (from `--hypervisor`), or `None` to
    /// auto-detect. Kept here so `run_inner`'s backend selection agrees with the
    /// admit/build sites that read it off `RunArgs`.
    pub hypervisor: Option<String>,
}

impl ExecRequest {
    /// Borrow the boot-shape half of this request. The launch resolution reads
    /// only these fields, so a run and a `pool warm` that agree on them resolve
    /// the same config — which is what makes the warm-pool compat key match.
    pub fn launch_shape(&self) -> LaunchShape<'_> {
        LaunchShape {
            name: self.name.as_deref(),
            image: &self.image,
            cpus: self.cpus,
            memory_mib: self.memory_mib,
            mem_initial_mib: self.mem_initial_mib,
            dir_shares: &self.dir_shares,
            disk_volumes: &self.disk_volumes,
            pty: self.pty,
            network_policy: &self.network_policy,
            warm_pool_size: self.warm_pool_size,
            sdk_host_services: &self.sdk_host_services,
            declared_libc: self.declared_libc,
            hypervisor: self.hypervisor.as_deref(),
        }
    }
}

pub(crate) fn select_exec_backend(
    image_requested: bool,
    network_policy: &mvm_core::network_policy::NetworkPolicy,
    requested: Option<&str>,
) -> Result<AnyBackend> {
    // CLI `--hypervisor` wins over the MVM_HYPERVISOR/MVM_BACKEND env override.
    let backend_override = requested
        .and_then(normalize_backend_override)
        .or_else(explicit_hypervisor_override);
    let backend_name = select_backend_name_for_egress(
        backend_override.as_deref(),
        image_requested,
        network_policy,
        "OCI --image runs with outbound egress enabled",
    )?;
    AnyBackend::require_hypervisor_selectable(&backend_name)?;
    Ok(AnyBackend::from_hypervisor(&backend_name))
}

/// An explicit workload-backend override from the environment. The transient
/// run path otherwise auto-detects the backend; this lets `MVM_HYPERVISOR`
/// (or `MVM_BACKEND`) pin it — e.g. `libkrun`, whose vsock-tunnel egress path
/// the auto-detected default would otherwise never select on this host. Every
/// `select_exec_backend` call site reads the same value, so the admitted plan's
/// backend and the boot backend agree.
fn explicit_hypervisor_override() -> Option<String> {
    ["MVM_HYPERVISOR", "MVM_BACKEND"]
        .into_iter()
        .filter_map(std::env::var_os)
        .find_map(|raw| normalize_backend_override(&raw.to_string_lossy()))
}

/// Normalize a backend-override string (trim + lowercase); a blank value yields
/// `None` so an empty env var is treated as "unset" rather than an invalid
/// backend name.
fn normalize_backend_override(raw: &str) -> Option<String> {
    let value = raw.trim().to_ascii_lowercase();
    (!value.is_empty()).then_some(value)
}

pub(crate) fn select_backend_name_for_egress(
    backend_override: Option<&str>,
    image_requested: bool,
    network_policy: &mvm_core::network_policy::NetworkPolicy,
    workload: &str,
) -> Result<String> {
    if let Some(backend_name) = backend_override {
        validate_backend_for_egress(backend_name, image_requested, network_policy, workload)?;
        return Ok(backend_name.to_string());
    }

    if !requires_vsock_proxy_backend(image_requested, network_policy) {
        return Ok(AnyBackend::auto_select().name().to_string());
    }

    AnyBackend::select_capable_available(&vsock_proxy_backend_requirements())
        .map(|backend| backend.name().to_string())
        .map_err(|e| anyhow!("{workload} require a NIC-less host-vsock-proxy backend: {e}"))
}

pub(crate) fn validate_backend_for_egress(
    backend_name: &str,
    image_requested: bool,
    network_policy: &mvm_core::network_policy::NetworkPolicy,
    workload: &str,
) -> Result<()> {
    if !requires_vsock_proxy_backend(image_requested, network_policy) {
        return Ok(());
    }

    let backend = AnyBackend::from_hypervisor(backend_name);
    let missing = backend
        .capabilities()
        .shortfall(&vsock_proxy_backend_requirements());
    if missing.is_empty() {
        let available = backend
            .is_available()
            .with_context(|| format!("probing backend {backend_name} availability"))?;
        if available {
            return Ok(());
        }
        anyhow::bail!(
            "{workload} require a NIC-less host-vsock-proxy backend; backend {backend_name} is unavailable on this host"
        );
    }

    anyhow::bail!(
        "{workload} require a NIC-less host-vsock-proxy backend; backend {backend_name} lacks [{}]",
        missing.join(", ")
    );
}

fn requires_vsock_proxy_backend(
    image_requested: bool,
    network_policy: &mvm_core::network_policy::NetworkPolicy,
) -> bool {
    image_requested && network_policy.allows_egress()
}

fn vsock_proxy_backend_requirements() -> RequiredCapabilities {
    RequiredCapabilities {
        vsock: true,
        no_routable_guest_nic: true,
        host_vsock_proxy: true,
        ..Default::default()
    }
}

pub(crate) fn validate_image_egress_backend(
    backend: &AnyBackend,
    image_requested: bool,
    network_policy: &mvm_core::network_policy::NetworkPolicy,
) -> Result<()> {
    if !image_requested || !network_policy.allows_egress() {
        return Ok(());
    }
    let caps = backend.capabilities();
    if caps.vsock && caps.no_routable_guest_nic && caps.host_vsock_proxy {
        return Ok(());
    }
    anyhow::bail!(
        "OCI --image runs with outbound egress enabled require a NIC-less host-vsock-proxy backend; \
         backend {} does not advertise {{vsock,no_routable_guest_nic,host_vsock_proxy}}",
        backend.name()
    );
}

pub(crate) fn validate_image_egress_backend_name(
    backend_name: &str,
    image_requested: bool,
    network_policy: &mvm_core::network_policy::NetworkPolicy,
) -> Result<()> {
    let backend = AnyBackend::from_hypervisor(backend_name);
    validate_image_egress_backend(&backend, image_requested, network_policy)
}

fn shape_uses_vsock_proxy_backend(shape: &LaunchShape<'_>) -> bool {
    matches!(
        shape.image,
        ImageSource::Prebuilt {
            unpacked_oci_root: Some(_),
            ..
        }
    ) && shape.network_policy.allows_egress()
}

/// Build the IR healthcheck from the CLI flags. A shell command string becomes
/// an exec argv the guest agent runs (`/bin/sh -lc <cmd>`). `None` command ⇒ no
/// healthcheck (a plain task).
pub fn build_healthcheck(
    cmd: Option<&str>,
    interval_secs: u32,
    timeout_secs: u32,
    retries: u32,
    start_period_secs: u32,
) -> Option<mvm_contract::ir::HealthCheck> {
    let cmd = cmd?;
    Some(mvm_contract::ir::HealthCheck {
        command: vec!["/bin/sh".into(), "-lc".into(), cmd.to_string()],
        interval_secs,
        timeout_secs,
        retries,
        start_period_secs,
    })
}

impl ExecRequest {
    /// Convert the target into a single shell command string suitable for
    /// `GuestRequest::Exec`. Argv is shell-quoted and prefixed with `exec`
    /// so the process inherits the wrapper's stdio.
    pub fn target_command(&self) -> String {
        match &self.target {
            ExecTarget::Inline { argv } => quote_argv_for_exec(argv),
            ExecTarget::LaunchPlan { entrypoint } => quote_argv_for_exec(&entrypoint.command),
        }
    }
}

fn quote_argv_for_exec(argv: &[String]) -> String {
    let quoted: Vec<String> = argv.iter().map(|a| shell_quote(a)).collect();
    format!("exec {}", quoted.join(" "))
}

/// Quote a single argument for inclusion in a shell command line.
///
/// Wraps in single quotes and escapes embedded single quotes the
/// portable POSIX way (`'` → `'\''`).
pub fn shell_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            out.push_str(r"'\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Build the wrapper script that runs inside the guest:
///   1. exports launch-plan-derived env vars (when target is LaunchPlan)
///   2. exports CLI `--env` vars (CLI overrides launch-plan)
///   3. cds into `working_dir` (when target is LaunchPlan and it's set)
///   4. execs the resolved command
///
/// Host directories are attached and mounted by the guest activation path. The
/// command wrapper must not contain a second mount implementation.
///
/// Env precedence (lowest → highest): launch-plan app.env → launch-plan
/// entrypoint.env → CLI `--env`. The first two are merged in
/// `parse_launch_plan`; CLI wins by being emitted last.
pub fn build_guest_wrapper(req: &ExecRequest) -> String {
    let mut script = String::from("set -e\n");
    if let ExecTarget::LaunchPlan { entrypoint } = &req.target {
        for (k, v) in &entrypoint.env {
            script.push_str(&format!("export {k}={}\n", shell_quote(v)));
        }
    }
    for (k, v) in &req.env {
        script.push_str(&format!("export {k}={}\n", shell_quote(v)));
    }
    // After the caller's exports, and composed against `$PATH` in the guest, so
    // the mediated tools win whatever the image or the caller sets. A NIC-less
    // guest's `ping` is one of these: the image's own copy fails at `socket()`.
    script.push_str(&format!(
        "export PATH={}:\"$PATH\"\n",
        shell_quote(mvm_core::guest_netd::MEDIATED_TOOLS_BIN),
    ));
    if let ExecTarget::LaunchPlan { entrypoint } = &req.target
        && let Some(wd) = &entrypoint.working_dir
    {
        script.push_str(&format!("cd {}\n", shell_quote(wd)));
    }
    script.push_str(&req.target_command());
    script.push('\n');
    script
}

/// Generate a transient VM name for an exec invocation.
pub fn transient_vm_name() -> String {
    mvm_core::naming::generate_machine_name()
}

/// Whether a transient run should pre-open interactive console data sockets.
///
/// `true` only when the caller requested a PTY (`pty`) AND the image is not
/// sealed (`image_sealed == false`). A verity-backed OCI/dev image may still be
/// interactive, so sealing/accessibility must follow the image sidecar rather
/// than the presence of verity sidecars alone.
pub fn transient_run_dev_console(pty: bool, image_sealed: bool) -> bool {
    pty && !image_sealed
}

/// Remove the transient VM's host state dir (`~/.mvm/vms/<name>`) once the VM
/// is stopped. Host-side
/// `std::fs` — never `run_in_vm`, which targets a path *inside* the guest and
/// (on macOS) would wake a builder VM to `rm` a path that isn't there, leaking
/// the real host dir. Runs for every transient run: the backend writes
/// `hvf.pid` / `console.log` here regardless, so a plain OCI launch created
/// the dir and must clean it up too. Best-effort — teardown must
/// never fail on a cleanup error.
fn remove_transient_state_dir(staging_dir: &str) {
    match std::fs::remove_dir_all(staging_dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::debug!(error = %e, dir = staging_dir, "transient state dir cleanup failed");
            // Firecracker is launched under sudo, so its console/hypervisor
            // logs, API socket, and vsock UDS are root-owned. A normal
            // `remove_dir_all` cannot delete them; fall back to the same
            // privilege level on Linux. On other platforms the leak is logged
            // and left for the next convergence pass / manual cleanup.
            #[cfg(target_os = "linux")]
            {
                let quoted = mvm_runtime::shell::shell_quote(staging_dir);
                match std::process::Command::new("bash")
                    .args(["-c", &format!("sudo rm -rf {quoted}")])
                    .output()
                {
                    Ok(output) if output.status.success() => {}
                    Ok(output) => {
                        tracing::debug!(
                            status = ?output.status,
                            stderr = %String::from_utf8_lossy(&output.stderr),
                            dir = staging_dir,
                            "privileged transient state dir cleanup failed"
                        );
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, dir = staging_dir, "privileged transient state dir cleanup command failed");
                    }
                }
            }
        }
    }
}

/// Decide whether snapshot restore is safe for this request.
///
/// Only enabled for the trivial case: a registered template (so the image
/// has a snapshot at all), no live directory shares (so the device layout
/// matches the snapshot's recorded layout), and a backend that advertises
/// snapshot support.
pub fn snapshot_eligible(
    image: &ImageSource,
    dir_shares: &[DirShareSpec],
    snap_present: bool,
    snapshot_capability: SnapshotCapability,
) -> bool {
    if snapshot_capability == SnapshotCapability::Unsupported
        || !snap_present
        || !dir_shares.is_empty()
    {
        return false;
    }
    matches!(image, ImageSource::Template(_))
}

/// Captured stdout/stderr/exit-code from a one-shot exec.
///
/// `run_captured` returns this instead of streaming guest output to the
/// CLI's terminal, so a caller can inspect the run's output as data.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub phase_timing: Option<crate::commands::vm::phase_timing::RunPhaseTimingReport>,
}

/// Run the request and capture stdout/stderr instead of streaming.
///
/// Same orchestration as [`run`]: boot a transient microVM, dispatch
/// the command via the guest agent's `Exec` over vsock, tear down.
/// The only difference is what happens with the guest's stdout/stderr
/// — captured into the returned [`ExecOutput`] instead of inherited
/// to the parent process's terminal.
///
/// Used where a caller needs the output as data; the CLI's interactive
/// `mvmctl exec` keeps using [`run`] (streaming) so human ergonomics
/// don't regress.
pub fn run_captured(req: ExecRequest, admit: Option<&SessionAdmit<'_>>) -> Result<ExecOutput> {
    run_inner(req, /* capture = */ true, admit, None)
        .map(|either| either.right().expect("capture mode returns ExecOutput"))
}

/// Like [`run_captured`], but also reports the resolved boot posture into
/// `posture` so the command layer can chain-audit it (`plan.boot_posture`).
pub fn run_captured_with_posture(
    req: ExecRequest,
    admit: Option<&SessionAdmit<'_>>,
    posture: &PostureSink,
) -> Result<ExecOutput> {
    run_inner(req, /* capture = */ true, admit, Some(posture))
        .map(|either| either.right().expect("capture mode returns ExecOutput"))
}

/// Run the request: boot, run, tear down.
///
/// Returns the guest command's exit code. On orchestrator failure (boot,
/// agent unreachable, vsock error), returns an error; the VM is torn down
/// best-effort before returning.
pub fn run(req: ExecRequest, admit: Option<&SessionAdmit<'_>>) -> Result<i32> {
    run_inner(req, /* capture = */ false, admit, None)
        .map(|either| either.left().expect("streaming mode returns exit code"))
}

/// Like [`run`], but also reports the resolved boot posture into `posture` so
/// the command layer can chain-audit it (`plan.boot_posture`).
pub fn run_with_posture(
    req: ExecRequest,
    admit: Option<&SessionAdmit<'_>>,
    posture: &PostureSink,
) -> Result<i32> {
    run_inner(req, /* capture = */ false, admit, Some(posture))
        .map(|either| either.left().expect("streaming mode returns exit code"))
}

fn boots_baked_entrypoint(req: &ExecRequest) -> bool {
    matches!(&req.target, ExecTarget::Inline { argv } if argv.is_empty())
}

fn baked_entrypoint_result(
    status: mvm_core::vm_backend::VmExitStatus,
    capture: bool,
    vm_name: &str,
) -> Result<Either<i32, ExecOutput>> {
    let code = status.code.with_context(|| {
        format!("baked workload in {vm_name} stopped without reporting its exit code")
    })?;
    if capture {
        Ok(Either::Right(ExecOutput {
            exit_code: code,
            stdout: String::new(),
            stderr: String::new(),
            phase_timing: None,
        }))
    } else {
        Ok(Either::Left(code))
    }
}

/// Side channel by which [`run_inner`] reports the resolved boot posture (which
/// rootfs strategy the run-path tier gate selected) back to the command layer,
/// which records it on the chain-signed admission log (`plan.boot_posture`).
/// The command layer reads it after the run returns. `None` means the caller
/// does not audit posture (session boots, which never reach virtiofs).
pub type PostureSink = std::cell::Cell<mvm_build::run_image::RootStrategy>;

fn run_inner(
    req: ExecRequest,
    capture: bool,
    admit: Option<&SessionAdmit<'_>>,
    posture: Option<&PostureSink>,
) -> Result<Either<i32, ExecOutput>> {
    // Phase timing (off unless `MVM_PHASE_TIMING` or a launch-sample path is
    // set): capture a host-monotonic mark at each run seam, then emit a
    // one-line breakdown and/or the machine-readable sample at teardown. When
    // both are off every mark stays `None` and costs nothing.
    let sample_path = crate::commands::vm::launch_sample::sample_path_from_env();
    let timing_mode = crate::commands::vm::phase_timing::mode();
    let timing = timing_mode.is_on() || sample_path.is_some();
    let mut sub_marks = crate::commands::vm::phase_timing::LaunchSubMarks::new(timing);
    let t_start = timing.then(std::time::Instant::now);

    // Everything from backend selection through admission and the runtime
    // overlay attach. It yields a bootable config without booting, which is
    // also what `pool warm` needs — so it lives in one function both call
    // rather than two that are free to drift.
    let mut resolve_marks = LaunchResolveMarks::new(timing);
    let launch = resolve_launch(
        &req.launch_shape(),
        admit,
        &mut resolve_marks,
        &mut sub_marks,
    )?;
    let ResolvedLaunch {
        backend,
        start_config,
        use_snapshot,
        root_strategy,
        image: resolved,
    } = launch;
    let vm_name = start_config.name.clone();

    // Report the resolved strategy to the command layer for chain-audit. This is
    // the single source of truth — the same value that drives the boot below —
    // so the `plan.boot_posture` entry can never diverge from what actually
    // booted.
    if let Some(sink) = posture {
        sink.set(root_strategy);
    }

    let t_image_resolved = resolve_marks.image_resolved;
    let t_drives_ready = resolve_marks.drives_ready;
    let t_admitted = resolve_marks.admitted;

    // Reap stale standbys, try a warm-pool claim, then fall back to
    // snapshot-restore / cold boot. See `boot_transient_vm`.
    let mut warm_claim_marks = crate::commands::vm::phase_timing::WarmClaimMarks::default();
    let requested_vm_name = vm_name.clone();
    let boot_attempt = BootAttempt {
        backend: &backend,
        start_config: &start_config,
        resolved: &resolved,
    };
    let (vm_name, launch_mode) = boot_transient_vm(
        vm_name,
        use_snapshot,
        &boot_attempt,
        timing.then_some(&mut warm_claim_marks),
        &mut sub_marks,
    )?;
    let t_backend_started = timing.then(std::time::Instant::now);

    // Read the backend's own phase sidecar now: teardown removes the state
    // directory that holds it, and by the time the sample is assembled it is
    // gone. A backend that does not trace itself yields nothing here.
    let backend_trace = timing
        .then(|| mvm_core::launch_trace::read_trace(&mvm_core::config::vm_state_dir(&vm_name)))
        .flatten();
    let backend_phases = backend_trace
        .as_ref()
        .map(|trace| trace.phases.clone())
        .unwrap_or_default();
    let degraded = backend_trace
        .map(|trace| trace.degraded)
        .unwrap_or_default();

    let warm_memory_start = if sample_path.is_some()
        && launch_mode == crate::commands::vm::phase_timing::LaunchMode::Warm
    {
        Some(begin_warm_memory_measurement(&backend, &vm_name))
    } else {
        None
    };

    // Install Ctrl-C handler that tears the VM down.
    let interrupted = install_ctrlc_teardown(&vm_name, backend.name());

    // Run the command + always tear down. The wasm backend has no guest
    // agent; the module already ran inside `start`, so we just collect its
    // exit status instead of waiting for a vsock console.
    let run_outcome = if backend.name() == "wasm" {
        match run_wasm_module(&backend, &vm_name) {
            Ok(code) => Ok((Either::Left(code), None)),
            Err(e) => Err(e),
        }
    } else if boots_baked_entrypoint(&req) {
        let workload_started = timing.then(std::time::Instant::now);
        backend
            .wait(&mvm_core::vm_backend::VmId(vm_name.clone()))
            .with_context(|| format!("waiting for baked workload in {vm_name}"))
            .and_then(|status| baked_entrypoint_result(status, capture, &vm_name))
            .map(|result| (result, workload_started))
    } else {
        run_in_guest(&vm_name, &req, capture, timing, &mut sub_marks)
    };
    let t_command_done = timing.then(std::time::Instant::now);
    let (mut result, t_vsock_ready) = match run_outcome {
        Ok((either, vsock_ready)) => (Ok(either), vsock_ready),
        Err(e) => (Err(e), None),
    };
    let warm_memory_result = warm_memory_start.map(|start| {
        start.and_then(|start| finish_warm_memory_measurement(&backend, &vm_name, start))
    });
    let warm_memory_error = warm_memory_result
        .as_ref()
        .and_then(|result| result.as_ref().err())
        .map(|error| format!("{error:#}"));
    let warm_first_command_memory = warm_memory_result.and_then(Result::ok);

    // Reap state dirs a killed or crashed prior transient run left behind: a
    // SIGKILL or a closed terminal skips teardown, so `~/.mvm/vms/<name>` leaks.
    // Keep this broad orphan-only sweep off the launch path; transient names
    // are unique and the current VM has already completed its command, so the
    // maintenance pass cannot delay admission or the first guest operation.
    let _ = mvm_runtime::vm::reconcile::reap_orphan_state_dirs(Some(vm_name.as_str()));

    sub_marks.start(crate::commands::vm::phase_timing::SubPhase::CleanupHandoff);
    teardown_transient_vm(&backend, &vm_name, &requested_vm_name, &mut sub_marks);
    sub_marks.finish(crate::commands::vm::phase_timing::SubPhase::CleanupHandoff);
    let t_torn_down = timing.then(std::time::Instant::now);

    // Emit the phase breakdown when every seam was marked (i.e. timing was
    // enabled and the run reached teardown without an early return).
    let mut phase_timing = None;
    if let (
        Some(start),
        Some(image_resolved),
        Some(drives_ready),
        Some(admitted),
        Some(backend_started),
        Some(vsock_ready),
        Some(command_done),
        Some(torn_down),
    ) = (
        t_start,
        t_image_resolved,
        t_drives_ready,
        t_admitted,
        t_backend_started,
        t_vsock_ready,
        t_command_done,
        t_torn_down,
    ) {
        let marks = crate::commands::vm::phase_timing::RunPhaseMarks {
            launch_mode,
            start,
            image_resolved,
            drives_ready,
            admitted,
            pool_wait_started: warm_claim_marks.pool_wait_started,
            claim_started: warm_claim_marks.claim_started,
            backend_started,
            vsock_ready,
            command_done,
            torn_down,
        };
        let phases = marks.to_timings();
        let sub_phases = sub_marks.to_timings();
        let report = crate::commands::vm::phase_timing::RunPhaseTimingReport::new(
            phases,
            sub_phases,
            backend_phases.clone(),
            degraded.clone(),
        );
        if timing_mode.is_on() {
            if capture {
                phase_timing = Some(report.clone());
            } else {
                eprintln!("{}", report.render_table());
                // Keep the line form available to existing timing consumers;
                // structured callers receive the report instead of stderr.
                if timing_mode == PhaseTimingMode::Line {
                    eprintln!("{}", report.phases.render());
                    eprintln!("{}", report.sub_phases.render());
                }
            }
        }
        if let Some(path) = sample_path.as_deref() {
            if let Some(error) = warm_memory_error.as_deref() {
                eprintln!(
                    "[mvm] launch sample not written: warm memory measurement failed: {error}"
                );
            } else {
                let sample = build_launch_sample(LaunchSampleInputs {
                    backend: backend.name(),
                    start_config: &start_config,
                    launch_mode,
                    root_strategy,
                    mount_materialized: sub_marks
                        .recorded(crate::commands::vm::phase_timing::SubPhase::MountMaterialize),
                    phases,
                    sub_phases,
                    warm_first_command_memory,
                    backend_phases: backend_phases.clone(),
                    degraded: degraded.clone(),
                });
                if let Err(e) = crate::commands::vm::launch_sample::write_sample(path, &sample) {
                    // A measurement that cannot be recorded must be loud: a
                    // silently missing sample reads downstream as a launch that
                    // never ran, not as a launch nobody wrote down.
                    eprintln!("[mvm] launch sample not written: {e:#}");
                }
            }
        }
    }

    if let Some(report) = phase_timing
        && let Ok(Either::Right(output)) = &mut result
    {
        output.phase_timing = Some(report);
    }

    if interrupted.load(std::sync::atomic::Ordering::SeqCst) {
        anyhow::bail!("interrupted");
    }
    if let Some(error) = warm_memory_error
        && result.is_ok()
    {
        anyhow::bail!("warm memory measurement failed: {error}");
    }
    result
}

/// Everything one finished launch knows about itself that a sample records.
struct LaunchSampleInputs<'a> {
    backend: &'a str,
    start_config: &'a VmStartConfig,
    launch_mode: crate::commands::vm::phase_timing::LaunchMode,
    /// Root filesystem strategy selected by the run-path tier gate.
    root_strategy: mvm_build::run_image::RootStrategy,
    /// Whether a mount image was materialized on this launch.
    mount_materialized: bool,
    phases: crate::commands::vm::phase_timing::RunPhaseTimings,
    sub_phases: crate::commands::vm::launch_sample::LaunchSubTimings,
    /// Whole-VMM memory evidence surrounding the first warm command.
    warm_first_command_memory: Option<crate::commands::vm::launch_sample::WarmFirstCommandMemory>,
    /// Phases the backend recorded inside `start`, read from its sidecar
    /// before teardown removed the state directory holding it.
    backend_phases: Vec<mvm_core::launch_trace::TracePhase>,
    /// Capabilities the backend reported coming up without.
    degraded: Vec<String>,
}

/// Assemble the machine-readable sample for a finished launch.
///
/// Artifact **paths** go in, not digests: hashing them here would charge the
/// measured launch for work a consumer can do once, afterwards.
fn build_launch_sample(
    inputs: LaunchSampleInputs<'_>,
) -> crate::commands::vm::launch_sample::LaunchSample {
    use crate::commands::vm::launch_sample as sample;

    let config = inputs.start_config;
    sample::LaunchSample {
        schema_version: sample::LAUNCH_SAMPLE_SCHEMA_VERSION,
        build_profile: sample::BuildProfile::current(),
        mvm_version: env!("CARGO_PKG_VERSION").to_string(),
        backend: inputs.backend.to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        launch_mode: inputs.launch_mode,
        root_strategy: Some(inputs.root_strategy.into()),
        sizing: sample::GuestSizing {
            cpus: config.cpus,
            memory_mib: config.memory_mib,
            mem_initial_mib: config.mem_initial_mib,
        },
        artifacts: sample::ArtifactPaths {
            kernel: config.kernel_path.clone(),
            initramfs: config.initrd_path.clone(),
            runtime_overlay: config.runtime_overlay_path.clone(),
            rootfs: Some(config.rootfs_path.clone()),
        },
        work: sample::recorded_work(
            inputs.mount_materialized,
            inputs.launch_mode == crate::commands::vm::phase_timing::LaunchMode::Warm,
        ),
        phases: inputs.phases,
        sub_phases: inputs.sub_phases,
        warm_first_command_memory: inputs.warm_first_command_memory,
        backend_phases: inputs.backend_phases,
        degraded: inputs.degraded,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WarmMemoryMeasurementStart {
    pid: u32,
    ready: crate::commands::vm::launch_sample::ProcessMemorySnapshot,
}

fn begin_warm_memory_measurement(
    backend: &AnyBackend,
    vm_name: &str,
) -> Result<WarmMemoryMeasurementStart> {
    let id = VmId(vm_name.to_string());
    let pid = backend.host_process_id(&id)?.with_context(|| {
        format!(
            "{} did not expose a host process for {vm_name}",
            backend.name()
        )
    })?;
    let ready = crate::bench::harness::read_process_memory_snapshot(pid)
        .with_context(|| format!("sampling warm-ready host process {pid}"))?;
    Ok(WarmMemoryMeasurementStart { pid, ready })
}

fn finish_warm_memory_measurement(
    backend: &AnyBackend,
    vm_name: &str,
    start: WarmMemoryMeasurementStart,
) -> Result<crate::commands::vm::launch_sample::WarmFirstCommandMemory> {
    use crate::commands::vm::launch_sample::{ProcessMemoryDelta, WarmFirstCommandMemory};

    let id = VmId(vm_name.to_string());
    let observed_pid = backend.host_process_id(&id)?.with_context(|| {
        format!(
            "{} no longer exposes a host process for {vm_name}",
            backend.name()
        )
    })?;
    if observed_pid != start.pid {
        anyhow::bail!(
            "host process changed from {} to {observed_pid} during the first command",
            start.pid
        );
    }
    let after_first_command = crate::bench::harness::read_process_memory_snapshot(start.pid)
        .with_context(|| format!("sampling host process {} after first command", start.pid))?;
    Ok(WarmFirstCommandMemory {
        pid: start.pid,
        ready: start.ready,
        after_first_command,
        delta: ProcessMemoryDelta::between(start.ready, after_first_command),
    })
}

/// Kernel/rootfs/initrd + provenance resolved from `req.image`: either a
/// named template lookup (which also probes for a snapshot) or a pre-built
/// kernel/rootfs pair carried through as-is.
struct ResolvedImage {
    vmlinux: String,
    initrd: Option<String>,
    rootfs: String,
    revision: String,
    flake_ref: String,
    profile: Option<String>,
    snap_info: Option<mvm_core::template::SnapshotInfo>,
    template_id: Option<String>,
}

/// Resolve image artifacts: either a named template or a pre-built pair. For
/// templates, also probe for a pre-built snapshot so the caller can skip the
/// cold-boot cost when the request turns out to be snapshot-eligible.
fn resolve_image_artifacts(image: &ImageSource) -> Result<ResolvedImage> {
    match image {
        ImageSource::Template(name) => {
            let (spec, vmlinux, initrd, rootfs, rev) =
                mvm_runtime::vm::template::lifecycle::template_artifacts_for_boot(name)
                    .with_context(|| format!("Loading template '{name}'"))?;
            let snap_info =
                mvm_runtime::vm::template::lifecycle::template_snapshot_info_dispatched(name)
                    .ok()
                    .flatten();
            Ok(ResolvedImage {
                vmlinux,
                initrd,
                rootfs,
                revision: rev,
                flake_ref: spec.flake_ref.clone(),
                profile: Some(spec.profile.clone()),
                snap_info,
                template_id: Some(name.clone()),
            })
        }
        ImageSource::PinnedTemplate {
            slot_hash,
            revision_hash,
        } => {
            let (spec, vmlinux, initrd, rootfs, rev) =
                mvm_runtime::vm::template::lifecycle::template_artifacts_for_slot_revision(
                    slot_hash,
                    revision_hash,
                )
                .with_context(|| {
                    format!("Loading stored template revision {slot_hash}@{revision_hash}")
                })?;
            Ok(ResolvedImage {
                vmlinux,
                initrd,
                rootfs,
                revision: rev,
                flake_ref: spec.flake_ref,
                profile: Some(spec.profile),
                snap_info: None,
                template_id: Some(slot_hash.clone()),
            })
        }
        ImageSource::Prebuilt {
            kernel_path,
            rootfs_path,
            initrd_path,
            label,
            ..
        } => Ok(ResolvedImage {
            vmlinux: kernel_path.clone(),
            initrd: initrd_path.clone(),
            rootfs: rootfs_path.clone(),
            revision: String::new(),
            flake_ref: label.clone(),
            profile: None,
            snap_info: None,
            template_id: None,
        }),
        ImageSource::WasmModule { module_path, label } => Ok(ResolvedImage {
            vmlinux: String::new(),
            initrd: None,
            rootfs: module_path.clone(),
            revision: String::new(),
            flake_ref: label.clone(),
            profile: None,
            snap_info: None,
            template_id: None,
        }),
    }
}

/// The run-path tier gate's outputs for one boot: whether the request is
/// still snapshot-restore eligible, the dm-verity sidecar (if any), the
/// resolved rootfs strategy + runtime source policy, and the effective
/// initrd.
struct BootStrategy {
    use_snapshot: bool,
    verity_path: Option<String>,
    roothash: Option<String>,
    root_strategy: mvm_build::run_image::RootStrategy,
    effective_initrd: Option<String>,
}

/// Resolve the boot strategy for `resolved`: snapshot eligibility, the
/// dm-verity sidecar probe, the virtiofs-root tier gate, the runtime source
/// policy, and the effective initrd. All of these fall out of the resolved
/// image + `req` + the backend's capabilities.
fn resolve_boot_strategy(
    shape: &LaunchShape<'_>,
    backend: &AnyBackend,
    resolved: &ResolvedImage,
    sub: &mut crate::commands::vm::phase_timing::LaunchSubMarks,
) -> Result<BootStrategy> {
    use crate::commands::vm::phase_timing::SubPhase;

    // Snapshot path is taken when the request is eligible; otherwise cold boot.
    let use_snapshot = snapshot_eligible(
        shape.image,
        shape.dir_shares,
        resolved.snap_info.is_some(),
        backend.capabilities().snapshot_capability,
    ) && shape.disk_volumes.is_empty();

    // Probe for the verity sidecar alongside the rootfs: production microVMs
    // ship `rootfs.verity` + `rootfs.roothash` next to `rootfs.ext4`. Their
    // absence is the dev-VM exemption. This is host-local and side-effect-free;
    // foreground OCI launches must never boot the builder/dev VM just to probe.
    // Wasm modules have no block rootfs, so there is no sidecar to probe.
    sub.start(SubPhase::ArtifactVerify);
    let (verity_path, roothash) = if backend.name() == "wasm" {
        (None, None)
    } else {
        mvm_runtime::microvm::probe_verity_sidecar(&resolved.rootfs)
    };
    sub.finish(SubPhase::ArtifactVerify);

    // Every root is a materialized block ext4 image. The dev-tier virtiofs root
    // could not be dm-verity sealed and exposed a host directory through a FUSE
    // parser merely to avoid materialization, so it is not a valid boot mode.
    let root_strategy = mvm_build::run_image::RootStrategy::BlockExt4;
    let effective_initrd = effective_transient_initrd(
        shape.image,
        resolved.initrd.as_deref(),
        &resolved.rootfs,
        root_strategy,
    )?;

    Ok(BootStrategy {
        use_snapshot,
        verity_path,
        roothash,
        root_strategy,
        effective_initrd,
    })
}

/// Turn each `--mount` into a volume, materializing the granted directory into
/// an ext4 image first.
fn mount_volumes(
    shape: &LaunchShape<'_>,
    vm_name: &str,
    sub: &mut crate::commands::vm::phase_timing::LaunchSubMarks,
) -> Result<Vec<VmVolume>> {
    if shape.dir_shares.is_empty() {
        return Ok(Vec::new());
    }
    // Named because it is the one cost this change adds, and it scales with
    // the mounted tree: ~100ms for a 30MB one. An unnamed span here would be
    // the same hole `attach_initramfs` sat in — a launch able to say how long
    // it took and not where.
    sub.start(crate::commands::vm::phase_timing::SubPhase::MountMaterialize);
    let volumes = mounts::materialize_mount_volumes(shape.dir_shares, vm_name);
    sub.finish(crate::commands::vm::phase_timing::SubPhase::MountMaterialize);
    volumes
}

/// Build the `VmStartConfig` for the transient boot from the resolved image +
/// boot-strategy state. Admission (tenant/plan binding) and the runtime
/// overlay attach happen in the caller, after this returns — this only
/// assembles the struct.
/// Refuse a catalogued runtime whose declared libc is not what its image
/// turned out to record.
///
/// Two independent facts about the same guest: the catalog *declares* a libc
/// for the image reference it pins, and the unpacker *observes* one in the tree
/// that reference resolved to. They agree until the upstream tag moves — a
/// `:alpine` image rebuilt on a glibc base, say — at which point the
/// declaration is silently wrong about every guest booted from it.
///
/// Selection uses the observed value, so a disagreement is not itself a boot
/// hazard; it is a catalog entry that has drifted from reality, and it is
/// invisible from anywhere else. Refusing is the only way anyone finds out.
///
/// `Unknown` on either side is not a disagreement: an image the host has no
/// declaration for is the ordinary `--image` case, and an image that recorded
/// no libc is refused later, by the resolver, with a message about what to do.
fn refuse_declared_libc_disagreement(
    declared: mvm_contract::guest_libc::GuestLibc,
    recorded: mvm_contract::guest_libc::GuestLibc,
) -> Result<()> {
    use mvm_contract::guest_libc::GuestLibc;
    if declared == GuestLibc::Unknown || recorded == GuestLibc::Unknown || declared == recorded {
        return Ok(());
    }
    anyhow::bail!(
        "refusing to launch: the runtime catalog declares this image is {declared}, but the \
         materialized rootfs records {recorded}. The catalog entry has drifted from the image \
         it pins — most likely the upstream tag was rebuilt on a different base. Report it; \
         naming the image directly with --image bypasses the declaration."
    )
}

fn build_start_config(
    shape: &LaunchShape<'_>,
    vm_name: &str,
    resolved: &ResolvedImage,
    boot: &BootStrategy,
    sdk_sidecar: Option<&crate::commands::vm::up::SdkSidecarAttachment>,
    sub: &mut crate::commands::vm::phase_timing::LaunchSubMarks,
) -> Result<VmStartConfig> {
    // Pre-open console data sockets for interactive PTY runs against
    // non-sealed images. OCI/dev images can carry verity sidecars and still be
    // interactive, so the sidecar's sealed bit is the load-bearing signal here.
    let is_wasm = shape.hypervisor == Some("wasm");
    let image_sealed = if is_wasm {
        false
    } else {
        crate::commands::vm::image_is_sealed(std::path::Path::new(&resolved.rootfs))
    };
    let dev_console = if is_wasm {
        false
    } else {
        transient_run_dev_console(shape.pty, image_sealed)
    };

    Ok(VmStartConfig {
        name: vm_name.to_string(),
        template_id: resolved.template_id.clone(),
        rootfs_path: resolved.rootfs.clone(),
        kernel_path: if is_wasm {
            None
        } else {
            Some(resolved.vmlinux.clone())
        },
        initrd_path: if is_wasm {
            None
        } else {
            boot.effective_initrd.clone()
        },
        verity_path: if is_wasm {
            None
        } else {
            boot.verity_path.clone()
        },
        roothash: if is_wasm { None } else { boot.roothash.clone() },
        dev_console,
        revision_hash: resolved.revision.clone(),
        flake_ref: resolved.flake_ref.clone(),
        profile: resolved.profile.clone(),
        cpus: shape.cpus,
        memory_mib: shape.memory_mib,
        mem_initial_mib: shape.mem_initial_mib,
        ports: Vec::new(),
        // Live shares precede the SDK sidecar so their tags and admission
        // records remain stable across sidecar changes.
        volumes: mount_volumes(shape, vm_name, sub)?
            .into_iter()
            .chain(shape.disk_volumes.iter().cloned())
            .chain(sdk_sidecar.iter().map(|a| a.volume.clone()))
            .collect(),
        config_files: Vec::new(),
        secret_files: Vec::new(),
        runner_dir: None,
        network_policy: shape.network_policy.clone(),
        warm_pool_size: shape.warm_pool_size,
        ..Default::default()
    })
}

/// Host-monotonic marks the launch resolution crosses, handed back so the run
/// path can render its phase breakdown. `new(false)` records nothing and costs
/// nothing — the shape `pool warm` uses, since it emits no breakdown.
#[derive(Debug, Default, Clone, Copy)]
pub struct LaunchResolveMarks {
    enabled: bool,
    /// After the image artifacts (kernel/rootfs/initrd) are resolved.
    pub image_resolved: Option<std::time::Instant>,
    /// After the boot strategy — verity probe, tier gate, effective initrd.
    pub drives_ready: Option<std::time::Instant>,
    /// After admission and the runtime-overlay/initramfs attach.
    pub admitted: Option<std::time::Instant>,
}

impl LaunchResolveMarks {
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            ..Self::default()
        }
    }

    fn now(&self) -> Option<std::time::Instant> {
        self.enabled.then(std::time::Instant::now)
    }
}

/// One launch's boot shape, resolved without starting a VM.
///
/// This is the whole of what a launch knows about itself before
/// [`boot_transient_vm`] runs: the backend it resolved against, a
/// [`VmStartConfig`] carrying the rootfs and its verity sidecars, the runtime
/// overlay and universal initramfs, the cmdline-bearing policy fields, and —
/// when the caller supplied an admission hook — the tenant and signed plan.
///
/// Producing one without booting is what lets the warm pool spawn a parent that
/// mirrors a real launch: `pool warm` resolves this, hands it to
/// `warm_to_target`, and the spawn derives the parent's boot shape and the
/// pool's compat key from the same value the launch will later be matched on.
pub struct ResolvedLaunch {
    /// The backend the launch resolved against. Selected here rather than by
    /// the caller so a warm spawn and the run it serves cannot disagree about
    /// which backend's capabilities shaped the config.
    pub backend: AnyBackend,
    pub start_config: VmStartConfig,
    /// Whether snapshot restore survives admission (an admitted workload
    /// always cold-boots).
    pub use_snapshot: bool,
    /// Rootfs strategy the run-path tier gate selected — the value the run path
    /// records as `plan.boot_posture`.
    pub root_strategy: mvm_build::run_image::RootStrategy,
    /// Resolved image artifacts, kept for the snapshot-restore leg of the boot.
    image: ResolvedImage,
}

/// Resolve a launch's bootable [`VmStartConfig`] **without starting a VM**.
///
/// Composes the four steps that used to exist only inline in [`run_inner`]:
/// image-artifact resolution, the boot-strategy tier gate, the start-config
/// assembly, and the admission + runtime-overlay/initramfs attach. Anything
/// that wants a launch's boot shape calls this; resolving it a second way is
/// how a warm parent comes to boot a shape no claim can match.
///
/// `admit` binds the run to a signed [`mvm_core::plan::ExecutionPlan`] and is
/// what makes the config claim-eligible. A warm spawn passes `None`: a factory
/// parent carries no workload authority, and the spawn drops the tenant and
/// plan from the config it is handed anyway.
pub fn resolve_launch(
    shape: &LaunchShape<'_>,
    admit: Option<&SessionAdmit<'_>>,
    marks: &mut LaunchResolveMarks,
    sub: &mut crate::commands::vm::phase_timing::LaunchSubMarks,
) -> Result<ResolvedLaunch> {
    use crate::commands::vm::phase_timing::SubPhase;

    let backend = select_exec_backend(
        shape_uses_vsock_proxy_backend(shape),
        shape.network_policy,
        shape.hypervisor,
    )?;

    // Resolve image artifacts: either a named template or a pre-built pair.
    // For templates, also probe for a pre-built snapshot so we can skip the
    // cold-boot cost when the request is snapshot-eligible.
    let image = resolve_image_artifacts(shape.image)?;
    marks.image_resolved = marks.now();

    // A transient run owns only its state directory. Host directories are
    // attached as live virtio-fs shares; no host tree is copied or staged.
    let vm_name = shape
        .name
        .map(str::to_string)
        .unwrap_or_else(transient_vm_name);

    // Snapshot eligibility, the dm-verity sidecar probe, the virtiofs-root
    // tier gate, and the effective initrd all fall out of the resolved image
    // + backend capabilities; see `resolve_boot_strategy`.
    let boot = resolve_boot_strategy(shape, &backend, &image, sub)?;
    marks.drives_ready = marks.now();

    // Template-restore VMs run without plan admission. Leave tenant_id /
    // plan_json / bundle_json at their None defaults (via
    // `..Default::default()`) so the libkrun/HVF backends take the legacy
    // `run_supervisor` dispatch. Routing template restores through
    // admission would add an `admit_for_run` call here and a
    // `populate_audit_substrate` invocation after the struct literal.
    // `admit_ms` is a window, not a call: it spans config assembly, admission,
    // and the two artifact attachments. Admission instruments itself, and its
    // spans account for roughly half the window, so the rest needs naming
    // before any of it can be acted on.
    // The SDK sidecar is chosen here, and only here, because this is the first
    // point at which the guest exists. There is one artifact per guest libc and
    // a musl process cannot `dlopen` the glibc one; the libc was observed when
    // the rootfs was unpacked and recorded beside it, which is the only thing
    // the host can still read once the tree is an ext4 blob.
    //
    // Selecting from the *recorded* value rather than a catalogued runtime's
    // declaration is what makes an arbitrary `--image` work: nothing declares a
    // libc for an image a user names themselves, and that is the case the
    // catalog is a convenience over.
    //
    // Not asked on a tier that attaches no ELF sidecar. Wasm has no dynamic
    // loader and never will, so "which libc" is the wrong question there: a
    // wasm workload binding an SDK host service is refused by the
    // backend-compatibility gate, which can say why.
    let sdk_sidecar = if backend.kind() == mvm_core::vm_backend::BackendKind::Wasm {
        None
    } else {
        let recorded =
            mvm_build::guest_libc::recorded_image_libc(std::path::Path::new(&image.rootfs));
        refuse_declared_libc_disagreement(shape.declared_libc, recorded)?;
        crate::commands::vm::up::resolve_sdk_sidecar_attachment_for_host(
            shape.sdk_host_services,
            recorded,
        )?
    };

    let t_build = std::time::Instant::now();
    let mut start_config =
        build_start_config(shape, &vm_name, &image, &boot, sdk_sidecar.as_ref(), sub)?;
    tracing::debug!(
        ms = t_build.elapsed().as_secs_f64() * 1000.0,
        "admit window: build_start_config"
    );
    let mut use_snapshot = boot.use_snapshot;

    // Admit the transient run as a locally-signed workload. Setting
    // tenant_id + plan_json makes the runner-backed microVM supervisor enforce
    // `network_policy` and chain-audit the run. Force cold boot when admitted —
    // snapshot restore is unavailable for workload admission.
    let t_admission = std::time::Instant::now();
    sub.start(SubPhase::AdmitPlan);
    if let Some(admit_fn) = admit
        && let Some(sub) = admit_fn(AdmitInputs {
            rootfs: std::path::Path::new(&image.rootfs),
            kernel: start_config
                .kernel_path
                .as_deref()
                .map(std::path::Path::new),
            vm_name: &vm_name,
            sdk_sidecar: sdk_sidecar.as_ref(),
        })?
    {
        start_config.tenant_id = Some(sub.tenant_id);
        start_config.plan_json = Some(sub.plan_json);
        start_config.bundle_json = sub.bundle_json;
        start_config.config_files.extend(sub.config_files);
        use_snapshot = false;

        refuse_unloadable_sidecar(
            &image.rootfs,
            &start_config.volumes,
            start_config.plan_json.as_deref(),
        )?;
    }
    sub.finish(SubPhase::AdmitPlan);
    tracing::debug!(
        ms = t_admission.elapsed().as_secs_f64() * 1000.0,
        "admit window: admission"
    );

    // Clamp the vCPU request to what this backend can actually create, and say
    // so. Before the backend is chosen there is nothing to clamp against, and
    // after the launch it is too late to tell anyone.
    //
    // Not an error. `--cpus 4` is a portable command meeting a host limit, and
    // refusing it would make the same script succeed on Linux and fail on
    // macOS for a reason the user cannot act on — worse, HVF's default is 2, so
    // a hard refusal at a ceiling of 1 failed *every* launch on that backend.
    // Silence is the other failure: a guest on one CPU while its admitted plan
    // says four, with nothing to explain the performance.
    if let Some(granted) =
        mvm_core::vm_backend::clamp_vcpus(start_config.cpus, backend.capabilities().max_vcpus)
    {
        ui::warn(&format!(
            "{} supports at most {granted} vCPU(s); {} requested, booting with {granted}",
            backend.name(),
            start_config.cpus,
        ));
        tracing::info!(
            backend = backend.name(),
            requested = start_config.cpus,
            granted,
            "vcpu request clamped to the backend ceiling"
        );
        start_config.cpus = granted;
    }

    let t_overlay = std::time::Instant::now();
    sub.start(SubPhase::AttachOverlay);
    crate::commands::vm::up::attach_runtime_overlay_if_cached(&mut start_config, backend.name())?;
    sub.finish(SubPhase::AttachOverlay);
    tracing::debug!(
        ms = t_overlay.elapsed().as_secs_f64() * 1000.0,
        "admit window: attach runtime overlay"
    );

    let t_initramfs = std::time::Instant::now();
    sub.start(SubPhase::AttachInitramfs);
    crate::commands::vm::up::attach_universal_initramfs_if_cached(&mut start_config)?;
    sub.finish(SubPhase::AttachInitramfs);
    tracing::debug!(
        ms = t_initramfs.elapsed().as_secs_f64() * 1000.0,
        "admit window: attach universal initramfs"
    );

    let t_status = std::time::Instant::now();
    crate::commands::vm::up::emit_runtime_source_status(&start_config);
    tracing::debug!(
        ms = t_status.elapsed().as_secs_f64() * 1000.0,
        "admit window: runtime source status"
    );
    marks.admitted = marks.now();

    Ok(ResolvedLaunch {
        backend,
        start_config,
        use_snapshot,
        root_strategy: boot.root_strategy,
        image,
    })
}

#[cfg(test)]
mod tests {

    use super::*;

    use mvm_core::util::test_env::TestEnv;

    fn baked_entrypoint_request() -> ExecRequest {
        ExecRequest {
            name: None,
            warm_pool_size: 0,
            image: ImageSource::Template("flake-slot".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            dir_shares: Vec::new(),
            disk_volumes: Vec::new(),
            env: Vec::new(),
            target: ExecTarget::Inline { argv: Vec::new() },
            timeout_secs: Some(120),
            pty: false,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
            sdk_host_services: Vec::new(),
            declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
        }
    }

    #[test]
    fn an_empty_inline_target_waits_for_the_images_baked_entrypoint() {
        assert!(boots_baked_entrypoint(&baked_entrypoint_request()));

        let mut request = baked_entrypoint_request();
        request.target = ExecTarget::Inline {
            argv: vec!["/bin/true".into()],
        };
        assert!(!boots_baked_entrypoint(&request));
    }

    #[test]
    fn a_baked_entrypoint_preserves_its_reported_nonzero_exit_code() {
        let status = mvm_core::vm_backend::VmExitStatus {
            code: Some(7),
            success: false,
        };
        let result = baked_entrypoint_result(status, false, "vm-flake")
            .expect("reported exit code must be returned");
        assert_eq!(result.left(), Some(7));
    }

    #[test]
    fn a_baked_entrypoint_without_an_exit_report_fails_closed() {
        let result = baked_entrypoint_result(
            mvm_core::vm_backend::VmExitStatus::UNKNOWN,
            false,
            "vm-flake",
        );
        let error = match result {
            Ok(_) => panic!("missing exit report must not become success"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("without reporting its exit code")
        );
    }

    #[test]
    fn build_healthcheck_wraps_shell_command() {
        let hc = build_healthcheck(Some("curl -fsS localhost/health"), 10, 5, 3, 0)
            .expect("Some when a command is given");
        assert_eq!(
            hc.command,
            vec!["/bin/sh", "-lc", "curl -fsS localhost/health"]
        );
        assert_eq!(hc.interval_secs, 10);
        assert_eq!(build_healthcheck(None, 30, 5, 3, 0), None);
    }

    #[test]
    fn resolve_launch_wasm_module_skips_kernel_initrd_and_verity() {
        let module_path = "/tmp/dummy.wasm";
        let image = ImageSource::WasmModule {
            module_path: module_path.to_string(),
            label: "wasm:test".to_string(),
        };
        let shape = LaunchShape {
            name: Some("wasm-test"),
            image: &image,
            cpus: 1,
            memory_mib: 64,
            mem_initial_mib: None,
            dir_shares: &[],
            disk_volumes: &[],
            pty: false,
            network_policy: &mvm_core::network_policy::NetworkPolicy::deny_all(),
            warm_pool_size: 0,
            sdk_host_services: &[],
            declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
            hypervisor: Some("wasm"),
        };
        let mut marks = LaunchResolveMarks::new(false);
        let mut sub = crate::commands::vm::phase_timing::LaunchSubMarks::default();
        let resolved =
            resolve_launch(&shape, None, &mut marks, &mut sub).expect("wasm launch should resolve");
        assert_eq!(resolved.start_config.rootfs_path, module_path);
        assert!(
            resolved.start_config.kernel_path.is_none(),
            "wasm has no kernel"
        );
        assert!(
            resolved.start_config.initrd_path.is_none(),
            "wasm has no initrd"
        );
        assert!(
            resolved.start_config.verity_path.is_none(),
            "wasm has no verity"
        );
        assert!(
            resolved.start_config.roothash.is_none(),
            "wasm has no roothash"
        );
        assert_eq!(resolved.backend.name(), "wasm");
    }

    #[test]
    fn select_exec_backend_requested_flag_selects_backend() {
        let deny_all = mvm_core::network_policy::NetworkPolicy::deny_all();
        let backend = select_exec_backend(false, &deny_all, Some("libkrun"))
            .expect("libkrun resolves without probing availability (image not requested)");
        assert_eq!(backend.name(), "libkrun");

        let backend = select_exec_backend(false, &deny_all, Some("hvf"))
            .expect("hvf resolves without probing availability (image not requested)");
        assert_eq!(backend.name(), "hvf");
    }

    #[test]
    fn select_exec_backend_none_with_no_env_falls_to_auto_detect() {
        let mut env = TestEnv::new();
        env.remove("MVM_HYPERVISOR");
        env.remove("MVM_BACKEND");
        let deny_all = mvm_core::network_policy::NetworkPolicy::deny_all();
        let backend =
            select_exec_backend(false, &deny_all, None).expect("auto-detect always resolves");
        assert_eq!(backend.name(), AnyBackend::auto_select().name());
    }

    /// The CLI `--hypervisor` flag (the `requested` param) wins over a
    /// conflicting `MVM_HYPERVISOR` env override — the admit/build/boot call
    /// sites must all resolve to the same backend as what was requested.
    #[test]
    fn select_exec_backend_requested_flag_beats_conflicting_env() {
        let mut env = TestEnv::new();
        env.remove("MVM_BACKEND");
        env.set("MVM_HYPERVISOR", "qemu");
        let deny_all = mvm_core::network_policy::NetworkPolicy::deny_all();
        let backend = select_exec_backend(false, &deny_all, Some("libkrun"))
            .expect("libkrun resolves without probing availability (image not requested)");
        assert_eq!(
            backend.name(),
            "libkrun",
            "the requested flag must win over MVM_HYPERVISOR=qemu"
        );
    }

    #[test]
    fn validate_backend_for_egress_refuses_unavailable_hvf_before_boot_work() {
        let _guard = mvm_runtime::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let policy = mvm_core::network_policy::NetworkPolicy::allow_list(vec![
            mvm_core::network_policy::HostPort::new("example.com", 443),
        ]);
        env.set("MVM_HVF_SUPERVISOR_PATH", "/no/such/mvm-hvf-supervisor");
        let err = validate_backend_for_egress(
            "hvf",
            true,
            &policy,
            "OCI --image runs with outbound egress enabled",
        )
        .expect_err("unavailable hvf must fail closed before OCI work");
        // SAFETY: test-only env mutation.
        unsafe {
            std::env::remove_var("MVM_HVF_SUPERVISOR_PATH");
        }
        // HVF always advertises the NIC-less host-vsock-proxy egress caps (they
        // are unconditional — the fail-closed posture), so the capability
        // shortfall is empty and the refusal comes from the availability probe:
        // a host whose supervisor can't launch is unavailable, not egress-capable.
        let msg = err.to_string();
        assert!(msg.contains("NIC-less host-vsock-proxy backend"));
        assert!(msg.contains("backend hvf is unavailable on this host"));
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn select_backend_name_for_egress_picks_hvf_when_proxy_support_is_available() {
        let _guard = mvm_runtime::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().expect("tempdir");
        let supervisor = dir.path().join("mvm-hvf-supervisor");
        std::fs::write(&supervisor, b"stub").expect("stub supervisor");
        let policy = mvm_core::network_policy::NetworkPolicy::allow_list(vec![
            mvm_core::network_policy::HostPort::new("example.com", 443),
        ]);

        env.set("MVM_HVF_SUPERVISOR_PATH", &supervisor);
        let selected = select_backend_name_for_egress(
            None,
            true,
            &policy,
            "OCI --image runs with outbound egress enabled",
        )
        .expect("hvf should satisfy the proxy backend requirement");

        assert_eq!(selected, "hvf");
    }

    /// A launch shape resolved from an `ExecRequest` must carry every field the
    /// resolution reads. If one is dropped here, a `pool warm` that builds its
    /// shape by hand and a run that builds one from its request resolve
    /// different configs — and the pool fills with parents no claim matches,
    /// with no error anywhere.
    #[test]
    fn launch_shape_borrows_every_field_the_resolution_reads() {
        let share = crate::commands::DirShareSpec {
            host_dir: "/host/data".into(),
            guest_mount: "/data".into(),
            read_only: true,
        };
        let req = ExecRequest {
            name: Some("named-vm".into()),
            warm_pool_size: 3,
            image: ImageSource::Template("t".into()),
            cpus: 4,
            memory_mib: 2048,
            mem_initial_mib: Some(512),
            dir_shares: vec![share.clone()],
            disk_volumes: vec![VmVolume {
                host: "/host/data.ext4".into(),
                guest: "/work/data".into(),
                size: "64M".into(),
                read_only: true,
                kind: mvm_core::vm_backend::VmVolumeKind::Disk,
                ..Default::default()
            }],
            env: vec![("K".into(), "V".into())],
            target: ExecTarget::Inline { argv: vec![] },
            timeout_secs: Some(30),
            pty: true,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            stdin: b"ignored".to_vec(),
            healthcheck: None,
            hypervisor: Some("mock".into()),
            sdk_host_services: Vec::new(),
            declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
        };

        let shape = req.launch_shape();

        assert_eq!(shape.name, Some("named-vm"));
        assert!(matches!(shape.image, ImageSource::Template(n) if n == "t"));
        assert_eq!(shape.cpus, 4);
        assert_eq!(shape.memory_mib, 2048);
        assert_eq!(shape.mem_initial_mib, Some(512));
        assert_eq!(shape.dir_shares.len(), 1);
        assert_eq!(shape.dir_shares[0].guest_mount, share.guest_mount);
        assert_eq!(shape.disk_volumes.len(), 1);
        assert_eq!(shape.disk_volumes[0].guest, "/work/data");
        assert!(shape.pty);
        assert_eq!(shape.warm_pool_size, 3);
        assert_eq!(shape.hypervisor, Some("mock"));
        assert!(shape.sdk_host_services.is_empty());
        assert_eq!(*shape.network_policy, req.network_policy);
    }

    /// The whole point of the extraction: a bootable config, verity sidecars
    /// included, obtained without starting a VM. `pool warm` depends on this —
    /// a pre-warm that had to boot to learn its own boot shape would be no
    /// The catalog declares a libc and the unpacker observes one. While they
    /// agree there is nothing to say; the check exists for the day the
    /// upstream tag is rebuilt on a different base and the declaration becomes
    /// quietly wrong about every guest booted from it.
    #[test]
    fn a_declaration_matching_what_the_image_records_is_not_a_disagreement() {
        use mvm_contract::guest_libc::GuestLibc;
        for libc in [GuestLibc::Glibc, GuestLibc::Musl] {
            assert!(refuse_declared_libc_disagreement(libc, libc).is_ok());
        }
    }

    #[test]
    fn a_declaration_the_image_contradicts_refuses_and_names_both() {
        use mvm_contract::guest_libc::GuestLibc;
        let err = refuse_declared_libc_disagreement(GuestLibc::Musl, GuestLibc::Glibc)
            .expect_err("a drifted catalog entry must not boot silently");
        let msg = err.to_string();
        assert!(msg.contains("musl"), "must name the declaration: {msg}");
        assert!(msg.contains("glibc"), "must name what was recorded: {msg}");
    }

    /// `Unknown` on either side is not a disagreement. An image the host has no
    /// declaration for is the ordinary `--image` case — the one this whole
    /// selection exists to serve — and an image that recorded no libc is
    /// refused later by the resolver, with a message about what to do next.
    /// Treating either as a conflict here would refuse both instead.
    #[test]
    fn an_unknown_on_either_side_is_not_a_disagreement() {
        use mvm_contract::guest_libc::GuestLibc;
        assert!(refuse_declared_libc_disagreement(GuestLibc::Unknown, GuestLibc::Musl).is_ok());
        assert!(refuse_declared_libc_disagreement(GuestLibc::Musl, GuestLibc::Unknown).is_ok());
        assert!(refuse_declared_libc_disagreement(GuestLibc::Unknown, GuestLibc::Unknown).is_ok());
    }

    /// pre-warm at all.
    #[cfg(feature = "test-support")]
    #[test]
    fn resolve_launch_yields_a_bootable_config_without_starting_a_vm() {
        let _guard = mvm_runtime::vm::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let kernel = tmp.path().join("vmlinux");
        std::fs::write(&kernel, b"kernel").unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        // A production rootfs ships its dm-verity sidecar pair beside it; the
        // resolution must pick both up, since a parent booting without them
        // boots a different shape than the launch it is meant to serve. The
        // probe requires a full 64-hex roothash, so a short stand-in reads as
        // "no sidecar" and would make this assert nothing.
        const ROOTHASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";
        std::fs::write(tmp.path().join("rootfs.verity"), b"verity").unwrap();
        std::fs::write(tmp.path().join("rootfs.roothash"), format!("{ROOTHASH}\n")).unwrap();

        let image = ImageSource::Prebuilt {
            kernel_path: kernel.display().to_string(),
            rootfs_path: rootfs.display().to_string(),
            initrd_path: None,
            label: "fixture".into(),
            unpacked_oci_root: None,
        };
        let policy = mvm_core::network_policy::NetworkPolicy::deny_all();
        let shape = LaunchShape {
            name: None,
            image: &image,
            cpus: 2,
            memory_mib: 1024,
            mem_initial_mib: None,
            dir_shares: &[],
            disk_volumes: &[],
            pty: false,
            network_policy: &policy,
            warm_pool_size: 1,
            sdk_host_services: Vec::new(),
            declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
            hypervisor: Some("mock"),
        };

        let resolved = resolve_launch(
            &shape,
            None,
            &mut LaunchResolveMarks::new(false),
            &mut crate::commands::vm::phase_timing::LaunchSubMarks::new(false),
        )
        .expect("a prebuilt image resolves without a VM");

        assert_eq!(
            resolved.start_config.rootfs_path,
            rootfs.display().to_string()
        );
        assert_eq!(
            resolved.start_config.kernel_path.as_deref(),
            Some(kernel.display().to_string().as_str())
        );
        assert!(
            resolved.start_config.verity_path.is_some(),
            "the verity sidecar beside the rootfs must reach the config"
        );
        assert_eq!(resolved.start_config.roothash.as_deref(), Some(ROOTHASH));
        assert_eq!(resolved.start_config.cpus, 2);
        assert_eq!(resolved.start_config.memory_mib, 1024);
        assert!(
            !resolved.start_config.name.is_empty(),
            "an unnamed launch generates a throwaway name"
        );
        // No admission hook, so no workload authority is bound.
        assert!(resolved.start_config.tenant_id.is_none());
        assert!(resolved.start_config.plan_json.is_none());
        // And nothing booted: starting a VM creates its state directory, so
        // resolving one must leave none behind.
        assert!(
            !mvm_core::config::vm_state_dir(&resolved.start_config.name).exists(),
            "resolving a launch must not start a VM"
        );
    }

    /// Timing marks are opt-in. `pool warm` resolves with them off and must pay
    /// nothing for a breakdown it never renders.
    #[test]
    fn launch_resolve_marks_record_nothing_when_disabled() {
        let marks = LaunchResolveMarks::new(false);
        assert!(marks.now().is_none());
        assert!(LaunchResolveMarks::new(true).now().is_some());
    }

    #[test]
    fn shell_quote_basic() {
        assert_eq!(shell_quote("hello"), "'hello'");
        assert_eq!(shell_quote("hello world"), "'hello world'");
    }

    #[test]
    fn shell_quote_escapes_single_quotes() {
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn target_command_inline_quotes_each_arg() {
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            // Live shares are attached by the guest activation path.
            dir_shares: Vec::new(),
            disk_volumes: Vec::new(),
            env: Vec::new(),
            target: ExecTarget::Inline {
                argv: vec!["uname".into(), "-a".into()],
            },
            timeout_secs: Some(30),
            pty: false,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
            sdk_host_services: Vec::new(),
            declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
        };
        assert_eq!(req.target_command(), "exec 'uname' '-a'");
    }

    #[test]
    fn build_guest_wrapper_no_extras() {
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            // Live shares are attached by the guest activation path.
            dir_shares: Vec::new(),
            disk_volumes: Vec::new(),
            env: Vec::new(),
            target: ExecTarget::Inline {
                argv: vec!["true".into()],
            },
            timeout_secs: Some(30),
            pty: false,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
            sdk_host_services: Vec::new(),
            declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
        };
        let script = build_guest_wrapper(&req);
        assert!(script.starts_with("set -e\n"));
        assert!(script.contains("exec 'true'"));
        assert!(!script.contains("mount"));
        // The mediated-tool PATH is always emitted; no caller export joins it.
        assert_eq!(script.matches("export ").count(), 1);
        assert!(script.contains(mvm_core::guest_netd::MEDIATED_TOOLS_BIN));
    }

    /// The image's own `ping` fails at `socket()` in a NIC-less guest, so the
    /// mediated stand-in has to win even when the caller sets `PATH` itself.
    #[test]
    fn build_guest_wrapper_mediated_path_outranks_a_caller_supplied_path() {
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            // Live shares are attached by the guest activation path.
            dir_shares: Vec::new(),
            disk_volumes: Vec::new(),
            env: vec![("PATH".into(), "/usr/bin".into())],
            target: ExecTarget::Inline {
                argv: vec!["true".into()],
            },
            timeout_secs: Some(30),
            pty: false,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
            sdk_host_services: Vec::new(),
            declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
        };
        let script = build_guest_wrapper(&req);
        let caller = script.find("export PATH='/usr/bin'").expect("caller PATH");
        let mediated = script
            .find(mvm_core::guest_netd::MEDIATED_TOOLS_BIN)
            .expect("mediated PATH");
        assert!(
            mediated > caller,
            "mediated PATH must come last to win; got:\n{script}"
        );
        // Composed against $PATH rather than replacing it, so the caller's
        // entry survives behind ours.
        assert!(script.contains(":\"$PATH\""), "got:\n{script}");
    }

    #[test]
    fn transient_vm_name_format() {
        let n = transient_vm_name();
        mvm_core::naming::validate_vm_name(&n)
            .unwrap_or_else(|e| panic!("transient name {n:?} invalid: {e}"));
        assert_eq!(n.split('-').count(), 3);
        assert!(!n.contains(' '));
        assert!(!n.contains('/'));
    }

    // -- launch.json parser --

    #[test]
    fn target_command_launch_plan_quotes_argv() {
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            // Live shares are attached by the guest activation path.
            dir_shares: Vec::new(),
            disk_volumes: Vec::new(),
            env: Vec::new(),
            target: ExecTarget::LaunchPlan {
                entrypoint: LaunchEntrypoint {
                    command: vec!["python".into(), "-m".into(), "x".into()],
                    working_dir: None,
                    env: BTreeMap::new(),
                },
            },
            timeout_secs: Some(30),
            pty: false,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
            sdk_host_services: Vec::new(),
            declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
        };
        assert_eq!(req.target_command(), "exec 'python' '-m' 'x'");
    }

    #[test]
    fn build_guest_wrapper_launch_plan_emits_cd_and_env() {
        let mut env = BTreeMap::new();
        env.insert("PORT".to_string(), "8080".to_string());
        env.insert("LOG".to_string(), "info".to_string());
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            // Live shares are attached by the guest activation path.
            dir_shares: Vec::new(),
            disk_volumes: Vec::new(),
            env: vec![("CLI_OVER".to_string(), "wins".to_string())],
            target: ExecTarget::LaunchPlan {
                entrypoint: LaunchEntrypoint {
                    command: vec!["python".into(), "main.py".into()],
                    working_dir: Some("/app".into()),
                    env,
                },
            },
            timeout_secs: Some(30),
            pty: false,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
            sdk_host_services: Vec::new(),
            declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
        };
        let script = build_guest_wrapper(&req);
        // Env from entrypoint exported.
        assert!(script.contains("export PORT='8080'"));
        assert!(script.contains("export LOG='info'"));
        // CLI env exported AFTER entrypoint env, so it wins on conflict.
        let cli_pos = script
            .find("export CLI_OVER='wins'")
            .expect("CLI env exported");
        let port_pos = script.find("export PORT='8080'").expect("port exported");
        assert!(
            cli_pos > port_pos,
            "CLI env must appear after launch-plan env"
        );
        // cd into working_dir before exec.
        assert!(script.contains("cd '/app'"));
        let cd_pos = script.find("cd '/app'").unwrap();
        let exec_pos = script.find("exec 'python' 'main.py'").unwrap();
        assert!(cd_pos < exec_pos, "cd must precede the final exec");
    }

    #[test]
    fn build_guest_wrapper_inline_target_unchanged() {
        // Sanity: inline target wrapper still does not emit cd or extra env blocks.
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            dir_shares: Vec::new(),
            disk_volumes: Vec::new(),
            env: Vec::new(),
            target: ExecTarget::Inline {
                argv: vec!["true".into()],
            },
            timeout_secs: Some(30),
            pty: false,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
            sdk_host_services: Vec::new(),
            declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
        };
        let script = build_guest_wrapper(&req);
        assert!(!script.contains("cd "));
        assert_eq!(script.matches("export ").count(), 1);
        assert!(script.contains(mvm_core::guest_netd::MEDIATED_TOOLS_BIN));
        assert!(script.contains("exec 'true'"));
    }

    // -- snapshot_eligible --

    fn template(name: &str) -> ImageSource {
        ImageSource::Template(name.into())
    }

    fn prebuilt() -> ImageSource {
        ImageSource::Prebuilt {
            kernel_path: "/k".into(),
            rootfs_path: "/r".into(),
            initrd_path: None,
            label: "lbl".into(),
            unpacked_oci_root: None,
        }
    }

    /// The virtiofs tier gate is gone, so what used to be tested here is that
    /// it could never fire. What survived it is the distinction the gate's
    /// input happened to encode: an OCI-derived prebuilt and the cached dev
    /// image take different initrds, and only the first has an unpacked tree.
    ///
    /// Deleting the field outright would have quietly given every prebuilt the
    /// OCI initrd, which nothing would have failed on.
    #[test]
    fn only_an_oci_derived_prebuilt_resolves_the_oci_initrd() {
        let oci = ImageSource::Prebuilt {
            kernel_path: "/k".into(),
            rootfs_path: "/r".into(),
            initrd_path: None,
            label: "oci:sha256:abc".into(),
            unpacked_oci_root: Some("/tree".into()),
        };
        // The cached dev image: a prebuilt with no unpacked tree behind it.
        let dev = prebuilt();

        // An explicit initrd always wins, whatever the image is.
        assert_eq!(
            effective_transient_initrd(
                &oci,
                Some("/explicit"),
                "/r",
                mvm_build::run_image::RootStrategy::BlockExt4
            )
            .unwrap()
            .as_deref(),
            Some("/explicit")
        );

        // The dev image never resolves an OCI initrd, whatever is on disk.
        assert_eq!(
            effective_transient_initrd(
                &dev,
                None,
                "/r",
                mvm_build::run_image::RootStrategy::BlockExt4
            )
            .unwrap(),
            None,
            "a non-OCI prebuilt must not take the OCI initrd path"
        );
    }

    #[test]
    fn snapshot_eligible_true_for_template_no_extras_with_snapshot() {
        assert!(snapshot_eligible(
            &template("t"),
            &[],
            true,
            SnapshotCapability::LiveMemory
        ));
    }

    #[test]
    fn snapshot_eligible_false_when_backend_lacks_support() {
        assert!(!snapshot_eligible(
            &template("t"),
            &[],
            true,
            SnapshotCapability::Unsupported
        ));
    }

    #[test]
    fn snapshot_eligible_false_when_no_snapshot_present() {
        assert!(!snapshot_eligible(
            &template("t"),
            &[],
            false,
            SnapshotCapability::LiveMemory
        ));
    }

    #[test]
    fn snapshot_eligible_false_with_directory_shares() {
        // A live share changes the device layout; snapshot would fail.
        assert!(!snapshot_eligible(
            &template("t"),
            &[DirShareSpec {
                host_dir: "/h".into(),
                guest_mount: "/g".into(),
                read_only: true,
            }],
            true,
            SnapshotCapability::LiveMemory
        ));
    }

    #[test]
    fn snapshot_eligible_false_for_prebuilt_image() {
        // The bundled default image isn't a registered template — no snapshot exists.
        assert!(!snapshot_eligible(
            &prebuilt(),
            &[],
            true,
            SnapshotCapability::LiveMemory
        ));
    }

    #[test]
    fn transient_oci_required_overlay_returns_no_initrd() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        let sibling = dir.path().join("rootfs.initrd");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        // A sibling legacy initrd must be ignored.
        std::fs::write(&sibling, b"initrd").unwrap();
        let image = ImageSource::Prebuilt {
            kernel_path: "/k".into(),
            rootfs_path: rootfs.display().to_string(),
            initrd_path: None,
            label: "oci".into(),
            unpacked_oci_root: Some("/tree".to_string()),
        };

        let resolved = effective_transient_initrd(
            &image,
            None,
            &rootfs.display().to_string(),
            mvm_build::run_image::RootStrategy::BlockExt4,
        )
        .unwrap();

        assert_eq!(resolved, None, "legacy initrd must not be returned");
    }

    #[test]
    fn transient_non_oci_prebuilt_does_not_infer_initrd() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();

        let resolved = effective_transient_initrd(
            &prebuilt(),
            None,
            &rootfs.display().to_string(),
            mvm_build::run_image::RootStrategy::BlockExt4,
        )
        .unwrap();

        assert!(resolved.is_none());
    }

    // --- transient_run_dev_console ---

    #[test]
    fn interactive_transient_run_sets_dev_console_when_not_sealed() {
        // PTY-mode run against a non-sealed image must pre-open console sockets
        // so the hvf backend can host-dial the guest's data port.
        assert!(transient_run_dev_console(true, false));
    }

    #[test]
    fn non_interactive_transient_run_leaves_dev_console_unset() {
        // A non-PTY run never needs the interactive console data sockets.
        assert!(!transient_run_dev_console(false, false));
    }

    #[test]
    fn interactive_sealed_run_leaves_dev_console_unset() {
        // A sealed image has no interactive agent; pre-opening sockets is
        // wasteful. enforce_accessible_gate refuses the attach separately.
        assert!(!transient_run_dev_console(true, true));
    }

    #[test]
    fn non_interactive_sealed_run_leaves_dev_console_unset() {
        assert!(!transient_run_dev_console(false, true));
    }

    #[test]
    fn interactive_verity_backed_oci_run_still_arms_dev_console() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"x").unwrap();
        std::fs::write(dir.path().join("rootfs.verity"), b"verity").unwrap();
        std::fs::write(dir.path().join("rootfs.roothash"), b"roothash").unwrap();
        mvm_build::builder_vm::GuestSidecar::for_oci_run("oci:test", false, true)
            .write_to_dir(dir.path())
            .unwrap();

        let image_sealed = crate::commands::vm::image_is_sealed(&rootfs);
        assert!(
            transient_run_dev_console(true, image_sealed),
            "verity-backed accessible OCI images must keep the interactive console armed"
        );
    }

    #[test]
    fn remove_transient_state_dir_removes_the_host_dir() {
        // Every transient run creates its state dir
        // when the backend writes hvf.pid / console.log there, so teardown must
        // remove it host-side — not via run_in_vm, which targets the guest.
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("vms").join("throwaway-vm");
        std::fs::create_dir_all(&dir).expect("create state dir");
        std::fs::write(dir.join("hvf.pid"), b"1234").expect("write pid file");
        assert!(dir.exists());

        remove_transient_state_dir(&dir.to_string_lossy());

        assert!(!dir.exists(), "the host state dir must be removed");
    }

    #[test]
    fn remove_transient_state_dir_is_a_noop_on_a_missing_dir() {
        // Best-effort: an already-gone dir (or a boot that never created one) is
        // a clean no-op, never a panic.
        remove_transient_state_dir("/nonexistent/mvm/vms/never-created");
    }

    #[test]
    fn normalize_backend_override_trims_lowercases_and_drops_blank() {
        assert_eq!(
            normalize_backend_override("  LibKrun \n"),
            Some("libkrun".to_string())
        );
        assert_eq!(
            normalize_backend_override("firecracker"),
            Some("firecracker".to_string())
        );
        assert_eq!(normalize_backend_override("   "), None);
        assert_eq!(normalize_backend_override(""), None);
    }
}
