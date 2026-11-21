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

use anyhow::{Context, Result};
use mvm_core::launch_trace::PhaseTimingMode;
use mvm_core::vm_backend::{VmId, VmStartConfig, VmVolume};
use mvm_runtime::backend::AnyBackend;
use mvm_vmm::vsock_transport;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

use crate::commands::DirShareSpec;
use crate::ui;

mod baked_entrypoint;
mod built_pack;
mod either;
mod guest_command;
pub use guest_command::{
    ExecOutput, PostureSink, build_guest_wrapper, build_healthcheck, run, run_captured,
    snapshot_eligible, transient_run_dev_console, transient_vm_name,
};
pub(crate) use guest_command::{
    quote_argv_for_exec, remove_transient_state_dir, reported_exit_code, run_captured_started,
    run_started,
};
mod guest_run;
mod image_artifacts;
use image_artifacts::{ResolvedImage, resolve_image_artifacts};
mod launch_plan;
mod mounts;
mod oci_boot;
use either::Either;
pub(crate) use mounts::admitted_instruction_mounts;
use mounts::refuse_unloadable_sidecar;
mod session;
mod sidecar_selection;
mod startup_slo;
mod transient;
use startup_slo::StartupClock;

pub use launch_plan::load_launch_plan;

use baked_entrypoint::{
    baked_entrypoint_result, boots_baked_entrypoint, dispatch_baked_entrypoint,
};
#[cfg(test)]
use baked_entrypoint::{baked_entrypoint_timeout_secs, dispatched_exit_status};
use guest_run::{emit_guest_console_diagnostic, run_in_guest, run_wasm_module};
pub(crate) use mvm_client::boot::{select_exec_backend, validate_image_egress_backend_name};
pub use mvm_client::entrypoint::{AdmitInputs, SessionAdmit, SessionAuditSubstrate};
pub(crate) use oci_boot::{ImageNaming, LaunchNames, boots_oci_image, oci_proxy_env};
use session::wait_for_agent_timed;
pub use session::{SessionVm, dispatch_in_session, wait_for_agent};
pub(crate) use session::{connect_session, dispatch_on_session_stream};
#[cfg(test)]
pub(crate) use transient::teardown_transient_vm;
use transient::{
    BootAttempt, LeaveAt, arm_interrupt_teardown, boot_transient_vm, check_admitted_projection,
    combine_run_and_flush, flush_writable_disks_before_teardown, leave_standby_when,
    standby_to_leave, start_mode,
};
pub(crate) use transient::{RuntimeRunCustody, TransientStopFailure, combine_run_and_stop};

pub(crate) type CliColdAdmit<'a> =
    dyn Fn(AdmitInputs<'_>) -> Result<mvm_client::admission::CliColdAdmissionResult> + 'a;

#[derive(Clone, Copy)]
pub(crate) enum LaunchAdmit<'a> {
    Session(&'a SessionAdmit<'a>),
    CliCold(&'a CliColdAdmit<'a>),
}

/// Exit code the CLI returns when a guest command exceeds its `--timeout`.
/// Matches GNU `timeout(1)` so scripts can branch on it.
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
///     `apps[].entrypoints[].env` (higher precedence).
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
        unpacked_oci_root: Option<String>,
    },
    /// Pre-built `wasm32-wasip1` module run directly under the wasm backend.
    /// No kernel, initrd, or rootfs — the module path is the workload.
    WasmModule { module_path: String, label: String },
    /// A built registry image reopened under an exact pin. No cached host path
    /// bypasses the shared client contract or final admitted-image check.
    RegistryPack {
        pin: mvm_core::registry_pack::PackPin,
    },
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
    /// Declared `--asset` bindings hashed into content identities at
    /// admission.
    pub assets: &'a [crate::commands::shared::AssetSpec],
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
    /// `--gpu` carried from the request: the start config takes it, and the
    /// resolved backend must advertise the `gpu` capability or selection
    /// refuses before anything boots.
    pub gpu: bool,
    /// Optional host GPU ordinal exposed to this launch as guest device zero.
    pub gpu_device: Option<u32>,
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
    /// Declared `--asset KIND:PATH` bindings hashed into content identities
    /// at admission. Nothing is attached to the guest — the hash is recorded
    /// in the signed plan and the chain-signed audit log.
    pub assets: Vec<crate::commands::shared::AssetSpec>,
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
    /// The standby an unnamed run of a claimable shape leaves for the next run
    /// of its image, or `None` when `pool warm` cannot prepare its source.
    pub standby_refill: Option<crate::commands::pool::StandbyRefill>,
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
    /// `--gpu`: forward the guest's CUDA/NVML calls to the host GPU
    /// endpoint over vsock. Carried here so the launch shape and the
    /// backend's required capabilities both see the same answer.
    pub gpu: bool,
    /// Optional host GPU ordinal exposed to this launch as guest device zero.
    pub gpu_device: Option<u32>,
}

impl ExecRequest {
    /// Borrow the boot-shape half of this request. The launch resolution reads
    /// only these fields, so a run and a `pool warm` that agree on them resolve
    /// the same config — which is what makes the warm-pool compat key match.
    pub fn launch_shape(&self) -> LaunchShape<'_> {
        LaunchShape {
            assets: &self.assets,
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
            gpu: self.gpu,
            gpu_device: self.gpu_device,
        }
    }
}

fn shape_uses_vsock_proxy_backend(shape: &LaunchShape<'_>) -> Result<bool> {
    Ok(
        boots_oci_image(ImageNaming::Resolved(shape.image))?
            && shape.network_policy.allows_egress(),
    )
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

fn run_inner(
    req: ExecRequest,
    capture: bool,
    admit: Option<LaunchAdmit<'_>>,
    audit_owner: Option<&std::cell::RefCell<Option<mvm_client::admission::CliAdmission>>>,
    posture: Option<&PostureSink>,
    startup_started: std::time::Instant,
) -> Result<Either<i32, ExecOutput>> {
    // The steps of this one launch share a single check of the signed runtime
    // release; the next launch checks again.
    let _runtime_proofs = mvm_build::guest_runtime::evidence::LaunchProofScope::begin();
    // Phase timing (off unless `MVM_PHASE_TIMING` or a launch-sample path is
    // set): capture a host-monotonic mark at each run seam, then emit a
    // one-line breakdown and/or the machine-readable sample at teardown. When
    // both are off every mark stays `None` and costs nothing.
    let sample_path = crate::commands::vm::launch_sample::sample_path_from_env();
    let timing_mode = crate::commands::vm::phase_timing::mode();
    let timing = timing_mode.is_on() || sample_path.is_some();
    // Sub-phase marks are always taken: the startup ceiling names the slow
    // phase when it refuses a launch, whether or not timing was requested.
    let mut sub_marks = crate::commands::vm::phase_timing::LaunchSubMarks::new(true);
    let t_start = timing.then(std::time::Instant::now);

    let named_lifecycle = req
        .name
        .as_deref()
        .map(mvm_runtime::vm::instance_snapshot::MachineLifecycleLock::acquire)
        .transpose()?;
    if let (Some(name), Some(lifecycle)) = (req.name.as_deref(), named_lifecycle.as_ref()) {
        anyhow::ensure!(
            !mvm_core::config::machine_spec_path(name).exists(),
            "a persistent machine named {name:?} exists; use its persistent lifecycle verbs"
        );
        anyhow::ensure!(
            lifecycle.reap_unowned_state()?,
            "machine {name:?} still owns its runtime state"
        );
    }

    // Serialize materialization for this invocation. The runtime transfers
    // writer custody to the actual backend, so an uncertain-stop return does
    // not rely on these caller-side guards remaining alive.
    let mut disk_images = req
        .disk_volumes
        .iter()
        .map(crate::commands::shared::materialize_disk_volume)
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter_map(|lock| lock.and_then(mvm_build::volume_image::VolumeImageLock::into_image))
        .collect::<Vec<_>>();

    // Everything from backend selection through admission and the runtime
    // overlay attach. It yields a bootable config without booting, which is
    // also what `pool warm` needs — so it lives in one function both call
    // rather than two that are free to drift.
    let mut resolve_marks = LaunchResolveMarks::new(timing);
    let launch = resolve_launch_with_admit(
        &req.launch_shape(),
        admit,
        &mut resolve_marks,
        &mut sub_marks,
    )?;
    let ResolvedLaunch {
        backend,
        start_config,
        host_budget,
        verified_runtime,
        mailbox_posture,
        cli_admission,
        use_snapshot,
        root_strategy,
        image: resolved,
        _built_runtime,
    } = launch;
    if let Some(admission) = cli_admission {
        let owner = audit_owner.context("prepared CLI cold launch has no audit owner")?;
        anyhow::ensure!(
            owner.borrow().is_none(),
            "CLI launch already has an admission owner"
        );
        *owner.borrow_mut() = Some(admission);
    }
    let startup_admitted = std::time::Instant::now();
    let vm_name = start_config.name.clone();

    // Report the resolved strategy to the command layer for chain-audit. This is
    // the single source of truth — the same value that drives the boot below —
    // so the `plan.boot_posture` entry can never diverge from what actually
    // booted.
    if let Some(sink) = posture {
        sink.set(mvm_client::admission::BootPosture {
            root_strategy,
            start: None,
        });
    }

    let t_image_resolved = resolve_marks.image_resolved;
    let t_drives_ready = resolve_marks.drives_ready;
    let t_admitted = resolve_marks.admitted;

    // Reap stale standbys, try a warm-pool claim, then fall back to
    // snapshot-restore / cold boot. See `boot_transient_vm`.
    let mut warm_claim_marks = crate::commands::vm::phase_timing::WarmClaimMarks::default();
    let requested_vm_name = vm_name.clone();
    let requested_lifecycle = match named_lifecycle {
        Some(lifecycle) => lifecycle,
        None => mvm_runtime::vm::instance_snapshot::MachineLifecycleLock::acquire(&vm_name)?,
    };
    if let Some(runtime) = &_built_runtime {
        runtime.verify_config(&start_config)?;
    }
    check_admitted_projection(audit_owner, &start_config)?;
    let mut boot_attempt = BootAttempt {
        backend: &backend,
        start_config: &start_config,
        verified_release: verified_runtime.as_ref().map(|runtime| runtime.release()),
        admission: audit_owner,
        mailbox_posture: mailbox_posture.as_ref(),
        resolved: &resolved,
        user_named: req.name.is_some(),
        writable_images: &mut disk_images,
    };
    if let Some(permit) = &host_budget {
        let plan = mvm_core::plan::plan_from_admitted_json(
            start_config
                .plan_json
                .as_deref()
                .context("admitted transient plan missing")?,
        )?;
        permit.mark_dispatching_for(&plan, &vm_name)?;
    }
    let booted = boot_transient_vm(
        vm_name,
        use_snapshot,
        &mut boot_attempt,
        timing.then_some(&mut warm_claim_marks),
        &mut sub_marks,
    )?;
    if let Some(permit) = &host_budget
        && let Err(error) = permit.record_started(&booted.name)
    {
        return match backend.stop(&mvm_core::vm_backend::VmId(booted.name.clone())) {
            Ok(_) => Err(error.context("recording transient host charge")),
            Err(stop) => Err(error.context(format!(
                "recording transient host charge; rollback unconfirmed: {stop:#}"
            ))),
        };
    }
    let vm_name = booted.name;
    let effective_lifecycle = booted.lifecycle;
    if vm_name != requested_vm_name {
        // Admission-only scratch has no running instance. Retire it while its
        // original launch still owns the name, never from delayed teardown.
        remove_transient_state_dir(
            &mvm_core::config::vm_state_dir(&requested_vm_name).to_string_lossy(),
        );
    }
    let exit_audit = start_config.plan_json.as_deref().map(|signed_plan_json| {
        mvm_client::launch::TransientExitAudit {
            signed_plan_json,
            vm_name: &vm_name,
            backend: backend.name(),
            exit_code: None,
            completed: false,
            posture: None,
        }
    });
    let custody = std::sync::Arc::new(RuntimeRunCustody::capture_or_stop(
        &backend,
        &vm_name,
        effective_lifecycle.as_ref().unwrap_or(&requested_lifecycle),
        exit_audit,
        &mut sub_marks,
    )?);
    drop(effective_lifecycle);
    drop(requested_lifecycle);
    let launch_mode = booted.launch_mode;
    if let Some(sink) = posture {
        sink.set(mvm_client::admission::BootPosture {
            root_strategy,
            start: Some(start_mode(booted.cold_reason)),
        });
    }
    let refill = standby_to_leave(req.standby_refill.as_ref(), booted.cold_reason);
    leave_standby_when(refill, launch_mode, LeaveAt::AfterBoot);
    let startup_clock = StartupClock {
        launch_mode,
        started: startup_started,
        admitted: startup_admitted,
        booted: std::time::Instant::now(),
    };
    let t_backend_started = timing.then_some(startup_clock.booted);

    // Read the backend's own phase sidecar now: teardown removes the state
    // directory that holds it, and by the time the sample is assembled it is
    // gone. A backend that does not trace itself yields nothing here.
    let backend_trace = timing
        .then(|| mvm_core::launch_trace::read_trace(&mvm_core::config::vm_state_dir(&vm_name)))
        .flatten();
    // The launch's own laps (admission and overlay attach) sit beside the
    // backend's phases: both are qualified names inside a runner phase.
    let backend_phases = backend_trace
        .as_ref()
        .map(|trace| trace.phases.clone())
        .unwrap_or_default()
        .into_iter()
        .chain(mvm_core::launch_trace::recorded_laps())
        .collect::<Vec<_>>();
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

    // A signal stops and removes the VM before the process exits.
    let interrupt_teardown = arm_interrupt_teardown(
        custody.clone(),
        backend.name(),
        start_config.plan_json.as_deref(),
    );

    // Answer the endpoint's `ask` decisions for as long as the run is in the
    // foreground. The wasm tier has no network endpoint to ask.
    let _approvals =
        (backend.name() != "wasm").then(|| crate::approval::serve_for(&vm_name, req.pty));

    // Run the command + always tear down. The wasm backend has no guest
    // agent; the module already ran inside `start`, so we just collect its
    // exit status instead of waiting for a vsock console.
    let run_outcome = if let Err(error) = start_config.wait_for_admission_durability() {
        Err(error)
    } else if backend.name() == "wasm" {
        match run_wasm_module(&backend, &vm_name) {
            Ok(code) => Ok((Either::Left(code), None)),
            Err(e) => Err(e),
        }
    } else if boots_baked_entrypoint(&req) {
        dispatch_baked_entrypoint(&vm_name, &req, &startup_clock, &mut sub_marks).and_then(
            |(status, ready)| {
                baked_entrypoint_result(status, capture, &vm_name)
                    .map(|result| (result, Some(ready)))
            },
        )
    } else {
        run_in_guest(&vm_name, &req, capture, &startup_clock, &mut sub_marks)
    };
    leave_standby_when(refill, launch_mode, LeaveAt::AfterWorkload);
    let reported_exit_code = reported_exit_code(&run_outcome);
    let workload_completed = run_outcome.is_ok();
    let t_command_done = timing.then(std::time::Instant::now);
    let (mut result, t_vsock_ready) = match run_outcome {
        Ok((either, vsock_ready)) => (Ok(either), vsock_ready),
        Err(e) => (Err(e), None),
    };
    let cleanup_lifecycle =
        mvm_runtime::vm::instance_snapshot::MachineLifecycleLock::acquire(&vm_name);
    let flush = match &cleanup_lifecycle {
        Ok(lifecycle) => custody
            .require_current(lifecycle)
            .and_then(|()| flush_writable_disks_before_teardown(&vm_name, &req.disk_volumes)),
        Err(error) => Err(anyhow::anyhow!("locking transient cleanup: {error:#}")),
    };
    result = combine_run_and_flush(result, flush);
    let warm_memory_result = warm_memory_start.map(|start| {
        start.and_then(|start| finish_warm_memory_measurement(&backend, &vm_name, start))
    });
    let warm_memory_error = warm_memory_result
        .as_ref()
        .and_then(|result| result.as_ref().err())
        .map(|error| format!("{error:#}"));
    let warm_first_command_memory = warm_memory_result.and_then(Result::ok);

    // Do not opportunistically reap other runs here: their missing PID is not
    // evidence that retained uncertain-stop state is safe to remove.

    sub_marks.start(crate::commands::vm::phase_timing::SubPhase::CleanupHandoff);
    let exit_audit = start_config.plan_json.as_deref().map(|signed_plan_json| {
        mvm_client::launch::TransientExitAudit {
            signed_plan_json,
            vm_name: &vm_name,
            backend: backend.name(),
            exit_code: reported_exit_code,
            completed: workload_completed,
            posture: posture.filter(|_| result.is_ok()).map(std::cell::Cell::get),
        }
    });
    let stopped = match &cleanup_lifecycle {
        Ok(lifecycle) => transient::teardown_custodied_in_lifecycle(
            &backend,
            &custody,
            lifecycle,
            exit_audit,
            &mut sub_marks,
        ),
        Err(error) => Err(transient::TransientStopFailure(anyhow::anyhow!(
            "locking transient cleanup: {error:#}"
        ))),
    };
    drop(cleanup_lifecycle);
    drop(interrupt_teardown);
    if stopped.is_err() {
        return combine_run_and_stop(result, stopped);
    }
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
            invoked: startup_started,
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
    _vm_name: &str,
    sub: &mut crate::commands::vm::phase_timing::LaunchSubMarks,
) -> Result<Vec<VmVolume>> {
    mounts::materialize_mount_volumes(shape.dir_shares, sub)
}

/// Build the `VmStartConfig` for the transient boot from the resolved image +
/// boot-strategy state. Admission (tenant/plan binding) and the runtime
/// overlay attach happen in the caller, after this returns — this only
/// assembles the struct.
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
        gpu: shape.gpu,
        gpu_device: shape.gpu_device,
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

#[cfg(test)]
fn prepare_then_admit<T>(
    prepare: impl FnOnce() -> Result<()>,
    admit: impl FnOnce() -> Result<T>,
) -> Result<T> {
    prepare()?;
    admit()
}

fn finish_cli_cold_lowering<T, U>(
    owner: &std::cell::RefCell<Option<T>>,
    lowering: Result<U>,
) -> Result<(T, U)> {
    let lowered = lowering?;
    let owner = owner
        .borrow_mut()
        .take()
        .context("CLI cold preparation lost its admitted audit owner")?;
    Ok((owner, lowered))
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
    /// The same one-use host hold returned by admission.
    pub host_budget: Option<std::sync::Arc<mvm_hostd::admission_budget::HostBudgetPermit>>,
    /// The backend the launch resolved against. Selected here rather than by
    /// the caller so a warm spawn and the run it serves cannot disagree about
    /// which backend's capabilities shaped the config.
    pub backend: AnyBackend,
    pub start_config: VmStartConfig,
    /// Exact signed release bytes owned until the lifecycle generation is bound.
    pub verified_runtime: Option<std::sync::Arc<mvm_runtime::runtime_evidence::VerifiedRuntimeSet>>,
    /// Only admission may supply Dev posture for an opted-in mailbox.
    pub mailbox_posture: Option<mvm_hostd::plan_admission::MailboxLaunchPosture>,
    /// Opaque host-prepared owner for the admitted CLI cold alternative.
    pub cli_admission: Option<mvm_client::admission::CliAdmission>,
    /// Whether snapshot restore survives admission (an admitted workload
    /// always cold-boots).
    pub use_snapshot: bool,
    /// Rootfs strategy the run-path tier gate selected — the value the run path
    /// records as `plan.boot_posture`.
    pub root_strategy: mvm_build::run_image::RootStrategy,
    /// Resolved image artifacts, kept for the snapshot-restore leg of the boot.
    image: ResolvedImage,
    /// Retained until normal runtime lifecycle binding has taken ownership.
    _built_runtime: Option<mvm_hostd::plan_admission::PreparedBuiltPackRuntime>,
}

impl ResolvedLaunch {
    /// Consume a planless resolution into the opaque client warm-parent facade.
    pub(crate) fn into_warm_parent(self) -> Result<mvm_client::standby::PreparedWarmParent> {
        mvm_client::standby::PreparedWarmParent::from_resolved(
            self.backend,
            self.start_config,
            self.verified_runtime,
            self._built_runtime,
        )
    }
}

/// Resolve a launch's bootable [`VmStartConfig`] **without starting a VM**.
///
/// Composes four steps:
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
    resolve_launch_with_admit(shape, admit.map(LaunchAdmit::Session), marks, sub)
}

fn resolve_launch_with_admit(
    shape: &LaunchShape<'_>,
    admit: Option<LaunchAdmit<'_>>,
    marks: &mut LaunchResolveMarks,
    sub: &mut crate::commands::vm::phase_timing::LaunchSubMarks,
) -> Result<ResolvedLaunch> {
    use crate::commands::vm::phase_timing::SubPhase;

    built_pack::validate_shape(
        shape.image,
        shape.assets,
        shape.warm_pool_size,
        admit.is_some(),
    )?;
    let backend = select_exec_backend(
        shape_uses_vsock_proxy_backend(shape)?,
        shape.network_policy,
        shape.hypervisor,
    )?;

    // Resolve image artifacts: either a named template or a pre-built pair.
    // For templates, also probe for a pre-built snapshot so we can skip the
    // cold-boot cost when the request is snapshot-eligible.
    let image = resolve_image_artifacts(shape.image, backend.name())?;
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
    // Chosen here, and only here, because this is the first point at which the
    // guest exists: the variant follows the libc its rootfs recorded when it
    // was unpacked. Resolved once and used twice — the volume goes into the
    // launch config below, and the same attachment reaches admission a few
    // lines further down, so the signed plan's grant names the bytes that were
    // actually attached.
    let sdk_sidecar = sidecar_selection::select_for_launch(
        backend.kind(),
        std::path::Path::new(&image.rootfs),
        shape.sdk_host_services,
        shape.declared_libc,
    )?;

    let t_build = std::time::Instant::now();
    let mut start_config =
        build_start_config(shape, &vm_name, &image, &boot, sdk_sidecar.as_ref(), sub)?;
    tracing::debug!(
        ms = t_build.elapsed().as_secs_f64() * 1000.0,
        "admit window: build_start_config"
    );
    let mut use_snapshot = boot.use_snapshot;
    let mut built_pack_check = None;
    let mut mailbox_posture = None;
    let mut host_budget = None;
    let mut verified_runtime = None;
    let mut built_runtime = None;
    let mut cli_admission = None;
    let clamp_vcpus = |config: &mut VmStartConfig| {
        if let Some(granted) =
            mvm_core::vm_backend::clamp_vcpus(config.cpus, backend.capabilities().max_vcpus)
        {
            ui::warn(&format!(
                "{} supports at most {granted} vCPU(s); {} requested, booting with {granted}",
                backend.name(),
                config.cpus,
            ));
            tracing::info!(
                backend = backend.name(),
                requested = config.cpus,
                granted,
                "vcpu request clamped to the backend ceiling"
            );
            config.cpus = granted;
        }
    };

    // Attach everything the boot waits on before admitting. Admission starts
    // the plan's validity window and the verb grant minted from it expires
    // with it, so a cold overlay build after admission would spend the window
    // the boot needs (see `mvm_client::launch::boot_order`).
    let bundle_archive = image
        .template_id
        .as_deref()
        .map(mvm_runtime::vm::template::lifecycle::installed_bundle_archive)
        .transpose()?
        .flatten();
    if let Some(LaunchAdmit::CliCold(admit_fn)) = admit {
        let sub = std::cell::RefCell::new(&mut *sub);
        let prepared = mvm_client::admission::prepare_cli_cold(
            &backend,
            start_config,
            |config| {
                let t_overlay = std::time::Instant::now();
                sub.borrow_mut().start(SubPhase::AttachOverlay);
                mvm_core::launch_trace::lap_reset(None);
                let release =
                    crate::commands::env::builder_vm::with_pair_artifact_source(|pair| {
                        crate::commands::vm::up::attach_runtime_overlay_if_cached_version_verified(
                            config,
                            backend.name(),
                            None,
                            pair,
                        )
                    })?;
                mvm_core::launch_trace::lap("attach_overlay.tail");
                sub.borrow_mut().finish(SubPhase::AttachOverlay);
                tracing::debug!(
                    ms = t_overlay.elapsed().as_secs_f64() * 1000.0,
                    "admit window: attach runtime overlay"
                );

                let t_initramfs = std::time::Instant::now();
                sub.borrow_mut().start(SubPhase::AttachInitramfs);
                mvm_core::launch_trace::lap_reset(None);
                if let Some(release) = &release {
                    crate::commands::vm::up::attach_universal_initramfs_with_verified_release(
                        config,
                        backend.name(),
                        release,
                    )?;
                } else {
                    crate::commands::vm::up::attach_universal_initramfs_if_cached(
                        config,
                        backend.name(),
                    )?;
                }
                mvm_core::launch_trace::lap("attach_initramfs.tail");
                sub.borrow_mut().finish(SubPhase::AttachInitramfs);
                tracing::debug!(
                    ms = t_initramfs.elapsed().as_secs_f64() * 1000.0,
                    "admit window: attach universal initramfs"
                );
                Ok(release)
            },
            |config, verified| {
                let t_admission = std::time::Instant::now();
                sub.borrow_mut().start(SubPhase::AdmitPlan);
                mvm_core::launch_trace::lap_reset(None);
                let mvm_client::admission::CliColdAdmissionResult {
                    admission,
                    mut substrate,
                } = admit_fn(AdmitInputs {
                    rootfs: std::path::Path::new(&image.rootfs),
                    kernel: config.kernel_path.as_deref().map(std::path::Path::new),
                    backend_kind: backend.kind(),
                    vm_name: &vm_name,
                    sdk_sidecar: sdk_sidecar.as_ref(),
                    assets: shape.assets,
                    volumes: &config.volumes,
                    bundle_archive: bundle_archive.as_deref(),
                    runtime_config: Some(config),
                    verified_runtime: verified,
                    verified_runtime_owner: None,
                })?;
                let lowering = (|| {
                    let built_pack_check = substrate.built_pack_check.take();
                    let read_only_materialized_images = substrate.apply_to(config);
                    for volume in &mut config.volumes {
                        if read_only_materialized_images.contains(&volume.host)
                            || volume
                                .materialized_image
                                .as_ref()
                                .is_some_and(|image| read_only_materialized_images.contains(image))
                        {
                            volume.read_only = true;
                        }
                    }
                    refuse_unloadable_sidecar(
                        &image.rootfs,
                        &config.volumes,
                        config.plan_json.as_deref(),
                    )?;
                    mvm_core::launch_trace::lap("admit_plan.apply_and_sidecar_check");
                    sub.borrow_mut().finish(SubPhase::AdmitPlan);
                    tracing::debug!(
                        ms = t_admission.elapsed().as_secs_f64() * 1000.0,
                        "admit window: admission"
                    );
                    clamp_vcpus(config);
                    let t_status = std::time::Instant::now();
                    crate::commands::vm::up::emit_runtime_source_status(config);
                    tracing::debug!(
                        ms = t_status.elapsed().as_secs_f64() * 1000.0,
                        "admit window: runtime source status"
                    );
                    let built_runtime = built_pack_check
                        .map(|check| check.prepare(config, backend.kind()))
                        .transpose()?
                        .flatten();
                    built_pack::require_handoff(shape.image, built_runtime.is_some())?;
                    Ok(built_runtime)
                })();
                let (admission, built_runtime) =
                    finish_cli_cold_lowering(admission.as_ref(), lowering)?;
                Ok(mvm_client::admission::CliColdAdmissionInput::new(
                    admission,
                    built_runtime,
                ))
            },
        )?;
        start_config = prepared.config;
        host_budget = Some(prepared.host_budget);
        mailbox_posture = prepared.mailbox_posture;
        cli_admission = Some(prepared.admission);
        use_snapshot = false;
    }

    if !matches!(admit, Some(LaunchAdmit::CliCold(_))) {
        let t_overlay = std::time::Instant::now();
        sub.start(SubPhase::AttachOverlay);
        mvm_core::launch_trace::lap_reset(None);
        let verified_release =
            crate::commands::env::builder_vm::with_pair_artifact_source(|pair| {
                crate::commands::vm::up::attach_runtime_overlay_if_cached_version_verified(
                    &mut start_config,
                    backend.name(),
                    None,
                    pair,
                )
            })?;
        mvm_core::launch_trace::lap("attach_overlay.tail");
        sub.finish(SubPhase::AttachOverlay);
        tracing::debug!(
            ms = t_overlay.elapsed().as_secs_f64() * 1000.0,
            "admit window: attach runtime overlay"
        );

        let t_initramfs = std::time::Instant::now();
        sub.start(SubPhase::AttachInitramfs);
        mvm_core::launch_trace::lap_reset(None);
        if let Some(release) = &verified_release {
            crate::commands::vm::up::attach_universal_initramfs_with_verified_release(
                &mut start_config,
                backend.name(),
                release,
            )?;
        } else {
            crate::commands::vm::up::attach_universal_initramfs_if_cached(
                &mut start_config,
                backend.name(),
            )?;
        }
        mvm_core::launch_trace::lap("attach_initramfs.tail");
        sub.finish(SubPhase::AttachInitramfs);
        tracing::debug!(
            ms = t_initramfs.elapsed().as_secs_f64() * 1000.0,
            "admit window: attach universal initramfs"
        );
        verified_runtime = verified_release
            .map(|release| {
                mvm_runtime::runtime_evidence::verify_release_runtime_set(&start_config, release)
                    .map(std::sync::Arc::new)
            })
            .transpose()?;

        // Admit the transient run as a locally-signed workload. Setting
        // tenant_id + plan_json makes the runner-backed microVM supervisor enforce
        // `network_policy` and chain-audit the run. Force cold boot when admitted —
        // snapshot restore is unavailable for workload admission.
        let t_admission = std::time::Instant::now();
        sub.start(SubPhase::AdmitPlan);
        mvm_core::launch_trace::lap_reset(None);
        // A run resolved from an installed bundle boots its extracted files;
        // admission pins the bundle and checks those files against what was signed.
        if let Some(LaunchAdmit::Session(admit_fn)) = admit
            && let Some(sub) = admit_fn(AdmitInputs {
                rootfs: std::path::Path::new(&image.rootfs),
                kernel: start_config
                    .kernel_path
                    .as_deref()
                    .map(std::path::Path::new),
                backend_kind: backend.kind(),
                vm_name: &vm_name,
                sdk_sidecar: sdk_sidecar.as_ref(),
                assets: shape.assets,
                volumes: &start_config.volumes,
                bundle_archive: bundle_archive.as_deref(),
                runtime_config: Some(&start_config),
                verified_runtime: verified_runtime.as_deref(),
                verified_runtime_owner: verified_runtime.as_ref(),
            })?
        {
            let mut sub = sub;
            built_pack_check = sub.built_pack_check.take();
            mailbox_posture = sub.mailbox_posture.take();
            host_budget = Some(std::sync::Arc::clone(&sub.host_budget));
            let read_only_materialized_images = sub.apply_to(&mut start_config);
            for volume in &mut start_config.volumes {
                if read_only_materialized_images.contains(&volume.host)
                    || volume
                        .materialized_image
                        .as_ref()
                        .is_some_and(|image| read_only_materialized_images.contains(image))
                {
                    volume.read_only = true;
                }
            }
            use_snapshot = false;

            refuse_unloadable_sidecar(
                &image.rootfs,
                &start_config.volumes,
                start_config.plan_json.as_deref(),
            )?;
        }
        mvm_core::launch_trace::lap("admit_plan.apply_and_sidecar_check");
        sub.finish(SubPhase::AdmitPlan);
        tracing::debug!(
            ms = t_admission.elapsed().as_secs_f64() * 1000.0,
            "admit window: admission"
        );

        clamp_vcpus(&mut start_config);
        let t_status = std::time::Instant::now();
        crate::commands::vm::up::emit_runtime_source_status(&start_config);
        tracing::debug!(
            ms = t_status.elapsed().as_secs_f64() * 1000.0,
            "admit window: runtime source status"
        );
        built_runtime = built_pack_check
            .map(|check| check.prepare(&mut start_config, backend.kind()))
            .transpose()?
            .flatten();
        built_pack::require_handoff(shape.image, built_runtime.is_some())?;
    }
    marks.admitted = marks.now();

    Ok(ResolvedLaunch {
        backend,
        start_config,
        host_budget,
        verified_runtime,
        mailbox_posture,
        cli_admission,
        use_snapshot,
        root_strategy: boot.root_strategy,
        image,
        _built_runtime: built_runtime,
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
            standby_refill: None,
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
            assets: Vec::new(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
            gpu: false,
            gpu_device: None,
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

    /// A dispatch that inherits no `--timeout` must not inherit a deadline it
    /// has already missed.
    ///
    /// `0` reads to the agent as "the wrapper has exceeded its window", not as
    /// "unbounded". The first live run of this fix passed 0 and came back
    /// `124: wrapper exceeded 0s timeout` — the workload never got to run, the
    /// same symptom by a different route as the bug being fixed.
    #[test]
    fn a_baked_entrypoint_without_a_timeout_gets_the_entrypoint_paths_default() {
        assert_eq!(
            baked_entrypoint_timeout_secs(None),
            30,
            "must match `--entrypoint`'s `args.run.timeout.unwrap_or(30)` for the same operation"
        );
        assert_ne!(
            baked_entrypoint_timeout_secs(None),
            0,
            "0 is an already-expired deadline, not an absent one"
        );
        assert_eq!(baked_entrypoint_timeout_secs(Some(120)), 120);
        // An explicit 0 is the caller's to make; only the *default* is guarded.
        assert_eq!(baked_entrypoint_timeout_secs(Some(0)), 0);
    }

    /// A dispatched entrypoint always yields a code, so this path can no
    /// longer land in the fail-closed branch by *not running the workload*.
    ///
    /// That was the defect: `machine run --flake <dir>` with no trailing
    /// command booted a guest, dispatched nothing, and waited for a report
    /// nothing produced. The agent has no autostart, and the only writer of the
    /// workload-exit port is exec'd solely by the detached-run reaper — so the
    /// wait could only ever time out. The error named a workload that had never
    /// started.
    #[test]
    fn a_dispatched_entrypoint_always_carries_a_code() {
        for code in [0, 1, 7, 124, 255] {
            let status = dispatched_exit_status(code);
            assert_eq!(status.code, Some(code));
            assert_eq!(status.success, code == 0);
            assert_ne!(
                status,
                mvm_core::vm_backend::VmExitStatus::UNKNOWN,
                "a dispatched entrypoint must never report UNKNOWN — that is \
                 reserved for a workload that was never run"
            );
        }
    }

    /// Kept, and now narrower in meaning: UNKNOWN on this path can only come
    /// from a dispatch that failed, never from a workload nobody started.
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
    fn resolve_launch_wasm_module_skips_kernel_initrd_and_verity() {
        // The launch resolver validates $MVM_IMAGES_DIR even for a wasm module
        // (which uses none of its contents), and a concurrent doctor test
        // points it at a "missing" path to exercise the refusal. Hold the env
        // guard and unset it: resolution then selects a sibling checkout or the
        // released set, neither of which a wasm module reads — and is immune
        // to an ambient MVM_IMAGES_DIR in the developer's shell.
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.remove(mvm_build::image_source::MVM_IMAGES_DIR_ENV);
        let module_path = "/tmp/dummy.wasm";
        let image = ImageSource::WasmModule {
            module_path: module_path.to_string(),
            label: "wasm:test".to_string(),
        };
        let no_assets: &[crate::commands::shared::AssetSpec] = &[];
        let shape = LaunchShape {
            assets: no_assets,
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
            gpu: false,
            gpu_device: None,
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
            include: Vec::new(),
            exclude: Vec::new(),
        };
        let req = ExecRequest {
            name: Some("named-vm".into()),
            warm_pool_size: 3,
            standby_refill: None,
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
            assets: Vec::new(),
            stdin: b"ignored".to_vec(),
            healthcheck: None,
            hypervisor: Some("mock".into()),
            gpu: false,
            gpu_device: None,
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
            assets: &[],
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
            sdk_host_services: &[],
            declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
            hypervisor: Some("mock"),
            gpu: false,
            gpu_device: None,
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
    fn slow_preparation_does_not_age_the_grant_window_before_admission() {
        let minted = prepare_then_admit(
            || {
                std::thread::sleep(std::time::Duration::from_millis(40));
                Ok(())
            },
            || Ok(std::time::Instant::now()),
        )
        .expect("preparation then admission succeeds");

        assert!(
            minted.elapsed() < std::time::Duration::from_millis(20),
            "the grant window must start when admission runs, not before preparation"
        );
    }

    #[test]
    fn post_admission_lowering_refusal_retains_the_exact_audit_owner() {
        let owner = std::cell::RefCell::new(Some("admitted-authority"));
        let error = finish_cli_cold_lowering::<_, ()>(
            &owner,
            Err(anyhow::anyhow!("built-pack preparation refused")),
        )
        .expect_err("post-admission lowering must refuse");
        assert!(error.to_string().contains("built-pack"));
        assert_eq!(
            owner.into_inner(),
            Some("admitted-authority"),
            "sidecar or built-pack refusal keeps the owner for failure/output audit"
        );
    }

    // -- snapshot_eligible --

    fn prebuilt() -> ImageSource {
        ImageSource::Prebuilt {
            kernel_path: "/k".into(),
            rootfs_path: "/r".into(),
            initrd_path: None,
            label: "lbl".into(),
            unpacked_oci_root: None,
        }
    }

    /// An OCI-derived prebuilt and the cached dev image take different
    /// initrds, and only the first has an unpacked tree.
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
    fn target_command_launch_plan_quotes_argv() {
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            standby_refill: None,
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
            assets: Vec::new(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
            gpu: false,
            gpu_device: None,
            sdk_host_services: Vec::new(),
            declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
        };
        assert_eq!(req.target_command(), "exec 'python' '-m' 'x'");
    }

    #[test]
    fn snapshot_eligible_false_for_prebuilt_image() {
        // The bundled default image isn't a registered template — no snapshot exists.
        assert!(!snapshot_eligible(
            &prebuilt(),
            &[],
            true,
            mvm_core::vm_backend::SnapshotCapability::LiveMemory
        ));
    }
}
