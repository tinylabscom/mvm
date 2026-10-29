//! Boot, restore and tear down one transient microVM.
//!
//! The lifecycle `run_inner` drives between resolving a launch and running a
//! command in the guest: claim a warm standby or cold-boot, optionally restore
//! from a template snapshot instead, and reap the VM and its state dir on the
//! way out — including on Ctrl-C, which is why the teardown flag is installed
//! here rather than at the call site.

use super::*;

/// Everything [`boot_transient_vm`] needs beyond the caller-varying
/// `vm_name` / `use_snapshot`.
pub(super) struct BootAttempt<'a> {
    pub(super) backend: &'a AnyBackend,
    pub(super) start_config: &'a VmStartConfig,
    pub(super) resolved: &'a ResolvedImage,
    /// The caller named this VM. A named run has an identity a shared standby
    /// cannot take on, so it keeps its cold path instead of requiring a claim.
    pub(super) user_named: bool,
}

/// Claim a warm standby for this attempt, or learn why it boots cold.
fn claim_warm_standby(
    attempt: &BootAttempt<'_>,
) -> Result<crate::commands::pool::WarmClaimOutcome> {
    crate::commands::pool::try_warm_claim(attempt.backend, attempt.start_config, attempt.user_named)
}

/// The VM a transient boot produced.
pub(super) struct BootedVm {
    /// The effective VM name — a claimed standby runs under its own standby
    /// id, not the requested name.
    pub(super) name: String,
    pub(super) launch_mode: crate::commands::vm::phase_timing::LaunchMode,
    /// Why the launch booted cold, or `None` when it claimed a standby.
    pub(super) cold_reason: Option<crate::commands::pool::ColdStartReason>,
}

/// Boot the transient VM: try to claim a warm standby first, then a
/// snapshot restore (when eligible), then fall back to a cold boot from
/// `attempt.start_config`. Reaps expired standbys first — best-effort TTL
/// housekeeping since there is no daemon to do it between invocations.
///
/// Returns the booted VM — a claimed standby runs under its own standby id,
/// not `vm_name` — and, for a cold boot, the reason no standby served it. A
/// failed snapshot restore is not fatal: the launch warns, drops the partial
/// restore state, and boots cold. A cold-boot failure returns the error after
/// the normal transient state cleanup path.
pub(super) fn boot_transient_vm(
    vm_name: String,
    use_snapshot: bool,
    attempt: &BootAttempt<'_>,
    mut warm_claim_marks: Option<&mut crate::commands::vm::phase_timing::WarmClaimMarks>,
    sub: &mut crate::commands::vm::phase_timing::LaunchSubMarks,
) -> Result<BootedVm> {
    use crate::commands::vm::phase_timing::SubPhase;

    let phase_timing = warm_claim_marks.is_some();
    let boot_started = phase_timing.then(std::time::Instant::now);
    if let Some(marks) = warm_claim_marks.as_mut() {
        marks.pool_wait_started = boot_started;
    }
    // The per-phase warm-claim lines are a human diagnostic; the marks above
    // feed the machine-readable sample and are collected whenever either is
    // asked for.
    //
    // Each line is the span since the previous mark, not the elapsed time since
    // boot started. Reporting cumulative time under span-shaped names
    // (`standby_reap=0.0ms warm_claim=4.1ms`) reads as two durations that sum,
    // when it was really two timestamps — so the reap looked free and the claim
    // absorbed its cost.
    let render_phases = crate::commands::vm::phase_timing::enabled();
    let previous_mark = std::cell::Cell::new(boot_started);
    let report_phase = |phase: &'static str| {
        let Some(since) = previous_mark.get().filter(|_| render_phases) else {
            return;
        };
        let now = std::time::Instant::now();
        previous_mark.set(Some(now));
        eprintln!(
            "[mvm] warm-claim-phase: {phase}={:.1}ms",
            now.saturating_duration_since(since).as_secs_f64() * 1_000.0
        );
    };
    // Reap dead/expired standbys before claiming/booting. There is no daemon, so
    // this on-use reap is what enforces the standby TTL between invocations —
    // without it a one-off run (or runs against different images) leaves warm
    // spares resident until a manual `cache prune`. Best-effort; never blocks.
    crate::commands::pool::reap_stale_standbys_best_effort();
    report_phase("standby_reap");

    if let Some(marks) = warm_claim_marks.as_mut() {
        marks.claim_started = phase_timing.then(std::time::Instant::now);
    }

    // Try a warm-pool claim before snapshot/cold-boot. A claimed standby is
    // pre-booted to agent-ready and runs under its own standby-id, so the
    // returned name diverges from `vm_name` — the caller rebinds it for the
    // Ctrl-C handler, run_in_guest, and teardown. try_warm_claim gates
    // internally (an auto-named launch of a shape a shared parent can serve,
    // a non-zero standby target, admitted tenant + signed plan threaded into
    // start_config, backend supports the pool). Finding no standby is not an
    // error: the launch boots cold, and says so when a standby could have
    // served it. Only a residency the operator set by name on a backend with
    // no pool is returned as an actionable error.
    let (vm_name, cold_reason) = match claim_warm_standby(attempt) {
        Ok(crate::commands::pool::WarmClaimOutcome::Claimed(id)) => {
            ui::info(&format!(
                "Claimed a warm standby ({}) — skipping cold boot.",
                id.0
            ));
            (id.0, None)
        }
        Ok(crate::commands::pool::WarmClaimOutcome::Cold(reason)) => {
            if let Some(declaration) = reason.declaration() {
                ui::notice(declaration);
            }
            (vm_name, Some(reason))
        }
        Err(e) => return Err(e).context("claiming configured warm standby"),
    };
    let warm_claimed = cold_reason.is_none();
    report_phase("warm_claim");

    let booted = warm_claimed
        || if use_snapshot {
            let tmpl = attempt
                .resolved
                .template_id
                .as_deref()
                .expect("snapshot_eligible only true for ImageSource::Template");
            let snap = attempt
                .resolved
                .snap_info
                .as_ref()
                .expect("snapshot_eligible requires snap_info.is_some()");
            ui::info(&format!(
                "Restoring transient VM '{vm_name}' from template '{tmpl}' snapshot..."
            ));
            // A restored guest resumes already running; there is no activation
            // left to hold it behind the admission's sync.
            attempt.start_config.wait_for_admission_durability()?;
            match restore_via_snapshot(&vm_name, tmpl, snap, attempt.start_config) {
                Ok(()) => true,
                Err(e) => {
                    // A snapshot is a boot accelerator, never a requirement:
                    // a missing, corrupt, or incompatible one degrades to the
                    // cold boot below rather than failing the launch. The
                    // attempt may have left partial state behind (a reserved
                    // slot's run-info.json), which the cold boot would
                    // otherwise inherit.
                    ui::warn(&format!(
                        "Snapshot restore failed ({e:#}) — booting '{vm_name}' cold instead."
                    ));
                    remove_transient_state_dir(
                        &mvm_core::config::vm_state_dir(&vm_name).to_string_lossy(),
                    );
                    false
                }
            }
        } else {
            false
        };

    if !booted {
        ui::info(&format!("Booting transient VM '{vm_name}'..."));
        if mvm_runtime::catalog::descriptor(attempt.backend.kind()).is_workload
            && let Err(error) =
                mvm_hostd::plan_admission::stash_plan_for_bridge(attempt.start_config)
        {
            remove_transient_state_dir(&mvm_core::config::vm_state_dir(&vm_name).to_string_lossy());
            return Err(error)
                .context("persisting admitted transient plan and guest verb grant before boot");
        }
        let phase = mvm_runtime::ui::activity::start(format!(
            "Booting the VM ({})",
            attempt.backend.name()
        ));
        sub.start(SubPhase::VmmCreate);
        if let Err(e) = attempt.backend.start(attempt.start_config) {
            drop(phase);
            emit_guest_console_diagnostic(&vm_name);
            remove_transient_state_dir(&mvm_core::config::vm_state_dir(&vm_name).to_string_lossy());
            return Err(e).context("starting transient microVM");
        }
        // How far into guest boot `start` has already gone is backend-defined
        // — a backend that confirms boot before returning leaves almost
        // nothing for the span below. Splitting VMM setup from guest boot
        // needs marks inside the driver, not here.
        sub.finish(SubPhase::VmmCreate);
        sub.start(SubPhase::GuestKernelEntry);
        phase.finish();
    }
    let launch_mode = if warm_claimed {
        crate::commands::vm::phase_timing::LaunchMode::Warm
    } else {
        crate::commands::vm::phase_timing::LaunchMode::Cold
    };
    Ok(BootedVm {
        name: vm_name,
        launch_mode,
        cold_reason,
    })
}

/// The start mode a launch records, from why it booted cold (`None` when it
/// claimed a standby).
pub(super) fn start_mode(
    cold_reason: Option<crate::commands::pool::ColdStartReason>,
) -> mvm_client::admission::StartMode {
    match cold_reason {
        None => mvm_client::admission::StartMode::Warm,
        Some(reason) => mvm_client::admission::StartMode::Cold {
            reason: reason.label(),
        },
    }
}

/// The standby this run leaves behind, if any: a run that claimed one replaces
/// it, and a run a standby could have served but did not prepares one. Any
/// other cold boot — a named run, a shape a shared parent cannot serve, a host
/// that keeps no standbys — leaves nothing, since nothing could claim it.
pub(super) fn standby_to_leave(
    refill: Option<&crate::commands::pool::StandbyRefill>,
    cold_reason: Option<crate::commands::pool::ColdStartReason>,
) -> Option<&crate::commands::pool::StandbyRefill> {
    match cold_reason {
        None => refill,
        Some(reason) if reason.leaves_a_standby() => refill,
        Some(_) => None,
    }
}

/// The point in a run at which [`leave_standby_when`] is called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LeaveAt {
    AfterBoot,
    AfterWorkload,
}

/// Start the refill for `refill` if this is the point the run's launch mode
/// starts it at. A cold boot is already past the startup ceiling's concern,
/// so its replacement starts right after boot and is ready that much sooner.
/// A warm claim's replacement waits for the workload, so it never competes
/// with the launch it is measured against.
pub(super) fn leave_standby_when(
    refill: Option<&crate::commands::pool::StandbyRefill>,
    launch_mode: crate::commands::vm::phase_timing::LaunchMode,
    at: LeaveAt,
) {
    use crate::commands::vm::phase_timing::LaunchMode;
    let due = matches!(
        (launch_mode, at),
        (LaunchMode::Cold, LeaveAt::AfterBoot) | (LaunchMode::Warm, LeaveAt::AfterWorkload)
    );
    if due && let Some(refill) = refill {
        crate::commands::pool::schedule_standby_refill(refill);
    }
}

/// Arm the Ctrl-C handler for this transient run: on interrupt, flag the
/// returned `AtomicBool` and best-effort stop the VM immediately, rather
/// than waiting for the in-flight guest command to return. The normal
/// teardown sequence still runs afterward when the run returns — this only
/// shortens the window an interrupted VM stays up.
pub(super) fn install_ctrlc_teardown(
    vm_name: &str,
    backend_name: &str,
) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
    let interrupted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let handler_interrupted = interrupted.clone();
    let vm_name = vm_name.to_string();
    let backend_name = backend_name.to_string();
    let _ = crate::signal::set_ctrlc_handler(move |_signal| {
        handler_interrupted.store(true, std::sync::atomic::Ordering::SeqCst);
        let backend = AnyBackend::from_hypervisor(&backend_name);
        let _ = backend.stop_transient(&VmId(vm_name.clone()));
    });
    interrupted
}

pub(super) fn has_writable_disk(volumes: &[VmVolume]) -> bool {
    volumes
        .iter()
        .any(|volume| volume.materialized_image.is_none() && !volume.read_only)
}

/// Ask the authenticated guest agent to flush every filesystem before the VMM
/// is force-stopped. The existing sleep-preparation verb is a control-plane
/// lifecycle operation and adds no new guest capability or transport surface.
pub(super) fn flush_writable_disks_before_teardown(
    vm_name: &str,
    volumes: &[VmVolume],
) -> Result<()> {
    if !has_writable_disk(volumes) {
        return Ok(());
    }

    let transport = vsock_transport::for_vm(vm_name)
        .with_context(|| format!("resolving guest transport for '{vm_name}' filesystem flush"))?;
    let mut stream = transport
        .connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
        .with_context(|| format!("connecting to guest '{vm_name}' for filesystem flush"))?;
    let timeout = std::time::Duration::from_secs(mvm_agentd::vsock::DEFAULT_TIMEOUT_SECS);
    stream
        .set_read_timeout(Some(timeout))
        .context("bounding the guest filesystem-flush response")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("bounding the guest filesystem-flush request")?;

    let verb = "sleep-prep";
    mvm_core::audit_emit!(
        NetworkPolicyAllow,
        vm: vm_name,
        "scope=rpc,direction=in,kind=vsock,verb={verb}",
        verb = verb,
    );
    let acknowledged = mvm_agentd::vsock::request_sleep_prep_on(
        &mut stream,
        mvm_agentd::vsock::DEFAULT_TIMEOUT_SECS,
    )
    .with_context(|| format!("requesting guest '{vm_name}' filesystem flush"))?;
    if !acknowledged {
        anyhow::bail!("guest '{vm_name}' did not acknowledge its filesystem flush");
    }
    Ok(())
}

pub(super) fn combine_run_and_flush<T>(run: Result<T>, flush: Result<()>) -> Result<T> {
    match (run, flush) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(flush_error)) => Err(flush_error),
        (Err(run_error), Ok(())) => Err(run_error),
        (Err(run_error), Err(flush_error)) => Err(run_error.context(format!(
            "guest filesystem flush also failed before teardown: {flush_error:#}"
        ))),
    }
}

/// Tear down the transient VM after the guest command finishes (or fails to
/// dispatch): stop the backend VM, top up the warm pool toward its target,
/// and remove the host VM state directory (`~/.mvm/vms/<name>`), which includes
/// backend files such as `hvf.pid` / `console.log`.
///
/// The caller invokes this unconditionally after capturing the guest
/// command's `Result` in a local — there is no `?` between the backend
/// start and this call, so teardown always runs on both the success and
/// error paths.
pub(super) fn teardown_transient_vm(
    backend: &AnyBackend,
    vm_name: &str,
    requested_vm_name: &str,
    exit_audit: Option<mvm_client::launch::TransientExitAudit<'_>>,
    sub: &mut crate::commands::vm::phase_timing::LaunchSubMarks,
) {
    use crate::commands::vm::phase_timing::SubPhase;

    sub.start(SubPhase::StopTransient);
    let (stop_error, stop_timing) = match backend.stop_transient(&VmId(vm_name.to_string())) {
        Ok(timing) => (None, timing),
        Err(error) => {
            let error = format!("{error:#}");
            tracing::warn!(
                error = %error,
                machine = vm_name,
                "transient stop failed; refusing to seal a potentially live session"
            );
            (Some(error), None)
        }
    };
    sub.finish(SubPhase::StopTransient);
    sub.record_stop_timing(stop_timing);

    // A potentially live session is never sealed, but its end is always
    // recorded: either the seal, or the reason there is none. The audit calls
    // record their own failures.
    if let Some(exit_audit) = exit_audit {
        match stop_error {
            Some(error) => mvm_client::launch::record_transient_stop_failure(exit_audit, &error),
            None => {
                let _ = mvm_client::launch::record_transient_exit(exit_audit);
            }
        }
    }

    // Refilling the pool is not this VM's cleanup: it boots a standby parent
    // for the *next* launch and holds nothing this launch owns. Doing it here
    // cost a measured 1026ms p50 on a launch whose own dispatch window was
    // 27ms, so a run spent three quarters of its wall clock provisioning for a
    // successor that might never come. Filling the pool is explicit
    // (`mvmctl pool warm`), which is what the same reasoning already settled on
    // for the image-bound rewarm: teardown does not spawn background work that
    // can contend with foreground launches, and it no longer does the work
    // inline either. A launch that finds no claimable standby cold-boots, which
    // is far cheaper than building one first.

    sub.start(SubPhase::StateRemove);
    let state_dir = mvm_core::config::vm_state_dir(vm_name);
    let requested_state_dir = mvm_core::config::vm_state_dir(requested_vm_name);
    remove_transient_state_dirs(&state_dir, &requested_state_dir);
    sub.finish(SubPhase::StateRemove);
}

/// Remove both state directories involved in a transient launch. A warm-pool
/// claim may replace the generated request name with a standby id, while plan
/// admission has already persisted state under the generated name.
pub(super) fn remove_transient_state_dirs(effective_dir: &Path, requested_dir: &Path) {
    if std::env::var_os("MVM_PRESERVE_TRANSIENT_STATE").is_some() {
        eprintln!("[mvm] Preserving transient state dirs: {effective_dir:?} {requested_dir:?}");
        return;
    }
    remove_transient_state_dir(&effective_dir.to_string_lossy());
    if effective_dir != requested_dir {
        remove_transient_state_dir(&requested_dir.to_string_lossy());
    }
}

/// Restore a transient microVM from a template snapshot instead of cold-booting.
///
/// Mirrors the snapshot path in `cmd_run`: allocate a slot, build a
/// `FlakeRunConfig` matching the snapshot's recorded layout, then call
/// `microvm::restore_from_template_snapshot`. The caller is responsible for
/// ensuring the request is `snapshot_eligible` first (no directory shares,
/// template image source).
pub(super) fn restore_via_snapshot(
    vm_name: &str,
    template_id: &str,
    snap_info: &mvm_core::template::SnapshotInfo,
    start_config: &VmStartConfig,
) -> Result<()> {
    let slot = mvm_runtime::microvm::allocate_slot(vm_name)?;
    let run_config = mvm_runtime::microvm::FlakeRunConfig {
        name: vm_name.to_string(),
        slot,
        vmlinux_path: start_config.kernel_path.clone().unwrap_or_default(),
        initrd_path: start_config.initrd_path.clone(),
        rootfs_path: start_config.rootfs_path.clone(),
        verity_path: start_config.verity_path.clone(),
        roothash: start_config.roothash.clone(),
        runtime_overlay_path: start_config.runtime_overlay_path.clone(),
        runtime_overlay_verity_path: start_config.runtime_overlay_verity_path.clone(),
        runtime_overlay_roothash: start_config.runtime_overlay_roothash.clone(),
        revision_hash: start_config.revision_hash.clone(),
        flake_ref: start_config.flake_ref.clone(),
        profile: start_config.profile.clone(),
        cpus: start_config.cpus,
        memory: start_config.memory_mib,
        // Inherit the balloon decision from the start_config. The
        // snapshot path is rare for balloon-enabled workloads (FC
        // snapshots don't checkpoint balloon state cleanly), but
        // we preserve the field so a future fix doesn't have to
        // re-thread it.
        mem_initial: start_config.mem_initial_mib,
        // Snapshot-eligible callers have no extra volumes; if that ever
        // changes the snapshot layout will mismatch and Firecracker will
        // refuse to load — `snapshot_eligible` enforces this.
        volumes: Vec::new(),
        config_files: Vec::new(),
        secret_files: Vec::new(),
        ports: Vec::new(),
    };
    let rev = if mvm_core::manifest::is_slot_hash_dirname(template_id) {
        mvm_runtime::vm::template::lifecycle::current_revision_id_for_slot(template_id)?
    } else {
        mvm_runtime::vm::template::lifecycle::current_revision_id(template_id)?
    };
    let snap_dir = if mvm_core::manifest::is_slot_hash_dirname(template_id) {
        mvm_core::manifest::slot_snapshot_dir(template_id, &rev)
    } else {
        mvm_core::template::template_snapshot_dir(template_id, &rev)
    };
    mvm_runtime::microvm::restore_from_template_snapshot(
        template_id,
        &run_config,
        &snap_dir,
        snap_info,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume(materialized_image: Option<&str>, read_only: bool) -> VmVolume {
        VmVolume {
            materialized_image: materialized_image.map(str::to_string),
            read_only,
            ..Default::default()
        }
    }

    #[test]
    fn only_a_writable_disk_requires_a_pre_teardown_flush() {
        let writable_disk = volume(None, false);
        let read_only_disk = volume(None, true);
        let directory = volume(Some("/state/mount.ext4"), false);

        assert!(has_writable_disk(&[writable_disk]));
        assert!(!has_writable_disk(&[read_only_disk]));
        assert!(!has_writable_disk(&[directory]));
        assert!(!has_writable_disk(&[]));
    }

    #[test]
    fn a_flush_failure_replaces_success_and_preserves_a_run_failure() {
        let flush_failed = anyhow::anyhow!("flush unavailable");
        let error = combine_run_and_flush::<i32>(Ok(0), Err(flush_failed))
            .expect_err("a successful workload cannot hide a failed flush");
        assert!(error.to_string().contains("flush unavailable"), "{error:#}");

        let run_failed = anyhow::anyhow!("workload failed");
        let flush_failed = anyhow::anyhow!("flush unavailable");
        let error = combine_run_and_flush::<i32>(Err(run_failed), Err(flush_failed))
            .expect_err("both failures must remain an error");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("workload failed"), "{rendered}");
        assert!(rendered.contains("flush unavailable"), "{rendered}");
    }

    #[test]
    fn a_successful_flush_preserves_the_workload_outcome() {
        assert_eq!(combine_run_and_flush(Ok(7), Ok(())).unwrap(), 7);
        let error = combine_run_and_flush::<i32>(Err(anyhow::anyhow!("workload failed")), Ok(()))
            .expect_err("a flush must not hide the workload failure");
        assert!(error.to_string().contains("workload failed"), "{error:#}");
    }

    fn resolved_image() -> ResolvedImage {
        ResolvedImage {
            vmlinux: "/k/vmlinux".into(),
            initrd: None,
            rootfs: "/vol/rootfs.ext4".into(),
            revision: "rev".into(),
            flake_ref: "image".into(),
            profile: None,
            snap_info: None,
            template_id: None,
        }
    }

    /// A resolved template image carrying snapshot metadata, as
    /// `snapshot_eligible` requires before the restore path runs.
    fn snapshot_resolved_image() -> ResolvedImage {
        ResolvedImage {
            template_id: Some("tmpl".into()),
            snap_info: Some(mvm_core::template::SnapshotInfo {
                created_at: "2026-01-01T00:00:00Z".into(),
                vmstate_size_bytes: 1,
                mem_size_bytes: 1,
                boot_args: String::new(),
                vcpus: 2,
                mem_mib: 1024,
                compatibility: None,
            }),
            ..resolved_image()
        }
    }

    /// A shape the pool could serve, on a host holding no standbys.
    fn claimable_config_without_a_pool() -> VmStartConfig {
        VmStartConfig {
            warm_pool_size: 0,
            kernel_path: Some("/k/vmlinux".into()),
            rootfs_path: "/vol/rootfs.ext4".into(),
            cpus: 2,
            memory_mib: 1024,
            tenant_id: Some("tenant-a".into()),
            plan_json: Some("{}".into()),
            ..Default::default()
        }
    }

    #[test]
    fn a_run_leaves_a_standby_only_where_a_later_run_could_claim_it() {
        use crate::commands::pool::{ColdStartReason, StandbyRefill};
        let refill = StandbyRefill {
            image: Some("alpine".into()),
            cpus: 2,
            memory_mib: 512,
            egress: false,
        };
        // A claim replaces what it took; a launch that found none prepares one.
        assert_eq!(standby_to_leave(Some(&refill), None), Some(&refill));
        assert_eq!(
            standby_to_leave(Some(&refill), Some(ColdStartReason::NoStandbyReady)),
            Some(&refill)
        );
        for reason in [
            ColdStartReason::Named,
            ColdStartReason::IneligibleShape,
            ColdStartReason::StandbysDisabled,
            ColdStartReason::BackendUnsupported,
            ColdStartReason::Unadmitted,
        ] {
            assert_eq!(standby_to_leave(Some(&refill), Some(reason)), None);
        }
        // A source the refill cannot resolve leaves nothing either way.
        assert_eq!(standby_to_leave(None, None), None);
    }

    #[test]
    fn the_recorded_start_mode_names_the_cold_reason() {
        use crate::commands::pool::ColdStartReason;
        assert_eq!(start_mode(None), mvm_client::admission::StartMode::Warm);
        assert_eq!(
            start_mode(Some(ColdStartReason::NoStandbyReady)),
            mvm_client::admission::StartMode::Cold {
                reason: "no_standby_ready"
            }
        );
    }

    #[test]
    fn a_named_transient_run_keeps_its_cold_path_without_a_standby() {
        let backend = AnyBackend::from_hypervisor("firecracker");
        let start_config = claimable_config_without_a_pool();
        let resolved = resolved_image();
        let attempt = BootAttempt {
            backend: &backend,
            start_config: &start_config,
            resolved: &resolved,
            user_named: true,
        };
        assert_eq!(
            claim_warm_standby(&attempt).unwrap(),
            crate::commands::pool::WarmClaimOutcome::Cold(
                crate::commands::pool::ColdStartReason::Named
            )
        );
    }

    /// The strict-startup refusal is gone: the first unnamed run of an image
    /// on a host with an empty pool boots cold rather than failing and
    /// telling the operator to prepare a standby first.
    #[test]
    fn an_unnamed_run_with_no_standby_ready_boots_cold_instead_of_refusing() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().expect("tempdir");
        env.isolate_mvm_home(tmp.path());
        env.remove("MVM_RESIDENCY");
        env.remove("MVM_HVF_WARM_REQUIRE_CLAIM");
        let kernel = tmp.path().join("vmlinux");
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&kernel, b"kernel").expect("write kernel");
        std::fs::write(&rootfs, b"rootfs").expect("write rootfs");
        let backend = AnyBackend::from_hypervisor("firecracker");
        let start_config = VmStartConfig {
            warm_pool_size: 1,
            kernel_path: Some(kernel.display().to_string()),
            rootfs_path: rootfs.display().to_string(),
            ..claimable_config_without_a_pool()
        };
        let resolved = resolved_image();
        let attempt = BootAttempt {
            backend: &backend,
            start_config: &start_config,
            resolved: &resolved,
            user_named: false,
        };
        assert_eq!(
            claim_warm_standby(&attempt).unwrap(),
            crate::commands::pool::WarmClaimOutcome::Cold(
                crate::commands::pool::ColdStartReason::NoStandbyReady
            )
        );
    }

    #[test]
    fn a_host_keeping_no_standbys_boots_cold_without_looking() {
        let backend = AnyBackend::from_hypervisor("firecracker");
        let start_config = claimable_config_without_a_pool();
        let resolved = resolved_image();
        let attempt = BootAttempt {
            backend: &backend,
            start_config: &start_config,
            resolved: &resolved,
            user_named: false,
        };
        assert_eq!(
            claim_warm_standby(&attempt).unwrap(),
            crate::commands::pool::WarmClaimOutcome::Cold(
                crate::commands::pool::ColdStartReason::StandbysDisabled
            )
        );
    }

    #[test]
    fn warm_claim_cleanup_removes_requested_and_effective_state_dirs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let requested = tmp.path().join("requested");
        let effective = tmp.path().join("standby");
        std::fs::create_dir_all(&requested).expect("create requested state dir");
        std::fs::create_dir_all(&effective).expect("create effective state dir");
        std::fs::write(requested.join("plan.json"), b"plan").expect("write requested plan");
        std::fs::write(effective.join("console.log"), b"console").expect("write console");

        remove_transient_state_dirs(&effective, &requested);

        assert!(
            !requested.exists(),
            "the pre-claim plan dir must be removed"
        );
        assert!(
            !effective.exists(),
            "the claimed standby dir must be removed"
        );
    }

    /// A snapshot restore that cannot complete — here the shell-backed slot
    /// allocation has no Linux environment behind it — warns and boots cold
    /// instead of failing the launch, dropping the partial state the attempt
    /// reserved so the cold boot does not inherit it.
    #[test]
    fn a_failed_snapshot_restore_falls_back_to_a_cold_boot() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.remove("MVM_RESIDENCY");
        env.remove("MVM_HVF_WARM_REQUIRE_CLAIM");
        // Every shell op answers empty output: `allocate_slot` finds no slot
        // index in it, so the restore fails before reaching the snapshot load.
        let _shell = mvm_vmm::host::shell::mock::install_handler(|_| {
            mvm_vmm::host::shell::mock::MockResponse::empty()
        });
        // The partial state a failed attempt leaves behind: the reserved
        // slot's run-info.json under the VM's state dir.
        let state_dir = mvm_core::config::vm_state_dir("vm-snap");
        std::fs::create_dir_all(&state_dir).expect("create state dir");
        std::fs::write(
            state_dir.join("run-info.json"),
            br#"{"slot_reserved":true}"#,
        )
        .expect("write slot reservation");

        let mock = mvm_runtime::MockBackend::new();
        let backend = AnyBackend::Mock(mock.clone());
        let start_config = VmStartConfig {
            name: "vm-snap".into(),
            ..claimable_config_without_a_pool()
        };
        let resolved = snapshot_resolved_image();
        let attempt = BootAttempt {
            backend: &backend,
            start_config: &start_config,
            resolved: &resolved,
            user_named: false,
        };
        let mut sub = crate::commands::vm::phase_timing::LaunchSubMarks::default();
        let booted = boot_transient_vm("vm-snap".to_string(), true, &attempt, None, &mut sub)
            .expect("a failed restore must degrade to a cold boot, not fail the launch");

        assert_eq!(booted.name, "vm-snap");
        assert_eq!(
            booted.launch_mode,
            crate::commands::vm::phase_timing::LaunchMode::Cold
        );
        assert_eq!(mock.count(), 1, "the cold path must boot the VM");
        assert!(
            !state_dir.exists(),
            "the partial restore state must be removed before the cold boot"
        );
    }
}
