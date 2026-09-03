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
}

/// Boot the transient VM: try to claim a warm standby first, then a
/// snapshot restore (when eligible), then fall back to a cold boot from
/// `attempt.start_config`. Reaps expired standbys first — best-effort TTL
/// housekeeping since there is no daemon to do it between invocations.
///
/// Returns the effective VM name — a claimed standby runs under its own
/// standby id, not `vm_name`. A cold-boot failure returns the error after
/// the normal transient state cleanup path.
pub(super) fn boot_transient_vm(
    vm_name: String,
    use_snapshot: bool,
    attempt: &BootAttempt<'_>,
    mut warm_claim_marks: Option<&mut crate::commands::vm::phase_timing::WarmClaimMarks>,
    sub: &mut crate::commands::vm::phase_timing::LaunchSubMarks,
) -> Result<(String, crate::commands::vm::phase_timing::LaunchMode)> {
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
    // internally (warm_pool_size > 0, admitted tenant + signed plan threaded
    // into start_config, a launch shape a shared parent can serve, backend
    // supports the pool). An explicitly configured but unsupported standby pool
    // is returned as an actionable error; only an ineligible launch shape
    // proceeds cold.
    let (vm_name, warm_claimed) =
        match crate::commands::pool::try_warm_claim(attempt.backend, attempt.start_config, false) {
            Ok(Some(id)) => {
                ui::info(&format!(
                    "Claimed a warm standby ({}) — skipping cold boot.",
                    id.0
                ));
                (id.0, true)
            }
            Ok(None) => (vm_name, false),
            Err(e) => return Err(e).context("claiming configured warm standby"),
        };
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
            match restore_via_snapshot(&vm_name, tmpl, snap, attempt.start_config) {
                Ok(()) => true,
                Err(e) => return Err(e).context("restoring transient VM snapshot"),
            }
        } else {
            false
        };

    if !booted {
        ui::info(&format!("Booting transient VM '{vm_name}'..."));
        sub.start(SubPhase::VmmCreate);
        if let Err(e) = attempt.backend.start(attempt.start_config) {
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
    }
    let launch_mode = if warm_claimed {
        crate::commands::vm::phase_timing::LaunchMode::Warm
    } else {
        crate::commands::vm::phase_timing::LaunchMode::Cold
    };
    Ok((vm_name, launch_mode))
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
    let _ = crate::signal::set_ctrlc_handler(move || {
        handler_interrupted.store(true, std::sync::atomic::Ordering::SeqCst);
        let backend = AnyBackend::from_hypervisor(&backend_name);
        let _ = backend.stop_transient(&VmId(vm_name.clone()));
    });
    interrupted
}

pub(super) fn has_writable_disk(volumes: &[VmVolume]) -> bool {
    volumes
        .iter()
        .any(|volume| volume.kind == mvm_core::vm_backend::VmVolumeKind::Disk && !volume.read_only)
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
    sub: &mut crate::commands::vm::phase_timing::LaunchSubMarks,
) {
    use crate::commands::vm::phase_timing::SubPhase;

    sub.start(SubPhase::StopTransient);
    let stop_timing = backend
        .stop_transient_with_timing(&VmId(vm_name.to_string()))
        .ok()
        .flatten();
    sub.finish(SubPhase::StopTransient);
    sub.record_stop_timing(stop_timing);

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

    fn volume(kind: mvm_core::vm_backend::VmVolumeKind, read_only: bool) -> VmVolume {
        VmVolume {
            kind,
            read_only,
            ..Default::default()
        }
    }

    #[test]
    fn only_a_writable_disk_requires_a_pre_teardown_flush() {
        let writable_disk = volume(mvm_core::vm_backend::VmVolumeKind::Disk, false);
        let read_only_disk = volume(mvm_core::vm_backend::VmVolumeKind::Disk, true);
        let directory = volume(mvm_core::vm_backend::VmVolumeKind::DirShare, false);

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
}
