use super::*;

#[cfg(feature = "builder-vm")]
pub(super) fn dev_vz_snapshot_exists() -> bool {
    let state_dir = mvm_build::vz_builder::persistent_vz_state_dir(DEV_VM_SESSION_ID);
    mvm_build::vz_builder::builder_snapshot_path(&state_dir).is_file()
}

#[cfg(not(feature = "builder-vm"))]
pub(super) fn dev_vz_snapshot_exists() -> bool {
    false
}

#[cfg(feature = "builder-vm")]
pub(super) fn should_park(allows_persistent: bool, alive: bool, reset: bool) -> bool {
    allows_persistent && alive && !reset
}

#[cfg(feature = "builder-vm")]
pub(super) fn should_resume(allows_persistent: bool, snapshot_present: bool) -> bool {
    allows_persistent && snapshot_present
}

#[cfg(feature = "builder-vm")]
pub(super) fn remove_dev_vz_snapshot_markers(state_dir: &std::path::Path) {
    let snap = mvm_build::vz_builder::builder_snapshot_path(state_dir);
    let mid = mvm_build::vz_builder::builder_snapshot_machine_id_path(&snap);
    let _ = std::fs::remove_file(&snap);
    let _ = std::fs::remove_file(&mid);
}

#[cfg(feature = "builder-vm")]
pub(super) fn wait_for_dev_vm_ready(console_log: &std::path::Path) -> Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if std::time::Instant::now() > deadline {
            anyhow::bail!(
                "Dev VM did not become ready within 60 seconds.\n\
                 Check the console log: {}",
                console_log.display()
            );
        }
        if dev_vm_guest_agent_connect().is_ok() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

#[cfg(feature = "builder-vm")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VzDevResidencyDecision {
    Keep,
    Park,
    Teardown,
}

#[cfg(feature = "builder-vm")]
pub(super) fn decide_vz_dev_residency(
    policy: &mvm_core::residency::ResidencyPolicy,
    running: bool,
    last_activity_unix_secs: Option<u64>,
    now_unix_secs: u64,
) -> VzDevResidencyDecision {
    if !running {
        return VzDevResidencyDecision::Keep;
    }
    match policy.kind() {
        mvm_core::residency::ResidencyKind::Cold => VzDevResidencyDecision::Teardown,
        mvm_core::residency::ResidencyKind::Parked => VzDevResidencyDecision::Park,
        mvm_core::residency::ResidencyKind::Warm => {
            let Some(threshold) = policy.idle_timeout() else {
                return VzDevResidencyDecision::Keep;
            };
            let Some(last) = last_activity_unix_secs else {
                return VzDevResidencyDecision::Keep;
            };
            let idle = std::time::Duration::from_secs(now_unix_secs.saturating_sub(last));
            match mvm_core::residency::decide_builder_residency_action(
                policy.kind(),
                idle,
                threshold,
            ) {
                mvm_core::residency::BuilderResidencyAction::Keep => VzDevResidencyDecision::Keep,
                mvm_core::residency::BuilderResidencyAction::Park => VzDevResidencyDecision::Park,
                mvm_core::residency::BuilderResidencyAction::Teardown => {
                    VzDevResidencyDecision::Teardown
                }
            }
        }
    }
}

#[cfg(feature = "builder-vm")]
fn dev_vz_activity_path(state_dir: &std::path::Path) -> std::path::PathBuf {
    state_dir.join(DEV_VZ_ACTIVITY_FILE)
}

#[cfg(feature = "builder-vm")]
fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(feature = "builder-vm")]
pub(super) fn read_dev_vz_last_activity(state_dir: &std::path::Path) -> Option<u64> {
    let body = std::fs::read_to_string(dev_vz_activity_path(state_dir)).ok()?;
    body.trim().parse().ok()
}

#[cfg(feature = "builder-vm")]
pub(super) fn touch_dev_vz_activity_at(
    state_dir: &std::path::Path,
    now_unix_secs: u64,
) -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    std::fs::write(dev_vz_activity_path(state_dir), now_unix_secs.to_string())
}

#[cfg(feature = "builder-vm")]
pub(in crate::commands) fn touch_dev_vz_activity_now() {
    let state_dir = mvm_build::vz_builder::persistent_vz_state_dir(DEV_VM_SESSION_ID);
    let _ = touch_dev_vz_activity_at(&state_dir, current_unix_secs());
}

#[cfg(feature = "builder-vm")]
pub(super) fn enforce_dev_vz_cold_policy_on_entry(state_dir: &std::path::Path) -> bool {
    let (policy, _source) = mvm_core::residency::resolve_residency();
    if !matches!(policy.kind(), mvm_core::residency::ResidencyKind::Cold) {
        return false;
    }
    remove_dev_vz_snapshot_markers(state_dir);
    if !mvm_build::vz_builder::persistent_vz_supervisor_alive(state_dir) {
        return false;
    }
    mvm_build::vz_builder::stop_persistent_vz_by_pid_file(state_dir);
    let _ = std::fs::remove_dir_all(state_dir.join("vsock"));
    true
}

#[cfg(feature = "builder-vm")]
pub(super) fn enforce_dev_vz_residency_policy() -> Result<Option<VzDevResidencyDecision>> {
    let state_dir = mvm_build::vz_builder::persistent_vz_state_dir(DEV_VM_SESSION_ID);
    let running = mvm_build::vz_builder::persistent_vz_supervisor_alive(&state_dir);
    let (policy, _source) = mvm_core::residency::resolve_residency();
    let decision = decide_vz_dev_residency(
        &policy,
        running,
        read_dev_vz_last_activity(&state_dir),
        current_unix_secs(),
    );
    match decision {
        VzDevResidencyDecision::Keep => Ok(None),
        VzDevResidencyDecision::Park => {
            mvm_build::vz_builder::park_persistent_vz_builder(&state_dir)
                .map_err(|e| anyhow::anyhow!("Failed to park dev VM by residency policy: {e}"))?;
            let _ = std::fs::remove_dir_all(state_dir.join("vsock"));
            Ok(Some(decision))
        }
        VzDevResidencyDecision::Teardown => {
            mvm_build::vz_builder::stop_persistent_vz_by_pid_file(&state_dir);
            let _ = std::fs::remove_dir_all(state_dir.join("vsock"));
            remove_dev_vz_snapshot_markers(&state_dir);
            Ok(Some(decision))
        }
    }
}
