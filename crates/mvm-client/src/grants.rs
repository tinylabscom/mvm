//! The enforced-grants record a machine carries from boot to `machine inspect`.
//!
//! The tier is read off a live control at boot and is gone the moment the
//! process that read it exits, so a later `inspect` has nothing to answer from
//! unless the boot wrote it down. Showing only the requested grant is the
//! specific confusion the read-back exists to prevent: a request and an
//! enforcement look identical in a spec file, and one of them is a security
//! property.
//!
//! Best-effort in both directions. A boot is not failed because a display
//! record could not be written, and an absent or unreadable record reads as
//! "unknown" rather than as "unenforced" — inventing `Declared` for a file that
//! failed to open would assert something about the run that was never measured.

use std::path::PathBuf;

use mvm_contract::protocol::resource_controls::EnforcedGrants;

/// Filename under the per-VM state directory.
const FILE: &str = "enforced-grants.json";

/// Where a machine's enforced-grants record lives. Routed through
/// `mvm-core::config` so `MVM_HOME` (and worktree isolation) is honored.
fn record_path(vm_name: &str) -> PathBuf {
    mvm_core::config::vm_state_dir(vm_name).join(FILE)
}

/// Persist what actually bounded `vm_name`, as read back after its boot.
///
/// Overwrites: the record describes the current run, and a stale tier from a
/// previous boot is worse than none.
pub fn record_enforced_grants(vm_name: &str, enforced: &EnforcedGrants) {
    let path = record_path(vm_name);
    let Some(parent) = path.parent() else {
        return;
    };
    if let Err(e) = std::fs::create_dir_all(parent) {
        tracing::warn!(error = %e, vm = vm_name, "creating the VM state dir for the enforced-grants record failed (non-fatal)");
        return;
    }
    let json = match serde_json::to_string_pretty(enforced) {
        Ok(json) => json,
        Err(e) => {
            tracing::warn!(error = %e, vm = vm_name, "serializing the enforced-grants record failed (non-fatal)");
            return;
        }
    };
    if let Err(e) = mvm_core::util::atomic_io::atomic_write_str(&path, &json) {
        tracing::warn!(error = %e, vm = vm_name, "writing the enforced-grants record failed (non-fatal)");
    }
}

/// What actually bounded `vm_name` on its last boot, or `None` when no boot
/// recorded it.
#[must_use]
pub fn enforced_grants_of(vm_name: &str) -> Option<EnforcedGrants> {
    let text = std::fs::read_to_string(record_path(vm_name)).ok()?;
    serde_json::from_str(&text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::resource_controls::EnforcedTier;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn a_recorded_tier_reads_back() {
        let home = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let enforced = EnforcedGrants {
            cpu: EnforcedTier::Cgroup2CpuMax,
            wall_clock: EnforcedTier::Declared,
        };
        record_enforced_grants("vm-a", &enforced);
        assert_eq!(enforced_grants_of("vm-a"), Some(enforced));
    }

    /// A machine that never booted must read as unknown, not as unenforced —
    /// "we did not measure" and "we measured nothing" are different answers.
    #[test]
    fn a_machine_with_no_record_reads_as_unknown() {
        let home = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        assert_eq!(enforced_grants_of("vm-never-booted"), None);
    }

    #[test]
    fn a_second_boot_replaces_the_first_boots_tier() {
        let home = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        record_enforced_grants(
            "vm-b",
            &EnforcedGrants {
                cpu: EnforcedTier::Cgroup2CpuMax,
                wall_clock: EnforcedTier::Declared,
            },
        );
        record_enforced_grants("vm-b", &EnforcedGrants::all_declared());
        assert_eq!(
            enforced_grants_of("vm-b"),
            Some(EnforcedGrants::all_declared()),
            "a stale tier from a previous boot would overstate this one"
        );
    }
}
