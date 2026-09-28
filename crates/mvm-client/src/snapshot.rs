//! Sealed instance-snapshot inspection and removal.
//!
//! A read/delete surface over `~/.mvm/instances/*/snapshot/` — the artifacts
//! `pause` produces — not the pause/resume lifecycle op itself. It lives
//! here, rather than in the CLI, so `mvmctl snapshot ls/rm` and the host
//! library reach the snapshot store through one implementation, with the
//! same name-registry cleanup and the same audit entries.
//!
//! Sync free functions, not `MvmClient` trait methods: a remote fleet
//! backend has no access to a host-local snapshot store.

use anyhow::{Context, Result};

pub use mvm_runtime::vm::instance_snapshot::{InstanceSnapshotEntry, list_instance_snapshots};

/// Remove a machine's sealed instance snapshot. Returns `true` when a
/// snapshot existed and was removed, `false` when the machine has none.
///
/// The name is validated at the boundary (fail-closed). On success the
/// machine's name-registry entry is un-paused so it can boot normally
/// again, and a `SnapshotDelete` entry is recorded in the audit chain.
pub fn remove_instance_snapshot(vm_name: &str) -> Result<bool> {
    mvm_core::naming::validate_vm_name(vm_name)
        .with_context(|| format!("Invalid VM name: {vm_name:?}"))?;
    let removed = mvm_runtime::vm::instance_snapshot::delete_instance_snapshot(vm_name)?;
    if !removed {
        return Ok(false);
    }
    let registry_path = mvm_runtime::vm::name_registry::registry_path();
    if let Ok(mut registry) = mvm_runtime::vm::name_registry::VmNameRegistry::load(&registry_path) {
        let _ = registry.set_paused(vm_name, false);
        let _ = registry.save(&registry_path);
    }
    mvm_core::audit_emit!(SnapshotDelete, vm: vm_name);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_instance_snapshot_refuses_an_invalid_name_without_touching_state() {
        let err = remove_instance_snapshot("not a vm name!").expect_err("invalid name refused");
        assert!(err.to_string().contains("Invalid VM name"), "{err:#}");
    }

    #[test]
    fn remove_instance_snapshot_reports_absent_snapshot_as_false() {
        let _guard = mvm_runtime::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let removed = remove_instance_snapshot("no-such-machine").expect("lookup runs");
        assert!(!removed, "a machine with no snapshot removes nothing");
    }
}
