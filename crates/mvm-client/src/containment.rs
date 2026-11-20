//! Contain one running workload by machine name: quarantine it, then replace
//! it under a fresh execution epoch. The CLI, the host library and the MCP
//! adapter all call these; the authority and audit logic lives in
//! `mvm_hostd::containment`.
//!
//! Quarantine does not stop the VM. The caller stops it through the ordinary
//! stop path, after this has recorded that the workload may not launch again.

use anyhow::Result;
use mvm_core::host_interface::workload::WorkloadLedger;
use mvm_hostd::audit::{emitter::AuditEmitter, host_keypair, plan_persist};
use mvm_hostd::containment::{CoordinatorWorkloads, WorkloadAuthority};

fn home() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_core::config::mvm_home())
}

fn emitter() -> Result<AuditEmitter> {
    AuditEmitter::new(host_keypair::load_or_init()?.signing)
}

/// The tenant a machine's audit entries belong to: its admitted plan's while
/// that survives, the local default once the VM state directory is gone.
fn tenant_of(name: &str) -> String {
    plan_persist::read_plan(name)
        .map(|p| p.tenant.0)
        .unwrap_or_else(|_| mvm_core::plan::DEFAULT_TENANT.to_owned())
}

/// Is `name` a machine this host has launched? True when its state directory
/// exists, the ledger has recorded it, or the audit chain mentions it. This
/// keeps a typo from minting a ledger entry that a later machine of that name
/// would inherit. Limit: the chain is read under the default tenant, so a
/// machine admitted under another tenant, stopped, and never contained is
/// not recognised.
fn known_workload(name: &str, emitter: &AuditEmitter) -> Result<bool> {
    use mvm_hostd::audit::session::{EventFilter, read_lines_from_genesis, workload_events};
    if home().join("vms").join(name).exists() || WorkloadLedger::load_at(&home())?.knows(name) {
        return Ok(true);
    }
    // No chain file at all reads as an error here, and means "never admitted".
    let Ok(lines) = read_lines_from_genesis(
        emitter.audit_dir(),
        mvm_core::plan::DEFAULT_TENANT,
        &emitter.verifying_key(),
    ) else {
        return Ok(false);
    };
    Ok(!workload_events(&lines, name, &EventFilter::default())?.is_empty())
}

fn ensure_known(name: &str, emitter: &AuditEmitter) -> Result<()> {
    anyhow::ensure!(
        known_workload(name, emitter)?,
        "no machine named {name:?} has been launched on this host"
    );
    Ok(())
}

/// Refuse further launches of machine `name` and record `reason`. Works by
/// name from the ledger and audit log, so a stopped machine can be contained.
/// The ledger change goes through the policy coordinator; with none available
/// this fails rather than writing the ledger locally.
pub fn quarantine(name: &str, reason: &str) -> Result<()> {
    crate::policy_profiles::coordinator::recover_interrupted_publication()?;
    quarantine_with(connect_coordinator, name, reason)
}

/// Authorize a replacement of machine `name`; returns the new execution epoch.
/// Needs no plan: stopping a machine removes its state directory, and replace
/// must work after that.
pub fn replace(name: &str) -> Result<u64> {
    crate::policy_profiles::coordinator::recover_interrupted_publication()?;
    replace_with(connect_coordinator, name)
}

/// Reached only after the machine is known, so a typo spawns nothing.
fn connect_coordinator() -> Result<CoordinatorWorkloads> {
    Ok(CoordinatorWorkloads::new(
        crate::policy_profiles::coordinator::ensure()?,
    ))
}

fn quarantine_with<A: WorkloadAuthority>(
    connect: impl FnOnce() -> Result<A>,
    name: &str,
    reason: &str,
) -> Result<()> {
    let emitter = emitter()?;
    ensure_known(name, &emitter)?;
    let authority = connect()?;
    mvm_hostd::containment::quarantine_named(&authority, &emitter, &tenant_of(name), name, reason)
}

fn replace_with<A: WorkloadAuthority>(
    connect: impl FnOnce() -> Result<A>,
    name: &str,
) -> Result<u64> {
    let emitter = emitter()?;
    ensure_known(name, &emitter)?;
    let authority = connect()?;
    mvm_hostd::containment::replace_named(&authority, &emitter, &tenant_of(name), name).map(|e| e.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_hostd::policy_generation::workload_store::OwnedWorkloadStore;

    #[test]
    fn quarantine_and_replace_by_machine_name_round_trip_through_the_ledger() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .workload("suspect")
            .build();
        plan_persist::write_plan("suspect", &plan).unwrap();
        let store = OwnedWorkloadStore::open(home.path()).unwrap();

        quarantine_with(|| Ok(&store), "suspect", "planted compromise").unwrap();
        let ledger = WorkloadLedger::load_at(home.path()).unwrap();
        assert!(ledger.authorize_local_start("suspect").is_err());
        assert!(ledger.authorize_local_start("other").is_ok());

        assert_eq!(replace_with(|| Ok(&store), "suspect").unwrap(), 2);
        let ledger = WorkloadLedger::load_at(home.path()).unwrap();
        assert!(ledger.authorize_local_start("suspect").is_ok());
    }

    #[test]
    fn replace_works_after_stop_removed_the_machines_plan() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .workload("suspect")
            .build();
        plan_persist::write_plan("suspect", &plan).unwrap();
        let store = OwnedWorkloadStore::open(home.path()).unwrap();
        quarantine_with(|| Ok(&store), "suspect", "planted compromise").unwrap();

        // `machine stop` deletes the VM state directory, plan.json included.
        std::fs::remove_dir_all(home.path().join("vms")).unwrap();
        assert!(plan_persist::read_plan("suspect").is_err());

        let ledger = WorkloadLedger::load_at(home.path()).unwrap();
        assert!(ledger.authorize_local_start("suspect").is_err());
        assert_eq!(replace_with(|| Ok(&store), "suspect").unwrap(), 2);
        // The relaunch is synthesized at the ledger's epoch.
        assert_eq!(
            mvm_core::plan::synthesis::current_local_epoch("suspect").unwrap(),
            2
        );
        let ledger = WorkloadLedger::load_at(home.path()).unwrap();
        assert!(ledger.authorize_local_start("suspect").is_ok());
        assert!(
            plan_persist::read_plan("suspect").is_err(),
            "replace recreates no plan"
        );

        // A second replace with no launch between advances the epoch again.
        assert_eq!(replace_with(|| Ok(&store), "suspect").unwrap(), 3);
    }

    #[test]
    fn an_unknown_machine_is_an_error_not_a_silent_no_op() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let store = OwnedWorkloadStore::open(home.path()).unwrap();
        assert!(quarantine_with(|| Ok(&store), "never-admitted", "x").is_err());
        assert!(replace_with(|| Ok(&store), "never-admitted").is_err());
        let ledger = WorkloadLedger::load_at(home.path()).unwrap();
        assert!(!ledger.knows("never-admitted"), "a typo mints no entry");
    }
}
