//! The machines already running on this host, and the cores each may use.
//!
//! A machine is running when its state dir carries a pid marker naming a live
//! process, the same probe the admission budget counts by. Its cores are the
//! set its scope was born confined to, or every online core when it was not
//! confined. Which unit it runs is the owner record written when its placement
//! read back as admitted, bound to the pid of the process that boot started.
//! A machine without a record belongs to no unit. A record that is malformed or
//! names another pid cannot be trusted at all, so the machine reads as
//! unconfined with no owner: it may run on every online core.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_contract::protocol::cpu_set::CpuSet;
use mvm_core::plan::{TenantId, WorkloadId};
use serde::{Deserialize, Serialize};

use mvm_core::spawn_scope::PLACEMENT_OWNER_FILE as OWNER_FILE;

/// The owner record on disk: the owner, and the pid of the boot it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerRecord {
    pid: i32,
    owner: PlacementOwner,
}

/// What a running machine's state dir says about its owner.
#[derive(Debug, Clone, PartialEq, Eq)]
enum OwnerReading {
    /// No record: the machine runs no unit.
    Absent,
    /// A record written by this boot.
    Owner(PlacementOwner),
    /// A record that is malformed or belongs to another boot.
    Untrusted,
}

/// The unit a placed machine runs, and whether its cores are exclusive or
/// the cores left over by exclusive placements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementOwner {
    pub tenant: TenantId,
    pub workload: WorkloadId,
    pub exclusive: bool,
}

/// One running machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveMachine {
    /// The machine's name, which is its state dir's name.
    pub name: String,
    /// The cores its scope was confined to, or `None` when unconfined.
    pub cpus: Option<CpuSet>,
    /// The unit it runs, when its placement was recorded.
    pub owner: Option<PlacementOwner>,
}

/// Every machine running under `home`. A host with no machines dir has none.
pub(super) fn live_machines(home: &Path) -> Vec<LiveMachine> {
    let Ok(entries) = std::fs::read_dir(mvm_core::config::vms_dir_at(home)) else {
        return Vec::new();
    };
    let mut live: Vec<LiveMachine> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|dir| mvm_vmm::host::process_liveness::state_dir_has_live_process(dir))
        .filter_map(|dir| machine_at(&dir))
        .collect();
    live.sort_by(|a, b| a.name.cmp(&b.name));
    live
}

fn machine_at(dir: &Path) -> Option<LiveMachine> {
    let name = dir.file_name()?.to_str()?.to_string();
    let (cpus, owner) = match read_owner(dir, live_pid(dir)) {
        OwnerReading::Absent => (mvm_core::spawn_scope::recorded_cpus(dir), None),
        OwnerReading::Owner(owner) => (mvm_core::spawn_scope::recorded_cpus(dir), Some(owner)),
        OwnerReading::Untrusted => (None, None),
    };
    Some(LiveMachine { name, cpus, owner })
}

/// The pid the state dir's live marker names, if any.
fn live_pid(dir: &Path) -> Option<i32> {
    use mvm_vmm::host::process_liveness::{live_process_pid_file, read_pid_file};
    read_pid_file(&live_process_pid_file(dir)?)
}

fn read_owner(dir: &Path, live_pid: Option<i32>) -> OwnerReading {
    let bytes = match std::fs::read(dir.join(OWNER_FILE)) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return OwnerReading::Absent,
        Err(_) => return OwnerReading::Untrusted,
    };
    match serde_json::from_slice::<OwnerRecord>(&bytes) {
        Ok(record) if Some(record.pid) == live_pid => OwnerReading::Owner(record.owner),
        _ => OwnerReading::Untrusted,
    }
}

/// Record which unit the machine in `state_dir` runs, bound to the pid its
/// live marker names now.
///
/// # Errors
///
/// No live marker, or the record cannot be written. The caller treats either
/// as a failed placement, since a running machine with no owner would refuse
/// its own unit's next generation.
pub(crate) fn record_owner(state_dir: &Path, owner: &PlacementOwner) -> Result<()> {
    let pid = live_pid(state_dir).with_context(|| {
        format!(
            "no live process marker in {} to bind the placement owner to",
            state_dir.display()
        )
    })?;
    let record = OwnerRecord {
        pid,
        owner: owner.clone(),
    };
    let bytes = serde_json::to_vec(&record).context("serializing the placement owner")?;
    mvm_core::util::atomic_io::atomic_write(&state_dir.join(OWNER_FILE), &bytes)
        .with_context(|| format!("recording the placement owner in {}", state_dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> PlacementOwner {
        PlacementOwner {
            tenant: TenantId("t".into()),
            workload: WorkloadId("w".into()),
            exclusive: true,
        }
    }

    /// A state dir whose live marker names this test process.
    fn running_dir(home: &Path, name: &str) -> std::path::PathBuf {
        let dir = mvm_core::config::vm_state_dir_at(home, name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("libkrun.pid"), std::process::id().to_string()).unwrap();
        dir
    }

    #[test]
    fn only_a_machine_with_a_live_pid_marker_is_listed() {
        let home = tempfile::tempdir().unwrap();
        let running = running_dir(home.path(), "running");
        std::fs::create_dir_all(mvm_core::config::vm_state_dir_at(home.path(), "stopped")).unwrap();
        record_owner(&running, &owner()).unwrap();
        std::fs::write(running.join("spawn-scope-cpus"), "2-3").unwrap();

        assert_eq!(
            live_machines(home.path()),
            vec![LiveMachine {
                name: "running".into(),
                cpus: Some(CpuSet::parse("2-3").unwrap()),
                owner: Some(owner()),
            }]
        );
    }

    #[test]
    fn a_host_without_machines_has_none_running() {
        let home = tempfile::tempdir().unwrap();
        assert!(live_machines(home.path()).is_empty());
    }

    #[test]
    fn a_record_without_a_live_marker_cannot_be_written() {
        let dir = tempfile::tempdir().unwrap();
        assert!(record_owner(dir.path(), &owner()).is_err());
    }

    #[test]
    fn a_record_for_another_pid_is_not_trusted_and_reads_as_unconfined() {
        let home = tempfile::tempdir().unwrap();
        let dir = running_dir(home.path(), "reused");
        let stale = OwnerRecord {
            pid: i32::MAX,
            owner: owner(),
        };
        std::fs::write(dir.join(OWNER_FILE), serde_json::to_vec(&stale).unwrap()).unwrap();
        std::fs::write(dir.join("spawn-scope-cpus"), "2-3").unwrap();
        assert_eq!(read_owner(&dir, live_pid(&dir)), OwnerReading::Untrusted);
        assert_eq!(
            live_machines(home.path()),
            vec![LiveMachine {
                name: "reused".into(),
                cpus: None,
                owner: None,
            }]
        );
    }

    #[test]
    fn a_malformed_record_on_a_running_machine_reads_as_unconfined() {
        let home = tempfile::tempdir().unwrap();
        let dir = running_dir(home.path(), "garbled");
        std::fs::write(dir.join(OWNER_FILE), "not json").unwrap();
        std::fs::write(dir.join("spawn-scope-cpus"), "2-3").unwrap();
        assert_eq!(
            live_machines(home.path()),
            vec![LiveMachine {
                name: "garbled".into(),
                cpus: None,
                owner: None,
            }]
        );
    }

    #[test]
    fn a_reused_state_dir_after_an_unconfined_boot_has_no_owner() {
        let home = tempfile::tempdir().unwrap();
        let dir = running_dir(home.path(), "reboot");
        record_owner(&dir, &owner()).unwrap();
        // The next boot of this machine is unconfined; the scope helper clears
        // the previous boot's records as it prepares the scope.
        let scratch = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        mvm_core::spawn_scope::pretend_mechanism_present(&mut env, scratch.path()).unwrap();
        let _ = mvm_core::spawn_scope::bind_spawn(
            std::process::Command::new("/bin/true"),
            "reboot",
            &dir,
            &mvm_core::spawn_scope::SpawnBounds::for_guest_memory(256),
        );
        assert_eq!(read_owner(&dir, live_pid(&dir)), OwnerReading::Absent);
        assert_eq!(live_machines(home.path())[0].owner, None);
    }
}
