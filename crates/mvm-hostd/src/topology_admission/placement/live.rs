//! The machines already running on this host, and the cores each may use.
//!
//! A machine is running when its state dir carries a pid marker naming a live
//! process, the same probe the admission budget counts by. Its cores are the
//! set its scope was born confined to, or every online core when it was not
//! confined. Which unit it runs is the owner record written when its placement
//! read back as admitted; a machine without one belongs to no unit.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_contract::protocol::cpu_set::CpuSet;
use mvm_core::plan::{TenantId, WorkloadId};
use serde::{Deserialize, Serialize};

/// The per-VM record naming the unit a placed machine runs.
const OWNER_FILE: &str = "placement-owner.json";

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
    Some(LiveMachine {
        name: dir.file_name()?.to_str()?.to_string(),
        cpus: mvm_core::spawn_scope::recorded_cpus(dir),
        owner: read_owner(dir),
    })
}

/// An unreadable owner record reads as no owner, which is the refusing
/// direction: the machine then belongs to no unit's pair.
fn read_owner(dir: &Path) -> Option<PlacementOwner> {
    serde_json::from_slice(&std::fs::read(dir.join(OWNER_FILE)).ok()?).ok()
}

/// Record which unit the machine in `state_dir` runs.
///
/// # Errors
///
/// The record cannot be written. The caller treats that as a failed
/// placement, since a running machine with no owner would refuse its own
/// unit's next generation.
pub(crate) fn record_owner(state_dir: &Path, owner: &PlacementOwner) -> Result<()> {
    let bytes = serde_json::to_vec(owner).context("serializing the placement owner")?;
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

    #[test]
    fn only_a_machine_with_a_live_pid_marker_is_listed() {
        let home = tempfile::tempdir().unwrap();
        let running = mvm_core::config::vm_state_dir_at(home.path(), "running");
        let stopped = mvm_core::config::vm_state_dir_at(home.path(), "stopped");
        for dir in [&running, &stopped] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(running.join("libkrun.pid"), std::process::id().to_string()).unwrap();
        record_owner(&running, &owner()).unwrap();
        std::fs::write(running.join("spawn-scope-cpus"), "2-3").unwrap();

        let live = live_machines(home.path());
        assert_eq!(
            live,
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
    fn an_unreadable_owner_reads_as_none() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(OWNER_FILE), "not json").unwrap();
        assert_eq!(read_owner(dir.path()), None);
    }
}
