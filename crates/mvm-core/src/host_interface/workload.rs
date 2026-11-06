//! Per-workload containment: quarantine one workload, then replace it under a
//! fresh execution epoch, without touching the rest of the node.
//!
//! The ledger lives beside the node record. Absent means no workload has been
//! contained, so a plain local run is unaffected. Like the node record, a
//! malformed ledger fails closed.
//!
//! shortcut: read-modify-write without a file lock; two operators racing on one
//! node could lose an update. Add an advisory lock when a second writer exists
//! (the `mvmd` implementation).

use std::{collections::BTreeMap, path::Path};

use serde::{Deserialize, Serialize};

use super::{
    ExecutionEpoch,
    error::{Denial, HostInterfaceError},
};

const FILE: &str = "workloads.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadEntry {
    pub epoch: ExecutionEpoch,
    pub quarantined: bool,
}

impl Default for WorkloadEntry {
    fn default() -> Self {
        Self {
            epoch: ExecutionEpoch(1),
            quarantined: false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkloadLedger(BTreeMap<String, WorkloadEntry>);

impl WorkloadLedger {
    pub fn load_at(home: &Path) -> Result<Self, HostInterfaceError> {
        let path = home.join("host-interface").join(FILE);
        match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| unreadable(&path, &e.to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(unreadable(&path, &e.to_string())),
        }
    }

    pub fn save_at(&self, home: &Path) -> std::io::Result<()> {
        let dir = home.join("host-interface");
        crate::private_fs::ensure_private_dir(&dir)?;
        let tmp = dir.join("workloads.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        crate::private_fs::set_mode(&tmp, 0o600)?;
        std::fs::rename(tmp, dir.join(FILE))
    }

    pub fn entry(&self, workload: &str) -> WorkloadEntry {
        self.0.get(workload).copied().unwrap_or_default()
    }

    /// Contain one workload: it may not launch again until it is replaced.
    pub fn quarantine(&mut self, workload: &str) {
        self.0.entry(workload.to_owned()).or_default().quarantined = true;
    }

    /// Authorize a fresh start under a new epoch; the old epoch is dead.
    pub fn replace(&mut self, workload: &str) -> ExecutionEpoch {
        let e = self.0.entry(workload.to_owned()).or_default();
        e.epoch = e.epoch.next();
        e.quarantined = false;
        e.epoch
    }

    /// Local launch gate: refuses a quarantined workload. It cannot check
    /// staleness because a local start carries no epoch of its own; that is
    /// enforced by [`Self::authorize`] where a command or replacement presents
    /// one (the managed and reconnect paths).
    pub fn authorize_local_start(&self, workload: &str) -> Result<(), Denial> {
        self.authorize(workload, self.entry(workload).epoch)
    }

    /// May `workload` start presenting `epoch`? Quarantine and staleness both
    /// refuse; only the current epoch of a contained-free workload passes.
    pub fn authorize(&self, workload: &str, epoch: ExecutionEpoch) -> Result<(), Denial> {
        let e = self.entry(workload);
        if epoch != e.epoch {
            return Err(Denial::StaleEpoch {
                got: epoch.0,
                current: e.epoch.0,
            });
        }
        if e.quarantined {
            return Err(Denial::WorkloadQuarantined(workload.to_owned()));
        }
        Ok(())
    }
}

fn unreadable(path: &Path, why: &str) -> HostInterfaceError {
    HostInterfaceError::Denied(Denial::StateUnreadable(format!(
        "{}: {why}",
        path.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contain_replace_cycle_only_affects_the_suspect_workload() {
        let mut l = WorkloadLedger::default();
        let start = l.entry("a").epoch;
        assert!(l.authorize("a", start).is_ok() && l.authorize("b", start).is_ok());

        l.quarantine("a");
        assert_eq!(
            l.authorize("a", start),
            Err(Denial::WorkloadQuarantined("a".into()))
        );
        assert!(l.authorize("b", start).is_ok(), "bystander unaffected");

        let fresh = l.replace("a");
        assert!(fresh > start);
        assert!(l.authorize("a", fresh).is_ok());
        assert_eq!(
            l.authorize("a", start),
            Err(Denial::StaleEpoch {
                got: start.0,
                current: fresh.0
            }),
            "the old epoch stays dead after replacement"
        );
    }

    #[test]
    fn ledger_persists_and_a_malformed_one_fails_closed() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(
            WorkloadLedger::load_at(d.path()).unwrap(),
            WorkloadLedger::default()
        );
        let mut l = WorkloadLedger::default();
        l.quarantine("a");
        l.save_at(d.path()).unwrap();
        assert!(
            WorkloadLedger::load_at(d.path())
                .unwrap()
                .entry("a")
                .quarantined
        );
        std::fs::write(d.path().join("host-interface/workloads.json"), b"[").unwrap();
        assert!(WorkloadLedger::load_at(d.path()).is_err());
    }
}
