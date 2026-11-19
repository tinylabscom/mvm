//! Per-workload containment: quarantine one workload, then replace it under a
//! fresh execution epoch, without touching the rest of the node.
//!
//! The ledger lives beside the node record. Absent means no workload has been
//! contained, so a plain local run is unaffected. Like the node record, a
//! malformed ledger fails closed.

use std::{collections::BTreeMap, path::Path};

use serde::{Deserialize, Serialize};

use super::{
    ExecutionEpoch,
    error::{Denial, HostInterfaceError, OfflineRefusal},
    recovery_custody::{ManagedRecoveryHistory, RecoveryCustodyError},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadEntry {
    pub epoch: ExecutionEpoch,
    pub quarantined: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) recovery: Option<ManagedRecoveryHistory>,
}

impl Default for WorkloadEntry {
    fn default() -> Self {
        Self {
            epoch: ExecutionEpoch(1),
            quarantined: false,
            recovery: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkloadLedger(BTreeMap<String, WorkloadEntry>);

impl WorkloadLedger {
    pub fn load_at(home: &Path) -> Result<Self, HostInterfaceError> {
        super::recovery_custody::load_ordinary_at(home)
    }

    pub fn save_at(&self, home: &Path) -> std::io::Result<()> {
        super::recovery_custody::save_legacy_at(home, self).map_err(std::io::Error::other)
    }

    /// Has containment ever recorded `workload`?
    pub fn knows(&self, workload: &str) -> bool {
        self.0.contains_key(workload)
    }

    pub fn entry(&self, workload: &str) -> WorkloadEntry {
        self.0.get(workload).cloned().unwrap_or_default()
    }

    /// Quarantine through the shared durable ledger transaction.
    ///
    /// # Errors
    /// Refuses unreadable/protected state or a failed durable publication.
    pub fn quarantine_at(home: &Path, workload: &str) -> Result<WorkloadEntry, HostInterfaceError> {
        super::recovery_custody::mutate_ordinary_at(home, workload, |ledger| {
            let entry = ledger.0.entry(workload.to_owned()).or_default();
            entry.quarantined = true;
            Ok(entry.clone())
        })
        .map_err(custody_error)
    }

    /// Replace a local-only workload through the shared durable transaction.
    ///
    /// Managed entries must use recovery reservation/activation and are refused.
    ///
    /// # Errors
    /// Refuses managed entries, epoch exhaustion, unreadable state, or a failed
    /// durable publication.
    pub fn replace_at(home: &Path, workload: &str) -> Result<ExecutionEpoch, HostInterfaceError> {
        Self::replace_at_with::<RecoveryCustodyError>(home, workload, |_, _| Ok(()))
            .map_err(custody_error)
    }

    /// Run a required check under the shared ledger lock, then publish the
    /// local replacement only after that check succeeds.
    ///
    /// # Errors
    /// Returns the check error before mutation, or a converted custody error.
    pub fn replace_at_with<E>(
        home: &Path,
        workload: &str,
        before_publish: impl FnOnce(ExecutionEpoch, ExecutionEpoch) -> Result<(), E>,
    ) -> Result<ExecutionEpoch, E>
    where
        E: From<RecoveryCustodyError>,
    {
        super::recovery_custody::mutate_ordinary_at(home, workload, |ledger| {
            let entry = ledger.0.entry(workload.to_owned()).or_default();
            if entry.recovery.is_some() {
                return Err(E::from(RecoveryCustodyError::Conflict));
            }
            let next = entry
                .epoch
                .0
                .checked_add(1)
                .map(ExecutionEpoch)
                .ok_or_else(|| E::from(RecoveryCustodyError::Limit))?;
            before_publish(entry.epoch, next)?;
            entry.epoch = next;
            entry.quarantined = false;
            Ok(next)
        })
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
        if e.recovery.is_some() {
            return Err(OfflineRefusal::ManagedAdmissionRequired.into());
        }
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

    pub(super) fn entries(&self) -> &BTreeMap<String, WorkloadEntry> {
        &self.0
    }

    pub(super) fn entries_mut(&mut self) -> &mut BTreeMap<String, WorkloadEntry> {
        &mut self.0
    }
}

fn custody_error(error: RecoveryCustodyError) -> HostInterfaceError {
    match error {
        RecoveryCustodyError::CommitUnknown { workload_id, .. } => {
            HostInterfaceError::StateCommitUnknown {
                workload: workload_id,
            }
        }
        error => HostInterfaceError::Denied(Denial::StateUnreadable(error.to_string())),
    }
}

pub(super) fn unreadable(path: &Path, why: &str) -> HostInterfaceError {
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
