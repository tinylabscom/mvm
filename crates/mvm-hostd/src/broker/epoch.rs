//! The epoch gate on every broker call.
//!
//! A VM registers with the unit and execution epoch of the plan it was
//! admitted under. Each call reads the workload ledger again and asks the
//! epoch gate whether that epoch may still act for its unit, so a replacement
//! or quarantine committed after the VM started refuses the VM's next call.
//! Replacing a unit does not stop the VM that ran at the old epoch, which is
//! why the decision is not taken once at registration.

use std::path::PathBuf;

use anyhow::{Context, Result};
use mvm_contract::protocol::mailbox::ExecutionEpoch;
use mvm_core::host_interface::{HostInterfaceError, epoch_gate::CommandGate};
use mvm_core::protocol::handler::CallEpoch;

/// The registration's unit and epoch, and the mvm home whose workload ledger
/// decides each call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerEpochGate {
    home: PathBuf,
    call: CallEpoch,
}

impl BrokerEpochGate {
    #[must_use]
    pub fn new(home: PathBuf, call: CallEpoch) -> Self {
        Self { home, call }
    }

    /// The gate a registration asks for. Both fields or neither: a
    /// registration naming only one of them is refused rather than served
    /// ungated. Neither yields `None`, which serves the VM without a gate.
    pub fn from_registration(
        workload: Option<&str>,
        execution_epoch: Option<ExecutionEpoch>,
        home: impl FnOnce() -> std::io::Result<PathBuf>,
    ) -> Result<Option<Self>> {
        match (workload, execution_epoch) {
            (None, None) => Ok(None),
            (Some(unit), Some(epoch)) if !unit.is_empty() => Ok(Some(Self::new(
                home().context("resolve the mvm home the epoch gate reads")?,
                CallEpoch {
                    unit: unit.to_owned(),
                    epoch,
                },
            ))),
            _ => anyhow::bail!(
                "a registration must name both its workload and its execution epoch, or neither"
            ),
        }
    }

    /// The unit and epoch each call carries in its context.
    #[must_use]
    pub fn call(&self) -> &CallEpoch {
        &self.call
    }

    /// Read the ledger now and admit the registration's epoch. An unreadable
    /// or malformed ledger refuses like a denial does.
    pub fn admit(&self) -> Result<(), HostInterfaceError> {
        CommandGate::load_at(&self.home)?.admit(&self.call.unit, self.call.epoch)?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::policy_generation::workload_store::OwnedWorkloadStore;
    use mvm_core::host_interface::error::Denial;
    use mvm_core::host_interface::workload::WorkloadChange;

    pub(crate) fn epoch(n: u64) -> ExecutionEpoch {
        ExecutionEpoch::new(n).unwrap()
    }

    pub(crate) fn gate_at(home: &std::path::Path, unit: &str, n: u64) -> BrokerEpochGate {
        BrokerEpochGate::new(
            home.to_path_buf(),
            CallEpoch {
                unit: unit.into(),
                epoch: epoch(n),
            },
        )
    }

    /// Advance `unit` to epoch 2 in the ledger under `home`.
    pub(crate) fn replace(home: &std::path::Path, unit: &str) {
        OwnedWorkloadStore::open(home)
            .unwrap()
            .commit(&WorkloadChange::Replace {
                workload: unit.into(),
                from_epoch: ExecutionEpoch::FIRST,
            })
            .unwrap();
    }

    pub(crate) fn quarantine(home: &std::path::Path, unit: &str) {
        OwnedWorkloadStore::open(home)
            .unwrap()
            .commit(&WorkloadChange::Quarantine {
                workload: unit.into(),
            })
            .unwrap();
    }

    fn denial(result: Result<(), HostInterfaceError>) -> Denial {
        match result {
            Err(HostInterfaceError::Denied(denial)) => denial,
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    #[test]
    fn the_current_epoch_is_admitted() {
        let home = tempfile::tempdir().unwrap();
        assert!(gate_at(home.path(), "unit", 1).admit().is_ok());
        replace(home.path(), "unit");
        assert!(gate_at(home.path(), "unit", 2).admit().is_ok());
    }

    #[test]
    fn a_replacement_after_registration_refuses_the_next_call() {
        let home = tempfile::tempdir().unwrap();
        let gate = gate_at(home.path(), "unit", 1);
        assert!(gate.admit().is_ok());
        replace(home.path(), "unit");
        assert_eq!(
            denial(gate.admit()),
            Denial::StaleEpoch { got: 1, current: 2 }
        );
        assert!(
            gate_at(home.path(), "other", 1).admit().is_ok(),
            "another unit is unaffected"
        );
    }

    #[test]
    fn an_epoch_not_yet_promoted_is_refused() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(
            denial(gate_at(home.path(), "unit", 2).admit()),
            Denial::EpochNotPromoted { got: 2, current: 1 }
        );
    }

    #[test]
    fn a_quarantined_unit_is_refused_at_its_current_epoch() {
        let home = tempfile::tempdir().unwrap();
        quarantine(home.path(), "unit");
        assert_eq!(
            denial(gate_at(home.path(), "unit", 1).admit()),
            Denial::WorkloadQuarantined("unit".into())
        );
    }

    #[test]
    fn a_registration_names_both_fields_or_neither() {
        let home = || Ok(PathBuf::from("/h"));
        assert!(
            BrokerEpochGate::from_registration(None, None, home)
                .unwrap()
                .is_none()
        );
        let gate = BrokerEpochGate::from_registration(Some("unit"), Some(epoch(3)), home)
            .unwrap()
            .unwrap();
        assert_eq!(gate.call().unit, "unit");
        assert_eq!(gate.call().epoch, epoch(3));
        assert!(BrokerEpochGate::from_registration(Some("unit"), None, home).is_err());
        assert!(BrokerEpochGate::from_registration(None, Some(epoch(1)), home).is_err());
        assert!(BrokerEpochGate::from_registration(Some(""), Some(epoch(1)), home).is_err());
    }
}
