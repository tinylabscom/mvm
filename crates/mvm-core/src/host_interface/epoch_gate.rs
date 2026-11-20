//! The one decision on whether an execution epoch may act for its unit.
//!
//! The gate is keyed by unit. Each unit's current epoch is read from the
//! durable record, the workload ledger the policy coordinator alone writes, so
//! replacing one unit fences its old epoch for every service that asks and
//! leaves every other unit as it was. Only the current epoch of a unit that is
//! not quarantined passes. An older epoch is stale. A newer one has not been
//! promoted: a standby is numbered above its unit's current epoch and stays
//! refused until the record names it current.

use std::{collections::BTreeMap, path::Path};

use super::{
    ExecutionEpoch,
    error::{Denial, HostInterfaceError},
    workload::{WorkloadEntry, WorkloadLedger},
};

/// Per-unit epoch gate over the durable record, plus a per-unit command
/// sequence that must rise strictly, so a replayed or reordered command from
/// either side of a partition is refused.
#[derive(Debug, Clone, Default)]
pub struct CommandGate {
    record: WorkloadLedger,
    last_seq: BTreeMap<String, u64>,
}

impl CommandGate {
    pub fn new(record: WorkloadLedger) -> Self {
        Self {
            record,
            last_seq: BTreeMap::new(),
        }
    }

    /// The gate over the record as committed on `home`. A malformed record,
    /// a zero epoch in it or an unresolved commit fails closed.
    pub fn load_at(home: &Path) -> Result<Self, HostInterfaceError> {
        WorkloadLedger::load_at(home).map(Self::new)
    }

    /// The unit's current epoch according to the durable record.
    pub fn current(&self, unit: &str) -> ExecutionEpoch {
        self.record.entry(unit).epoch
    }

    /// May `epoch` act for `unit`? Returns the current epoch when it may.
    pub fn admit(&self, unit: &str, epoch: ExecutionEpoch) -> Result<ExecutionEpoch, Denial> {
        decide(unit, self.record.entry(unit), epoch)
    }

    /// Admit a command: the epoch must pass [`Self::admit`] and `seq` must be
    /// greater than every sequence number accepted before for this unit.
    pub fn accept(&mut self, unit: &str, epoch: ExecutionEpoch, seq: u64) -> Result<(), Denial> {
        self.admit(unit, epoch)?;
        let last = self.last_seq.get(unit).copied().unwrap_or(0);
        if seq <= last {
            return Err(Denial::ReplayedCommand { got: seq, last });
        }
        self.last_seq.insert(unit.to_owned(), seq);
        Ok(())
    }
}

/// The gate's rule for one unit's record entry.
pub(super) fn decide(
    unit: &str,
    entry: WorkloadEntry,
    epoch: ExecutionEpoch,
) -> Result<ExecutionEpoch, Denial> {
    let (got, current) = (epoch.get(), entry.epoch.get());
    if epoch < entry.epoch {
        return Err(Denial::StaleEpoch { got, current });
    }
    if epoch > entry.epoch {
        return Err(Denial::EpochNotPromoted { got, current });
    }
    if entry.quarantined {
        return Err(Denial::WorkloadQuarantined(unit.to_owned()));
    }
    Ok(entry.epoch)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(n: u64) -> ExecutionEpoch {
        ExecutionEpoch::new(n).unwrap()
    }

    fn replaced(units: &[&str]) -> WorkloadLedger {
        let mut ledger = WorkloadLedger::default();
        for unit in units {
            ledger.replace(unit).unwrap();
        }
        ledger
    }

    #[test]
    fn replacing_one_unit_fences_only_that_unit() {
        let gate = CommandGate::new(replaced(&["a"]));
        assert_eq!(gate.current("a"), epoch(2));
        assert_eq!(
            gate.admit("a", epoch(1)),
            Err(Denial::StaleEpoch { got: 1, current: 2 })
        );
        assert_eq!(gate.admit("a", epoch(2)), Ok(epoch(2)));
        assert_eq!(
            gate.admit("b", epoch(1)),
            Ok(epoch(1)),
            "bystander unaffected"
        );
    }

    #[test]
    fn an_epoch_numbered_above_the_current_one_is_refused_until_promoted() {
        let gate = CommandGate::new(WorkloadLedger::default());
        assert_eq!(
            gate.admit("a", epoch(2)),
            Err(Denial::EpochNotPromoted { got: 2, current: 1 })
        );
        let promoted = CommandGate::new(replaced(&["a"]));
        assert_eq!(promoted.admit("a", epoch(2)), Ok(epoch(2)));
    }

    #[test]
    fn a_quarantined_unit_is_refused_even_at_its_current_epoch() {
        let mut ledger = WorkloadLedger::default();
        ledger.quarantine("a");
        let gate = CommandGate::new(ledger);
        assert_eq!(
            gate.admit("a", epoch(1)),
            Err(Denial::WorkloadQuarantined("a".into()))
        );
    }

    #[test]
    fn commands_are_sequenced_per_unit_and_refuse_replay_reorder_and_stale_epochs() {
        let mut g = CommandGate::new(replaced(&["a"]));
        assert!(g.accept("a", epoch(2), 1).is_ok());
        assert!(g.accept("a", epoch(2), 3).is_ok());
        assert_eq!(
            g.accept("a", epoch(2), 3),
            Err(Denial::ReplayedCommand { got: 3, last: 3 })
        );
        assert_eq!(
            g.accept("a", epoch(2), 2),
            Err(Denial::ReplayedCommand { got: 2, last: 3 })
        );
        assert_eq!(
            g.accept("a", epoch(1), 9),
            Err(Denial::StaleEpoch { got: 1, current: 2 })
        );
        assert!(g.accept("b", epoch(1), 1).is_ok(), "sequences are per unit");
    }

    #[test]
    fn a_zero_or_malformed_record_fails_closed_on_load() {
        let d = tempfile::tempdir().unwrap();
        let path = super::super::workload::canonical_dir_at(d.path())
            .join(super::super::workload::LEDGER_FILE);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        for bytes in [
            r#"{"sequence":1,"workloads":{"a":{"epoch":0,"quarantined":false}}}"#,
            r#"{"sequence":1,"workloads":{"a":{"epoch":-1,"quarantined":false}}}"#,
            r#"{"sequence":1,"workloads":{"a":{"epoch":2,"quarantined":false,"x":1}}}"#,
        ] {
            std::fs::write(&path, bytes).unwrap();
            assert!(CommandGate::load_at(d.path()).is_err(), "{bytes}");
        }
        std::fs::write(
            &path,
            r#"{"sequence":1,"workloads":{"a":{"epoch":2,"quarantined":false}}}"#,
        )
        .unwrap();
        assert_eq!(
            CommandGate::load_at(d.path()).unwrap().current("a"),
            epoch(2)
        );
    }
}
