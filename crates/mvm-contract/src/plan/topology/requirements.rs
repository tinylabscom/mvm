//! Whether a backend enforces what a topology requires.
//!
//! Under the critical profile every requirement a topology states is either
//! enforced or the topology is refused, with the requirement and the element
//! that stated it named. There is no third outcome in which a requirement is
//! recorded as declared and then left to nothing.

use alloc::string::String;
use core::num::NonZeroU32;

use super::{CorePlacement, CryptoSuite, IsolationTier, StandbyClass, StandbyPair, Topology, Unit};
use crate::plan::types::WorkloadId;
use crate::protocol::resource_controls::{
    LivenessControl, PlacementControl, ResourceControls, StandbyControl, StateCellControl,
    SuiteControl,
};

/// The failover time measured for this host and backend, in milliseconds.
///
/// Supplied by the caller. A host with no measurement passes `None`, and then
/// every recovery bound is refused: a bound nobody has measured against is a
/// bound nobody can say is met.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeasuredFailoverMs(pub NonZeroU32);

/// The first requirement a backend does not enforce, and who stated it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnmetRequirement {
    #[error("suite {suite:?} is not implemented by this backend's admission path")]
    CryptoSuite { suite: CryptoSuite },
    #[error("unit {} requires exclusive core placement, which this backend does not enforce", .unit.0)]
    ExclusivePlacement { unit: WorkloadId },
    #[error(
        "unit {} requires isolation tier {required:?}; this backend provides {provided:?}",
        .unit.0
    )]
    IsolationTier {
        unit: WorkloadId,
        required: IsolationTier,
        provided: Option<IsolationTier>,
    },
    #[error(
        "the pair for {} states a {bound_ms} ms recovery bound and no failover has been \
         measured on this host and backend",
        .active.0
    )]
    RecoveryBoundUnmeasured {
        active: WorkloadId,
        bound_ms: NonZeroU32,
    },
    #[error(
        "the pair for {} states a {bound_ms} ms recovery bound, tighter than the measured \
         {measured_ms} ms failover",
        .active.0
    )]
    RecoveryBoundTighterThanMeasured {
        active: WorkloadId,
        bound_ms: NonZeroU32,
        measured_ms: NonZeroU32,
    },
    #[error("the pair for {} requires a {class:?} standby, which this backend does not keep", .active.0)]
    StandbyClass {
        active: WorkloadId,
        class: StandbyClass,
    },
    #[error(
        "unit {} declares a {period_ms} ms liveness period, and this backend holds no \
         liveness deadline",
        .unit.0
    )]
    LivenessPeriod {
        unit: WorkloadId,
        period_ms: NonZeroU32,
    },
    #[error("cell {cell} requires a host-held state cell, which this backend does not provide")]
    StateCell { cell: String },
}

/// Compare what `topology` requires with what `controls` enforce, returning
/// the first unmet requirement.
///
/// Structure is [`Topology::validate`]'s job and is not rechecked here; this
/// reads only the requirements each element states.
pub fn check_requirements(
    topology: &Topology,
    controls: ResourceControls,
    measured: Option<MeasuredFailoverMs>,
) -> Result<(), UnmetRequirement> {
    check_suite(topology.suite, controls.suite)?;
    for unit in &topology.units {
        check_placement(unit, controls.placement)?;
        check_isolation(unit, controls.isolation)?;
        check_liveness(unit, controls.liveness)?;
    }
    for pair in &topology.standby_pairs {
        // The bound is checked before the class so that a pair whose class is
        // refused still reports a bound it could never have met.
        check_recovery_bound(pair, measured)?;
        check_standby(pair, controls.standby)?;
    }
    if let Some(cell) = topology.cells.first() {
        match controls.state_cells {
            StateCellControl::None => {
                return Err(UnmetRequirement::StateCell {
                    cell: cell.name.clone(),
                });
            }
        }
    }
    Ok(())
}

fn check_suite(suite: CryptoSuite, control: SuiteControl) -> Result<(), UnmetRequirement> {
    match control {
        SuiteControl::ClassicalOnly if suite == CryptoSuite::CLASSICAL => Ok(()),
        SuiteControl::ClassicalOnly => Err(UnmetRequirement::CryptoSuite { suite }),
    }
}

fn check_placement(unit: &Unit, control: PlacementControl) -> Result<(), UnmetRequirement> {
    match (&unit.placement, control) {
        (CorePlacement::Floating, _) => Ok(()),
        (CorePlacement::Exclusive(_), PlacementControl::None) => {
            Err(UnmetRequirement::ExclusivePlacement {
                unit: unit.workload.clone(),
            })
        }
    }
}

fn check_isolation(unit: &Unit, provided: Option<IsolationTier>) -> Result<(), UnmetRequirement> {
    match unit.min_isolation {
        Some(required) if provided < Some(required) => Err(UnmetRequirement::IsolationTier {
            unit: unit.workload.clone(),
            required,
            provided,
        }),
        _ => Ok(()),
    }
}

fn check_liveness(unit: &Unit, control: LivenessControl) -> Result<(), UnmetRequirement> {
    match (unit.liveness_period_ms, control) {
        (None, _) => Ok(()),
        (Some(period_ms), LivenessControl::None) => Err(UnmetRequirement::LivenessPeriod {
            unit: unit.workload.clone(),
            period_ms,
        }),
    }
}

fn check_recovery_bound(
    pair: &StandbyPair,
    measured: Option<MeasuredFailoverMs>,
) -> Result<(), UnmetRequirement> {
    let Some(bound_ms) = pair.recovery_bound_ms else {
        return Ok(());
    };
    match measured {
        None => Err(UnmetRequirement::RecoveryBoundUnmeasured {
            active: pair.active.clone(),
            bound_ms,
        }),
        Some(MeasuredFailoverMs(measured_ms)) if bound_ms < measured_ms => {
            Err(UnmetRequirement::RecoveryBoundTighterThanMeasured {
                active: pair.active.clone(),
                bound_ms,
                measured_ms,
            })
        }
        Some(_) => Ok(()),
    }
}

fn check_standby(pair: &StandbyPair, control: StandbyControl) -> Result<(), UnmetRequirement> {
    match (pair.class, control) {
        (StandbyClass::None, _) => Ok(()),
        (class, StandbyControl::None) => Err(UnmetRequirement::StandbyClass {
            active: pair.active.clone(),
            class,
        }),
    }
}

#[cfg(test)]
mod tests;
