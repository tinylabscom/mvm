use alloc::vec;
use core::num::NonZeroU32;

use super::super::tests::{full, id};
use super::super::*;
use super::*;
use crate::protocol::vm_backend::BackendKind;

/// [`full`] with every requirement taken out: floating placement, no
/// isolation floor, pairs of class `None` with no bound, and no cells. Its
/// edges and succession stay, because neither states a requirement.
fn stating_nothing() -> Topology {
    let mut topology = full();
    for unit in &mut topology.units {
        unit.placement = CorePlacement::Floating;
        unit.min_isolation = None;
    }
    for pair in &mut topology.standby_pairs {
        pair.class = StandbyClass::None;
        pair.recovery_bound_ms = None;
    }
    topology.cells.clear();
    topology
}

fn ms(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).expect("non-zero")
}

fn vm_backend() -> ResourceControls {
    ResourceControls::for_backend(BackendKind::Firecracker)
}

#[test]
fn a_topology_stating_nothing_passes_on_every_backend() {
    let topology = stating_nothing();
    topology.validate().expect("the fixture stays valid");
    assert!(
        !topology.standby_pairs.is_empty(),
        "pairs of class None are exercised"
    );
    for &kind in BackendKind::ALL {
        let controls = ResourceControls::for_backend(kind);
        assert_eq!(
            check_requirements(&topology, controls, None),
            Ok(()),
            "{kind:?}"
        );
        assert_eq!(
            check_requirements(&topology, controls, Some(MeasuredFailoverMs(ms(1)))),
            Ok(()),
            "{kind:?}"
        );
    }
}

#[test]
fn exclusive_placement_is_refused_with_its_unit() {
    let mut topology = stating_nothing();
    topology.units[2].placement = CorePlacement::Exclusive(vec![CoreId(3)]);
    for &kind in BackendKind::ALL {
        assert_eq!(
            check_requirements(&topology, ResourceControls::for_backend(kind), None),
            Err(UnmetRequirement::ExclusivePlacement { unit: id("w1") }),
            "{kind:?}"
        );
    }
}

#[test]
fn a_liveness_period_is_refused_with_its_unit_on_every_backend() {
    let mut topology = stating_nothing();
    topology.units[3].liveness_period_ms = Some(ms(100));
    for &kind in BackendKind::ALL {
        assert_eq!(
            check_requirements(
                &topology,
                ResourceControls::for_backend(kind),
                Some(MeasuredFailoverMs(ms(1)))
            ),
            Err(UnmetRequirement::LivenessPeriod {
                unit: id("w1-standby"),
                period_ms: ms(100),
            }),
            "{kind:?}"
        );
    }
}

#[test]
fn a_state_cell_is_refused_with_its_name() {
    let mut topology = stating_nothing();
    topology.cells = full().cells;
    for &kind in BackendKind::ALL {
        assert_eq!(
            check_requirements(&topology, ResourceControls::for_backend(kind), None),
            Err(UnmetRequirement::StateCell {
                cell: "brake".into()
            }),
            "{kind:?}"
        );
    }
}

#[test]
fn every_kept_standby_class_is_refused_with_its_pair() {
    for class in [
        StandbyClass::Resident,
        StandbyClass::Warm,
        StandbyClass::Cold,
    ] {
        let mut topology = stating_nothing();
        topology.standby_pairs[1].class = class;
        for &kind in BackendKind::ALL {
            assert_eq!(
                check_requirements(&topology, ResourceControls::for_backend(kind), None),
                Err(UnmetRequirement::StandbyClass {
                    active: id("w1"),
                    class
                }),
                "{kind:?} {class:?}"
            );
        }
    }
}

#[test]
fn a_recovery_bound_without_a_measured_failover_is_refused() {
    let mut topology = stating_nothing();
    topology.standby_pairs[0].class = StandbyClass::Resident;
    topology.standby_pairs[0].recovery_bound_ms = Some(ms(50));
    assert_eq!(
        check_requirements(&topology, vm_backend(), None),
        Err(UnmetRequirement::RecoveryBoundUnmeasured {
            active: id("ctl-a"),
            bound_ms: ms(50),
        })
    );
}

#[test]
fn a_recovery_bound_tighter_than_the_measured_failover_is_refused() {
    let mut topology = stating_nothing();
    topology.standby_pairs[0].class = StandbyClass::Resident;
    topology.standby_pairs[0].recovery_bound_ms = Some(ms(50));
    assert_eq!(
        check_requirements(&topology, vm_backend(), Some(MeasuredFailoverMs(ms(51)))),
        Err(UnmetRequirement::RecoveryBoundTighterThanMeasured {
            active: id("ctl-a"),
            bound_ms: ms(50),
            measured_ms: ms(51),
        })
    );
}

#[test]
fn a_recovery_bound_the_measured_failover_meets_reaches_the_standby_check() {
    let mut topology = stating_nothing();
    topology.standby_pairs[0].class = StandbyClass::Resident;
    topology.standby_pairs[0].recovery_bound_ms = Some(ms(50));
    // An equal figure meets the bound, so the next refusal is the class.
    assert_eq!(
        check_requirements(&topology, vm_backend(), Some(MeasuredFailoverMs(ms(50)))),
        Err(UnmetRequirement::StandbyClass {
            active: id("ctl-a"),
            class: StandbyClass::Resident,
        })
    );
}

#[test]
fn every_non_classical_suite_is_refused() {
    let signatures = [
        SignatureSuite::Ed25519,
        SignatureSuite::Ed25519MlDsa65,
        SignatureSuite::Ed25519MlDsa87,
    ];
    let key_establishments = [
        KeyEstablishmentSuite::X25519,
        KeyEstablishmentSuite::X25519MlKem768,
        KeyEstablishmentSuite::X25519MlKem1024,
    ];
    for signature in signatures {
        for key_establishment in key_establishments {
            let suite = CryptoSuite {
                signature,
                key_establishment,
            };
            if suite == CryptoSuite::CLASSICAL {
                continue;
            }
            let mut topology = stating_nothing();
            topology.suite = suite;
            for &kind in BackendKind::ALL {
                assert_eq!(
                    check_requirements(&topology, ResourceControls::for_backend(kind), None),
                    Err(UnmetRequirement::CryptoSuite { suite }),
                    "{kind:?} {suite:?}"
                );
            }
        }
    }
}

#[test]
fn an_isolation_floor_above_the_backend_is_refused_with_its_unit() {
    let mut topology = stating_nothing();
    topology.units[4].min_isolation = Some(IsolationTier::Vm);
    assert_eq!(
        check_requirements(
            &topology,
            ResourceControls::for_backend(BackendKind::Wasm),
            None
        ),
        Err(UnmetRequirement::IsolationTier {
            unit: id("w2"),
            required: IsolationTier::Vm,
            provided: Some(IsolationTier::Task),
        })
    );
    topology.units[4].min_isolation = Some(IsolationTier::Task);
    assert_eq!(
        check_requirements(
            &topology,
            ResourceControls::for_backend(BackendKind::Mock),
            None
        ),
        Err(UnmetRequirement::IsolationTier {
            unit: id("w2"),
            required: IsolationTier::Task,
            provided: None,
        })
    );
}

#[test]
fn an_isolation_floor_the_backend_meets_passes() {
    for floor in [
        IsolationTier::Task,
        IsolationTier::Partition,
        IsolationTier::Vm,
    ] {
        let mut topology = stating_nothing();
        topology.units[0].min_isolation = Some(floor);
        assert_eq!(
            check_requirements(&topology, vm_backend(), None),
            Ok(()),
            "{floor:?}"
        );
    }
}
