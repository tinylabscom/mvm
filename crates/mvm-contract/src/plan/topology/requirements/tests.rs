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
fn exclusive_placement_is_refused_on_a_host_without_the_scope_cpuset() {
    let mut topology = stating_nothing();
    topology.units[2].placement = CorePlacement::Exclusive(vec![CoreId(3)]);
    for &kind in BackendKind::ALL {
        assert_eq!(
            check_requirements(&topology, ResourceControls::on_host(kind, false), None),
            Err(UnmetRequirement::ExclusivePlacement { unit: id("w1") }),
            "{kind:?}"
        );
    }
}

#[test]
fn exclusive_placement_is_admitted_only_against_the_scope_cpuset() {
    let mut topology = stating_nothing();
    topology.units[2].placement = CorePlacement::Exclusive(vec![CoreId(3)]);
    for &kind in BackendKind::ALL {
        let controls = ResourceControls::on_host(kind, true);
        let expected = match controls.placement {
            PlacementControl::SpawnScopeCpuSet => Ok(()),
            PlacementControl::None => Err(UnmetRequirement::ExclusivePlacement { unit: id("w1") }),
        };
        assert_eq!(
            check_requirements(&topology, controls, None),
            expected,
            "{kind:?}"
        );
    }
}

#[test]
fn only_firecracker_declares_the_scope_cpuset() {
    for &kind in BackendKind::ALL {
        let declares = matches!(
            PlacementControl::for_host(kind, true),
            PlacementControl::SpawnScopeCpuSet
        );
        assert_eq!(declares, kind == BackendKind::Firecracker, "{kind:?}");
        assert_eq!(
            PlacementControl::for_host(kind, false),
            PlacementControl::None
        );
    }
    // The mock backend boots nothing, so it refuses the requirement whatever
    // the host offers.
    assert_eq!(
        ResourceControls::on_host(BackendKind::Mock, true).placement,
        PlacementControl::None
    );
}

#[test]
fn a_liveness_period_is_refused_with_its_unit_where_no_deadline_is_held() {
    let mut topology = stating_nothing();
    topology.units[3].liveness_period_ms = Some(ms(100));
    for &kind in BackendKind::ALL {
        if ResourceControls::for_backend(kind).liveness == LivenessControl::HostDeadline {
            continue;
        }
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
fn a_liveness_period_is_admitted_on_the_supervised_tiers_and_refused_on_the_rest() {
    let mut topology = stating_nothing();
    topology.units[3].liveness_period_ms = Some(ms(MIN_LIVENESS_PERIOD_MS));
    let admits = |kind| check_requirements(&topology, ResourceControls::for_backend(kind), None);
    for kind in [
        BackendKind::Libkrun,
        BackendKind::Hvf,
        BackendKind::AppleContainer,
    ] {
        assert_eq!(admits(kind), Ok(()), "{kind:?}");
    }
    for kind in [
        BackendKind::Firecracker,
        BackendKind::Qemu,
        BackendKind::Wasm,
        BackendKind::WebLinux,
    ] {
        assert!(
            matches!(admits(kind), Err(UnmetRequirement::LivenessPeriod { .. })),
            "{kind:?}"
        );
    }
}

#[test]
fn the_period_range_holds_on_the_supervised_tiers() {
    for kind in [BackendKind::Libkrun, BackendKind::Hvf] {
        for period in [MIN_LIVENESS_PERIOD_MS - 1, MAX_LIVENESS_PERIOD_MS + 1] {
            let mut topology = stating_nothing();
            topology.units[3].liveness_period_ms = Some(ms(period));
            assert_eq!(
                check_requirements(&topology, ResourceControls::for_backend(kind), None),
                Err(UnmetRequirement::LivenessPeriodOutOfRange {
                    unit: id("w1-standby"),
                    period_ms: ms(period),
                }),
                "{kind:?} {period}"
            );
        }
    }
}

fn host_deadline() -> ResourceControls {
    ResourceControls {
        liveness: LivenessControl::HostDeadline,
        ..vm_backend()
    }
}

#[test]
fn a_liveness_period_within_the_host_range_passes_where_the_host_holds_the_deadline() {
    for period in [MIN_LIVENESS_PERIOD_MS, 5_000, MAX_LIVENESS_PERIOD_MS] {
        let mut topology = stating_nothing();
        topology.units[3].liveness_period_ms = Some(ms(period));
        assert_eq!(
            check_requirements(&topology, host_deadline(), None),
            Ok(()),
            "{period}"
        );
    }
}

#[test]
fn a_liveness_period_outside_the_host_range_is_refused_with_its_unit() {
    for period in [1, MIN_LIVENESS_PERIOD_MS - 1, MAX_LIVENESS_PERIOD_MS + 1] {
        let mut topology = stating_nothing();
        topology.units[3].liveness_period_ms = Some(ms(period));
        assert_eq!(
            check_requirements(&topology, host_deadline(), None),
            Err(UnmetRequirement::LivenessPeriodOutOfRange {
                unit: id("w1-standby"),
                period_ms: ms(period),
            }),
            "{period}"
        );
    }
}

#[test]
fn more_liveness_units_than_the_host_holds_are_refused_by_count() {
    let mut topology = stating_nothing();
    let template = topology.units[0].clone();
    topology.units = (0..=MAX_LIVENESS_UNITS)
        .map(|i| Unit {
            workload: id(&alloc::format!("u{i:03}")),
            liveness_period_ms: Some(ms(5_000)),
            ..template.clone()
        })
        .collect();
    assert_eq!(
        check_requirements(&topology, host_deadline(), None),
        Err(UnmetRequirement::TooManyLivenessUnits {
            count: MAX_LIVENESS_UNITS + 1
        })
    );
    topology.units.pop();
    assert_eq!(check_requirements(&topology, host_deadline(), None), Ok(()));
}

#[test]
fn a_state_cell_is_refused_with_its_name_where_no_host_store_exists() {
    let mut topology = stating_nothing();
    topology.cells = full().cells;
    for kind in [BackendKind::Wasm, BackendKind::WebLinux] {
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
fn a_plain_state_cell_is_admitted_on_the_host_store() {
    let mut topology = stating_nothing();
    topology.cells = full().cells;
    topology.cells[0].update = CellUpdate::AtPromotion;
    topology.cells[0].per_write_audit = false;
    for &kind in BackendKind::ALL {
        let controls = ResourceControls::for_backend(kind);
        let expected = match controls.state_cells {
            StateCellControl::HostStore => Ok(()),
            StateCellControl::None => Err(UnmetRequirement::StateCell {
                cell: "brake".into(),
            }),
        };
        assert_eq!(
            check_requirements(&topology, controls, None),
            expected,
            "{kind:?}"
        );
    }
}

#[test]
fn a_cell_asking_for_follow_or_per_write_audit_is_refused_on_the_host_store() {
    let mut topology = stating_nothing();
    topology.cells = full().cells;
    topology.cells[0].per_write_audit = false;
    assert_eq!(
        check_requirements(&topology, vm_backend(), None),
        Err(UnmetRequirement::CellFollow {
            cell: "brake".into()
        })
    );
    topology.cells[0].update = CellUpdate::AtPromotion;
    topology.cells[0].per_write_audit = true;
    assert_eq!(
        check_requirements(&topology, vm_backend(), None),
        Err(UnmetRequirement::CellPerWriteAudit {
            cell: "brake".into()
        })
    );
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
