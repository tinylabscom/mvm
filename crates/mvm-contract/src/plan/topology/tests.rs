use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::num::{NonZeroU32, NonZeroU64};

use super::*;

pub(super) fn id(name: &str) -> WorkloadId {
    WorkloadId(name.to_string())
}

fn recipe(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes(&[byte; 32])
}

fn unit(name: &str, role: UnitRole, cores: &[u32]) -> Unit {
    Unit {
        workload: id(name),
        role,
        recipe: recipe(name.len() as u8),
        resources: UnitResources {
            cpus: 1,
            mem_mib: 256,
            disk_mib: 512,
        },
        placement: if cores.is_empty() {
            CorePlacement::Floating
        } else {
            CorePlacement::Exclusive(cores.iter().copied().map(CoreId).collect())
        },
        min_isolation: None,
        permits: SealedTransitions::default(),
        liveness_period_ms: None,
        require_isolated_cores: false,
    }
}

/// A topology that exercises every element and passes validation.
pub(super) fn full() -> Topology {
    let mut ctl_a = unit("ctl-a", UnitRole::Controller, &[0]);
    ctl_a.min_isolation = Some(IsolationTier::Vm);
    let mut w2 = unit("w2", UnitRole::Worker, &[]);
    w2.permits = SealedTransitions {
        sleep: true,
        wake: true,
        pause: false,
        checkpoint: false,
    };
    Topology {
        schema_version: TOPOLOGY_SCHEMA_VERSION,
        tenant: TenantId("acme".to_string()),
        generation: 7,
        valid_from: "2026-11-01T00:00:00Z".parse().unwrap(),
        valid_until: "2026-12-01T00:00:00Z".parse().unwrap(),
        suite: CryptoSuite::CLASSICAL,
        units: vec![
            ctl_a,
            unit("ctl-b", UnitRole::Controller, &[0]),
            unit("w1", UnitRole::Worker, &[1, 2]),
            unit("w1-standby", UnitRole::Worker, &[1, 2]),
            w2,
        ],
        standby_pairs: vec![
            StandbyPair {
                active: id("ctl-a"),
                standby: id("ctl-b"),
                class: StandbyClass::Resident,
                recovery_bound_ms: NonZeroU32::new(50),
            },
            StandbyPair {
                active: id("w1"),
                standby: id("w1-standby"),
                class: StandbyClass::Warm,
                recovery_bound_ms: NonZeroU32::new(200),
            },
        ],
        cells: vec![StateCell {
            name: "brake".to_string(),
            writer: id("w1"),
            readers: vec![id("ctl-a"), id("w2")],
            size_bytes: NonZeroU64::new(64).unwrap(),
            update: CellUpdate::Follow,
            per_write_audit: true,
        }],
        edges: vec![
            Edge {
                kind: EdgeKind::Mailbox,
                from: id("ctl-a"),
                to: id("w1"),
            },
            Edge {
                kind: EdgeKind::Stream,
                from: id("w1"),
                to: id("w2"),
            },
        ],
        succession: vec![id("ctl-a"), id("ctl-b")],
    }
}

fn refused(topology: &Topology) -> TopologyValidationError {
    topology
        .validate()
        .expect_err("the topology must be refused")
}

#[test]
fn a_full_topology_is_valid() {
    full().validate().unwrap();
}

#[test]
fn serde_round_trips() {
    let topology = full();
    let json = serde_json::to_string(&topology).unwrap();
    let back: Topology = serde_json::from_str(&json).unwrap();
    assert_eq!(back, topology);
}

#[test]
fn defaults_are_omitted_and_restored() {
    let mut topology = full();
    topology.standby_pairs.clear();
    topology.cells.clear();
    topology.edges.clear();
    topology.succession.clear();
    let json = serde_json::to_string(&topology).unwrap();
    for absent in [
        "standby_pairs",
        "cells",
        "edges",
        "succession",
        "\"checkpoint\"",
        "liveness_period_ms",
    ] {
        assert!(!json.contains(absent), "{absent} serialized at its default");
    }
    let back: Topology = serde_json::from_str(&json).unwrap();
    assert_eq!(back, topology);
}

fn with_extra_field(path: &[&str]) -> String {
    let mut value = serde_json::to_value(full()).unwrap();
    let mut target = &mut value;
    for key in path {
        target = match key.parse::<usize>() {
            Ok(index) => &mut target[index],
            Err(_) => &mut target[*key],
        };
    }
    target
        .as_object_mut()
        .unwrap()
        .insert("surprise".to_string(), serde_json::Value::Bool(true));
    serde_json::to_string(&value).unwrap()
}

#[test]
fn unknown_fields_are_rejected_at_every_level() {
    for path in [
        &[][..],
        &["units", "0"],
        &["units", "4", "permits"],
        &["standby_pairs", "0"],
        &["cells", "0"],
        &["edges", "0"],
        &["suite"],
    ] {
        let json = with_extra_field(path);
        let error = serde_json::from_str::<Topology>(&json).unwrap_err();
        assert!(
            error.to_string().contains("unknown field"),
            "{path:?}: {error}"
        );
    }
}

/// Pins the canonical encoding. A change here is a wire change: every signed
/// topology and every plan naming one changes with it.
#[test]
fn the_digest_of_a_fixed_topology_is_pinned() {
    assert_eq!(
        full().digest().as_str(),
        "sha256:2c973eeab3374206c79e63dd6022fdeae8197114b0cadfc482697dd1a4ae541d"
    );
}

/// [`full`] with a liveness period on a paired unit, inside its recovery
/// bound, and on an unpaired one.
fn with_liveness() -> Topology {
    let mut topology = full();
    topology.units[2].liveness_period_ms = NonZeroU32::new(150);
    topology.units[4].liveness_period_ms = NonZeroU32::new(100);
    topology
}

#[test]
fn the_digest_of_a_fixed_topology_with_liveness_periods_is_pinned() {
    let topology = with_liveness();
    topology.validate().unwrap();
    assert_eq!(
        topology.digest().as_str(),
        "sha256:03476fe25e1a0b00296ad9236d82aea65b5bc2ccfbac793d4b98a3c66f177995"
    );
}

/// [`full`] with a paired unit requiring its exclusive cores isolated.
fn with_isolated_cores() -> Topology {
    let mut topology = full();
    topology.units[2].require_isolated_cores = true;
    topology
}

#[test]
fn the_digest_of_a_fixed_topology_requiring_isolated_cores_is_pinned() {
    let topology = with_isolated_cores();
    topology.validate().unwrap();
    assert_eq!(
        topology.digest().as_str(),
        "sha256:fa16d9f3b71759a21f9e3ccf27dc51a754b36a9e7f8c692bf0ee772591c8b0e0"
    );
}

#[test]
fn an_isolation_requirement_is_omitted_from_the_encoding_when_false() {
    let json = serde_json::to_string(&full()).unwrap();
    assert!(!json.contains("require_isolated_cores"), "{json}");
    let json = serde_json::to_string(&with_isolated_cores()).unwrap();
    assert!(json.contains(r#""require_isolated_cores":true"#), "{json}");
}

#[test]
fn an_isolation_requirement_without_exclusive_cores_is_refused() {
    let mut topology = full();
    topology.units[4].require_isolated_cores = true;
    assert_eq!(
        topology.validate(),
        Err(TopologyValidationError::IsolationWithoutExclusiveCores { unit: id("w2") })
    );
}

#[test]
fn the_digest_changes_when_any_field_changes() {
    type Mutation = fn(&mut Topology);
    let mutations: Vec<(&str, Mutation)> = vec![
        ("schema_version", |t| t.schema_version += 1),
        ("tenant", |t| t.tenant.0.push('x')),
        ("generation", |t| t.generation += 1),
        ("valid_from", |t| {
            t.valid_from = t.valid_from.checked_add_secs(-1).unwrap();
        }),
        ("valid_until", |t| {
            t.valid_until = t.valid_until.checked_add_secs(1).unwrap();
        }),
        ("signature", |t| {
            t.suite.signature = SignatureSuite::Ed25519MlDsa65;
        }),
        ("key_establishment", |t| {
            t.suite.key_establishment = KeyEstablishmentSuite::X25519MlKem1024;
        }),
        ("role", |t| t.units[4].role = UnitRole::Controller),
        ("recipe", |t| t.units[0].recipe = recipe(0xee)),
        ("resources", |t| t.units[0].resources.mem_mib += 1),
        ("placement", |t| {
            t.units[4].placement = CorePlacement::Exclusive(vec![CoreId(9)]);
        }),
        ("min_isolation", |t| t.units[0].min_isolation = None),
        ("permits", |t| t.units[0].permits.checkpoint = true),
        ("require isolated cores", |t| {
            t.units[2].require_isolated_cores = true
        }),
        ("liveness period", |t| {
            t.units[4].liveness_period_ms = NonZeroU32::new(100);
        }),
        ("pair class", |t| {
            t.standby_pairs[1].class = StandbyClass::Cold
        }),
        ("recovery bound", |t| {
            t.standby_pairs[0].recovery_bound_ms = None;
        }),
        ("cell size", |t| {
            t.cells[0].size_bytes = NonZeroU64::new(65).unwrap();
        }),
        ("cell readers", |t| {
            t.cells[0].readers.pop().map(drop).unwrap()
        }),
        ("cell update", |t| {
            t.cells[0].update = CellUpdate::AtPromotion
        }),
        ("cell audit", |t| t.cells[0].per_write_audit = false),
        ("edge kind", |t| t.edges[1].kind = EdgeKind::Mailbox),
        ("succession order", |t| t.succession.reverse()),
    ];
    let base = full().digest();
    for (name, mutate) in mutations {
        let mut changed = full();
        mutate(&mut changed);
        assert_ne!(changed.digest(), base, "{name} is outside the digest");
    }
}

#[test]
fn a_reordered_topology_is_refused_rather_than_normalised() {
    let mut units = full();
    units.units.swap(0, 1);
    assert_eq!(
        refused(&units),
        TopologyValidationError::Unsorted {
            collection: Collection::Units
        }
    );

    let mut pairs = full();
    pairs.standby_pairs.reverse();
    assert_eq!(
        refused(&pairs),
        TopologyValidationError::Unsorted {
            collection: Collection::StandbyPairs
        }
    );

    let mut readers = full();
    readers.cells[0].readers.reverse();
    assert_eq!(
        refused(&readers),
        TopologyValidationError::Unsorted {
            collection: Collection::CellReaders {
                cell: "brake".to_string()
            }
        }
    );

    let mut edges = full();
    edges.edges.reverse();
    assert_eq!(
        refused(&edges),
        TopologyValidationError::Unsorted {
            collection: Collection::Edges
        }
    );

    let mut cores = full();
    cores.units[2].placement = CorePlacement::Exclusive(vec![CoreId(2), CoreId(1)]);
    cores.units[3].placement = CorePlacement::Exclusive(vec![CoreId(2), CoreId(1)]);
    assert_eq!(
        refused(&cores),
        TopologyValidationError::Unsorted {
            collection: Collection::Cores { unit: id("w1") }
        }
    );
}

#[test]
fn no_units_is_refused() {
    let mut topology = full();
    topology.units.clear();
    topology.standby_pairs.clear();
    topology.cells.clear();
    topology.edges.clear();
    topology.succession.clear();
    assert_eq!(refused(&topology), TopologyValidationError::NoUnits);
}

#[test]
fn an_empty_validity_window_is_refused() {
    let mut topology = full();
    topology.valid_until = topology.valid_from;
    assert_eq!(
        refused(&topology),
        TopologyValidationError::EmptyValidityWindow
    );
}

#[test]
fn an_inverted_validity_window_is_refused() {
    let mut topology = full();
    core::mem::swap(&mut topology.valid_from, &mut topology.valid_until);
    assert_eq!(
        refused(&topology),
        TopologyValidationError::InvertedValidityWindow
    );
}

#[test]
fn a_duplicate_unit_is_refused() {
    let mut topology = full();
    topology.units.insert(4, unit("w2", UnitRole::Worker, &[]));
    assert_eq!(
        refused(&topology),
        TopologyValidationError::DuplicateUnit { unit: id("w2") }
    );
}

#[test]
fn a_cell_declared_twice_is_refused() {
    let mut topology = full();
    let mut second = topology.cells[0].clone();
    second.writer = id("w2");
    second.readers.clear();
    topology.cells.push(second);
    assert_eq!(
        refused(&topology),
        TopologyValidationError::DuplicateCell {
            cell: "brake".to_string()
        }
    );
}

#[test]
fn a_cell_with_an_unknown_writer_is_refused() {
    let mut topology = full();
    topology.cells[0].writer = id("ghost");
    assert_eq!(
        refused(&topology),
        TopologyValidationError::UnknownUnit {
            reference: UnitReference::CellWriter {
                cell: "brake".to_string()
            },
            unit: id("ghost"),
        }
    );
}

#[test]
fn a_cell_reader_naming_an_unknown_unit_is_refused() {
    let mut topology = full();
    topology.cells[0].readers.push(id("zz-ghost"));
    assert_eq!(
        refused(&topology),
        TopologyValidationError::UnknownUnit {
            reference: UnitReference::CellReader {
                cell: "brake".to_string()
            },
            unit: id("zz-ghost"),
        }
    );
}

#[test]
fn a_cell_reader_listed_twice_is_refused() {
    let mut topology = full();
    topology.cells[0].readers.push(id("w2"));
    assert_eq!(
        refused(&topology),
        TopologyValidationError::DuplicateEntry {
            collection: Collection::CellReaders {
                cell: "brake".to_string()
            },
            entry: "w2".to_string(),
        }
    );
}

#[test]
fn a_writer_listed_as_reader_is_refused() {
    let mut topology = full();
    topology.cells[0].readers = vec![id("ctl-a"), id("w1"), id("w2")];
    assert_eq!(
        refused(&topology),
        TopologyValidationError::WriterIsReader {
            cell: "brake".to_string(),
            unit: id("w1"),
        }
    );
}

#[test]
fn a_standby_member_naming_an_unknown_unit_is_refused() {
    let mut topology = full();
    topology.standby_pairs[1].standby = id("ghost");
    assert_eq!(
        refused(&topology),
        TopologyValidationError::UnknownUnit {
            reference: UnitReference::StandbyMember,
            unit: id("ghost"),
        }
    );

    let mut active = full();
    active.standby_pairs[1].active = id("x-ghost");
    assert_eq!(
        refused(&active),
        TopologyValidationError::UnknownUnit {
            reference: UnitReference::StandbyActive,
            unit: id("x-ghost"),
        }
    );
}

#[test]
fn an_edge_naming_an_unknown_unit_is_refused() {
    let mut from = full();
    from.edges[1].from = id("ghost");
    assert_eq!(
        refused(&from),
        TopologyValidationError::UnknownUnit {
            reference: UnitReference::EdgeFrom,
            unit: id("ghost"),
        }
    );

    let mut to = full();
    to.edges[1].to = id("ghost");
    assert_eq!(
        refused(&to),
        TopologyValidationError::UnknownUnit {
            reference: UnitReference::EdgeTo,
            unit: id("ghost"),
        }
    );
}

#[test]
fn a_succession_entry_naming_an_unknown_unit_is_refused() {
    let mut topology = full();
    topology.succession.push(id("ghost"));
    assert_eq!(
        refused(&topology),
        TopologyValidationError::UnknownUnit {
            reference: UnitReference::Succession,
            unit: id("ghost"),
        }
    );
}

#[test]
fn a_succession_entry_that_is_not_a_controller_is_refused() {
    let mut topology = full();
    topology.succession.push(id("w2"));
    assert_eq!(
        refused(&topology),
        TopologyValidationError::SuccessorNotController { unit: id("w2") }
    );
}

#[test]
fn a_succession_entry_listed_twice_is_refused() {
    let mut topology = full();
    topology.succession.push(id("ctl-a"));
    assert_eq!(
        refused(&topology),
        TopologyValidationError::DuplicateEntry {
            collection: Collection::Succession,
            entry: "ctl-a".to_string(),
        }
    );
}

#[test]
fn overlapping_exclusive_cores_outside_a_pair_are_refused() {
    let mut topology = full();
    topology.units[4].placement = CorePlacement::Exclusive(vec![CoreId(2), CoreId(3)]);
    assert_eq!(
        refused(&topology),
        TopologyValidationError::SharedExclusiveCore {
            first: id("w1"),
            second: id("w2"),
            core: CoreId(2),
        }
    );
}

#[test]
fn a_pair_that_shares_cores_stops_being_allowed_once_unpaired() {
    let mut topology = full();
    topology.standby_pairs.remove(1);
    assert_eq!(
        refused(&topology),
        TopologyValidationError::SharedExclusiveCore {
            first: id("w1"),
            second: id("w1-standby"),
            core: CoreId(1),
        }
    );
}

#[test]
fn an_empty_exclusive_core_set_is_refused() {
    let mut topology = full();
    topology.units[4].placement = CorePlacement::Exclusive(Vec::new());
    assert_eq!(
        refused(&topology),
        TopologyValidationError::EmptyCoreSet { unit: id("w2") }
    );
}

#[test]
fn a_duplicate_core_is_refused() {
    let mut topology = full();
    topology.units[4].placement = CorePlacement::Exclusive(vec![CoreId(5), CoreId(5)]);
    assert_eq!(
        refused(&topology),
        TopologyValidationError::DuplicateEntry {
            collection: Collection::Cores { unit: id("w2") },
            entry: "core 5".to_string(),
        }
    );
}

#[test]
fn a_recovery_bound_with_no_standby_kept_is_refused() {
    let mut topology = full();
    topology.standby_pairs[1].class = StandbyClass::None;
    assert_eq!(
        refused(&topology),
        TopologyValidationError::RecoveryBoundWithoutStandby { active: id("w1") }
    );

    topology.standby_pairs[1].recovery_bound_ms = None;
    topology.validate().unwrap();
}

#[test]
fn a_recovery_bound_no_longer_than_the_liveness_period_is_refused() {
    for period in [200, 201] {
        let mut topology = full();
        topology.units[2].liveness_period_ms = NonZeroU32::new(period);
        assert_eq!(
            refused(&topology),
            TopologyValidationError::RecoveryBoundWithinLivenessPeriod {
                active: id("w1"),
                bound_ms: NonZeroU32::new(200).unwrap(),
                period_ms: NonZeroU32::new(period).unwrap(),
            },
            "period {period}"
        );
    }
    let mut topology = full();
    topology.units[2].liveness_period_ms = NonZeroU32::new(199);
    topology.validate().unwrap();
}

#[test]
fn a_liveness_period_on_the_standby_does_not_constrain_the_bound() {
    let mut topology = full();
    topology.units[3].liveness_period_ms = NonZeroU32::new(500);
    topology.validate().unwrap();
}

#[test]
fn a_unit_in_two_standby_pairs_is_refused() {
    let mut topology = full();
    topology.standby_pairs[1].standby = id("ctl-b");
    topology.units[3].placement = CorePlacement::Floating;
    assert_eq!(
        refused(&topology),
        TopologyValidationError::UnitInTwoPairs { unit: id("ctl-b") }
    );
}

#[test]
fn a_unit_paired_with_itself_is_refused() {
    let mut topology = full();
    topology.standby_pairs[1].standby = id("w1");
    assert_eq!(
        refused(&topology),
        TopologyValidationError::SelfStandby { unit: id("w1") }
    );
}

#[test]
fn errors_name_the_offending_element() {
    let message = TopologyValidationError::SharedExclusiveCore {
        first: id("w1"),
        second: id("w2"),
        core: CoreId(2),
    }
    .to_string();
    assert!(message.contains("w1") && message.contains("w2") && message.contains('2'));
}

#[test]
fn an_isolation_label_is_the_serde_spelling() {
    for tier in [
        IsolationTier::Task,
        IsolationTier::Partition,
        IsolationTier::Vm,
    ] {
        assert_eq!(
            serde_json::to_value(tier).unwrap(),
            serde_json::Value::String(tier.label().to_string())
        );
    }
}
