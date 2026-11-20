use super::*;
use mvm_contract::plan::topology::{CoreId, StandbyClass, StandbyPair};

fn tenant(name: &str) -> TenantId {
    TenantId(name.to_string())
}

fn wid(name: &str) -> WorkloadId {
    WorkloadId(name.to_string())
}

fn set(list: &str) -> CpuSet {
    CpuSet::parse(list).unwrap()
}

fn with_placements(placements: &[(&str, &[u32])]) -> Topology {
    let mut topology = super::super::tests::topology(1);
    let template = topology.units[0].clone();
    topology.standby_pairs.clear();
    topology.units = placements
        .iter()
        .map(|(name, cores)| {
            let mut unit = template.clone();
            unit.workload = wid(name);
            unit.placement = if cores.is_empty() {
                CorePlacement::Floating
            } else {
                CorePlacement::Exclusive(cores.iter().map(|c| CoreId(*c)).collect())
            };
            unit
        })
        .collect();
    topology
}

fn host(online: &str) -> HostCpus {
    HostCpus {
        scope_cpuset: true,
        online: Some(set(online)),
        isolated: Some(CpuSet::default()),
        live: Vec::new(),
    }
}

fn running(name: &str, cpus: Option<&str>, owner: Option<(&str, &str, bool)>) -> LiveMachine {
    LiveMachine {
        name: name.to_string(),
        cpus: cpus.map(set),
        owner: owner.map(|(t, w, exclusive)| PlacementOwner {
            tenant: tenant(t),
            workload: wid(w),
            exclusive,
        }),
    }
}

#[test]
fn a_core_the_host_does_not_have_is_refused() {
    let topology = with_placements(&[("a", &[2, 9])]);
    assert_eq!(
        check_host_placement(&tenant("t"), &topology, &host("0-7"), &[]),
        Err(HostPlacementRefusal::UnknownCore {
            unit: wid("a"),
            core: 9
        })
    );
}

#[test]
fn a_host_with_no_cpu_list_refuses_any_exclusive_core() {
    let topology = with_placements(&[("a", &[1])]);
    let host = HostCpus {
        online: None,
        ..host("0")
    };
    assert_eq!(
        check_host_placement(&tenant("t"), &topology, &host, &[]),
        Err(HostPlacementRefusal::NoCpuList {
            unit: wid("a"),
            core: 1
        })
    );
}

#[test]
fn a_core_another_tenant_holds_is_refused() {
    let ours = with_placements(&[("a", &[2, 3])]);
    let theirs = with_placements(&[("x", &[]), ("y", &[3, 4])]);
    assert_eq!(
        check_host_placement(&tenant("t"), &ours, &host("0-7"), &[(tenant("u"), theirs)]),
        Err(HostPlacementRefusal::HeldByAnotherTenant {
            unit: wid("a"),
            core: 3,
            other_tenant: tenant("u"),
            other_unit: wid("y"),
        })
    );
}

#[test]
fn our_own_previous_generation_does_not_conflict() {
    let ours = with_placements(&[("a", &[2, 3])]);
    let previous = ours.clone();
    assert_eq!(
        check_host_placement(
            &tenant("t"),
            &ours,
            &host("0-7"),
            &[(tenant("t"), previous)]
        ),
        Ok(())
    );
}

#[test]
fn disjoint_tenants_and_floating_units_are_admitted() {
    let ours = with_placements(&[("a", &[2, 3]), ("b", &[])]);
    let theirs = with_placements(&[("y", &[4])]);
    assert_eq!(
        check_host_placement(&tenant("t"), &ours, &host("0-7"), &[(tenant("u"), theirs)]),
        Ok(())
    );
    let floating = with_placements(&[("a", &[])]);
    let nothing_known = HostCpus {
        scope_cpuset: false,
        online: None,
        isolated: None,
        live: vec![running("anything", None, None)],
    };
    assert_eq!(
        check_host_placement(&tenant("t"), &floating, &nothing_known, &[]),
        Ok(()),
        "a topology with no exclusive core reads nothing off the host"
    );
}

#[test]
fn a_placement_that_leaves_no_core_is_refused() {
    let ours = with_placements(&[("a", &[0, 1])]);
    let theirs = with_placements(&[("y", &[2, 3])]);
    assert_eq!(
        check_host_placement(&tenant("t"), &ours, &host("0-3"), &[(tenant("u"), theirs)]),
        Err(HostPlacementRefusal::NoCoreLeft { held: set("0-3") })
    );
}

#[test]
fn the_remaining_cores_exclude_every_held_one() {
    let online = set("0-7");
    let held = exclusive_cores(&with_placements(&[("a", &[2, 3]), ("b", &[]), ("c", &[6])]));
    assert_eq!(held.to_string(), "2-3,6");
    assert_eq!(
        remaining_cores(&online, &held).unwrap().to_string(),
        "0-1,4-5,7"
    );
}

fn requiring_isolation(cores: &[u32]) -> Topology {
    let mut topology = with_placements(&[("a", cores)]);
    topology.units[0].require_isolated_cores = true;
    topology
}

#[test]
fn required_isolation_on_isolated_cores_is_admitted() {
    let host = HostCpus {
        isolated: Some(set("2-5")),
        ..host("0-7")
    };
    assert_eq!(
        check_host_placement(&tenant("t"), &requiring_isolation(&[2, 3]), &host, &[]),
        Ok(())
    );
}

#[test]
fn required_isolation_names_the_cores_that_are_not_isolated() {
    let host = HostCpus {
        isolated: Some(set("2")),
        ..host("0-7")
    };
    assert_eq!(
        check_host_placement(&tenant("t"), &requiring_isolation(&[2, 3, 4]), &host, &[]),
        Err(HostPlacementRefusal::CoresNotIsolated {
            unit: wid("a"),
            cores: set("3-4"),
        })
    );
}

#[test]
fn isolation_is_not_read_when_it_is_not_required() {
    let host = HostCpus {
        isolated: None,
        ..host("0-7")
    };
    assert_eq!(
        check_host_placement(&tenant("t"), &with_placements(&[("a", &[2])]), &host, &[]),
        Ok(())
    );
}

#[test]
fn required_isolation_without_an_isolation_list_is_refused() {
    let host = HostCpus {
        isolated: None,
        ..host("0-7")
    };
    assert_eq!(
        check_host_placement(&tenant("t"), &requiring_isolation(&[2]), &host, &[]),
        Err(HostPlacementRefusal::NoIsolationList { unit: wid("a") })
    );
}

#[test]
fn an_unconfined_running_machine_holds_every_online_core() {
    let host = HostCpus {
        live: vec![running("old-vm", None, None)],
        ..host("0-7")
    };
    assert_eq!(
        check_host_placement(
            &tenant("t"),
            &with_placements(&[("a", &[2, 3])]),
            &host,
            &[]
        ),
        Err(HostPlacementRefusal::HeldByLiveMachine {
            unit: wid("a"),
            machine: "old-vm".into(),
            cores: set("2-3"),
        })
    );
}

#[test]
fn a_confined_running_machine_conflicts_only_on_its_own_cores() {
    let host = HostCpus {
        live: vec![running(
            "floating-vm",
            Some("0-1,4-7"),
            Some(("t", "b", false)),
        )],
        ..host("0-7")
    };
    assert_eq!(
        check_host_placement(
            &tenant("t"),
            &with_placements(&[("a", &[2, 3])]),
            &host,
            &[]
        ),
        Ok(())
    );
    assert_eq!(
        check_host_placement(
            &tenant("t"),
            &with_placements(&[("a", &[3, 4])]),
            &host,
            &[]
        ),
        Err(HostPlacementRefusal::HeldByLiveMachine {
            unit: wid("a"),
            machine: "floating-vm".into(),
            cores: set("4"),
        })
    );
}

#[test]
fn the_units_own_pair_may_keep_running_on_its_cores() {
    let mut topology = with_placements(&[("a", &[2, 3]), ("a-standby", &[2, 3])]);
    topology.standby_pairs = vec![StandbyPair {
        active: wid("a"),
        standby: wid("a-standby"),
        class: StandbyClass::None,
        recovery_bound_ms: None,
    }];
    let host = HostCpus {
        live: vec![
            running("a-vm", Some("2-3"), Some(("t", "a", true))),
            running("standby-vm", Some("2-3"), Some(("t", "a-standby", true))),
        ],
        ..host("0-7")
    };
    assert_eq!(
        check_host_placement(&tenant("t"), &topology, &host, &[]),
        Ok(())
    );
    // The same machines belong to no unit of another tenant's topology.
    assert!(matches!(
        check_host_placement(&tenant("u"), &with_placements(&[("a", &[2])]), &host, &[]),
        Err(HostPlacementRefusal::HeldByLiveMachine { .. })
    ));
}

#[test]
fn a_running_exclusive_machine_keeps_its_cores_held_after_release() {
    // The tenant's latest generation no longer holds 2-3, but the machine
    // placed there under the earlier one still runs.
    let both = HostCpus {
        live: vec![
            running("pinned", Some("2-3"), Some(("t", "a", true))),
            running("floating", Some("0-1,4-7"), Some(("t", "b", false))),
        ],
        ..host("0-7")
    };
    assert_eq!(both.held_by_live_machines(), set("2-3"));
    assert_eq!(
        check_host_placement(
            &tenant("t"),
            &with_placements(&[("c", &[0, 1, 4, 5, 6, 7])]),
            &HostCpus {
                live: vec![running("pinned", Some("2-3"), Some(("t", "a", true)))],
                ..host("0-7")
            },
            &[]
        ),
        Err(HostPlacementRefusal::NoCoreLeft { held: set("0-7") })
    );
}

#[test]
fn a_malformed_owner_record_on_a_running_machine_refuses_an_exclusive_topology() {
    let home = tempfile::tempdir().unwrap();
    let dir = mvm_core::config::vm_state_dir_at(home.path(), "garbled");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("libkrun.pid"), std::process::id().to_string()).unwrap();
    std::fs::write(dir.join(mvm_core::spawn_scope::PLACEMENT_OWNER_FILE), "{").unwrap();
    // Its recorded set would keep it off core 2, but nothing read beside a
    // record that cannot be trusted is trusted either.
    std::fs::write(dir.join("spawn-scope-cpus"), "0-1").unwrap();
    let host = HostCpus {
        live: live::live_machines(home.path()),
        ..host("0-7")
    };
    assert_eq!(
        check_host_placement(&tenant("t"), &with_placements(&[("a", &[2])]), &host, &[]),
        Err(HostPlacementRefusal::HeldByLiveMachine {
            unit: wid("a"),
            machine: "garbled".into(),
            cores: set("2"),
        })
    );
}
