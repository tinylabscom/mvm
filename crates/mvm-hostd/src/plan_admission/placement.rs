//! The host cores an admitted launch is confined to, and the check that the
//! scope it was born into holds exactly those.
//!
//! A unit whose topology entry holds cores exclusively runs on those cores. A
//! floating unit, or a plan bound to no topology, runs on the cores no admitted
//! topology holds, but only while some topology on this host holds any: with
//! none admitted, nothing is confined and scheduling is the host's, as it has
//! always been.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_contract::plan::topology::{CorePlacement, Unit};
use mvm_contract::protocol::cpu_set::CpuSet;
use mvm_contract::protocol::resource_controls::EnforcedGrants;
use mvm_contract::protocol::vm_backend::BackendKind;

use crate::topology_admission::placement::{held_on_host, remaining_cores};

/// The CPU set to confine a launch to, or `None` when it is not confined.
///
/// `unit` is the topology unit the plan boots, from the binding check.
/// Floating confinement applies only on Firecracker, the one backend that
/// declares a scope CPU set; a unit holding cores exclusively was refused at
/// topology admission on any other.
///
/// # Errors
///
/// The admitted topologies cannot be read, the host publishes no CPU list
/// while cores are held, or the held cores leave none.
pub(super) fn admitted_cpus(
    home: &Path,
    unit: Option<&Unit>,
    backend: Option<BackendKind>,
    host_signer_keys_dir: Option<&Path>,
) -> Result<Option<CpuSet>> {
    if let Some(cores) = unit.and_then(exclusive) {
        return Ok(Some(cores));
    }
    if backend != Some(BackendKind::Firecracker) {
        return Ok(None);
    }
    let held = held_on_host(home, host_signer_keys_dir)
        .context("reading the core placements admitted on this host")?;
    if held.is_empty() {
        return Ok(None);
    }
    let online = mvm_core::spawn_scope::online_cpus().with_context(|| {
        format!("cores {held} are held exclusively and this host publishes no list of its CPUs")
    })?;
    Ok(Some(remaining_cores(&online, &held)?))
}

fn exclusive(unit: &Unit) -> Option<CpuSet> {
    match &unit.placement {
        CorePlacement::Floating => None,
        CorePlacement::Exclusive(cores) => Some(CpuSet::from_cores(cores)),
    }
}

/// A scope that does not hold the cores the launch was placed on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "the VMM's scope was asked for cores {requested} and reads back {}",
    .effective.as_ref().map_or_else(|| "no cpuset".to_string(), ToString::to_string)
)]
pub(crate) struct PlacementMismatch {
    pub(crate) requested: CpuSet,
    pub(crate) effective: Option<CpuSet>,
}

/// Record `requested` beside the read-back in `enforced`, and refuse a
/// read-back that differs from it.
///
/// A launch admission did not place records nothing, whatever the backend
/// read back: its scope's cpuset is whatever it inherited, not a placement.
///
/// # Errors
///
/// [`PlacementMismatch`] when the effective set is absent or not the request.
pub(super) fn check_placement_readback(
    requested: Option<&CpuSet>,
    enforced: &mut EnforcedGrants,
) -> Result<(), PlacementMismatch> {
    let Some(requested) = requested else {
        enforced.placement = Default::default();
        return Ok(());
    };
    enforced.placement.requested = Some(requested.clone());
    if enforced.placement.effective.as_ref() == Some(requested) {
        return Ok(());
    }
    Err(PlacementMismatch {
        requested: requested.clone(),
        effective: enforced.placement.effective.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::resource_controls::EnforcedPlacement;

    fn set(list: &str) -> CpuSet {
        CpuSet::parse(list).unwrap()
    }

    fn floating_unit() -> Unit {
        use mvm_contract::plan::topology::{SealedTransitions, UnitResources, UnitRole};
        Unit {
            workload: mvm_core::plan::WorkloadId("w".to_string()),
            role: UnitRole::Worker,
            recipe: mvm_contract::assurance::Sha256Digest::from_bytes(&[7; 32]),
            resources: UnitResources {
                cpus: 1,
                mem_mib: 256,
                disk_mib: 512,
            },
            placement: CorePlacement::Floating,
            min_isolation: None,
            liveness_period_ms: None,
            permits: SealedTransitions::default(),
        }
    }

    fn read_back(effective: Option<&str>) -> EnforcedGrants {
        let mut grants = EnforcedGrants::all_declared();
        grants.placement.effective = effective.map(set);
        grants
    }

    #[test]
    fn a_matching_read_back_is_recorded_with_its_request() {
        let mut grants = read_back(Some("2,3"));
        check_placement_readback(Some(&set("2-3")), &mut grants).unwrap();
        assert_eq!(
            grants.placement,
            EnforcedPlacement {
                requested: Some(set("2-3")),
                effective: Some(set("2-3")),
            }
        );
    }

    #[test]
    fn a_read_back_that_differs_is_refused() {
        let mut grants = read_back(Some("0-7"));
        assert_eq!(
            check_placement_readback(Some(&set("2-3")), &mut grants),
            Err(PlacementMismatch {
                requested: set("2-3"),
                effective: Some(set("0-7")),
            })
        );
    }

    #[test]
    fn a_missing_read_back_is_refused() {
        let mut grants = read_back(None);
        let err = check_placement_readback(Some(&set("1")), &mut grants).unwrap_err();
        assert_eq!(
            err.to_string(),
            "the VMM's scope was asked for cores 1 and reads back no cpuset"
        );
    }

    #[test]
    fn an_unplaced_launch_records_no_placement() {
        let mut grants = read_back(Some("0-7"));
        check_placement_readback(None, &mut grants).unwrap();
        assert!(grants.placement.is_unset());
    }

    #[test]
    fn a_unit_holding_cores_is_confined_to_them_on_any_backend() {
        let home = tempfile::tempdir().unwrap();
        let mut unit = floating_unit();
        unit.placement = CorePlacement::Exclusive(vec![
            mvm_contract::plan::topology::CoreId(4),
            mvm_contract::plan::topology::CoreId(5),
        ]);
        assert_eq!(
            admitted_cpus(home.path(), Some(&unit), None, None).unwrap(),
            Some(set("4-5"))
        );
    }

    #[test]
    fn nothing_is_confined_while_no_topology_holds_a_core() {
        let home = tempfile::tempdir().unwrap();
        let unit = floating_unit();
        for unit in [None, Some(&unit)] {
            assert_eq!(
                admitted_cpus(home.path(), unit, Some(BackendKind::Firecracker), None).unwrap(),
                None
            );
        }
        assert_eq!(
            admitted_cpus(home.path(), None, Some(BackendKind::Qemu), None).unwrap(),
            None
        );
    }
}
