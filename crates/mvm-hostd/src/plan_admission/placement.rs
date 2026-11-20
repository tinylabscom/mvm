//! The host cores an admitted launch is confined to, and the check that the
//! scope it was born into holds exactly those.
//!
//! A unit whose topology entry holds cores exclusively runs on those cores. A
//! floating unit, or a plan bound to no topology, runs on the cores nothing
//! holds exclusively, but only while something on this host holds any: with
//! no core held, nothing is confined and scheduling is the host's, as it has
//! always been. While cores are held, a launch that cannot be confined to the
//! rest is refused rather than run on them.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_contract::plan::topology::{CorePlacement, Unit};
use mvm_contract::protocol::cpu_set::CpuSet;
use mvm_contract::protocol::resource_controls::EnforcedGrants;
use mvm_contract::protocol::vm_backend::BackendKind;

use crate::topology_admission::placement::{
    HostCpus, HostPlacementRefusal, held_on_host, remaining_cores,
};

/// The cores admission placed a launch on, and whether they are the unit's
/// own exclusive cores or the cores left over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmittedPlacement {
    pub(crate) cpus: CpuSet,
    pub(crate) exclusive: bool,
}

/// Why a launch cannot be placed while cores are held exclusively.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum PlanPlacementRefusal {
    #[error(
        "cores {held} are held exclusively on this host, and a launch on {} cannot be \
         confined to the rest",
        .backend.map_or("an unknown backend", BackendKind::as_str)
    )]
    BackendCannotConfine {
        backend: Option<BackendKind>,
        held: CpuSet,
    },
    #[error(
        "cores {held} are held exclusively on this host, and its spawn scope cannot carry a \
         CPU set to keep this launch off them"
    )]
    ScopeCannotConfine { held: CpuSet },
    #[error("cores {held} are held exclusively, and this host publishes no list of its CPUs")]
    NoCpuList { held: CpuSet },
    #[error(transparent)]
    Host(#[from] HostPlacementRefusal),
}

/// The placement of a launch, or `None` when it is not confined.
///
/// `unit` is the topology unit the plan boots, from the binding check. A unit
/// holding cores exclusively gets them on any backend; topology admission
/// already refused it on one without the mechanism, and the read-back refuses
/// a scope that did not hold them.
///
/// # Errors
///
/// The admitted topologies cannot be read, or a [`PlanPlacementRefusal`].
pub(super) fn admitted_placement(
    home: &Path,
    unit: Option<&Unit>,
    backend: Option<BackendKind>,
    host: &HostCpus,
    host_signer_keys_dir: Option<&Path>,
) -> Result<Option<AdmittedPlacement>> {
    if let Some(cpus) = unit.and_then(exclusive) {
        return Ok(Some(AdmittedPlacement {
            cpus,
            exclusive: true,
        }));
    }
    let held = held_on_host(home, host, host_signer_keys_dir)
        .context("reading the core placements held on this host")?;
    if held.is_empty() {
        return Ok(None);
    }
    Ok(Some(AdmittedPlacement {
        cpus: floating_cpus(backend, host, held)?,
        exclusive: false,
    }))
}

/// [`admitted_placement`] on this host, under `home`, with a refusal written
/// to the plan's chain once, as the topology binding check writes its own.
///
/// # Errors
///
/// As [`admitted_placement`], carrying the audited marker when the refusal
/// was recorded.
pub(super) fn admit_core_placement(
    home: &Path,
    plan: &mvm_core::plan::ExecutionPlan,
    unit: Option<&Unit>,
    backend: Option<BackendKind>,
    host_signer_keys_dir: Option<&Path>,
) -> Result<Option<AdmittedPlacement>> {
    let host = HostCpus::probe(home);
    admitted_placement(home, unit, backend, &host, host_signer_keys_dir).map_err(|refusal| {
        super::topology_binding::audit_refusal(
            home,
            plan,
            host_signer_keys_dir,
            super::topology_binding::AuditedRefusal::CORE_PLACEMENT,
            refusal,
        )
    })
}

/// The cores left for a floating launch while `held` are held.
fn floating_cpus(
    backend: Option<BackendKind>,
    host: &HostCpus,
    held: CpuSet,
) -> Result<CpuSet, PlanPlacementRefusal> {
    if backend != Some(BackendKind::Firecracker) {
        return Err(PlanPlacementRefusal::BackendCannotConfine { backend, held });
    }
    if !host.scope_cpuset {
        return Err(PlanPlacementRefusal::ScopeCannotConfine { held });
    }
    let Some(online) = &host.online else {
        return Err(PlanPlacementRefusal::NoCpuList { held });
    };
    Ok(remaining_cores(online, &held)?)
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
            require_isolated_cores: false,
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

    fn no_host() -> HostCpus {
        HostCpus {
            scope_cpuset: false,
            online: None,
            isolated: None,
            live: Vec::new(),
        }
    }

    /// A host where a running machine holds 2-3 exclusively.
    fn held_host() -> HostCpus {
        use crate::topology_admission::placement::{LiveMachine, PlacementOwner};
        HostCpus {
            scope_cpuset: true,
            online: Some(set("0-7")),
            isolated: None,
            live: vec![LiveMachine {
                name: "pinned".into(),
                cpus: Some(set("2-3")),
                owner: Some(PlacementOwner {
                    tenant: mvm_core::plan::TenantId("t".into()),
                    workload: mvm_core::plan::WorkloadId("a".into()),
                    exclusive: true,
                }),
            }],
        }
    }

    fn refusal(err: anyhow::Error) -> PlanPlacementRefusal {
        err.downcast::<PlanPlacementRefusal>()
            .expect("a typed refusal")
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
            admitted_placement(home.path(), Some(&unit), None, &no_host(), None).unwrap(),
            Some(AdmittedPlacement {
                cpus: set("4-5"),
                exclusive: true
            })
        );
    }

    #[test]
    fn nothing_is_confined_or_refused_while_no_core_is_held() {
        let home = tempfile::tempdir().unwrap();
        let unit = floating_unit();
        for backend in [
            Some(BackendKind::Firecracker),
            Some(BackendKind::Qemu),
            Some(BackendKind::Hvf),
            Some(BackendKind::Wasm),
            None,
        ] {
            for unit in [None, Some(&unit)] {
                assert_eq!(
                    admitted_placement(home.path(), unit, backend, &no_host(), None).unwrap(),
                    None,
                    "{backend:?}"
                );
            }
        }
    }

    #[test]
    fn a_floating_firecracker_launch_gets_the_cores_left_over() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(
            admitted_placement(
                home.path(),
                None,
                Some(BackendKind::Firecracker),
                &held_host(),
                None
            )
            .unwrap(),
            Some(AdmittedPlacement {
                cpus: set("0-1,4-7"),
                exclusive: false
            })
        );
    }

    #[test]
    fn a_launch_that_cannot_be_confined_is_refused_while_cores_are_held() {
        let home = tempfile::tempdir().unwrap();
        for backend in [
            Some(BackendKind::Qemu),
            Some(BackendKind::Libkrun),
            Some(BackendKind::Hvf),
            Some(BackendKind::Wasm),
            None,
        ] {
            let err = admitted_placement(home.path(), None, backend, &held_host(), None)
                .expect_err("refused");
            assert_eq!(
                refusal(err),
                PlanPlacementRefusal::BackendCannotConfine {
                    backend,
                    held: set("2-3")
                }
            );
        }
        let no_scope = HostCpus {
            scope_cpuset: false,
            ..held_host()
        };
        let err = admitted_placement(
            home.path(),
            None,
            Some(BackendKind::Firecracker),
            &no_scope,
            None,
        )
        .expect_err("refused");
        assert_eq!(
            refusal(err),
            PlanPlacementRefusal::ScopeCannotConfine { held: set("2-3") }
        );
        let no_list = HostCpus {
            online: None,
            ..held_host()
        };
        let err = admitted_placement(
            home.path(),
            None,
            Some(BackendKind::Firecracker),
            &no_list,
            None,
        )
        .expect_err("refused");
        assert_eq!(
            refusal(err),
            PlanPlacementRefusal::NoCpuList { held: set("2-3") }
        );
    }
}
