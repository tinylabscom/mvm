//! The binding of one execution plan to one unit of an admitted topology.
//!
//! A unit still boots from its own signed plan. The plan names the digest of
//! the topology it belongs to and the unit it is, and admission compares that
//! with the topology the host admitted last for the plan's tenant. A host that
//! has admitted no topology for the tenant admits unbound plans as it always
//! has; once it has admitted one, every plan for that tenant must be bound to
//! it.

use alloc::string::String;

use serde::{Deserialize, Serialize};

use super::{Topology, Unit, UnitResources};
use crate::assurance::Sha256Digest;
use crate::plan::execution_plan::ExecutionPlan;
use crate::plan::types::WorkloadId;

/// Which topology a plan belongs to and which of its units it boots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyBinding {
    /// [`Topology::digest`] of the generation the plan was issued under.
    pub topology: Sha256Digest,
    /// The unit's workload ID in that topology.
    pub unit: WorkloadId,
}

/// Why a plan's binding does not match the admitted topology.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TopologyBindingRefusal {
    #[error(
        "the plan names no topology, and this host has admitted topology {admitted} for its tenant"
    )]
    Unbound { admitted: Sha256Digest },
    #[error(
        "the plan is bound to topology {bound}, and this host has admitted none for its tenant"
    )]
    NoAdmittedTopology { bound: Sha256Digest },
    #[error("the plan is bound to topology {bound}; the admitted topology is {admitted}")]
    DigestMismatch {
        bound: Sha256Digest,
        admitted: Sha256Digest,
    },
    #[error("the plan names unit {} but launches workload {}", .unit.0, .workload.0)]
    WorkloadMismatch {
        unit: WorkloadId,
        workload: WorkloadId,
    },
    #[error("the admitted topology names no unit {}", .unit.0)]
    UnknownUnit { unit: WorkloadId },
    #[error("unit {} boots recipe {topology}; the plan boots {plan}", .unit.0)]
    RecipeMismatch {
        unit: WorkloadId,
        topology: Sha256Digest,
        plan: String,
    },
    #[error("unit {} is sized {topology:?}; the plan asks for {plan:?}", .unit.0)]
    ResourcesMismatch {
        unit: WorkloadId,
        topology: UnitResources,
        plan: UnitResources,
    },
}

/// The digest a plan boots from, in the sense of [`Unit::recipe`]: the pinned
/// bundle when there is one, since the bundle is what is verified and booted,
/// and the image otherwise.
#[must_use]
pub fn plan_recipe(plan: &ExecutionPlan) -> &str {
    plan.bundle
        .as_ref()
        .map_or(plan.image.sha256.as_str(), |bundle| {
            bundle.bundle_sha256.as_str()
        })
}

/// Compare `plan`'s binding with `admitted`, the topology the host admitted
/// last for the plan's tenant, and return the unit the plan boots, if any.
///
/// # Errors
///
/// The first mismatch, in the order of [`TopologyBindingRefusal`]'s variants.
pub fn check_topology_binding<'t>(
    plan: &ExecutionPlan,
    admitted: Option<&'t Topology>,
) -> Result<Option<&'t Unit>, TopologyBindingRefusal> {
    let (binding, topology) = match (plan.topology.as_ref(), admitted) {
        (None, None) => return Ok(None),
        (None, Some(topology)) => {
            return Err(TopologyBindingRefusal::Unbound {
                admitted: topology.digest(),
            });
        }
        (Some(binding), None) => {
            return Err(TopologyBindingRefusal::NoAdmittedTopology {
                bound: binding.topology.clone(),
            });
        }
        (Some(binding), Some(topology)) => (binding, topology),
    };
    let digest = topology.digest();
    if binding.topology != digest {
        return Err(TopologyBindingRefusal::DigestMismatch {
            bound: binding.topology.clone(),
            admitted: digest,
        });
    }
    if plan.workload != binding.unit {
        return Err(TopologyBindingRefusal::WorkloadMismatch {
            unit: binding.unit.clone(),
            workload: plan.workload.clone(),
        });
    }
    let unit = topology
        .units
        .iter()
        .find(|unit| unit.workload == binding.unit)
        .ok_or_else(|| TopologyBindingRefusal::UnknownUnit {
            unit: binding.unit.clone(),
        })?;
    check_unit(plan, unit)?;
    Ok(Some(unit))
}

fn check_unit(plan: &ExecutionPlan, unit: &Unit) -> Result<(), TopologyBindingRefusal> {
    let recipe = plan_recipe(plan);
    if !same_digest(&unit.recipe, recipe) {
        return Err(TopologyBindingRefusal::RecipeMismatch {
            unit: unit.workload.clone(),
            topology: unit.recipe.clone(),
            plan: recipe.into(),
        });
    }
    let asked = UnitResources {
        cpus: plan.resources.cpus,
        mem_mib: plan.resources.mem_mib,
        disk_mib: plan.resources.disk_mib,
    };
    if asked != unit.resources {
        return Err(TopologyBindingRefusal::ResourcesMismatch {
            unit: unit.workload.clone(),
            topology: unit.resources,
            plan: asked,
        });
    }
    Ok(())
}

/// Plans carry bare hex digests and topologies carry `sha256:`-prefixed ones.
fn same_digest(recipe: &Sha256Digest, plan: &str) -> bool {
    let hex =
        |s: &'_ str| -> String { s.strip_prefix("sha256:").unwrap_or(s).to_ascii_lowercase() };
    hex(recipe.as_str()) == hex(plan)
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;
    use crate::plan::execution_plan::minimal_plan;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes(&[byte; 32])
    }

    fn unit(plan: &ExecutionPlan) -> Unit {
        let mut topology = super::super::tests::full();
        let mut unit = topology.units.remove(0);
        unit.workload = plan.workload.clone();
        unit.recipe = Sha256Digest::parse(alloc::format!("sha256:{}", plan.image.sha256)).unwrap();
        unit.resources = UnitResources {
            cpus: plan.resources.cpus,
            mem_mib: plan.resources.mem_mib,
            disk_mib: plan.resources.disk_mib,
        };
        unit
    }

    /// A one-unit topology the plan matches exactly, and the plan bound to it.
    fn matching() -> (ExecutionPlan, Topology) {
        let mut plan = minimal_plan();
        let mut topology = super::super::tests::full();
        topology.units = alloc::vec![unit(&plan)];
        topology.standby_pairs.clear();
        topology.cells.clear();
        topology.edges.clear();
        topology.succession.clear();
        plan.topology = Some(TopologyBinding {
            topology: topology.digest(),
            unit: plan.workload.clone(),
        });
        (plan, topology)
    }

    #[test]
    fn an_unbound_plan_with_no_admitted_topology_passes() {
        assert_eq!(check_topology_binding(&minimal_plan(), None), Ok(None));
    }

    #[test]
    fn a_matching_bound_plan_passes_and_names_its_unit() {
        let (plan, topology) = matching();
        let unit = check_topology_binding(&plan, Some(&topology)).unwrap();
        assert_eq!(unit.unwrap().workload, plan.workload);
    }

    #[test]
    fn an_unbound_plan_is_refused_once_a_topology_is_admitted() {
        let (mut plan, topology) = matching();
        plan.topology = None;
        assert_eq!(
            check_topology_binding(&plan, Some(&topology)),
            Err(TopologyBindingRefusal::Unbound {
                admitted: topology.digest()
            })
        );
    }

    #[test]
    fn a_bound_plan_is_refused_when_no_topology_is_admitted() {
        let (plan, _) = matching();
        assert!(matches!(
            check_topology_binding(&plan, None),
            Err(TopologyBindingRefusal::NoAdmittedTopology { .. })
        ));
    }

    #[test]
    fn a_plan_bound_to_another_digest_is_refused() {
        let (mut plan, topology) = matching();
        plan.topology.as_mut().unwrap().topology = digest(9);
        assert_eq!(
            check_topology_binding(&plan, Some(&topology)),
            Err(TopologyBindingRefusal::DigestMismatch {
                bound: digest(9),
                admitted: topology.digest()
            })
        );
    }

    #[test]
    fn a_plan_naming_a_unit_the_topology_lacks_is_refused() {
        let (mut plan, mut topology) = matching();
        topology.units[0].workload = WorkloadId("unit-z".to_string());
        plan.topology.as_mut().unwrap().topology = topology.digest();
        assert_eq!(
            check_topology_binding(&plan, Some(&topology)),
            Err(TopologyBindingRefusal::UnknownUnit {
                unit: plan.workload.clone()
            })
        );
    }

    #[test]
    fn a_plan_for_another_workload_cannot_take_a_units_slot() {
        let (mut plan, topology) = matching();
        plan.workload = WorkloadId("vm-other".to_string());
        assert_eq!(
            check_topology_binding(&plan, Some(&topology)),
            Err(TopologyBindingRefusal::WorkloadMismatch {
                unit: topology.units[0].workload.clone(),
                workload: WorkloadId("vm-other".to_string()),
            })
        );
    }

    #[test]
    fn a_plan_booting_another_recipe_is_refused() {
        let (mut plan, topology) = matching();
        plan.image.sha256 = "b".repeat(64);
        assert!(matches!(
            check_topology_binding(&plan, Some(&topology)),
            Err(TopologyBindingRefusal::RecipeMismatch { .. })
        ));
    }

    #[test]
    fn a_pinned_bundle_is_the_recipe_rather_than_the_image() {
        let (mut plan, topology) = matching();
        plan.bundle = Some(crate::plan::bundle::PlanArtifact::new(
            plan.image.sha256.clone(),
            &[0; 64],
            crate::plan::bundle::KeyId("k".to_string()),
        ));
        plan.image.sha256 = "b".repeat(64);
        assert!(check_topology_binding(&plan, Some(&topology)).is_ok());
    }

    #[test]
    fn a_plan_sized_differently_from_its_unit_is_refused() {
        let changes: [fn(&mut ExecutionPlan); 3] = [
            |p: &mut ExecutionPlan| p.resources.cpus += 1,
            |p: &mut ExecutionPlan| p.resources.mem_mib += 1,
            |p: &mut ExecutionPlan| p.resources.disk_mib += 1,
        ];
        for change in changes {
            let (mut plan, topology) = matching();
            change(&mut plan);
            assert!(matches!(
                check_topology_binding(&plan, Some(&topology)),
                Err(TopologyBindingRefusal::ResourcesMismatch { .. })
            ));
        }
    }

    #[test]
    fn the_wall_clock_bound_is_not_part_of_the_unit() {
        let (mut plan, topology) = matching();
        plan.resources.timeouts.exec_secs += 60;
        assert!(check_topology_binding(&plan, Some(&topology)).is_ok());
    }

    #[test]
    fn an_unbound_plan_serializes_without_the_field() {
        let json = serde_json::to_string(&minimal_plan()).unwrap();
        assert!(!json.contains("\"topology\""));
    }
}
