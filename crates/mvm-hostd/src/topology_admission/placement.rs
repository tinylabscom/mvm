//! The host half of exclusive core placement: which cores this host has, which
//! cores admitted topologies already hold, and what is left for everything
//! else.
//!
//! [`check_requirements`](mvm_contract::plan::topology::check_requirements)
//! decides whether the backend has a mechanism at all, and
//! [`Topology::validate`] refuses an overlap between two units of one
//! topology. What neither can see is the host: a core the kernel does not
//! have, and a core another tenant's admitted topology holds.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_contract::plan::topology::{CorePlacement, Topology};
use mvm_contract::protocol::cpu_set::CpuSet;
use mvm_core::plan::{TenantId, WorkloadId};

/// What admission needs to know about this host's cores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCpus {
    /// Whether a spawn scope here can carry an allowed-CPU set.
    pub scope_cpuset: bool,
    /// The CPUs the kernel has online, or `None` where it publishes no list.
    pub online: Option<CpuSet>,
}

impl HostCpus {
    /// This host, as it is now.
    #[must_use]
    pub fn probe() -> Self {
        Self {
            scope_cpuset: mvm_core::spawn_scope::cpuset_gap().is_none(),
            online: mvm_core::spawn_scope::online_cpus(),
        }
    }
}

/// Why this host cannot serve a topology's exclusive placement, or what is
/// left of it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostPlacementRefusal {
    #[error("unit {} holds core {core} exclusively, and this host has no such core", .unit.0)]
    UnknownCore { unit: WorkloadId, core: u32 },
    #[error(
        "unit {} holds core {core} exclusively, and this host publishes no list of its CPUs",
        .unit.0
    )]
    NoCpuList { unit: WorkloadId, core: u32 },
    #[error(
        "unit {} holds core {core} exclusively, which unit {} of tenant {} already holds",
        .unit.0, .other_unit.0, .other_tenant.0
    )]
    HeldByAnotherTenant {
        unit: WorkloadId,
        core: u32,
        other_tenant: TenantId,
        other_unit: WorkloadId,
    },
    #[error("exclusive placement holds every online core ({held}), leaving none for anything else")]
    NoCoreLeft { held: CpuSet },
}

/// Every core any unit of `topology` holds exclusively.
#[must_use]
pub(crate) fn exclusive_cores(topology: &Topology) -> CpuSet {
    topology
        .units
        .iter()
        .fold(CpuSet::default(), |held, unit| match &unit.placement {
            CorePlacement::Floating => held,
            CorePlacement::Exclusive(cores) => held.union(&CpuSet::from_cores(cores)),
        })
}

/// Check `topology`, about to be admitted for `tenant`, against this host's
/// cores and the topologies already admitted for other tenants.
///
/// `admitted` may include `tenant`'s own last generation; it is skipped,
/// because the generation being admitted replaces it.
///
/// # Errors
///
/// The first core the host lacks, the first core another tenant holds, or a
/// placement that would leave no core for floating units and MVM's own work.
pub(crate) fn check_host_placement(
    tenant: &TenantId,
    topology: &Topology,
    host: &HostCpus,
    admitted: &[(TenantId, Topology)],
) -> Result<(), HostPlacementRefusal> {
    let others: Vec<&(TenantId, Topology)> = admitted
        .iter()
        .filter(|(other, _)| other != tenant)
        .collect();
    let mut held = CpuSet::default();
    for unit in &topology.units {
        let CorePlacement::Exclusive(cores) = &unit.placement else {
            continue;
        };
        let cores = CpuSet::from_cores(cores);
        for core in cores.iter() {
            match &host.online {
                None => {
                    return Err(HostPlacementRefusal::NoCpuList {
                        unit: unit.workload.clone(),
                        core,
                    });
                }
                Some(online) if !online.contains(core) => {
                    return Err(HostPlacementRefusal::UnknownCore {
                        unit: unit.workload.clone(),
                        core,
                    });
                }
                Some(_) => {}
            }
        }
        for (other_tenant, other) in &others {
            for other_unit in &other.units {
                let CorePlacement::Exclusive(other_cores) = &other_unit.placement else {
                    continue;
                };
                if let Some(core) = cores.first_shared(&CpuSet::from_cores(other_cores)) {
                    return Err(HostPlacementRefusal::HeldByAnotherTenant {
                        unit: unit.workload.clone(),
                        core,
                        other_tenant: other_tenant.clone(),
                        other_unit: other_unit.workload.clone(),
                    });
                }
            }
        }
        held = held.union(&cores);
    }
    if let Some(online) = &host.online
        && !held.is_empty()
    {
        let held_everywhere = others
            .iter()
            .fold(held, |all, (_, other)| all.union(&exclusive_cores(other)));
        remaining_cores(online, &held_everywhere)?;
    }
    Ok(())
}

/// The online cores no admitted topology holds exclusively.
///
/// # Errors
///
/// [`HostPlacementRefusal::NoCoreLeft`] when nothing remains.
pub(crate) fn remaining_cores(
    online: &CpuSet,
    held: &CpuSet,
) -> Result<CpuSet, HostPlacementRefusal> {
    let remaining = online.difference(held);
    if remaining.is_empty() {
        return Err(HostPlacementRefusal::NoCoreLeft { held: held.clone() });
    }
    Ok(remaining)
}

/// The last admitted generation for every tenant with a topology on record
/// under `home`, each verified again.
///
/// # Errors
///
/// A topology store that cannot be listed, or a record that does not verify.
/// A directory whose name is not a tenant is skipped: nothing admits one.
pub(crate) fn admitted_topologies(
    home: &Path,
    host_signer_keys_dir: Option<&Path>,
) -> Result<Vec<(TenantId, Topology)>> {
    let dir = mvm_core::config::topologies_dir_at(home);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("listing {}", dir.display())),
    };
    let mut admitted = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("listing {}", dir.display()))?;
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if crate::audit::prune_pins::validate_tenant(&name).is_err() {
            continue;
        }
        let tenant = TenantId(name);
        if let Some(topology) = super::last_admitted_topology(home, &tenant, host_signer_keys_dir)?
        {
            admitted.push((tenant, topology));
        }
    }
    admitted.sort_by(|a, b| a.0.0.cmp(&b.0.0));
    Ok(admitted)
}

/// Every core held exclusively by any topology admitted under the resolved
/// mvm home, for a report rather than a decision.
///
/// # Errors
///
/// As [`admitted_topologies`].
pub fn exclusive_cores_held_on_host() -> Result<CpuSet> {
    held_on_host(&mvm_core::config::mvm_home_strict()?, None)
}

/// Every core held exclusively by any topology admitted on this host.
///
/// # Errors
///
/// As [`admitted_topologies`].
pub(crate) fn held_on_host(home: &Path, host_signer_keys_dir: Option<&Path>) -> Result<CpuSet> {
    Ok(admitted_topologies(home, host_signer_keys_dir)?
        .iter()
        .fold(CpuSet::default(), |held, (_, topology)| {
            held.union(&exclusive_cores(topology))
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::plan::topology::CoreId;

    fn tenant(name: &str) -> TenantId {
        TenantId(name.to_string())
    }

    fn with_placements(placements: &[(&str, &[u32])]) -> Topology {
        let mut topology = super::super::tests::topology(1);
        let template = topology.units[0].clone();
        topology.units = placements
            .iter()
            .map(|(name, cores)| {
                let mut unit = template.clone();
                unit.workload = WorkloadId((*name).to_string());
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
            online: Some(CpuSet::parse(online).unwrap()),
        }
    }

    #[test]
    fn a_core_the_host_does_not_have_is_refused() {
        let topology = with_placements(&[("a", &[2, 9])]);
        assert_eq!(
            check_host_placement(&tenant("t"), &topology, &host("0-7"), &[]),
            Err(HostPlacementRefusal::UnknownCore {
                unit: WorkloadId("a".into()),
                core: 9
            })
        );
    }

    #[test]
    fn a_host_with_no_cpu_list_refuses_any_exclusive_core() {
        let topology = with_placements(&[("a", &[1])]);
        let host = HostCpus {
            scope_cpuset: true,
            online: None,
        };
        assert_eq!(
            check_host_placement(&tenant("t"), &topology, &host, &[]),
            Err(HostPlacementRefusal::NoCpuList {
                unit: WorkloadId("a".into()),
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
                unit: WorkloadId("a".into()),
                core: 3,
                other_tenant: tenant("u"),
                other_unit: WorkloadId("y".into()),
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
        let no_list = HostCpus {
            scope_cpuset: false,
            online: None,
        };
        assert_eq!(
            check_host_placement(&tenant("t"), &floating, &no_list, &[]),
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
            Err(HostPlacementRefusal::NoCoreLeft {
                held: CpuSet::parse("0-3").unwrap()
            })
        );
    }

    #[test]
    fn the_remaining_cores_exclude_every_held_one() {
        let online = CpuSet::parse("0-7").unwrap();
        let held = exclusive_cores(&with_placements(&[("a", &[2, 3]), ("b", &[]), ("c", &[6])]));
        assert_eq!(held.to_string(), "2-3,6");
        assert_eq!(
            remaining_cores(&online, &held).unwrap().to_string(),
            "0-1,4-5,7"
        );
    }
}
