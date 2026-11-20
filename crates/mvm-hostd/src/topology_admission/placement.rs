//! The host half of exclusive core placement: which cores this host has, which
//! cores admitted topologies and running machines already hold, and what is
//! left for everything else.
//!
//! [`check_requirements`](mvm_contract::plan::topology::check_requirements)
//! decides whether the backend has a mechanism at all, and
//! [`Topology::validate`] refuses an overlap between two units of one
//! topology. What neither can see is the host: a core the kernel does not
//! have or does not isolate, a core another tenant's admitted topology holds,
//! and a core a machine that is already running may use.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_contract::plan::topology::{CorePlacement, Topology, Unit};
use mvm_contract::protocol::cpu_set::CpuSet;
use mvm_core::plan::{TenantId, WorkloadId};

mod live;
pub(crate) use live::record_owner;
pub use live::{LiveMachine, PlacementOwner};

/// What admission needs to know about this host's cores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCpus {
    /// Whether a spawn scope here can carry an allowed-CPU set.
    pub scope_cpuset: bool,
    /// The CPUs the kernel has online, or `None` where it publishes no list.
    pub online: Option<CpuSet>,
    /// The CPUs isolated from the general scheduler, or `None` where the
    /// kernel publishes no list.
    pub isolated: Option<CpuSet>,
    /// Every machine running on this host, with the cores it may use.
    pub live: Vec<LiveMachine>,
}

impl HostCpus {
    /// This host, as it is now, with the machines running under `home`.
    #[must_use]
    pub fn probe(home: &Path) -> Self {
        Self {
            scope_cpuset: mvm_core::spawn_scope::cpuset_gap().is_none(),
            online: mvm_core::spawn_scope::online_cpus(),
            isolated: mvm_core::spawn_scope::isolated_cpus(),
            live: live::live_machines(home),
        }
    }

    /// The cores a running machine may use: its recorded set, or every online
    /// core when it was not confined.
    fn cores_of<'a>(&'a self, machine: &'a LiveMachine) -> Option<&'a CpuSet> {
        machine.cpus.as_ref().or(self.online.as_ref())
    }

    /// Cores running machines hold exclusively, whatever the latest
    /// generation of their topology says.
    #[must_use]
    pub fn held_by_live_machines(&self) -> CpuSet {
        self.live
            .iter()
            .filter(|machine| machine.owner.as_ref().is_some_and(|o| o.exclusive))
            .filter_map(|machine| machine.cpus.as_ref())
            .fold(CpuSet::default(), |held, cpus| held.union(cpus))
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
    #[error(
        "unit {} holds cores {cores} exclusively, and running machine {machine} may use them",
        .unit.0
    )]
    HeldByLiveMachine {
        unit: WorkloadId,
        machine: String,
        cores: CpuSet,
    },
    #[error(
        "unit {} requires its cores isolated from the general scheduler, and {cores} are not",
        .unit.0
    )]
    CoresNotIsolated { unit: WorkloadId, cores: CpuSet },
    #[error(
        "unit {} requires its cores isolated from the general scheduler, and this host \
         publishes no list of isolated CPUs",
        .unit.0
    )]
    NoIsolationList { unit: WorkloadId },
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
/// cores, the topologies already admitted for other tenants, and the machines
/// already running.
///
/// `admitted` may include `tenant`'s own last generation; it is skipped,
/// because the generation being admitted replaces it. A running machine is
/// not skipped for that reason: a core it may use stays in use until it stops.
///
/// # Errors
///
/// The first refusal in the order of [`HostPlacementRefusal`]'s checks per
/// unit, then a placement that would leave no core free.
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
        check_online(unit, &cores, host)?;
        check_isolated(unit, &cores, host)?;
        check_other_tenants(unit, &cores, &others)?;
        check_live_machines(tenant, topology, unit, &cores, host)?;
        held = held.union(&cores);
    }
    if let Some(online) = &host.online
        && !held.is_empty()
    {
        let held_everywhere = others
            .iter()
            .fold(held, |all, (_, other)| all.union(&exclusive_cores(other)))
            .union(&host.held_by_live_machines());
        remaining_cores(online, &held_everywhere)?;
    }
    Ok(())
}

fn check_online(unit: &Unit, cores: &CpuSet, host: &HostCpus) -> Result<(), HostPlacementRefusal> {
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
    Ok(())
}

/// Read isolation only for a unit that requires it.
fn check_isolated(
    unit: &Unit,
    cores: &CpuSet,
    host: &HostCpus,
) -> Result<(), HostPlacementRefusal> {
    if !unit.require_isolated_cores {
        return Ok(());
    }
    let Some(isolated) = &host.isolated else {
        return Err(HostPlacementRefusal::NoIsolationList {
            unit: unit.workload.clone(),
        });
    };
    let exposed = cores.difference(isolated);
    if exposed.is_empty() {
        return Ok(());
    }
    Err(HostPlacementRefusal::CoresNotIsolated {
        unit: unit.workload.clone(),
        cores: exposed,
    })
}

fn check_other_tenants(
    unit: &Unit,
    cores: &CpuSet,
    others: &[&(TenantId, Topology)],
) -> Result<(), HostPlacementRefusal> {
    for (other_tenant, other) in others {
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
    Ok(())
}

/// Refuse cores a running machine may use, unless it runs this unit or the
/// other member of its standby pair.
fn check_live_machines(
    tenant: &TenantId,
    topology: &Topology,
    unit: &Unit,
    cores: &CpuSet,
    host: &HostCpus,
) -> Result<(), HostPlacementRefusal> {
    for machine in &host.live {
        if machine
            .owner
            .as_ref()
            .is_some_and(|owner| owns_pair(tenant, topology, unit, owner))
        {
            continue;
        }
        let Some(usable) = host.cores_of(machine) else {
            continue;
        };
        let shared = cores.intersection(usable);
        if !shared.is_empty() {
            return Err(HostPlacementRefusal::HeldByLiveMachine {
                unit: unit.workload.clone(),
                machine: machine.name.clone(),
                cores: shared,
            });
        }
    }
    Ok(())
}

fn owns_pair(tenant: &TenantId, topology: &Topology, unit: &Unit, owner: &PlacementOwner) -> bool {
    if owner.tenant != *tenant {
        return false;
    }
    owner.workload == unit.workload
        || topology.standby_pairs.iter().any(|pair| {
            (pair.active == unit.workload && pair.standby == owner.workload)
                || (pair.standby == unit.workload && pair.active == owner.workload)
        })
}

/// The online cores nothing holds exclusively.
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

/// Every core held exclusively on this host, by an admitted topology or a
/// running machine, for a report rather than a decision.
///
/// # Errors
///
/// As [`admitted_topologies`].
pub fn exclusive_cores_held_on_host() -> Result<CpuSet> {
    let home = mvm_core::config::mvm_home_strict()?;
    let live = HostCpus {
        scope_cpuset: false,
        online: None,
        isolated: None,
        live: live::live_machines(&home),
    };
    held_on_host(&home, &live, None)
}

/// Every core held exclusively on this host: by any admitted topology, and by
/// any running machine placed exclusively, even one whose topology has since
/// released it.
///
/// # Errors
///
/// As [`admitted_topologies`].
pub(crate) fn held_on_host(
    home: &Path,
    host: &HostCpus,
    host_signer_keys_dir: Option<&Path>,
) -> Result<CpuSet> {
    Ok(admitted_topologies(home, host_signer_keys_dir)?
        .iter()
        .fold(host.held_by_live_machines(), |held, (_, topology)| {
            held.union(&exclusive_cores(topology))
        }))
}

#[cfg(test)]
mod tests;
