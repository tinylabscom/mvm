//! Seal a VM for a test: admit a one-unit topology for a plan's tenant and
//! persist the plan, bound to it, beside the VM. The caller owns an isolated
//! `MVM_HOME`; everything here resolves under it.

use anyhow::Result;
use chrono::{Duration, Utc};
use mvm_contract::assurance::Sha256Digest;
use mvm_contract::plan::topology::{
    CorePlacement, CryptoSuite, SealedTransitions, TOPOLOGY_SCHEMA_VERSION, Topology,
    TopologyBinding, Unit, UnitResources, UnitRole, plan_recipe,
};
use mvm_core::plan::ExecutionPlan;

use crate::audit::emitter::AuditEmitter;
use crate::topology_admission::{TopologyAdmissionRequest, admit_topology, sign_topology_as_host};

/// A topology whose one unit is exactly `plan`, permitting `permits`.
#[must_use]
pub fn topology_for(plan: &ExecutionPlan, generation: u64, permits: SealedTransitions) -> Topology {
    let now = Utc::now();
    let recipe = plan_recipe(plan);
    let recipe = format!(
        "sha256:{}",
        recipe.strip_prefix("sha256:").unwrap_or(recipe)
    );
    Topology {
        schema_version: TOPOLOGY_SCHEMA_VERSION,
        tenant: plan.tenant.clone(),
        generation,
        valid_from: now - Duration::days(1),
        valid_until: now + Duration::days(30),
        suite: CryptoSuite::CLASSICAL,
        units: vec![Unit {
            workload: plan.workload.clone(),
            role: UnitRole::Worker,
            recipe: Sha256Digest::parse(recipe).expect("the plan's recipe is a sha256 digest"),
            resources: UnitResources {
                cpus: plan.resources.cpus,
                mem_mib: plan.resources.mem_mib,
                disk_mib: plan.resources.disk_mib,
            },
            placement: CorePlacement::Floating,
            min_isolation: None,
            permits,
            liveness_period_ms: None,
            require_isolated_cores: false,
        }],
        standby_pairs: Vec::new(),
        cells: Vec::new(),
        edges: Vec::new(),
        succession: Vec::new(),
    }
}

/// Admit `topology` on this host under the host signer.
///
/// # Errors
///
/// The topology was refused or could not be signed.
pub fn admit(topology: &Topology) -> Result<()> {
    let signed = sign_topology_as_host(topology, None)?;
    let emitter = AuditEmitter::new(crate::audit::host_keypair::load_or_init()?.signing)?;
    admit_topology(&TopologyAdmissionRequest {
        tenant: &topology.tenant,
        signed: &signed,
        backend: mvm_core::vm_backend::BackendKind::Firecracker,
        measured_failover: None,
        // The topology places nothing, so no host fact is read.
        host_cpus: &crate::topology_admission::HostCpus {
            scope_cpuset: false,
            online: None,
            isolated: None,
            live: Vec::new(),
        },
        clock: &mvm_core::time::SystemClock,
        host_signer_keys_dir: None,
        emitter: &emitter,
    })?;
    Ok(())
}

/// Admit a topology for `plan` and persist `plan`, bound to its one unit,
/// beside VM `vm`. Returns the bound plan.
///
/// # Errors
///
/// The topology was refused, or the plan could not be persisted.
pub fn seal(vm: &str, plan: ExecutionPlan, permits: SealedTransitions) -> Result<ExecutionPlan> {
    let mut sealed = seal_all(&[(vm, plan, permits)])?;
    Ok(sealed.remove(0))
}

/// [`seal`] for several VMs of one tenant at once: a host holds one topology
/// per tenant, so every unit has to be in it.
///
/// # Errors
///
/// The topology was refused, or a plan could not be persisted.
pub fn seal_all(units: &[(&str, ExecutionPlan, SealedTransitions)]) -> Result<Vec<ExecutionPlan>> {
    let Some((_, first, _)) = units.first() else {
        return Ok(Vec::new());
    };
    let mut topology = topology_for(first, 1, SealedTransitions::default());
    topology.units = units
        .iter()
        .flat_map(|(_, plan, permits)| topology_for(plan, 1, *permits).units)
        .collect();
    admit(&topology)?;
    units
        .iter()
        .map(|(vm, plan, _)| {
            let plan = bind(plan.clone(), &topology);
            crate::audit::plan_persist::write_plan(vm, &plan)?;
            Ok(plan)
        })
        .collect()
}

/// `plan` bound to `topology`'s unit for `plan`'s workload.
#[must_use]
pub fn bind(mut plan: ExecutionPlan, topology: &Topology) -> ExecutionPlan {
    plan.topology = Some(TopologyBinding {
        topology: topology.digest(),
        unit: plan.workload.clone(),
    });
    plan
}
