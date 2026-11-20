//! The one host check every post-admission change to a running unit passes.
//!
//! A unit is sealed when the plan it was admitted under carries a topology
//! binding. After admission its configuration does not change: memory target,
//! idle timeout, attached volumes, grants and expiry are refused outright, and
//! sleep, wake, pause, resume and checkpoint are refused unless the unit's
//! entry in the admitted topology declares them. Every refusal is written to
//! the tenant's chain as `unit.mutation_refused`, once.
//!
//! Sealed-ness is read from the plan persisted beside the VM. A bound plan is
//! always persisted before its VM is dispatched ([`persist_sealed_plan`]), so
//! a VM without one was not admitted under a topology and is not sealed. A
//! plan file that exists but cannot be read, or a bound plan whose topology
//! cannot be read or no longer matches the one admitted, is refused: whether
//! the change is allowed cannot be decided, and the answer is no.
//!
//! Stopping is not a change. Stop, quarantine, force-stop, session kill and
//! reap, and the wall-clock and idle-timeout kills never call this module, so
//! a sealed unit is never harder to stop.
//!
//! This is a host-code gate. A process running as the same user can drive a
//! VMM's control socket or signal its process directly; that is inside the
//! trusted-host assumption and outside what this check claims.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_contract::plan::topology::{
    SealedTransitions, TopologyBindingRefusal, check_topology_binding,
};
use mvm_core::plan::{ExecutionPlan, TenantId};

use crate::audit::emitter::AuditEmitter;
use crate::audit::plan_persist;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
#[cfg(test)]
mod tests;

/// The audit event a refusal is recorded as.
pub const MUTATION_REFUSED_EVENT: &str = "unit.mutation_refused";

/// A post-admission change to a running unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutation {
    MemoryTarget,
    IdleTimeout,
    VolumeMount,
    VolumeUnmount,
    VolumeRefresh,
    GrantChange,
    Sleep,
    Wake,
    Pause,
    Resume,
    Checkpoint,
    Expiry,
}

impl Mutation {
    pub const ALL: [Self; 12] = [
        Self::MemoryTarget,
        Self::IdleTimeout,
        Self::VolumeMount,
        Self::VolumeUnmount,
        Self::VolumeRefresh,
        Self::GrantChange,
        Self::Sleep,
        Self::Wake,
        Self::Pause,
        Self::Resume,
        Self::Checkpoint,
        Self::Expiry,
    ];

    /// The label the audit entry and the refusal carry.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MemoryTarget => "memory_target",
            Self::IdleTimeout => "idle_timeout",
            Self::VolumeMount => "volume_mount",
            Self::VolumeUnmount => "volume_unmount",
            Self::VolumeRefresh => "volume_refresh",
            Self::GrantChange => "grant_change",
            Self::Sleep => "sleep",
            Self::Wake => "wake",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Checkpoint => "checkpoint",
            Self::Expiry => "expiry",
        }
    }

    /// Whether a sealed unit declaring `permits` may undergo this change.
    /// A resume undoes either a pause or a sleep, so a unit that declares
    /// either `pause` or `wake` may be resumed.
    #[must_use]
    pub const fn permitted_by(self, permits: &SealedTransitions) -> bool {
        match self {
            Self::Sleep => permits.sleep,
            Self::Wake => permits.wake,
            Self::Pause => permits.pause,
            Self::Resume => permits.wake || permits.pause,
            Self::Checkpoint => permits.checkpoint,
            Self::MemoryTarget
            | Self::IdleTimeout
            | Self::VolumeMount
            | Self::VolumeUnmount
            | Self::VolumeRefresh
            | Self::GrantChange
            | Self::Expiry => false,
        }
    }

    /// Whether the topology can declare this change at all.
    const fn declarable(self) -> bool {
        matches!(
            self,
            Self::Sleep | Self::Wake | Self::Pause | Self::Resume | Self::Checkpoint
        )
    }
}

impl std::fmt::Display for Mutation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Why a change to a running unit was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SealRefusal {
    #[error("unit {unit} of VM {vm:?} is sealed: {mutation} is not allowed after admission")]
    Sealed {
        vm: String,
        unit: String,
        mutation: Mutation,
    },
    #[error(
        "unit {unit} of VM {vm:?} is sealed and its topology entry does not declare {mutation}"
    )]
    NotDeclared {
        vm: String,
        unit: String,
        mutation: Mutation,
    },
    #[error("the plan persisted for VM {vm:?} cannot be read, so it may be sealed: {detail}")]
    PlanUnreadable { vm: String, detail: String },
    #[error("the topology VM {vm:?} was admitted under cannot be read: {detail}")]
    TopologyUnreadable { vm: String, detail: String },
    #[error("VM {vm:?} no longer matches the admitted topology: {refusal}")]
    TopologyMismatch {
        vm: String,
        refusal: TopologyBindingRefusal,
    },
}

/// Allow `mutation` of VM `vm_name`, or refuse it and record the refusal.
///
/// # Errors
///
/// A [`SealRefusal`] as the root cause. If its audit entry could not be
/// written the refusal still stands, and the error says so.
pub fn authorize(vm_name: &str, mutation: Mutation) -> Result<()> {
    let home = mvm_core::config::mvm_home_strict()
        .context("resolving the mvm home the VM's plan is kept under")?;
    match decide(&home, vm_name, mutation) {
        Ok(()) => Ok(()),
        Err((plan, refusal)) => Err(audited(plan.as_deref(), vm_name, mutation, refusal)),
    }
}

/// Persist `plan` beside VM `vm_name` when it is bound to a topology. A bound
/// plan that cannot be persisted fails the launch: without it the unit would
/// read as unsealed. An unbound plan is left to the launch's own best-effort
/// persistence.
///
/// # Errors
///
/// The write failed for a bound plan.
pub fn persist_sealed_plan(vm_name: &str, plan: &ExecutionPlan) -> Result<()> {
    if plan.topology.is_none() {
        return Ok(());
    }
    plan_persist::write_plan(vm_name, plan)
        .map(|_| ())
        .context("persisting the plan of a unit admitted under a topology")
}

type Refused = (Option<Box<ExecutionPlan>>, SealRefusal);

fn decide(home: &Path, vm: &str, mutation: Mutation) -> Result<(), Refused> {
    let Some(plan) = read_persisted_plan(home, vm)? else {
        return Ok(());
    };
    if plan.topology.is_none() {
        return Ok(());
    }
    let permits = match sealed_permits(home, vm, &plan) {
        Ok(permits) => permits,
        Err(refusal) => return Err((Some(Box::new(plan)), refusal)),
    };
    if mutation.permitted_by(&permits) {
        return Ok(());
    }
    let unit = plan.workload.0.clone();
    let vm = vm.to_owned();
    let refusal = if mutation.declarable() {
        SealRefusal::NotDeclared { vm, unit, mutation }
    } else {
        SealRefusal::Sealed { vm, unit, mutation }
    };
    Err((Some(Box::new(plan)), refusal))
}

/// The plan persisted beside `vm`, or `None` when there is none.
fn read_persisted_plan(home: &Path, vm: &str) -> Result<Option<ExecutionPlan>, Refused> {
    let path = mvm_core::config::vm_state_dir_at(home, vm).join(plan_persist::PLAN_FILENAME);
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        _ => {}
    }
    plan_persist::read_plan_at(&path).map(Some).map_err(|e| {
        let refusal = SealRefusal::PlanUnreadable {
            vm: vm.to_owned(),
            detail: format!("{e:#}"),
        };
        (None, refusal)
    })
}

/// What the unit `plan` is bound to may still do, read from the topology
/// admitted for its tenant.
fn sealed_permits(
    home: &Path,
    vm: &str,
    plan: &ExecutionPlan,
) -> Result<SealedTransitions, SealRefusal> {
    let admitted = crate::topology_admission::last_admitted_topology(home, &plan.tenant, None)
        .map_err(|e| SealRefusal::TopologyUnreadable {
            vm: vm.to_owned(),
            detail: format!("{e:#}"),
        })?;
    match check_topology_binding(plan, admitted.as_ref()) {
        Ok(Some(unit)) => Ok(unit.permits),
        // Unreachable for a bound plan; it permits nothing.
        Ok(None) => Ok(SealedTransitions::default()),
        Err(refusal) => Err(SealRefusal::TopologyMismatch {
            vm: vm.to_owned(),
            refusal,
        }),
    }
}

fn audited(
    plan: Option<&ExecutionPlan>,
    vm: &str,
    mutation: Mutation,
    refusal: SealRefusal,
) -> anyhow::Error {
    let reason = refusal.to_string();
    match emit(plan, vm, mutation, &reason) {
        Ok(()) => anyhow::Error::new(refusal),
        Err(e) => anyhow::Error::new(refusal).context(format!(
            "the refusal could not be written to the audit chain: {e:#}"
        )),
    }
}

fn emit(plan: Option<&ExecutionPlan>, vm: &str, mutation: Mutation, reason: &str) -> Result<()> {
    let signer = crate::audit::host_keypair::load_or_init()?;
    let emitter = AuditEmitter::new(signer.signing)?;
    // A plan that cannot be read names no tenant; the refusal goes on the
    // local default chain.
    let tenant = plan.map_or_else(
        || TenantId(mvm_core::plan::DEFAULT_TENANT.to_owned()),
        |plan| plan.tenant.clone(),
    );
    emitter.emit_sealed_mutation_refused(
        plan,
        &tenant,
        [
            ("vm".to_owned(), vm.to_owned()),
            ("mutation".to_owned(), mutation.label().to_owned()),
            ("reason".to_owned(), reason.to_owned()),
        ],
    )
}
