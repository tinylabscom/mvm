use anyhow::Result;
use mvm_core::plan::ExecutionPlan;

use super::AuditEmitter;

impl AuditEmitter {
    /// Emit `session.parked` — a durable agent session released its sandbox.
    ///
    /// Bound to the plan the parked residency was admitted under, so the chain
    /// records which authorization the session was running with when it
    /// stopped. The caller supplies the labels; they name the session, the
    /// generation, the reason and the storage tier, and carry nothing the
    /// session was working on.
    pub fn emit_session_parked(
        &self,
        plan: &ExecutionPlan,
        labels: Vec<(String, String)>,
    ) -> Result<()> {
        self.emit(plan, "session.parked", labels)
    }

    /// Emit `session.resumed` — a parked durable agent session was
    /// re-admitted into a new residency.
    ///
    /// Bound to the freshly signed plan the resume admitted, which is the
    /// authority the new residency runs under. Nothing of the previous
    /// residency's authority carries over, and neither does its plan.
    pub fn emit_session_resumed(
        &self,
        plan: &ExecutionPlan,
        labels: Vec<(String, String)>,
    ) -> Result<()> {
        self.emit(plan, "session.resumed", labels)
    }
}
