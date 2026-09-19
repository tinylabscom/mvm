//! Chain-signed refusal records for the grant-gated drive plane.

use super::AuditEmitter;
use anyhow::Result;
use mvm_agentd::vsock::DriveRefusal;
use mvm_core::plan::ExecutionPlan;

/// Wire-stable event name for a drive refusal.
pub const REFUSED_EVENT: &str = "drive.refused";
/// Label naming the machine whose drive request was refused.
pub const LABEL_VM_NAME: &str = "vm_name";
/// Label carrying the payload-free refusal reason.
pub const LABEL_REASON: &str = "drive_refusal_reason";

impl AuditEmitter {
    /// Emit a payload-free, chain-signed drive refusal.
    pub fn emit_drive_refused(
        &self,
        plan: &ExecutionPlan,
        vm_name: &str,
        refusal: DriveRefusal,
    ) -> Result<()> {
        self.emit(
            plan,
            REFUSED_EVENT,
            [
                (LABEL_VM_NAME.to_string(), vm_name.to_string()),
                (LABEL_REASON.to_string(), refusal.reason().to_string()),
            ],
        )
    }
}
