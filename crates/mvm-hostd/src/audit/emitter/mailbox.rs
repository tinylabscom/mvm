use super::AuditEmitter;
use anyhow::Result;
use mvm_core::plan::ExecutionPlan;

impl AuditEmitter {
    /// Emit `mailbox.read` — the host took one message off `vm_name`'s guest
    /// mailbox queue. Payload-free: the VM name, the message's byte length, and
    /// the queue's lifetime accepted and read counts. The counts are what the
    /// mailbox process reports; deliveries it accepted are audited here, at
    /// read time, and not one by one as they arrive.
    pub fn emit_mailbox_read(
        &self,
        plan: &ExecutionPlan,
        vm_name: &str,
        bytes: usize,
        accepted: u64,
        read: u64,
    ) -> Result<()> {
        self.emit(
            plan,
            "mailbox.read",
            [
                ("vm_name".to_string(), vm_name.to_string()),
                ("bytes".to_string(), bytes.to_string()),
                ("accepted_total".to_string(), accepted.to_string()),
                ("read_total".to_string(), read.to_string()),
            ],
        )
    }
}
