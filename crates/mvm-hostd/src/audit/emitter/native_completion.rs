//! Observations emitted only from an original native owner's completion token.

use super::AuditEmitter;
use anyhow::{Context, Result};
use mvm_core::plan::ExecutionPlan;

impl AuditEmitter {
    /// Record only a completion produced by the original native custody owner.
    pub fn emit_native_completed(
        &self,
        plan: &ExecutionPlan,
        completion: &mvm_runtime::workload_runner::runner::NativeCompletion,
    ) -> Result<()> {
        anyhow::ensure!(
            completion.evidence().instance.vm_id == plan.workload.0
                && completion.evidence().rootfs_sha256 == plan.image.sha256,
            "original native completion differs from its admitted workload or image"
        );
        let evidence = serde_json::to_string(completion.evidence())
            .context("encoding native completion observations")?;
        self.emit(
            plan,
            "plan.native_completed",
            [
                ("native_completion".to_owned(), evidence),
                (
                    "bundle_sha256".to_owned(),
                    plan.bundle
                        .as_ref()
                        .map(|bundle| bundle.bundle_sha256.clone())
                        .unwrap_or_default(),
                ),
            ],
        )
    }
}
