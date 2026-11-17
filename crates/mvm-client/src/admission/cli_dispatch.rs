//! One-shot CLI admission handoff into the host's common cold dispatch tail.

use super::{AdmissionContext, AuditContinuation, CliAdmission, PendingCliAdmission};

/// The failure class a hostd CLI cold dispatch already reached, for the
/// command layer's custody and audit decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliStartFailureKind {
    /// The dispatch boundary already wrote this refusal's chain failure.
    Recorded,
    /// The refusal is unrecorded; the CLI audit owner owes a `plan.failed` entry.
    Unrecorded,
    /// Rollback was not confirmed; a VM may still be live.
    UncertainStop,
}

/// Classify a hostd CLI cold-start failure without naming the hostd type at
/// the command layer.
#[must_use]
pub fn cli_start_failure_kind(error: &anyhow::Error) -> Option<CliStartFailureKind> {
    match error.downcast_ref::<mvm_hostd::plan_admission::CliStartFailure>() {
        Some(mvm_hostd::plan_admission::CliStartFailure::Recorded(_)) => {
            Some(CliStartFailureKind::Recorded)
        }
        Some(mvm_hostd::plan_admission::CliStartFailure::Unrecorded(_)) => {
            Some(CliStartFailureKind::Unrecorded)
        }
        Some(mvm_hostd::plan_admission::CliStartFailure::UncertainStop(_)) => {
            Some(CliStartFailureKind::UncertainStop)
        }
        None => None,
    }
}

impl CliAdmission {
    /// Retain the actual admission and audit owner, never a decoded plan JSON.
    #[must_use]
    pub fn new(context: AdmissionContext) -> Self {
        Self::new_with_rootfs(context, None, None)
    }

    /// Bind the admitted CLI source to the exact resolved rootfs path.
    #[must_use]
    pub fn new_for_rootfs(context: AdmissionContext, rootfs: &std::path::Path) -> Self {
        Self::new_with_rootfs(context, Some(rootfs.to_path_buf()), None)
    }

    /// Retain the exact launch-owned set used during this plan's admission.
    #[must_use]
    pub fn new_for_rootfs_with_runtime(
        context: AdmissionContext,
        rootfs: &std::path::Path,
        verified_runtime: Option<std::sync::Arc<mvm_runtime::runtime_evidence::VerifiedRuntimeSet>>,
    ) -> Self {
        Self::new_with_rootfs(context, Some(rootfs.to_path_buf()), verified_runtime)
    }

    fn new_with_rootfs(
        context: AdmissionContext,
        source_rootfs: Option<std::path::PathBuf>,
        verified_runtime: Option<std::sync::Arc<mvm_runtime::runtime_evidence::VerifiedRuntimeSet>>,
    ) -> Self {
        let audit = AuditContinuation {
            plan: context.admitted.plan().clone(),
            emitter: context.emitter,
        };
        Self::Pending(Box::new(PendingCliAdmission {
            authority: context.admitted,
            policy_bundle: context.policy_bundle,
            audit,
            source_rootfs,
            verified_runtime,
        }))
    }

    /// The signed plan that owns this run's single admission.
    #[must_use]
    pub fn plan(&self) -> &mvm_core::plan::ExecutionPlan {
        match self {
            Self::Pending(pending) => pending.authority.plan(),
            Self::Dispatched(audit) => audit.plan(),
        }
    }

    /// The original read-only audit owner, retained across a failed dispatch.
    #[must_use]
    pub fn audit_continuation(&self) -> &AuditContinuation {
        match self {
            Self::Pending(pending) => &pending.audit,
            Self::Dispatched(audit) => audit,
        }
    }

    /// Compare the legacy VM name, signed-plan JSON and policy-bundle JSON.
    ///
    /// Kernel, volume and network enforcement remain in their existing
    /// admission and runner gates. The rootfs path is compared here; the
    /// authenticated bytes remain the runner's responsibility.
    ///
    /// # Errors
    /// Refuses a changed name, rootfs path, signed-plan or policy-bundle JSON.
    /// The JSON is compared with the typed owner, never used as authority.
    pub fn check_legacy_projection(
        &self,
        config: &mvm_core::vm_backend::VmStartConfig,
    ) -> anyhow::Result<()> {
        let Self::Pending(pending) = self else {
            anyhow::bail!("CLI admission was already dispatched");
        };
        anyhow::ensure!(
            config.name == pending.authority.plan().image.name,
            "launch identity differs from admitted plan"
        );
        if let Some(rootfs) = &pending.source_rootfs {
            anyhow::ensure!(
                std::path::Path::new(&config.rootfs_path) == rootfs,
                "launch rootfs differs from admitted source"
            );
        }
        let expected = serde_json::to_string(pending.authority.signed())?;
        anyhow::ensure!(
            config.plan_json.as_deref() == Some(expected.as_str()),
            "legacy launch plan projection differs from admitted authority"
        );
        let policy = pending
            .policy_bundle
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        anyhow::ensure!(
            config.bundle_json == policy,
            "legacy launch policy projection differs from admitted authority"
        );
        Ok(())
    }

    /// Spend the actual admission through the common host dispatch tail.
    ///
    /// Returns the original audit owner even on failure, for output refusal
    /// and uncertain-stop custody. No signed-plan JSON is admitted again.
    pub fn start_cold(
        self,
        backend: &mvm_runtime::AnyBackend,
        config: mvm_core::vm_backend::VmStartConfig,
        writable_images: mvm_vmm::driver::prepared_disks::WritableVolumeImages,
    ) -> (Self, anyhow::Result<()>) {
        if !matches!(&self, Self::Pending(pending) if pending.source_rootfs.is_some()) {
            return (
                self,
                Err(anyhow::anyhow!(
                    "CLI cold launch has no pending source binding"
                )),
            );
        }
        if let Self::Pending(pending) = &self
            && pending.authority.plan().runtime_identity.is_some()
                != pending.verified_runtime.is_some()
        {
            return (
                self,
                Err(anyhow::anyhow!(
                    "CLI release admission and its launch-owned verification set differ"
                )),
            );
        }
        if let Err(error) = self.check_legacy_projection(&config) {
            return (self, Err(error));
        }
        let Self::Pending(pending) = self else {
            return (
                self,
                Err(anyhow::anyhow!("CLI admission was already dispatched")),
            );
        };
        let PendingCliAdmission {
            authority,
            policy_bundle,
            audit,
            source_rootfs: _,
            verified_runtime,
        } = *pending;
        let result = mvm_hostd::plan_admission::start_cli_transient(
            mvm_hostd::plan_admission::StartAdmittedParams {
                backend,
                admitted: authority,
                config,
                policy_bundle: policy_bundle.as_ref(),
                emitter: Some(&audit.emitter),
                assurance: None,
            },
            verified_runtime.as_deref(),
            writable_images,
        )
        .map(|_| ());
        (Self::Dispatched(Box::new(audit)), result)
    }

    /// Retire the one-use authority after the unmigrated warm or cold path.
    #[must_use]
    pub fn finish_legacy(self) -> AuditContinuation {
        match self {
            Self::Pending(pending) => pending.audit,
            Self::Dispatched(audit) => *audit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_start_failure_kind_preserves_host_outcomes() {
        let cases = [
            (
                mvm_hostd::plan_admission::CliStartFailure::Recorded(anyhow::anyhow!("pack")),
                CliStartFailureKind::Recorded,
            ),
            (
                mvm_hostd::plan_admission::CliStartFailure::Unrecorded(anyhow::anyhow!("start")),
                CliStartFailureKind::Unrecorded,
            ),
            (
                mvm_hostd::plan_admission::CliStartFailure::UncertainStop(anyhow::anyhow!("stop")),
                CliStartFailureKind::UncertainStop,
            ),
        ];
        for (failure, expected) in cases {
            let error = anyhow::Error::new(failure);
            assert_eq!(cli_start_failure_kind(&error), Some(expected));
        }
        assert_eq!(cli_start_failure_kind(&anyhow::anyhow!("unrelated")), None);
    }
}
