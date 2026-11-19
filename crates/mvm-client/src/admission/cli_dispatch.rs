//! One-shot CLI admission handoff into the host's common cold dispatch tail.

use super::{AdmissionContext, AuditContinuation, CliAdmission, PendingCliAdmission};

/// Run source-specific attach and lowering inside hostd's ordered CLI preparation.
///
/// # Errors
/// Propagates attachment, selected-runtime verification, durable admission and
/// source-lowering refusals. Preparation never starts a backend.
pub fn prepare_cli_cold(
    backend: &mvm_runtime::AnyBackend,
    config: mvm_core::vm_backend::VmStartConfig,
    attach: impl FnOnce(
        &mut mvm_core::vm_backend::VmStartConfig,
    ) -> anyhow::Result<
        Option<std::sync::Arc<mvm_build::guest_runtime::evidence::VerifiedReleaseRuntime>>,
    >,
    admit: impl FnOnce(
        &mut mvm_core::vm_backend::VmStartConfig,
        Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
    ) -> anyhow::Result<super::CliColdAdmissionInput>,
) -> anyhow::Result<super::PreparedCliCold> {
    let prepared = mvm_hostd::plan_admission::prepare_cli_cold(
        mvm_hostd::plan_admission::PrepareCliColdParams { backend, config },
        attach,
        |config, verified_runtime| {
            let super::CliColdAdmissionInput {
                admission,
                built_runtime,
            } = admit(config, verified_runtime)?;
            let CliAdmission::Pending(pending) = admission else {
                anyhow::bail!("CLI cold preparation lost its pending admission");
            };
            let PendingCliAdmission {
                authority,
                policy_bundle,
                audit,
                source_rootfs: _,
                verified_runtime: _,
            } = *pending;
            let host_budget = authority.host_budget_permit();
            let mailbox_posture = authority.mailbox_posture();
            Ok(mvm_hostd::plan_admission::LaunchAdmission {
                admitted: authority,
                emitter: audit.emitter,
                policy_bundle,
                continuation: super::CliColdContinuation {
                    host_budget,
                    mailbox_posture,
                    _built_runtime: built_runtime,
                },
            })
        },
    )?;
    let continuation = prepared.continuation();
    let config = prepared.config().clone();
    let host_budget = std::sync::Arc::clone(&continuation.host_budget);
    let mailbox_posture = continuation.mailbox_posture.clone();
    Ok(super::PreparedCliCold {
        admission: CliAdmission::PreparedCold(Box::new(prepared)),
        config,
        host_budget,
        mailbox_posture,
    })
}

/// A materialized filesystem child bound to its own fresh, one-use admission.
/// This is not a transient run: its launch audit is written after backend
/// start, while the fork does not add an immediate host budget charge.
pub struct FsQuickBootAdmission(CliAdmission);

impl FsQuickBootAdmission {
    /// Bind the materialized child and refuse a plan that violates fork secret policy.
    ///
    /// The expected rootfs is derived from the fork artifact, not caller input.
    /// # Errors
    /// Refuses a child plan that widens or drops secrets against the fork policy.
    pub fn new(
        context: AdmissionContext,
        child: &crate::checkpoint::fs_quick::MaterializedFsQuickFork,
        verified_runtime: Option<std::sync::Arc<mvm_runtime::runtime_evidence::VerifiedRuntimeSet>>,
    ) -> anyhow::Result<Self> {
        if let Err(error) = child.validate_admitted_plan(&context.admitted) {
            let error = anyhow::Error::new(error);
            super::emit_failed(&context, "fork-secret-policy", &error);
            return Err(error);
        }
        let rootfs = child.destination().join("rootfs.ext4");
        Ok(Self(CliAdmission::new_for_rootfs_with_runtime(
            context,
            &rootfs,
            verified_runtime,
        )))
    }

    /// Spend the admitted child through hostd, retaining the CLI's fork audit semantics.
    pub fn start(
        self,
        backend: &mvm_runtime::AnyBackend,
        config: mvm_core::vm_backend::VmStartConfig,
    ) -> anyhow::Result<()> {
        let owner = self.0;
        if let Err(error) = owner.check_legacy_projection(&config) {
            owner
                .audit_continuation()
                .expect("filesystem fork retains its audit continuation")
                .emit_failed("backend-start", &error);
            return Err(error);
        }
        let CliAdmission::Pending(pending) = owner else {
            anyhow::bail!("filesystem fork admission already dispatched");
        };
        let PendingCliAdmission {
            authority,
            policy_bundle,
            audit,
            source_rootfs: _,
            verified_runtime,
        } = *pending;
        let result = if authority.plan().runtime_identity.is_some() != verified_runtime.is_some() {
            Err(anyhow::anyhow!(
                "filesystem fork release admission and verification set differ"
            ))
        } else {
            mvm_hostd::plan_admission::start_fs_quick_fork(
                mvm_hostd::plan_admission::StartAdmittedParams {
                    backend,
                    admitted: authority,
                    config,
                    policy_bundle: policy_bundle.as_ref(),
                    emitter: Some(&audit.emitter),
                    assurance: None,
                },
                verified_runtime.as_deref(),
            )
            .map(|_| ())
        };
        match &result {
            Ok(()) => audit.emit_fork_launched(backend.name()),
            Err(error)
                if matches!(
                    cli_start_failure_kind(error),
                    Some(CliStartFailureKind::UncertainStop)
                ) => {}
            Err(error) => audit.emit_failed("backend-start", error),
        }
        result
    }
}

/// The failure class a hostd CLI cold dispatch already reached, for the
/// command layer's custody and audit decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliStartFailureKind {
    /// The dispatch boundary already wrote this refusal's chain failure.
    Recorded,
    /// The refusal is unrecorded; the CLI audit owner owes a `plan.failed` entry.
    Unrecorded,
    /// A caller supplied a lifecycle guard for another machine or non-cold state.
    StateNotOwned,
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
        Some(mvm_hostd::plan_admission::CliStartFailure::StateNotOwned(_)) => {
            Some(CliStartFailureKind::StateNotOwned)
        }
        Some(mvm_hostd::plan_admission::CliStartFailure::UncertainStop(_)) => {
            Some(CliStartFailureKind::UncertainStop)
        }
        None => None,
    }
}

fn finish_prepared(
    dispatched: mvm_hostd::plan_admission::DispatchedCliCold<super::CliColdContinuation>,
) -> AuditContinuation {
    let (plan, emitter, _continuation) = dispatched.into_parts();
    AuditContinuation { plan, emitter }
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
            Self::PreparedCold(prepared) => prepared.plan(),
            Self::Pending(pending) => pending.authority.plan(),
            Self::Dispatched(audit) => audit.plan(),
        }
    }

    /// The original read-only audit owner, retained across a failed dispatch.
    #[must_use]
    pub fn audit_continuation(&self) -> Option<&AuditContinuation> {
        match self {
            Self::PreparedCold(_) => None,
            Self::Pending(pending) => Some(&pending.audit),
            Self::Dispatched(audit) => Some(audit),
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
        if let Self::PreparedCold(prepared) = self {
            return prepared.verify_projection(config);
        }
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
        if let Self::PreparedCold(prepared) = self {
            if let Err(error) = prepared.verify_projection(&config) {
                return (Self::PreparedCold(prepared), Err(error));
            }
            let (dispatched, result) = mvm_hostd::plan_admission::start_prepared_cli_cold(
                *prepared,
                backend,
                writable_images,
            );
            return (
                Self::Dispatched(Box::new(finish_prepared(dispatched))),
                result.map(|_| ()),
            );
        }
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

    /// Spend the CLI's one-use admission on a selected, verified warm parent.
    ///
    /// The pool miss is resolved before calling this method, so the caller
    /// retains the pending owner for the existing admitted cold path.
    pub fn claim_warm(
        self,
        backend: &mvm_runtime::AnyBackend,
        config: mvm_core::vm_backend::VmStartConfig,
        ctx: &mvm_runtime::workload_runner::ClaimContext<'_>,
        handle: &mvm_core::vm_backend::StandbyHandle,
    ) -> (Self, anyhow::Result<crate::standby::OwnedWarmClaim>) {
        if let Self::PreparedCold(prepared) = self {
            if let Err(error) = prepared.verify_projection(&config) {
                return (Self::PreparedCold(prepared), Err(error));
            }
            return match mvm_hostd::plan_admission::claim_prepared_cli_cold(
                *prepared, backend, ctx, handle,
            ) {
                mvm_hostd::plan_admission::PreparedCliWarmClaim::Claimed { claim, dispatched } => (
                    Self::Dispatched(Box::new(finish_prepared(dispatched))),
                    Ok(claim),
                ),
                mvm_hostd::plan_admission::PreparedCliWarmClaim::ReservationLost(prepared) => (
                    Self::PreparedCold(prepared),
                    Err(mvm_core::vm_backend::StandbyError::ReservationLost.into()),
                ),
                mvm_hostd::plan_admission::PreparedCliWarmClaim::Refused { error, dispatched } => (
                    Self::Dispatched(Box::new(finish_prepared(dispatched))),
                    Err(error),
                ),
            };
        }
        if !matches!(&self, Self::Pending(pending) if pending.source_rootfs.is_some()) {
            return (
                self,
                Err(anyhow::anyhow!(
                    "CLI warm claim has no pending source binding"
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
            source_rootfs,
            verified_runtime,
        } = *pending;
        let result = mvm_hostd::plan_admission::claim_cli_transient(
            backend,
            authority,
            config,
            policy_bundle.as_ref(),
            verified_runtime.as_deref(),
            ctx,
            handle,
        );
        match result {
            Ok(mvm_hostd::plan_admission::WarmClaimDispatch::Claimed(owned)) => {
                (Self::Dispatched(Box::new(audit)), Ok(owned))
            }
            Ok(mvm_hostd::plan_admission::WarmClaimDispatch::ReservationLost(authority)) => (
                Self::Pending(Box::new(PendingCliAdmission {
                    authority: *authority,
                    policy_bundle,
                    audit,
                    source_rootfs,
                    verified_runtime,
                })),
                Err(mvm_core::vm_backend::StandbyError::ReservationLost.into()),
            ),
            Err(error) => (Self::Dispatched(Box::new(audit)), Err(error)),
        }
    }

    /// Return the original audit continuation after a warm or cold dispatch.
    #[must_use]
    pub fn finish_legacy(self) -> AuditContinuation {
        match self {
            Self::PreparedCold(prepared) => finish_prepared(
                mvm_hostd::plan_admission::abandon_prepared_cli_cold(*prepared),
            ),
            Self::Pending(pending) => pending.audit,
            Self::Dispatched(audit) => *audit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(unix, feature = "test-support"))]
    #[test]
    fn filesystem_fork_facade_spends_admission_once_and_audits_mock_launch() {
        let _home = super::super::admit_plan_tests::isolated_home();
        let keys = tempfile::tempdir().expect("keys");
        let audit = tempfile::tempdir().expect("audit");
        let rootfs_dir = tempfile::tempdir().expect("mock rootfs");
        let rootfs = rootfs_dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"mock rootfs").expect("mock rootfs bytes");
        let ledger = super::super::InMemoryNonceLedger::new();
        let context = super::super::admit_plan_for_boot(super::super::AdmitPlanForBootParams {
            vm_name: "fs-quick-facade-mock",
            backend_name: "mock",
            keys_dir: Some(keys.path()),
            audit_dir: Some(audit.path()),
            ..super::super::admit_plan_tests::pinning_params(&rootfs, &ledger)
        })
        .expect("fresh child admission");
        let signed = serde_json::to_string(context.admitted.signed()).expect("signed plan");
        let config = mvm_core::vm_backend::VmStartConfig {
            name: "fs-quick-facade-mock".into(),
            rootfs_path: rootfs.display().to_string(),
            plan_json: Some(signed),
            cpus: 2,
            memory_mib: 512,
            ..Default::default()
        };
        let source = FsQuickBootAdmission(CliAdmission::new_for_rootfs(
            context,
            std::path::Path::new(&config.rootfs_path),
        ));
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        source
            .start(&backend, config)
            .expect("mock fork consumes its admission");
        let chain =
            std::fs::read_to_string(audit.path().join("local.jsonl")).expect("fork audit chain");
        assert_eq!(chain.matches("plan.admitted").count(), 1, "{chain}");
        assert_eq!(chain.matches("plan.launched").count(), 1, "{chain}");
        assert_eq!(chain.matches("plan.failed").count(), 0, "{chain}");
    }

    #[cfg(all(unix, feature = "test-support"))]
    #[test]
    fn filesystem_fork_facade_refuses_substituted_child_rootfs() {
        let _home = super::super::admit_plan_tests::isolated_home();
        let keys = tempfile::tempdir().expect("keys");
        let audit = tempfile::tempdir().expect("audit");
        let context = super::super::admit_plan_tests::admitted_into(
            keys.path(),
            audit.path(),
            "fs-quick-drift-mock",
        );
        let signed = serde_json::to_string(context.admitted.signed()).expect("signed plan");
        let source = FsQuickBootAdmission(CliAdmission::new_for_rootfs(
            context,
            std::path::Path::new("/admitted/rootfs"),
        ));
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let config = mvm_core::vm_backend::VmStartConfig {
            name: "fs-quick-drift-mock".into(),
            rootfs_path: "/substituted/rootfs".into(),
            plan_json: Some(signed),
            ..Default::default()
        };
        let error = source
            .start(&backend, config)
            .expect_err("rootfs substitution refuses before backend start");
        assert!(error.to_string().contains("rootfs differs"), "{error:#}");
        let chain =
            std::fs::read_to_string(audit.path().join("local.jsonl")).expect("fork audit chain");
        assert_eq!(chain.matches("plan.admitted").count(), 1, "{chain}");
        assert_eq!(chain.matches("plan.failed").count(), 1, "{chain}");
        assert_eq!(chain.matches("plan.launched").count(), 0, "{chain}");
    }

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
                mvm_hostd::plan_admission::CliStartFailure::StateNotOwned(anyhow::anyhow!("lock")),
                CliStartFailureKind::StateNotOwned,
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
