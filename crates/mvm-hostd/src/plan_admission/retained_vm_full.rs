//! Retained-source admission and one-use dispatch for a full-VM checkpoint child.
//!
//! A restore resumes a retained runtime, not a fresh kernel boot. The
//! checkpoint layer owns lineage/content verification and the backend's
//! paused-load/no-NIC/resume sequence; this boundary binds that operation to
//! the child's *new* signed admission before it can execute.

use anyhow::{Context, Result, ensure};
use mvm_core::checkpoint::{CheckpointDigest, CheckpointId, CheckpointMeta, VmFullOrigin};
use mvm_runtime::checkpoint::{
    CheckpointChainAnchor, CheckpointStore, ForkParams, ForkRestorer, VerifiedRetainedRuntime,
};

use super::AdmittedPlan;

/// An authenticated full-VM checkpoint source before child admission.
///
/// This capability owns the retained-runtime proof for the exact metadata
/// object authenticated against the lineage anchor. It is deliberately
/// non-serializable and has no constructor outside this module.
pub struct VerifiedVmFullForkSource {
    checkpoint: CheckpointId,
    parent_digest: CheckpointDigest,
    parent: CheckpointMeta,
    restored_rootfs_sha256: String,
    runtime: VerifiedRetainedRuntime,
}

impl VerifiedVmFullForkSource {
    /// Digest of the root filesystem the child admission must name.
    #[must_use]
    pub fn restored_rootfs_sha256(&self) -> &str {
        &self.restored_rootfs_sha256
    }

    /// Verified retained runtime to bind into the child's signed admission.
    #[must_use]
    pub fn runtime(&self) -> &VerifiedRetainedRuntime {
        &self.runtime
    }

    /// Authenticated parent metadata used for source projections.
    #[must_use]
    pub fn parent(&self) -> &CheckpointMeta {
        &self.parent
    }

    /// Authenticated backend origin carried by this checkpoint.
    #[must_use]
    pub fn origin(&self) -> Option<VmFullOrigin> {
        mvm_core::checkpoint::vm_full_origin(&self.parent)
    }

    /// Bind a fresh child admission to this exact retained source.
    ///
    /// Caller-supplied plan JSON and tenant projections are discarded later at
    /// dispatch. The opaque admitted owner is the sole authority.
    pub fn bind_child(self, admitted: AdmittedPlan, params: ForkParams) -> RetainedVmFullFork {
        RetainedVmFullFork {
            source: self,
            admitted,
            params,
        }
    }
}

/// Verify lineage, metadata, content identity, and retained runtime as one source.
pub fn verify_vm_full_fork_source(
    store: &CheckpointStore,
    checkpoint: &CheckpointId,
    expected_parent: &CheckpointMeta,
    anchor: &dyn CheckpointChainAnchor,
) -> Result<VerifiedVmFullForkSource> {
    mvm_runtime::checkpoint::verify_lineage(store, checkpoint, anchor)
        .context("authenticating the fork parent lineage")?;
    let parent = store.read_meta(checkpoint)?;
    ensure!(
        parent == *expected_parent && parent.compute_meta_digest() == parent.meta_digest,
        "fork runtime metadata differs from the authenticated checkpoint"
    );
    let runtime = mvm_runtime::checkpoint::verify_checkpoint_runtime(store, &parent)?;
    let restored_rootfs_sha256 = mvm_runtime::checkpoint::materialized_blob_sha256(
        store,
        &parent,
        mvm_core::checkpoint::ROOTFS_BLOB,
    )?;
    Ok(VerifiedVmFullForkSource {
        checkpoint: checkpoint.clone(),
        parent_digest: parent.meta_digest.clone(),
        parent,
        restored_rootfs_sha256,
        runtime,
    })
}

/// Typed backend alternatives for a retained full-VM fork.
enum VmFullForkRestorer<'a> {
    /// Firecracker snapshot load with Firecracker runtime/device evidence.
    Firecracker(&'a mvm_runtime::firecracker::FcForkRestorer),
    /// Native HVF restore with private RAM/frame ownership.
    Hvf(&'a mvm_runtime::hvf_restore::HvfForkRestorer),
    /// Injected HVF restorer for cross-crate containment tests only.
    #[cfg(feature = "test-support")]
    TestHvf(&'a dyn ForkRestorer),
}

impl VmFullForkRestorer<'_> {
    fn matches(&self, origin: Option<VmFullOrigin>) -> bool {
        match (self, origin) {
            (Self::Firecracker(_), Some(VmFullOrigin::Firecracker))
            | (Self::Hvf(_), Some(VmFullOrigin::Hvf)) => true,
            #[cfg(feature = "test-support")]
            (Self::TestHvf(_), Some(VmFullOrigin::Hvf)) => true,
            _ => false,
        }
    }
}

impl ForkRestorer for VmFullForkRestorer<'_> {
    fn verifies_on_load(&self) -> &'static [&'static str] {
        match self {
            Self::Firecracker(restorer) => restorer.verifies_on_load(),
            Self::Hvf(restorer) => restorer.verifies_on_load(),
            #[cfg(feature = "test-support")]
            Self::TestHvf(restorer) => restorer.verifies_on_load(),
        }
    }

    fn restore(&self, child: &mvm_runtime::checkpoint::RestoredChild<'_>) -> Result<()> {
        match self {
            Self::Firecracker(restorer) => restorer.restore(child),
            Self::Hvf(restorer) => restorer.restore(child),
            #[cfg(feature = "test-support")]
            Self::TestHvf(restorer) => restorer.restore(child),
        }
    }
}

/// One-use retained source bound to a fresh child admission.
pub struct RetainedVmFullFork {
    source: VerifiedVmFullForkSource,
    admitted: AdmittedPlan,
    params: ForkParams,
}

/// Result plus the spent admission retained for source-compatible auditing.
pub struct VmFullForkDispatch {
    pub result: Result<CheckpointMeta>,
    pub admitted: AdmittedPlan,
}

impl RetainedVmFullFork {
    /// Spend admission on the authenticated Firecracker restore implementation.
    pub fn dispatch_firecracker(
        self,
        store: &CheckpointStore,
        restorer: &mvm_runtime::firecracker::FcForkRestorer,
        anchor: &dyn CheckpointChainAnchor,
        stop_child: &dyn Fn(&str) -> Result<()>,
    ) -> VmFullForkDispatch {
        self.dispatch(
            store,
            VmFullForkRestorer::Firecracker(restorer),
            anchor,
            stop_child,
        )
    }

    /// Spend admission on the authenticated HVF restore implementation.
    pub fn dispatch_hvf(
        self,
        store: &CheckpointStore,
        restorer: &mvm_runtime::hvf_restore::HvfForkRestorer,
        anchor: &dyn CheckpointChainAnchor,
        stop_child: &dyn Fn(&str) -> Result<()>,
    ) -> VmFullForkDispatch {
        self.dispatch(store, VmFullForkRestorer::Hvf(restorer), anchor, stop_child)
    }

    /// Inject an HVF-compatible restorer for cross-crate containment tests.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn dispatch_test_hvf(
        self,
        store: &CheckpointStore,
        restorer: &dyn ForkRestorer,
        anchor: &dyn CheckpointChainAnchor,
        stop_child: &dyn Fn(&str) -> Result<()>,
    ) -> VmFullForkDispatch {
        self.dispatch(
            store,
            VmFullForkRestorer::TestHvf(restorer),
            anchor,
            stop_child,
        )
    }

    /// Spend admission before clone/restore and select exactly one typed restorer.
    fn dispatch(
        mut self,
        store: &CheckpointStore,
        restorer: VmFullForkRestorer<'_>,
        anchor: &dyn CheckpointChainAnchor,
        stop_child: &dyn Fn(&str) -> Result<()>,
    ) -> VmFullForkDispatch {
        let result = (|| {
            bind_fork_dispatch(
                &mut self.admitted,
                &mut self.params,
                self.source.runtime.identity(),
            )?;
            ensure!(
                self.params.checkpoint == self.source.checkpoint,
                "fork request names a different checkpoint than the verified source"
            );
            ensure!(
                self.admitted.plan().workload.0 == self.params.child_vm_name,
                "admitted child plan names a different VM"
            );
            ensure!(
                self.admitted.plan().image.sha256 == self.source.restored_rootfs_sha256,
                "admitted child image differs from the authenticated restored rootfs"
            );
            match (
                self.admitted.plan().runtime_identity.as_ref(),
                self.source.runtime.identity(),
            ) {
                (Some(_), Some(identity)) => self
                    .admitted
                    .plan()
                    .require_runtime_identity(identity)
                    .context("retained fork runtime differs from the admitted child")?,
                (None, None) => {}
                _ => {
                    anyhow::bail!(
                        "admitted child and retained fork runtime disagree on runtime identity"
                    )
                }
            }
            ensure!(
                self.source.parent.meta_digest == self.source.parent_digest,
                "verified fork source metadata identity changed"
            );
            let expected_backend = match self.source.origin() {
                Some(VmFullOrigin::Firecracker) => mvm_core::vm_backend::BackendKind::Firecracker,
                Some(VmFullOrigin::Hvf) => mvm_core::vm_backend::BackendKind::Hvf,
                Some(VmFullOrigin::Retired) | None => {
                    anyhow::bail!("checkpoint has no supported authenticated runtime backend")
                }
            };
            ensure!(
                self.admitted.backend_kind() == Some(expected_backend),
                "admitted child backend differs from the authenticated checkpoint origin"
            );
            ensure!(
                restorer.matches(self.source.origin()),
                "full-VM fork selected a restorer for the wrong backend"
            );
            let child_name = self.params.child_vm_name.clone();
            let meta = mvm_runtime::checkpoint::fork_vm_full_verified_with_rollback(
                store,
                self.params,
                &restorer,
                anchor,
                &self.source.runtime,
                &self.source.restored_rootfs_sha256,
                stop_child,
            )?;
            // The child is live after restore. Share the original fork path's
            // containment/uncertain-stop boundary before handing it to the caller.
            super::containment_recheck::recheck_live_fork(
                self.admitted.plan(),
                &child_name,
                stop_child,
            )?;
            Ok(meta)
        })();
        VmFullForkDispatch {
            result,
            admitted: self.admitted,
        }
    }
}

fn bind_fork_dispatch(
    admitted: &mut AdmittedPlan,
    params: &mut ForkParams,
    runtime_identity: Option<&mvm_core::plan::RuntimeIdentity>,
) -> Result<()> {
    ensure!(
        !admitted.dispatched,
        "original admitted plan was already dispatched"
    );
    // Dispatch is an attempt, not a successful clone. Spend before every
    // binding check so a mismatched request cannot probe and then retry the
    // same one-use admission with different projections.
    admitted.dispatched = true;
    ensure!(
        admitted.plan().workload.0 == params.child_vm_name,
        "admitted child plan names a different VM"
    );
    match (admitted.plan().runtime_identity.as_ref(), runtime_identity) {
        (Some(_), Some(identity)) => admitted
            .plan()
            .require_runtime_identity(identity)
            .context("retained fork runtime differs from the admitted child")?,
        (None, None) => {}
        _ => anyhow::bail!("admitted child and retained fork runtime disagree on runtime identity"),
    }
    params.child_plan_json = Some(
        serde_json::to_string(admitted.signed())
            .context("serializing the admitted fork child envelope")?,
    );
    params.child_tenant_id = Some(admitted.plan().tenant.0.clone());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admitted_child() -> AdmittedPlan {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.workload.0 = "fork-child".into();
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        let signer = "host:test".to_string();
        let signed = mvm_core::plan::sign_plan(
            &plan,
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            &signer,
        );
        AdmittedPlan::for_test(plan, signer, signed)
    }

    fn params(name: &str) -> ForkParams {
        ForkParams {
            checkpoint: mvm_core::checkpoint::CheckpointId::new("parent"),
            child_id: mvm_core::checkpoint::CheckpointId::new("child"),
            child_vm_name: name.into(),
            dest_dir: std::path::PathBuf::new(),
            created_unix: 1,
            parent_liveness: mvm_runtime::checkpoint::ForkParentLiveness::MayBeRunning,
            // Caller projections must never become the dispatch authority.
            child_plan_json: Some("untrusted".into()),
            child_tenant_id: Some("other-tenant".into()),
        }
    }

    #[test]
    fn fork_dispatch_projects_its_own_plan_and_spends_it_once() {
        let mut admitted = admitted_child();
        let mut launch = params("fork-child");
        bind_fork_dispatch(&mut admitted, &mut launch, None).unwrap();
        let projected = mvm_core::plan::plan_from_admitted_json(
            launch.child_plan_json.as_deref().expect("signed envelope"),
        )
        .unwrap();
        assert_eq!(projected.plan_id, admitted.plan_id().clone());
        assert_eq!(
            launch.child_tenant_id.as_deref(),
            Some(admitted.plan().tenant.0.as_str())
        );
        let error = bind_fork_dispatch(&mut admitted, &mut launch, None).unwrap_err();
        assert!(
            error.to_string().contains("already dispatched"),
            "{error:#}"
        );
    }

    #[test]
    fn fork_dispatch_refuses_a_different_child_and_spends_the_attempt() {
        let mut admitted = admitted_child();
        let mut wrong = params("other-child");
        let error = bind_fork_dispatch(&mut admitted, &mut wrong, None).unwrap_err();
        assert!(error.to_string().contains("different VM"), "{error:#}");
        let mut correct = params("fork-child");
        let retry = bind_fork_dispatch(&mut admitted, &mut correct, None).unwrap_err();
        assert!(
            retry.to_string().contains("already dispatched"),
            "{retry:#}"
        );
    }

    #[test]
    fn backend_restorer_variants_match_only_their_authenticated_origin() {
        let firecracker =
            VmFullForkRestorer::Firecracker(&mvm_runtime::firecracker::FcForkRestorer);
        assert!(firecracker.matches(Some(VmFullOrigin::Firecracker)));
        assert!(!firecracker.matches(Some(VmFullOrigin::Hvf)));

        let hvf = VmFullForkRestorer::Hvf(&mvm_runtime::hvf_restore::HvfForkRestorer);
        assert!(hvf.matches(Some(VmFullOrigin::Hvf)));
        assert!(!hvf.matches(Some(VmFullOrigin::Firecracker)));
        assert!(!hvf.matches(None));
    }
}
