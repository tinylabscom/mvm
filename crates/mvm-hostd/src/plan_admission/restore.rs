//! One-use admitted dispatch for a full-VM checkpoint child.
//!
//! A restore resumes a retained runtime, not a fresh kernel boot. The
//! checkpoint layer owns lineage/content verification and the backend's
//! paused-load/no-NIC/resume sequence; this boundary binds that operation to
//! the child's *new* signed admission before it can execute.

use anyhow::{Context, Result, ensure};
use mvm_runtime::checkpoint::{
    CheckpointChainAnchor, CheckpointStore, ForkParams, ForkRestore, VerifiedRetainedRuntime,
};

use super::AdmittedPlan;

/// Spend the child's admitted authority on exactly one authenticated restore.
///
/// The serialized envelope and tenant sent to the checkpoint layer are
/// projections of `admitted`, never authority supplied by the caller. On
/// failure the admission remains spent once restore was attempted; the caller
/// retains it only to record the source-specific failed audit and rollback.
pub fn dispatch_vm_full_fork(
    admitted: &mut AdmittedPlan,
    store: &CheckpointStore,
    mut params: ForkParams,
    restore: &ForkRestore<'_>,
    anchor: &dyn CheckpointChainAnchor,
    runtime: &VerifiedRetainedRuntime,
    stop_child: &dyn Fn(&str) -> Result<()>,
) -> Result<mvm_core::checkpoint::CheckpointMeta> {
    // The parent record alone is not the lineage: authenticate every ancestor
    // before the lower transaction binds the same parent object to the child.
    mvm_runtime::checkpoint::verify_lineage(store, &params.checkpoint, anchor)
        .context("authenticating the fork parent lineage before dispatch")?;
    let admitted_image = admitted.plan().image.sha256.clone();
    bind_fork_dispatch(admitted, &mut params, runtime.identity())?;
    // The lower checkpoint transaction re-verifies the parent against the
    // signed chain, its retained runtime, and the child's own image/grant
    // bounds before calling the backend-specific restorer.
    let child_name = params.child_vm_name.clone();
    let meta = mvm_runtime::checkpoint::fork_vm_full_verified_with_rollback(
        store,
        params,
        restore,
        anchor,
        runtime,
        &admitted_image,
        stop_child,
    )?;
    // The child is live and registered; a containment committed since its
    // admission stops it here rather than letting it keep running.
    if let Err(error) = super::containment_recheck::still_admitted(admitted.plan()) {
        return Err(match stop_child(&child_name) {
            Ok(()) => error,
            Err(stop) => mvm_runtime::checkpoint::ForkStopUncertain {
                name: child_name,
                primary: error,
                stop,
            }
            .into(),
        });
    }
    Ok(meta)
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
    // Spend the plan before any snapshot cloning, including a failed or
    // uncertain restore. There is no permission to retry with the same plan.
    admitted.dispatched = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_runtime::checkpoint::CheckpointChainAnchor;

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
    fn fork_dispatch_refuses_a_different_child_before_spending_plan() {
        let mut admitted = admitted_child();
        let mut wrong = params("other-child");
        let error = bind_fork_dispatch(&mut admitted, &mut wrong, None).unwrap_err();
        assert!(error.to_string().contains("different VM"), "{error:#}");
        let mut correct = params("fork-child");
        bind_fork_dispatch(&mut admitted, &mut correct, None).unwrap();
    }

    struct HostedVm {
        rootfs: std::path::PathBuf,
    }

    impl mvm_vmm::checkpoint::VmFullControl for HostedVm {
        fn pause(&self) -> Result<()> {
            Ok(())
        }
        fn resume(&self) -> Result<()> {
            Ok(())
        }
        fn save_memory(&self, memory_path: &std::path::Path) -> Result<()> {
            std::fs::write(memory_path, b"mem")?;
            std::fs::write(memory_path.with_file_name("vmstate.bin"), b"fake-vmstate")?;
            Ok(())
        }
        fn rootfs_path(&self) -> Result<std::path::PathBuf> {
            Ok(self.rootfs.clone())
        }
        fn runtime_artifacts(&self) -> Result<mvm_vmm::runtime_artifacts::RuntimeArtifacts> {
            Ok(mvm_vmm::runtime_artifacts::RuntimeArtifacts {
                kernel: None,
                firecracker_drives: Some(vec![mvm_vmm::runtime_artifacts::FirecrackerDrive {
                    drive_id: "blk0".into(),
                    path: self.rootfs.clone(),
                    is_root_device: true,
                    is_read_only: true,
                }]),
                initramfs: None,
                disks: vec![mvm_vmm::runtime_artifacts::RuntimeArtifact {
                    path: self.rootfs.clone(),
                    sha256: mvm_core::crypto::image_verify::sha256_file(&self.rootfs)?,
                }],
                kernel_cmdline: String::new(),
            })
        }
        fn extra_content(
            &self,
            content_dir: &std::path::Path,
        ) -> Result<Vec<mvm_core::checkpoint::ContentBlob>> {
            Ok(vec![mvm_core::checkpoint::ContentBlob {
                name: "vmstate.bin".into(),
                sha256: mvm_core::crypto::image_verify::sha256_file(
                    &content_dir.join("vmstate.bin"),
                )?,
            }])
        }
        fn device_anchors(&self) -> Result<mvm_core::checkpoint::DeviceAnchors> {
            Ok(mvm_core::checkpoint::DeviceAnchors {
                rootfs: self.rootfs.clone(),
                rootfs_verity: None,
                config: None,
                secrets: None,
                identity: None,
                vsock: self.rootfs.with_file_name("v.sock"),
            })
        }
    }

    struct Agreeing;

    impl CheckpointChainAnchor for Agreeing {
        fn recorded_creation_digest(
            &self,
            meta: &mvm_core::checkpoint::CheckpointMeta,
        ) -> Result<Option<mvm_core::checkpoint::CheckpointDigest>> {
            Ok(Some(meta.compute_meta_digest()))
        }
        fn recorded_creation_tenant(
            &self,
            _meta: &mvm_core::checkpoint::CheckpointMeta,
        ) -> Result<Option<String>> {
            Ok(Some("local".into()))
        }
    }

    /// Fork a child admitted before its workload was quarantined; returns the
    /// outcome, the names `stop_child` saw, and whether the restorer ran.
    fn fork_after_quarantine(
        stop: impl Fn(&str) -> Result<()>,
    ) -> (
        Result<mvm_core::checkpoint::CheckpointMeta>,
        Vec<String>,
        bool,
    ) {
        use std::cell::{Cell, RefCell};
        let home = tempfile::tempdir().expect("isolated home");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let store = CheckpointStore::at(home.path().join("store"));
        let rootfs = home.path().join("live.ext4");
        std::fs::write(&rootfs, b"disk").expect("rootfs");
        let parent = mvm_runtime::checkpoint::capture_vm_full(
            &store,
            mvm_runtime::checkpoint::CaptureVmFullParams {
                id: mvm_core::checkpoint::CheckpointId::new("parent"),
                vm_name: "origin".into(),
                supervisor_config_digest: "d".into(),
                runtime_overlay_version: None,
                runtime_launch_binding: None,
                supervisor_config_src: None,
                tag: None,
                created_unix: 1,
                retain_paused: false,
                grants: None,
                parent: None,
                session: None,
                workspace_volumes: Vec::new(),
                key_domain: mvm_core::checkpoint::CheckpointKeyDomain::host(),
            },
            &HostedVm { rootfs },
        )
        .expect("parent checkpoint");
        let image = mvm_runtime::checkpoint::materialized_blob_sha256(
            &store,
            &parent,
            mvm_core::checkpoint::ROOTFS_BLOB,
        )
        .expect("rootfs digest");
        let mut plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .workload("fork-child")
            .build();
        plan.image.sha256 = image;
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        let signer = "host:test".to_string();
        let signed = mvm_core::plan::sign_plan(
            &plan,
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            &signer,
        );
        let mut admitted = AdmittedPlan::for_test(plan, signer, signed);
        let workload = admitted.plan().workload.0.clone();
        crate::policy_generation::workload_store::OwnedWorkloadStore::open(home.path())
            .expect("workload store")
            .commit(&mvm_core::host_interface::workload::WorkloadChange::Quarantine { workload })
            .expect("quarantine after the child's admission");
        let runtime = mvm_runtime::checkpoint::verify_checkpoint_runtime(&store, &parent)
            .expect("retained runtime");
        let restored = Cell::new(false);
        let stopped = RefCell::new(Vec::new());
        let outcome = dispatch_vm_full_fork(
            &mut admitted,
            &store,
            ForkParams {
                dest_dir: home.path().join("child"),
                ..params_for(&parent.id, "fork-child")
            },
            &|_: &mvm_runtime::checkpoint::RestoredChild<'_>| {
                restored.set(true);
                Ok(())
            },
            &Agreeing,
            &runtime,
            &|name| {
                stopped.borrow_mut().push(name.to_string());
                stop(name)
            },
        );
        (outcome, stopped.into_inner(), restored.get())
    }

    fn params_for(parent: &mvm_core::checkpoint::CheckpointId, name: &str) -> ForkParams {
        ForkParams {
            checkpoint: parent.clone(),
            ..params(name)
        }
    }

    #[test]
    fn a_fork_child_contained_after_admission_is_stopped_and_refused() {
        let (outcome, stopped, restored) = fork_after_quarantine(|_| Ok(()));
        let error = outcome.expect_err("a contained child must not be handed back");
        assert!(
            restored,
            "the child really was restored before the recheck: {error:#}"
        );
        assert_eq!(stopped, vec!["fork-child".to_string()]);
        assert!(
            format!("{error:#}").contains("no longer admits"),
            "{error:#}"
        );
        assert!(
            error
                .downcast_ref::<mvm_runtime::checkpoint::ForkStopUncertain>()
                .is_none(),
            "{error:#}"
        );
    }

    #[test]
    fn a_fork_child_that_cannot_be_stopped_is_reported_uncertain() {
        let (outcome, stopped, _) = fork_after_quarantine(|_| anyhow::bail!("stop not confirmed"));
        let error = outcome.expect_err("a contained child must not be handed back");
        assert_eq!(stopped, vec!["fork-child".to_string()]);
        let uncertain = error
            .downcast_ref::<mvm_runtime::checkpoint::ForkStopUncertain>()
            .unwrap_or_else(|| panic!("expected ForkStopUncertain: {error:#}"));
        assert_eq!(uncertain.name, "fork-child");
    }
}
