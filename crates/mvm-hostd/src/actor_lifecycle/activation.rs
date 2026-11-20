//! Host-captured controller boot identity, rechecked against durable current state.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Result, ensure};
use mvm_contract::plan::ExecutionPlan;
use mvm_contract::protocol::workload_actor::{
    LifecycleGrant, LifecycleOperation, ParentIdentity, WorkflowRole,
};
use mvm_core::host_interface::ExecutionEpoch;
use mvm_core::host_interface::workload::WorkloadLedger;
use mvm_core::net::actor_session::ActorSessionBinding;
use mvm_core::util::atomic_io::{FileLock, write_private};
use mvm_runtime::actor_teardown::ActorOwner;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::plan_admission::StartedMachine;

const MAX_ACTIVATION_BYTES: u64 = 8192;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveBoot {
    parent: ParentIdentity,
    vm_id: String,
    session: ActorSessionBinding,
    native_owner: Option<[u8; 32]>,
}

/// Captured from a successful admitted parent boot, not the service request.
pub struct ParentActivation {
    path: PathBuf,
    active: ActiveBoot,
    plan: ExecutionPlan,
}

impl ParentActivation {
    /// Publish a parent boot after ordinary admission and successful backend start.
    ///
    /// The trusted launcher must pass the same boot identity provisioned into the
    /// guest session and actor key holder. Replacing this record fences old handlers.
    pub fn activate(
        started: &StartedMachine,
        session: ActorSessionBinding,
        path: &Path,
    ) -> Result<Self> {
        let plan = started.admitted.plan();
        let binding = plan
            .workflow
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("direct workload has no actor activation"))?;
        let WorkflowRole::Controller { grant } = &binding.role else {
            anyhow::bail!("worker has no lifecycle authority");
        };
        session.session_id()?;
        let identity = grant.controller.clone();
        ensure!(
            session.tenant == plan.tenant.0
                && session.workflow == binding.workflow_id.as_str()
                && session.boot_id == hex::encode(identity.boot_id.as_bytes())
                && session.epoch == identity.execution_epoch.get()
                && session.controller_generation == identity.generation.get()
                && format!("sha256:{}", hex::encode(session.plan_digest)) == plan.plan_id.0,
            "controller session differs from signed grant"
        );
        ensure!(
            plan.tenant == identity.tenant
                && plan.workload == identity.workload
                && plan.execution_epoch == identity.execution_epoch.get()
                && started.vm_id.0 == plan.workload.0,
            "controller admission identity mismatch"
        );
        let active = ActiveBoot {
            parent: ParentIdentity {
                controller: identity,
                plan_id: plan.plan_id.clone(),
            },
            vm_id: started.vm_id.0.clone(),
            session,
            native_owner: None,
        };
        let _lock = FileLock::acquire(path)?;
        write_private(path, &serde_json::to_vec(&active)?)?;
        Ok(Self {
            path: path.to_owned(),
            active,
            plan: plan.clone(),
        })
    }

    pub fn plan(&self) -> &ExecutionPlan {
        &self.plan
    }

    pub fn identity(&self) -> &ParentIdentity {
        &self.active.parent
    }

    pub(super) fn bind_owner(&mut self, owner: &ActorOwner) -> Result<()> {
        ensure!(
            owner.vm_id().0 == self.active.vm_id && owner.is_running()?,
            "controller original owner mismatch"
        );
        let digest: [u8; 32] = Sha256::digest(serde_jcs::to_vec(&owner.journal())?).into();
        let _lock = FileLock::acquire(&self.path)?;
        ensure!(
            self.read_current()? == self.active,
            "controller activation changed before native binding"
        );
        ensure!(
            self.active.native_owner.is_none_or(|old| old == digest),
            "controller native owner changed"
        );
        self.active.native_owner = Some(digest);
        write_private(&self.path, &serde_json::to_vec(&self.active)?)?;
        Ok(())
    }

    pub(super) fn grant(&self) -> Result<&LifecycleGrant> {
        let Some(binding) = &self.plan.workflow else {
            anyhow::bail!("controller membership missing");
        };
        match &binding.role {
            WorkflowRole::Controller { grant } => Ok(grant),
            WorkflowRole::Worker { .. } => anyhow::bail!("worker cannot delegate"),
        }
    }

    /// Current durable activation, containment epoch, lease and backend state all gate work.
    pub(super) fn check(
        &self,
        owner: &ActorOwner,
        operation: LifecycleOperation,
        now_unix_ms: i64,
    ) -> Result<()> {
        self.check_current_record(operation, now_unix_ms)?;
        let digest: [u8; 32] = Sha256::digest(serde_jcs::to_vec(&owner.journal())?).into();
        ensure!(
            self.active.native_owner == Some(digest)
                && owner.vm_id().0 == self.active.vm_id
                && owner.is_running()?,
            "controller original native owner is not running"
        );
        Ok(())
    }

    fn read_current(&self) -> Result<ActiveBoot> {
        let mut bytes = Vec::new();
        std::fs::File::open(&self.path)?
            .take(MAX_ACTIVATION_BYTES + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_ACTIVATION_BYTES,
            "controller activation exceeds bound"
        );
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn check_current_record(&self, operation: LifecycleOperation, now_unix_ms: i64) -> Result<()> {
        let _lock = FileLock::acquire(&self.path)?;
        let active = self.read_current()?;
        ensure!(active == self.active, "controller activation is stale");
        self.grant()?.check_operation(operation, now_unix_ms)?;
        ensure!(
            now_unix_ms >= self.plan.valid_from.timestamp_millis()
                && now_unix_ms < self.plan.valid_until.timestamp_millis(),
            "controller plan expired"
        );
        WorkloadLedger::load_at(Path::new(&mvm_core::config::mvm_home()))?.authorize(
            &self.plan.workload.0,
            ExecutionEpoch(self.plan.execution_epoch),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use mvm_contract::assurance::Sha256Digest;
    use mvm_contract::protocol::mailbox::{BootId, ExecutionEpoch as MailboxEpoch};
    use mvm_contract::protocol::resource_controls::EnforcedGrants;
    use mvm_contract::protocol::workload_actor::{
        ActorBindingId, ActorProtocolVersion, ControllerIdentity, DelegationDepth, TemplateBinding,
        WorkflowBinding,
    };
    use mvm_core::plan::{compute_plan_id, sign_plan, test_support::PlanFixture};
    use mvm_core::protocol::broker::ServiceId;
    use mvm_core::vm_backend::{VmId, VmStartConfig};
    use mvm_runtime::AnyBackend;

    use super::*;

    fn started(backend: &AnyBackend, generation: u64) -> (StartedMachine, ActorSessionBinding) {
        let mut plan = PlanFixture::new()
            .services(vec![ServiceId::parse("host.actor.v1").unwrap()])
            .build();
        let controller = ControllerIdentity {
            tenant: plan.tenant.clone(),
            workload: plan.workload.clone(),
            execution_epoch: MailboxEpoch::new(1).unwrap(),
            boot_id: BootId::from_bytes([u8::try_from(generation).unwrap(); 32]),
            generation: NonZeroU64::new(generation).unwrap(),
        };
        plan.workflow = Some(WorkflowBinding {
            version: ActorProtocolVersion::V1,
            workflow_id: ActorBindingId::new("workflow").unwrap(),
            constraint_snapshot_digest: Sha256Digest::from_bytes(&[4; 32]),
            role: WorkflowRole::Controller {
                grant: LifecycleGrant {
                    id: ActorBindingId::new("grant").unwrap(),
                    controller,
                    depth: DelegationDepth::One,
                    templates: vec![TemplateBinding {
                        id: ActorBindingId::new("worker").unwrap(),
                        digest: Sha256Digest::from_bytes(&[3; 32]),
                    }],
                    operations: vec![
                        LifecycleOperation::Launch,
                        LifecycleOperation::ObserveChild,
                        LifecycleOperation::ReleaseChild,
                    ],
                    not_before_unix_ms: plan.valid_from.timestamp_millis(),
                    expires_at_unix_ms: plan.valid_until.timestamp_millis(),
                    workflow_deadline_unix_ms: plan.valid_until.timestamp_millis(),
                },
            },
        });
        plan.plan_id = compute_plan_id(&plan);
        let material = mvm_vmm::host::actor_identity::ActorBootMaterial::for_plan(&plan)
            .unwrap()
            .unwrap();
        let binding = material.binding().clone();
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let signed = sign_plan(&plan, &key, "host:test");
        let vm_id = if generation == 1 {
            backend
                .start(&VmStartConfig {
                    name: plan.workload.0.clone(),
                    ..Default::default()
                })
                .unwrap()
        } else {
            VmId(plan.workload.0.clone())
        };
        (
            StartedMachine {
                vm_id,
                admitted: crate::plan_admission::AdmittedPlan::for_test(
                    plan,
                    "host:test".into(),
                    signed,
                ),
                enforced_grants: EnforcedGrants::all_declared(),
            },
            binding,
        )
    }

    #[test]
    fn captured_session_and_current_activation_gate_every_operation() {
        let home = tempfile::tempdir().unwrap();
        let mut environment = mvm_core::util::test_env::TestEnv::new();
        environment.isolate_mvm_home(home.path());
        let backend = AnyBackend::from_hypervisor("mock");
        let (machine, binding) = started(&backend, 1);
        let path = home.path().join("active");
        let mut wrong = binding.clone();
        wrong.plan_digest[0] ^= 1;
        assert!(ParentActivation::activate(&machine, wrong, &path).is_err());
        let active = ParentActivation::activate(&machine, binding, &path).unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        assert!(
            active
                .check_current_record(LifecycleOperation::Launch, now)
                .is_ok()
        );
        assert!(
            active
                .check_current_record(
                    LifecycleOperation::Launch,
                    machine.admitted.plan().valid_until.timestamp_millis()
                )
                .is_err()
        );
        let (replacement, replacement_binding) = started(&backend, 2);
        ParentActivation::activate(&replacement, replacement_binding, &path).unwrap();
        assert!(
            active
                .check_current_record(LifecycleOperation::ObserveChild, now)
                .is_err()
        );
        std::fs::remove_file(path).unwrap();
        assert!(
            active
                .check_current_record(LifecycleOperation::ReleaseChild, now)
                .is_err()
        );
    }
}
