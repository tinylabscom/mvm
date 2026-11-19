//! Separate per-boot lifecycle keys and their exact admitted controller binding.

use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use mvm_contract::protocol::workload_actor::WorkflowRole;
use mvm_core::net::actor_session::{ActorSessionBinding, MAX_ACTOR_BINDING_BYTES};
use mvm_core::plan::ExecutionPlan;
use rand::TryRng as _;
use zeroize::Zeroizing;

/// Non-cloneable boot material. Host secrets are transferred only to helper stdin.
pub struct ActorBootMaterial {
    binding: ActorSessionBinding,
    host_seed: Zeroizing<[u8; 32]>,
    guest_seed: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for ActorBootMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActorBootMaterial")
            .field("binding", &self.binding)
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

/// Borrowed guest-only drive projection; it cannot expose the host signing seed.
#[derive(Clone, Copy)]
pub struct ActorGuestProjection<'a> {
    binding: &'a ActorSessionBinding,
    seed: &'a [u8; 32],
}

impl std::fmt::Debug for ActorGuestProjection<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActorGuestProjection")
            .field("binding", &self.binding)
            .field("seed", &"[REDACTED]")
            .finish()
    }
}

impl ActorGuestProjection<'_> {
    /// Public binding for the host holder and guest transport to pin identically.
    pub fn binding(&self) -> &ActorSessionBinding {
        self.binding
    }

    /// Guest-only seed for the existing private identity drive writer.
    pub(super) fn seed(&self) -> &[u8; 32] {
        self.seed
    }
}

impl ActorBootMaterial {
    /// Mint exactly once after ordinary signed-plan admission and before boot.
    ///
    /// A direct plan or unbound service allocates no keys or actor state. This
    /// checks content and identity consistency, not the plan's issuer signature;
    /// the caller must already hold ordinary admission for this exact plan.
    ///
    /// # Errors
    /// Refuses a bound service without controller authority, inconsistent signed
    /// identity, invalid content address, or entropy failure.
    pub fn for_plan(plan: &ExecutionPlan) -> Result<Option<Self>> {
        if !plan
            .services
            .iter()
            .any(|service| service.as_str() == "host.actor.v1")
        {
            return Ok(None);
        }
        let workflow = plan
            .workflow
            .as_ref()
            .context("actor service requires workflow membership")?;
        workflow
            .validate()
            .context("invalid actor workflow binding")?;
        let WorkflowRole::Controller { grant } = &workflow.role else {
            anyhow::bail!("actor lifecycle service requires controller authority");
        };
        ensure!(
            grant.controller.tenant == plan.tenant
                && grant.controller.workload == plan.workload
                && grant.controller.execution_epoch.get() == plan.execution_epoch,
            "actor controller identity differs from admitted plan"
        );
        mvm_core::plan::verify_plan_id(plan).context("actor plan is not content-addressed")?;
        let mut plan_digest = [0u8; 32];
        hex::decode_to_slice(
            plan.plan_id
                .0
                .strip_prefix("sha256:")
                .context("actor plan digest prefix")?,
            &mut plan_digest,
        )
        .context("actor plan digest")?;
        let guest_seed = mint_seed()?;
        let host_seed = mint_seed()?;
        let binding = ActorSessionBinding {
            protocol_version: 1,
            purpose: "host.actor.v1".into(),
            tenant: plan.tenant.0.clone(),
            workflow: workflow.workflow_id.as_str().into(),
            boot_id: hex::encode(grant.controller.boot_id.as_bytes()),
            plan_digest,
            epoch: plan.execution_epoch,
            controller_generation: grant.controller.generation.get(),
            key_generation: 1,
            guest_public_key: SigningKey::from_bytes(&guest_seed)
                .verifying_key()
                .to_bytes(),
            host_public_key: SigningKey::from_bytes(&host_seed)
                .verifying_key()
                .to_bytes(),
        };
        binding
            .session_id()
            .context("validate actor boot binding")?;
        ensure!(
            serde_json::to_vec(&binding)?.len() <= MAX_ACTOR_BINDING_BYTES,
            "actor boot binding exceeds the encoded bound"
        );
        ensure!(
            binding.guest_public_key != binding.host_public_key,
            "actor keys must be distinct"
        );
        Ok(Some(Self {
            binding,
            host_seed,
            guest_seed,
        }))
    }

    /// Public context for trusted post-boot registration.
    pub fn binding(&self) -> &ActorSessionBinding {
        &self.binding
    }

    /// Project only the guest half into the private read-only identity drive.
    pub fn guest_projection(&self) -> ActorGuestProjection<'_> {
        ActorGuestProjection {
            binding: &self.binding,
            seed: &self.guest_seed,
        }
    }

    /// Consume the material after drive projection and transfer the host half.
    ///
    /// The recipient must send the seed only over the holder's private stdin,
    /// never persist it in metadata, command lines, environment, or log output.
    pub fn into_host_parts(self) -> (ActorSessionBinding, Zeroizing<[u8; 32]>) {
        (self.binding, self.host_seed)
    }
}

fn mint_seed() -> Result<Zeroizing<[u8; 32]>> {
    let mut seed = Zeroizing::new([0; 32]);
    rand::rngs::SysRng
        .try_fill_bytes(seed.as_mut())
        .context("drawing system entropy for actor boot identity")?;
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::assurance::Sha256Digest;
    use mvm_contract::protocol::broker::ServiceId;
    use mvm_contract::protocol::mailbox::{BootId, ExecutionEpoch};
    use mvm_contract::protocol::workload_actor::{
        ActorBindingId, ActorProtocolVersion, ControllerIdentity, DelegationDepth, LifecycleGrant,
        LifecycleOperation, ParentIdentity, TemplateBinding, WorkflowBinding,
    };
    use std::num::NonZeroU64;

    fn plan() -> ExecutionPlan {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.services
            .push(ServiceId::parse("host.actor.v1").unwrap());
        plan.workflow = Some(WorkflowBinding {
            version: ActorProtocolVersion::V1,
            workflow_id: ActorBindingId::new("workflow").unwrap(),
            constraint_snapshot_digest: Sha256Digest::from_bytes(&[1; 32]),
            role: WorkflowRole::Controller {
                grant: LifecycleGrant {
                    id: ActorBindingId::new("grant").unwrap(),
                    controller: ControllerIdentity {
                        tenant: plan.tenant.clone(),
                        workload: plan.workload.clone(),
                        execution_epoch: ExecutionEpoch::new(plan.execution_epoch).unwrap(),
                        boot_id: BootId::from_bytes([2; 32]),
                        generation: NonZeroU64::new(3).unwrap(),
                    },
                    depth: DelegationDepth::One,
                    templates: vec![TemplateBinding {
                        id: ActorBindingId::new("worker").unwrap(),
                        digest: Sha256Digest::from_bytes(&[4; 32]),
                    }],
                    operations: vec![LifecycleOperation::Launch],
                    not_before_unix_ms: 1,
                    expires_at_unix_ms: 2,
                    workflow_deadline_unix_ms: 3,
                },
            },
        });
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        plan
    }

    #[test]
    fn direct_and_unbound_plans_mint_no_actor_material() {
        let direct = mvm_core::plan::test_support::PlanFixture::new().build();
        assert!(ActorBootMaterial::for_plan(&direct).unwrap().is_none());
        let mut unbound = plan();
        unbound.services.clear();
        assert!(ActorBootMaterial::for_plan(&unbound).unwrap().is_none());
    }

    #[test]
    fn actor_material_is_exact_boot_bound_distinct_and_redacted() {
        let plan = plan();
        let material = ActorBootMaterial::for_plan(&plan).unwrap().unwrap();
        let next = ActorBootMaterial::for_plan(&plan).unwrap().unwrap();
        let binding = material.binding();
        assert_eq!(binding.boot_id, "02".repeat(32));
        assert_eq!(binding.epoch, plan.execution_epoch);
        assert_eq!(binding.controller_generation, 3);
        assert_eq!(binding.key_generation, 1);
        assert_eq!(
            format!("sha256:{}", hex::encode(binding.plan_digest)),
            plan.plan_id.0
        );
        assert_ne!(binding.guest_public_key, binding.host_public_key);
        assert_ne!(binding.guest_public_key, next.binding.guest_public_key);
        assert_ne!(binding.host_public_key, next.binding.host_public_key);
        for secret in [&material.host_seed, &material.guest_seed] {
            assert!(!format!("{material:?}").contains(&hex::encode(secret.as_slice())));
            assert!(
                !format!("{:?}", material.guest_projection())
                    .contains(&hex::encode(secret.as_slice()))
            );
        }
        let expected = material.binding.clone();
        let (public, host) = material.into_host_parts();
        assert_eq!(public, expected);
        assert_eq!(
            SigningKey::from_bytes(&host).verifying_key().to_bytes(),
            public.host_public_key
        );
    }

    #[test]
    fn bound_service_refuses_missing_membership_worker_or_mismatched_identity() {
        let valid = plan();
        let mut direct = valid.clone();
        direct.workflow = None;
        assert!(ActorBootMaterial::for_plan(&direct).is_err());
        let WorkflowRole::Controller { grant } = &valid.workflow.as_ref().unwrap().role else {
            panic!("controller fixture");
        };
        let mut worker = valid.clone();
        worker.workflow.as_mut().unwrap().role = WorkflowRole::Worker {
            parent: ParentIdentity {
                controller: grant.controller.clone(),
                plan_id: valid.plan_id.clone(),
            },
        };
        assert!(ActorBootMaterial::for_plan(&worker).is_err());
        for field in ["tenant", "workload", "epoch", "digest"] {
            let mut changed = valid.clone();
            match field {
                "tenant" => changed.tenant.0 = "another".into(),
                "workload" => changed.workload.0 = "another".into(),
                "epoch" => changed.execution_epoch += 1,
                "digest" => changed.plan_id.0 = "sha256:bad".into(),
                _ => unreachable!(),
            }
            assert!(ActorBootMaterial::for_plan(&changed).is_err(), "{field}");
        }
    }

    #[test]
    fn drive_contains_guest_material_but_never_the_actor_host_seed() {
        use super::super::flowmux_identity::{GuestIdentityMaterial, IdentityDriveContents};
        use mvm_core::net::actor_session::{ACTOR_BINDING_FILE, ACTOR_GUEST_KEY_FILE};
        let material = ActorBootMaterial::for_plan(&plan()).unwrap().unwrap();
        let guest =
            GuestIdentityMaterial::mint(SigningKey::from_bytes(&[8; 32]).verifying_key()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let drive = dir.path().join("identity.ext4");
        guest
            .write_drive_with(&drive, &IdentityDriveContents::default())
            .unwrap();
        let direct = std::fs::read(&drive).unwrap();
        assert!(
            !direct
                .windows(ACTOR_GUEST_KEY_FILE.len())
                .any(|bytes| bytes == ACTOR_GUEST_KEY_FILE.as_bytes())
        );
        guest
            .write_drive_with(
                &drive,
                &IdentityDriveContents {
                    actor: Some(material.guest_projection()),
                    ..Default::default()
                },
            )
            .unwrap();
        let image = std::fs::read(&drive).unwrap();
        for name in [ACTOR_BINDING_FILE, ACTOR_GUEST_KEY_FILE] {
            assert!(
                image
                    .windows(name.len())
                    .any(|bytes| bytes == name.as_bytes())
            );
        }
        assert!(
            image
                .windows(32)
                .any(|bytes| bytes == material.guest_seed.as_slice())
        );
        assert!(
            !image
                .windows(32)
                .any(|bytes| bytes == material.host_seed.as_slice())
        );
    }
}
