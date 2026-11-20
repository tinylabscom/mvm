//! Host-authenticated endpoint issuance and immutable ordinary-mailbox configuration.

use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use mvm_contract::assurance::Sha256Digest;
use mvm_contract::plan::ExecutionPlan;
use mvm_contract::protocol::mailbox::{
    AuthorizationDomainId, CapabilityOperations, ContentType, ExecutionEpoch, MailboxGrant,
    MailboxMessageKind, MailboxOperation, ReplyRoute, TenantId,
};
use mvm_contract::protocol::workload_actor::WorkflowRole;
use serde::{Deserialize, Serialize};

use crate::mailbox_launch::actor_template::{self, ActorEndpointTemplate};
use crate::mailbox_launch::authority_key_for;

use super::{ActorMailboxes, DerivedChildMailbox};

/// Explicit authority to create fresh endpoints, included in the workflow snapshot.
///
/// The initial profile has only Call/Reply and Send/Receive/Reply operations.
/// It never treats a legacy loopback capability as endpoint-creation authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorMailboxPolicy {
    pub tenant: TenantId,
    pub authorization_domain: AuthorizationDomainId,
    pub content_types: Vec<ContentType>,
    pub max_payload_bytes: u32,
    pub max_messages_per_minute: u32,
    pub max_outstanding_calls: u32,
    pub max_queue_contribution_bytes: u64,
    pub max_storage_bytes: u64,
    pub max_send_attempts: u32,
    pub policy_epoch: u64,
    pub not_before_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}

/// Trusted launcher custody. Never pass this owner or host roots to a scheduler.
#[derive(Debug)]
pub struct LocalActorMailboxes {
    keys_dir: PathBuf,
    policy: ActorMailboxPolicy,
    snapshot_digest: Sha256Digest,
    digest_bytes: [u8; 32],
}

impl LocalActorMailboxes {
    /// The caller must authenticate the complete snapshot containing `policy`.
    pub fn new(
        keys_dir: PathBuf,
        policy: ActorMailboxPolicy,
        snapshot_digest: [u8; 32],
    ) -> Result<Self> {
        ensure!(
            keys_dir.is_absolute(),
            "actor mailbox keys directory must be absolute"
        );
        ensure!(
            !policy.content_types.is_empty()
                && policy.content_types.len()
                    <= mvm_contract::protocol::mailbox::MAX_CAPABILITY_LIST_ITEMS
                && policy.max_payload_bytes > 0
                && policy.max_payload_bytes as usize
                    <= mvm_contract::protocol::mailbox::MAX_MAILBOX_PAYLOAD_BYTES
                && policy.max_messages_per_minute > 0
                && policy.max_outstanding_calls > 0
                && policy.max_queue_contribution_bytes >= u64::from(policy.max_payload_bytes)
                && policy.max_storage_bytes > 0
                && policy.max_send_attempts > 0
                && policy.not_before_unix_ms < policy.expires_at_unix_ms,
            "invalid actor mailbox policy"
        );
        Ok(Self {
            keys_dir,
            policy,
            snapshot_digest: Sha256Digest::from_bytes(&snapshot_digest),
            digest_bytes: snapshot_digest,
        })
    }

    /// Install the explicit controller endpoint before final plan signing.
    ///
    /// The caller assigns the returned authority-correct grant to the plan and
    /// recomputes its content address. Existing differing bindings refuse.
    pub fn install_controller(&self, plan: &ExecutionPlan) -> Result<MailboxGrant> {
        let workflow = plan
            .workflow
            .as_ref()
            .context("controller has no workflow")?;
        ensure!(
            workflow.constraint_snapshot_digest == self.snapshot_digest
                && matches!(workflow.role, WorkflowRole::Controller { .. }),
            "controller mailbox snapshot mismatch"
        );
        let mut grant = plan.mailbox.context("controller has no mailbox grant")?;
        ensure!(
            grant.epoch.get() == plan.execution_epoch && grant.retention.is_some(),
            "controller mailbox epoch or retention missing"
        );
        grant.authority_key =
            authority_key_for(&self.keys_dir, &grant.mailbox, grant.epoch)?.to_bytes();
        let endpoint = self.endpoint(plan, grant)?;
        actor_template::install(&self.keys_dir, endpoint)?;
        Ok(grant)
    }

    fn endpoint(&self, plan: &ExecutionPlan, grant: MailboxGrant) -> Result<ActorEndpointTemplate> {
        let mut template =
            actor_template::base_template(&self.keys_dir, &grant, self.policy.not_before_unix_ms)?;
        let policy = &self.policy;
        let capability = &mut template.capability;
        capability.address.tenant = policy.tenant;
        capability.address.authorization_domain = policy.authorization_domain;
        // Sender identity is the endpoint identity, not an unrelated loopback alias.
        capability.address.recipient = capability.subject;
        capability.operations = CapabilityOperations::from_operations(&[
            MailboxOperation::Send,
            MailboxOperation::Receive,
            MailboxOperation::Reply,
        ]);
        capability.message_kinds = vec![MailboxMessageKind::Call, MailboxMessageKind::Reply];
        capability.content_types = policy.content_types.clone();
        capability.max_payload_bytes = policy.max_payload_bytes;
        capability.max_messages_per_minute = policy.max_messages_per_minute;
        capability.max_outstanding_calls = policy.max_outstanding_calls;
        capability.max_queue_contribution_bytes = policy.max_queue_contribution_bytes;
        capability.policy_epoch = policy.policy_epoch;
        capability.not_before_unix_ms = policy
            .not_before_unix_ms
            .max(plan.valid_from.timestamp_millis());
        capability.expires_at_unix_ms = policy
            .expires_at_unix_ms
            .min(plan.valid_until.timestamp_millis());
        capability.delegation_depth = 0;
        capability.validate_bounds()?;
        let header = &mut template.header;
        header.tenant = policy.tenant;
        header.authorization_domain = policy.authorization_domain;
        header.recipient = capability.subject;
        header.sender = capability.subject;
        header.content_type = policy.content_types[0].clone();
        header.policy_epoch = policy.policy_epoch;
        header.issued_at_unix_ms = capability.not_before_unix_ms;
        header.expires_at_unix_ms = capability.expires_at_unix_ms;
        header.reply_to = Some(ReplyRoute {
            address: capability.address,
            capability_id: capability.capability_id,
        });
        template.routing.expires_at_unix_ms = capability.expires_at_unix_ms;
        Ok(ActorEndpointTemplate {
            workload: plan.workload.0.clone(),
            snapshot_digest: self.digest_bytes,
            max_storage_bytes: self.policy.max_storage_bytes,
            max_send_attempts: self.policy.max_send_attempts,
            membership: plan
                .workflow
                .clone()
                .context("actor endpoint has no membership")?,
            grant,
            template,
            parent: None,
        })
    }

    fn parent_endpoint(&self, parent: &ExecutionPlan) -> Result<ActorEndpointTemplate> {
        let endpoint = actor_template::verify_plan(&self.keys_dir, parent)?
            .context("actor parent endpoint is not installed")?;
        let workflow = parent.workflow.as_ref().context("parent has no workflow")?;
        ensure!(
            workflow.constraint_snapshot_digest == self.snapshot_digest
                && matches!(workflow.role, WorkflowRole::Controller { .. }),
            "parent mailbox snapshot mismatch"
        );
        ensure!(
            endpoint == self.endpoint(parent, endpoint.grant)?,
            "parent mailbox policy changed"
        );
        Ok(endpoint)
    }

    fn require_current(endpoint: &ActorEndpointTemplate) -> Result<()> {
        let now = crate::mailbox_launch::actor_template::current_time_ms()?;
        ensure!(
            now >= endpoint.template.capability.not_before_unix_ms
                && now < endpoint.template.capability.expires_at_unix_ms,
            "parent mailbox authority is not current"
        );
        Ok(())
    }

    fn child_endpoint(
        &self,
        parent: &ExecutionPlan,
        child: &ExecutionPlan,
    ) -> Result<(ActorEndpointTemplate, ActorEndpointTemplate)> {
        let parent_endpoint = self.parent_endpoint(parent)?;
        ensure!(
            child.workload != parent.workload
                && child.tenant == parent.tenant
                && child.execution_epoch == 1
                && parent_endpoint.grant.epoch.get() == child.execution_epoch,
            "child mailbox identity is not fresh"
        );
        let membership = child.workflow.as_ref().context("child has no workflow")?;
        ensure!(
            membership.constraint_snapshot_digest == self.snapshot_digest,
            "child snapshot mismatch"
        );
        let WorkflowRole::Worker { parent: lineage } = &membership.role else {
            anyhow::bail!("child mailbox cannot delegate");
        };
        ensure!(
            lineage.plan_id == parent.plan_id
                && lineage.controller.workload == parent.workload
                && lineage.controller.tenant == parent.tenant,
            "child mailbox lineage mismatch"
        );
        let template_grant = child.mailbox.context("child template has no mailbox")?;
        ensure!(
            template_grant.retention == parent_endpoint.grant.retention
                && template_grant.report.is_none_or(|report| {
                    parent_endpoint.grant.report.is_some_and(|parent| {
                        report.max_payload_bytes() <= parent.max_payload_bytes()
                    })
                }),
            "child mailbox retention or report widened"
        );
        let epoch = ExecutionEpoch::new(child.execution_epoch)?;
        let mailbox = actor_template::child_mailbox(
            &self.keys_dir,
            &parent_endpoint.grant,
            &child.workload.0,
            epoch,
        )?;
        ensure!(
            mailbox != parent_endpoint.grant.mailbox,
            "child mailbox reused parent"
        );
        let grant = MailboxGrant {
            mailbox,
            epoch,
            authority_key: authority_key_for(&self.keys_dir, &mailbox, epoch)?.to_bytes(),
            report: template_grant.report,
            retention: template_grant.retention,
            service_blind: None,
        };
        let mut endpoint = self.endpoint(child, grant)?;
        endpoint.parent = Some(parent_endpoint.grant);
        ensure!(
            endpoint.template.capability.not_before_unix_ms
                >= parent_endpoint.template.capability.not_before_unix_ms
                && endpoint.template.capability.expires_at_unix_ms
                    <= parent_endpoint.template.capability.expires_at_unix_ms,
            "child mailbox validity widened"
        );
        Ok((parent_endpoint, endpoint))
    }
}

impl ActorMailboxes for LocalActorMailboxes {
    fn reap_attempt(&self, parent: &ExecutionPlan, child: &ExecutionPlan) -> Result<()> {
        let (parent_endpoint, endpoint) = self.child_endpoint(parent, child)?;
        actor_template::reap_attempt(&self.keys_dir, &parent_endpoint, &endpoint)?;
        Ok(())
    }

    fn derive(&self, parent: &ExecutionPlan, child: &ExecutionPlan) -> Result<DerivedChildMailbox> {
        let (parent_endpoint, endpoint) = self.child_endpoint(parent, child)?;
        Self::require_current(&parent_endpoint)?;
        let grant = endpoint.grant;
        actor_template::install(&self.keys_dir, endpoint.clone())?;
        actor_template::install_pair(&self.keys_dir, &parent_endpoint, &endpoint)?;
        Ok(DerivedChildMailbox {
            grant,
            address: endpoint.template.capability.address,
            parent_capability: actor_template::signed_capability(&self.keys_dir, &parent_endpoint)?,
            child_capability: actor_template::signed_capability(&self.keys_dir, &endpoint)?,
            parent_issuer_key: parent_endpoint.grant.authority_key,
            child_issuer_key: grant.authority_key,
        })
    }

    fn verify_current(&self, parent: &ExecutionPlan, child: &DerivedChildMailbox) -> Result<()> {
        let parent_endpoint = self.parent_endpoint(parent)?;
        Self::require_current(&parent_endpoint)?;
        let endpoint = actor_template::load(&self.keys_dir, &child.grant)?
            .context("child mailbox binding missing")?;
        ensure!(
            endpoint.snapshot_digest == self.digest_bytes
                && endpoint.parent == Some(parent_endpoint.grant)
                && endpoint.template.capability.address == child.address
                && child.parent_issuer_key == parent_endpoint.grant.authority_key
                && child.child_issuer_key == endpoint.grant.authority_key
                && child.parent_capability
                    == actor_template::signed_capability(&self.keys_dir, &parent_endpoint)?
                && child.child_capability
                    == actor_template::signed_capability(&self.keys_dir, &endpoint)?,
            "actor mailbox binding changed"
        );
        let now = actor_template::current_time_ms()?;
        ensure!(
            now >= endpoint.template.capability.not_before_unix_ms
                && now < endpoint.template.capability.expires_at_unix_ms,
            "child mailbox authority is not current"
        );
        actor_template::verify_pair(&self.keys_dir, &parent_endpoint, &endpoint)?;
        Ok(())
    }

    fn reap(&self, child: &DerivedChildMailbox) -> Result<()> {
        ensure!(
            child.child_issuer_key
                == authority_key_for(&self.keys_dir, &child.grant.mailbox, child.grant.epoch)?
                    .to_bytes()
                && child.address.mailbox == child.grant.mailbox,
            "child mailbox cleanup scope mismatch"
        );
        actor_template::reap(
            &self.keys_dir,
            &child.grant,
            self.digest_bytes,
            &child.child_capability,
        )?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use mvm_contract::protocol::mailbox::{BootId, MailboxId, MailboxRetentionPolicy};
    use mvm_contract::protocol::workload_actor::{
        ActorBindingId, ActorProtocolVersion, ControllerIdentity, DelegationDepth, LifecycleGrant,
        LifecycleOperation, ParentIdentity, TemplateBinding, WorkflowBinding,
    };
    use mvm_core::crypto::aead::Key;
    use mvm_core::plan::{compute_plan_id, test_support::PlanFixture};
    use std::num::NonZeroU64;

    /// Keep the fifth element alive: peer socket bindings depend on `MVM_HOME`.
    pub(crate) fn setup() -> (
        tempfile::TempDir,
        LocalActorMailboxes,
        ExecutionPlan,
        ExecutionPlan,
        mvm_core::util::test_env::TestEnv,
    ) {
        let environment = mvm_core::util::test_env::TestEnv::new();
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
        let mut parent = PlanFixture::new().build();
        let epoch = ExecutionEpoch::new(1).unwrap();
        let controller = ControllerIdentity {
            tenant: parent.tenant.clone(),
            workload: parent.workload.clone(),
            execution_epoch: epoch,
            boot_id: BootId::from_bytes([3; 32]),
            generation: NonZeroU64::new(1).unwrap(),
        };
        let policy = ActorMailboxPolicy {
            tenant: TenantId::from_bytes([1; 32]),
            authorization_domain: AuthorizationDomainId::from_bytes([2; 32]),
            content_types: vec![ContentType::parse("application/vnd.mvm.actor-test", 1).unwrap()],
            max_payload_bytes: 1024,
            max_messages_per_minute: 60,
            max_outstanding_calls: 4,
            max_queue_contribution_bytes: 4096,
            max_storage_bytes: 2 * 1024 * 1024,
            max_send_attempts: 8,
            policy_epoch: 1,
            not_before_unix_ms: parent.valid_from.timestamp_millis(),
            expires_at_unix_ms: parent.valid_until.timestamp_millis(),
        };
        parent.workflow = Some(WorkflowBinding {
            version: ActorProtocolVersion::V1,
            workflow_id: ActorBindingId::new("workflow").unwrap(),
            constraint_snapshot_digest: Sha256Digest::from_bytes(&[5; 32]),
            role: WorkflowRole::Controller {
                grant: LifecycleGrant {
                    id: ActorBindingId::new("controller").unwrap(),
                    controller: controller.clone(),
                    depth: DelegationDepth::One,
                    templates: vec![TemplateBinding {
                        id: ActorBindingId::new("child").unwrap(),
                        digest: Sha256Digest::from_bytes(&[6; 32]),
                    }],
                    operations: vec![LifecycleOperation::Launch],
                    not_before_unix_ms: policy.not_before_unix_ms,
                    expires_at_unix_ms: policy.expires_at_unix_ms,
                    workflow_deadline_unix_ms: policy.expires_at_unix_ms,
                },
            },
        });
        parent.mailbox = Some(MailboxGrant {
            mailbox: MailboxId::from_bytes([7; 32]),
            authority_key: [0; 32],
            epoch,
            report: None,
            retention: Some(MailboxRetentionPolicy::new(10_000).unwrap()),
            service_blind: None,
        });
        let owner = LocalActorMailboxes::new(dir.path().to_owned(), policy, [5; 32]).unwrap();
        parent.mailbox = Some(owner.install_controller(&parent).unwrap());
        parent.plan_id = compute_plan_id(&parent);
        actor_template::endpoint_material(dir.path(), &parent)
            .unwrap()
            .unwrap();
        let mut child = parent.clone();
        child.workload.0 = "child-fresh-workload".into();
        child.workflow.as_mut().unwrap().role = WorkflowRole::Worker {
            parent: ParentIdentity {
                controller,
                plan_id: parent.plan_id.clone(),
            },
        };
        (dir, owner, parent, child, environment)
    }

    #[test]
    fn the_fixture_holds_the_process_environment_for_its_lifetime() {
        mvm_core::util::test_env::isolated_env_probe(|| {
            let fixture = setup();
            let (started, ready) = std::sync::mpsc::channel();
            let (sent, received) = std::sync::mpsc::channel();
            let probe = std::thread::spawn(move || {
                started.send(()).expect("report the probe started");
                let _environment = mvm_core::util::test_env::TestEnv::new();
                sent.send(()).expect("report the acquired environment");
            });
            ready
                .recv_timeout(std::time::Duration::from_secs(60))
                .expect("the probe starts");
            let while_live = received.recv_timeout(std::time::Duration::from_millis(300));
            drop(fixture);
            let after_drop = received.recv_timeout(std::time::Duration::from_secs(60));
            after_drop.expect("the environment is released with the fixture");
            probe.join().expect("probe thread");
            assert_eq!(
                while_live,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout),
                "another test acquired the environment while the fixture was live"
            );
        });
    }

    #[test]
    fn real_keys_install_exact_live_templates_and_pair_specific_directions() {
        let (dir, owner, parent, mut child, _environment) = setup();
        let derived = owner.derive(&parent, &child).unwrap();
        owner.verify_current(&parent, &derived).unwrap();
        child.mailbox = Some(derived.grant);
        child.plan_id = compute_plan_id(&child);
        let (policy, sealer) =
            crate::mailbox_launch::derive_launch_keys(dir.path(), &derived.grant, &Key::random())
                .unwrap()
                .trust();
        assert_eq!(sealer.capability, derived.child_capability.grant);
        assert_eq!(policy.context.expected_tenant, derived.address.tenant);
        assert_eq!(policy.context.expected_recipient, derived.address.recipient);
        assert_eq!(policy.authority_key.to_bytes(), derived.child_issuer_key);
        let parent_keys = actor_template::endpoint_material(dir.path(), &parent)
            .unwrap()
            .unwrap();
        let child_keys = actor_template::endpoint_material(dir.path(), &child)
            .unwrap()
            .unwrap();
        let outgoing = parent_keys.peer(&derived.address).unwrap();
        let incoming = child_keys.peer(&parent_keys.address).unwrap();
        assert_eq!(
            outgoing.peer_socket,
            mvm_core::config::vm_mailbox_socket_at(&mvm_core::config::vm_state_dir(
                &child.workload.0
            ))
        );
        assert_eq!(
            incoming.peer_socket,
            mvm_core::config::vm_mailbox_socket_at(&mvm_core::config::vm_state_dir(
                &parent.workload.0
            ))
        );
        assert_eq!(
            outgoing.call_key().expose_bytes(),
            incoming.call_key().expose_bytes()
        );
        assert_eq!(
            outgoing.reply_key().expose_bytes(),
            incoming.reply_key().expose_bytes()
        );
        assert_ne!(
            outgoing.call_key().expose_bytes(),
            outgoing.reply_key().expose_bytes()
        );
        assert!(
            outgoing
                .send_capability
                .grant
                .operations
                .allows(MailboxOperation::Send)
        );
        assert!(
            !outgoing
                .send_capability
                .grant
                .operations
                .allows(MailboxOperation::Reply)
        );
        assert!(
            outgoing
                .parent_receive
                .grant
                .operations
                .allows(MailboxOperation::Receive)
        );
        assert!(
            !outgoing
                .parent_receive
                .grant
                .operations
                .allows(MailboxOperation::Send)
        );
        mvm_core::mailbox::verify_capability_signature(
            &outgoing.send_capability,
            &child_keys.authority_key().verifying_key(),
        )
        .unwrap();
        let same = owner.derive(&parent, &child).unwrap();
        assert_eq!(same.child_capability, derived.child_capability);
        let mut sibling_plan = child.clone();
        sibling_plan.workload.0 = "independent-child".into();
        let sibling = owner.derive(&parent, &sibling_plan).unwrap();
        sibling_plan.mailbox = Some(sibling.grant);
        sibling_plan.plan_id = compute_plan_id(&sibling_plan);
        actor_template::endpoint_material(dir.path(), &sibling_plan)
            .unwrap()
            .unwrap();
        assert_ne!(derived.address, sibling.address);
        let sibling_peer = parent_keys.peer(&sibling.address).unwrap();
        assert_ne!(
            outgoing.reply_key().expose_bytes(),
            sibling_peer.reply_key().expose_bytes()
        );
        assert_ne!(
            outgoing.call_key().expose_bytes(),
            sibling_peer.call_key().expose_bytes()
        );
    }

    #[test]
    fn policy_scope_tamper_and_uninstalled_parent_refuse() {
        let (dir, owner, parent, child, _environment) = setup();
        let mut foreign = parent.clone();
        foreign
            .workflow
            .as_mut()
            .unwrap()
            .constraint_snapshot_digest = Sha256Digest::from_bytes(&[9; 32]);
        assert!(owner.derive(&foreign, &child).is_err());
        let mut foreign = child.clone();
        foreign.workflow.as_mut().unwrap().role = parent.workflow.as_ref().unwrap().role.clone();
        assert!(owner.derive(&parent, &foreign).is_err());
        let mut foreign = parent.clone();
        foreign.mailbox.as_mut().unwrap().mailbox = MailboxId::from_bytes([44; 32]);
        assert!(owner.derive(&foreign, &child).is_err());
        let mut policy = owner.policy.clone();
        policy.max_payload_bytes += 1;
        let other = LocalActorMailboxes::new(dir.path().to_owned(), policy, [5; 32]).unwrap();
        assert!(other.install_controller(&parent).is_err());
        assert!(other.derive(&parent, &child).is_err());
        let derived = owner.derive(&parent, &child).unwrap();
        let mut tampered = derived.clone();
        tampered.child_capability.grant.max_payload_bytes += 1;
        assert!(owner.verify_current(&parent, &tampered).is_err());
    }

    #[test]
    fn actual_pair_keys_seal_and_authenticate_only_the_admitted_direction() {
        use mvm_contract::protocol::mailbox::{CapabilityId, MessageId};
        use mvm_core::mailbox::{InMemoryReplayProtector, OpenContext, SealRequest};
        let (dir, owner, parent, mut child, _environment) = setup();
        let derived = owner.derive(&parent, &child).unwrap();
        child.mailbox = Some(derived.grant);
        child.plan_id = compute_plan_id(&child);
        let parent_keys = actor_template::endpoint_material(dir.path(), &parent)
            .unwrap()
            .unwrap();
        let child_keys = actor_template::endpoint_material(dir.path(), &child)
            .unwrap()
            .unwrap();
        parent_keys.verify_plan(&parent).unwrap();
        child_keys.verify_plan(&child).unwrap();
        assert_eq!(parent_keys.peers().unwrap().len(), 1);
        let outgoing = parent_keys.peer(&derived.address).unwrap();
        let mut header = outgoing.call.header.clone();
        header.reply_to = Some(ReplyRoute {
            address: parent_keys.address,
            capability_id: CapabilityId::from_bytes([45; 32]),
        });
        header.message_id = MessageId::from_bytes([46; 32]);
        header.plaintext_len = 5;
        let context = OpenContext {
            expected_tenant: header.tenant,
            expected_authorization_domain: header.authorization_domain,
            expected_mailbox: header.mailbox,
            expected_sender: header.sender,
            expected_recipient: header.recipient,
            acting_principal: header.sender,
            expected_capability_issuer: outgoing.send_capability.grant.issuer,
            current_execution_epoch: header.execution_epoch,
            current_policy_epoch: header.policy_epoch,
            required_operation: MailboxOperation::Send,
            now_unix_ms: actor_template::current_time_ms().unwrap(),
            accepted_content_types: vec![header.content_type.clone()],
            revoked_capabilities: vec![],
        };
        let envelope = mvm_core::mailbox::seal_envelope(
            SealRequest {
                routing: outgoing.call.routing.clone(),
                header,
                plaintext: b"hello",
            },
            &outgoing.call_key(),
            &parent_keys.sender_key(),
        )
        .unwrap();
        let incoming = child_keys.peers().unwrap().pop().unwrap();
        let opened = mvm_core::mailbox::open_authenticated_envelope(
            &envelope,
            &incoming.send_capability,
            &context,
            &incoming.call_key(),
            &parent_keys.sender_key().verifying_key(),
            &child_keys.authority_key().verifying_key(),
            &mut InMemoryReplayProtector::default(),
        );
        assert!(opened.is_ok());
        assert!(
            mvm_core::mailbox::open_authenticated_envelope(
                &envelope,
                &incoming.send_capability,
                &context,
                &incoming.reply_key(),
                &parent_keys.sender_key().verifying_key(),
                &child_keys.authority_key().verifying_key(),
                &mut InMemoryReplayProtector::default(),
            )
            .is_err()
        );
        let mut other_plan = child.clone();
        other_plan.nonce = mvm_contract::plan::Nonce::from_bytes([91; 16]);
        assert!(child_keys.verify_plan(&other_plan).is_err());
    }

    #[test]
    fn corrupt_peer_registry_and_missing_root_refuse_without_reinitializing() {
        let (dir, owner, parent, child, _environment) = setup();
        let derived = owner.derive(&parent, &child).unwrap();
        let parent_keys = actor_template::endpoint_material(dir.path(), &parent)
            .unwrap()
            .unwrap();
        let path = std::fs::read_dir(&parent_keys.registry_directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "sealed")
            })
            .unwrap();
        std::fs::write(&path, b"truncated").unwrap();
        assert!(parent_keys.peer(&derived.address).is_err());
        assert!(parent_keys.peers().is_err());
        assert!(owner.reap(&derived).is_err());
        std::fs::remove_file(dir.path().join("mailbox-encryption.root")).unwrap();
        assert!(owner.derive(&parent, &child).is_err());
        assert!(!dir.path().join("mailbox-encryption.root").exists());
    }

    #[test]
    fn revocation_is_durable_idempotent_and_preserves_sealed_history() {
        let (dir, owner, parent, mut child, _environment) = setup();
        let derived = owner.derive(&parent, &child).unwrap();
        child.mailbox = Some(derived.grant);
        child.plan_id = compute_plan_id(&child);
        actor_template::endpoint_material(dir.path(), &child)
            .unwrap()
            .unwrap();
        let parent_keys = actor_template::endpoint_material(dir.path(), &parent)
            .unwrap()
            .unwrap();
        assert!(parent_keys.peer(&derived.address).is_ok());
        owner.reap(&derived).unwrap();
        owner.reap(&derived).unwrap();
        assert!(parent_keys.peer(&derived.address).is_err());
        assert!(owner.verify_current(&parent, &derived).is_err());
        assert!(owner.derive(&parent, &child).is_err());
        assert!(
            crate::mailbox_launch::derive_launch_keys(dir.path(), &derived.grant, &Key::random())
                .is_err()
        );
        let directory = dir.path().join("actor-mailbox-templates");
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "sealed")
            {
                let bytes = std::fs::read(entry.path()).unwrap();
                assert!(
                    !bytes
                        .windows(child.workload.0.len())
                        .any(|bytes| bytes == child.workload.0.as_bytes())
                );
                assert!(serde_json::from_slice::<serde_json::Value>(&bytes).is_err());
            }
        }
    }
}
