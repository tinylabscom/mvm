//! One host-owned lifecycle coordinator; no guest endpoint reaches its launch worker.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Result, ensure};
use chrono::Utc;
use mvm_contract::assurance::Sha256Digest;
use mvm_contract::plan::{ExecutionPlan, Nonce, Resources, Variant, WorkloadId};
use mvm_contract::policy::resolver::EffectivePolicy;
use mvm_contract::protocol::agent_capability::CapabilityBinding;
use mvm_contract::protocol::workload_actor::{
    ActorBindingId, ActorHandle, ActorOperation, ActorOutcome, ActorProtocolVersion,
    ActorRefusalCode, ActorRequest, ActorResponse, ActorToken, LifecycleOperation, WorkflowRole,
};
use mvm_core::network_policy::NetworkPolicy;
use mvm_core::plan::compute_plan_id;
use mvm_runtime::AnyBackend;
use mvm_runtime::actor_teardown::{ActorOwner, supports_actor_backend};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::journal::{AttemptRecord, ChildRecord, ChildState, Records};
use super::{ActorJournal, ActorMailboxes, ActorTemplate, ExactTemplateCatalog, ParentActivation};
use crate::actor_authority::{
    ChildAuthorityContext, MailboxDerivation, PolicyMaterial, validate_child_authority,
};
use crate::actor_reservations::{
    ActorReservations, ReservationCeilings, ReservationIdentity, ReservationRequest, ReserveOutcome,
};
use crate::admission_budget::HostBudgetPermit;
use crate::audit::emitter::AuditEmitter;
use crate::plan_admission::{
    HostPermitAdmission, InMemoryNonceLedger, RunPosture, StartAdmittedParams, SystemClock,
    admit_plan_for_run_with_host_permit, start_admitted_owned_actor,
};

/// Exact host constraint snapshot whose canonical digest the parent plan signs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorConstraints {
    pub ceilings: ReservationCeilings,
    pub parent_charge: mvm_contract::protocol::actor_budget::ActorResources,
    pub child_resources: Resources,
    pub network: NetworkPolicy,
    pub effective_policy: EffectivePolicy,
    pub capabilities: Vec<CapabilityBinding>,
    pub mailbox_policy: super::local_mailboxes::ActorMailboxPolicy,
}

impl ActorConstraints {
    pub fn digest(&self) -> Result<Sha256Digest> {
        Ok(Sha256Digest::from_bytes(&hash(self)?))
    }

    /// Validate the signed root reservation before the bootstrap reserves or boots it.
    pub fn validate_parent_charge(&self, plan: &ExecutionPlan) -> Result<()> {
        let charge = self.parent_charge;
        ensure!(
            charge.live_vms == 1
                && charge.resident_vmms == 1
                && charge.controllers == 1
                && charge.concurrent_launches == 1
                && charge.warm_slots == 0
                && charge.parked_slots == 0
                && charge.checkpoint_slots == 0,
            "actor parent charge must describe one cold controller"
        );
        super::template::validate_resource_charge(plan, charge)?;
        self.validate_mailbox_charge(charge.mailbox_bytes)
    }

    fn validate_mailbox_charge(&self, mailbox_bytes: u64) -> Result<()> {
        ensure!(
            self.mailbox_policy.max_storage_bytes > 0
                && mailbox_bytes >= self.mailbox_policy.max_storage_bytes,
            "actor mailbox charge does not cover authenticated storage capacity"
        );
        Ok(())
    }
}

/// Host-owned construction inputs, deliberately not a guest-deserializable configuration.
pub struct ActorLifecycleInputs {
    pub parent: ParentActivation,
    pub templates: ExactTemplateCatalog,
    pub journal: ActorJournal,
    pub reservations: ActorReservations,
    pub constraints: ActorConstraints,
    pub backend: AnyBackend,
    pub mailboxes: Arc<dyn ActorMailboxes>,
    pub emitter: AuditEmitter,
    pub signer_keys_dir: PathBuf,
    pub variant: Variant,
}

/// Serial host admission owner. Original runtime custody never enters the broker.
pub struct ActorLifecycle {
    host: ActorLifecycleInputs,
    nonces: InMemoryNonceLedger,
    owners: BTreeMap<String, ActorOwner>,
    failed_starts: BTreeMap<String, anyhow::Error>,
    pending_attempts: std::cell::RefCell<BTreeMap<String, AttemptRecord>>,
    entrypoints: BTreeMap<String, EntrypointReader>,
}

struct EntrypointReader {
    cancel: mvm_runtime::actor_teardown::ActorEntrypointCancel,
    thread: Option<std::thread::JoinHandle<Result<()>>>,
    terminal_observed: Option<bool>,
}

impl EntrypointReader {
    fn finish(&mut self) -> Result<&'static str> {
        if self.terminal_observed.is_none() {
            let thread = self
                .thread
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("actor entrypoint reader missing"))?;
            if !thread.is_finished() {
                self.cancel.cancel()?;
            }
            let thread = self
                .thread
                .take()
                .ok_or_else(|| anyhow::anyhow!("actor entrypoint reader missing"))?;
            self.terminal_observed = Some(matches!(thread.join(), Ok(Ok(()))));
        }
        Ok(if self.terminal_observed == Some(true) {
            "terminal_observed"
        } else {
            "uncertain"
        })
    }
}

struct ReservedLaunch<'a> {
    template: &'a ActorTemplate,
    child_name: &'a str,
    identity: ReservationIdentity,
    key: &'a ActorBindingId,
    host_permit: HostBudgetPermit,
}

enum ReleaseAuthority<'a> {
    Controller(&'a ActorOwner),
    HostCleanup,
}

impl ActorLifecycle {
    pub fn new(mut host: ActorLifecycleInputs, parent_owner: &ActorOwner) -> Result<Self> {
        supports_actor_backend(&host.backend)?;
        host.constraints
            .validate_parent_charge(host.parent.plan())?;
        ensure!(
            host.constraints.effective_policy == EffectivePolicy::default(),
            "actor profile requires the ordinary default policy bundle"
        );
        let membership = host
            .parent
            .plan()
            .workflow
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("direct workload cannot open actor service"))?;
        ensure!(
            membership.constraint_snapshot_digest == host.constraints.digest()?,
            "actor constraint snapshot mismatch"
        );
        for binding in &host.parent.grant()?.templates {
            let template = host.templates.resolve(binding)?;
            host.constraints
                .validate_mailbox_charge(template.definition().charge.mailbox_bytes)?;
            // Check the existing template's non-mailbox authority before any
            // endpoint installation. The launch still requires the full proof.
            let mut shape = template.definition().plan.clone();
            shape.mailbox = None;
            shape.valid_from = shape.valid_from.max(host.parent.plan().valid_from);
            shape.valid_until = shape.valid_until.min(host.parent.plan().valid_until);
            Self::validate_authority(&host, template, &shape, None)?;
        }
        host.parent.bind_owner(parent_owner)?;
        Ok(Self {
            host,
            nonces: InMemoryNonceLedger::new(),
            owners: BTreeMap::new(),
            failed_starts: BTreeMap::new(),
            pending_attempts: std::cell::RefCell::new(BTreeMap::new()),
            entrypoints: BTreeMap::new(),
        })
    }

    /// Called only through the inherited channel from this parent's encrypted key holder.
    pub fn handle(&mut self, request: ActorRequest, parent_owner: &ActorOwner) -> ActorResponse {
        let operation = match &request.operation {
            ActorOperation::Launch { .. } => LifecycleOperation::Launch,
            ActorOperation::ObserveChild { .. } => LifecycleOperation::ObserveChild,
            ActorOperation::ReleaseChild { .. } => LifecycleOperation::ReleaseChild,
        };
        let outcome = if let Err(code) = self.authenticate(operation, parent_owner) {
            refused(code)
        } else {
            match &request.operation {
                ActorOperation::Launch {
                    grant_id,
                    template_id,
                    idempotency_key,
                } => self.launch(
                    &request,
                    grant_id,
                    template_id,
                    idempotency_key,
                    parent_owner,
                ),
                ActorOperation::ObserveChild { handle } => self.observe(handle),
                ActorOperation::ReleaseChild {
                    handle,
                    idempotency_key,
                } => self.release(handle, idempotency_key, parent_owner),
            }
            .unwrap_or_else(|_| refused(ActorRefusalCode::Unavailable))
        };
        ActorResponse {
            version: ActorProtocolVersion::V1,
            outcome,
        }
    }

    fn authenticate(
        &self,
        operation: LifecycleOperation,
        parent_owner: &ActorOwner,
    ) -> std::result::Result<(), ActorRefusalCode> {
        let now = Utc::now().timestamp_millis();
        let plan = self.host.parent.plan();
        let grant = self
            .host
            .parent
            .grant()
            .map_err(|_| ActorRefusalCode::NotBound)?;
        if now < plan.valid_from.timestamp_millis()
            || now >= plan.valid_until.timestamp_millis()
            || now < grant.not_before_unix_ms
            || now >= grant.expires_at_unix_ms
        {
            return Err(ActorRefusalCode::Expired);
        }
        grant
            .check_operation(operation, now)
            .map_err(|_| ActorRefusalCode::Unauthorized)?;
        self.host
            .parent
            .check(parent_owner, operation, now)
            .map_err(|_| ActorRefusalCode::StaleController)
    }

    /// Stop owned descendants before the controller process relinquishes root custody.
    ///
    /// This is a host containment action, not renewed guest delegation after expiry.
    /// Uncertain children retain their journals and budget holds and fail shutdown.
    pub fn shutdown_all(&mut self) -> Result<()> {
        let mut incomplete = self.cleanup_attempts().is_err();
        let records = {
            let _lock = self.host.journal.lock()?;
            self.host.journal.read()?
        };
        for error in self.failed_starts.values() {
            if let Some(failure) =
                error.downcast_ref::<mvm_runtime::actor_teardown::ActorStartFailure>()
            {
                // A retried rollback is not a terminal proof and releases no budget.
                let _ = failure.retry_stop();
            }
        }
        for record in &records.children {
            if record.parent != *self.host.parent.identity() {
                continue;
            }
            let key = record
                .release_request
                .clone()
                .unwrap_or(ActorBindingId::new(format!(
                    "cleanup-{}",
                    hex::encode(record.reservation.request_digest)
                ))?);
            match self.release_inner(&record.handle, &key, ReleaseAuthority::HostCleanup) {
                Ok(ActorOutcome::Released { .. }) => {}
                Ok(
                    ActorOutcome::Pending { .. }
                    | ActorOutcome::Running { .. }
                    | ActorOutcome::Refused { .. }
                    | ActorOutcome::Unknown { .. },
                )
                | Err(_) => incomplete = true,
            }
        }
        ensure!(
            !incomplete && self.failed_starts.is_empty(),
            "actor shutdown retains uncertain child custody"
        );
        Ok(())
    }

    fn launch(
        &mut self,
        request: &ActorRequest,
        grant_id: &ActorBindingId,
        template_id: &ActorBindingId,
        key: &ActorBindingId,
        parent_owner: &ActorOwner,
    ) -> Result<ActorOutcome> {
        let grant = self.host.parent.grant()?;
        if grant.id != *grant_id {
            return Ok(refused(ActorRefusalCode::Unauthorized));
        }
        let Some(binding) = grant
            .templates
            .iter()
            .find(|binding| binding.id == *template_id)
        else {
            return Ok(refused(ActorRefusalCode::UnknownTemplate));
        };
        let template = self.host.templates.resolve(binding)?;
        let identity = self.reservation_identity(request, template, key)?;
        let _lock = self.host.journal.lock()?;
        let mut records = self.host.journal.read()?;
        if let Some(attempt) = records.attempts.iter().find(|attempt| {
            attempt.reservation.tenant == identity.tenant
                && attempt.reservation.workflow == identity.workflow
                && attempt.request_id == *key
        }) {
            return Ok(if attempt.reservation != identity {
                refused(ActorRefusalCode::RequestConflict)
            } else if attempt.terminal_evidence_digest.is_some() {
                ActorOutcome::Released {
                    request_id: key.clone(),
                }
            } else {
                unknown(key)
            });
        }
        if records
            .children
            .iter()
            .any(|record| record.release_request.as_ref() == Some(key))
        {
            return Ok(refused(ActorRefusalCode::RequestConflict));
        }
        if let Some(record) = records.children.iter().find(|record| {
            record.reservation.tenant == identity.tenant
                && record.reservation.workflow == identity.workflow
                && record.request_id == *key
        }) {
            return Ok(if record.reservation == identity {
                self.outcome(record)
            } else {
                refused(ActorRefusalCode::RequestConflict)
            });
        }
        match self.host.reservations.observe(&identity) {
            Ok(_) => return Ok(unknown(key)),
            Err(crate::actor_reservations::ReservationError::NotFound) => {}
            Err(crate::actor_reservations::ReservationError::Conflict) => {
                return Ok(refused(ActorRefusalCode::RequestConflict));
            }
            Err(error) => return Err(error.into()),
        }
        let child_name = format!("actor-{}", hex::encode(rand::random::<[u8; 16]>()));
        ensure!(
            !records
                .children
                .iter()
                .any(|record| record.child_workload == child_name),
            "actor workload identity collision"
        );
        let definition = template.definition();
        let charge = crate::admission_budget::charge_for(
            definition.plan.resources.mem_mib,
            definition
                .plan
                .grants
                .as_ref()
                .unwrap_or(&Default::default()),
        );
        let host_permit = HostBudgetPermit::reserve(&child_name, charge)?;
        host_permit.bind_coordinator(&hex::encode(identity.request_digest))?;
        match self.host.reservations.reserve(
            ReservationRequest {
                identity: identity.clone(),
                resources: definition.charge,
            },
            self.host.constraints.ceilings,
        ) {
            Ok(ReserveOutcome::Existing(_)) => {
                host_permit.release_pre_dispatch()?;
                return Ok(unknown(key));
            }
            Ok(ReserveOutcome::Reserved(_)) => {}
            Err(error) => {
                host_permit.release_pre_dispatch()?;
                return Ok(refused(match error {
                    crate::actor_reservations::ReservationError::Exhausted => {
                        ActorRefusalCode::Capacity
                    }
                    crate::actor_reservations::ReservationError::Conflict => {
                        ActorRefusalCode::RequestConflict
                    }
                    crate::actor_reservations::ReservationError::Io(_)
                    | crate::actor_reservations::ReservationError::Lock(_)
                    | crate::actor_reservations::ReservationError::Corrupt
                    | crate::actor_reservations::ReservationError::NotFound => {
                        ActorRefusalCode::Unavailable
                    }
                }));
            }
        }
        // From here every interruption is retained intent, never permission to retry a boot.
        let mut owner = None;
        let mut entrypoint = None;
        let attempted = self.launch_reserved(
            ReservedLaunch {
                template,
                child_name: &child_name,
                identity,
                key,
                host_permit,
            },
            &mut records,
            &mut owner,
            parent_owner,
            &mut entrypoint,
        );
        if let Some(reader) = entrypoint {
            self.entrypoints.insert(child_name.clone(), reader);
        }
        let has_owner = owner.is_some();
        if let Some(owner) = owner {
            self.owners.insert(child_name.clone(), owner);
        }
        match attempted {
            Ok(outcome) => Ok(outcome),
            Err(error) => {
                if !has_owner {
                    self.failed_starts.insert(child_name, error);
                }
                Ok(unknown(key))
            }
        }
    }

    fn launch_reserved(
        &self,
        reserved: ReservedLaunch<'_>,
        records: &mut Records,
        owner: &mut Option<ActorOwner>,
        parent_owner: &ActorOwner,
        entrypoint: &mut Option<EntrypointReader>,
    ) -> Result<ActorOutcome> {
        let ReservedLaunch {
            template,
            child_name,
            identity,
            key,
            host_permit,
        } = reserved;
        let mut child = template.definition().plan.clone();
        child.workload = WorkloadId(child_name.to_owned());
        child.image.name = child_name.to_owned();
        child.execution_epoch = 1;
        let attempt = AttemptRecord {
            parent: self.host.parent.identity().clone(),
            request_id: key.clone(),
            reservation: identity.clone(),
            host_reservation: host_permit.id().to_owned(),
            child: child.clone(),
            mailbox_preparing: false,
            terminal_evidence_digest: None,
        };
        self.pending_attempts
            .borrow_mut()
            .insert(child_name.to_owned(), attempt.clone());
        records.attempts.push(attempt);
        self.host.journal.write(records)?;
        self.pending_attempts.borrow_mut().remove(child_name);
        child.nonce = Nonce::from_bytes(rand::random());
        child.valid_from = child.valid_from.max(self.host.parent.plan().valid_from);
        child.valid_until = child.valid_until.min(self.host.parent.plan().valid_until);
        let grant_expiry =
            chrono::DateTime::from_timestamp_millis(self.host.parent.grant()?.expires_at_unix_ms)
                .ok_or_else(|| anyhow::anyhow!("invalid actor grant expiry"))?;
        child.valid_until = child.valid_until.min(grant_expiry);
        let mut workflow = self
            .host
            .parent
            .plan()
            .workflow
            .clone()
            .ok_or_else(|| anyhow::anyhow!("controller membership missing"))?;
        workflow.role = WorkflowRole::Worker {
            parent: self.host.parent.identity().clone(),
        };
        child.workflow = Some(workflow);
        records
            .attempts
            .last_mut()
            .ok_or_else(|| anyhow::anyhow!("actor attempt missing"))?
            .child = child.clone();
        self.host.journal.write(records)?;
        self.host.emitter.emit(
            self.host.parent.plan(),
            "actor.launch.intent",
            [
                (
                    "request_digest".into(),
                    hex::encode(identity.request_digest),
                ),
                (
                    "template_digest".into(),
                    hex::encode(identity.template_digest),
                ),
            ],
        )?;
        records
            .attempts
            .last_mut()
            .ok_or_else(|| anyhow::anyhow!("actor attempt missing"))?
            .mailbox_preparing = true;
        self.host.journal.write(records)?;
        let mailbox = self
            .host
            .mailboxes
            .derive(self.host.parent.plan(), &child)?;
        let template_grant = child
            .mailbox
            .ok_or_else(|| anyhow::anyhow!("actor mailbox template missing"))?;
        ensure!(
            mailbox.grant.epoch.get() == 1
                && mailbox.grant.mailbox != template_grant.mailbox
                && mailbox.grant.report == template_grant.report
                && mailbox.grant.retention == template_grant.retention,
            "derived mailbox widened exact template"
        );
        child.mailbox = Some(mailbox.grant);
        child.plan_id = compute_plan_id(&child);
        self.validate_child(template, &child, &mailbox)?;
        self.host
            .mailboxes
            .verify_current(self.host.parent.plan(), &mailbox)?;
        let mut config = template.config(&child)?;
        config.mailbox_conversation =
            Some(mvm_core::mailbox::conversation_wire::ConversationTarget {
                address: mailbox.address,
                policy_epoch: self.host.constraints.mailbox_policy.policy_epoch,
            });
        let record = ChildRecord {
            parent: self.host.parent.identity().clone(),
            request_id: key.clone(),
            reservation: identity.clone(),
            host_reservation: host_permit.id().to_owned(),
            child_workload: child_name.to_owned(),
            handle: ActorHandle {
                token: ActorToken::from_bytes(rand::random()),
                mailbox: mailbox.address,
            },
            mailbox,
            child_plan_digest: None,
            teardown: None,
            terminal_evidence_digest: None,
            state: ChildState::Pending,
            release_request: None,
        };
        records
            .attempts
            .retain(|attempt| attempt.reservation != identity);
        records.children.push(record);
        self.host.journal.write(records)?;
        let admitted = admit_plan_for_run_with_host_permit(HostPermitAdmission {
            plan: &child,
            clock: &SystemClock,
            ledger: &self.nonces,
            host_signer_keys_dir: Some(&self.host.signer_keys_dir),
            bundle_ctx: None,
            extension_ctx: None,
            posture: RunPosture::on_backend(self.host.variant, self.host.backend.kind())
                .with_runtime(Some(&config)),
            host_permit,
        })?;
        self.host
            .emitter
            .emit_admitted(admitted.plan(), admitted.signer_id())?;
        let digest = hash(admitted.signed())?;
        self.host.reservations.mark_prepared(&identity, digest)?;
        let record = records
            .children
            .last_mut()
            .ok_or_else(|| anyhow::anyhow!("actor record missing"))?;
        record.child_plan_digest = Some(digest);
        record.state = ChildState::Prepared;
        self.host.journal.write(records)?;
        self.host.parent.check(
            parent_owner,
            LifecycleOperation::Launch,
            Utc::now().timestamp_millis(),
        )?;
        self.host.mailboxes.verify_current(
            self.host.parent.plan(),
            &records
                .children
                .last()
                .ok_or_else(|| anyhow::anyhow!("actor record missing"))?
                .mailbox,
        )?;
        records
            .children
            .last_mut()
            .ok_or_else(|| anyhow::anyhow!("actor record missing"))?
            .state = ChildState::Dispatching;
        self.host.journal.write(records)?;
        let started = start_admitted_owned_actor(
            StartAdmittedParams {
                backend: &self.host.backend,
                admitted,
                config,
                policy_bundle: None,
                emitter: Some(&self.host.emitter),
                assurance: None,
            },
            owner,
            || {
                self.host.parent.check(
                    parent_owner,
                    LifecycleOperation::Launch,
                    Utc::now().timestamp_millis(),
                )?;
                self.host.mailboxes.verify_current(
                    self.host.parent.plan(),
                    &records
                        .children
                        .last()
                        .ok_or_else(|| anyhow::anyhow!("actor record missing"))?
                        .mailbox,
                )
            },
        );
        if let Some(owner) = owner.as_mut() {
            let index = records
                .children
                .len()
                .checked_sub(1)
                .ok_or_else(|| anyhow::anyhow!("actor record missing"))?;
            persist_original_custody(records, index, owner, |records| {
                self.host.journal.write(records)
            })?;
        }
        let started = match started {
            Ok(started) => started,
            Err(error) => {
                let record = records
                    .children
                    .last_mut()
                    .ok_or_else(|| anyhow::anyhow!("actor record missing"))?;
                if owner.is_none() && record_runtime_no_dispatch(&error, record) {
                    self.host.journal.write(records)?;
                }
                if let Some(owner) = owner {
                    let _ = owner.stop_and_reap();
                }
                return Err(error);
            }
        };
        ensure!(
            started.vm_id.0 == child_name && owner.is_some(),
            "actor launch lost original custody"
        );
        if let Some(owner) = owner.as_mut()
            && let Err(error) = owner.verify_resource_envelope(&template.definition().charge)
        {
            let _ = owner.stop_and_reap();
            return Err(error);
        }
        let original = owner
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("actor launch lost original custody"))?;
        let dispatched = (|| {
            self.host.parent.check(
                parent_owner,
                LifecycleOperation::Launch,
                Utc::now().timestamp_millis(),
            )?;
            self.host.emitter.emit(
                self.host.parent.plan(),
                "actor.entrypoint.intent",
                [(
                    "request_digest".into(),
                    hex::encode(identity.request_digest),
                )],
            )?;
            let plan = started.admitted.plan();
            let mut timeout = plan
                .valid_until
                .signed_duration_since(Utc::now())
                .to_std()?;
            if plan.resources.timeouts.exec_secs != 0 {
                timeout = timeout.min(std::time::Duration::from_secs(u64::from(
                    plan.resources.timeouts.exec_secs,
                )));
            }
            ensure!(!timeout.is_zero(), "actor entrypoint validity expired");
            let deadline = std::time::Instant::now()
                .checked_add(timeout)
                .ok_or_else(|| anyhow::anyhow!("actor entrypoint deadline overflow"))?;
            let running = original.dispatch_entrypoint(deadline)?;
            let cancel = running.cancellation_handle()?;
            let thread = std::thread::Builder::new()
                .name("actor-entrypoint".into())
                .spawn(move || {
                    #[cfg(feature = "hvf-live-validation")]
                    let mut reported = 0u16;
                    let terminal = running.wait(|_event| {
                        #[cfg(feature = "hvf-live-validation")]
                        match _event {
                            mvm_agentd::vsock::EntrypointEvent::Stderr { chunk } => {
                                for (index, marker) in [
                                    "ACTOR_CHILD_STAGE_RECEIVE",
                                    "ACTOR_CHILD_STAGE_REPLY",
                                    "ACTOR_CHILD_STAGE_ACK_REQUEST",
                                    "ACTOR_CHILD_STAGE_ACKNOWLEDGED",
                                    "ACTOR_CHILD_REFUSAL_NOT_AUTHORIZED",
                                    "ACTOR_CHILD_REFUSAL_UNAVAILABLE",
                                    "ACTOR_CHILD_REFUSAL_EXPIRED",
                                    "ACTOR_CHILD_REFUSAL_MALFORMED",
                                    "ACTOR_CHILD_REFUSAL_STORAGE_FULL",
                                    "ACTOR_CHILD_REFUSAL_QUEUE_FULL",
                                    "ACTOR_CHILD_REFUSAL_RETRIES_EXHAUSTED",
                                    "ACTOR_CHILD_REFUSAL_OTHER",
                                ]
                                .into_iter()
                                .enumerate()
                                {
                                    if reported & (1 << index) == 0
                                        && chunk
                                            .windows(marker.len())
                                            .any(|bytes| bytes == marker.as_bytes())
                                    {
                                        reported |= 1 << index;
                                        eprintln!("{marker}");
                                    }
                                }
                            }
                            mvm_agentd::vsock::EntrypointEvent::Exit { code } if *code != 0 => {
                                eprintln!("ACTOR_CHILD_EXIT_FAILED");
                            }
                            _ => {}
                        }
                    });
                    #[cfg(feature = "hvf-live-validation")]
                    if terminal.is_err() {
                        eprintln!("ACTOR_CHILD_ENTRYPOINT_TRANSPORT_FAILED");
                    }
                    terminal.map(|_| ())
                })?;
            Ok(EntrypointReader {
                cancel,
                thread: Some(thread),
                terminal_observed: None,
            })
        })();
        match dispatched {
            Ok(reader) => *entrypoint = Some(reader),
            Err(error) => {
                let _ = original.stop_and_reap();
                return Err(error);
            }
        }
        if let Err(error) = self.host.emitter.emit(
            self.host.parent.plan(),
            "actor.launch.running",
            [
                (
                    "request_digest".into(),
                    hex::encode(identity.request_digest),
                ),
                ("child_plan_digest".into(), hex::encode(digest)),
            ],
        ) {
            if let Some(owner) = owner {
                let _ = owner.stop_and_reap();
            }
            return Err(error);
        }
        if let Err(error) = self.host.reservations.mark_running(&identity, digest) {
            if let Some(owner) = owner.as_mut() {
                let _ = owner.stop_and_reap();
            }
            return Err(error.into());
        }
        let record = records
            .children
            .last_mut()
            .ok_or_else(|| anyhow::anyhow!("actor record missing"))?;
        record.state = ChildState::Running;
        let handle = record.handle.clone();
        if let Err(error) = self.host.journal.write(records) {
            if let Some(owner) = owner.as_mut() {
                let _ = owner.stop_and_reap();
            }
            return Err(error);
        }
        Ok(ActorOutcome::Running { handle })
    }

    fn validate_child(
        &self,
        template: &ActorTemplate,
        child: &ExecutionPlan,
        mailbox: &super::DerivedChildMailbox,
    ) -> Result<()> {
        mailbox.validate(|mailbox| {
            Self::validate_authority(&self.host, template, child, Some(mailbox))
        })
    }

    fn validate_authority(
        host: &ActorLifecycleInputs,
        template: &ActorTemplate,
        child: &ExecutionPlan,
        mailbox: Option<MailboxDerivation<'_>>,
    ) -> Result<()> {
        let constraints = &host.constraints;
        let definition = template.definition();
        let parent_digest = hash(&(&constraints.network, &constraints.effective_policy))?;
        let child_digest = hash(&(
            &definition.launch.network_policy,
            &definition.effective_policy,
        ))?;
        validate_child_authority(
            host.parent.plan(),
            child,
            &ChildAuthorityContext {
                resource_ceiling: &constraints.child_resources,
                parent_policy: PolicyMaterial {
                    resolved_digest: parent_digest,
                    network: &constraints.network,
                    effective: &constraints.effective_policy,
                    capabilities: &constraints.capabilities,
                },
                child_policy: PolicyMaterial {
                    resolved_digest: child_digest,
                    network: &definition.launch.network_policy,
                    effective: &definition.effective_policy,
                    capabilities: &definition.capabilities,
                },
                mailbox,
            },
        )?;
        Ok(())
    }

    fn reservation_identity(
        &self,
        request: &ActorRequest,
        template: &ActorTemplate,
        key: &ActorBindingId,
    ) -> Result<ReservationIdentity> {
        let parent = self.host.parent.identity();
        let membership = self
            .host
            .parent
            .plan()
            .workflow
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("controller membership missing"))?;
        Ok(ReservationIdentity {
            tenant: hash(&parent.controller.tenant)?,
            workflow: hash(&membership.workflow_id)?,
            controller: hash(&parent.controller)?,
            controller_generation: parent.controller.generation.get(),
            idempotency_key: hash(key)?,
            template_digest: hex::decode(
                template
                    .binding()
                    .digest
                    .as_str()
                    .strip_prefix("sha256:")
                    .ok_or_else(|| anyhow::anyhow!("invalid template digest"))?,
            )?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid template digest length"))?,
            parent_plan_digest: hash(&parent.plan_id)?,
            request_digest: hash(&(parent, template.binding(), request))?,
        })
    }

    fn observe(&self, handle: &ActorHandle) -> Result<ActorOutcome> {
        let _lock = self.host.journal.lock()?;
        let records = self.host.journal.read()?;
        let Some(record) = self.find_handle(&records, handle) else {
            return Ok(refused(ActorRefusalCode::Unauthorized));
        };
        Ok(self.outcome(record))
    }

    fn find_handle<'a>(
        &self,
        records: &'a Records,
        handle: &ActorHandle,
    ) -> Option<&'a ChildRecord> {
        records
            .children
            .iter()
            .find(|record| record.matches_handle(self.host.parent.identity(), handle))
    }

    fn outcome(&self, record: &ChildRecord) -> ActorOutcome {
        match record.state {
            ChildState::Terminal | ChildState::Cancelled => ActorOutcome::Released {
                request_id: record
                    .release_request
                    .as_ref()
                    .unwrap_or(&record.request_id)
                    .clone(),
            },
            ChildState::Running
                if self
                    .owners
                    .get(&record.child_workload)
                    .is_some_and(|owner| owner.is_running().unwrap_or(false)) =>
            {
                ActorOutcome::Running {
                    handle: record.handle.clone(),
                }
            }
            ChildState::Pending
            | ChildState::Prepared
            | ChildState::Dispatching
            | ChildState::Running
            | ChildState::Stopping
            | ChildState::Cancelling => unknown(&record.request_id),
        }
    }

    fn release(
        &mut self,
        handle: &ActorHandle,
        key: &ActorBindingId,
        parent_owner: &ActorOwner,
    ) -> Result<ActorOutcome> {
        self.release_inner(handle, key, ReleaseAuthority::Controller(parent_owner))
    }

    fn release_inner(
        &mut self,
        handle: &ActorHandle,
        key: &ActorBindingId,
        authority: ReleaseAuthority<'_>,
    ) -> Result<ActorOutcome> {
        let _lock = self.host.journal.lock()?;
        let mut records = self.host.journal.read()?;
        if records.children.iter().any(|record| {
            record.request_id == *key
                || (record.release_request.as_ref() == Some(key) && record.handle != *handle)
        }) {
            return Ok(refused(ActorRefusalCode::RequestConflict));
        }
        let Some(index) = records
            .children
            .iter()
            .position(|record| record.matches_handle(self.host.parent.identity(), handle))
        else {
            return Ok(refused(ActorRefusalCode::Unauthorized));
        };
        let record = &mut records.children[index];
        if record
            .release_request
            .as_ref()
            .is_some_and(|old| old != key)
        {
            return Ok(refused(ActorRefusalCode::RequestConflict));
        }
        if matches!(record.state, ChildState::Terminal | ChildState::Cancelled) {
            self.refund_terminal(record)?;
            let outcome = self.outcome(record);
            self.failed_starts.remove(&record.child_workload);
            self.owners.remove(&record.child_workload);
            self.entrypoints.remove(&record.child_workload);
            return Ok(outcome);
        }
        record.begin_release(key);
        self.host.journal.write(&records)?;
        if let Some(owner) = self.owners.get_mut(&records.children[index].child_workload) {
            persist_original_custody(&mut records, index, owner, |records| {
                self.host.journal.write(records)
            })?;
        }
        let record = &records.children[index];
        let result = (|| -> Result<[u8; 32]> {
            self.host.emitter.emit(
                self.host.parent.plan(),
                "actor.release.intent",
                [(
                    "request_digest".into(),
                    hex::encode(record.reservation.request_digest),
                )],
            )?;
            if let ReleaseAuthority::Controller(parent_owner) = authority {
                self.host.parent.check(
                    parent_owner,
                    LifecycleOperation::ReleaseChild,
                    Utc::now().timestamp_millis(),
                )?;
            }
            let evidence_digest = if record.state == ChildState::Cancelling {
                ensure!(
                    !self.owners.contains_key(&record.child_workload)
                        && !self
                            .failed_starts
                            .get(&record.child_workload)
                            .is_some_and(|error| {
                                error
                                    .downcast_ref::<mvm_runtime::actor_teardown::ActorStartFailure>(
                                    )
                                    .is_some()
                                    && !runtime_no_dispatch_matches(error, record)
                            }),
                    "never-dispatched cleanup has uncertain native custody"
                );
                if let Some(proof) = self
                    .failed_starts
                    .get(&record.child_workload)
                    .and_then(|error| {
                        error.downcast_ref::<mvm_runtime::actor_teardown::ActorStartFailure>()
                    })
                    .and_then(|failure| failure.no_dispatch_proof())
                {
                    let signed = proof
                        .signed_plan_for(&record.child_workload)
                        .ok_or_else(|| anyhow::anyhow!("original signed attempt absent"))?;
                    let plan =
                        mvm_core::plan::plan_from_admitted_json(&serde_json::to_string(signed)?)?;
                    HostBudgetPermit::reopen(
                        &record.host_reservation,
                        &hex::encode(record.reservation.request_digest),
                    )?
                    .record_runtime_no_dispatch(
                        proof,
                        &record.child_workload,
                        &plan,
                        &self.host.emitter,
                    )?;
                }
                hash(&(record.reservation.request_digest, "never_dispatched"))?
            } else {
                if !self.owners.contains_key(&record.child_workload)
                    && let Some(error) = self.failed_starts.get(&record.child_workload)
                    && let Some(failure) =
                        error.downcast_ref::<mvm_runtime::actor_teardown::ActorStartFailure>()
                {
                    let _ = failure.retry_stop();
                }
                let owner = self
                    .owners
                    .get_mut(&record.child_workload)
                    .ok_or_else(|| anyhow::anyhow!("original actor custody unavailable"))?;
                let terminal_proof = owner.stop_and_reap()?;
                if let Some(reader) = self.entrypoints.get_mut(&record.child_workload) {
                    let observation = reader.finish()?;
                    self.host.emitter.emit(
                        self.host.parent.plan(),
                        "actor.entrypoint.observed",
                        [
                            (
                                "request_digest".into(),
                                hex::encode(record.reservation.request_digest),
                            ),
                            ("observation".into(), observation.into()),
                        ],
                    )?;
                }
                let evidence_digest = hash(terminal_proof.journal())?;
                ensure!(
                    record
                        .teardown
                        .as_ref()
                        .is_some_and(|captured| hash(captured).ok() == Some(evidence_digest)),
                    "terminal proof differs from original actor custody"
                );
                evidence_digest
            };
            self.host.mailboxes.reap(&record.mailbox)?;
            self.host.emitter.emit(
                self.host.parent.plan(),
                "actor.release.terminal",
                [
                    (
                        "request_digest".into(),
                        hex::encode(record.reservation.request_digest),
                    ),
                    ("teardown_digest".into(), hex::encode(evidence_digest)),
                    (
                        "cleanup_class".into(),
                        if record.state == ChildState::Cancelling {
                            "never_dispatched".into()
                        } else {
                            "original_owner".into()
                        },
                    ),
                ],
            )?;
            Ok(evidence_digest)
        })();
        let Ok(evidence_digest) = result else {
            return Ok(unknown(key));
        };
        records.children[index].state = if records.children[index].state == ChildState::Cancelling {
            ChildState::Cancelled
        } else {
            ChildState::Terminal
        };
        records.children[index].terminal_evidence_digest = Some(evidence_digest);
        self.host.journal.write(&records)?;
        let record = &records.children[index];
        self.refund_terminal(record)?;
        self.owners.remove(&record.child_workload);
        self.failed_starts.remove(&record.child_workload);
        self.entrypoints.remove(&record.child_workload);
        Ok(ActorOutcome::Released {
            request_id: key.clone(),
        })
    }

    fn cleanup_attempts(&mut self) -> Result<()> {
        let _lock = self.host.journal.lock()?;
        let mut records = self.host.journal.read()?;
        for attempt in self.pending_attempts.borrow().values() {
            restore_pending_attempt(&mut records, attempt, |records| {
                self.host.journal.write(records)
            })?;
        }
        self.pending_attempts.borrow_mut().clear();
        for index in 0..records.attempts.len() {
            let attempt = &records.attempts[index];
            if attempt.parent != *self.host.parent.identity() {
                continue;
            }
            let digest = if let Some(digest) = attempt.terminal_evidence_digest {
                digest
            } else {
                ensure!(
                    !self.owners.contains_key(&attempt.child.workload.0)
                        && !self
                            .failed_starts
                            .get(&attempt.child.workload.0)
                            .is_some_and(|error| error
                                .downcast_ref::<mvm_runtime::actor_teardown::ActorStartFailure>()
                                .is_some()),
                    "preparation attempt unexpectedly owns native custody"
                );
                self.host.emitter.emit(
                    self.host.parent.plan(),
                    "actor.prepare.cleanup.intent",
                    [(
                        "request_digest".into(),
                        hex::encode(attempt.reservation.request_digest),
                    )],
                )?;
                if attempt.mailbox_preparing {
                    self.host
                        .mailboxes
                        .reap_attempt(self.host.parent.plan(), &attempt.child)?;
                }
                let digest = hash(&(attempt.reservation.request_digest, "preparation_cancelled"))?;
                self.host.emitter.emit(
                    self.host.parent.plan(),
                    "actor.prepare.cleanup.terminal",
                    [(
                        "request_digest".into(),
                        hex::encode(attempt.reservation.request_digest),
                    )],
                )?;
                records.attempts[index].terminal_evidence_digest = Some(digest);
                self.host.journal.write(&records)?;
                digest
            };
            let attempt = &records.attempts[index];
            HostBudgetPermit::reopen(
                &attempt.host_reservation,
                &hex::encode(attempt.reservation.request_digest),
            )?
            .reconcile_never_dispatched(&hex::encode(digest))?;
            self.host
                .reservations
                .reconcile_terminal(&attempt.reservation, digest)?;
            self.failed_starts.remove(&attempt.child.workload.0);
        }
        Ok(())
    }

    fn refund_terminal(&self, record: &ChildRecord) -> Result<()> {
        ensure!(
            matches!(record.state, ChildState::Terminal | ChildState::Cancelled)
                && record.terminal_evidence_digest.is_some(),
            "actor cleanup is not terminal"
        );
        let result_digest = hash(&(
            record.reservation.request_digest,
            record.terminal_evidence_digest,
            "released",
        ))?;
        let permit = HostBudgetPermit::reopen(
            &record.host_reservation,
            &hex::encode(record.reservation.request_digest),
        )?;
        if record.state == ChildState::Cancelled {
            permit.reconcile_never_dispatched(&hex::encode(result_digest))?;
        } else {
            permit.reconcile_terminal(&hex::encode(result_digest))?;
        }
        self.host
            .reservations
            .reconcile_terminal(&record.reservation, result_digest)?;
        Ok(())
    }
}

fn record_runtime_no_dispatch(error: &anyhow::Error, record: &mut ChildRecord) -> bool {
    if record.state != ChildState::Dispatching
        || record.teardown.is_some()
        || !runtime_no_dispatch_matches(error, record)
    {
        return false;
    }
    record.state = ChildState::Cancelling;
    true
}

fn runtime_no_dispatch_matches(error: &anyhow::Error, record: &ChildRecord) -> bool {
    error
        .downcast_ref::<mvm_runtime::actor_teardown::ActorStartFailure>()
        .and_then(|failure| failure.no_dispatch_proof())
        .and_then(|proof| proof.signed_plan_for(&record.child_workload))
        .is_some_and(|signed| {
            record.child_plan_digest.is_some() && hash(signed).ok() == record.child_plan_digest
        })
}

fn restore_pending_attempt(
    records: &mut Records,
    pending: &AttemptRecord,
    persist: impl FnOnce(&Records) -> Result<()>,
) -> Result<()> {
    if let Some(existing) = records.attempts.iter().find(|attempt| {
        attempt.child.workload == pending.child.workload
            || attempt.reservation == pending.reservation
    }) {
        ensure!(
            existing == pending,
            "uncertain actor attempt differs from retained original"
        );
        return Ok(());
    }
    ensure!(
        !records
            .children
            .iter()
            .any(|child| child.child_workload == pending.child.workload.0
                || child.reservation == pending.reservation),
        "uncertain actor attempt conflicts with child receipt"
    );
    records.attempts.push(pending.clone());
    persist(records)
}

fn persist_original_custody(
    records: &mut Records,
    index: usize,
    owner: &mut ActorOwner,
    persist: impl FnOnce(&Records) -> Result<()>,
) -> Result<()> {
    let outcome = (|| {
        let record = records
            .children
            .get_mut(index)
            .ok_or_else(|| anyhow::anyhow!("actor record missing"))?;
        let original = owner.journal();
        if let Some(captured) = &record.teardown {
            ensure!(
                hash(captured)? == hash(&original)?,
                "original actor custody changed"
            );
        } else {
            record.teardown = Some(original);
        }
        persist(records)
    })();
    if outcome.is_err() {
        let _ = owner.stop_and_reap();
    }
    outcome
}

fn hash(value: &impl Serialize) -> Result<[u8; 32]> {
    Ok(Sha256::digest(serde_jcs::to_vec(value)?).into())
}

fn refused(code: ActorRefusalCode) -> ActorOutcome {
    ActorOutcome::Refused { code }
}
fn unknown(key: &ActorBindingId) -> ActorOutcome {
    ActorOutcome::Unknown {
        request_id: key.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct InterruptedMailboxes {
        real: super::super::local_mailboxes::LocalActorMailboxes,
        fail_derive: AtomicBool,
        fail_cleanup: AtomicBool,
        derives: AtomicUsize,
    }

    impl ActorMailboxes for InterruptedMailboxes {
        fn derive(
            &self,
            parent: &ExecutionPlan,
            child: &ExecutionPlan,
        ) -> Result<super::super::DerivedChildMailbox> {
            self.derives.fetch_add(1, Ordering::SeqCst);
            let derived = self.real.derive(parent, child)?;
            ensure!(
                !self.fail_derive.load(Ordering::SeqCst),
                "injected failure after real mailbox preparation"
            );
            Ok(derived)
        }
        fn verify_current(
            &self,
            parent: &ExecutionPlan,
            child: &super::super::DerivedChildMailbox,
        ) -> Result<()> {
            self.real.verify_current(parent, child)
        }
        fn reap(&self, child: &super::super::DerivedChildMailbox) -> Result<()> {
            self.real.reap(child)
        }
        fn reap_attempt(&self, parent: &ExecutionPlan, child: &ExecutionPlan) -> Result<()> {
            ensure!(
                !self.fail_cleanup.load(Ordering::SeqCst),
                "injected cleanup unavailable"
            );
            self.real.reap_attempt(parent, child)
        }
    }

    fn interrupted_fixture(
        home: &std::path::Path,
    ) -> (
        ActorLifecycle,
        ActorOwner,
        Arc<InterruptedMailboxes>,
        ActorRequest,
        PathBuf,
    ) {
        let mut authored = crate::actor_bootstrap::tests::authored();
        authored.launch.kernel_path = None;
        for template in &mut authored.templates {
            template.definition.launch.kernel_path = None;
        }
        mvm_core::user_config::save(
            &mvm_core::user_config::MvmConfig {
                host_budget_memory_mib: Some(4096),
                host_budget_cpu_millicores: Some(8000),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let bootstrap = authored.provision().unwrap();
        let keys = mvm_core::config::mvm_keys_dir();
        let mailboxes = Arc::new(InterruptedMailboxes {
            real: super::super::local_mailboxes::LocalActorMailboxes::new(
                keys.clone(),
                bootstrap.constraints.mailbox_policy.clone(),
                hash(&bootstrap.constraints).unwrap(),
            )
            .unwrap(),
            fail_derive: AtomicBool::new(false),
            fail_cleanup: AtomicBool::new(false),
            derives: AtomicUsize::new(0),
        });
        let backend = AnyBackend::from_hypervisor("mock");
        // Only the parent identity is a fixture. The tested child path still goes
        // through the production coordinator, reservations, audit and mailbox owner.
        let owner = backend
            .start_owned_actor(
                &mvm_core::vm_backend::VmStartConfig {
                    name: bootstrap.parent.workload.0.clone(),
                    cpus: 1,
                    memory_mib: 128,
                    ..Default::default()
                },
                None,
            )
            .unwrap();
        let material =
            mvm_vmm::host::actor_identity::ActorBootMaterial::for_plan(&bootstrap.parent)
                .unwrap()
                .unwrap();
        let signer = crate::audit::host_keypair::load_or_init_at(&keys).unwrap();
        let signed = mvm_core::plan::sign_plan(&bootstrap.parent, &signer.signing, "host:fixture");
        let started = crate::plan_admission::StartedMachine {
            vm_id: owner.vm_id().clone(),
            admitted: crate::plan_admission::AdmittedPlan::for_test(
                bootstrap.parent,
                "host:fixture".into(),
                signed,
            ),
            enforced_grants:
                mvm_contract::protocol::resource_controls::EnforcedGrants::all_declared(),
        };
        let parent =
            ParentActivation::activate(&started, material.binding().clone(), &home.join("active"))
                .unwrap();
        let grant = parent.grant().unwrap();
        let request = ActorRequest {
            version: ActorProtocolVersion::V1,
            operation: ActorOperation::Launch {
                grant_id: grant.id.clone(),
                template_id: grant.templates[0].id.clone(),
                idempotency_key: ActorBindingId::new("interrupted-launch").unwrap(),
            },
        };
        let audit = home.join("audit");
        let emitter = AuditEmitter::with_dir(signer.signing, &audit).unwrap();
        let templates = bootstrap
            .templates
            .into_iter()
            .map(|template| ActorTemplate::new(template.id, template.definition).unwrap())
            .collect();
        let engine = ActorLifecycle::new(
            ActorLifecycleInputs {
                parent,
                templates: ExactTemplateCatalog::new(templates).unwrap(),
                journal: ActorJournal::create(
                    &home.join("journal"),
                    mvm_core::crypto::aead::Key::random(),
                )
                .unwrap(),
                reservations: ActorReservations::create(
                    &home.join("reservations"),
                    bootstrap.host_budget,
                )
                .unwrap(),
                constraints: bootstrap.constraints,
                backend,
                mailboxes: mailboxes.clone(),
                emitter,
                signer_keys_dir: keys,
                variant: Variant::Dev,
            },
            &owner,
        )
        .unwrap();
        let audit_file =
            crate::audit::emitter::audit_path_for_tenant(&audit, &started.admitted.plan().tenant.0);
        (engine, owner, mailboxes, request, audit_file)
    }

    #[test]
    fn first_attempt_write_failure_recovers_exact_retained_attempt_without_redispatch() {
        for committed in [false, true] {
            let home = tempfile::tempdir().unwrap();
            let mut env = mvm_core::util::test_env::TestEnv::new();
            env.isolate_mvm_home(home.path());
            let (mut engine, mut parent, mailboxes, request, _) = interrupted_fixture(home.path());
            engine.host.journal.fail_next_write(committed);
            assert!(matches!(
                engine.handle(request.clone(), &parent).outcome,
                ActorOutcome::Unknown { .. }
            ));
            let pending = engine
                .pending_attempts
                .borrow()
                .values()
                .next()
                .unwrap()
                .clone();
            assert_eq!(
                engine.host.journal.read().unwrap().attempts.len(),
                usize::from(committed)
            );
            assert_eq!(mailboxes.derives.load(Ordering::SeqCst), 0);
            assert_eq!(
                engine
                    .host
                    .reservations
                    .observe(&pending.reservation)
                    .unwrap()
                    .state,
                crate::actor_reservations::ReservationState::Pending
            );
            assert!(matches!(
                engine.handle(request.clone(), &parent).outcome,
                ActorOutcome::Unknown { .. }
            ));
            engine.shutdown_all().unwrap();
            engine.shutdown_all().unwrap();
            assert!(engine.pending_attempts.borrow().is_empty() && engine.failed_starts.is_empty());
            let records = engine.host.journal.read().unwrap();
            assert_eq!(
                records.attempts.len(),
                1,
                "uncertain commit never appends a duplicate"
            );
            assert!(records.attempts[0].terminal_evidence_digest.is_some());
            assert!(matches!(
                engine
                    .host
                    .reservations
                    .observe(&pending.reservation)
                    .unwrap()
                    .state,
                crate::actor_reservations::ReservationState::Terminal { .. }
            ));
            assert!(
                HostBudgetPermit::reopen(
                    &pending.host_reservation,
                    &hex::encode(pending.reservation.request_digest)
                )
                .unwrap()
                .release_pre_dispatch()
                .is_err()
            );
            assert!(matches!(
                engine.handle(request, &parent).outcome,
                ActorOutcome::Released { .. }
            ));
            assert_eq!(mailboxes.derives.load(Ordering::SeqCst), 0);
            assert!(engine.owners.is_empty());
            let _proof = parent.stop_and_reap().unwrap();
        }
    }

    #[test]
    fn intent_audit_failure_is_durable_and_cleanup_does_not_dispatch() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let (mut engine, mut parent, mailboxes, request, audit_file) =
            interrupted_fixture(home.path());
        std::fs::create_dir(&audit_file).unwrap();
        assert!(matches!(
            engine.handle(request.clone(), &parent).outcome,
            ActorOutcome::Unknown { .. }
        ));
        let records = engine.host.journal.read().unwrap();
        assert_eq!(records.attempts.len(), 1);
        assert!(!records.attempts[0].mailbox_preparing);
        assert!(
            engine.shutdown_all().is_err(),
            "failed audit cannot release holds"
        );
        assert_eq!(
            engine
                .host
                .reservations
                .observe(&records.attempts[0].reservation)
                .unwrap()
                .state,
            crate::actor_reservations::ReservationState::Pending
        );
        std::fs::remove_dir(&audit_file).unwrap();
        engine.shutdown_all().unwrap();
        assert!(
            HostBudgetPermit::reopen(
                &records.attempts[0].host_reservation,
                &hex::encode(records.attempts[0].reservation.request_digest),
            )
            .unwrap()
            .release_pre_dispatch()
            .is_err(),
            "cleanup leaves a terminal hold tombstone, not a prepared hold"
        );
        assert!(matches!(
            engine.handle(request, &parent).outcome,
            ActorOutcome::Released { .. }
        ));
        assert_eq!(mailboxes.derives.load(Ordering::SeqCst), 0);
        assert!(engine.owners.is_empty());
        assert!(engine.failed_starts.is_empty());
        let _proof = parent.stop_and_reap().unwrap();
    }

    #[test]
    fn partial_real_mailbox_failure_retries_cleanup_not_preparation() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let (mut engine, mut parent, mailboxes, request, _) = interrupted_fixture(home.path());
        mailboxes.fail_derive.store(true, Ordering::SeqCst);
        mailboxes.fail_cleanup.store(true, Ordering::SeqCst);
        assert!(matches!(
            engine.handle(request.clone(), &parent).outcome,
            ActorOutcome::Unknown { .. }
        ));
        let records = engine.host.journal.read().unwrap();
        assert!(records.attempts[0].mailbox_preparing);
        assert!(engine.shutdown_all().is_err());
        assert!(matches!(
            engine.handle(request.clone(), &parent).outcome,
            ActorOutcome::Unknown { .. }
        ));
        assert_eq!(mailboxes.derives.load(Ordering::SeqCst), 1);
        assert_eq!(
            engine
                .host
                .reservations
                .observe(&records.attempts[0].reservation)
                .unwrap()
                .state,
            crate::actor_reservations::ReservationState::Pending
        );
        mailboxes.fail_derive.store(false, Ordering::SeqCst);
        mailboxes.fail_cleanup.store(false, Ordering::SeqCst);
        engine.shutdown_all().unwrap();
        engine.shutdown_all().unwrap();
        assert!(
            HostBudgetPermit::reopen(
                &records.attempts[0].host_reservation,
                &hex::encode(records.attempts[0].reservation.request_digest),
            )
            .unwrap()
            .release_pre_dispatch()
            .is_err(),
            "host hold becomes terminal only after successful cleanup"
        );
        assert!(matches!(
            engine.handle(request, &parent).outcome,
            ActorOutcome::Released { .. }
        ));
        assert_eq!(mailboxes.derives.load(Ordering::SeqCst), 1);
        assert!(matches!(
            engine
                .host
                .reservations
                .observe(&records.attempts[0].reservation)
                .unwrap()
                .state,
            crate::actor_reservations::ReservationState::Terminal { .. }
        ));
        assert!(engine.failed_starts.is_empty() && engine.owners.is_empty());
        let _proof = parent.stop_and_reap().unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn child_preboot_refusal_cancels_only_its_original_signed_attempt() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let keys = home.path().join("keys");
        mvm_core::private_fs::ensure_private_dir(&keys).unwrap();
        let mut record = super::super::journal::fixture_record(&keys);
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.workload.0.clone_from(&record.child_workload);
        let signed = mvm_core::plan::sign_plan(
            &plan,
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            "host:test",
        );
        let config = mvm_core::vm_backend::VmStartConfig {
            name: record.child_workload.clone(),
            rootfs_path: home.path().join("missing.ext4").display().to_string(),
            plan_json: Some(serde_json::to_string(&signed).unwrap()),
            ..Default::default()
        };
        let error = AnyBackend::from_hypervisor("hvf")
            .start_owned_actor(&config, None)
            .unwrap_err();
        assert!(error.to_string().contains("mvm-meta"));
        record.state = ChildState::Dispatching;
        record.teardown = None;
        record.child_plan_digest = Some([11; 32]);
        assert!(!record_runtime_no_dispatch(&error, &mut record));
        assert_eq!(record.state, ChildState::Dispatching);
        record.child_plan_digest = Some(hash(&signed).unwrap());
        assert!(!record_runtime_no_dispatch(
            &anyhow::anyhow!("unknown native dispatch"),
            &mut record
        ));
        assert!(record_runtime_no_dispatch(&error, &mut record));
        assert_eq!(record.state, ChildState::Cancelling);
        let journal = ActorJournal::create(
            &home.path().join("journal"),
            mvm_core::crypto::aead::Key::from_bytes([3; 32]),
        )
        .unwrap();
        let mut records = journal.read().unwrap();
        records.children.push(record);
        journal.write(&records).unwrap();
        let mut recovered = journal.read().unwrap();
        recovered.children[0].begin_release(&ActorBindingId::new("release").unwrap());
        assert_eq!(recovered.children[0].state, ChildState::Cancelling);
        assert!(recovered.children[0].teardown.is_none());
    }

    #[test]
    fn failed_original_custody_write_stops_and_can_persist_retained_owner_on_release() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let keys = home.path().join("keys");
        mvm_core::private_fs::ensure_private_dir(&keys).unwrap();
        let mut record = super::super::journal::fixture_record(&keys);
        record.state = ChildState::Dispatching;
        record.child_plan_digest = Some([11; 32]);
        let backend = AnyBackend::from_hypervisor("mock");
        let mut owner = backend
            .start_owned_actor(
                &mvm_core::vm_backend::VmStartConfig {
                    name: record.child_workload.clone(),
                    cpus: 1,
                    memory_mib: 64,
                    ..Default::default()
                },
                None,
            )
            .unwrap();
        assert!(owner.is_running().unwrap());
        let path = home.path().join("actor-journal");
        let journal =
            ActorJournal::create(&path, mvm_core::crypto::aead::Key::from_bytes([3; 32])).unwrap();
        let mut records = journal.read().unwrap();
        records.children.push(record);
        journal.write(&records).unwrap();
        assert!(
            persist_original_custody(&mut records, 0, &mut owner, |_| {
                anyhow::bail!("injected one-shot persistence failure")
            })
            .is_err()
        );
        assert!(
            !owner.is_running().unwrap_or(false),
            "required persistence failure must stop the original owner"
        );

        let reopened =
            ActorJournal::open(&path, mvm_core::crypto::aead::Key::from_bytes([3; 32])).unwrap();
        let mut recovered = reopened.read().unwrap();
        assert!(recovered.children[0].teardown.is_none());
        recovered.children[0].begin_release(&ActorBindingId::new("release").unwrap());
        reopened.write(&recovered).unwrap();
        persist_original_custody(&mut recovered, 0, &mut owner, |records| {
            reopened.write(records)
        })
        .unwrap();
        let terminal = owner.stop_and_reap().unwrap();
        let digest = hash(terminal.journal()).unwrap();
        assert_eq!(
            hash(recovered.children[0].teardown.as_ref().unwrap()).unwrap(),
            digest
        );
        recovered.children[0].state = ChildState::Terminal;
        recovered.children[0].terminal_evidence_digest = Some(digest);
        reopened.write(&recovered).unwrap();
        assert_eq!(
            reopened.read().unwrap().children[0].state,
            ChildState::Terminal
        );
    }
}
