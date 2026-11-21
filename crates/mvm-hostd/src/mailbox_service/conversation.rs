//! VM-scoped call intents and application results over the canonical mailbox.
//!
//! The owner supplies admitted endpoint keys. This is a trusted-host endpoint,
//! not a keyless scheduler or protection from an active compromised host.
//! Source intent and result metadata are encrypted separately from the existing
//! destination journal. An uncertain write poisons this instance until reopen.
//!
//! The lifecycle owner must pin the caller address, authority issuer, epoch,
//! responder verification key and purpose-separated existing custody keys before
//! constructing this endpoint. Request-supplied identities are not that authority.
//! Dispatch uses [`Conversation::sealed_call`] on the dedicated mailbox transport;
//! no transport, lifecycle queue, process or scheduler is created here.
//!
//! A call moves from pending to an exact reply-admission intent, journal-backed
//! reply, application ACK intent, and settled. Both intermediate intents survive
//! restart and reconcile against exact journal bytes. Timeout does not retract
//! the request or imply that the responder did not execute. Reply acceptance and
//! request delivery ACK never settle a call. Result replay requires current
//! Receive authority and still-valid signed envelope/grant expiry: the call wait
//! deadline can be shorter than that bounded application-ACK window. Retention
//! does not extend authority, and pruning does not prove physical erasure.

use std::fs;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::PathBuf;
use std::time::Instant;

use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_contract::protocol::mailbox::{
    CausationId, ExecutionEpoch, MailboxAddress, MailboxEnvelope, MailboxEnvelopeHeader,
    MailboxMessageKind, MailboxOperation, MailboxRetentionPolicy, SignedDestinationReceipt,
    SignedMailboxCapability, SignedMailboxDeliveryAck,
};
use mvm_core::crypto::aead::{self, Key};
use mvm_core::mailbox::journal::{
    FileJournalAnchor, JournalAdmission, JournalError, JournalGuestAck, JournalGuestLease,
    JournalReceive, LeasedMailboxMessage, MailboxJournal,
};
use mvm_core::mailbox::{
    InMemoryReplayProtector, MailboxError, OpenContext, OpenedMailboxEnvelope, ReplayIdentity,
    authorize_receive, open_authenticated_envelope, verify_capability_signature,
};
use mvm_core::private_fs;
use mvm_core::util::atomic_io::{FileLock, atomic_write_durable, sync_dir};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::MailboxPolicy;

/// Finite caller-owned storage limits; no implicit retention duration.
#[derive(Debug, Clone, Copy)]
pub struct ConversationLimits {
    pub max_calls: usize,
    pub max_bytes: usize,
    pub retention: MailboxRetentionPolicy,
}

/// Admitted VM-scoped custody and identity, supplied by the endpoint owner.
pub struct ConversationConfig {
    pub directory: PathBuf,
    pub address: MailboxAddress,
    pub epoch: ExecutionEpoch,
    pub policy_epoch: u64,
    /// Trusted wall-clock observation at open; elapsed time thereafter is monotonic.
    pub now_unix_ms: i64,
    pub issuer: mvm_contract::protocol::mailbox::PrincipalId,
    pub authority: SigningKey,
    pub reply_key: Key,
    pub state_key: Key,
    pub limits: ConversationLimits,
}

/// An immutable sealed call plus the lifecycle-issued exact reply authority.
pub struct CallAdmission<'a> {
    pub envelope: &'a MailboxEnvelope,
    pub capability: &'a SignedMailboxCapability,
    pub policy: &'a MailboxPolicy,
    pub reply_capability: &'a SignedMailboxCapability,
    pub responder_key: &'a VerifyingKey,
    pub deadline_unix_ms: i64,
}

/// No transport receipt or request ACK is an application result.
#[derive(Debug)]
pub enum CallResult {
    Pending,
    /// An observation, not rollback of remote execution.
    TimedOut,
    Reply(Box<OpenedMailboxEnvelope>),
    Settled,
}

/// Refusals omit payload-derived diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum ConversationError {
    #[error("conversation scope mismatch")]
    Scope,
    #[error("conversation quota exhausted")]
    Full,
    #[error("unknown call")]
    Unknown,
    #[error("call has no acceptable reply")]
    NotReady,
    #[error("conversation state uncertain; reopen required")]
    Uncertain,
    #[error("conversation storage failed")]
    Storage,
    #[error("conversation authentication failed")]
    Mailbox(#[from] MailboxError),
    #[error("destination journal refused operation")]
    Journal(#[from] JournalError),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingCall {
    header: MailboxEnvelopeHeader,
    call: MailboxEnvelope,
    send_capability: SignedMailboxCapability,
    reply_capability: SignedMailboxCapability,
    responder_key: [u8; 32],
    deadline: i64,
    retain_until: i64,
    reply_identity: Option<ReplayIdentity>,
    result: ResultState,
}

#[derive(Clone, Serialize, Deserialize)]
enum ResultState {
    Pending,
    TimedOut,
    // Commit the exact candidate before journal admission. Reopen reconciles
    // against journal evidence, never inferring acceptance from this intent.
    Accepting(MailboxEnvelope),
    Replied(MailboxEnvelope),
    AckRequested(MailboxEnvelope),
    SignedAckRequested {
        envelope: MailboxEnvelope,
        signed: Box<SignedMailboxDeliveryAck>,
    },
    Settled,
}

#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    calls: Vec<PendingCall>,
    observed_at_unix_ms: i64,
}

/// Exclusive VM-scoped conversation owner; the destination journal remains
/// the authority for reply acceptance and application acknowledgement.
pub struct Conversation {
    config: ConversationConfig,
    journal: MailboxJournal,
    anchor: FileJournalAnchor,
    state: Snapshot,
    aad: Vec<u8>,
    poisoned: bool,
    started: Instant,
    clock_base_unix_ms: i64,
    observed_at_unix_ms: i64,
    _lock: FileLock,
}

impl Conversation {
    /// Reopen existing encrypted state with existing custody material.
    ///
    /// A new outbox requires a nonexistent directory. Missing state in an
    /// existing outbox fails closed; the owner must retain it with its epoch.
    pub fn open(
        config: ConversationConfig,
        journal: MailboxJournal,
        anchor: FileJournalAnchor,
    ) -> Result<Self, ConversationError> {
        if config.limits.max_calls == 0 || config.limits.max_bytes == 0 {
            return Err(ConversationError::Full);
        }
        let read_limit = u64::try_from(config.limits.max_bytes)
            .ok()
            .and_then(|bytes| bytes.checked_add(1))
            .ok_or(ConversationError::Full)?;
        journal.local_ready(&anchor, &config.authority.verifying_key())?;
        let existed = config
            .directory
            .try_exists()
            .map_err(|_| ConversationError::Storage)?;
        private_fs::ensure_private_dir(&config.directory)
            .map_err(|_| ConversationError::Storage)?;
        let lock = FileLock::try_acquire(&config.directory.join("conversation"))
            .map_err(|_| ConversationError::Storage)?
            .ok_or(ConversationError::Uncertain)?;
        let aad = serde_json::to_vec(&(
            "mvm.mailbox.conversation.local.v1",
            config.address,
            config.epoch,
            config.policy_epoch,
            config.issuer,
            config.authority.verifying_key().to_bytes(),
        ))
        .map_err(|_| ConversationError::Storage)?;
        let path = config.directory.join("state");
        let state = match fs::symlink_metadata(&path) {
            Ok(meta) => {
                if !meta.file_type().is_file() || meta.len() > config.limits.max_bytes as u64 {
                    return Err(ConversationError::Storage);
                }
                let mut bytes = Vec::new();
                let file = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(&path)
                    .map_err(|_| ConversationError::Storage)?;
                let meta = file.metadata().map_err(|_| ConversationError::Storage)?;
                if !meta.is_file()
                    || meta.nlink() != 1
                    || meta.len() > config.limits.max_bytes as u64
                {
                    return Err(ConversationError::Storage);
                }
                file.take(read_limit)
                    .read_to_end(&mut bytes)
                    .map_err(|_| ConversationError::Storage)?;
                if bytes.len() > config.limits.max_bytes {
                    return Err(ConversationError::Full);
                }
                let plaintext = Zeroizing::new(
                    aead::open(&config.state_key, &bytes, &aad)
                        .map_err(|_| ConversationError::Storage)?,
                );
                let state: Snapshot =
                    serde_json::from_slice(&plaintext).map_err(|_| ConversationError::Storage)?;
                if state.calls.len() > config.limits.max_calls {
                    return Err(ConversationError::Full);
                }
                state
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !existed => {
                if journal.tip().cursor != 0 {
                    return Err(ConversationError::Storage);
                }
                Snapshot::default()
            }
            Err(_) => return Err(ConversationError::Storage),
        };
        let clock_base_unix_ms = config.now_unix_ms.max(state.observed_at_unix_ms);
        let mut conversation = Self {
            config,
            journal,
            anchor,
            state,
            aad,
            poisoned: false,
            started: Instant::now(),
            clock_base_unix_ms,
            observed_at_unix_ms: clock_base_unix_ms,
            _lock: lock,
        };
        if !existed {
            conversation.commit(Snapshot::default())?;
            sync_dir(
                conversation
                    .config
                    .directory
                    .parent()
                    .ok_or(ConversationError::Storage)?,
            )
            .map_err(|_| ConversationError::Storage)?;
        }
        Ok(conversation)
    }

    /// Persist the sealed source intent before any transport may dispatch it.
    /// Exact retries return the original identity; conflicting reuse refuses.
    pub fn enqueue_call(
        &mut self,
        request: CallAdmission<'_>,
    ) -> Result<ReplayIdentity, ConversationError> {
        self.ready()?;
        let admission = &request;
        let current = self.current_context(&admission.policy.context)?;
        let opened = open_authenticated_envelope(
            admission.envelope,
            admission.capability,
            &current,
            &admission.policy.encryption_key,
            &admission.policy.sender_key,
            &admission.policy.authority_key,
            &mut InMemoryReplayProtector::default(),
        )?;
        let header = opened.header();
        let grant = &request.reply_capability.grant;
        verify_capability_signature(
            request.reply_capability,
            &self.config.authority.verifying_key(),
        )?;
        let route = header.reply_to.ok_or(ConversationError::Scope)?;
        let now = current.now_unix_ms;
        if current.required_operation != MailboxOperation::Send
            || header.kind != MailboxMessageKind::Call
            || header.sender != self.config.address.recipient
            || header.execution_epoch != self.config.epoch
            || header.policy_epoch != self.config.policy_epoch
            || route.address != self.config.address
            || route.capability_id != grant.capability_id
            || grant.address != self.config.address
            || grant.subject != header.recipient
            || grant.issuer != self.config.issuer
            || grant.policy_epoch != self.config.policy_epoch
            || !grant.admits_epoch(self.config.epoch)
            || grant.not_before_unix_ms > now
            || grant.expires_at_unix_ms <= now
            || !grant.operations.allows(MailboxOperation::Reply)
            || grant.message_kinds != [MailboxMessageKind::Reply]
            || request.deadline_unix_ms <= now
            || request.deadline_unix_ms > header.expires_at_unix_ms
            || header.expires_at_unix_ms > admission.capability.grant.expires_at_unix_ms
            || request.deadline_unix_ms > admission.capability.grant.expires_at_unix_ms
            || request.deadline_unix_ms > grant.expires_at_unix_ms
            || current.revoked_capabilities.contains(&grant.revocation_id)
        {
            return Err(ConversationError::Scope);
        }
        let id = ReplayIdentity::from_header(header);
        if let Some(previous) = self
            .state
            .calls
            .iter()
            .find(|call| ReplayIdentity::from_header(&call.header) == id)
        {
            if previous.call != *admission.envelope
                || previous.send_capability != *admission.capability
                || previous.reply_capability != *request.reply_capability
                || previous.responder_key != request.responder_key.to_bytes()
                || previous.deadline != request.deadline_unix_ms
            {
                return Err(ConversationError::Scope);
            }
            return Ok(id);
        }
        if self.state.calls.iter().any(|call| {
            call.header.correlation_id == header.correlation_id
                || call.reply_capability.grant.capability_id == grant.capability_id
        }) {
            return Err(ConversationError::Scope);
        }
        let outstanding = self
            .state
            .calls
            .iter()
            .filter(|call| !matches!(call.result, ResultState::Settled))
            .count();
        let granted = admission
            .capability
            .grant
            .max_outstanding_calls
            .min(grant.max_outstanding_calls) as usize;
        if self.state.calls.len() >= self.config.limits.max_calls || outstanding >= granted {
            return Err(ConversationError::Full);
        }
        let retain_until = self
            .config
            .limits
            .retention
            .retained_until(header.expires_at_unix_ms.max(grant.expires_at_unix_ms))
            .map_err(|_| ConversationError::Scope)?;
        let mut next = self.state.clone();
        next.calls.push(PendingCall {
            header: header.clone(),
            call: admission.envelope.clone(),
            send_capability: admission.capability.clone(),
            reply_capability: request.reply_capability.clone(),
            responder_key: request.responder_key.to_bytes(),
            deadline: request.deadline_unix_ms,
            retain_until,
            reply_identity: None,
            result: ResultState::Pending,
        });
        self.commit(next)?;
        Ok(id)
    }

    /// Borrow exact persisted bytes for the dedicated mailbox transport.
    pub fn sealed_call(
        &self,
        id: ReplayIdentity,
    ) -> Result<(&SignedMailboxCapability, &MailboxEnvelope), ConversationError> {
        self.ready()?;
        let call = &self.state.calls[self.index(id)?];
        Ok((&call.send_capability, &call.call))
    }

    /// Verify exact reply scope, then commit the canonical destination journal.
    /// This returns delivery acceptance, not application completion.
    pub fn accept_reply(
        &mut self,
        id: ReplayIdentity,
        envelope: &MailboxEnvelope,
        context: &OpenContext,
    ) -> Result<SignedDestinationReceipt, ConversationError> {
        self.ready()?;
        let current = self.current_context(context)?;
        let context = &current;
        let index = self.index(id)?;
        self.reconcile(index)?;
        let call = &self.state.calls[index];
        self.check_context(call, context, MailboxOperation::Reply)?;
        let key =
            VerifyingKey::from_bytes(&call.responder_key).map_err(|_| ConversationError::Scope)?;
        let opened = open_authenticated_envelope(
            envelope,
            &call.reply_capability,
            context,
            &self.config.reply_key,
            &key,
            &self.config.authority.verifying_key(),
            &mut InMemoryReplayProtector::default(),
        )?;
        let header = opened.header();
        if header.kind != MailboxMessageKind::Reply
            || header.correlation_id != call.header.correlation_id
            || header.causation_id != CausationId::from_bytes(*call.header.message_id.as_bytes())
            || header.capability_id != call.reply_capability.grant.capability_id
            || header.expires_at_unix_ms > call.reply_capability.grant.expires_at_unix_ms
        {
            return Err(ConversationError::Scope);
        }
        if context.now_unix_ms >= call.deadline
            && matches!(
                call.result,
                ResultState::Pending | ResultState::Accepting(_)
            )
        {
            let mut next = self.state.clone();
            next.calls[index].result = ResultState::TimedOut;
            self.commit(next)?;
            return Err(ConversationError::NotReady);
        }
        match &call.result {
            ResultState::Pending if context.now_unix_ms < call.deadline => {}
            ResultState::Accepting(previous) | ResultState::Replied(previous)
                if previous == envelope => {}
            ResultState::Pending
            | ResultState::Accepting(_)
            | ResultState::Replied(_)
            | ResultState::TimedOut
            | ResultState::AckRequested(_)
            | ResultState::SignedAckRequested { .. }
            | ResultState::Settled => return Err(ConversationError::NotReady),
        }
        if matches!(call.result, ResultState::Pending) {
            let mut next = self.state.clone();
            next.calls[index].reply_identity = Some(ReplayIdentity::from_header(opened.header()));
            next.calls[index].result = ResultState::Accepting(envelope.clone());
            self.commit(next)?;
        }
        let commit_context = self.current_context(context)?;
        if matches!(self.state.calls[index].result, ResultState::Accepting(_))
            && commit_context.now_unix_ms >= self.state.calls[index].deadline
        {
            let mut next = self.state.clone();
            next.calls[index].result = ResultState::TimedOut;
            self.commit(next)?;
            return Err(ConversationError::NotReady);
        }
        let receipt = self.journal.admit_local(
            JournalAdmission {
                envelope,
                capability: &self.state.calls[index].reply_capability,
                context: &commit_context,
                encryption_key: &self.config.reply_key,
                sender_key: &key,
                signer: &self.config.authority,
            },
            &self.anchor,
        )?;
        let mut next = self.state.clone();
        next.calls[index].result = ResultState::Replied(envelope.clone());
        self.commit(next)?;
        Ok(receipt)
    }

    /// Observe a pending call or independently authorize and replay its result.
    /// Reading never settles the call.
    pub fn receive_result(
        &mut self,
        id: ReplayIdentity,
        capability: &SignedMailboxCapability,
        context: &OpenContext,
    ) -> Result<CallResult, ConversationError> {
        self.ready()?;
        let current = self.current_context(context)?;
        let context = &current;
        let index = self.index(id)?;
        self.reconcile(index)?;
        let call = &self.state.calls[index];
        self.check_context(call, context, MailboxOperation::Receive)?;
        self.authorize_observation(capability, context)?;
        match &call.result {
            ResultState::Pending | ResultState::Accepting(_) => {
                if context.now_unix_ms >= call.deadline {
                    let mut next = self.state.clone();
                    next.calls[index].result = ResultState::TimedOut;
                    self.commit(next)?;
                    Ok(CallResult::TimedOut)
                } else {
                    Ok(CallResult::Pending)
                }
            }
            ResultState::TimedOut => Ok(CallResult::TimedOut),
            ResultState::Replied(envelope) => {
                let key = VerifyingKey::from_bytes(&call.responder_key)
                    .map_err(|_| ConversationError::Scope)?;
                let mut reply = context.clone();
                reply.required_operation = MailboxOperation::Reply;
                reply.acting_principal = call.header.recipient;
                let opened = open_authenticated_envelope(
                    envelope,
                    &call.reply_capability,
                    &reply,
                    &self.config.reply_key,
                    &key,
                    &self.config.authority.verifying_key(),
                    &mut InMemoryReplayProtector::default(),
                )?;
                authorize_receive(
                    opened.header(),
                    capability,
                    context,
                    &self.config.authority.verifying_key(),
                )?;
                Ok(CallResult::Reply(Box::new(opened)))
            }
            ResultState::AckRequested(_) => {
                self.acknowledge_result(id, capability, context)?;
                Ok(CallResult::Settled)
            }
            ResultState::Settled => Ok(CallResult::Settled),
            ResultState::SignedAckRequested { .. } => Err(ConversationError::NotReady),
        }
    }

    /// Commit application ACK intent first, then journal ACK, then settlement.
    /// An interrupted ACK never re-exposes a result as a new completion.
    pub fn acknowledge_result(
        &mut self,
        id: ReplayIdentity,
        capability: &SignedMailboxCapability,
        context: &OpenContext,
    ) -> Result<(), ConversationError> {
        self.ready()?;
        let current = self.current_context(context)?;
        let context = &current;
        let index = self.index(id)?;
        self.reconcile(index)?;
        let call = &self.state.calls[index];
        self.check_context(call, context, MailboxOperation::Receive)?;
        self.authorize_observation(capability, context)?;
        let envelope = match &call.result {
            ResultState::Replied(envelope) | ResultState::AckRequested(envelope) => {
                envelope.clone()
            }
            ResultState::Settled => return Ok(()),
            ResultState::Pending
            | ResultState::TimedOut
            | ResultState::Accepting(_)
            | ResultState::SignedAckRequested { .. } => {
                return Err(ConversationError::NotReady);
            }
        };
        let key =
            VerifyingKey::from_bytes(&call.responder_key).map_err(|_| ConversationError::Scope)?;
        let mut reply = context.clone();
        reply.required_operation = MailboxOperation::Reply;
        reply.acting_principal = call.header.recipient;
        let opened = open_authenticated_envelope(
            &envelope,
            &call.reply_capability,
            &reply,
            &self.config.reply_key,
            &key,
            &self.config.authority.verifying_key(),
            &mut InMemoryReplayProtector::default(),
        )?;
        authorize_receive(
            opened.header(),
            capability,
            context,
            &self.config.authority.verifying_key(),
        )?;
        let identity = ReplayIdentity::from_header(opened.header());
        let mut next = self.state.clone();
        next.calls[index].result = ResultState::AckRequested(envelope);
        self.commit(next)?;
        self.journal.acknowledge(
            identity,
            JournalReceive {
                capability,
                context,
                encryption_key: &self.config.reply_key,
                sender_key: &key,
            },
            |tip| self.anchor.advance(tip),
        )?;
        let mut next = self.state.clone();
        next.calls[index].result = ResultState::Settled;
        self.commit(next)
    }

    /// Issue a canonical guest-signed-ACK lease for this exact committed reply.
    /// Fresh enrolled possession is checked by the existing journal before disclosure.
    pub fn lease_result(
        &mut self,
        id: ReplayIdentity,
        request: JournalGuestLease<'_>,
    ) -> Result<Option<LeasedMailboxMessage>, ConversationError> {
        self.ready()?;
        let current = self.current_context(request.receive.context)?;
        let index = self.index(id)?;
        self.reconcile(index)?;
        let call = &self.state.calls[index];
        self.check_context(call, &current, MailboxOperation::Receive)?;
        if !matches!(call.result, ResultState::Replied(_)) {
            return Ok(None);
        }
        let identity = self.result_identity(index, &current)?;
        let request = JournalGuestLease {
            receive: JournalReceive {
                context: &current,
                ..request.receive
            },
            scope: mvm_contract::protocol::mailbox::MailboxGuestReaderScope {
                now_unix_ms: current.now_unix_ms,
                ..request.scope
            },
            ..request
        };
        Ok(self
            .journal
            .lease_message(identity, request, |tip| self.anchor.advance(tip))?)
    }

    /// Persist an exact authenticated guest ACK intent, then the canonical journal ACK.
    pub fn acknowledge_result_signed(
        &mut self,
        id: ReplayIdentity,
        request: JournalGuestAck<'_>,
    ) -> Result<(), ConversationError> {
        self.ready()?;
        let current = self.current_context(request.receive.context)?;
        let index = self.index(id)?;
        self.reconcile(index)?;
        self.check_context(
            &self.state.calls[index],
            &current,
            MailboxOperation::Receive,
        )?;
        let request = JournalGuestAck {
            receive: JournalReceive {
                context: &current,
                ..request.receive
            },
            scope: mvm_contract::protocol::mailbox::MailboxGuestReaderScope {
                now_unix_ms: current.now_unix_ms,
                ..request.scope
            },
            ..request
        };
        let identity = self.journal.verify_guest_ack(request)?;
        if self.state.calls[index].reply_identity != Some(identity) {
            return Err(ConversationError::Scope);
        }
        if matches!(self.state.calls[index].result, ResultState::Settled) {
            return Ok(());
        }
        if identity != self.result_identity(index, &current)? {
            return Err(ConversationError::Scope);
        }
        let envelope = match &self.state.calls[index].result {
            ResultState::Replied(envelope) => envelope.clone(),
            ResultState::SignedAckRequested { envelope, signed } if **signed == *request.signed => {
                envelope.clone()
            }
            ResultState::Pending
            | ResultState::TimedOut
            | ResultState::Accepting(_)
            | ResultState::AckRequested(_)
            | ResultState::SignedAckRequested { .. }
            | ResultState::Settled => return Err(ConversationError::NotReady),
        };
        let mut next = self.state.clone();
        next.calls[index].result = ResultState::SignedAckRequested {
            envelope,
            signed: Box::new(request.signed.clone()),
        };
        self.commit(next)?;
        let commit_context = self.current_context(request.receive.context)?;
        let request = JournalGuestAck {
            receive: JournalReceive {
                context: &commit_context,
                ..request.receive
            },
            scope: mvm_contract::protocol::mailbox::MailboxGuestReaderScope {
                now_unix_ms: commit_context.now_unix_ms,
                ..request.scope
            },
            ..request
        };
        self.journal
            .acknowledge_signed(request, |tip| self.anchor.advance(tip))?;
        let mut next = self.state.clone();
        next.calls[index].result = ResultState::Settled;
        self.commit(next)
    }

    fn result_identity(
        &self,
        index: usize,
        context: &OpenContext,
    ) -> Result<ReplayIdentity, ConversationError> {
        let call = &self.state.calls[index];
        let envelope = match &call.result {
            ResultState::Replied(envelope)
            | ResultState::AckRequested(envelope)
            | ResultState::SignedAckRequested { envelope, .. } => envelope,
            ResultState::Pending
            | ResultState::TimedOut
            | ResultState::Accepting(_)
            | ResultState::Settled => return Err(ConversationError::NotReady),
        };
        let key =
            VerifyingKey::from_bytes(&call.responder_key).map_err(|_| ConversationError::Scope)?;
        let mut reply = context.clone();
        reply.required_operation = MailboxOperation::Reply;
        reply.acting_principal = call.header.recipient;
        let opened = open_authenticated_envelope(
            envelope,
            &call.reply_capability,
            &reply,
            &self.config.reply_key,
            &key,
            &self.config.authority.verifying_key(),
            &mut InMemoryReplayProtector::default(),
        )?;
        Ok(ReplayIdentity::from_header(opened.header()))
    }

    /// Remove only records past the signed authority lifetime plus retention.
    /// Late traffic cannot authenticate after that lifetime.
    pub fn prune(&mut self, now_unix_ms: i64) -> Result<(), ConversationError> {
        self.ready()?;
        let now_unix_ms = self.observe_time(now_unix_ms)?;
        // Resolve cross-store commits before retention can remove their journal evidence.
        for index in 0..self.state.calls.len() {
            self.reconcile(index)?;
        }
        if self.journal.local_compaction_due(now_unix_ms)? {
            self.journal
                .compact_local(now_unix_ms, &self.config.authority, &self.anchor)?;
        }
        for _ in 0..self.config.limits.max_calls {
            if self
                .journal
                .expire_next(now_unix_ms, &self.config.authority, |tip| {
                    self.anchor.advance(tip)
                })?
                .is_none()
            {
                break;
            }
        }
        if self.journal.local_compaction_due(now_unix_ms)? {
            self.journal
                .compact_local(now_unix_ms, &self.config.authority, &self.anchor)?;
        }
        let mut next = self.state.clone();
        next.calls.retain(|call| now_unix_ms < call.retain_until);
        self.commit(next)
    }

    fn reconcile(&mut self, index: usize) -> Result<(), ConversationError> {
        let call = &self.state.calls[index];
        if let ResultState::AckRequested(envelope)
        | ResultState::SignedAckRequested { envelope, .. } = &call.result
            && self.journal.locally_acknowledged(
                envelope,
                &call.reply_capability,
                &self.config.authority,
                &self.anchor,
            )?
        {
            let mut next = self.state.clone();
            next.calls[index].result = ResultState::Settled;
            return self.commit(next);
        }
        if let ResultState::Accepting(envelope) = &call.result
            && self
                .journal
                .accepted_local_receipt(
                    envelope,
                    &call.reply_capability,
                    &self.config.authority,
                    &self.anchor,
                )?
                .is_some()
        {
            let mut next = self.state.clone();
            next.calls[index].result = ResultState::Replied(envelope.clone());
            self.commit(next)?;
        }
        Ok(())
    }

    fn check_context(
        &self,
        call: &PendingCall,
        context: &OpenContext,
        operation: MailboxOperation,
    ) -> Result<(), ConversationError> {
        let address = self.config.address;
        if context.expected_tenant != address.tenant
            || context.expected_authorization_domain != address.authorization_domain
            || context.expected_mailbox != address.mailbox
            || context.expected_recipient != address.recipient
            || context.expected_sender != call.header.recipient
            || context.current_execution_epoch != self.config.epoch
            || context.current_policy_epoch != self.config.policy_epoch
            || context.expected_capability_issuer != self.config.issuer
            || context.required_operation != operation
            || context.acting_principal
                != if operation == MailboxOperation::Reply {
                    call.header.recipient
                } else {
                    address.recipient
                }
        {
            return Err(ConversationError::Scope);
        }
        Ok(())
    }

    fn authorize_observation(
        &self,
        capability: &SignedMailboxCapability,
        context: &OpenContext,
    ) -> Result<(), ConversationError> {
        verify_capability_signature(capability, &self.config.authority.verifying_key())?;
        let grant = &capability.grant;
        if grant.address != self.config.address
            || grant.subject != self.config.address.recipient
            || grant.issuer != self.config.issuer
            || !grant.operations.allows(MailboxOperation::Receive)
            || !grant.message_kinds.contains(&MailboxMessageKind::Reply)
            || !grant.admits_epoch(self.config.epoch)
            || grant.policy_epoch != self.config.policy_epoch
            || context.now_unix_ms < grant.not_before_unix_ms
            || context.now_unix_ms >= grant.expires_at_unix_ms
            || context.revoked_capabilities.contains(&grant.revocation_id)
        {
            return Err(ConversationError::Scope);
        }
        Ok(())
    }

    fn index(&self, id: ReplayIdentity) -> Result<usize, ConversationError> {
        self.state
            .calls
            .iter()
            .position(|call| ReplayIdentity::from_header(&call.header) == id)
            .ok_or(ConversationError::Unknown)
    }

    fn ready(&self) -> Result<(), ConversationError> {
        if self.poisoned {
            Err(ConversationError::Uncertain)
        } else {
            Ok(())
        }
    }

    fn current_context(&mut self, context: &OpenContext) -> Result<OpenContext, ConversationError> {
        let mut current = context.clone();
        current.now_unix_ms = self.observe_time(context.now_unix_ms)?;
        Ok(current)
    }

    fn observe_time(&mut self, wall_unix_ms: i64) -> Result<i64, ConversationError> {
        let elapsed = i64::try_from(self.started.elapsed().as_millis())
            .map_err(|_| ConversationError::Uncertain)?;
        let mut now = self
            .clock_base_unix_ms
            .checked_add(elapsed)
            .ok_or(ConversationError::Uncertain)?;
        if wall_unix_ms > now {
            self.clock_base_unix_ms = wall_unix_ms
                .checked_sub(elapsed)
                .ok_or(ConversationError::Uncertain)?;
            now = wall_unix_ms;
        }
        self.observed_at_unix_ms = self.observed_at_unix_ms.max(wall_unix_ms).max(now);
        Ok(self.observed_at_unix_ms)
    }

    fn commit(&mut self, mut next: Snapshot) -> Result<(), ConversationError> {
        self.ready()?;
        next.observed_at_unix_ms = self.observed_at_unix_ms;
        let plaintext =
            Zeroizing::new(serde_json::to_vec(&next).map_err(|_| ConversationError::Storage)?);
        if plaintext
            .len()
            .saturating_add(aead::NONCE_SIZE + aead::TAG_SIZE)
            > self.config.limits.max_bytes
        {
            return Err(ConversationError::Full);
        }
        let sealed = aead::seal(&self.config.state_key, &plaintext, &self.aad);
        if atomic_write_durable(&self.config.directory.join("state"), &sealed)
            .and_then(|()| sync_dir(&self.config.directory))
            .is_err()
        {
            self.poisoned = true;
            return Err(ConversationError::Storage);
        }
        self.state = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
