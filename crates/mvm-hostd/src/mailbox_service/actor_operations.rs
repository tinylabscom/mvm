//! Durable endpoint operations; transport owns authenticated sessions and dispatch.
//!
//! No network I/O runs while the endpoint transaction lock is held. Outgoing
//! frames are persisted first and drained by the transport outside that lock.

use std::path::PathBuf;
use std::time::Instant;

use hmac::{Hmac, KeyInit, Mac};
use mvm_contract::plan::ExecutionPlan;
use mvm_contract::protocol::mailbox::{
    BootId, CapabilityId, CapabilityOperations, CausationId, ContentType, CorrelationId,
    DeliveryId, DeliveryOutcome, MailboxAddress, MailboxEnvelope, MailboxEnvelopeHeader,
    MailboxMessageKind, MailboxOperation, MailboxRetentionPolicy, MessageId, ReplayNonce,
    ReplyRoute, SequenceNumber, SignedDestinationReceipt, SignedMailboxCapability,
    SignedMailboxDeliveryAck, SignedMailboxDeliveryLease,
};
use mvm_core::crypto::aead::{self, Key};
use mvm_core::host_interface::epoch_gate::admit_at;
use mvm_core::host_interface::workload::DestinationTip;
use mvm_core::mailbox::conversation_wire::{
    ConversationBinding, ConversationRequest, ConversationResponse,
};
use mvm_core::mailbox::frame::Refusal;
use mvm_core::mailbox::journal::{
    FileJournalAnchor, HistoryKeyRef, JournalAdmission, JournalGuestAck, JournalGuestLease,
    JournalLimits, JournalReceive, MailboxJournal,
};
use mvm_core::mailbox::{InMemoryReplayProtector, ReplayIdentity, SealRequest};
use mvm_core::private_fs;
use mvm_core::util::atomic_io::{FileLock, write_private};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::conversation::{
    CallAdmission, CallResult, Conversation, ConversationConfig, ConversationLimits,
};
use super::durable::{ConversationOperations, CurrentBootAuthority};
use crate::mailbox_launch::actor_template::{
    ActorEndpointMaterial, ActorPeerBinding, ActorPeerRole,
};

mod guest_requests;
mod scope;
use crate::mailbox_commit::{ActorJournal, JournalOrder, actor_destination_id, require_reached};
use guest_requests::{AckRequest, ReplyRequest};
use scope::{ScopedHistory, address, key, reader_scope, storage};

const MAX_RETAINED_CALLS: usize = 4096;
const MAX_SEGMENT_RECORDS: usize = 64;
const CONTROL_STORAGE_BYTES: usize = 8192;
const STATE_DOMAIN: &str = "mvm.actor.endpoint-state.v1";

type Result<T> = std::result::Result<T, Refusal>;

/// This entire frame travels inside the authenticated encrypted peer channel.
/// The only routing selector is the canonical envelope's opaque route token.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActorPeerFrame {
    Call {
        envelope: MailboxEnvelope,
        reply_capability: Box<SignedMailboxCapability>,
    },
    Reply {
        envelope: MailboxEnvelope,
    },
}

impl std::fmt::Debug for ActorPeerFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActorPeerFrame").finish_non_exhaustive()
    }
}

impl ActorPeerFrame {
    pub fn envelope(&self) -> &MailboxEnvelope {
        match self {
            Self::Call { envelope, .. } | Self::Reply { envelope } => envelope,
        }
    }
}

/// An immutable persisted intent for transport outside the endpoint mutex.
pub struct ActorDispatch {
    pub message_id: MessageId,
    pub peer: ActorPeerBinding,
    pub frame: ActorPeerFrame,
}

/// Trusted launch inputs; storage remains outside the VM's disposable directory.
pub struct ActorOperationConfig {
    pub plan: ExecutionPlan,
    pub binding: ConversationBinding,
    pub directory: PathBuf,
    /// Aggregate disk allowance, including retained call metadata and all segments.
    pub max_storage_bytes: usize,
    pub now_unix_ms: i64,
    /// This unit's execution epoch, read from the epoch gate when it bound.
    pub current_epoch: mvm_contract::protocol::mailbox::ExecutionEpoch,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Direction {
    Outbound,
    Inbound,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    direction: Direction,
    peer: MailboxAddress,
    header: MailboxEnvelopeHeader,
    call: MailboxEnvelope,
    reply_capability: SignedMailboxCapability,
    initialized: bool,
    call_receipt: Option<SignedDestinationReceipt>,
    reply: Option<MailboxEnvelope>,
    reply_header: Option<MailboxEnvelopeHeader>,
    reply_receipt: Option<SignedDestinationReceipt>,
    delivery: Option<SignedMailboxDeliveryLease>,
    acknowledged: bool,
    dispatch_attempts: u32,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    binding: [u8; 32],
    reader: ConversationBinding,
    storage_bytes: usize,
    clock: i64,
    recent_messages: Vec<i64>,
    records: Vec<Record>,
}

/// One VM-scoped owner serializes all peer quotas, source intents and delivery state.
///
/// Retained records count against capacity even after ACK. Saturation refuses;
/// reopening never discards history to make room or treats a timeout as rollback.
pub struct ActorConversationEndpoint {
    config: ActorOperationConfig,
    material: ActorEndpointMaterial,
    retention: MailboxRetentionPolicy,
    state: State,
    started: Instant,
    clock_origin_ms: i64,
    poisoned: bool,
    ordering: JournalOrder,
    /// Asked before each new peer acceptance; absent in unit tests that bind
    /// no ledger.
    unit_gate: Option<super::UnitGate>,
    _lock: FileLock,
}

impl ActorConversationEndpoint {
    pub(crate) fn open<F>(
        config: ActorOperationConfig,
        material: ActorEndpointMaterial,
        ordering: F,
    ) -> Result<Self>
    where
        F: FnOnce(&std::path::Path) -> Result<JournalOrder>,
    {
        material.verify_plan(&config.plan).map_err(storage)?;
        config
            .binding
            .reader
            .check_plan(&config.plan)
            .map_err(storage)?;
        if config.binding.address != material.address
            || config.binding.policy_epoch != material.template.capability.policy_epoch
            || config
                .plan
                .mailbox
                .is_none_or(|grant| admit_at(config.current_epoch, grant.epoch).is_err())
        {
            return Err(Refusal::NotAuthorized);
        }
        let retention = config
            .plan
            .mailbox
            .and_then(|grant| grant.retention)
            .ok_or(Refusal::NotAuthorized)?;
        let calls = material.template.capability.max_outstanding_calls as usize;
        if calls == 0
            || calls > MAX_RETAINED_CALLS
            || config.max_storage_bytes as u64 != material.max_storage_bytes
            || config
                .max_storage_bytes
                .saturating_sub(CONTROL_STORAGE_BYTES)
                / calls
                / 4
                < 4096
        {
            return Err(Refusal::StorageFull);
        }
        let existed = config.directory.try_exists().map_err(storage)?;
        if !existed {
            private_fs::create_owned_private_dir(&config.directory).map_err(storage)?;
            mvm_core::atomic_io::sync_dir(config.directory.parent().ok_or(Refusal::Unavailable)?)
                .map_err(storage)?;
        }
        let metadata = std::fs::symlink_metadata(&config.directory).map_err(storage)?;
        private_fs::require_current_owner(&metadata).map_err(storage)?;
        if !metadata.is_dir()
            || private_fs::mode_bits(&config.directory, &metadata).map_err(storage)? & 0o077 != 0
        {
            return Err(Refusal::Unavailable);
        }
        let lock = crate::admission_budget::acquire_lock(&config.directory.join("owner.lock"))
            .map_err(storage)?;
        let state = match crate::admission_budget::read_private(
            &config.directory.join("state"),
            (config.max_storage_bytes - CONTROL_STORAGE_BYTES) / 4,
        )
        .map_err(storage)?
        {
            Some(bytes) => {
                let clear = Zeroizing::new(
                    aead::open(&material.state_key(), &bytes, STATE_DOMAIN.as_bytes())
                        .map_err(storage)?,
                );
                serde_json::from_slice::<State>(&clear).map_err(storage)?
            }
            None if !existed => State {
                binding: material.plan_binding(),
                reader: config.binding.clone(),
                storage_bytes: config.max_storage_bytes,
                clock: config.now_unix_ms,
                recent_messages: Vec::new(),
                records: Vec::new(),
            },
            None => return Err(Refusal::Unavailable),
        };
        if state.binding != material.plan_binding()
            || state.reader != config.binding
            || state.storage_bytes != config.max_storage_bytes
            || state.records.len() > calls
            || state.recent_messages.len() > MAX_RETAINED_CALLS
        {
            return Err(Refusal::Unavailable);
        }
        for (index, record) in state.records.iter().enumerate() {
            if state.records[..index].iter().any(|other| {
                other.header.message_id == record.header.message_id
                    || (other.peer == record.peer
                        && other.header.correlation_id == record.header.correlation_id)
            }) {
                return Err(Refusal::Unavailable);
            }
        }
        let clock_origin_ms = state.clock.max(config.now_unix_ms);
        let mut owner = Self {
            config,
            material,
            retention,
            state,
            started: Instant::now(),
            clock_origin_ms,
            poisoned: false,
            ordering: JournalOrder::Unordered,
            unit_gate: None,
            _lock: lock,
        };
        if !existed {
            owner.commit(owner.state.clone())?;
        }
        owner.check_quota(&owner.state)?;
        // Persist initial state before minting the ordering key, so an interrupted
        // open can safely resume instead of leaving a key-only directory.
        owner.ordering = ordering(&owner.config.directory)?;
        Ok(owner)
    }

    /// Ask the unit's epoch gate before accepting each peer frame, so a
    /// replacement or quarantine committed after bind refuses the next one.
    #[must_use]
    pub(crate) fn gated(mut self, gate: super::UnitGate) -> Self {
        self.unit_gate = Some(gate);
        self
    }

    fn admit_unit(&self) -> Result<()> {
        self.unit_gate
            .as_ref()
            .map_or(Ok(()), super::UnitGate::admit)
    }

    /// The receipt this endpoint already gave for exactly these bytes, if any.
    fn accepted_receipt(
        &self,
        index: usize,
        envelope: &MailboxEnvelope,
        capability: &SignedMailboxCapability,
    ) -> Result<Option<SignedDestinationReceipt>> {
        if !self.state.records[index].initialized {
            return Ok(None);
        }
        let (journal, anchor) = self.journal(index)?;
        journal
            .accepted_local_receipt(
                envelope,
                capability,
                &self.material.authority_key(),
                &anchor,
            )
            .map_err(storage)
    }

    /// The anchor to open a journal with, and the tip the ledger holds for it
    /// when ordered. A refused or unknown ordering is an unavailable
    /// destination to the caller.
    fn ordered(
        &self,
        anchor: FileJournalAnchor,
        journal: ActorJournal,
        id: MessageId,
    ) -> Result<(FileJournalAnchor, Option<DestinationTip>)> {
        let JournalOrder::Ledger(ordering) = &self.ordering else {
            return Ok((anchor, None));
        };
        let destination =
            actor_destination_id(&self.material.address, &self.material.epoch, journal, &id)
                .map_err(storage)?;
        let coordinated = ordering.order(anchor, destination).map_err(storage)?;
        Ok((coordinated.anchor, Some(coordinated.enrolled)))
    }

    fn now(&self) -> Result<i64> {
        self.clock_origin_ms
            .checked_add(i64::try_from(self.started.elapsed().as_millis()).map_err(storage)?)
            .ok_or(Refusal::Unavailable)
    }

    fn ready(&self) -> Result<()> {
        if self.poisoned {
            Err(Refusal::Unavailable)
        } else {
            Ok(())
        }
    }

    fn check_quota(&self, state: &State) -> Result<()> {
        let cap = &self.material.template.capability;
        if state.records.len() > cap.max_outstanding_calls as usize {
            return Err(Refusal::QueueFull(cap.max_outstanding_calls as usize));
        }
        let bytes = state
            .records
            .iter()
            .try_fold(0u64, |total, record| {
                total
                    .checked_add(u64::from(record.header.plaintext_len))?
                    .checked_add(u64::from(record.reply_capability.grant.max_payload_bytes))
            })
            .ok_or(Refusal::StorageFull)?;
        if bytes > cap.max_queue_contribution_bytes {
            return Err(Refusal::StorageFull);
        }
        Ok(())
    }

    fn charge_message(&self, state: &mut State, now: i64) -> Result<()> {
        state
            .recent_messages
            .retain(|time| *time > now.saturating_sub(60_000));
        let limit = (self.material.template.capability.max_messages_per_minute as usize)
            .min(MAX_RETAINED_CALLS);
        if state.recent_messages.len() >= limit {
            return Err(Refusal::QueueFull(limit));
        }
        state.recent_messages.push(now);
        Ok(())
    }

    fn commit(&mut self, mut state: State) -> Result<()> {
        self.ready()?;
        self.check_quota(&state)?;
        state.clock = self.now()?;
        let clear = Zeroizing::new(serde_json::to_vec(&state).map_err(storage)?);
        if clear
            .len()
            .checked_add(aead::NONCE_SIZE + aead::TAG_SIZE)
            .is_none_or(|size| size > (self.config.max_storage_bytes - CONTROL_STORAGE_BYTES) / 4)
        {
            return Err(Refusal::StorageFull);
        }
        let sealed = aead::seal(&self.material.state_key(), &clear, STATE_DOMAIN.as_bytes());
        if write_private(&self.config.directory.join("state"), &sealed).is_err() {
            self.poisoned = true;
            return Err(Refusal::Unavailable);
        }
        self.state = state;
        Ok(())
    }

    fn peer(&self, address: MailboxAddress) -> Result<ActorPeerBinding> {
        self.material
            .peer(&address)
            .map_err(|_| Refusal::NotAuthorized)
    }

    fn segment(&self, index: usize) -> Result<PathBuf> {
        let record = self
            .state
            .records
            .get(index)
            .ok_or(Refusal::NotAuthorized)?;
        Ok(self
            .config
            .directory
            .join(hex::encode(record.header.message_id.as_bytes())))
    }

    fn purpose_key(&self, id: MessageId, purpose: &[u8]) -> Key {
        let root = self.material.state_key();
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(root.expose_bytes())
            .expect("fixed key length");
        mac.update(purpose);
        mac.update(id.as_bytes());
        Key::from_bytes(mac.finalize().into_bytes().into())
    }

    fn journal(&self, index: usize) -> Result<(MailboxJournal, FileJournalAnchor)> {
        let record = self
            .state
            .records
            .get(index)
            .ok_or(Refusal::NotAuthorized)?;
        let directory = self.segment(index)?;
        // Only a recorded, not-yet-initialized intent may create its segment.
        if record.initialized {
            if !directory.join("journal").is_dir() {
                return Err(Refusal::Unavailable);
            }
        } else {
            std::fs::metadata(&self.config.directory).map_err(storage)?;
            private_fs::ensure_private_dir(&directory).map_err(storage)?;
            mvm_core::atomic_io::sync_dir(&self.config.directory).map_err(storage)?;
        }
        let id = record.header.message_id;
        let key = self.purpose_key(id, b"history");
        let reference = HistoryKeyRef::new(
            self.material.address,
            self.material.epoch,
            Sha256::digest(key.expose_bytes()).into(),
            1,
        )
        .map_err(storage)?;
        let custody = ScopedHistory { reference, key };
        let anchor = FileJournalAnchor::open(
            &directory.join("anchor"),
            self.material.address,
            *self.purpose_key(id, b"anchor").expose_bytes(),
        )
        .map_err(storage)?;
        let (anchor, enrolled) = self.ordered(anchor, ActorJournal::Call, id)?;
        let segment_bytes = ((self.config.max_storage_bytes - CONTROL_STORAGE_BYTES) / 4 * 3)
            / self.material.template.capability.max_outstanding_calls as usize;
        let journal = MailboxJournal::open_local_with_custody(
            &directory.join("journal"),
            reference,
            self.material.authority_key().verifying_key(),
            JournalLimits {
                max_records: MAX_SEGMENT_RECORDS,
                max_bytes: (segment_bytes.saturating_sub(4096) / 2) as u64,
            },
            &custody,
            &anchor,
            self.retention,
        )
        .map_err(storage)?;
        if let Some(enrolled) = &enrolled {
            require_reached(&anchor, enrolled).map_err(storage)?;
        }
        Ok((journal, anchor))
    }

    fn conversation(&self, index: usize, peer: &ActorPeerBinding) -> Result<Conversation> {
        let record = &self.state.records[index];
        if record.direction != Direction::Outbound {
            return Err(Refusal::NotAuthorized);
        }
        let (journal, anchor) = self.journal(index)?;
        let directory = self.segment(index)?.join("source");
        if record.initialized && !directory.join("state").is_file() {
            return Err(Refusal::Unavailable);
        }
        let segment_bytes = ((self.config.max_storage_bytes - CONTROL_STORAGE_BYTES) / 4 * 3)
            / self.material.template.capability.max_outstanding_calls as usize;
        Conversation::open(
            ConversationConfig {
                directory,
                address: self.material.address,
                epoch: self.material.epoch,
                policy_epoch: self.material.template.capability.policy_epoch,
                now_unix_ms: self.now()?,
                issuer: self.material.template.capability.issuer,
                authority: self.material.authority_key(),
                reply_key: peer.reply_key(),
                state_key: self.purpose_key(record.header.message_id, b"source-state"),
                limits: ConversationLimits {
                    max_calls: 1,
                    max_bytes: segment_bytes.saturating_sub(4096) / 2,
                    retention: self.retention,
                },
            },
            journal,
            anchor,
        )
        .map_err(storage)
    }

    fn initialize_call(&mut self, index: usize, peer: &ActorPeerBinding) -> Result<()> {
        let record = &self.state.records[index];
        if record.direction == Direction::Outbound {
            let mut conversation = self.conversation(index, peer)?;
            let policy = self.call_policy(peer, self.now()?)?;
            conversation
                .enqueue_call(CallAdmission {
                    envelope: &record.call,
                    capability: &peer.send_capability,
                    policy: &policy,
                    reply_capability: &record.reply_capability,
                    responder_key: &key(peer.child_sender_key)?,
                    deadline_unix_ms: record.header.expires_at_unix_ms,
                })
                .map_err(storage)?;
        } else {
            self.journal(index)?;
        }
        if !record.initialized {
            let mut next = self.state.clone();
            next.records[index].initialized = true;
            self.commit(next)?;
        }
        Ok(())
    }

    /// The service's reader/session gate has no application traffic of its own.
    /// Actor-mode transport must refuse legacy outbox and reader frames.
    pub(crate) fn control_journal(&self) -> Result<(MailboxJournal, FileJournalAnchor)> {
        let directory = self.config.directory.join("control");
        private_fs::ensure_private_dir(&directory).map_err(storage)?;
        mvm_core::atomic_io::sync_dir(&self.config.directory).map_err(storage)?;
        let id = MessageId::from_bytes([0; 32]);
        let key = self.purpose_key(id, b"control-history");
        let reference = HistoryKeyRef::new(
            self.material.address,
            self.material.epoch,
            Sha256::digest(key.expose_bytes()).into(),
            1,
        )
        .map_err(storage)?;
        let custody = ScopedHistory { reference, key };
        let anchor = FileJournalAnchor::open(
            &directory.join("anchor"),
            self.material.address,
            *self.purpose_key(id, b"control-anchor").expose_bytes(),
        )
        .map_err(storage)?;
        let (anchor, enrolled) = self.ordered(anchor, ActorJournal::Control, id)?;
        let journal = MailboxJournal::open_local_with_custody(
            &directory.join("journal"),
            reference,
            self.material.authority_key().verifying_key(),
            JournalLimits {
                max_records: 1,
                max_bytes: (CONTROL_STORAGE_BYTES / 2) as u64,
            },
            &custody,
            &anchor,
            self.retention,
        )
        .map_err(storage)?;
        if let Some(enrolled) = &enrolled {
            require_reached(&anchor, enrolled).map_err(storage)?;
        }
        Ok((journal, anchor))
    }

    fn queue_call(
        &mut self,
        boot: BootId,
        request: CallRequest<'_>,
    ) -> Result<ConversationResponse> {
        self.ready()?;
        let peer = self.peer(request.destination)?;
        if peer.role != ActorPeerRole::Parent {
            return Err(Refusal::NotAuthorized);
        }
        if request.payload.len() > peer.send_capability.grant.max_payload_bytes as usize {
            return Err(Refusal::Oversized(
                peer.send_capability.grant.max_payload_bytes as usize,
            ));
        }
        let now = self.now()?;
        if request.deadline <= now
            || request.deadline > peer.send_capability.grant.expires_at_unix_ms
        {
            return Err(Refusal::Expired);
        }
        if let Some(index) = self
            .state
            .records
            .iter()
            .position(|record| record.header.message_id == request.message_id)
        {
            let record = &self.state.records[index];
            if record.direction != Direction::Outbound
                || record.peer != request.destination
                || record.header.correlation_id != request.correlation_id
                || record.header.expires_at_unix_ms != request.deadline
                || record.header.content_type != *request.content_type
            {
                return Err(Refusal::NotAuthorized);
            }
            let policy = self.call_policy(&peer, now)?;
            let opened = mvm_core::mailbox::open_authenticated_envelope(
                &record.call,
                &peer.send_capability,
                &policy.context,
                &policy.encryption_key,
                &policy.sender_key,
                &policy.authority_key,
                &mut InMemoryReplayProtector::default(),
            )
            .map_err(|_| Refusal::NotAuthorized)?;
            if opened.payload() != request.payload {
                return Err(Refusal::NotAuthorized);
            }
            self.initialize_call(index, &peer)?;
            return Ok(ConversationResponse::Queued {
                call_message_id: request.message_id,
            });
        }
        if self
            .state
            .records
            .iter()
            .any(|record| record.header.correlation_id == request.correlation_id)
            || request.message_id.as_bytes() == &[0; 32]
            || request.correlation_id.as_bytes() == &[0; 32]
        {
            return Err(Refusal::NotAuthorized);
        }
        let mut reply = peer.parent_receive.grant.clone();
        reply.capability_id = CapabilityId::from_bytes(
            *self
                .purpose_key(request.message_id, b"reply-capability")
                .expose_bytes(),
        );
        reply.subject = peer.child_address.recipient;
        reply.operations = CapabilityOperations::from_operations(&[MailboxOperation::Reply]);
        reply.message_kinds = vec![MailboxMessageKind::Reply];
        reply.not_before_unix_ms = now;
        reply.expires_at_unix_ms = reply
            .expires_at_unix_ms
            .min(peer.send_capability.grant.expires_at_unix_ms);
        reply.max_outstanding_calls = 1;
        let reply = mvm_core::mailbox::sign_capability(reply, &self.material.authority_key())
            .map_err(storage)?;
        let mut header = peer.call.header.clone();
        header.message_id = request.message_id;
        header.correlation_id = request.correlation_id;
        header.causation_id = CausationId::from_bytes(*request.message_id.as_bytes());
        header.sender_boot = boot;
        header.nonce = ReplayNonce::from_bytes(rand::random());
        header.sequence =
            SequenceNumber::new(self.state.records.len() as u64 + 1).map_err(storage)?;
        header.issued_at_unix_ms = now;
        header.expires_at_unix_ms = request.deadline;
        header.content_type = request.content_type.clone();
        header.plaintext_len = request.payload.len().try_into().map_err(|_| {
            Refusal::Oversized(peer.send_capability.grant.max_payload_bytes as usize)
        })?;
        header.reply_to = Some(ReplyRoute {
            address: self.material.address,
            capability_id: reply.grant.capability_id,
        });
        let mut routing = peer.call.routing.clone();
        routing.delivery_id = DeliveryId::from_bytes(rand::random());
        routing.expires_at_unix_ms = request.deadline;
        let call = mvm_core::mailbox::seal_envelope(
            SealRequest {
                routing,
                header: header.clone(),
                plaintext: request.payload,
            },
            &peer.call_key(),
            &self.material.sender_key(),
        )
        .map_err(|_| Refusal::NotAuthorized)?;
        let policy = self.call_policy(&peer, now)?;
        mvm_core::mailbox::open_authenticated_envelope(
            &call,
            &peer.send_capability,
            &policy.context,
            &policy.encryption_key,
            &policy.sender_key,
            &policy.authority_key,
            &mut InMemoryReplayProtector::default(),
        )
        .map_err(|_| Refusal::NotAuthorized)?;
        let mut next = self.state.clone();
        self.charge_message(&mut next, now)?;
        next.records.push(Record {
            direction: Direction::Outbound,
            peer: request.destination,
            header,
            call,
            reply_capability: reply,
            initialized: false,
            call_receipt: None,
            reply: None,
            reply_header: None,
            reply_receipt: None,
            delivery: None,
            acknowledged: false,
            dispatch_attempts: 0,
        });
        self.commit(next)?;
        self.initialize_call(self.state.records.len() - 1, &peer)?;
        Ok(ConversationResponse::Queued {
            call_message_id: request.message_id,
        })
    }

    /// Return exact persisted frames; callers release their mutex before sending.
    pub fn pending_dispatches(&mut self) -> Result<Vec<ActorDispatch>> {
        self.ready()?;
        let mut pending = Vec::new();
        let mut charged = Vec::new();
        let mut exhausted = false;
        for index in 0..self.state.records.len() {
            let record = &self.state.records[index];
            if !((record.direction == Direction::Outbound && record.call_receipt.is_none())
                || (record.direction == Direction::Inbound
                    && record.reply.is_some()
                    && record.reply_receipt.is_none()))
            {
                continue;
            }
            let peer = self.peer(self.state.records[index].peer)?;
            let expires = match record.direction {
                Direction::Outbound => record.header.expires_at_unix_ms,
                Direction::Inbound => record
                    .reply_header
                    .as_ref()
                    .map_or(record.header.expires_at_unix_ms, |header| {
                        header.expires_at_unix_ms
                    }),
            };
            if expires <= self.now()? {
                continue;
            }
            self.initialize_call(index, &peer)?;
            let record = &self.state.records[index];
            if record.direction == Direction::Outbound && record.call_receipt.is_none() {
                if record.dispatch_attempts >= self.material.max_send_attempts {
                    exhausted = true;
                    continue;
                }
                charged.push(index);
                pending.push(ActorDispatch {
                    message_id: record.header.message_id,
                    peer,
                    frame: ActorPeerFrame::Call {
                        envelope: record.call.clone(),
                        reply_capability: Box::new(record.reply_capability.clone()),
                    },
                });
            } else if record.direction == Direction::Inbound
                && record.reply_receipt.is_none()
                && let (Some(envelope), Some(header)) = (&record.reply, &record.reply_header)
            {
                if record.dispatch_attempts >= self.material.max_send_attempts {
                    exhausted = true;
                    continue;
                }
                charged.push(index);
                pending.push(ActorDispatch {
                    message_id: header.message_id,
                    peer,
                    frame: ActorPeerFrame::Reply {
                        envelope: envelope.clone(),
                    },
                });
            }
        }
        if !pending.is_empty() {
            let mut next = self.state.clone();
            let now = self.now()?;
            for index in charged {
                self.charge_message(&mut next, now)?;
                next.records[index].dispatch_attempts = next.records[index]
                    .dispatch_attempts
                    .checked_add(1)
                    .ok_or(Refusal::RetriesExhausted)?;
            }
            self.commit(next)?;
        } else if exhausted {
            return Err(Refusal::RetriesExhausted);
        }
        Ok(pending)
    }

    /// Deadline of the exact retained call; never extended by a repeated wait.
    pub fn wait_deadline_unix_ms(&self, request: &ConversationRequest) -> Result<Option<i64>> {
        self.ready()?;
        match request {
            ConversationRequest::ReceiveResult { call_message_id } => self
                .state
                .records
                .iter()
                .find(|record| {
                    record.direction == Direction::Outbound
                        && record.header.message_id == *call_message_id
                })
                .map(|record| Some(record.header.expires_at_unix_ms))
                .ok_or(Refusal::NotAuthorized),
            ConversationRequest::Call { .. }
            | ConversationRequest::Receive {}
            | ConversationRequest::Reply { .. }
            | ConversationRequest::AckResult { .. }
            | ConversationRequest::AckRequest { .. }
            | ConversationRequest::Possession { .. } => Ok(None),
        }
    }

    /// Verify the destination's exact local-durable receipt before stopping retries.
    pub fn record_dispatch_receipt(
        &mut self,
        id: MessageId,
        receipt: SignedDestinationReceipt,
    ) -> Result<()> {
        self.ready()?;
        let (index, record) = self
            .state
            .records
            .iter()
            .enumerate()
            .find(|(_, record)| {
                (record.direction == Direction::Outbound && record.header.message_id == id)
                    || (record.direction == Direction::Inbound
                        && record
                            .reply_header
                            .as_ref()
                            .is_some_and(|header| header.message_id == id))
            })
            .ok_or(Refusal::NotAuthorized)?;
        let peer = self.peer(record.peer)?;
        let (header, envelope, authority) = if record.direction == Direction::Outbound {
            (&record.header, &record.call, peer.child_authority_key)
        } else {
            (
                record.reply_header.as_ref().ok_or(Refusal::Unavailable)?,
                record.reply.as_ref().ok_or(Refusal::Unavailable)?,
                peer.parent_authority_key,
            )
        };
        mvm_core::mailbox::verify_receipt(&receipt, &key(authority)?)
            .map_err(|_| Refusal::NotAuthorized)?;
        if receipt.receipt.outcome != DeliveryOutcome::AcceptedLocalDurable
            || receipt.receipt.message_id != header.message_id
            || receipt.receipt.address != address(header)
            || receipt.receipt.execution_epoch != header.execution_epoch
            || receipt.receipt.delivery_id != envelope.routing.delivery_id
            || receipt.receipt.ciphertext_commitment != envelope.ciphertext_commitment
        {
            return Err(Refusal::NotAuthorized);
        }
        let mut next = self.state.clone();
        if record.direction == Direction::Outbound {
            next.records[index].call_receipt = Some(receipt);
        } else {
            next.records[index].reply_receipt = Some(receipt);
        }
        self.commit(next)
    }

    /// Authenticate fixed-pair ingress before any destination journal allocation.
    pub fn accept_peer(&mut self, frame: ActorPeerFrame) -> Result<SignedDestinationReceipt> {
        self.ready()?;
        let peers = self.material.peers().map_err(storage)?;
        let matches: Vec<_> = peers
            .into_iter()
            .filter(|peer| match &frame {
                ActorPeerFrame::Call { envelope, .. } => {
                    peer.role == ActorPeerRole::Child
                        && peer.call.routing.destination_route_token
                            == envelope.routing.destination_route_token
                }
                ActorPeerFrame::Reply { envelope } => {
                    peer.role == ActorPeerRole::Parent
                        && peer.reply_routing.destination_route_token
                            == envelope.routing.destination_route_token
                }
            })
            .collect();
        if matches.len() != 1 {
            return Err(Refusal::NotAuthorized);
        }
        let peer = &matches[0];
        match frame {
            ActorPeerFrame::Call {
                envelope,
                reply_capability,
            } => self.accept_call(peer, envelope, *reply_capability),
            ActorPeerFrame::Reply { envelope } => self.accept_reply(peer, envelope),
        }
    }

    pub fn peer_for_route(
        &self,
        token: mvm_contract::protocol::mailbox::DestinationRouteToken,
    ) -> Result<ActorPeerBinding> {
        let mut matches = self
            .material
            .peers()
            .map_err(storage)?
            .into_iter()
            .filter(|peer| match peer.role {
                ActorPeerRole::Parent => peer.reply_routing.destination_route_token == token,
                ActorPeerRole::Child => peer.call.routing.destination_route_token == token,
            });
        let peer = matches.next().ok_or(Refusal::NotAuthorized)?;
        if matches.next().is_some() {
            return Err(Refusal::NotAuthorized);
        }
        Ok(peer)
    }

    fn accept_call(
        &mut self,
        peer: &ActorPeerBinding,
        envelope: MailboxEnvelope,
        reply: SignedMailboxCapability,
    ) -> Result<SignedDestinationReceipt> {
        let now = self.now()?;
        let policy = self.call_policy(peer, now)?;
        let opened = mvm_core::mailbox::open_authenticated_envelope(
            &envelope,
            &peer.send_capability,
            &policy.context,
            &policy.encryption_key,
            &policy.sender_key,
            &policy.authority_key,
            &mut InMemoryReplayProtector::default(),
        )
        .map_err(|_| Refusal::NotAuthorized)?;
        let header = opened.header().clone();
        mvm_core::mailbox::verify_capability_signature(&reply, &key(peer.parent_authority_key)?)
            .map_err(|_| Refusal::NotAuthorized)?;
        let grant = &reply.grant;
        let ceiling = &peer.parent_receive.grant;
        if header.reply_to
            != Some(ReplyRoute {
                address: peer.parent_address,
                capability_id: grant.capability_id,
            })
            || grant.address != peer.parent_address
            || grant.subject != peer.child_address.recipient
            || grant.issuer != ceiling.issuer
            || grant.policy_epoch != ceiling.policy_epoch
            || grant.operations != CapabilityOperations::from_operations(&[MailboxOperation::Reply])
            || grant.message_kinds != [MailboxMessageKind::Reply]
            || !grant
                .content_types
                .iter()
                .all(|kind| ceiling.content_types.contains(kind))
            || grant.minimum_execution_epoch != peer.epoch
            || grant.maximum_execution_epoch != peer.epoch
            || grant.max_payload_bytes > ceiling.max_payload_bytes
            || grant.max_messages_per_minute > ceiling.max_messages_per_minute
            || grant.max_outstanding_calls != 1
            || grant.max_queue_contribution_bytes > ceiling.max_queue_contribution_bytes
            || grant.not_before_unix_ms < ceiling.not_before_unix_ms
            || grant.not_before_unix_ms > now
            || grant.expires_at_unix_ms < header.expires_at_unix_ms
            || grant.expires_at_unix_ms > ceiling.expires_at_unix_ms
            || grant.expires_at_unix_ms > peer.send_capability.grant.expires_at_unix_ms
            || grant.delegation_depth != 0
        {
            return Err(Refusal::NotAuthorized);
        }
        let existing = self
            .state
            .records
            .iter()
            .position(|record| record.header.message_id == header.message_id);
        if let Some(index) = existing {
            let previous = &self.state.records[index];
            if previous.direction != Direction::Inbound
                || previous.peer != peer.parent_address
                || previous.call != envelope
                || previous.reply_capability != reply
            {
                return Err(Refusal::NotAuthorized);
            }
            if let Some(receipt) = self.accepted_receipt(index, &envelope, &peer.send_capability)? {
                return Ok(receipt);
            }
        }
        // After recovery, so a retry of a frame already accepted still gets
        // its receipt; only a new acceptance needs the unit to be current.
        self.admit_unit()?;
        let index = if let Some(index) = existing {
            index
        } else {
            if self.state.records.iter().any(|record| {
                record.header.correlation_id == header.correlation_id
                    || record.reply_capability.grant.capability_id == reply.grant.capability_id
            }) {
                return Err(Refusal::NotAuthorized);
            }
            let mut next = self.state.clone();
            self.charge_message(&mut next, now)?;
            next.records.push(Record {
                direction: Direction::Inbound,
                peer: peer.parent_address,
                header,
                call: envelope,
                reply_capability: reply,
                initialized: false,
                call_receipt: None,
                reply: None,
                reply_header: None,
                reply_receipt: None,
                delivery: None,
                acknowledged: false,
                dispatch_attempts: 0,
            });
            self.commit(next)?;
            self.state.records.len() - 1
        };
        self.initialize_call(index, peer)?;
        let record = &self.state.records[index];
        let (mut journal, anchor) = self.journal(index)?;
        journal
            .admit_local(
                JournalAdmission {
                    envelope: &record.call,
                    capability: &peer.send_capability,
                    context: &policy.context,
                    encryption_key: &policy.encryption_key,
                    sender_key: &policy.sender_key,
                    signer: &self.material.authority_key(),
                },
                &anchor,
            )
            .map_err(storage)
    }

    fn accept_reply(
        &mut self,
        peer: &ActorPeerBinding,
        envelope: MailboxEnvelope,
    ) -> Result<SignedDestinationReceipt> {
        for (index, record) in self.state.records.iter().enumerate() {
            if record.direction != Direction::Outbound || record.peer != peer.child_address {
                continue;
            }
            let context = self.context(
                &peer.reply_header,
                &record.reply_capability,
                self.now()?,
                MailboxOperation::Reply,
            );
            let opened = mvm_core::mailbox::open_authenticated_envelope(
                &envelope,
                &record.reply_capability,
                &context,
                &peer.reply_key(),
                &key(peer.child_sender_key)?,
                &key(peer.parent_authority_key)?,
                &mut InMemoryReplayProtector::default(),
            );
            let Ok(opened) = opened else {
                continue;
            };
            if opened.header().correlation_id != record.header.correlation_id
                || opened.header().causation_id
                    != CausationId::from_bytes(*record.header.message_id.as_bytes())
            {
                return Err(Refusal::NotAuthorized);
            }
            if let Some(receipt) =
                self.accepted_receipt(index, &envelope, &record.reply_capability)?
            {
                return Ok(receipt);
            }
            self.admit_unit()?;
            let mut conversation = self.conversation(index, peer)?;
            return conversation
                .accept_reply(
                    ReplayIdentity::from_header(&record.header),
                    &envelope,
                    &context,
                )
                .map_err(storage);
        }
        Err(Refusal::NotAuthorized)
    }
}

struct CallRequest<'a> {
    destination: MailboxAddress,
    message_id: MessageId,
    correlation_id: CorrelationId,
    deadline: i64,
    content_type: &'a ContentType,
    payload: &'a [u8],
}

impl ConversationOperations for ActorConversationEndpoint {
    fn wait_deadline_unix_ms(&self, request: &ConversationRequest) -> Result<Option<i64>> {
        ActorConversationEndpoint::wait_deadline_unix_ms(self, request)
    }

    fn peer_for_route(
        &self,
        token: mvm_contract::protocol::mailbox::DestinationRouteToken,
    ) -> Result<ActorPeerBinding> {
        ActorConversationEndpoint::peer_for_route(self, token)
    }

    fn pending_dispatches(&mut self) -> Result<Vec<ActorDispatch>> {
        ActorConversationEndpoint::pending_dispatches(self)
    }

    fn record_dispatch_receipt(
        &mut self,
        id: MessageId,
        receipt: SignedDestinationReceipt,
    ) -> Result<()> {
        ActorConversationEndpoint::record_dispatch_receipt(self, id, receipt)
    }

    fn accept_peer(&mut self, frame: ActorPeerFrame) -> Result<SignedDestinationReceipt> {
        ActorConversationEndpoint::accept_peer(self, frame)
    }

    fn execute(
        &mut self,
        authority: &CurrentBootAuthority,
        request: ConversationRequest,
    ) -> Result<ConversationResponse> {
        self.ready()?;
        if authority.binding() != &self.config.binding {
            return Err(Refusal::NotAuthorized);
        }
        match request {
            ConversationRequest::Call {
                destination,
                message_id,
                correlation_id,
                deadline_unix_ms,
                content_type,
                payload,
            } => self.queue_call(
                authority.binding().reader.boot,
                CallRequest {
                    destination,
                    message_id,
                    correlation_id,
                    deadline: deadline_unix_ms,
                    content_type: &content_type,
                    payload: &payload,
                },
            ),
            ConversationRequest::Receive {} => self.receive_request(authority),
            ConversationRequest::Reply {
                request_message_id,
                message_id,
                content_type,
                payload,
            } => self.queue_reply(
                authority.binding().reader.boot,
                ReplyRequest {
                    request_message_id,
                    message_id,
                    content_type: &content_type,
                    payload: &payload,
                },
            ),
            ConversationRequest::ReceiveResult { call_message_id } => {
                self.receive_result(authority, call_message_id)
            }
            ConversationRequest::AckRequest {
                request_message_id,
                lease,
                signed,
            } => self.acknowledge(
                authority,
                AckRequest {
                    direction: Direction::Inbound,
                    call_id: request_message_id,
                    delivered_id: request_message_id,
                    lease: &lease,
                    signed: signed.as_deref(),
                },
            ),
            ConversationRequest::AckResult {
                call_message_id,
                result_message_id,
                lease,
                signed,
            } => self.acknowledge(
                authority,
                AckRequest {
                    direction: Direction::Outbound,
                    call_id: call_message_id,
                    delivered_id: result_message_id,
                    lease: &lease,
                    signed: signed.as_deref(),
                },
            ),
            ConversationRequest::Possession { .. } => Err(Refusal::NotAuthorized),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor_lifecycle::{ActorMailboxes, local_mailboxes::LocalActorMailboxes};
    use crate::mailbox_launch::actor_template;
    use ed25519_dalek::SigningKey;
    use mvm_contract::protocol::mailbox::ExecutionEpoch;
    use mvm_core::mailbox::reader::MailboxReaderBootBinding;
    use std::sync::Arc;

    struct Pair {
        directory: tempfile::TempDir,
        owner: LocalActorMailboxes,
        parent_plan: ExecutionPlan,
        child_plan: ExecutionPlan,
        parent_binding: ConversationBinding,
        child_binding: ConversationBinding,
        parent: ActorConversationEndpoint,
        child: ActorConversationEndpoint,
        _environment: mvm_core::util::test_env::TestEnv,
    }

    fn binding(plan: &ExecutionPlan, address: MailboxAddress, seed: u8) -> ConversationBinding {
        ConversationBinding {
            reader: MailboxReaderBootBinding::mint(
                plan,
                SigningKey::from_bytes(&[seed; 32]).verifying_key(),
                SigningKey::from_bytes(&[seed + 1; 32])
                    .verifying_key()
                    .to_bytes(),
            )
            .unwrap(),
            address,
            policy_epoch: 1,
        }
    }

    fn open(
        directory: &std::path::Path,
        name: &str,
        plan: &ExecutionPlan,
        binding: &ConversationBinding,
    ) -> ActorConversationEndpoint {
        let current = ExecutionEpoch::new(plan.execution_epoch).unwrap();
        open_at(directory, name, plan, binding, current).unwrap()
    }

    fn open_at(
        directory: &std::path::Path,
        name: &str,
        plan: &ExecutionPlan,
        binding: &ConversationBinding,
        current_epoch: ExecutionEpoch,
    ) -> Result<ActorConversationEndpoint> {
        let material = actor_template::endpoint_material(directory, plan)
            .unwrap()
            .unwrap();
        ActorConversationEndpoint::open(
            ActorOperationConfig {
                plan: plan.clone(),
                binding: binding.clone(),
                directory: directory.join(name),
                max_storage_bytes: material.max_storage_bytes as usize,
                now_unix_ms: actor_template::current_time_ms().unwrap(),
                current_epoch,
            },
            material,
            |_| Ok(JournalOrder::Unordered),
        )
    }

    fn pair() -> Pair {
        let (directory, owner, parent_plan, mut child_plan, environment) =
            crate::actor_lifecycle::local_mailboxes::tests::setup();
        let derived = owner.derive(&parent_plan, &child_plan).unwrap();
        child_plan.mailbox = Some(derived.grant);
        child_plan.plan_id = mvm_core::plan::compute_plan_id(&child_plan);
        let parent_material = actor_template::endpoint_material(directory.path(), &parent_plan)
            .unwrap()
            .unwrap();
        actor_template::endpoint_material(directory.path(), &child_plan)
            .unwrap()
            .unwrap();
        let parent_binding = binding(&parent_plan, parent_material.address, 20);
        let child_binding = binding(&child_plan, derived.address, 30);
        let parent = open(
            directory.path(),
            "parent-state",
            &parent_plan,
            &parent_binding,
        );
        let child = open(directory.path(), "child-state", &child_plan, &child_binding);
        Pair {
            directory,
            owner,
            parent_plan,
            child_plan,
            parent_binding,
            child_binding,
            parent,
            child,
            _environment: environment,
        }
    }

    fn queue(
        store: &mut ActorConversationEndpoint,
        destination: MailboxAddress,
        id: u8,
        body: &[u8],
    ) -> Result<ConversationResponse> {
        let content_type = ContentType::parse("application/vnd.mvm.actor-test", 1).unwrap();
        let deadline = store.config.plan.valid_until.unix_millis() - 1000;
        store.queue_call(
            store.config.binding.reader.boot,
            CallRequest {
                destination,
                message_id: MessageId::from_bytes([id; 32]),
                correlation_id: CorrelationId::from_bytes([id; 32]),
                deadline,
                content_type: &content_type,
                payload: body,
            },
        )
    }

    fn authority(
        store: &ActorConversationEndpoint,
        ack_seed: u8,
        challenge_seed: u8,
    ) -> CurrentBootAuthority {
        use mvm_contract::protocol::mailbox::{
            ConsumerSessionId, MailboxGuestReaderEnrollment, ProtocolVersion, SignatureAlgorithm,
        };
        use mvm_core::mailbox::{conversation_wire, reader};
        let binding = store.config.binding.clone();
        let own = store.material.authority_key();
        let ack = SigningKey::from_bytes(&[ack_seed; 32]);
        let mut send = store.material.template.capability.clone();
        send.operations = CapabilityOperations::from_operations(&[MailboxOperation::Send]);
        let send = mvm_core::mailbox::sign_capability(send, &own).unwrap();
        let grant = store.config.plan.mailbox.unwrap();
        let capability = reader::mint_guest_receive_capability(
            &grant,
            &binding.reader,
            &send,
            binding.address,
            &own,
        )
        .unwrap();
        let enrollment = reader::sign_guest_reader_enrollment(
            MailboxGuestReaderEnrollment {
                protocol_version: ProtocolVersion::V1,
                signature_algorithm: SignatureAlgorithm::ED25519,
                plan_id: binding.reader.plan_id.clone(),
                plan_nonce: binding.reader.plan_nonce.clone(),
                address: binding.address,
                consumer: binding.address.recipient,
                consumer_boot: binding.reader.boot,
                consumer_session: ConsumerSessionId::from_bytes([99; 32]),
                receive_capability_id: capability.grant.capability_id,
                ack_public_key: ack.verifying_key().to_bytes(),
                execution_epoch: grant.epoch,
                policy_epoch: binding.policy_epoch,
                issued_at_unix_ms: capability.grant.not_before_unix_ms,
                expires_at_unix_ms: capability.grant.expires_at_unix_ms,
            },
            &own,
        )
        .unwrap();
        let reader = super::super::durable::GuestReaderAuthority {
            grant,
            boot: binding.reader.clone(),
            capability,
            enrollment,
            revocations_path: store.config.directory.join("revocations"),
        };
        let (mut host, mut guest) = std::os::unix::net::UnixStream::pair().unwrap();
        for stream in [&host, &guest] {
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
        }
        let guest_binding = binding.clone();
        let guest_ack = ack.clone();
        let guest = std::thread::spawn(move || {
            conversation_wire::guest_session(&mut guest, &guest_binding, guest_ack).unwrap()
        });
        use std::io::Read as _;
        let mut prefix = [0u8; 4];
        host.read_exact(&mut prefix).unwrap();
        let mut body = vec![0; u32::from_be_bytes(prefix) as usize];
        host.read_exact(&mut body).unwrap();
        assert!(conversation_wire::is_session_request(&body));
        let session = conversation_wire::host_session(&mut host, &binding, own).unwrap();
        let guest_session = guest.join().unwrap();
        let challenge = [challenge_seed; 32];
        let possession = reader::sign_reader_possession(&reader.enrollment, &challenge, &ack)
            .unwrap()
            .to_vec();
        assert!(
            CurrentBootAuthority::verify(
                &guest_session,
                &reader,
                store.now().unwrap(),
                &[],
                challenge,
                possession.clone()
            )
            .is_err()
        );
        CurrentBootAuthority::verify(
            &session,
            &reader,
            store.now().unwrap(),
            &[],
            challenge,
            possession,
        )
        .unwrap()
    }

    fn signed_ack(lease: &SignedMailboxDeliveryLease, ack_seed: u8) -> SignedMailboxDeliveryAck {
        use mvm_contract::protocol::mailbox::{
            DeliveryAckNonce, MailboxDeliveryAck, ProtocolVersion, SignatureAlgorithm,
        };
        mvm_core::mailbox::reader::sign_delivery_ack(
            MailboxDeliveryAck {
                protocol_version: ProtocolVersion::V1,
                signature_algorithm: SignatureAlgorithm::ED25519,
                lease: lease.clone(),
                ack_nonce: DeliveryAckNonce::from_bytes([ack_seed; 16]),
                acknowledged_at_unix_ms: lease.lease.issued_at_unix_ms,
            },
            &SigningKey::from_bytes(&[ack_seed; 32]),
        )
        .unwrap()
    }

    #[test]
    fn an_endpoint_opens_only_at_its_units_gated_epoch() {
        use crate::mailbox_service::bound_epoch;
        use crate::policy_generation::workload_store::OwnedWorkloadStore;
        use mvm_core::host_interface::workload::WorkloadChange;

        let pair = pair();
        let ledger = tempfile::tempdir().unwrap();
        let dir = pair.directory.path();
        let parent = pair.parent_plan.workload.0.clone();
        let child = pair.child_plan.workload.0.clone();
        let open_parent = |name: &str| {
            let current = bound_epoch(ledger.path(), &parent).unwrap();
            open_at(dir, name, &pair.parent_plan, &pair.parent_binding, current)
        };
        let open_child = |name: &str| {
            let current = bound_epoch(ledger.path(), &child).unwrap();
            open_at(dir, name, &pair.child_plan, &pair.child_binding, current)
        };
        assert!(open_parent("gated-parent-1").is_ok());
        assert!(open_child("gated-child-1").is_ok());

        let store = OwnedWorkloadStore::open(ledger.path()).unwrap();
        store
            .commit(&WorkloadChange::Replace {
                workload: parent.clone(),
                from_epoch: ExecutionEpoch::FIRST,
            })
            .unwrap();
        assert!(matches!(
            open_parent("gated-parent-2"),
            Err(Refusal::NotAuthorized)
        ));
        assert!(open_child("gated-child-2").is_ok());

        store
            .commit(&WorkloadChange::Quarantine {
                workload: child.clone(),
            })
            .unwrap();
        let refused = bound_epoch(ledger.path(), &child).unwrap_err();
        assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            bound_epoch(ledger.path(), &parent).unwrap(),
            ExecutionEpoch::new(2).unwrap()
        );
    }

    /// A second endpoint for the pair's child that asks the ledger under
    /// `ledger` before each peer frame, as the mailbox process binds it.
    fn gated_child(pair: &Pair, ledger: &std::path::Path) -> ActorConversationEndpoint {
        let gate = super::super::UnitGate::bind(ledger, &pair.child_plan.workload.0).unwrap();
        open(
            pair.directory.path(),
            "gated-child-state",
            &pair.child_plan,
            &pair.child_binding,
        )
        .gated(gate)
    }

    fn commit(
        ledger: &std::path::Path,
        change: mvm_core::host_interface::workload::WorkloadChange,
    ) {
        crate::policy_generation::workload_store::OwnedWorkloadStore::open(ledger)
            .unwrap()
            .commit(&change)
            .unwrap();
    }

    fn replaced(unit: &str) -> mvm_core::host_interface::workload::WorkloadChange {
        mvm_core::host_interface::workload::WorkloadChange::Replace {
            workload: unit.to_owned(),
            from_epoch: ExecutionEpoch::FIRST,
        }
    }

    fn dispatch_one(pair: &mut Pair) -> ActorDispatch {
        let child_address = pair.child_binding.address;
        queue(&mut pair.parent, child_address, 40, b"call").unwrap();
        pair.parent.pending_dispatches().unwrap().pop().unwrap()
    }

    #[test]
    fn a_running_endpoint_refuses_a_peer_frame_once_its_unit_is_replaced() {
        let mut pair = pair();
        let ledger = tempfile::tempdir().unwrap();
        let mut child = gated_child(&pair, ledger.path());
        let dispatch = dispatch_one(&mut pair);
        commit(ledger.path(), replaced(&pair.child_plan.workload.0));
        let stale = mvm_core::host_interface::Denial::StaleEpoch { got: 1, current: 2 };
        assert_eq!(
            child.accept_peer(dispatch.frame.clone()),
            Err(Refusal::Mailbox(stale.to_string()))
        );
        assert!(child.state.records.is_empty(), "nothing was recorded");
        // The frame itself is good: an endpoint that asks no ledger takes it.
        assert!(pair.child.accept_peer(dispatch.frame).is_ok());
    }

    #[test]
    fn a_running_endpoint_refuses_a_peer_frame_once_its_unit_is_quarantined() {
        let mut pair = pair();
        let ledger = tempfile::tempdir().unwrap();
        let mut child = gated_child(&pair, ledger.path());
        let dispatch = dispatch_one(&mut pair);
        let unit = pair.child_plan.workload.0.clone();
        commit(
            ledger.path(),
            mvm_core::host_interface::workload::WorkloadChange::Quarantine {
                workload: unit.clone(),
            },
        );
        let quarantined = mvm_core::host_interface::Denial::WorkloadQuarantined(unit);
        assert_eq!(
            child.accept_peer(dispatch.frame),
            Err(Refusal::Mailbox(quarantined.to_string()))
        );
    }

    #[test]
    fn a_retried_frame_accepted_before_the_replacement_still_gets_its_receipt() {
        let mut pair = pair();
        let ledger = tempfile::tempdir().unwrap();
        let mut child = gated_child(&pair, ledger.path());
        let dispatch = dispatch_one(&mut pair);
        let accepted = child.accept_peer(dispatch.frame.clone()).unwrap();
        commit(ledger.path(), replaced(&pair.child_plan.workload.0));
        assert_eq!(child.accept_peer(dispatch.frame), Ok(accepted));
        assert_eq!(child.state.records.len(), 1);
    }

    #[test]
    fn real_guest_sessions_and_signed_leases_deliver_reply_after_wait_deadline() {
        let mut pair = pair();
        let id = MessageId::from_bytes([40; 32]);
        let reply_id = MessageId::from_bytes([41; 32]);
        let content_type = ContentType::parse("application/vnd.mvm.actor-test", 1).unwrap();
        let deadline = pair.parent.now().unwrap() + 30_000;
        let proof = authority(&pair.parent, 21, 1);
        pair.parent
            .execute(
                &proof,
                ConversationRequest::Call {
                    destination: pair.child_binding.address,
                    message_id: id,
                    correlation_id: CorrelationId::from_bytes([40; 32]),
                    deadline_unix_ms: deadline,
                    content_type: content_type.clone(),
                    payload: b"call".to_vec(),
                },
            )
            .unwrap();
        let dispatch = pair.parent.pending_dispatches().unwrap().pop().unwrap();
        let receipt = pair.child.accept_peer(dispatch.frame).unwrap();
        pair.parent.record_dispatch_receipt(id, receipt).unwrap();
        let proof = authority(&pair.child, 31, 2);
        let ConversationResponse::Delivery { lease, payload, .. } = pair
            .child
            .execute(&proof, ConversationRequest::Receive {})
            .unwrap()
        else {
            panic!("request lease");
        };
        assert_eq!(payload, b"call");
        let proof = authority(&pair.child, 31, 3);
        assert!(
            pair.child
                .execute(
                    &proof,
                    ConversationRequest::AckRequest {
                        request_message_id: id,
                        lease: lease.clone(),
                        signed: None,
                    }
                )
                .is_err()
        );
        let signed = signed_ack(&lease, 31);
        pair.child
            .execute(
                &proof,
                ConversationRequest::AckRequest {
                    request_message_id: id,
                    lease: lease.clone(),
                    signed: Some(Box::new(signed)),
                },
            )
            .unwrap();
        let proof = authority(&pair.child, 31, 4);
        pair.child
            .execute(
                &proof,
                ConversationRequest::Reply {
                    request_message_id: id,
                    message_id: reply_id,
                    content_type,
                    payload: b"reply".to_vec(),
                },
            )
            .unwrap();
        let dispatch = pair.child.pending_dispatches().unwrap().pop().unwrap();
        assert!(dispatch.frame.envelope().routing.expires_at_unix_ms > deadline);
        let receipt = pair.parent.accept_peer(dispatch.frame).unwrap();
        pair.child
            .record_dispatch_receipt(reply_id, receipt)
            .unwrap();
        pair.parent.clock_origin_ms = deadline + 1;
        let proof = authority(&pair.parent, 21, 5);
        let ConversationResponse::Delivery {
            lease,
            payload,
            header,
        } = pair
            .parent
            .execute(
                &proof,
                ConversationRequest::ReceiveResult {
                    call_message_id: id,
                },
            )
            .unwrap()
        else {
            panic!("reply lease after wait deadline");
        };
        assert_eq!(payload, b"reply");
        assert_eq!(header.message_id, reply_id);
        let signed = signed_ack(&lease, 21);
        let proof = authority(&pair.parent, 21, 6);
        let ack = ConversationRequest::AckResult {
            call_message_id: id,
            result_message_id: reply_id,
            lease,
            signed: Some(Box::new(signed)),
        };
        assert_eq!(
            pair.parent.execute(&proof, ack.clone()).unwrap(),
            ConversationResponse::Acknowledged
        );
        assert_eq!(
            pair.parent.execute(&proof, ack).unwrap(),
            ConversationResponse::Acknowledged
        );
        assert_eq!(
            pair.parent
                .execute(
                    &proof,
                    ConversationRequest::ReceiveResult {
                        call_message_id: id
                    }
                )
                .unwrap(),
            ConversationResponse::Settled
        );
    }

    #[test]
    fn source_intent_and_destination_receipt_survive_reopen_with_exact_replay() {
        let mut pair = pair();
        let child_address = pair.child_binding.address;
        queue(
            &mut pair.parent,
            child_address,
            40,
            b"PRIVATE_ACTOR_PAYLOAD",
        )
        .unwrap();
        let original = pair.parent.pending_dispatches().unwrap().pop().unwrap();
        let exact_frame = original.frame.clone();
        let accepted = pair.child.accept_peer(original.frame).unwrap();
        assert_eq!(
            accepted.receipt.outcome,
            DeliveryOutcome::AcceptedLocalDurable
        );
        assert_eq!(pair.child.state.records.len(), 1);
        assert!(
            pair.child
                .queue_reply(
                    pair.child_binding.reader.boot,
                    ReplyRequest {
                        request_message_id: MessageId::from_bytes([40; 32]),
                        message_id: MessageId::from_bytes([41; 32]),
                        content_type: &ContentType::parse("application/vnd.mvm.actor-test", 1)
                            .unwrap(),
                        payload: b"not delivered yet",
                    }
                )
                .is_err()
        );
        drop(pair.parent);
        drop(pair.child);
        let mut parent = open(
            pair.directory.path(),
            "parent-state",
            &pair.parent_plan,
            &pair.parent_binding,
        );
        let mut child = open(
            pair.directory.path(),
            "child-state",
            &pair.child_plan,
            &pair.child_binding,
        );
        let replay = parent.pending_dispatches().unwrap().pop().unwrap();
        assert_eq!(replay.frame, exact_frame);
        let retried = child.accept_peer(replay.frame).unwrap();
        assert_eq!(retried, accepted);
        let mut wrong = retried.clone();
        wrong.receipt.message_id = MessageId::from_bytes([99; 32]);
        assert!(
            parent
                .record_dispatch_receipt(original.message_id, wrong)
                .is_err()
        );
        assert_eq!(parent.pending_dispatches().unwrap().len(), 1);
        parent
            .record_dispatch_receipt(original.message_id, retried)
            .unwrap();
        assert!(parent.pending_dispatches().unwrap().is_empty());
        queue(&mut parent, child_address, 40, b"PRIVATE_ACTOR_PAYLOAD").unwrap();
        assert!(queue(&mut parent, child_address, 40, b"conflicting body").is_err());
        assert_eq!(parent.state.records.len(), 1);
        let bytes = std::fs::read(pair.directory.path().join("parent-state/state")).unwrap();
        assert!(
            !bytes
                .windows(21)
                .any(|part| part == b"PRIVATE_ACTOR_PAYLOAD")
        );
    }

    #[test]
    fn each_peer_shares_the_same_aggregate_payload_and_retention_bound() {
        let mut pair = pair();
        let mut sibling = pair.child_plan.clone();
        sibling.workload.0 = "another-child".into();
        let mailbox = pair.owner.derive(&pair.parent_plan, &sibling).unwrap();
        sibling.mailbox = Some(mailbox.grant);
        sibling.plan_id = mvm_core::plan::compute_plan_id(&sibling);
        actor_template::endpoint_material(pair.directory.path(), &sibling)
            .unwrap()
            .unwrap();
        let body = vec![1; 1024];
        queue(&mut pair.parent, pair.child_binding.address, 40, &body).unwrap();
        queue(&mut pair.parent, mailbox.address, 41, &body).unwrap();
        assert_eq!(
            queue(&mut pair.parent, mailbox.address, 42, &body).unwrap_err(),
            Refusal::StorageFull
        );
        assert_eq!(pair.parent.state.records.len(), 2);
        let mut retained = pair.parent.state.clone();
        retained.records[0].acknowledged = true;
        retained.records[1].acknowledged = true;
        assert_eq!(retained.records.len(), 2);
        pair.parent.commit(retained).unwrap();
        assert!(queue(&mut pair.parent, mailbox.address, 42, &body).is_err());
    }

    #[test]
    fn dispatch_attempts_survive_restart_and_waits_keep_the_original_deadline() {
        let mut pair = pair();
        queue(&mut pair.parent, pair.child_binding.address, 40, b"payload").unwrap();
        let wait = ConversationRequest::ReceiveResult {
            call_message_id: MessageId::from_bytes([40; 32]),
        };
        let deadline = pair.parent.state.records[0].header.expires_at_unix_ms;
        assert_eq!(
            pair.parent.wait_deadline_unix_ms(&wait).unwrap(),
            Some(deadline)
        );
        assert!(
            pair.parent
                .wait_deadline_unix_ms(&ConversationRequest::ReceiveResult {
                    call_message_id: MessageId::from_bytes([99; 32]),
                })
                .is_err()
        );
        for attempt in 1..=pair.parent.material.max_send_attempts {
            assert_eq!(pair.parent.pending_dispatches().unwrap().len(), 1);
            assert_eq!(pair.parent.state.records[0].dispatch_attempts, attempt);
        }
        assert!(matches!(
            pair.parent.pending_dispatches(),
            Err(Refusal::RetriesExhausted)
        ));
        drop(pair.parent);
        let mut parent = open(
            pair.directory.path(),
            "parent-state",
            &pair.parent_plan,
            &pair.parent_binding,
        );
        assert!(matches!(
            parent.pending_dispatches(),
            Err(Refusal::RetriesExhausted)
        ));
        assert_eq!(parent.wait_deadline_unix_ms(&wait).unwrap(), Some(deadline));
    }

    #[test]
    fn delivery_worker_retries_exact_peer_without_an_unrelated_wakeup() {
        use super::super::{durable, peer_transport};
        use std::io::Read as _;
        use std::os::fd::AsRawFd as _;
        use std::os::unix::net::{UnixListener, UnixStream};
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
            mpsc,
        };
        use std::time::Duration;

        let mut pair = pair();
        // The canonical workload names are shared by fixtures; only this pair
        // may own the retry listener, without mutating process-global MVM_HOME.
        pair.parent
            .material
            .set_test_peer_socket(
                &pair.child_binding.address,
                pair.directory.path().join("retry-peer.sock"),
            )
            .unwrap();
        queue(&mut pair.parent, pair.child_binding.address, 40, b"payload").unwrap();
        let expected = pair.parent.state.records[0].call.clone();
        let peer = pair.parent.peer(pair.child_binding.address).unwrap();
        let child_peer = pair.child.peer(pair.parent_binding.address).unwrap();
        let signer = pair.parent.material.authority_key();
        let child_signer = pair.child.material.authority_key();
        let operations: Mutex<Box<dyn ConversationOperations>> = Mutex::new(Box::new(pair.parent));
        let stop = Arc::new(AtomicBool::new(false));
        let (wake, events) = mpsc::sync_channel(1);
        let (failed, first_failure) = mpsc::sync_channel(1);
        let (ready, listener_ready) = mpsc::sync_channel(1);
        let (mut accepted, notify) = UnixStream::pair().unwrap();
        accepted
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        notify.set_nonblocking(true).unwrap();
        let worker_stop = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            let mut first = true;
            durable::delivery_loop(&events, &worker_stop, || {
                let retry = durable::dispatch_pending(&operations, &signer, &worker_stop, &notify);
                if first {
                    first = false;
                    failed.send(retry).unwrap();
                    listener_ready.recv_timeout(Duration::from_secs(3)).unwrap();
                }
                retry
            });
            operations
                .lock()
                .unwrap()
                .pending_dispatches()
                .unwrap()
                .is_empty()
        });
        assert!(first_failure.recv_timeout(Duration::from_secs(3)).unwrap());
        let listener = UnixListener::bind(&peer.peer_socket).unwrap();
        ready.send(()).unwrap(); // Release the test barrier, not the worker's wake channel.
        let receiver = std::thread::spawn(move || {
            let mut fd = libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: fd points to one initialized pollfd for a live listener.
            assert_eq!(unsafe { libc::poll(&mut fd, 1, 3_000) }, 1);
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let preface =
                super::super::read_frame(peer_transport::PREFACE_BYTES, &mut stream).unwrap();
            peer_transport::route_from_preface(&preface).unwrap();
            peer_transport::receive_peer(&mut stream, &child_peer, child_signer, |frame| {
                assert_eq!(frame.envelope(), &expected);
                pair.child.accept_peer(frame)
            })
            .unwrap();
        });
        let acceptance = accepted.read_exact(&mut [0]);
        stop.store(true, Ordering::SeqCst);
        wake.try_send(()).unwrap();
        let settled = worker.join().unwrap();
        receiver.join().unwrap();
        acceptance.unwrap();
        assert!(
            settled,
            "only the verified, committed receipt settles dispatch"
        );
    }

    #[test]
    fn delivery_worker_stops_scheduling_at_persisted_budget_or_expiry() {
        use super::super::durable;
        use std::os::unix::net::UnixStream;
        use std::sync::{Mutex, atomic::AtomicBool};

        for expired in [false, true] {
            let mut pair = pair();
            pair.parent
                .material
                .set_test_peer_socket(
                    &pair.child_binding.address,
                    pair.directory.path().join("unavailable-peer.sock"),
                )
                .unwrap();
            pair.parent.material.max_send_attempts = 1;
            queue(&mut pair.parent, pair.child_binding.address, 40, b"payload").unwrap();
            if expired {
                pair.parent.clock_origin_ms =
                    pair.parent.state.records[0].header.expires_at_unix_ms;
            }
            let signer = pair.parent.material.authority_key();
            let operations: Mutex<Box<dyn ConversationOperations>> =
                Mutex::new(Box::new(pair.parent));
            let (_events, notify) = UnixStream::pair().unwrap();
            let stop = AtomicBool::new(false);
            assert_eq!(
                durable::dispatch_pending(&operations, &signer, &stop, &notify),
                !expired
            );
            assert!(!durable::dispatch_pending(
                &operations,
                &signer,
                &stop,
                &notify
            ));
        }
    }

    #[test]
    fn bad_ingress_unknown_route_and_corrupt_state_never_gain_an_acceptance() {
        let mut pair = pair();
        queue(&mut pair.parent, pair.child_binding.address, 40, b"payload").unwrap();
        let mut frame = pair
            .parent
            .pending_dispatches()
            .unwrap()
            .pop()
            .unwrap()
            .frame;
        if let ActorPeerFrame::Call {
            reply_capability, ..
        } = &mut frame
        {
            reply_capability.signature[0] ^= 1;
        }
        assert!(pair.child.accept_peer(frame).is_err());
        assert!(pair.child.state.records.is_empty());
        assert!(
            pair.child
                .peer_for_route(
                    mvm_contract::protocol::mailbox::DestinationRouteToken::from_bytes([0; 32])
                )
                .is_err()
        );
        let path = pair.parent.config.directory.clone();
        drop(pair.parent);
        std::fs::write(path.join("state"), b"truncated").unwrap();
        let material = actor_template::endpoint_material(pair.directory.path(), &pair.parent_plan)
            .unwrap()
            .unwrap();
        assert!(
            ActorConversationEndpoint::open(
                ActorOperationConfig {
                    plan: pair.parent_plan,
                    binding: pair.parent_binding,
                    directory: path,
                    max_storage_bytes: material.max_storage_bytes as usize,
                    now_unix_ms: actor_template::current_time_ms().unwrap(),
                    current_epoch: mvm_contract::protocol::mailbox::ExecutionEpoch::new(1).unwrap(),
                },
                material,
                |_| Ok(JournalOrder::Unordered),
            )
            .is_err()
        );
    }

    mod ordered {
        use super::*;
        use crate::mailbox_commit::{
            ActorJournal, ActorOrdering, OrderingFlags, actor_destination_id,
        };
        use crate::policy_generation::workload_store::OwnedWorkloadStore;
        use mvm_core::host_interface::workload::{
            CanonicalLedger, WorkloadChange, read_ledger_bytes_at,
        };
        use std::sync::atomic::Ordering;

        /// A pair whose child, the endpoint that accepts calls, is ordered.
        struct Ordered {
            pair: Pair,
            store: Arc<OwnedWorkloadStore>,
            ordering: Arc<ActorOrdering>,
        }

        fn ordered() -> Ordered {
            let mut pair = pair();
            let store = Arc::new(OwnedWorkloadStore::open(pair.directory.path()).unwrap());
            let ordering = Arc::new(ActorOrdering {
                authority: store.clone(),
                key: SigningKey::from_bytes(&[77; 32]),
                workload: pair.child_plan.workload.0.clone(),
                epoch: mvm_contract::protocol::mailbox::ExecutionEpoch::new(
                    pair.child_plan.execution_epoch,
                )
                .unwrap(),
                flags: OrderingFlags::default(),
            });
            pair.child.ordering = JournalOrder::Ledger(Arc::clone(&ordering));
            Ordered {
                pair,
                store,
                ordering,
            }
        }

        fn ledger(ordered: &Ordered) -> CanonicalLedger {
            let bytes = read_ledger_bytes_at(ordered.pair.directory.path())
                .unwrap()
                .unwrap();
            serde_json::from_slice(&bytes).unwrap()
        }

        fn id_of(ordered: &Ordered, journal: ActorJournal, message: u8) -> String {
            let material = &ordered.pair.child.material;
            actor_destination_id(
                &material.address,
                &material.epoch,
                journal,
                &MessageId::from_bytes([message; 32]),
            )
            .unwrap()
        }

        /// The parent queues call `id`; the child accepts it.
        fn deliver(ordered: &mut Ordered, id: u8) -> Result<SignedDestinationReceipt> {
            let destination = ordered.pair.child_binding.address;
            queue(&mut ordered.pair.parent, destination, id, b"call").unwrap();
            let dispatch = ordered
                .pair
                .parent
                .pending_dispatches()
                .unwrap()
                .into_iter()
                .find(|dispatch| dispatch.message_id == MessageId::from_bytes([id; 32]))
                .unwrap();
            ordered.pair.child.accept_peer(dispatch.frame)
        }

        fn quarantine(ordered: &Ordered) {
            ordered
                .store
                .commit(&WorkloadChange::Quarantine {
                    workload: ordered.pair.child_plan.workload.0.clone(),
                })
                .unwrap();
        }

        #[test]
        fn accepting_a_call_advances_that_calls_destination_and_the_control_journal_is_another() {
            let mut ordered = ordered();
            deliver(&mut ordered, 1).unwrap();
            let call = id_of(&ordered, ActorJournal::Call, 1);
            assert!(ledger(&ordered).destinations[&call].tip.cursor >= 1);

            ordered.pair.child.control_journal().unwrap();
            let control = id_of(&ordered, ActorJournal::Control, 0);
            assert_ne!(call, control);
            assert!(ledger(&ordered).destinations.contains_key(&control));
        }

        #[test]
        fn after_a_quarantine_a_new_call_is_refused_and_an_open_segments_anchor_is_untouched() {
            let mut ordered = ordered();
            deliver(&mut ordered, 1).unwrap();
            let anchor = ordered.pair.child.segment(0).unwrap().join("anchor");
            let before = std::fs::read(&anchor).unwrap();
            quarantine(&ordered);

            assert!(
                deliver(&mut ordered, 2).is_err(),
                "a refused ordering is never a success"
            );
            assert!(ordered.ordering.flags.refused.load(Ordering::SeqCst));
            assert!(!ordered.ordering.flags.unknown.load(Ordering::SeqCst));
            assert_eq!(std::fs::read(&anchor).unwrap(), before);
        }

        #[test]
        fn a_call_accepted_before_a_quarantine_still_opens_and_reaches_its_tip() {
            let mut ordered = ordered();
            deliver(&mut ordered, 1).unwrap();
            quarantine(&ordered);
            ordered.pair.child.journal(0).unwrap();
            assert!(!ordered.ordering.flags.refused.load(Ordering::SeqCst));
        }
    }
}
