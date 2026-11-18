use super::*;
use mvm_contract::protocol::mailbox::*;
use mvm_core::mailbox::journal::{HistoryKeyCustody, HistoryKeyRef, JournalLimits};
use mvm_core::mailbox::{SealRequest, seal_envelope, sign_capability};

const NOW: i64 = 1_000;
const DEADLINE: i64 = NOW + 60_000;
const EXPIRES: i64 = NOW + 120_000;
const PAYLOAD: &[u8] = b"application secret result";

struct Fixture {
    dir: tempfile::TempDir,
    authority: SigningKey,
    caller: SigningKey,
    responder: SigningKey,
    payload_key: Key,
    header: MailboxEnvelopeHeader,
    send: SignedMailboxCapability,
    reply: SignedMailboxCapability,
    receive: SignedMailboxCapability,
}

struct Custody;
impl HistoryKeyCustody for Custody {
    fn load_existing(&self, _: &HistoryKeyRef) -> Result<Key, JournalError> {
        Ok(Key::from_bytes([39; 32]))
    }
}

fn address(recipient: u8) -> MailboxAddress {
    MailboxAddress {
        tenant: TenantId::from_bytes([1; 32]),
        authorization_domain: AuthorizationDomainId::from_bytes([2; 32]),
        mailbox: MailboxId::from_bytes([recipient; 32]),
        recipient: PrincipalId::from_bytes([recipient; 32]),
    }
}

impl Fixture {
    fn new() -> Self {
        let authority = SigningKey::from_bytes(&[30; 32]);
        let content_type = ContentType::parse("application/octet-stream", 1).unwrap();
        let epoch = ExecutionEpoch::new(1).unwrap();
        let make_grant = |id, subject, destination, operation, kind| {
            sign_capability(
                MailboxCapabilityGrant {
                    protocol_version: ProtocolVersion::V1,
                    signature_algorithm: SignatureAlgorithm::ED25519,
                    capability_id: CapabilityId::from_bytes([id; 32]),
                    issuer: PrincipalId::from_bytes([9; 32]),
                    subject: PrincipalId::from_bytes([subject; 32]),
                    address: address(destination),
                    operations: CapabilityOperations::from_operations(&[operation]),
                    message_kinds: vec![kind],
                    content_types: vec![content_type.clone()],
                    max_payload_bytes: 1024,
                    max_messages_per_minute: 10,
                    max_outstanding_calls: 2,
                    max_queue_contribution_bytes: 4096,
                    minimum_execution_epoch: epoch,
                    maximum_execution_epoch: epoch,
                    policy_epoch: 1,
                    not_before_unix_ms: 900,
                    expires_at_unix_ms: EXPIRES,
                    revocation_id: RevocationId::from_bytes([id; 32]),
                    delegation_depth: 0,
                },
                &authority,
            )
            .unwrap()
        };
        let send = make_grant(10, 3, 4, MailboxOperation::Send, MailboxMessageKind::Call);
        let reply = make_grant(11, 4, 3, MailboxOperation::Reply, MailboxMessageKind::Reply);
        let receive = make_grant(
            12,
            3,
            3,
            MailboxOperation::Receive,
            MailboxMessageKind::Reply,
        );
        Self {
            dir: tempfile::tempdir().unwrap(),
            authority,
            caller: SigningKey::from_bytes(&[31; 32]),
            responder: SigningKey::from_bytes(&[32; 32]),
            payload_key: Key::from_bytes([33; 32]),
            header: MailboxEnvelopeHeader {
                protocol_version: ProtocolVersion::V1,
                signature_algorithm: SignatureAlgorithm::ED25519,
                tenant: address(3).tenant,
                authorization_domain: address(3).authorization_domain,
                sender: address(3).recipient,
                recipient: address(4).recipient,
                mailbox: address(4).mailbox,
                sender_boot: BootId::from_bytes([5; 32]),
                execution_epoch: epoch,
                message_id: MessageId::from_bytes([6; 32]),
                correlation_id: CorrelationId::from_bytes([7; 32]),
                causation_id: CausationId::from_bytes([8; 32]),
                kind: MailboxMessageKind::Call,
                reply_to: Some(ReplyRoute {
                    address: address(3),
                    capability_id: reply.grant.capability_id,
                }),
                ordering_scope: OrderingScope::parse("calls").unwrap(),
                sequence: SequenceNumber::new(1).unwrap(),
                issued_at_unix_ms: 900,
                expires_at_unix_ms: EXPIRES,
                nonce: ReplayNonce::from_bytes([9; 16]),
                content_type,
                capability_id: send.grant.capability_id,
                policy_epoch: 1,
                encryption: EncryptionContext {
                    algorithm: EncryptionAlgorithm::AES_256_GCM,
                    key_id: [34; 32],
                },
                plaintext_len: u32::try_from(PAYLOAD.len()).unwrap(),
            },
            send,
            reply,
            receive,
        }
    }

    fn open(&self) -> Conversation {
        self.try_open().unwrap()
    }

    fn try_open(&self) -> Result<Conversation, ConversationError> {
        let anchor =
            FileJournalAnchor::open(&self.dir.path().join("anchor/tip"), address(3), [35; 32])
                .unwrap();
        let retention = MailboxRetentionPolicy::new(1_000).unwrap();
        let journal = MailboxJournal::open_local_with_custody(
            &self.dir.path().join("journal"),
            HistoryKeyRef::new(address(3), self.header.execution_epoch, [36; 32], 1).unwrap(),
            self.authority.verifying_key(),
            JournalLimits {
                max_records: 32,
                max_bytes: 1_000_000,
            },
            &Custody,
            &anchor,
            retention,
        )
        .unwrap();
        Conversation::open(
            ConversationConfig {
                directory: self.dir.path().join("outbox"),
                address: address(3),
                epoch: self.header.execution_epoch,
                policy_epoch: 1,
                now_unix_ms: NOW,
                issuer: PrincipalId::from_bytes([9; 32]),
                authority: self.authority.clone(),
                reply_key: Key::from_bytes(*self.payload_key.expose_bytes()),
                state_key: Key::from_bytes([37; 32]),
                limits: ConversationLimits {
                    max_calls: 4,
                    max_bytes: 100_000,
                    retention,
                },
            },
            journal,
            anchor,
        )
    }

    fn context(&self, operation: MailboxOperation) -> OpenContext {
        let (sender, recipient, actor) = if operation == MailboxOperation::Send {
            (3, 4, 3)
        } else if operation == MailboxOperation::Reply {
            (4, 3, 4)
        } else {
            (4, 3, 3)
        };
        OpenContext {
            expected_tenant: address(3).tenant,
            expected_authorization_domain: address(3).authorization_domain,
            expected_mailbox: address(recipient).mailbox,
            expected_sender: address(sender).recipient,
            expected_recipient: address(recipient).recipient,
            acting_principal: address(actor).recipient,
            expected_capability_issuer: PrincipalId::from_bytes([9; 32]),
            current_execution_epoch: self.header.execution_epoch,
            current_policy_epoch: 1,
            required_operation: operation,
            now_unix_ms: NOW,
            accepted_content_types: vec![self.header.content_type.clone()],
            revoked_capabilities: vec![],
        }
    }

    fn seal(&self, header: MailboxEnvelopeHeader, signer: &SigningKey) -> MailboxEnvelope {
        seal_envelope(
            SealRequest {
                routing: MailboxRoutingFrame {
                    protocol_version: ProtocolVersion::V1,
                    authorization_domain_route_label: AuthorizationDomainRouteLabel::from_bytes(
                        [20; 32],
                    ),
                    destination_route_token: DestinationRouteToken::from_bytes([21; 32]),
                    delivery_id: DeliveryId::from_bytes(*header.message_id.as_bytes()),
                    ciphertext_len: 0,
                    padding: CiphertextPadding::Exact,
                    expires_at_unix_ms: header.expires_at_unix_ms,
                    hop_limit: 1,
                    transport_binding_id: TransportBindingId::from_bytes([22; 32]),
                },
                header,
                plaintext: PAYLOAD,
            },
            &self.payload_key,
            signer,
        )
        .unwrap()
    }

    fn enqueue(&self, conversation: &mut Conversation) -> ReplayIdentity {
        let envelope = self.seal(self.header.clone(), &self.caller);
        self.enqueue_envelope(conversation, &envelope).unwrap()
    }

    fn enqueue_envelope(
        &self,
        conversation: &mut Conversation,
        envelope: &MailboxEnvelope,
    ) -> Result<ReplayIdentity, ConversationError> {
        conversation.enqueue_call(CallAdmission {
            envelope,
            capability: &self.send,
            policy: &MailboxPolicy {
                context: self.context(MailboxOperation::Send),
                encryption_key: Key::from_bytes(*self.payload_key.expose_bytes()),
                sender_key: self.caller.verifying_key(),
                authority_key: self.authority.verifying_key(),
            },
            reply_capability: &self.reply,
            responder_key: &self.responder.verifying_key(),
            deadline_unix_ms: DEADLINE,
        })
    }

    fn reply_header(&self) -> MailboxEnvelopeHeader {
        let mut header = self.header.clone();
        header.sender = address(4).recipient;
        header.recipient = address(3).recipient;
        header.mailbox = address(3).mailbox;
        header.kind = MailboxMessageKind::Reply;
        header.reply_to = None;
        header.causation_id = CausationId::from_bytes(*self.header.message_id.as_bytes());
        header.message_id = MessageId::from_bytes([40; 32]);
        header.capability_id = self.reply.grant.capability_id;
        header
    }

    fn reply(&self) -> MailboxEnvelope {
        self.seal(self.reply_header(), &self.responder)
    }
}

#[test]
fn durable_reopen_replays_same_reply_until_explicit_ack() {
    let f = Fixture::new();
    let mut c = f.open();
    let id = f.enqueue(&mut c);
    let original = c.sealed_call(id).unwrap().1.clone();
    assert!(matches!(
        c.receive_result(id, &f.receive, &f.context(MailboxOperation::Receive))
            .unwrap(),
        CallResult::Pending
    ));
    drop(c);
    let mut c = f.open();
    assert_eq!(c.sealed_call(id).unwrap().1, &original);
    assert_eq!(f.enqueue_envelope(&mut c, &original).unwrap(), id);
    let reply = f.reply();
    let receipt = c
        .accept_reply(id, &reply, &f.context(MailboxOperation::Reply))
        .unwrap();
    assert_eq!(receipt.receipt.protocol_version, ProtocolVersion::V2);
    assert_eq!(
        receipt.receipt.outcome,
        DeliveryOutcome::AcceptedLocalDurable
    );
    assert_eq!(
        c.accept_reply(id, &reply, &f.context(MailboxOperation::Reply))
            .unwrap(),
        receipt
    );
    let mut duplicate = f.reply_header();
    duplicate.message_id = MessageId::from_bytes([80; 32]);
    assert!(
        c.accept_reply(
            id,
            &f.seal(duplicate, &f.responder),
            &f.context(MailboxOperation::Reply)
        )
        .is_err(),
        "a second application result cannot replace the accepted exact reply"
    );
    drop(c);
    let mut c = f.open();
    for _ in 0..2 {
        let CallResult::Reply(opened) = c
            .receive_result(id, &f.receive, &f.context(MailboxOperation::Receive))
            .unwrap()
        else {
            panic!("result must replay");
        };
        assert_eq!(opened.payload(), PAYLOAD);
        assert_eq!(opened.header().message_id, receipt.receipt.message_id);
        assert_eq!(opened.header().correlation_id, f.header.correlation_id);
    }
    c.acknowledge_result(id, &f.receive, &f.context(MailboxOperation::Receive))
        .unwrap();
    drop(c);
    let mut c = f.open();
    assert!(matches!(
        c.receive_result(id, &f.receive, &f.context(MailboxOperation::Receive))
            .unwrap(),
        CallResult::Settled
    ));
    assert!(
        c.accept_reply(id, &reply, &f.context(MailboxOperation::Reply))
            .is_err()
    );
}

#[test]
fn wrong_reply_scope_never_enters_journal() {
    let f = Fixture::new();
    let mut c = f.open();
    let id = f.enqueue(&mut c);
    for mutation in 0..6 {
        let mut header = f.reply_header();
        match mutation {
            0 => header.sender = address(8).recipient,
            1 => header.correlation_id = CorrelationId::from_bytes([55; 32]),
            2 => header.capability_id = CapabilityId::from_bytes([55; 32]),
            3 => header.mailbox = address(8).mailbox,
            4 => header.execution_epoch = ExecutionEpoch::new(2).unwrap(),
            5 => header.causation_id = CausationId::from_bytes([55; 32]),
            _ => unreachable!(),
        }
        assert!(
            c.accept_reply(
                id,
                &f.seal(header, &f.responder),
                &f.context(MailboxOperation::Reply)
            )
            .is_err()
        );
        assert_eq!(c.journal.tip().cursor, 0);
    }
    assert!(
        c.accept_reply(
            id,
            &f.seal(f.reply_header(), &f.caller),
            &f.context(MailboxOperation::Reply)
        )
        .is_err()
    );
}

#[test]
fn timeout_is_durable_observation_not_request_rollback() {
    let f = Fixture::new();
    let mut c = f.open();
    let id = f.enqueue(&mut c);
    let mut context = f.context(MailboxOperation::Receive);
    context.now_unix_ms = DEADLINE;
    assert!(matches!(
        c.receive_result(id, &f.receive, &context).unwrap(),
        CallResult::TimedOut
    ));
    drop(c);
    let mut c = f.open();
    assert!(
        c.sealed_call(id).is_ok(),
        "timeout cannot retract immutable dispatch intent"
    );
    assert!(
        c.accept_reply(id, &f.reply(), &f.context(MailboxOperation::Reply))
            .is_err(),
        "clock rewind cannot reopen timeout"
    );
    assert_eq!(c.journal.tip().cursor, 0);
}

#[test]
fn crash_after_acceptance_and_after_ack_reconciles_original_ids() {
    let f = Fixture::new();
    let mut c = f.open();
    let id = f.enqueue(&mut c);
    let reply = f.reply();
    c.accept_reply(id, &reply, &f.context(MailboxOperation::Reply))
        .unwrap();
    // Simulate the durable state immediately before the final snapshot write.
    let mut interrupted = c.state.clone();
    interrupted.calls[0].result = ResultState::Accepting(reply.clone());
    c.commit(interrupted).unwrap();
    drop(c);
    let mut c = f.open();
    assert!(matches!(
        c.receive_result(id, &f.receive, &f.context(MailboxOperation::Receive))
            .unwrap(),
        CallResult::Reply(_)
    ));
    c.acknowledge_result(id, &f.receive, &f.context(MailboxOperation::Receive))
        .unwrap();
    let mut interrupted = c.state.clone();
    interrupted.calls[0].result = ResultState::AckRequested(reply);
    c.commit(interrupted).unwrap();
    let cursor = c.journal.tip().cursor;
    drop(c);
    let mut c = f.open();
    assert!(matches!(
        c.receive_result(id, &f.receive, &f.context(MailboxOperation::Receive))
            .unwrap(),
        CallResult::Settled
    ));
    assert_eq!(
        c.journal.tip().cursor,
        cursor,
        "ACK replay creates no extra journal event"
    );
}

#[test]
fn quotas_failed_commit_and_sealed_storage() {
    let f = Fixture::new();
    let mut c = f.open();
    c.config.limits.max_bytes = 1;
    let envelope = f.seal(f.header.clone(), &f.caller);
    assert!(matches!(
        f.enqueue_envelope(&mut c, &envelope),
        Err(ConversationError::Full)
    ));
    assert!(c.state.calls.is_empty());
    c.config.limits.max_bytes = 100_000;
    let id = f.enqueue_envelope(&mut c, &envelope).unwrap();
    c.accept_reply(id, &f.reply(), &f.context(MailboxOperation::Reply))
        .unwrap();
    fn inspect(path: &std::path::Path) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                inspect(&entry.path());
            } else {
                let bytes = fs::read(entry.path()).unwrap();
                assert!(!bytes.windows(PAYLOAD.len()).any(|window| window == PAYLOAD));
            }
        }
    }
    inspect(f.dir.path());
    fs::remove_file(c.config.directory.join("state")).unwrap();
    fs::create_dir(c.config.directory.join("state")).unwrap();
    assert!(matches!(c.prune(1_100), Err(ConversationError::Storage)));
    assert!(matches!(
        c.sealed_call(id),
        Err(ConversationError::Uncertain)
    ));
}

#[test]
fn wrong_reply_issuer_and_receive_authority_refuse() {
    let mut f = Fixture::new();
    let mut c = f.open();
    let original = f.reply.clone();
    f.reply.grant.issuer = PrincipalId::from_bytes([77; 32]);
    f.reply = sign_capability(f.reply.grant.clone(), &f.authority).unwrap();
    let envelope = f.seal(f.header.clone(), &f.caller);
    assert!(matches!(
        f.enqueue_envelope(&mut c, &envelope),
        Err(ConversationError::Scope)
    ));
    f.reply = original;
    let id = f.enqueue_envelope(&mut c, &envelope).unwrap();
    assert!(
        c.receive_result(id, &f.reply, &f.context(MailboxOperation::Receive))
            .is_err()
    );
    assert!(
        c.acknowledge_result(id, &f.receive, &f.context(MailboxOperation::Receive))
            .is_err()
    );
}

#[test]
fn finite_call_count_and_retention_do_not_reuse_old_reply() {
    let mut f = Fixture::new();
    let mut c = f.open();
    c.config.limits.max_calls = 1;
    let old_id = f.enqueue(&mut c);
    let old_reply = f.reply();
    f.header.message_id = MessageId::from_bytes([61; 32]);
    f.header.correlation_id = CorrelationId::from_bytes([62; 32]);
    f.reply.grant.capability_id = CapabilityId::from_bytes([63; 32]);
    f.reply = sign_capability(f.reply.grant.clone(), &f.authority).unwrap();
    f.header.reply_to.as_mut().unwrap().capability_id = f.reply.grant.capability_id;
    let envelope = f.seal(f.header.clone(), &f.caller);
    assert!(matches!(
        f.enqueue_envelope(&mut c, &envelope),
        Err(ConversationError::Full)
    ));
    c.config.limits.max_calls = 4;
    let new_id = f.enqueue_envelope(&mut c, &envelope).unwrap();
    assert!(
        c.accept_reply(new_id, &old_reply, &f.context(MailboxOperation::Reply))
            .is_err(),
        "old reply cannot complete another pending call"
    );
    f.header.message_id = MessageId::from_bytes([64; 32]);
    f.header.correlation_id = CorrelationId::from_bytes([65; 32]);
    f.reply.grant.capability_id = CapabilityId::from_bytes([66; 32]);
    f.reply = sign_capability(f.reply.grant.clone(), &f.authority).unwrap();
    f.header.reply_to.as_mut().unwrap().capability_id = f.reply.grant.capability_id;
    let third = f.seal(f.header.clone(), &f.caller);
    assert!(
        matches!(
            f.enqueue_envelope(&mut c, &third),
            Err(ConversationError::Full)
        ),
        "signed max_outstanding_calls is tighter than host capacity"
    );
    c.prune(EXPIRES + 999).unwrap();
    assert!(c.sealed_call(old_id).is_ok());
    c.prune(EXPIRES + 1_000).unwrap();
    assert!(c.sealed_call(old_id).is_err());
    // A new grant cannot reuse an old signed response, even with a matching caller.
    f.header.issued_at_unix_ms = 3_000;
    f.header.expires_at_unix_ms = 4_000;
    assert!(
        c.accept_reply(old_id, &old_reply, &f.context(MailboxOperation::Reply))
            .is_err()
    );
}

#[test]
fn monotonic_elapsed_time_cannot_be_extended_by_wall_clock_rewind() {
    let f = Fixture::new();
    let mut c = f.open();
    let id = f.enqueue(&mut c);
    c.started -= std::time::Duration::from_millis(60_001);
    assert!(matches!(
        c.receive_result(id, &f.receive, &f.context(MailboxOperation::Receive))
            .unwrap(),
        CallResult::TimedOut
    ));
}

#[test]
fn failed_destination_commit_never_exposes_result() {
    let f = Fixture::new();
    let mut c = f.open();
    let id = f.enqueue(&mut c);
    let reply = f.reply();
    let original_anchor = f.dir.path().join("anchor/tip");
    fs::create_dir(&original_anchor).unwrap();
    assert!(
        c.accept_reply(id, &reply, &f.context(MailboxOperation::Reply))
            .is_err()
    );
    assert!(
        c.receive_result(id, &f.receive, &f.context(MailboxOperation::Receive))
            .is_err()
    );
    drop(c);
    fs::remove_dir(&original_anchor).unwrap();
    // Journal recovery authenticates and reconciles the committed record.
    let mut c = f.open();
    assert!(matches!(
        c.receive_result(id, &f.receive, &f.context(MailboxOperation::Receive))
            .unwrap(),
        CallResult::Reply(_)
    ));
}

#[test]
fn missing_or_tampered_snapshot_never_resets_history() {
    let f = Fixture::new();
    let mut c = f.open();
    f.enqueue(&mut c);
    drop(c);
    let path = f.dir.path().join("outbox/state");
    let mut bytes = fs::read(&path).unwrap();
    bytes[0] ^= 1;
    fs::write(&path, bytes).unwrap();
    assert!(matches!(f.try_open(), Err(ConversationError::Storage)));
    fs::remove_file(path).unwrap();
    assert!(matches!(f.try_open(), Err(ConversationError::Storage)));
}

#[test]
fn submillisecond_observations_keep_the_original_monotonic_anchor() {
    let f = Fixture::new();
    let mut c = f.open();
    let start = c.started;
    for _ in 0..1_000 {
        c.current_context(&f.context(MailboxOperation::Receive))
            .unwrap();
    }
    assert_eq!(
        c.started, start,
        "observations must not discard elapsed fractional milliseconds"
    );
    let advanced = c.observe_time(NOW + 10_000).unwrap();
    c.started -= std::time::Duration::from_millis(1_001);
    assert!(
        c.observe_time(NOW).unwrap() >= advanced + 1_001,
        "a forward wall-clock observation must not freeze subsequent monotonic time"
    );
}

#[test]
fn pruning_advances_authority_clock_and_reopen_retains_its_floor() {
    let f = Fixture::new();
    let mut c = f.open();
    let envelope = f.seal(f.header.clone(), &f.caller);
    f.enqueue_envelope(&mut c, &envelope).unwrap();
    c.prune(EXPIRES + 1_000).unwrap();
    assert!(
        f.enqueue_envelope(&mut c, &envelope).is_err(),
        "pruning cannot renew expired authority"
    );
    drop(c);
    let mut c = f.open();
    assert!(
        f.enqueue_envelope(&mut c, &envelope).is_err(),
        "reopen cannot rewind the durable authority clock"
    );
}

#[test]
fn retention_reconciles_ack_before_removing_journal_evidence() {
    let f = Fixture::new();
    let mut c = f.open();
    let id = f.enqueue(&mut c);
    let mut header = f.reply_header();
    header.expires_at_unix_ms = NOW + 1_000;
    let envelope = f.seal(header, &f.responder);
    c.accept_reply(id, &envelope, &f.context(MailboxOperation::Reply))
        .unwrap();
    c.acknowledge_result(id, &f.receive, &f.context(MailboxOperation::Receive))
        .unwrap();
    let mut interrupted = c.state.clone();
    interrupted.calls[0].result = ResultState::AckRequested(envelope);
    c.commit(interrupted).unwrap();
    drop(c);
    let mut c = f.open();
    c.prune(NOW + 2_000).unwrap();
    assert!(matches!(
        c.receive_result(id, &f.receive, &f.context(MailboxOperation::Receive))
            .unwrap(),
        CallResult::Settled
    ));
}

#[test]
fn exact_guest_lease_and_signed_ack_settle_result_durably() {
    use mvm_contract::plan::{Nonce, PlanId};
    use mvm_core::mailbox::reader::{
        sign_delivery_ack, sign_guest_reader_enrollment, sign_reader_possession,
    };

    let mut f = Fixture::new();
    let mut c = f.open();
    let first_id = f.enqueue(&mut c);
    c.accept_reply(first_id, &f.reply(), &f.context(MailboxOperation::Reply))
        .unwrap();
    f.header.message_id = MessageId::from_bytes([86; 32]);
    f.header.correlation_id = CorrelationId::from_bytes([87; 32]);
    f.header.sequence = SequenceNumber::new(2).unwrap();
    f.reply.grant.capability_id = CapabilityId::from_bytes([88; 32]);
    f.reply = sign_capability(f.reply.grant.clone(), &f.authority).unwrap();
    f.header.reply_to.as_mut().unwrap().capability_id = f.reply.grant.capability_id;
    let id = f.enqueue(&mut c);
    let mut second_reply = f.reply_header();
    second_reply.message_id = MessageId::from_bytes([89; 32]);
    let envelope = f.seal(second_reply.clone(), &f.responder);
    c.accept_reply(id, &envelope, &f.context(MailboxOperation::Reply))
        .unwrap();
    let guest_key = SigningKey::from_bytes(&[71; 32]);
    let plan_id = PlanId("canonical-parent-plan".into());
    let plan_nonce = Nonce::from_bytes([72; 16]);
    let session = ConsumerSessionId::from_bytes([73; 32]);
    let plan = MailboxGrant {
        mailbox: address(3).mailbox,
        authority_key: f.authority.verifying_key().to_bytes(),
        epoch: f.header.execution_epoch,
        report: None,
        retention: None,
        service_blind: None,
    };
    let enrollment = sign_guest_reader_enrollment(
        MailboxGuestReaderEnrollment {
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            plan_id: plan_id.clone(),
            plan_nonce: plan_nonce.clone(),
            address: address(3),
            consumer: address(3).recipient,
            consumer_boot: f.header.sender_boot,
            consumer_session: session,
            receive_capability_id: f.receive.grant.capability_id,
            ack_public_key: guest_key.verifying_key().to_bytes(),
            execution_epoch: f.header.execution_epoch,
            policy_epoch: 1,
            issued_at_unix_ms: 900,
            expires_at_unix_ms: EXPIRES,
        },
        &f.authority,
    )
    .unwrap();
    let scope = MailboxGuestReaderScope {
        plan: &plan,
        plan_id: &plan_id,
        plan_nonce: &plan_nonce,
        receive: &f.receive.grant,
        current_boot: f.header.sender_boot,
        current_session: session,
        now_unix_ms: NOW,
    };
    let context = f.context(MailboxOperation::Receive);
    let sender = f.responder.verifying_key();
    let receive = JournalReceive {
        capability: &f.receive,
        context: &context,
        encryption_key: &f.payload_key,
        sender_key: &sender,
    };
    let challenge = [74; 32];
    let possession = sign_reader_possession(&enrollment, &challenge, &guest_key).unwrap();
    let delivery = c
        .lease_result(
            id,
            JournalGuestLease {
                receive,
                plan: &plan,
                scope,
                enrollment: &enrollment,
                challenge: &challenge,
                possession_signature: &possession,
                signer: &f.authority,
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        delivery.header().message_id,
        second_reply.message_id,
        "exact selection must skip the first queued reply"
    );
    assert_eq!(delivery.payload(), PAYLOAD);
    let signed = sign_delivery_ack(
        MailboxDeliveryAck {
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            lease: delivery.lease().clone(),
            ack_nonce: DeliveryAckNonce::from_bytes([75; 16]),
            acknowledged_at_unix_ms: delivery.lease().lease.issued_at_unix_ms,
        },
        &guest_key,
    )
    .unwrap();
    let request = JournalGuestAck {
        receive,
        plan: &plan,
        scope,
        enrollment: &enrollment,
        signed: &signed,
    };
    let mut wrong = signed.clone();
    wrong.ack.lease.lease.message_id = MessageId::from_bytes([76; 32]);
    assert!(
        c.acknowledge_result_signed(
            id,
            JournalGuestAck {
                signed: &wrong,
                ..request
            }
        )
        .is_err()
    );
    let index = c.index(id).unwrap();
    assert!(matches!(
        c.state.calls[index].result,
        ResultState::Replied(_)
    ));
    c.acknowledge_result_signed(id, request).unwrap();
    assert!(
        c.acknowledge_result_signed(first_id, request).is_err(),
        "a valid ACK cannot settle another call"
    );
    assert!(matches!(
        c.receive_result(first_id, &f.receive, &context).unwrap(),
        CallResult::Reply(_)
    ));
    // Reopen an interrupted final source write after the canonical journal ACK.
    let mut interrupted = c.state.clone();
    interrupted.calls[index].result = ResultState::SignedAckRequested {
        envelope,
        signed: Box::new(signed),
    };
    c.commit(interrupted).unwrap();
    drop(c);
    let mut c = f.open();
    assert!(matches!(
        c.receive_result(id, &f.receive, &context).unwrap(),
        CallResult::Settled
    ));
}
