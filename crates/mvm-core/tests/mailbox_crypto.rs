use ed25519_dalek::{Signer, SigningKey};
use mvm_contract::plan::{Nonce, PlanId};
use mvm_contract::protocol::mailbox::{
    AuthorizationDomainId, AuthorizationDomainRouteLabel, BootId, CapabilityId,
    CapabilityOperations, CausationId, CiphertextPadding, ContentType, CorrelationId, DeliveryId,
    DeliveryOutcome, DestinationRouteToken, EncryptionAlgorithm, EncryptionContext, ExecutionEpoch,
    MAX_MAILBOX_PAYLOAD_BYTES, MailboxAddress, MailboxCapabilityGrant, MailboxEnvelopeHeader,
    MailboxId, MailboxMessageKind, MailboxOperation, MailboxRoutingFrame, MessageId, OrderingScope,
    PrincipalId, ProtocolVersion, ReplayNonce, ReplyRoute, RevocationId, SequenceNumber,
    SignatureAlgorithm, TenantId, TransportBindingId,
};
use mvm_contract::protocol::workload_report::{
    ReportError, ReportIdentity, ReportKind, WORKLOAD_REPORT_CONTENT_TYPE, WORKLOAD_REPORT_VERSION,
    WorkloadReport,
};
use mvm_core::crypto::aead::Key;
use mvm_core::mailbox::{
    InMemoryReplayProtector, MailboxError, OpenContext, SealRequest, decode_envelope,
    encode_envelope, open_envelope, seal_envelope, sign_capability, sign_receipt, verify_receipt,
};

fn domain() -> AuthorizationDomainId {
    AuthorizationDomainId::from_bytes([1; 32])
}

fn tenant() -> TenantId {
    TenantId::from_bytes([19; 32])
}

fn sender() -> PrincipalId {
    PrincipalId::from_bytes([2; 32])
}

fn recipient() -> PrincipalId {
    PrincipalId::from_bytes([3; 32])
}

fn address() -> MailboxAddress {
    MailboxAddress {
        tenant: tenant(),
        authorization_domain: domain(),
        mailbox: MailboxId::from_bytes([4; 32]),
        recipient: recipient(),
    }
}

fn content_type() -> ContentType {
    ContentType::parse("application/vnd.mvm.prompt", 1).expect("content type")
}

fn header() -> MailboxEnvelopeHeader {
    MailboxEnvelopeHeader {
        protocol_version: ProtocolVersion::V1,
        signature_algorithm: SignatureAlgorithm::ED25519,
        tenant: tenant(),
        authorization_domain: domain(),
        sender: sender(),
        recipient: recipient(),
        mailbox: address().mailbox,
        sender_boot: BootId::from_bytes([5; 32]),
        execution_epoch: ExecutionEpoch::new(7).expect("nonzero epoch"),
        message_id: MessageId::from_bytes([6; 32]),
        correlation_id: CorrelationId::from_bytes([7; 32]),
        causation_id: CausationId::from_bytes([8; 32]),
        kind: MailboxMessageKind::Call,
        reply_to: Some(ReplyRoute {
            address: address(),
            capability_id: CapabilityId::from_bytes([14; 32]),
        }),
        ordering_scope: OrderingScope::parse("interactive").expect("scope"),
        sequence: SequenceNumber::new(1).expect("nonzero sequence"),
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
        nonce: ReplayNonce::from_bytes([9; 16]),
        content_type: content_type(),
        capability_id: CapabilityId::from_bytes([10; 32]),
        policy_epoch: 4,
        encryption: EncryptionContext {
            algorithm: EncryptionAlgorithm::AES_256_GCM,
            key_id: [11; 32],
        },
        plaintext_len: 5,
    }
}

fn routing() -> MailboxRoutingFrame {
    MailboxRoutingFrame {
        protocol_version: ProtocolVersion::V1,
        authorization_domain_route_label: AuthorizationDomainRouteLabel::from_bytes([15; 32]),
        destination_route_token: DestinationRouteToken::from_bytes([16; 32]),
        delivery_id: DeliveryId::from_bytes([17; 32]),
        ciphertext_len: 0,
        padding: CiphertextPadding::Exact,
        expires_at_unix_ms: 2_000,
        hop_limit: 8,
        transport_binding_id: TransportBindingId::from_bytes([18; 32]),
    }
}

fn grant() -> MailboxCapabilityGrant {
    MailboxCapabilityGrant {
        protocol_version: ProtocolVersion::V1,
        signature_algorithm: SignatureAlgorithm::ED25519,
        capability_id: CapabilityId::from_bytes([10; 32]),
        issuer: PrincipalId::from_bytes([12; 32]),
        subject: sender(),
        address: address(),
        operations: CapabilityOperations::from_operations(&[
            MailboxOperation::Send,
            MailboxOperation::Receive,
            MailboxOperation::Reply,
        ]),
        message_kinds: vec![MailboxMessageKind::Call, MailboxMessageKind::Reply],
        content_types: vec![content_type()],
        max_payload_bytes: 1024,
        max_messages_per_minute: 60,
        max_outstanding_calls: 8,
        max_queue_contribution_bytes: 4096,
        minimum_execution_epoch: ExecutionEpoch::new(7).expect("epoch"),
        maximum_execution_epoch: ExecutionEpoch::new(9).expect("epoch"),
        policy_epoch: 4,
        not_before_unix_ms: 900,
        expires_at_unix_ms: 3_000,
        revocation_id: RevocationId::from_bytes([13; 32]),
        delegation_depth: 0,
    }
}

fn context() -> OpenContext {
    OpenContext {
        expected_tenant: tenant(),
        expected_authorization_domain: domain(),
        expected_mailbox: address().mailbox,
        expected_sender: sender(),
        expected_recipient: recipient(),
        acting_principal: sender(),
        expected_capability_issuer: PrincipalId::from_bytes([12; 32]),
        current_execution_epoch: ExecutionEpoch::new(7).expect("epoch"),
        current_policy_epoch: 4,
        required_operation: MailboxOperation::Send,
        now_unix_ms: 1_500,
        accepted_content_types: vec![content_type()],
        revoked_capabilities: vec![],
    }
}

#[test]
fn envelope_roundtrips_and_opens_without_losing_signed_fields() {
    let sender_key = SigningKey::from_bytes(&[21; 32]);
    let authority_key = SigningKey::from_bytes(&[22; 32]);
    let encryption_key = Key::from_bytes([23; 32]);
    let capability = sign_capability(grant(), &authority_key).expect("sign capability");
    let envelope = seal_envelope(
        SealRequest {
            routing: routing(),
            header: header(),
            plaintext: b"hello",
        },
        &encryption_key,
        &sender_key,
    )
    .expect("seal");

    let wire = encode_envelope(&envelope).expect("encode");
    let host_visible = core::str::from_utf8(&wire).expect("JSON wire");
    for forbidden in [
        "application/vnd.mvm.prompt",
        "sender_boot",
        "signature",
        "tenant",
        "correlation_id",
        "capability_id",
        "ordering_scope",
        "plaintext_len",
    ] {
        assert!(
            !host_visible.contains(forbidden),
            "inner field {forbidden} leaked into the outer routing frame"
        );
    }
    let decoded = decode_envelope(&wire).expect("decode");
    assert_eq!(decoded, envelope);

    let mut replay = InMemoryReplayProtector::default();
    let opened = open_envelope(
        &decoded,
        &capability,
        &context(),
        &encryption_key,
        &sender_key.verifying_key(),
        &authority_key.verifying_key(),
        &mut replay,
    )
    .expect("verify and open");
    assert_eq!(opened, b"hello");
}

#[test]
fn tampering_wrong_key_and_replay_fail_closed() {
    let sender_key = SigningKey::from_bytes(&[21; 32]);
    let authority_key = SigningKey::from_bytes(&[22; 32]);
    let encryption_key = Key::from_bytes([23; 32]);
    let capability = sign_capability(grant(), &authority_key).expect("sign capability");
    let envelope = seal_envelope(
        SealRequest {
            routing: routing(),
            header: header(),
            plaintext: b"hello",
        },
        &encryption_key,
        &sender_key,
    )
    .expect("seal");

    let mut tampered = envelope.clone();
    tampered.routing.hop_limit = 7;
    let mut replay = InMemoryReplayProtector::default();
    assert!(matches!(
        open_envelope(
            &tampered,
            &capability,
            &context(),
            &encryption_key,
            &sender_key.verifying_key(),
            &authority_key.verifying_key(),
            &mut replay,
        ),
        Err(MailboxError::DecryptionFailed)
    ));

    let mut replay = InMemoryReplayProtector::default();
    assert!(matches!(
        open_envelope(
            &envelope,
            &capability,
            &context(),
            &Key::from_bytes([99; 32]),
            &sender_key.verifying_key(),
            &authority_key.verifying_key(),
            &mut replay,
        ),
        Err(MailboxError::DecryptionFailed)
    ));

    let mut replay = InMemoryReplayProtector::default();
    open_envelope(
        &envelope,
        &capability,
        &context(),
        &encryption_key,
        &sender_key.verifying_key(),
        &authority_key.verifying_key(),
        &mut replay,
    )
    .expect("first delivery");
    assert!(matches!(
        open_envelope(
            &envelope,
            &capability,
            &context(),
            &encryption_key,
            &sender_key.verifying_key(),
            &authority_key.verifying_key(),
            &mut replay,
        ),
        Err(MailboxError::Replay)
    ));

    let mut changed_nonce_header = header();
    changed_nonce_header.nonce = ReplayNonce::from_bytes([88; 16]);
    let changed_nonce = seal_envelope(
        SealRequest {
            routing: routing(),
            header: changed_nonce_header,
            plaintext: b"hello",
        },
        &encryption_key,
        &sender_key,
    )
    .expect("seal same message ID with a different nonce");
    assert_eq!(
        open_envelope(
            &changed_nonce,
            &capability,
            &context(),
            &encryption_key,
            &sender_key.verifying_key(),
            &authority_key.verifying_key(),
            &mut replay,
        )
        .expect_err("nonce changes cannot bypass message-ID replay protection"),
        MailboxError::Replay
    );
}

#[test]
fn identity_scope_epoch_expiry_and_content_type_are_checked() {
    let sender_key = SigningKey::from_bytes(&[21; 32]);
    let authority_key = SigningKey::from_bytes(&[22; 32]);
    let encryption_key = Key::from_bytes([23; 32]);
    let capability = sign_capability(grant(), &authority_key).expect("sign capability");
    let envelope = seal_envelope(
        SealRequest {
            routing: routing(),
            header: header(),
            plaintext: b"hello",
        },
        &encryption_key,
        &sender_key,
    )
    .expect("seal");

    let cases = [
        (
            {
                let mut value = context();
                value.expected_tenant = TenantId::from_bytes([44; 32]);
                value
            },
            MailboxError::WrongTenant,
        ),
        (
            {
                let mut value = context();
                value.expected_sender = PrincipalId::from_bytes([40; 32]);
                value
            },
            MailboxError::WrongSender,
        ),
        (
            {
                let mut value = context();
                value.expected_recipient = PrincipalId::from_bytes([41; 32]);
                value
            },
            MailboxError::WrongRecipient,
        ),
        (
            {
                let mut value = context();
                value.expected_authorization_domain = AuthorizationDomainId::from_bytes([42; 32]);
                value
            },
            MailboxError::WrongAuthorizationDomain,
        ),
        (
            {
                let mut value = context();
                value.expected_mailbox = MailboxId::from_bytes([43; 32]);
                value
            },
            MailboxError::WrongMailbox,
        ),
        (
            {
                let mut value = context();
                value.current_execution_epoch = ExecutionEpoch::new(8).expect("epoch");
                value
            },
            MailboxError::StaleExecutionEpoch,
        ),
        (
            {
                let mut value = context();
                value.now_unix_ms = 2_001;
                value
            },
            MailboxError::Expired,
        ),
        (
            {
                let mut value = context();
                value.accepted_content_types.clear();
                value
            },
            MailboxError::UnsupportedContentType,
        ),
    ];

    for (case, expected) in cases {
        let mut replay = InMemoryReplayProtector::default();
        let actual = open_envelope(
            &envelope,
            &capability,
            &case,
            &encryption_key,
            &sender_key.verifying_key(),
            &authority_key.verifying_key(),
            &mut replay,
        )
        .expect_err("case must fail");
        assert_eq!(actual, expected);
    }
}

#[cfg(feature = "test-support")]
#[test]
fn local_journal_expiry_recovers_after_interrupted_anchor_commit() {
    use mvm_core::mailbox::journal::{
        FileJournalAnchor, HistoryKeyCustody, HistoryKeyRef, JournalAdmission, JournalError,
        JournalLimits, MailboxJournal,
    };

    struct ExistingKey(HistoryKeyRef);
    impl HistoryKeyCustody for ExistingKey {
        fn load_existing(&self, reference: &HistoryKeyRef) -> Result<Key, JournalError> {
            if reference != &self.0 {
                return Err(JournalError::HistoryKeyMismatch);
            }
            Ok(Key::from_bytes([41; 32]))
        }
    }

    let dir = tempfile::tempdir().expect("private journal fixture");
    let root = dir.path().join("journal");
    let anchor_path = dir.path().join("anchor").join("tip");
    let signer = SigningKey::from_bytes(&[22; 32]);
    let sender_key = SigningKey::from_bytes(&[21; 32]);
    let payload_key = Key::from_bytes([23; 32]);
    let capability = sign_capability(grant(), &signer).expect("send grant");
    let envelope = seal_envelope(
        SealRequest {
            routing: routing(),
            header: header(),
            plaintext: b"hello",
        },
        &payload_key,
        &sender_key,
    )
    .expect("canonical encrypted envelope");
    let context = context();
    let reference = HistoryKeyRef::new(address(), header().execution_epoch, [42; 32], 1)
        .expect("history identity");
    let custody = ExistingKey(reference);
    let limits = JournalLimits {
        max_records: 4,
        max_bytes: 64 * 1024,
    };
    let anchor =
        FileJournalAnchor::open(&anchor_path, address(), [43; 32]).expect("local anchor genesis");
    let mut journal = MailboxJournal::open_local_with_custody(
        &root,
        reference,
        signer.verifying_key(),
        limits,
        &custody,
        &anchor,
    )
    .expect("empty local journal");
    let accepted = journal
        .admit_local(
            JournalAdmission {
                envelope: &envelope,
                capability: &capability,
                context: &context,
                encryption_key: &payload_key,
                sender_key: &sender_key.verifying_key(),
                signer: &signer,
            },
            &anchor,
        )
        .expect("fsynced local acceptance");
    assert_eq!(
        accepted.receipt.outcome,
        DeliveryOutcome::AcceptedLocalDurable
    );
    let identity = mvm_core::mailbox::ReplayIdentity::from_header(&header());
    assert!(matches!(
        journal.expire_next(routing().expires_at_unix_ms, &signer, |_| {
            Err(JournalError::Rollback)
        }),
        Err(JournalError::Rollback)
    ));
    assert_eq!(anchor.tip().cursor, 1, "no terminal receipt before anchor");
    drop(journal);
    drop(anchor);

    let anchor =
        FileJournalAnchor::open(&anchor_path, address(), [43; 32]).expect("recover local anchor");
    let journal = MailboxJournal::open_local_with_custody(
        &root,
        reference,
        signer.verifying_key(),
        limits,
        &custody,
        &anchor,
    )
    .expect("reconcile verified terminal state");
    let expired = journal
        .expired_receipt(identity, &signer)
        .expect("signed terminal outcome after restart");
    assert_eq!(expired.receipt.outcome, DeliveryOutcome::Expired);
    verify_receipt(&expired, &signer.verifying_key()).expect("signed expiry");
    assert_eq!(anchor.tip().cursor, 2);
}

#[test]
fn destination_receipt_wire_roundtrip_and_signature_cover_outcome_and_identity() {
    let destination_key = SigningKey::from_bytes(&[31; 32]);
    let receipt = mvm_contract::protocol::mailbox::DestinationReceipt {
        protocol_version: ProtocolVersion::V1,
        signature_algorithm: SignatureAlgorithm::ED25519,
        delivery_id: DeliveryId::from_bytes([32; 32]),
        message_id: MessageId::from_bytes([6; 32]),
        address: address(),
        execution_epoch: ExecutionEpoch::new(7).expect("epoch"),
        outcome: DeliveryOutcome::AcceptedDurable,
        observed_at_unix_ms: 1_600,
        ciphertext_commitment: [33; 32],
    };
    let mut signed = sign_receipt(receipt, &destination_key).expect("sign receipt");
    let mut invalid = signed.receipt.clone();
    invalid.outcome = DeliveryOutcome::AcceptedLocalDurable;
    assert!(
        sign_receipt(invalid, &destination_key).is_err(),
        "a V1 signer must not label local acceptance as durable"
    );
    let wire = serde_jcs::to_vec(&signed).expect("encode receipt");
    let decoded: mvm_contract::protocol::mailbox::SignedDestinationReceipt =
        serde_json::from_slice(&wire).expect("decode receipt");
    assert_eq!(decoded, signed);
    verify_receipt(&decoded, &destination_key.verifying_key()).expect("verify decoded receipt");
    signed.receipt.outcome = DeliveryOutcome::Refused;
    assert!(matches!(
        verify_receipt(&signed, &destination_key.verifying_key()),
        Err(MailboxError::ReceiptSignatureInvalid)
    ));
}

#[test]
fn local_receipt_uses_only_its_v2_signature_domain() {
    let destination_key = SigningKey::from_bytes(&[31; 32]);
    let receipt = mvm_contract::protocol::mailbox::DestinationReceipt {
        protocol_version: ProtocolVersion::V2,
        signature_algorithm: SignatureAlgorithm::ED25519,
        delivery_id: DeliveryId::from_bytes([32; 32]),
        message_id: MessageId::from_bytes([6; 32]),
        address: address(),
        execution_epoch: ExecutionEpoch::new(7).expect("epoch"),
        outcome: DeliveryOutcome::AcceptedLocalDurable,
        observed_at_unix_ms: 1_600,
        ciphertext_commitment: [33; 32],
    };
    let signed = sign_receipt(receipt.clone(), &destination_key).expect("sign V2 local receipt");
    verify_receipt(&signed, &destination_key.verifying_key()).expect("verify V2 local receipt");
    assert_eq!(
        sign_receipt(receipt, &destination_key)
            .expect("deterministic local signature")
            .signature,
        signed.signature
    );

    let mut wrong_domain = signed.clone();
    let mut v1_bytes = b"mvm.mailbox.receipt.v1\0".to_vec();
    v1_bytes.extend(serde_jcs::to_vec(&signed.receipt).expect("canonical receipt"));
    wrong_domain.signature = destination_key.sign(&v1_bytes).to_bytes().to_vec();
    assert_eq!(
        verify_receipt(&wrong_domain, &destination_key.verifying_key()),
        Err(MailboxError::ReceiptSignatureInvalid)
    );
    assert_eq!(
        verify_receipt(&signed, &SigningKey::from_bytes(&[34; 32]).verifying_key()),
        Err(MailboxError::ReceiptSignatureInvalid)
    );
    let mut old_outcome = signed.receipt.clone();
    old_outcome.outcome = DeliveryOutcome::Duplicate;
    assert!(sign_receipt(old_outcome, &destination_key).is_err());
    let mut old_version = signed.receipt;
    old_version.protocol_version = ProtocolVersion::V1;
    assert!(sign_receipt(old_version, &destination_key).is_err());
}

#[test]
fn protocol_algorithm_signature_and_nonce_tampering_are_typed_failures() {
    let sender_key = SigningKey::from_bytes(&[21; 32]);
    let authority_key = SigningKey::from_bytes(&[22; 32]);
    let encryption_key = Key::from_bytes([23; 32]);
    let capability = sign_capability(grant(), &authority_key).expect("sign capability");

    let mut unsupported = header();
    unsupported.protocol_version = ProtocolVersion(99);
    assert_eq!(
        seal_envelope(
            SealRequest {
                routing: routing(),
                header: unsupported,
                plaintext: b"hello",
            },
            &encryption_key,
            &sender_key,
        )
        .expect_err("unknown protocol must fail"),
        MailboxError::UnsupportedProtocolVersion
    );

    let mut unsupported = header();
    unsupported.encryption.algorithm = EncryptionAlgorithm(99);
    assert_eq!(
        seal_envelope(
            SealRequest {
                routing: routing(),
                header: unsupported,
                plaintext: b"hello",
            },
            &encryption_key,
            &sender_key,
        )
        .expect_err("unknown encryption must fail"),
        MailboxError::UnsupportedEncryptionAlgorithm
    );

    let mut unsupported = header();
    unsupported.signature_algorithm = SignatureAlgorithm(99);
    assert_eq!(
        seal_envelope(
            SealRequest {
                routing: routing(),
                header: unsupported,
                plaintext: b"hello",
            },
            &encryption_key,
            &sender_key,
        )
        .expect_err("unknown signature algorithm must fail"),
        MailboxError::UnsupportedSignatureAlgorithm
    );

    let envelope = seal_envelope(
        SealRequest {
            routing: routing(),
            header: header(),
            plaintext: b"hello",
        },
        &encryption_key,
        &sender_key,
    )
    .expect("seal");
    let wrong_sender_key = SigningKey::from_bytes(&[98; 32]);
    let mut replay = InMemoryReplayProtector::default();
    assert_eq!(
        open_envelope(
            &envelope,
            &capability,
            &context(),
            &encryption_key,
            &wrong_sender_key.verifying_key(),
            &authority_key.verifying_key(),
            &mut replay,
        )
        .expect_err("wrong sender signature key must fail"),
        MailboxError::SignatureInvalid
    );

    let mut ciphertext_tampered = envelope;
    ciphertext_tampered.ciphertext[0] ^= 1;
    let mut replay = InMemoryReplayProtector::default();
    assert_eq!(
        open_envelope(
            &ciphertext_tampered,
            &capability,
            &context(),
            &encryption_key,
            &sender_key.verifying_key(),
            &authority_key.verifying_key(),
            &mut replay,
        )
        .expect_err("ciphertext tamper must fail"),
        MailboxError::CiphertextCommitmentInvalid
    );
}

#[test]
fn every_capability_operation_is_checked_by_the_same_authority_gate() {
    let sender_key = SigningKey::from_bytes(&[21; 32]);
    let authority_key = SigningKey::from_bytes(&[22; 32]);
    let encryption_key = Key::from_bytes([23; 32]);
    let envelope = seal_envelope(
        SealRequest {
            routing: routing(),
            header: header(),
            plaintext: b"hello",
        },
        &encryption_key,
        &sender_key,
    )
    .expect("seal");

    for operation in [
        MailboxOperation::Send,
        MailboxOperation::Receive,
        MailboxOperation::Reply,
        MailboxOperation::Monitor,
        MailboxOperation::Administer,
    ] {
        let mut scoped_grant = grant();
        scoped_grant.operations = CapabilityOperations::from_operations(&[operation]);
        let capability = sign_capability(scoped_grant, &authority_key).expect("sign capability");
        let mut scoped_context = context();
        scoped_context.required_operation = operation;
        let mut replay = InMemoryReplayProtector::default();
        assert_eq!(
            open_envelope(
                &envelope,
                &capability,
                &scoped_context,
                &encryption_key,
                &sender_key.verifying_key(),
                &authority_key.verifying_key(),
                &mut replay,
            )
            .expect("the exact granted operation opens"),
            b"hello"
        );
    }
}

#[test]
fn call_cast_and_reply_enforce_their_reply_route_shape() {
    let sender_key = SigningKey::from_bytes(&[21; 32]);
    let encryption_key = Key::from_bytes([23; 32]);

    for kind in [
        MailboxMessageKind::Call,
        MailboxMessageKind::Cast,
        MailboxMessageKind::Reply,
    ] {
        let mut message_header = header();
        message_header.kind = kind;
        if kind != MailboxMessageKind::Call {
            message_header.reply_to = None;
        }
        seal_envelope(
            SealRequest {
                routing: routing(),
                header: message_header,
                plaintext: b"hello",
            },
            &encryption_key,
            &sender_key,
        )
        .expect("valid message-kind shape seals");
    }

    let mut cast_with_reply = header();
    cast_with_reply.kind = MailboxMessageKind::Cast;
    assert!(matches!(
        seal_envelope(
            SealRequest {
                routing: routing(),
                header: cast_with_reply,
                plaintext: b"hello",
            },
            &encryption_key,
            &sender_key,
        ),
        Err(MailboxError::Contract(
            mvm_contract::protocol::mailbox::MailboxContractError::UnexpectedReplyRoute
        ))
    ));
}

#[test]
fn capability_scope_revocation_and_signature_are_enforced() {
    let sender_key = SigningKey::from_bytes(&[21; 32]);
    let authority_key = SigningKey::from_bytes(&[22; 32]);
    let encryption_key = Key::from_bytes([23; 32]);
    let envelope = seal_envelope(
        SealRequest {
            routing: routing(),
            header: header(),
            plaintext: b"hello",
        },
        &encryption_key,
        &sender_key,
    )
    .expect("seal");

    let mut wrong_id = grant();
    wrong_id.capability_id = CapabilityId::from_bytes([55; 32]);
    let wrong_id = sign_capability(wrong_id, &authority_key).expect("sign");
    let mut replay = InMemoryReplayProtector::default();
    assert_eq!(
        open_envelope(
            &envelope,
            &wrong_id,
            &context(),
            &encryption_key,
            &sender_key.verifying_key(),
            &authority_key.verifying_key(),
            &mut replay,
        )
        .expect_err("wrong capability must fail"),
        MailboxError::WrongCapability
    );

    let mut wrong_operation = grant();
    wrong_operation.operations =
        CapabilityOperations::from_operations(&[MailboxOperation::Receive]);
    let wrong_operation = sign_capability(wrong_operation, &authority_key).expect("sign");
    let mut replay = InMemoryReplayProtector::default();
    assert_eq!(
        open_envelope(
            &envelope,
            &wrong_operation,
            &context(),
            &encryption_key,
            &sender_key.verifying_key(),
            &authority_key.verifying_key(),
            &mut replay,
        )
        .expect_err("ungranted operation must fail"),
        MailboxError::OperationNotAuthorized
    );

    let mut wrong_issuer_context = context();
    wrong_issuer_context.expected_capability_issuer = PrincipalId::from_bytes([56; 32]);
    let capability = sign_capability(grant(), &authority_key).expect("sign");
    let mut replay = InMemoryReplayProtector::default();
    assert_eq!(
        open_envelope(
            &envelope,
            &capability,
            &wrong_issuer_context,
            &encryption_key,
            &sender_key.verifying_key(),
            &authority_key.verifying_key(),
            &mut replay,
        )
        .expect_err("capability issuer identity must match the trusted authority"),
        MailboxError::WrongCapabilityIssuer
    );

    let mut revoked_context = context();
    revoked_context
        .revoked_capabilities
        .push(RevocationId::from_bytes([13; 32]));
    let capability = sign_capability(grant(), &authority_key).expect("sign");
    let mut replay = InMemoryReplayProtector::default();
    assert_eq!(
        open_envelope(
            &envelope,
            &capability,
            &revoked_context,
            &encryption_key,
            &sender_key.verifying_key(),
            &authority_key.verifying_key(),
            &mut replay,
        )
        .expect_err("revoked capability must fail"),
        MailboxError::CapabilityRevoked
    );

    let mut bad_signature = capability;
    bad_signature.signature[0] ^= 1;
    let mut replay = InMemoryReplayProtector::default();
    assert_eq!(
        open_envelope(
            &envelope,
            &bad_signature,
            &context(),
            &encryption_key,
            &sender_key.verifying_key(),
            &authority_key.verifying_key(),
            &mut replay,
        )
        .expect_err("forged capability must fail"),
        MailboxError::CapabilitySignatureInvalid
    );
}

#[test]
fn maximum_payload_roundtrips_and_oversize_input_is_rejected_before_decode() {
    let sender_key = SigningKey::from_bytes(&[21; 32]);
    let encryption_key = Key::from_bytes([23; 32]);
    let payload = vec![0x5a; MAX_MAILBOX_PAYLOAD_BYTES];
    let mut max_header = header();
    max_header.plaintext_len = u32::try_from(payload.len()).expect("payload fits u32");
    let envelope = seal_envelope(
        SealRequest {
            routing: routing(),
            header: max_header,
            plaintext: &payload,
        },
        &encryption_key,
        &sender_key,
    )
    .expect("seal maximum payload");
    let encoded = encode_envelope(&envelope).expect("encode maximum payload");
    assert_eq!(decode_envelope(&encoded).expect("decode"), envelope);

    let oversized = vec![b' '; mvm_contract::protocol::mailbox::MAX_ENCODED_ENVELOPE_BYTES + 1];
    assert_eq!(
        decode_envelope(&oversized).expect_err("oversize frame must be refused"),
        MailboxError::EncodedSizeExceeded
    );
}

#[test]
fn legacy_mvmd_v1_fixture_is_not_reinterpreted_as_the_canonical_envelope() {
    let fixture = include_bytes!("fixtures/mvmd-mailbox-v1.json");
    assert_eq!(
        decode_envelope(fixture).expect_err("legacy ownership must require an adapter"),
        MailboxError::Decoding
    );
}

#[test]
fn deeply_nested_frames_within_the_size_bound_are_refused_without_recursion() {
    let depth = 500_000;
    for (open, close) in [("[", "]"), ("{\"routing\":", "}")] {
        let frame = format!("{}0{}", open.repeat(depth), close.repeat(depth));
        assert!(frame.len() <= mvm_contract::protocol::mailbox::MAX_ENCODED_ENVELOPE_BYTES);
        assert_eq!(
            decode_envelope(frame.as_bytes()).expect_err("nesting must be refused"),
            MailboxError::Decoding
        );
    }
}

// ── operational contract: admission, dedup, fencing, vocabulary ──────────────

fn contract_keys() -> (SigningKey, SigningKey, Key) {
    (
        SigningKey::from_bytes(&[21; 32]),
        SigningKey::from_bytes(&[22; 32]),
        Key::from_bytes([23; 32]),
    )
}

fn seal_with(
    header: MailboxEnvelopeHeader,
    plaintext: &[u8],
) -> mvm_contract::protocol::mailbox::MailboxEnvelope {
    let (sender_key, _, encryption_key) = contract_keys();
    seal_envelope(
        SealRequest {
            routing: routing(),
            header,
            plaintext,
        },
        &encryption_key,
        &sender_key,
    )
    .expect("seal")
}

fn open_under(
    envelope: &mvm_contract::protocol::mailbox::MailboxEnvelope,
    grant: MailboxCapabilityGrant,
    context: &OpenContext,
    replay: &mut InMemoryReplayProtector,
) -> Result<Vec<u8>, MailboxError> {
    let (sender_key, authority_key, encryption_key) = contract_keys();
    let capability = sign_capability(grant, &authority_key).expect("sign capability");
    open_envelope(
        envelope,
        &capability,
        context,
        &encryption_key,
        &sender_key.verifying_key(),
        &authority_key.verifying_key(),
        replay,
    )
}

#[test]
fn verified_open_retains_authenticated_header_and_records_replay_once() {
    #[derive(Default)]
    struct CountingReplay(usize);

    impl mvm_core::mailbox::ReplayProtector for CountingReplay {
        fn check_and_record(&mut self, _: mvm_core::mailbox::ReplayIdentity) -> bool {
            self.0 += 1;
            self.0 == 1
        }
    }

    let (sender_key, authority_key, encryption_key) = contract_keys();
    let capability = sign_capability(grant(), &authority_key).expect("capability");
    let expected = header();
    let envelope = seal_with(expected.clone(), b"hello");
    let mut replay = CountingReplay::default();
    let opened = mvm_core::mailbox::open_verified_envelope(
        &envelope,
        &capability,
        &context(),
        &encryption_key,
        &sender_key.verifying_key(),
        &authority_key.verifying_key(),
        &mut replay,
    )
    .expect("verified header and bytes");
    assert_eq!(opened.header(), &expected);
    assert_eq!(opened.payload(), b"hello");
    assert_eq!(replay.0, 1);
    assert_eq!(opened.into_payload(), b"hello");
    assert_eq!(
        open_envelope(
            &envelope,
            &capability,
            &context(),
            &encryption_key,
            &sender_key.verifying_key(),
            &authority_key.verifying_key(),
            &mut replay,
        )
        .expect_err("legacy open shares replay authority"),
        MailboxError::Replay
    );
    assert_eq!(replay.0, 2);
}

#[test]
fn refused_verified_open_exposes_no_proof_and_preserves_replay_identity() {
    let (sender_key, authority_key, encryption_key) = contract_keys();
    let capability = sign_capability(grant(), &authority_key).expect("capability");
    let envelope = seal_with(header(), b"hello");
    let open = |current: &OpenContext, replay: &mut InMemoryReplayProtector| {
        mvm_core::mailbox::open_verified_envelope(
            &envelope,
            &capability,
            current,
            &encryption_key,
            &sender_key.verifying_key(),
            &authority_key.verifying_key(),
            replay,
        )
    };
    let mut recipient = context();
    recipient.expected_recipient = PrincipalId::from_bytes([41; 32]);
    let mut epoch = context();
    epoch.current_execution_epoch = ExecutionEpoch::new(8).expect("epoch");
    let mut policy = context();
    policy.current_policy_epoch += 1;
    let mut revoked = context();
    revoked.revoked_capabilities.push(grant().revocation_id);
    let mut expired = context();
    expired.now_unix_ms = 2_000;
    for (refused, expected) in [
        (recipient, MailboxError::WrongRecipient),
        (epoch, MailboxError::StaleExecutionEpoch),
        (policy, MailboxError::StalePolicyEpoch),
        (revoked, MailboxError::CapabilityRevoked),
        (expired, MailboxError::Expired),
    ] {
        let mut replay = InMemoryReplayProtector::default();
        assert_eq!(open(&refused, &mut replay).expect_err("no proof"), expected);
        let accepted = open(&context(), &mut replay).expect("refusal did not consume identity");
        assert_eq!(accepted.header(), &header());
        assert_eq!(accepted.payload(), b"hello");
        let debug = format!("{accepted:?}");
        assert!(!debug.contains("hello"));
        assert!(!debug.contains("capability_id"));
    }
}

#[test]
fn a_refused_message_does_not_consume_its_dedup_identity() {
    let envelope = seal_with(header(), b"hello");
    let mut replay = InMemoryReplayProtector::default();

    let mut late = context();
    late.now_unix_ms = 2_001;
    assert_eq!(
        open_under(&envelope, grant(), &late, &mut replay).expect_err("expired"),
        MailboxError::Expired
    );
    let mut wrong_recipient = context();
    wrong_recipient.expected_recipient = PrincipalId::from_bytes([41; 32]);
    assert_eq!(
        open_under(&envelope, grant(), &wrong_recipient, &mut replay).expect_err("refused"),
        MailboxError::WrongRecipient
    );

    // Refusals left nothing behind, so the retry of the same stable
    // identity is accepted exactly once.
    assert_eq!(
        open_under(&envelope, grant(), &context(), &mut replay).expect("retry accepted"),
        b"hello"
    );
    assert_eq!(
        open_under(&envelope, grant(), &context(), &mut replay).expect_err("duplicate"),
        MailboxError::Replay
    );
}

#[test]
fn a_stable_message_id_retried_into_a_new_epoch_or_boot_is_not_a_duplicate() {
    let mut replay = InMemoryReplayProtector::default();
    open_under(
        &seal_with(header(), b"hello"),
        grant(),
        &context(),
        &mut replay,
    )
    .expect("first delivery");

    let mut next_epoch = header();
    next_epoch.execution_epoch = ExecutionEpoch::new(8).expect("epoch");
    let mut next_epoch_context = context();
    next_epoch_context.current_execution_epoch = ExecutionEpoch::new(8).expect("epoch");
    open_under(
        &seal_with(next_epoch, b"hello"),
        grant(),
        &next_epoch_context,
        &mut replay,
    )
    .expect("same id, newly authorized epoch");

    let mut next_boot = header();
    next_boot.sender_boot = BootId::from_bytes([55; 32]);
    open_under(
        &seal_with(next_boot, b"hello"),
        grant(),
        &context(),
        &mut replay,
    )
    .expect("same id, new sender boot");
}

#[test]
fn stale_or_foreign_epochs_are_fenced_on_both_sides() {
    let refuse =
        |header: MailboxEnvelopeHeader, grant: MailboxCapabilityGrant, context: OpenContext| {
            open_under(
                &seal_with(header, b"hello"),
                grant,
                &context,
                &mut InMemoryReplayProtector::default(),
            )
            .expect_err("must be fenced")
        };

    // A message from an epoch the owner has not reached.
    let mut owner_behind = context();
    owner_behind.current_execution_epoch = ExecutionEpoch::new(6).expect("epoch");
    assert_eq!(
        refuse(header(), grant(), owner_behind),
        MailboxError::StaleExecutionEpoch
    );

    // Header and owner agree, but the capability was minted for earlier epochs.
    let mut beyond_grant = header();
    beyond_grant.execution_epoch = ExecutionEpoch::new(10).expect("epoch");
    let mut beyond_grant_context = context();
    beyond_grant_context.current_execution_epoch = ExecutionEpoch::new(10).expect("epoch");
    assert_eq!(
        refuse(beyond_grant, grant(), beyond_grant_context),
        MailboxError::StaleExecutionEpoch
    );

    // Policy epoch: stale on the message, on the owner, and on the capability.
    let mut stale_header = header();
    stale_header.policy_epoch = 3;
    assert_eq!(
        refuse(stale_header, grant(), context()),
        MailboxError::StalePolicyEpoch
    );
    let mut newer_policy = context();
    newer_policy.current_policy_epoch = 5;
    assert_eq!(
        refuse(header(), grant(), newer_policy),
        MailboxError::StalePolicyEpoch
    );
    let mut stale_grant = grant();
    stale_grant.policy_epoch = 3;
    assert_eq!(
        refuse(header(), stale_grant, context()),
        MailboxError::StalePolicyEpoch
    );
}

#[test]
fn cast_is_admitted_only_when_the_capability_names_it_and_bounds_it() {
    let mut cast = header();
    cast.kind = MailboxMessageKind::Cast;
    cast.reply_to = None;
    let envelope = seal_with(cast, b"hello");

    // `grant()` authorizes call and reply only.
    assert_eq!(
        open_under(
            &envelope,
            grant(),
            &context(),
            &mut InMemoryReplayProtector::default()
        )
        .expect_err("cast not granted"),
        MailboxError::MessageKindNotAuthorized
    );

    let mut with_cast = grant();
    with_cast.message_kinds.push(MailboxMessageKind::Cast);
    assert_eq!(
        open_under(
            &envelope,
            with_cast.clone(),
            &context(),
            &mut InMemoryReplayProtector::default()
        )
        .expect("granted cast"),
        b"hello"
    );

    with_cast.max_payload_bytes = 4;
    assert_eq!(
        open_under(
            &envelope,
            with_cast,
            &context(),
            &mut InMemoryReplayProtector::default()
        )
        .expect_err("over the capability's payload bound"),
        MailboxError::CapabilityPayloadExceeded
    );
}

#[test]
fn typed_workload_report_uses_the_verified_canonical_cast() {
    let report_type =
        ContentType::parse(WORKLOAD_REPORT_CONTENT_TYPE, WORKLOAD_REPORT_VERSION).expect("type");
    let mut cast = header();
    cast.kind = MailboxMessageKind::Cast;
    cast.reply_to = None;
    cast.content_type = report_type.clone();
    let identity = ReportIdentity {
        plan_id: PlanId("sha256:".to_owned() + &"a".repeat(64)),
        plan_nonce: Nonce::from_bytes([24; 16]),
        message_id: cast.message_id,
    };
    let report = WorkloadReport::new(
        identity.clone(),
        ReportKind::Result,
        ContentType::parse("application/json", 1).expect("application content type"),
        b"{\"private\":\"result\"}".to_vec(),
    )
    .expect("report");
    let bytes = report.encode().expect("bounded report");
    cast.plaintext_len = u32::try_from(bytes.len()).expect("mailbox bound fits u32");
    let envelope = seal_with(cast, &bytes);
    let encoded = encode_envelope(&envelope).expect("canonical envelope");
    assert!(
        !String::from_utf8_lossy(&encoded).contains("private"),
        "routing frame must not disclose report content"
    );

    let mut permitted = grant();
    permitted.message_kinds.push(MailboxMessageKind::Cast);
    let mut receiving = context();
    receiving.accepted_content_types.push(report_type.clone());
    assert_eq!(
        open_under(
            &envelope,
            permitted.clone(),
            &receiving,
            &mut InMemoryReplayProtector::default()
        )
        .expect_err("the signed capability did not grant this report content type"),
        MailboxError::ContentTypeNotAuthorized
    );
    permitted.content_types.push(report_type.clone());
    assert_eq!(
        report_type.name(),
        WORKLOAD_REPORT_CONTENT_TYPE,
        "the signed envelope must declare the typed report content"
    );
    let opened = open_under(
        &envelope,
        permitted.clone(),
        &receiving,
        &mut InMemoryReplayProtector::default(),
    )
    .expect("capability-authorized result");
    let decoded = WorkloadReport::decode(&opened).expect("typed report");
    assert_eq!(decoded, report);
    decoded
        .verify_identity(&identity)
        .expect("report matches admitted run and signed message");
    let mut wrong_run = identity;
    wrong_run.plan_nonce = Nonce::from_bytes([25; 16]);
    assert_eq!(
        decoded.verify_identity(&wrong_run),
        Err(ReportError::WrongIdentity)
    );

    permitted.max_payload_bytes = u32::try_from(bytes.len() - 1).expect("bounded report");
    assert_eq!(
        open_under(
            &envelope,
            permitted,
            &receiving,
            &mut InMemoryReplayProtector::default()
        )
        .expect_err("the signed grant must bound the whole encoded report"),
        MailboxError::CapabilityPayloadExceeded
    );
}

#[test]
fn the_delivery_and_message_vocabularies_are_closed() {
    // The exhaustive matches stop compiling when a variant is added, so a new
    // outcome (a lossy cast, a "not executed" claim) needs a deliberate edit
    // here and in the ADR.
    fn outcome_name(outcome: DeliveryOutcome) -> &'static str {
        match outcome {
            DeliveryOutcome::AcceptedEphemeral => "accepted_ephemeral",
            DeliveryOutcome::AcceptedDurable => "accepted_durable",
            DeliveryOutcome::AcceptedLocalDurable => "accepted_local_durable",
            DeliveryOutcome::Duplicate => "duplicate",
            DeliveryOutcome::Expired => "expired",
            DeliveryOutcome::Refused => "refused",
            DeliveryOutcome::Full => "full",
            DeliveryOutcome::Unavailable => "unavailable",
            DeliveryOutcome::Late => "late",
            DeliveryOutcome::DeadLettered => "dead_lettered",
        }
    }
    fn kind_name(kind: MailboxMessageKind) -> &'static str {
        match kind {
            MailboxMessageKind::Call => "call",
            MailboxMessageKind::Cast => "cast",
            MailboxMessageKind::Reply => "reply",
        }
    }
    for outcome in [
        DeliveryOutcome::AcceptedEphemeral,
        DeliveryOutcome::AcceptedDurable,
        DeliveryOutcome::AcceptedLocalDurable,
        DeliveryOutcome::Duplicate,
        DeliveryOutcome::Expired,
        DeliveryOutcome::Refused,
        DeliveryOutcome::Full,
        DeliveryOutcome::Unavailable,
        DeliveryOutcome::Late,
        DeliveryOutcome::DeadLettered,
    ] {
        let wire = serde_json::to_string(&outcome).expect("encode");
        assert_eq!(wire, format!("\"{}\"", outcome_name(outcome)));
        assert_eq!(
            serde_json::from_str::<DeliveryOutcome>(&wire).unwrap(),
            outcome
        );
    }
    for kind in [
        MailboxMessageKind::Call,
        MailboxMessageKind::Cast,
        MailboxMessageKind::Reply,
    ] {
        let wire = serde_json::to_string(&kind).expect("encode");
        assert_eq!(wire, format!("\"{}\"", kind_name(kind)));
        assert_eq!(
            serde_json::from_str::<MailboxMessageKind>(&wire).unwrap(),
            kind
        );
    }
    // A timeout is an observation, never a claim about execution; and there
    // is no lossy cast.
    for unknown in ["timed_out", "not_executed", "delivered", "cancelled"] {
        assert!(serde_json::from_str::<DeliveryOutcome>(&format!("\"{unknown}\"")).is_err());
    }
    for unknown in ["best_effort_cast", "cast_lossy", "notify"] {
        assert!(serde_json::from_str::<MailboxMessageKind>(&format!("\"{unknown}\"")).is_err());
    }
}

#[test]
fn a_router_sees_routing_fields_and_opaque_ciphertext_only() {
    let plaintext = b"a-distinctive-plaintext-marker";
    let mut message_header = header();
    message_header.plaintext_len = u32::try_from(plaintext.len()).expect("fits");
    let envelope = seal_with(message_header, plaintext);

    let keys = |value: serde_json::Value| -> std::collections::BTreeSet<String> {
        value.as_object().expect("object").keys().cloned().collect()
    };
    let expect = |names: &[&str]| -> std::collections::BTreeSet<String> {
        names.iter().map(|name| (*name).to_string()).collect()
    };
    assert_eq!(
        keys(serde_json::to_value(&envelope).unwrap()),
        expect(&[
            "routing",
            "encryption",
            "ciphertext_commitment",
            "ciphertext"
        ])
    );
    assert_eq!(
        keys(serde_json::to_value(&envelope.routing).unwrap()),
        expect(&[
            "protocol_version",
            "authorization_domain_route_label",
            "destination_route_token",
            "delivery_id",
            "ciphertext_len",
            "padding",
            "expires_at_unix_ms",
            "hop_limit",
            "transport_binding_id",
        ])
    );
    let wire = encode_envelope(&envelope).expect("encode");
    assert!(
        !wire.windows(plaintext.len()).any(|w| w == plaintext),
        "plaintext must not appear on the wire"
    );
}

#[test]
fn only_the_destination_authority_can_sign_acceptance() {
    let destination_key = SigningKey::from_bytes(&[31; 32]);
    let relay_key = SigningKey::from_bytes(&[34; 32]);
    let receipt = mvm_contract::protocol::mailbox::DestinationReceipt {
        protocol_version: ProtocolVersion::V1,
        signature_algorithm: SignatureAlgorithm::ED25519,
        delivery_id: DeliveryId::from_bytes([32; 32]),
        message_id: MessageId::from_bytes([6; 32]),
        address: address(),
        execution_epoch: ExecutionEpoch::new(7).expect("epoch"),
        outcome: DeliveryOutcome::AcceptedDurable,
        observed_at_unix_ms: 1_600,
        ciphertext_commitment: [33; 32],
    };
    let forged = sign_receipt(receipt, &relay_key).expect("sign");
    assert!(matches!(
        verify_receipt(&forged, &destination_key.verifying_key()),
        Err(MailboxError::ReceiptSignatureInvalid)
    ));
}

#[test]
fn verified_admission_retains_original_ciphertext_and_service_plaintext_allocations() {
    use mvm_core::mailbox::{ReplayIdentity, ReplayProtector, open_verified_admission};
    #[derive(Default)]
    struct CountingReplay(usize);
    impl ReplayProtector for CountingReplay {
        fn check_and_record(&mut self, _: ReplayIdentity) -> bool {
            self.0 += 1;
            self.0 == 1
        }
    }
    let (sender_key, authority_key, encryption_key) = contract_keys();
    let capability = sign_capability(grant(), &authority_key).unwrap();
    let expected = header();
    let envelope = seal_with(expected.clone(), b"hello");
    let ciphertext_ptr = envelope.ciphertext.as_ptr();
    let ciphertext_capacity = envelope.ciphertext.capacity();
    let mut replay = CountingReplay::default();
    let admission = open_verified_admission(
        envelope,
        &capability,
        &context(),
        &encryption_key,
        &sender_key.verifying_key(),
        &authority_key.verifying_key(),
        &mut replay,
    )
    .unwrap();
    assert_eq!(replay.0, 1);
    {
        let view = admission.journal_view();
        assert_eq!(view.envelope().ciphertext.as_ptr(), ciphertext_ptr);
        assert_eq!(view.envelope().ciphertext.capacity(), ciphertext_capacity);
        assert_eq!(view.header(), &expected);
        assert_eq!(
            view.replay_identity(),
            ReplayIdentity::from_header(&expected)
        );
        assert_eq!(
            view.ciphertext_commitment(),
            &view.envelope().ciphertext_commitment
        );
        assert_eq!(
            view.verified_scope().acting_principal(),
            context().acting_principal
        );
        assert_eq!(
            view.verified_scope().required_operation(),
            context().required_operation
        );
        assert_eq!(
            view.verified_scope().capability_issuer(),
            context().expected_capability_issuer
        );
        assert_eq!(
            view.verified_scope().current_execution_epoch(),
            context().current_execution_epoch
        );
        assert_eq!(
            view.verified_scope().current_policy_epoch(),
            context().current_policy_epoch
        );
        assert_eq!(
            view.verified_scope().verified_at_unix_ms(),
            context().now_unix_ms
        );
    }
    assert_eq!(admission.payload(), b"hello");
    let plaintext_ptr = admission.payload().as_ptr();
    let view = admission.journal_view();
    assert_eq!(view.header(), &expected);
    assert_eq!(replay.0, 1, "views must not verify or consume replay again");
    let (envelope, opened) = admission.into_parts();
    assert_eq!(envelope.ciphertext.as_ptr(), ciphertext_ptr);
    assert_eq!(opened.payload().as_ptr(), plaintext_ptr);
    assert_eq!(opened.header(), &expected);
    assert_eq!(opened.into_payload(), b"hello");
    assert_eq!(
        open_envelope(
            &envelope,
            &capability,
            &context(),
            &encryption_key,
            &sender_key.verifying_key(),
            &authority_key.verifying_key(),
            &mut replay
        )
        .unwrap_err(),
        MailboxError::Replay
    );
    assert_eq!(replay.0, 2);
}

#[test]
fn verified_admission_refusals_do_not_mint_capsule_or_record_replay() {
    use mvm_core::mailbox::{ReplayIdentity, ReplayProtector, open_verified_admission};
    #[derive(Default)]
    struct CountingReplay(usize);
    impl ReplayProtector for CountingReplay {
        fn check_and_record(&mut self, _: ReplayIdentity) -> bool {
            self.0 += 1;
            true
        }
    }
    let (sender_key, authority_key, encryption_key) = contract_keys();
    let capability = sign_capability(grant(), &authority_key).unwrap();
    for failure in [
        "ciphertext",
        "sender_key",
        "authority_key",
        "tenant",
        "domain",
        "recipient",
        "acting_principal",
        "operation",
        "issuer",
        "epoch",
        "policy",
        "expired",
        "revoked",
    ] {
        let mut envelope = seal_with(header(), b"hello");
        let mut current = context();
        let mut sender_public = sender_key.verifying_key();
        let mut authority_public = authority_key.verifying_key();
        match failure {
            "ciphertext" => envelope.ciphertext[0] ^= 1,
            "sender_key" => sender_public = SigningKey::from_bytes(&[99; 32]).verifying_key(),
            "authority_key" => authority_public = SigningKey::from_bytes(&[99; 32]).verifying_key(),
            "tenant" => current.expected_tenant = TenantId::from_bytes([99; 32]),
            "domain" => {
                current.expected_authorization_domain = AuthorizationDomainId::from_bytes([99; 32])
            }
            "recipient" => current.expected_recipient = PrincipalId::from_bytes([99; 32]),
            "acting_principal" => current.acting_principal = PrincipalId::from_bytes([99; 32]),
            "operation" => current.required_operation = MailboxOperation::Monitor,
            "issuer" => current.expected_capability_issuer = PrincipalId::from_bytes([99; 32]),
            "epoch" => current.current_execution_epoch = ExecutionEpoch::new(8).unwrap(),
            "policy" => current.current_policy_epoch += 1,
            "expired" => current.now_unix_ms = 2_000,
            _ => current.revoked_capabilities.push(grant().revocation_id),
        }
        let mut replay = CountingReplay::default();
        assert!(
            open_verified_admission(
                envelope,
                &capability,
                &current,
                &encryption_key,
                &sender_public,
                &authority_public,
                &mut replay
            )
            .is_err(),
            "{failure}"
        );
        assert_eq!(replay.0, 0, "{failure}");
    }
}

#[test]
fn verified_admission_debug_never_contains_payload_or_ciphertext() {
    use mvm_core::mailbox::open_verified_admission;
    let (sender_key, authority_key, encryption_key) = contract_keys();
    let capability = sign_capability(grant(), &authority_key).unwrap();
    let admission = open_verified_admission(
        seal_with(header(), b"hello"),
        &capability,
        &context(),
        &encryption_key,
        &sender_key.verifying_key(),
        &authority_key.verifying_key(),
        &mut InMemoryReplayProtector::default(),
    )
    .unwrap();
    assert_eq!(format!("{admission:?}"), "VerifiedMailboxAdmission { .. }");
    assert_eq!(
        format!("{:?}", admission.journal_view()),
        "JournalAdmissionView { .. }"
    );
}

#[test]
fn verified_admission_scope_preserves_supplied_operation_and_historical_context() {
    use mvm_core::mailbox::{VerifiedMailboxScope, open_verified_admission};
    let (sender_key, authority_key, encryption_key) = contract_keys();
    let capability = sign_capability(grant(), &authority_key).unwrap();
    let mut current = context();
    let admission = open_verified_admission(
        seal_with(header(), b"hello"),
        &capability,
        &current,
        &encryption_key,
        &sender_key.verifying_key(),
        &authority_key.verifying_key(),
        &mut InMemoryReplayProtector::default(),
    )
    .unwrap();
    current.now_unix_ms += 100;
    current.current_policy_epoch += 1;
    current.required_operation = MailboxOperation::Receive;
    current.revoked_capabilities.push(grant().revocation_id);
    let view = admission.journal_view();
    let scope = view.verified_scope();
    assert_eq!(
        scope.required_operation(),
        MailboxOperation::Send,
        "verification cannot become receive authority"
    );
    assert_eq!(scope.verified_at_unix_ms(), 1_500);
    assert_eq!(scope.current_policy_epoch(), 4);
    assert_ne!(scope.current_policy_epoch(), current.current_policy_epoch);
    assert_eq!(scope.tenant(), view.header().tenant);
    assert_eq!(
        scope.authorization_domain(),
        view.header().authorization_domain
    );
    assert_eq!(scope.mailbox(), view.header().mailbox);
    assert_eq!(scope.sender(), view.header().sender);
    assert_eq!(scope.recipient(), view.header().recipient);
    assert_eq!(scope.sender_boot(), view.header().sender_boot);
    assert_eq!(scope.message_id(), view.header().message_id);
    assert_eq!(scope.capability_id(), view.header().capability_id);
    assert_eq!(scope.encryption_key_id(), view.header().encryption.key_id);
    assert_eq!(scope.execution_epoch(), view.header().execution_epoch);
    assert_eq!(scope.policy_epoch(), view.header().policy_epoch);
    assert_eq!(scope.expires_at_unix_ms(), view.header().expires_at_unix_ms);
    assert!(
        !std::mem::needs_drop::<VerifiedMailboxScope>(),
        "fixed scope must not retain owned context vectors"
    );
}
