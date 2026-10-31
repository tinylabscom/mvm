use ed25519_dalek::SigningKey;
use mvm_contract::protocol::mailbox::{
    AuthorizationDomainId, AuthorizationDomainRouteLabel, BootId, CapabilityId,
    CapabilityOperations, CausationId, CiphertextPadding, ContentType, CorrelationId, DeliveryId,
    DeliveryOutcome, DestinationRouteToken, EncryptionAlgorithm, EncryptionContext, ExecutionEpoch,
    MAX_MAILBOX_PAYLOAD_BYTES, MailboxAddress, MailboxCapabilityGrant, MailboxEnvelopeHeader,
    MailboxId, MailboxMessageKind, MailboxOperation, MailboxRoutingFrame, MessageId, OrderingScope,
    PrincipalId, ProtocolVersion, ReplayNonce, ReplyRoute, RevocationId, SequenceNumber,
    SignatureAlgorithm, TenantId, TransportBindingId,
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

#[test]
fn destination_receipt_signature_covers_outcome_and_identity() {
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
    verify_receipt(&signed, &destination_key.verifying_key()).expect("verify receipt");
    signed.receipt.outcome = DeliveryOutcome::Refused;
    assert!(matches!(
        verify_receipt(&signed, &destination_key.verifying_key()),
        Err(MailboxError::ReceiptSignatureInvalid)
    ));
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
