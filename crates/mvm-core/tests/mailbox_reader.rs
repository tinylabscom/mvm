use ed25519_dalek::SigningKey;
use mvm_contract::plan::{Nonce, PlanId};
use mvm_contract::protocol::mailbox::{
    AuthorizationDomainId, AuthorizationDomainRouteLabel, BootId, CapabilityId,
    CapabilityOperations, ConsumerSessionId, ContentType, CorrelationId, DeliveryAckNonce,
    DeliveryId, DeliveryLeaseNonce, DestinationRouteToken, EncryptionAlgorithm, EncryptionContext,
    ExecutionEpoch, MailboxAddress, MailboxCapabilityGrant, MailboxDeliveryAck,
    MailboxDeliveryLease, MailboxEnvelopeHeader, MailboxGrant, MailboxGuestReaderEnrollment,
    MailboxGuestReaderScope, MailboxId, MailboxMessageKind, MailboxOperation, MailboxRoutingFrame,
    MessageId, OrderingScope, PrincipalId, ProtocolVersion, ReplayNonce, RevocationId,
    SequenceNumber, SignatureAlgorithm, SignedMailboxDeliveryAck, SignedMailboxDeliveryLease,
    TenantId, TransportBindingId,
};
use mvm_core::crypto::aead::Key;
use mvm_core::mailbox::reader::{
    MailboxReaderBootBinding, ReaderDeliveryContext, mint_guest_receive_capability,
    sign_delivery_ack, sign_delivery_lease, sign_guest_reader_enrollment, sign_reader_possession,
    verify_delivery_ack, verify_delivery_lease, verify_guest_reader_enrollment,
    verify_reader_possession,
};
use mvm_core::mailbox::{MailboxError, SealRequest, seal_envelope, sign_capability};

fn fixture() -> (
    SigningKey,
    SigningKey,
    MailboxGrant,
    PlanId,
    Nonce,
    MailboxCapabilityGrant,
    MailboxGuestReaderEnrollment,
) {
    let authority = SigningKey::from_bytes(&[5; 32]);
    let guest = SigningKey::from_bytes(&[6; 32]);
    let address = MailboxAddress {
        tenant: TenantId::from_bytes([1; 32]),
        authorization_domain: AuthorizationDomainId::from_bytes([2; 32]),
        mailbox: MailboxId::from_bytes([3; 32]),
        recipient: PrincipalId::from_bytes([4; 32]),
    };
    let epoch = ExecutionEpoch::new(7).unwrap();
    let plan = MailboxGrant {
        mailbox: address.mailbox,
        authority_key: authority.verifying_key().to_bytes(),
        epoch,
    };
    let plan_id = PlanId(format!("sha256:{}", "a".repeat(64)));
    let plan_nonce = Nonce::from_bytes([7; 16]);
    let receive = MailboxCapabilityGrant {
        protocol_version: ProtocolVersion::V1,
        signature_algorithm: SignatureAlgorithm::ED25519,
        capability_id: CapabilityId::from_bytes([8; 32]),
        issuer: PrincipalId::from_bytes([9; 32]),
        subject: PrincipalId::from_bytes([10; 32]),
        address,
        operations: CapabilityOperations::from_operations(&[MailboxOperation::Receive]),
        message_kinds: vec![MailboxMessageKind::Cast],
        content_types: vec![ContentType::parse("application/vnd.mvm.workload-report", 1).unwrap()],
        max_payload_bytes: 1024,
        max_messages_per_minute: 60,
        max_outstanding_calls: 1,
        max_queue_contribution_bytes: 4096,
        minimum_execution_epoch: epoch,
        maximum_execution_epoch: epoch,
        policy_epoch: 12,
        not_before_unix_ms: 100,
        expires_at_unix_ms: 300,
        revocation_id: RevocationId::from_bytes([11; 32]),
        delegation_depth: 0,
    };
    let enrollment = MailboxGuestReaderEnrollment {
        protocol_version: ProtocolVersion::V1,
        signature_algorithm: SignatureAlgorithm::ED25519,
        plan_id: plan_id.clone(),
        plan_nonce: plan_nonce.clone(),
        address,
        consumer: receive.subject,
        consumer_boot: BootId::from_bytes([12; 32]),
        consumer_session: ConsumerSessionId::from_bytes([13; 32]),
        receive_capability_id: receive.capability_id,
        ack_public_key: guest.verifying_key().to_bytes(),
        execution_epoch: epoch,
        policy_epoch: receive.policy_epoch,
        issued_at_unix_ms: 110,
        expires_at_unix_ms: 200,
    };
    (
        authority, guest, plan, plan_id, plan_nonce, receive, enrollment,
    )
}

#[test]
fn own_mailbox_grant_mints_a_distinct_boot_bound_receive_capability() {
    let (authority, guest, grant, plan_id, plan_nonce, mut send, mut enrollment) = fixture();
    let binding = MailboxReaderBootBinding {
        plan_id: plan_id.clone(),
        plan_nonce: plan_nonce.clone(),
        mailbox: grant.mailbox,
        authority_key: grant.authority_key,
        execution_epoch: grant.epoch,
        boot: enrollment.consumer_boot,
        guest_identity_key: SigningKey::from_bytes(&[17; 32]).verifying_key().to_bytes(),
        ack_public_key: guest.verifying_key().to_bytes(),
    };
    send.issuer = PrincipalId::from_bytes(authority.verifying_key().to_bytes());
    send.subject = PrincipalId::from_bytes([21; 32]);
    send.operations = CapabilityOperations::from_operations(&[MailboxOperation::Send]);
    let signed_send = sign_capability(send.clone(), &authority).unwrap();
    let receive =
        mint_guest_receive_capability(&grant, &binding, &signed_send, send.address, &authority)
            .unwrap();
    assert!(receive.grant.operations.allows(MailboxOperation::Receive));
    assert!(!receive.grant.operations.allows(MailboxOperation::Send));
    assert_eq!(receive.grant.subject, send.address.recipient);
    assert_eq!(receive.grant.address, send.address);
    assert_eq!(receive.grant.expires_at_unix_ms, send.expires_at_unix_ms);
    assert_ne!(receive.grant.capability_id, send.capability_id);
    assert_ne!(receive.grant.revocation_id, send.revocation_id);
    let mut next_boot = binding.clone();
    next_boot.boot = BootId::from_bytes([42; 32]);
    assert_ne!(
        mint_guest_receive_capability(&grant, &next_boot, &signed_send, send.address, &authority,)
            .unwrap()
            .grant
            .capability_id,
        receive.grant.capability_id,
        "a warm child must receive a fresh boot-scoped capability",
    );

    enrollment.consumer = receive.grant.subject;
    enrollment.receive_capability_id = receive.grant.capability_id;
    let signed_enrollment = sign_guest_reader_enrollment(enrollment, &authority).unwrap();
    let scope = MailboxGuestReaderScope {
        plan: &grant,
        plan_id: &plan_id,
        plan_nonce: &plan_nonce,
        receive: &receive.grant,
        current_boot: binding.boot,
        current_session: signed_enrollment.enrollment.consumer_session,
        now_unix_ms: 150,
    };
    verify_guest_reader_enrollment(
        &signed_enrollment,
        &receive,
        &scope,
        &authority.verifying_key(),
        &[],
    )
    .unwrap();

    let mut stale = binding.clone();
    stale.boot = BootId::from_bytes([0; 32]);
    assert!(
        mint_guest_receive_capability(&grant, &stale, &signed_send, send.address, &authority)
            .is_err()
    );
    stale = binding.clone();
    stale.execution_epoch = ExecutionEpoch::new(8).unwrap();
    assert!(
        mint_guest_receive_capability(&grant, &stale, &signed_send, send.address, &authority)
            .is_err()
    );
    stale = binding.clone();
    stale.mailbox = MailboxId::from_bytes([99; 32]);
    assert!(
        mint_guest_receive_capability(&grant, &stale, &signed_send, send.address, &authority)
            .is_err()
    );
    let mut wrong_address = send.clone();
    wrong_address.address.tenant = TenantId::from_bytes([99; 32]);
    let signed_other = sign_capability(wrong_address, &authority).unwrap();
    assert!(
        mint_guest_receive_capability(&grant, &binding, &signed_other, send.address, &authority)
            .is_err(),
        "a signed Send grant for another tenant must not authorize our inbox",
    );
    let mut tampered = signed_send.clone();
    tampered.grant.address.recipient = PrincipalId::from_bytes([24; 32]);
    assert!(
        mint_guest_receive_capability(&grant, &binding, &tampered, send.address, &authority)
            .is_err()
    );
    assert!(
        mint_guest_receive_capability(
            &grant,
            &binding,
            &signed_send,
            send.address,
            &SigningKey::from_bytes(&[75; 32]),
        )
        .is_err()
    );
}

#[test]
fn enrolled_reader_requires_two_authority_signatures_and_fresh_guest_possession() {
    let (authority, guest, plan, plan_id, plan_nonce, receive, enrollment) = fixture();
    let cap = sign_capability(receive.clone(), &authority).unwrap();
    let signed = sign_guest_reader_enrollment(enrollment, &authority).unwrap();
    let scope = MailboxGuestReaderScope {
        plan: &plan,
        plan_id: &plan_id,
        plan_nonce: &plan_nonce,
        receive: &receive,
        current_boot: signed.enrollment.consumer_boot,
        current_session: signed.enrollment.consumer_session,
        now_unix_ms: 150,
    };
    let key =
        verify_guest_reader_enrollment(&signed, &cap, &scope, &authority.verifying_key(), &[])
            .expect("current signed plan and Receive grant");
    let challenge = [20; 32];
    let proof = sign_reader_possession(&signed, &challenge, &guest).unwrap();
    verify_reader_possession(&signed, &challenge, &proof, &key).unwrap();
    assert_eq!(
        verify_reader_possession(&signed, &[21; 32], &proof, &key),
        Err(MailboxError::ReaderPossessionInvalid),
        "a proof for one fresh host challenge cannot answer another"
    );
    assert_eq!(
        verify_reader_possession(&signed, &[0; 32], &proof, &key),
        Err(MailboxError::ReaderPossessionInvalid)
    );
    assert_eq!(
        sign_reader_possession(&signed, &challenge, &authority),
        Err(MailboxError::ReaderKeyInvalid),
        "the host authority must not substitute for the guest-held key"
    );

    let mut forged_enrollment = signed.clone();
    forged_enrollment.enrollment.ack_public_key =
        SigningKey::from_bytes(&[44; 32]).verifying_key().to_bytes();
    assert_eq!(
        verify_guest_reader_enrollment(
            &forged_enrollment,
            &cap,
            &scope,
            &authority.verifying_key(),
            &[],
        ),
        Err(MailboxError::ReaderEnrollmentSignatureInvalid)
    );
    let mut forged_capability = cap.clone();
    forged_capability.signature[0] ^= 1;
    assert_eq!(
        verify_guest_reader_enrollment(
            &signed,
            &forged_capability,
            &scope,
            &authority.verifying_key(),
            &[],
        ),
        Err(MailboxError::CapabilitySignatureInvalid)
    );
    assert_eq!(
        verify_guest_reader_enrollment(
            &signed,
            &cap,
            &scope,
            &authority.verifying_key(),
            &[receive.revocation_id],
        ),
        Err(MailboxError::CapabilityRevoked)
    );
}

#[test]
fn enrollment_refuses_stale_boot_plan_recipient_and_policy_before_key_use() {
    let (authority, _, plan, plan_id, plan_nonce, receive, enrollment) = fixture();
    let signed = sign_guest_reader_enrollment(enrollment, &authority).unwrap();
    let cap = sign_capability(receive.clone(), &authority).unwrap();
    let scope = MailboxGuestReaderScope {
        plan: &plan,
        plan_id: &plan_id,
        plan_nonce: &plan_nonce,
        receive: &receive,
        current_boot: signed.enrollment.consumer_boot,
        current_session: signed.enrollment.consumer_session,
        now_unix_ms: 150,
    };
    let mut previous_boot = scope;
    previous_boot.current_boot = BootId::from_bytes([99; 32]);
    assert!(
        verify_guest_reader_enrollment(
            &signed,
            &cap,
            &previous_boot,
            &authority.verifying_key(),
            &[],
        )
        .is_err()
    );
    let wrong_nonce = Nonce::from_bytes([98; 16]);
    let wrong_plan = MailboxGuestReaderScope {
        plan_nonce: &wrong_nonce,
        ..scope
    };
    assert!(verify_guest_reader_enrollment(
        &signed,
        &cap,
        &wrong_plan,
        &authority.verifying_key(),
        &[],
    )
    .is_err());
    let mut wrong_recipient = receive.clone();
    wrong_recipient.address.recipient = PrincipalId::from_bytes([97; 32]);
    let wrong_scope = MailboxGuestReaderScope {
        receive: &wrong_recipient,
        ..scope
    };
    assert_eq!(
        verify_guest_reader_enrollment(
            &signed,
            &cap,
            &wrong_scope,
            &authority.verifying_key(),
            &[],
        ),
        Err(MailboxError::WrongCapability),
        "the verified capability must be exactly the scoped grant"
    );
    let mut stale_policy = receive.clone();
    stale_policy.policy_epoch += 1;
    let stale_cap = sign_capability(stale_policy.clone(), &authority).unwrap();
    let stale_scope = MailboxGuestReaderScope {
        receive: &stale_policy,
        ..scope
    };
    assert!(
        verify_guest_reader_enrollment(
            &signed,
            &stale_cap,
            &stale_scope,
            &authority.verifying_key(),
            &[],
        )
        .is_err()
    );
}

#[test]
fn lease_and_ack_signatures_bind_committed_ciphertext_and_consumer() {
    let (authority, guest, plan, plan_id, plan_nonce, receive, enrollment) = fixture();
    let signed_enrollment = sign_guest_reader_enrollment(enrollment.clone(), &authority).unwrap();
    let capability = sign_capability(receive.clone(), &authority).unwrap();
    let header = MailboxEnvelopeHeader {
        protocol_version: ProtocolVersion::V1,
        signature_algorithm: SignatureAlgorithm::ED25519,
        tenant: receive.address.tenant,
        authorization_domain: receive.address.authorization_domain,
        sender: PrincipalId::from_bytes([30; 32]),
        recipient: receive.address.recipient,
        mailbox: plan.mailbox,
        sender_boot: BootId::from_bytes([31; 32]),
        execution_epoch: plan.epoch,
        message_id: MessageId::from_bytes([32; 32]),
        correlation_id: CorrelationId::from_bytes([33; 32]),
        causation_id: mvm_contract::protocol::mailbox::CausationId::from_bytes([34; 32]),
        kind: MailboxMessageKind::Cast,
        reply_to: None,
        ordering_scope: OrderingScope::parse("report").unwrap(),
        sequence: SequenceNumber::new(1).unwrap(),
        issued_at_unix_ms: 110,
        expires_at_unix_ms: 200,
        nonce: ReplayNonce::from_bytes([35; 16]),
        content_type: receive.content_types[0].clone(),
        capability_id: CapabilityId::from_bytes([36; 32]),
        policy_epoch: receive.policy_epoch,
        encryption: EncryptionContext {
            algorithm: EncryptionAlgorithm::AES_256_GCM,
            key_id: [37; 32],
        },
        plaintext_len: 5,
    };
    let envelope = seal_envelope(
        SealRequest {
            routing: MailboxRoutingFrame {
                protocol_version: ProtocolVersion::V1,
                authorization_domain_route_label: AuthorizationDomainRouteLabel::from_bytes(
                    [38; 32],
                ),
                destination_route_token: DestinationRouteToken::from_bytes([39; 32]),
                delivery_id: DeliveryId::from_bytes([40; 32]),
                ciphertext_len: 0,
                padding: mvm_contract::protocol::mailbox::CiphertextPadding::Exact,
                expires_at_unix_ms: header.expires_at_unix_ms,
                hop_limit: 1,
                transport_binding_id: TransportBindingId::from_bytes([41; 32]),
            },
            header: header.clone(),
            plaintext: b"hello",
        },
        &Key::from_bytes([42; 32]),
        &SigningKey::from_bytes(&[43; 32]),
    )
    .unwrap();
    let lease = sign_delivery_lease(
        MailboxDeliveryLease {
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            address: receive.address,
            sender: header.sender,
            sender_boot: header.sender_boot,
            message_id: header.message_id,
            delivery_id: envelope.routing.delivery_id,
            execution_epoch: plan.epoch,
            consumer: receive.subject,
            consumer_session: enrollment.consumer_session,
            receive_capability_id: receive.capability_id,
            policy_epoch: receive.policy_epoch,
            ciphertext_commitment: envelope.ciphertext_commitment,
            issued_at_unix_ms: 120,
            expires_at_unix_ms: 190,
            lease_nonce: DeliveryLeaseNonce::from_bytes([44; 16]),
        },
        &authority,
    )
    .unwrap();
    let authority_vk = authority.verifying_key();
    let context = ReaderDeliveryContext {
        plan: &plan,
        capability: &capability,
        reader_scope: MailboxGuestReaderScope {
            plan: &plan,
            plan_id: &plan_id,
            plan_nonce: &plan_nonce,
            receive: &receive,
            current_boot: enrollment.consumer_boot,
            current_session: enrollment.consumer_session,
            now_unix_ms: 150,
        },
        consumer_session: enrollment.consumer_session,
        now_unix_ms: 150,
        envelope: &envelope,
        header: &header,
        authority: &authority_vk,
        revoked: &[],
    };
    let verify_lease = |value: &SignedMailboxDeliveryLease| verify_delivery_lease(value, &context);
    verify_lease(&lease).unwrap();
    let ack = sign_delivery_ack(
        MailboxDeliveryAck {
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            lease: lease.clone(),
            ack_nonce: DeliveryAckNonce::from_bytes([45; 16]),
            acknowledged_at_unix_ms: 150,
        },
        &guest,
    )
    .unwrap();
    let verify_ack = |value: &SignedMailboxDeliveryAck, session| {
        verify_delivery_ack(
            value,
            &lease,
            &ReaderDeliveryContext {
                consumer_session: session,
                ..context
            },
            &signed_enrollment,
            &guest.verifying_key(),
        )
    };
    verify_ack(&ack, enrollment.consumer_session).unwrap();
    let wrong_guest = SigningKey::from_bytes(&[99; 32]).verifying_key();
    assert_eq!(
        verify_delivery_ack(&ack, &lease, &context, &signed_enrollment, &wrong_guest),
        Err(MailboxError::ReaderKeyInvalid)
    );
    let mut forged_enrollment = signed_enrollment.clone();
    forged_enrollment.signature[0] ^= 1;
    assert_eq!(
        verify_delivery_ack(
            &ack,
            &lease,
            &context,
            &forged_enrollment,
            &guest.verifying_key(),
        ),
        Err(MailboxError::ReaderEnrollmentSignatureInvalid)
    );
    let previous_boot = ReaderDeliveryContext {
        reader_scope: MailboxGuestReaderScope {
            current_boot: BootId::from_bytes([92; 32]),
            ..context.reader_scope
        },
        ..context
    };
    assert!(
        verify_delivery_ack(
            &ack,
            &lease,
            &previous_boot,
            &signed_enrollment,
            &guest.verifying_key(),
        )
        .is_err()
    );
    let stale_nonce = Nonce::from_bytes([93; 16]);
    let wrong_plan = ReaderDeliveryContext {
        reader_scope: MailboxGuestReaderScope {
            plan_nonce: &stale_nonce,
            ..context.reader_scope
        },
        ..context
    };
    assert!(
        verify_delivery_ack(
            &ack,
            &lease,
            &wrong_plan,
            &signed_enrollment,
            &guest.verifying_key(),
        )
        .is_err()
    );
    let other_guest = SigningKey::from_bytes(&[98; 32]);
    let forged_ack = sign_delivery_ack(ack.ack.clone(), &other_guest).unwrap();
    assert_eq!(
        verify_delivery_ack(
            &forged_ack,
            &lease,
            &context,
            &signed_enrollment,
            &guest.verifying_key(),
        ),
        Err(MailboxError::DeliveryAckSignatureInvalid)
    );
    assert_eq!(
        verify_delivery_lease(
            &lease,
            &ReaderDeliveryContext {
                revoked: &[receive.revocation_id],
                ..context
            },
        ),
        Err(MailboxError::CapabilityRevoked)
    );
    let mut different_ciphertext = envelope.clone();
    different_ciphertext.ciphertext_commitment[0] ^= 1;
    assert_eq!(
        verify_delivery_lease(
            &lease,
            &ReaderDeliveryContext {
                envelope: &different_ciphertext,
                ..context
            },
        ),
        Err(MailboxError::DeliveryLeaseMismatch)
    );
    let mut bad_lease = lease.clone();
    bad_lease.signature[0] ^= 1;
    assert_eq!(
        verify_lease(&bad_lease),
        Err(MailboxError::DeliveryLeaseSignatureInvalid)
    );
    bad_lease = lease.clone();
    bad_lease.lease.ciphertext_commitment[0] ^= 1;
    assert_eq!(
        verify_lease(&bad_lease),
        Err(MailboxError::DeliveryLeaseMismatch)
    );
    let mut bad_ack = ack.clone();
    bad_ack.signature[0] ^= 1;
    assert_eq!(
        verify_ack(&bad_ack, enrollment.consumer_session),
        Err(MailboxError::DeliveryAckSignatureInvalid)
    );
    bad_ack = ack.clone();
    bad_ack.ack.lease.lease.lease_nonce = DeliveryLeaseNonce::from_bytes([46; 16]);
    assert_eq!(
        verify_ack(&bad_ack, enrollment.consumer_session),
        Err(MailboxError::DeliveryLeaseMismatch)
    );
    assert!(
        verify_ack(&ack, ConsumerSessionId::from_bytes([47; 32])).is_err(),
        "an inherited or stale reader session must not ACK this lease"
    );
}
