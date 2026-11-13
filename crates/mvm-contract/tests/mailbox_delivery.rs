use mvm_contract::plan::{Nonce, PlanId};
use mvm_contract::protocol::mailbox::{
    AuthorizationDomainId, BootId, CapabilityId, CapabilityOperations, ConsumerSessionId,
    ContentType, DeliveryAckNonce, DeliveryId, DeliveryLeaseNonce, ExecutionEpoch, MailboxAddress,
    MailboxCapabilityGrant, MailboxDeliveryAck, MailboxDeliveryError, MailboxDeliveryLease,
    MailboxGrant, MailboxGuestReaderEnrollment, MailboxGuestReaderScope, MailboxId,
    MailboxMessageKind, MailboxOperation, MailboxReportSendPolicy, MessageId, PrincipalId,
    ProtocolVersion, ReplyRoute, RevocationId, SignatureAlgorithm, SignedMailboxDeliveryAck,
    SignedMailboxDeliveryLease, SignedMailboxGuestReaderEnrollment, TenantId,
};

fn address() -> MailboxAddress {
    MailboxAddress {
        tenant: TenantId::from_bytes([1; 32]),
        authorization_domain: AuthorizationDomainId::from_bytes([2; 32]),
        mailbox: MailboxId::from_bytes([3; 32]),
        recipient: PrincipalId::from_bytes([4; 32]),
    }
}

fn plan_grant() -> MailboxGrant {
    MailboxGrant {
        mailbox: address().mailbox,
        authority_key: [5; 32],
        epoch: ExecutionEpoch::new(7).expect("epoch"),
        report: None,
        retention: None,
    }
}

#[test]
fn report_policy_is_signed_plan_only_and_legacy_grants_stay_byte_identical() {
    let old = plan_grant();
    let encoded = serde_json::to_vec(&old).expect("serialize legacy grant");
    assert!(!String::from_utf8_lossy(&encoded).contains("report"));
    assert_eq!(
        serde_json::from_slice::<MailboxGrant>(&encoded).expect("old plan grant"),
        old
    );
    let mut enabled = old;
    enabled.report = Some(MailboxReportSendPolicy::new(16 * 1024).expect("bound"));
    let encoded = serde_json::to_vec(&enabled).expect("serialize plan grant");
    assert_eq!(
        serde_json::from_slice::<MailboxGrant>(&encoded).expect("report plan grant"),
        enabled
    );
    assert!(String::from_utf8_lossy(&encoded).contains("\"report\""));
    assert_ne!(old, enabled, "missing policy cannot authorize a report");
    for (version, max_payload_bytes) in [(2, 100), (1, 0), (1, 1024 * 1024 + 1)] {
        let mut changed: serde_json::Value = serde_json::from_slice(&encoded).expect("JSON");
        changed["report"]["version"] = version.into();
        changed["report"]["max_payload_bytes"] = max_payload_bytes.into();
        assert!(
            serde_json::from_value::<MailboxGrant>(changed).is_err(),
            "unsupported version or payload bound must refuse"
        );
    }
}

#[test]
fn report_policy_allows_only_its_signed_cast_type_and_bounded_body() {
    use mvm_contract::protocol::mailbox::MailboxContractError;
    use mvm_contract::protocol::workload_report::{
        WORKLOAD_REPORT_CONTENT_TYPE, WORKLOAD_REPORT_VERSION,
    };

    let report_type = ContentType::parse(WORKLOAD_REPORT_CONTENT_TYPE, WORKLOAD_REPORT_VERSION)
        .expect("static content type");
    let ordinary_type =
        ContentType::parse("application/vnd.mvm.guest-message", 1).expect("static content type");
    let old = plan_grant();
    assert_eq!(
        old.check_report_send(MailboxMessageKind::Cast, &report_type, None, 1),
        Err(MailboxContractError::ReportNotGranted)
    );

    let mut enabled = old;
    enabled.report = Some(MailboxReportSendPolicy::new(16 * 1024).expect("bound"));
    assert_eq!(
        enabled.check_report_send(MailboxMessageKind::Cast, &report_type, None, 16 * 1024),
        Ok(())
    );
    assert_eq!(
        enabled.check_report_send(MailboxMessageKind::Cast, &report_type, None, 16 * 1024 + 1),
        Err(MailboxContractError::ReportPayloadTooLarge)
    );
    assert_eq!(
        enabled.check_report_send(MailboxMessageKind::Call, &report_type, None, 1),
        Err(MailboxContractError::InvalidReportMessageKind)
    );
    let reply = ReplyRoute {
        address: address(),
        capability_id: CapabilityId::from_bytes([19; 32]),
    };
    assert_eq!(
        enabled.check_report_send(MailboxMessageKind::Cast, &report_type, Some(&reply), 1),
        Err(MailboxContractError::InvalidReportMessageKind)
    );
    assert_eq!(
        enabled.check_report_send(MailboxMessageKind::Cast, &ordinary_type, None, 1),
        Err(MailboxContractError::InvalidReportContentType)
    );
}

fn receive_capability() -> MailboxCapabilityGrant {
    MailboxCapabilityGrant {
        protocol_version: ProtocolVersion::V1,
        signature_algorithm: SignatureAlgorithm::ED25519,
        capability_id: CapabilityId::from_bytes([6; 32]),
        issuer: PrincipalId::from_bytes([5; 32]),
        subject: PrincipalId::from_bytes([8; 32]),
        address: address(),
        operations: CapabilityOperations::from_operations(&[MailboxOperation::Receive]),
        message_kinds: vec![MailboxMessageKind::Cast],
        content_types: vec![
            ContentType::parse("application/vnd.mvm.workload-report", 1)
                .expect("static content type"),
        ],
        max_payload_bytes: 1024,
        max_messages_per_minute: 60,
        max_outstanding_calls: 1,
        max_queue_contribution_bytes: 4096,
        minimum_execution_epoch: plan_grant().epoch,
        maximum_execution_epoch: plan_grant().epoch,
        policy_epoch: 2,
        not_before_unix_ms: 50,
        expires_at_unix_ms: 300,
        revocation_id: RevocationId::from_bytes([9; 32]),
        delegation_depth: 0,
    }
}

fn current_session() -> ConsumerSessionId {
    ConsumerSessionId::from_bytes([14; 32])
}

fn lease() -> MailboxDeliveryLease {
    MailboxDeliveryLease {
        protocol_version: ProtocolVersion::V1,
        signature_algorithm: SignatureAlgorithm::ED25519,
        address: address(),
        sender: PrincipalId::from_bytes([10; 32]),
        sender_boot: BootId::from_bytes([11; 32]),
        message_id: MessageId::from_bytes([12; 32]),
        delivery_id: DeliveryId::from_bytes([13; 32]),
        execution_epoch: plan_grant().epoch,
        consumer: receive_capability().subject,
        consumer_session: current_session(),
        receive_capability_id: receive_capability().capability_id,
        policy_epoch: 2,
        ciphertext_commitment: [15; 32],
        issued_at_unix_ms: 100,
        expires_at_unix_ms: 200,
        lease_nonce: DeliveryLeaseNonce::from_bytes([16; 16]),
    }
}

fn reader_plan_id() -> PlanId {
    PlanId("sha256:".to_owned() + &"a".repeat(64))
}

fn reader_plan_nonce() -> Nonce {
    Nonce::from_bytes([26; 16])
}

fn reader_boot() -> BootId {
    BootId::from_bytes([27; 32])
}

fn reader_enrollment() -> SignedMailboxGuestReaderEnrollment {
    SignedMailboxGuestReaderEnrollment {
        enrollment: MailboxGuestReaderEnrollment {
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            plan_id: reader_plan_id(),
            plan_nonce: reader_plan_nonce(),
            address: address(),
            consumer: receive_capability().subject,
            consumer_boot: reader_boot(),
            consumer_session: current_session(),
            receive_capability_id: receive_capability().capability_id,
            ack_public_key: [28; 32],
            execution_epoch: plan_grant().epoch,
            policy_epoch: 2,
            issued_at_unix_ms: 100,
            expires_at_unix_ms: 200,
        },
        signature: vec![29; 64],
    }
}

#[test]
fn enrolled_guest_reader_requires_its_current_plan_boot_and_receive_grant() {
    let plan = plan_grant();
    let cap = receive_capability();
    let plan_id = reader_plan_id();
    let plan_nonce = reader_plan_nonce();
    let scope = MailboxGuestReaderScope {
        plan: &plan,
        plan_id: &plan_id,
        plan_nonce: &plan_nonce,
        receive: &cap,
        current_boot: reader_boot(),
        current_session: current_session(),
        now_unix_ms: 150,
    };
    let enrolled = reader_enrollment();
    assert_eq!(enrolled.check_scope(&scope), Ok(()));
    assert_eq!(
        SignedMailboxGuestReaderEnrollment::decode(&enrolled.encode().expect("bounded enrollment"))
            .expect("decode enrollment"),
        enrolled
    );

    let mut stale_parent = scope;
    stale_parent.current_boot = BootId::from_bytes([30; 32]);
    assert_eq!(
        enrolled.check_scope(&stale_parent),
        Err(MailboxDeliveryError::StaleConsumerBoot)
    );
    let stale_session = MailboxGuestReaderScope {
        current_session: ConsumerSessionId::from_bytes([33; 32]),
        ..scope
    };
    assert_eq!(
        enrolled.check_scope(&stale_session),
        Err(MailboxDeliveryError::StaleConsumerSession)
    );
    let wrong_nonce = Nonce::from_bytes([31; 16]);
    let wrong_plan = MailboxGuestReaderScope {
        plan_nonce: &wrong_nonce,
        ..scope
    };
    assert_eq!(
        enrolled.check_scope(&wrong_plan),
        Err(MailboxDeliveryError::WrongPlanIdentity)
    );
    let mut wrong_recipient = cap.clone();
    wrong_recipient.address.recipient = PrincipalId::from_bytes([32; 32]);
    let wrong_scope = MailboxGuestReaderScope {
        receive: &wrong_recipient,
        ..scope
    };
    assert_eq!(
        enrolled.check_scope(&wrong_scope),
        Err(MailboxDeliveryError::WrongAddress)
    );
    let expired = MailboxGuestReaderScope {
        now_unix_ms: 200,
        ..scope
    };
    assert_eq!(
        enrolled.check_scope(&expired),
        Err(MailboxDeliveryError::Expired)
    );
}

#[test]
fn forged_or_stale_reader_enrollment_refuses_without_exposing_an_ack_key() {
    let plan = plan_grant();
    let cap = receive_capability();
    let plan_id = reader_plan_id();
    let plan_nonce = reader_plan_nonce();
    let scope = MailboxGuestReaderScope {
        plan: &plan,
        plan_id: &plan_id,
        plan_nonce: &plan_nonce,
        receive: &cap,
        current_boot: reader_boot(),
        current_session: current_session(),
        now_unix_ms: 150,
    };
    let mut enrolled = reader_enrollment();
    enrolled.enrollment.ack_public_key = [0; 32];
    assert_eq!(
        enrolled.check_scope(&scope),
        Err(MailboxDeliveryError::InvalidReaderKey)
    );
    enrolled = reader_enrollment();
    enrolled.signature.clear();
    assert_eq!(
        enrolled.check_scope(&scope),
        Err(MailboxDeliveryError::InvalidSignatureLength)
    );
    let mut stale = reader_enrollment();
    stale.enrollment.execution_epoch = ExecutionEpoch::new(8).expect("epoch");
    assert_eq!(
        stale.check_scope(&scope),
        Err(MailboxDeliveryError::StaleExecutionEpoch)
    );
    stale = reader_enrollment();
    stale.enrollment.policy_epoch = 3;
    assert_eq!(
        stale.check_scope(&scope),
        Err(MailboxDeliveryError::StalePolicyEpoch)
    );
    let mut send_only = cap.clone();
    send_only.operations = CapabilityOperations::from_operations(&[MailboxOperation::Send]);
    let wrong_scope = MailboxGuestReaderScope {
        receive: &send_only,
        ..scope
    };
    assert_eq!(
        reader_enrollment().check_scope(&wrong_scope),
        Err(MailboxDeliveryError::ReceiveNotAuthorized)
    );
}

#[test]
fn signed_lease_and_ack_round_trip_with_exact_reader_scope() {
    let signed_lease = SignedMailboxDeliveryLease {
        lease: lease(),
        signature: vec![17; 64],
    };
    let ack = SignedMailboxDeliveryAck {
        ack: MailboxDeliveryAck {
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            lease: signed_lease.clone(),
            ack_nonce: DeliveryAckNonce::from_bytes([18; 16]),
            acknowledged_at_unix_ms: 150,
        },
        signature: vec![19; 64],
    };
    assert_eq!(
        signed_lease.check_scope(&plan_grant(), &receive_capability(), current_session(), 150),
        Ok(())
    );
    assert_eq!(
        ack.check_scope(&plan_grant(), &receive_capability(), current_session(), 150),
        Ok(())
    );
    let wire = serde_json::to_vec(&ack).expect("encode");
    assert_eq!(
        serde_json::from_slice::<SignedMailboxDeliveryAck>(&wire).expect("decode"),
        ack
    );
    assert_eq!(ack.ack.lease.lease.delivery_id, lease().delivery_id);
    assert_eq!(
        ack.ack.lease.lease.consumer_session,
        lease().consumer_session
    );
    let lease_wire = signed_lease.encode().expect("bounded lease");
    assert_eq!(
        SignedMailboxDeliveryLease::decode(&lease_wire).expect("decode lease"),
        signed_lease
    );
    let ack_wire = ack.encode().expect("bounded acknowledgement");
    let retried = SignedMailboxDeliveryAck::decode(&ack_wire).expect("decode ACK");
    assert_eq!(retried, ack);
    assert_eq!(retried.replay_identity(), ack.replay_identity());
    let mut conflicting = retried.clone();
    conflicting.ack.lease.lease.message_id = MessageId::from_bytes([42; 32]);
    assert_eq!(
        conflicting.replay_identity(),
        ack.replay_identity(),
        "same ACK operation with changed content must be a conflict, not a fresh identity"
    );
    conflicting.ack.ack_nonce = DeliveryAckNonce::from_bytes([43; 16]);
    assert_eq!(
        conflicting.replay_identity(),
        ack.replay_identity(),
        "a second nonce cannot create a second ACK for one lease"
    );
}

#[test]
fn control_frames_are_bounded_before_parsing_and_reject_unknown_fields() {
    use mvm_contract::protocol::mailbox::MAX_MAILBOX_DELIVERY_CONTROL_BYTES;

    let oversized = vec![b'x'; MAX_MAILBOX_DELIVERY_CONTROL_BYTES + 1];
    assert_eq!(
        SignedMailboxDeliveryLease::decode(&oversized),
        Err(MailboxDeliveryError::Oversized)
    );
    assert_eq!(
        SignedMailboxDeliveryAck::decode(&oversized),
        Err(MailboxDeliveryError::Oversized)
    );
    assert_eq!(
        SignedMailboxGuestReaderEnrollment::decode(&oversized),
        Err(MailboxDeliveryError::Oversized)
    );
    let mut wire = serde_json::to_value(SignedMailboxDeliveryLease {
        lease: lease(),
        signature: vec![17; 64],
    })
    .expect("encode lease");
    wire["lease"]["unknown"] = true.into();
    assert_eq!(
        SignedMailboxDeliveryLease::decode(&serde_json::to_vec(&wire).expect("JSON")),
        Err(MailboxDeliveryError::Malformed)
    );
    let mut lease = SignedMailboxDeliveryLease {
        lease: lease(),
        signature: vec![17; 64],
    };
    lease.lease.protocol_version = ProtocolVersion(2);
    assert_eq!(
        lease.encode(),
        Err(MailboxDeliveryError::UnsupportedVersion)
    );
    lease.lease.protocol_version = ProtocolVersion::V1;
    lease.signature.clear();
    assert_eq!(
        lease.encode(),
        Err(MailboxDeliveryError::InvalidSignatureLength)
    );
}

#[test]
fn receive_is_never_authorized_by_address_or_transport_alone() {
    let lease = lease();
    let mut capability = receive_capability();
    capability.operations = CapabilityOperations::from_operations(&[MailboxOperation::Send]);
    assert_eq!(
        lease.check_scope(&plan_grant(), &capability, current_session(), 150),
        Err(MailboxDeliveryError::ReceiveNotAuthorized)
    );

    let mut capability = receive_capability();
    capability.address.tenant = TenantId::from_bytes([20; 32]);
    assert_eq!(
        lease.check_scope(&plan_grant(), &capability, current_session(), 150),
        Err(MailboxDeliveryError::WrongAddress)
    );
    let mut capability = receive_capability();
    capability.address.recipient = PrincipalId::from_bytes([21; 32]);
    assert_eq!(
        lease.check_scope(&plan_grant(), &capability, current_session(), 150),
        Err(MailboxDeliveryError::WrongAddress)
    );
    let mut capability = receive_capability();
    capability.subject = PrincipalId::from_bytes([22; 32]);
    assert_eq!(
        lease.check_scope(&plan_grant(), &capability, current_session(), 150),
        Err(MailboxDeliveryError::WrongConsumer)
    );
    assert_eq!(
        lease.check_scope(
            &plan_grant(),
            &receive_capability(),
            ConsumerSessionId::from_bytes([99; 32]),
            150
        ),
        Err(MailboxDeliveryError::StaleConsumerSession)
    );
    let mut capability = receive_capability();
    capability.capability_id = CapabilityId::from_bytes([23; 32]);
    assert_eq!(
        lease.check_scope(&plan_grant(), &capability, current_session(), 150),
        Err(MailboxDeliveryError::WrongCapability)
    );
}

#[test]
fn stale_epoch_policy_and_expired_lease_cannot_acknowledge() {
    let mut plan = plan_grant();
    plan.epoch = ExecutionEpoch::new(8).expect("new epoch");
    assert_eq!(
        lease().check_scope(&plan, &receive_capability(), current_session(), 150),
        Err(MailboxDeliveryError::StaleExecutionEpoch)
    );
    plan = plan_grant();
    plan.mailbox = MailboxId::from_bytes([24; 32]);
    assert_eq!(
        lease().check_scope(&plan, &receive_capability(), current_session(), 150),
        Err(MailboxDeliveryError::WrongPlanMailbox)
    );
    let mut capability = receive_capability();
    capability.policy_epoch = 3;
    assert_eq!(
        lease().check_scope(&plan_grant(), &capability, current_session(), 150),
        Err(MailboxDeliveryError::StalePolicyEpoch)
    );
    assert_eq!(
        lease().check_scope(&plan_grant(), &receive_capability(), current_session(), 200),
        Err(MailboxDeliveryError::Expired)
    );

    let mut ack = SignedMailboxDeliveryAck {
        ack: MailboxDeliveryAck {
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            lease: SignedMailboxDeliveryLease {
                lease: lease(),
                signature: vec![17; 64],
            },
            ack_nonce: DeliveryAckNonce::from_bytes([18; 16]),
            acknowledged_at_unix_ms: 201,
        },
        signature: vec![19; 64],
    };
    assert_eq!(
        ack.check_scope(&plan_grant(), &receive_capability(), current_session(), 150),
        Err(MailboxDeliveryError::AckOutsideLease)
    );
    ack.ack.acknowledged_at_unix_ms = 150;
    ack.signature.clear();
    assert_eq!(
        ack.check_scope(&plan_grant(), &receive_capability(), current_session(), 150),
        Err(MailboxDeliveryError::InvalidSignatureLength)
    );
}
