use super::*;
use mvm_contract::protocol::mailbox::{
    AuthorizationDomainId, BootId, CapabilityId, CapabilityOperations, CausationId,
    CiphertextPadding, ContentType, CorrelationId, DeliveryId, DeliveryOutcome,
    EncryptionAlgorithm, EncryptionContext, MailboxCapabilityGrant, MailboxId, MailboxMessageKind,
    MailboxRoutingFrame, MessageId, OrderingScope, ReplayNonce, RevocationId, SequenceNumber,
    TenantId,
};

use crate::crypto::aead::Key;
use crate::mailbox::journal::{
    FileJournalAnchor, JournalAdmission, JournalError, JournalLimits, JournalReceive, JournalTip,
    MailboxJournal,
};
use crate::mailbox::{
    InMemoryReplayProtector, SealRequest, decode_envelope, open_authenticated_envelope,
    sign_capability,
};

const NOW: i64 = 1_800_000_000_000;

fn id<const N: usize>(byte: u8) -> [u8; N] {
    [byte; N]
}

fn address() -> MailboxAddress {
    MailboxAddress {
        tenant: TenantId::from_bytes(id(1)),
        authorization_domain: AuthorizationDomainId::from_bytes(id(2)),
        mailbox: MailboxId::from_bytes(id(3)),
        recipient: PrincipalId::from_bytes(id(4)),
    }
}

fn issuer() -> PrincipalId {
    PrincipalId::from_bytes(id(5))
}

fn sender() -> PrincipalId {
    PrincipalId::from_bytes(id(6))
}

fn epoch() -> ExecutionEpoch {
    ExecutionEpoch::new(7).expect("nonzero epoch")
}

fn claims(path: TransportPath, route_byte: u8) -> TransportBindingClaims {
    TransportBindingClaims {
        protocol_version: ProtocolVersion::V1,
        signature_algorithm: SignatureAlgorithm::ED25519,
        binding_id: TransportBindingId::from_bytes(id(8)),
        issuer: issuer(),
        address: address(),
        execution_epoch: epoch(),
        transport_identity: TransportIdentity::from_bytes(id(9)),
        route_id: RouteId::from_bytes(id(route_byte)),
        authorization_domain_route_label: AuthorizationDomainRouteLabel::from_bytes(id(10)),
        destination_route_token: DestinationRouteToken::from_bytes(id(11)),
        path,
        locator: RouteLocator::parse(format!("memory://route-{route_byte}")).expect("locator"),
        assurance: TransportAssurance::IsolatedProduction,
        policy_epoch: 12,
        not_before_unix_ms: NOW - 1,
        expires_at_unix_ms: NOW + 10_000,
    }
}

fn binding_context() -> TransportBindingContext {
    TransportBindingContext {
        expected_issuer: issuer(),
        expected_address: address(),
        current_execution_epoch: epoch(),
        current_policy_epoch: 12,
        minimum_assurance: TransportAssurance::IsolatedProduction,
        now_unix_ms: NOW,
        revoked_bindings: Vec::new(),
    }
}

fn signed_route(
    path: TransportPath,
    route_byte: u8,
    authority: &SigningKey,
) -> (SignedTransportBinding, AuthorizedRoute) {
    let signed =
        sign_transport_binding(claims(path, route_byte), authority).expect("binding signs");
    let route = authorize_route(&signed, &binding_context(), &authority.verifying_key())
        .expect("binding verifies");
    (signed, route)
}

struct MailboxFixture {
    prepared: PreparedMailboxEnvelope,
    capability: SignedMailboxCapability,
    context: OpenContext,
    capability_authority: SigningKey,
}

fn mailbox_fixture() -> MailboxFixture {
    let content_type = ContentType::parse("application/vnd.mvm.test", 1).expect("content type");
    let header = MailboxEnvelopeHeader {
        protocol_version: ProtocolVersion::V1,
        signature_algorithm: SignatureAlgorithm::ED25519,
        tenant: address().tenant,
        authorization_domain: address().authorization_domain,
        sender: sender(),
        recipient: address().recipient,
        mailbox: address().mailbox,
        sender_boot: BootId::from_bytes(id(13)),
        execution_epoch: epoch(),
        message_id: MessageId::from_bytes(id(14)),
        correlation_id: CorrelationId::from_bytes(id(15)),
        causation_id: CausationId::from_bytes(id(16)),
        kind: MailboxMessageKind::Cast,
        reply_to: None,
        ordering_scope: OrderingScope::parse("default").expect("ordering scope"),
        sequence: SequenceNumber::new(1).expect("sequence"),
        issued_at_unix_ms: NOW - 1,
        expires_at_unix_ms: NOW + 5_000,
        nonce: ReplayNonce::from_bytes(id(17)),
        content_type: content_type.clone(),
        capability_id: CapabilityId::from_bytes(id(18)),
        policy_epoch: 12,
        encryption: EncryptionContext {
            algorithm: EncryptionAlgorithm::AES_256_GCM,
            key_id: id(19),
        },
        plaintext_len: 5,
    };
    let routing = MailboxRoutingFrame {
        protocol_version: ProtocolVersion::V1,
        authorization_domain_route_label: AuthorizationDomainRouteLabel::from_bytes(id(10)),
        destination_route_token: DestinationRouteToken::from_bytes(id(11)),
        delivery_id: DeliveryId::from_bytes(id(20)),
        ciphertext_len: 0,
        padding: CiphertextPadding::Exact,
        expires_at_unix_ms: header.expires_at_unix_ms,
        hop_limit: 4,
        transport_binding_id: TransportBindingId::from_bytes(id(8)),
    };
    let payload_key = Key::from_bytes(id(21));
    let sender_key = SigningKey::from_bytes(&id(22));
    let prepared = prepare_mailbox_envelope(
        SealRequest {
            routing,
            header: header.clone(),
            plaintext: b"hello",
        },
        &payload_key,
        &sender_key,
    )
    .expect("envelope seals");
    let capability_authority = SigningKey::from_bytes(&id(23));
    let grant = MailboxCapabilityGrant {
        protocol_version: ProtocolVersion::V1,
        signature_algorithm: SignatureAlgorithm::ED25519,
        capability_id: header.capability_id,
        issuer: issuer(),
        subject: sender(),
        address: address(),
        operations: CapabilityOperations::from_operations(&[MailboxOperation::Send]),
        message_kinds: vec![MailboxMessageKind::Cast],
        content_types: vec![content_type.clone()],
        max_payload_bytes: 64,
        max_messages_per_minute: 60,
        max_outstanding_calls: 1,
        max_queue_contribution_bytes: 1024,
        minimum_execution_epoch: epoch(),
        maximum_execution_epoch: epoch(),
        policy_epoch: 12,
        not_before_unix_ms: NOW - 10,
        expires_at_unix_ms: NOW + 10_000,
        revocation_id: RevocationId::from_bytes(id(24)),
        delegation_depth: 0,
    };
    let capability = sign_capability(grant, &capability_authority).expect("capability signs");
    let context = OpenContext {
        expected_tenant: address().tenant,
        expected_authorization_domain: address().authorization_domain,
        expected_mailbox: address().mailbox,
        expected_sender: sender(),
        expected_recipient: address().recipient,
        acting_principal: sender(),
        expected_capability_issuer: issuer(),
        current_execution_epoch: epoch(),
        current_policy_epoch: 12,
        required_operation: MailboxOperation::Send,
        now_unix_ms: NOW,
        accepted_content_types: vec![content_type],
        revoked_capabilities: Vec::new(),
    };
    MailboxFixture {
        prepared,
        capability,
        context,
        capability_authority,
    }
}

#[test]
fn only_an_authenticated_inner_header_can_supply_a_durable_replay_identity() {
    let fixture = mailbox_fixture();
    let mut replay = InMemoryReplayProtector::default();
    let sender_key = SigningKey::from_bytes(&id(22)).verifying_key();
    let opened = open_authenticated_envelope(
        fixture.prepared.envelope(),
        &fixture.capability,
        &fixture.context,
        &Key::from_bytes(id(21)),
        &sender_key,
        &fixture.capability_authority.verifying_key(),
        &mut replay,
    )
    .expect("signed envelope and capability");
    assert_eq!(opened.header().message_id, MessageId::from_bytes(id(14)));
    assert_eq!(opened.payload(), b"hello");
    assert!(
        !format!("{opened:?}").contains("hello"),
        "debug output must not disclose mailbox plaintext"
    );
    assert_eq!(
        open_authenticated_envelope(
            fixture.prepared.envelope(),
            &fixture.capability,
            &fixture.context,
            &Key::from_bytes(id(21)),
            &sender_key,
            &fixture.capability_authority.verifying_key(),
            &mut replay,
        ),
        Err(MailboxError::Replay),
        "the same verified header cannot be admitted twice"
    );
    let mut tampered = fixture.capability.clone();
    tampered.signature[0] ^= 1;
    assert_eq!(
        open_authenticated_envelope(
            fixture.prepared.envelope(),
            &tampered,
            &fixture.context,
            &Key::from_bytes(id(21)),
            &sender_key,
            &fixture.capability_authority.verifying_key(),
            &mut InMemoryReplayProtector::default(),
        ),
        Err(MailboxError::CapabilitySignatureInvalid),
        "an unverified capability cannot yield a journal identity"
    );
}

#[test]
fn receive_requires_its_own_signed_recipient_capability_not_the_send_grant() {
    let fixture = mailbox_fixture();
    let header = mailbox_header_for_retry();
    let mut context = fixture.context.clone();
    context.acting_principal = address().recipient;
    context.required_operation = MailboxOperation::Receive;
    assert_eq!(
        crate::mailbox::authorize_receive(
            &header,
            &fixture.capability,
            &context,
            &fixture.capability_authority.verifying_key()
        ),
        Err(MailboxError::WrongCapabilitySubject),
        "the signed Send grant cannot double as Receive authority"
    );
    let mut grant = fixture.capability.grant.clone();
    grant.capability_id = CapabilityId::from_bytes(id(99));
    grant.subject = address().recipient;
    grant.operations = CapabilityOperations::from_operations(&[MailboxOperation::Receive]);
    let receive = sign_capability(grant, &fixture.capability_authority).unwrap();
    crate::mailbox::authorize_receive(
        &header,
        &receive,
        &context,
        &fixture.capability_authority.verifying_key(),
    )
    .expect("independent Receive capability is authorized");
    let mut stale = context.clone();
    stale.current_execution_epoch = ExecutionEpoch::new(8).unwrap();
    assert_eq!(
        crate::mailbox::authorize_receive(
            &header,
            &receive,
            &stale,
            &fixture.capability_authority.verifying_key()
        ),
        Err(MailboxError::StaleExecutionEpoch)
    );
}

#[test]
fn receive_and_ack_require_independent_authority_and_survive_recovery() {
    let dir = tempfile::tempdir().expect("journal directory");
    let fixture = mailbox_fixture();
    let signer = &fixture.capability_authority;
    let sender = SigningKey::from_bytes(&id(22)).verifying_key();
    let encryption_key = Key::from_bytes(id(21));
    let limits = JournalLimits {
        max_records: 3,
        max_bytes: 64 * 1024,
    };
    let mut journal = MailboxJournal::open(
        dir.path(),
        address(),
        signer.verifying_key(),
        id(90),
        limits,
        JournalTip::genesis(),
    )
    .expect("empty journal");
    let mut tip = JournalTip::genesis();
    journal
        .admit(
            JournalAdmission {
                envelope: fixture.prepared.envelope(),
                capability: &fixture.capability,
                context: &fixture.context,
                encryption_key: &encryption_key,
                sender_key: &sender,
                signer,
            },
            |committed| {
                tip = committed;
                Ok(())
            },
        )
        .expect("durable Send");
    let mut grant = fixture.capability.grant.clone();
    grant.capability_id = CapabilityId::from_bytes(id(99));
    grant.subject = address().recipient;
    grant.operations = CapabilityOperations::from_operations(&[MailboxOperation::Receive]);
    let receive_capability = sign_capability(grant, signer).expect("Receive capability");
    let mut reader = fixture.context.clone();
    reader.acting_principal = address().recipient;
    reader.required_operation = MailboxOperation::Receive;
    let request = |capability| JournalReceive {
        capability,
        context: &reader,
        encryption_key: &encryption_key,
        sender_key: &sender,
    };
    assert!(matches!(
        journal.receive_next(request(&fixture.capability)),
        Err(JournalError::Mailbox(MailboxError::WrongCapabilitySubject))
    ));
    let pending = journal
        .receive_next(request(&receive_capability))
        .expect("authorized Receive")
        .expect("one pending message");
    assert_eq!(pending.payload(), b"hello");
    let identity = pending.identity();
    assert_eq!(
        journal
            .receive_next(request(&receive_capability))
            .expect("at-least-once redelivery before ACK")
            .expect("still pending")
            .identity(),
        identity
    );
    journal
        .acknowledge(identity, request(&receive_capability), |committed| {
            tip = committed;
            Ok(())
        })
        .expect("durable ACK");
    assert_eq!(
        journal
            .acknowledge(identity, request(&receive_capability), |_| {
                panic!("an idempotent ACK cannot append a second event")
            })
            .expect("duplicate ACK"),
        tip
    );
    let mut stale_reader = reader.clone();
    stale_reader.current_execution_epoch = ExecutionEpoch::new(8).unwrap();
    assert!(matches!(
        journal.acknowledge(
            identity,
            JournalReceive {
                capability: &receive_capability,
                context: &stale_reader,
                encryption_key: &encryption_key,
                sender_key: &sender,
            },
            |_| Ok(()),
        ),
        Err(JournalError::Mailbox(MailboxError::StaleExecutionEpoch))
    ));
    assert!(
        journal
            .receive_next(request(&receive_capability))
            .expect("queue after ACK")
            .is_none()
    );
    drop(journal);
    let recovered = MailboxJournal::open(
        dir.path(),
        address(),
        signer.verifying_key(),
        id(90),
        limits,
        tip,
    )
    .expect("journal and ACK recover");
    assert!(
        recovered
            .receive_next(request(&receive_capability))
            .expect("recovered queue")
            .is_none()
    );
    drop(recovered);
    let ack_path = dir.path().join("entry-00000000000000000002.bin");
    let ack = std::fs::read(&ack_path).expect("ACK record");
    let mut tampered = ack.clone();
    tampered[40] ^= 1;
    std::fs::write(&ack_path, tampered).expect("tamper ACK fixture");
    assert!(matches!(
        MailboxJournal::open(
            dir.path(),
            address(),
            signer.verifying_key(),
            id(90),
            limits,
            tip
        ),
        Err(JournalError::Corrupt)
    ));
    std::fs::remove_file(&ack_path).expect("roll back ACK fixture");
    assert!(matches!(
        MailboxJournal::open(
            dir.path(),
            address(),
            signer.verifying_key(),
            id(90),
            limits,
            tip
        ),
        Err(JournalError::Rollback)
    ));
    std::fs::write(&ack_path, ack).expect("restore ACK fixture");
}

#[test]
fn guest_lease_and_signed_ack_are_durable_replay_fenced_and_boot_bound() {
    use crate::mailbox::journal::{JournalGuestAck, JournalGuestLease};
    use crate::mailbox::reader::{
        sign_delivery_ack, sign_guest_reader_enrollment, sign_reader_possession,
    };
    use mvm_contract::plan::{Nonce, PlanId};
    use mvm_contract::protocol::mailbox::{
        ConsumerSessionId, DeliveryAckNonce, MailboxDeliveryAck, MailboxGrant,
        MailboxGuestReaderEnrollment, MailboxGuestReaderScope,
    };

    let dir = tempfile::tempdir().expect("journal directory");
    let fixture = mailbox_fixture();
    let signer = &fixture.capability_authority;
    let sender = SigningKey::from_bytes(&id(22)).verifying_key();
    let encryption_key = Key::from_bytes(id(21));
    let limits = JournalLimits {
        max_records: 5,
        max_bytes: 128 * 1024,
    };
    let mut journal = MailboxJournal::open(
        dir.path(),
        address(),
        signer.verifying_key(),
        id(90),
        limits,
        JournalTip::genesis(),
    )
    .unwrap();
    let mut tip = JournalTip::genesis();
    journal
        .admit(
            JournalAdmission {
                envelope: fixture.prepared.envelope(),
                capability: &fixture.capability,
                context: &fixture.context,
                encryption_key: &encryption_key,
                sender_key: &sender,
                signer,
            },
            |next| {
                tip = next;
                Ok(())
            },
        )
        .expect("durable send before guest reader");
    let mut receive_grant = fixture.capability.grant.clone();
    receive_grant.capability_id = CapabilityId::from_bytes(id(51));
    receive_grant.subject = address().recipient;
    receive_grant.operations = CapabilityOperations::from_operations(&[MailboxOperation::Receive]);
    let receive_cap = sign_capability(receive_grant, signer).unwrap();
    let mut reader = fixture.context.clone();
    reader.acting_principal = address().recipient;
    reader.required_operation = MailboxOperation::Receive;
    let receive = || JournalReceive {
        capability: &receive_cap,
        context: &reader,
        encryption_key: &encryption_key,
        sender_key: &sender,
    };
    let plan = MailboxGrant {
        mailbox: address().mailbox,
        authority_key: signer.verifying_key().to_bytes(),
        epoch: epoch(),
    };
    let plan_id = PlanId(format!("sha256:{}", "a".repeat(64)));
    let plan_nonce = Nonce::from_bytes(id(52));
    let boot = BootId::from_bytes(id(53));
    let session = ConsumerSessionId::from_bytes(id(54));
    let scope = MailboxGuestReaderScope {
        plan: &plan,
        plan_id: &plan_id,
        plan_nonce: &plan_nonce,
        receive: &receive_cap.grant,
        current_boot: boot,
        current_session: session,
        now_unix_ms: NOW,
    };
    let guest = SigningKey::from_bytes(&id(55));
    let enrollment = sign_guest_reader_enrollment(
        MailboxGuestReaderEnrollment {
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            plan_id: plan_id.clone(),
            plan_nonce: plan_nonce.clone(),
            address: address(),
            consumer: address().recipient,
            consumer_boot: boot,
            consumer_session: session,
            receive_capability_id: receive_cap.grant.capability_id,
            ack_public_key: guest.verifying_key().to_bytes(),
            execution_epoch: epoch(),
            policy_epoch: receive_cap.grant.policy_epoch,
            issued_at_unix_ms: NOW - 1,
            expires_at_unix_ms: NOW + 5_000,
        },
        signer,
    )
    .unwrap();
    let challenge = id(56);
    let proof = sign_reader_possession(&enrollment, &challenge, &guest).unwrap();
    let lease_req = |scope| JournalGuestLease {
        receive: receive(),
        plan: &plan,
        scope,
        enrollment: &enrollment,
        challenge: &challenge,
        possession_signature: &proof,
        signer,
    };
    assert!(matches!(
        journal.lease_next(
            JournalGuestLease {
                possession_signature: &[0; 64],
                ..lease_req(scope)
            },
            |_| panic!("forgery cannot commit"),
        ),
        Err(JournalError::Mailbox(MailboxError::ReaderPossessionInvalid))
    ));
    assert!(matches!(
        journal.lease_next(
            lease_req(MailboxGuestReaderScope {
                current_boot: BootId::from_bytes(id(57)),
                ..scope
            }),
            |_| panic!("stale boot cannot commit"),
        ),
        Err(JournalError::Mailbox(MailboxError::DeliveryContract(_)))
    ));
    assert_eq!(journal.tip(), tip);
    let leased = journal
        .lease_next(lease_req(scope), |next| {
            tip = next;
            Ok(())
        })
        .expect("verified guest obtains a lease")
        .expect("pending ciphertext");
    assert_eq!(leased.payload(), b"hello");
    let signed_lease = leased.lease().clone();
    assert_eq!(journal.tip(), tip);
    assert_eq!(
        journal
            .lease_next(lease_req(scope), |_| panic!("same lease does not append"))
            .unwrap()
            .unwrap()
            .lease(),
        &signed_lease
    );
    let ack = sign_delivery_ack(
        MailboxDeliveryAck {
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            lease: signed_lease.clone(),
            ack_nonce: DeliveryAckNonce::from_bytes(id(58)),
            acknowledged_at_unix_ms: NOW,
        },
        &guest,
    )
    .unwrap();
    let ack_req = |signed| JournalGuestAck {
        receive: receive(),
        plan: &plan,
        scope,
        enrollment: &enrollment,
        signed,
    };
    let forged = sign_delivery_ack(ack.ack.clone(), signer).unwrap();
    assert!(matches!(
        journal.acknowledge_signed(ack_req(&forged), |_| panic!("wrong signer")),
        Err(JournalError::Mailbox(
            MailboxError::DeliveryAckSignatureInvalid
        ))
    ));
    assert_eq!(journal.tip(), tip);
    journal
        .acknowledge_signed(ack_req(&ack), |next| {
            tip = next;
            Ok(())
        })
        .expect("signed ACK commits");
    assert_eq!(
        journal
            .acknowledge_signed(ack_req(&ack), |_| panic!("exact ACK is idempotent"))
            .unwrap(),
        tip
    );
    let mut changed_ack = ack.ack.clone();
    changed_ack.ack_nonce = DeliveryAckNonce::from_bytes(id(59));
    let conflict = sign_delivery_ack(changed_ack, &guest).unwrap();
    assert!(matches!(
        journal.acknowledge_signed(ack_req(&conflict), |_| panic!("conflicting ACK")),
        Err(JournalError::ConflictingRetry)
    ));
    assert!(journal.receive_next(receive()).unwrap().is_none());
    drop(journal);
    let mut recovered = MailboxJournal::open(
        dir.path(),
        address(),
        signer.verifying_key(),
        id(90),
        limits,
        tip,
    )
    .expect("lease and ACK survive restart");
    assert!(recovered.receive_next(receive()).unwrap().is_none());
    assert_eq!(
        recovered
            .acknowledge_signed(ack_req(&ack), |_| panic!("recovered ACK is idempotent"))
            .unwrap(),
        tip
    );
    assert!(matches!(
        recovered.acknowledge_signed(ack_req(&conflict), |_| panic!("replayed ACK conflict")),
        Err(JournalError::ConflictingRetry)
    ));
    assert!(
        matches!(
            recovered.lease_next(lease_req(scope), |_| panic!("challenge replay")),
            Ok(None),
        ),
        "a consumed message cannot be leased a second time"
    );
    let mut next_header = fixture.prepared.header.clone();
    next_header.message_id = MessageId::from_bytes(id(61));
    next_header.nonce = ReplayNonce::from_bytes(id(62));
    next_header.sequence = SequenceNumber::new(2).unwrap();
    let mut next_routing = fixture.prepared.envelope().routing.clone();
    next_routing.delivery_id = DeliveryId::from_bytes(id(63));
    let next = crate::mailbox::seal_envelope(
        SealRequest {
            routing: next_routing,
            header: next_header,
            plaintext: b"hello",
        },
        &encryption_key,
        &SigningKey::from_bytes(&id(22)),
    )
    .unwrap();
    recovered
        .admit(
            JournalAdmission {
                envelope: &next,
                capability: &fixture.capability,
                context: &fixture.context,
                encryption_key: &encryption_key,
                sender_key: &sender,
                signer,
            },
            |committed| {
                tip = committed;
                Ok(())
            },
        )
        .unwrap();
    assert!(matches!(
        recovered.lease_next(lease_req(scope), |_| panic!("reused challenge")),
        Err(JournalError::ConflictingRetry)
    ));
    assert_eq!(recovered.tip(), tip);
    let fresh_challenge = id(64);
    let fresh_proof = sign_reader_possession(&enrollment, &fresh_challenge, &guest).unwrap();
    let next_lease = recovered
        .lease_next(
            JournalGuestLease {
                challenge: &fresh_challenge,
                possession_signature: &fresh_proof,
                ..lease_req(scope)
            },
            |committed| {
                tip = committed;
                Ok(())
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        next_lease.lease().lease.message_id,
        MessageId::from_bytes(id(61))
    );
    assert_eq!(recovered.tip(), tip);
}

#[test]
fn durable_admission_recovers_ciphertext_dedup_and_a_signed_destination_verdict() {
    use mvm_contract::protocol::mailbox::DeliveryOutcome;

    let dir = tempfile::tempdir().expect("journal directory");
    let fixture = mailbox_fixture();
    let signer = &fixture.capability_authority;
    let sender = SigningKey::from_bytes(&id(22)).verifying_key();
    let limits = JournalLimits {
        max_records: 2,
        max_bytes: 64 * 1024,
    };
    let mut journal = MailboxJournal::open(
        dir.path(),
        address(),
        signer.verifying_key(),
        id(90),
        limits,
        JournalTip::genesis(),
    )
    .expect("empty journal");
    let mut anchored = None;
    let receipt = journal
        .admit(
            JournalAdmission {
                envelope: fixture.prepared.envelope(),
                capability: &fixture.capability,
                context: &fixture.context,
                encryption_key: &Key::from_bytes(id(21)),
                sender_key: &sender,
                signer,
            },
            |tip| {
                anchored = Some(tip);
                Ok(())
            },
        )
        .expect("durable acceptance");
    assert_eq!(receipt.receipt.outcome, DeliveryOutcome::AcceptedDurable);
    crate::mailbox::verify_receipt(&receipt, &signer.verifying_key())
        .expect("destination authority signature");
    let tip = anchored.expect("external anchor is published before acceptance");
    assert_eq!(journal.tip(), tip);
    let bytes =
        std::fs::read(dir.path().join("entry-00000000000000000001.bin")).expect("durable record");
    assert!(
        !bytes.windows(5).any(|w| w == b"hello"),
        "journal contains no plaintext"
    );
    for metadata in [b"recipient".as_slice(), b"capability_id", b"message_id"] {
        assert!(
            !bytes.windows(metadata.len()).any(|w| w == metadata),
            "journal record must conceal authenticated inner metadata"
        );
    }
    drop(journal);

    let mut recovered = MailboxJournal::open(
        dir.path(),
        address(),
        signer.verifying_key(),
        id(90),
        limits,
        tip,
    )
    .expect("recover accepted entry");
    let duplicate = recovered
        .admit(
            JournalAdmission {
                envelope: fixture.prepared.envelope(),
                capability: &fixture.capability,
                context: &fixture.context,
                encryption_key: &Key::from_bytes(id(21)),
                sender_key: &sender,
                signer,
            },
            |_| panic!("a duplicate cannot advance the external anchor"),
        )
        .expect("duplicate receipt");
    assert_eq!(duplicate.receipt.outcome, DeliveryOutcome::Duplicate);
    assert_eq!(
        recovered.tip(),
        tip,
        "duplicate does not append a second entry"
    );
    let original = fixture.prepared.envelope();
    let conflicting = crate::mailbox::seal_envelope(
        SealRequest {
            routing: original.routing.clone(),
            header: mailbox_header_for_retry(),
            plaintext: b"hello",
        },
        &Key::from_bytes(id(21)),
        &SigningKey::from_bytes(&id(22)),
    )
    .expect("fresh ciphertext with the same signed message identity");
    assert!(matches!(
        recovered.admit(
            JournalAdmission {
                envelope: &conflicting,
                capability: &fixture.capability,
                context: &fixture.context,
                encryption_key: &Key::from_bytes(id(21)),
                sender_key: &sender,
                signer,
            },
            |_| Ok(()),
        ),
        Err(JournalError::ConflictingRetry)
    ));
}

#[test]
fn a_transport_verdict_cannot_substitute_for_a_matching_signed_destination_receipt() {
    use mvm_contract::protocol::mailbox::{
        DeliveryOutcome, DestinationReceipt, SignedDestinationReceipt,
    };
    use std::io::{Read, Write};

    struct Reply(std::io::Cursor<Vec<u8>>);
    impl Read for Reply {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }
    }
    impl Write for Reply {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let fixture = mailbox_fixture();
    let envelope = fixture.prepared.envelope();
    let header = &fixture.prepared.header;
    let key = fixture.capability_authority.verifying_key();
    let receipt = crate::mailbox::sign_receipt(
        DestinationReceipt {
            protocol_version: ProtocolVersion::V1,
            signature_algorithm: SignatureAlgorithm::ED25519,
            delivery_id: envelope.routing.delivery_id,
            message_id: header.message_id,
            address: address(),
            execution_epoch: header.execution_epoch,
            outcome: DeliveryOutcome::AcceptedDurable,
            observed_at_unix_ms: NOW,
            ciphertext_commitment: envelope.ciphertext_commitment,
        },
        &fixture.capability_authority,
    )
    .expect("signed receipt");
    let exchange = |signed: &SignedDestinationReceipt| {
        let reply = serde_json::to_vec(&Ok::<_, crate::mailbox::frame::Refusal>(signed))
            .expect("reply serialization");
        crate::mailbox::frame::send_receipted_frame(
            &mut Reply(std::io::Cursor::new(reply)),
            &fixture.capability,
            envelope,
            header,
            &key,
        )
    };
    assert_eq!(exchange(&receipt), Ok(receipt.clone()));

    let mut wrong_message = receipt.clone();
    wrong_message.receipt.message_id = MessageId::from_bytes(id(77));
    wrong_message =
        crate::mailbox::sign_receipt(wrong_message.receipt, &fixture.capability_authority)
            .expect("different signed message ID");
    assert_eq!(
        exchange(&wrong_message),
        Err(crate::mailbox::frame::Refusal::Malformed)
    );
    let mut forged = receipt.clone();
    forged.signature[0] ^= 1;
    assert_eq!(
        exchange(&forged),
        Err(crate::mailbox::frame::Refusal::Malformed)
    );
    let refused = crate::mailbox::sign_receipt(
        DestinationReceipt {
            outcome: DeliveryOutcome::Refused,
            ..receipt.receipt
        },
        &fixture.capability_authority,
    )
    .expect("signed refusal");
    assert_eq!(
        exchange(&refused),
        Err(crate::mailbox::frame::Refusal::Malformed)
    );
}

fn mailbox_header_for_retry() -> MailboxEnvelopeHeader {
    // The fixture seals a stable message ID for a retry. Recovering the inner
    // header through the authority gate avoids constructing a second identity.
    let fixture = mailbox_fixture();
    let mut replay = InMemoryReplayProtector::default();
    open_authenticated_envelope(
        fixture.prepared.envelope(),
        &fixture.capability,
        &fixture.context,
        &Key::from_bytes(id(21)),
        &SigningKey::from_bytes(&id(22)).verifying_key(),
        &fixture.capability_authority.verifying_key(),
        &mut replay,
    )
    .expect("fixture opens")
    .header()
    .clone()
}

#[test]
fn journal_recovery_refuses_wrong_key_tamper_truncation_and_rollback() {
    let dir = tempfile::tempdir().expect("journal directory");
    let fixture = mailbox_fixture();
    let signer = &fixture.capability_authority;
    let sender = SigningKey::from_bytes(&id(22)).verifying_key();
    let limits = JournalLimits {
        max_records: 1,
        max_bytes: 64 * 1024,
    };
    let mut journal = MailboxJournal::open(
        dir.path(),
        address(),
        signer.verifying_key(),
        id(90),
        limits,
        JournalTip::genesis(),
    )
    .expect("empty journal");
    journal
        .admit(
            JournalAdmission {
                envelope: fixture.prepared.envelope(),
                capability: &fixture.capability,
                context: &fixture.context,
                encryption_key: &Key::from_bytes(id(21)),
                sender_key: &sender,
                signer,
            },
            |_| Ok(()),
        )
        .expect("accepted");
    let tip = journal.tip();
    drop(journal);
    assert!(matches!(
        MailboxJournal::open(
            dir.path(),
            address(),
            signer.verifying_key(),
            id(91),
            limits,
            tip
        ),
        Err(JournalError::Corrupt)
    ));
    let mut wrong_address = address();
    wrong_address.tenant = TenantId::from_bytes(id(99));
    assert!(matches!(
        MailboxJournal::open(
            dir.path(),
            wrong_address,
            signer.verifying_key(),
            id(90),
            limits,
            tip
        ),
        Err(JournalError::Corrupt)
    ));
    assert!(matches!(
        MailboxJournal::open(
            dir.path(),
            address(),
            signer.verifying_key(),
            id(90),
            limits,
            JournalTip::genesis()
        ),
        Err(JournalError::Rollback)
    ));
    let path = dir.path().join("entry-00000000000000000001.bin");
    let original = std::fs::read(&path).expect("record");
    let mut tampered = original.clone();
    tampered[40] ^= 1;
    std::fs::write(&path, tampered).expect("tamper fixture");
    assert!(matches!(
        MailboxJournal::open(
            dir.path(),
            address(),
            signer.verifying_key(),
            id(90),
            limits,
            tip
        ),
        Err(JournalError::Corrupt)
    ));
    std::fs::write(&path, &original[..original.len() - 1]).expect("truncate fixture");
    assert!(matches!(
        MailboxJournal::open(
            dir.path(),
            address(),
            signer.verifying_key(),
            id(90),
            limits,
            tip
        ),
        Err(JournalError::Corrupt)
    ));
}

#[test]
fn a_full_journal_never_publishes_a_durable_acceptance_or_advances_its_tip() {
    let dir = tempfile::tempdir().expect("journal directory");
    let fixture = mailbox_fixture();
    let signer = &fixture.capability_authority;
    let sender = SigningKey::from_bytes(&id(22)).verifying_key();
    let mut journal = MailboxJournal::open(
        dir.path(),
        address(),
        signer.verifying_key(),
        id(90),
        JournalLimits {
            max_records: 1,
            max_bytes: 1,
        },
        JournalTip::genesis(),
    )
    .expect("empty journal");
    assert!(matches!(
        journal.admit(
            JournalAdmission {
                envelope: fixture.prepared.envelope(),
                capability: &fixture.capability,
                context: &fixture.context,
                encryption_key: &Key::from_bytes(id(21)),
                sender_key: &sender,
                signer,
            },
            |_| panic!("a quota refusal must not update the external anchor"),
        ),
        Err(JournalError::Full)
    ));
    assert_eq!(journal.tip(), JournalTip::genesis());
    assert_eq!(
        std::fs::read_dir(dir.path())
            .expect("journal directory")
            .count(),
        1,
        "only the writer lock exists; no accepted record was published"
    );
}

#[test]
fn anchor_failure_after_fsync_returns_uncertain_and_blocks_further_admission() {
    let dir = tempfile::tempdir().expect("journal directory");
    let fixture = mailbox_fixture();
    let signer = &fixture.capability_authority;
    let sender = SigningKey::from_bytes(&id(22)).verifying_key();
    let limits = JournalLimits {
        max_records: 2,
        max_bytes: 64 * 1024,
    };
    let mut journal = MailboxJournal::open(
        dir.path(),
        address(),
        signer.verifying_key(),
        id(90),
        limits,
        JournalTip::genesis(),
    )
    .expect("empty journal");
    let encryption_key = Key::from_bytes(id(21));
    let request = || JournalAdmission {
        envelope: fixture.prepared.envelope(),
        capability: &fixture.capability,
        context: &fixture.context,
        encryption_key: &encryption_key,
        sender_key: &sender,
        signer,
    };
    assert!(matches!(
        journal.admit(request(), |_| Err(JournalError::Uncertain)),
        Err(JournalError::Uncertain)
    ));
    assert_eq!(
        journal.tip().cursor,
        1,
        "ciphertext was committed before anchoring"
    );
    assert!(
        matches!(
            journal.admit(request(), |_| Ok(())),
            Err(JournalError::Uncertain)
        ),
        "a failed anchor cannot be mistaken for a fresh acceptance"
    );
    drop(journal);
    assert!(
        matches!(
            MailboxJournal::open(
                dir.path(),
                address(),
                signer.verifying_key(),
                id(90),
                limits,
                JournalTip::genesis()
            ),
            Err(JournalError::Rollback)
        ),
        "recovery with the old anchor fails closed until reconciliation"
    );
}

#[test]
fn startup_reconciles_only_a_verified_fsynced_suffix_before_accepting_retries() {
    let dir = tempfile::tempdir().expect("destination");
    let root = dir.path().join("journal");
    let anchor_path = dir.path().join("anchor");
    let fixture = mailbox_fixture();
    let signer = &fixture.capability_authority;
    let sender = SigningKey::from_bytes(&id(22)).verifying_key();
    let encryption_key = Key::from_bytes(id(21));
    let limits = JournalLimits {
        max_records: 2,
        max_bytes: 64 * 1024,
    };
    let anchor = FileJournalAnchor::open(&anchor_path, address(), id(91)).expect("anchor");
    let mut journal = MailboxJournal::open_reconciling(
        &root,
        address(),
        signer.verifying_key(),
        id(90),
        limits,
        &anchor,
    )
    .expect("empty journal");
    let request = || JournalAdmission {
        envelope: fixture.prepared.envelope(),
        capability: &fixture.capability,
        context: &fixture.context,
        encryption_key: &encryption_key,
        sender_key: &sender,
        signer,
    };
    assert!(matches!(
        journal.admit(request(), |_| Err(JournalError::Uncertain)),
        Err(JournalError::Uncertain)
    ));
    assert_eq!(anchor.tip(), JournalTip::genesis());
    let fsynced = journal.tip();
    drop(journal);
    drop(anchor);

    let anchor = FileJournalAnchor::open(&anchor_path, address(), id(91)).expect("reopen anchor");
    let mut recovered = MailboxJournal::open_reconciling(
        &root,
        address(),
        signer.verifying_key(),
        id(90),
        limits,
        &anchor,
    )
    .expect("reconcile verified suffix");
    assert_eq!(anchor.tip(), fsynced);
    let duplicate = recovered
        .admit(request(), |_| panic!("a duplicate must not append"))
        .expect("retry after reconciliation");
    assert_eq!(duplicate.receipt.outcome, DeliveryOutcome::Duplicate);
    assert_eq!(recovered.tip(), fsynced);
    drop(recovered);
    drop(anchor);

    let bad_anchor_path = dir.path().join("wrong-anchor");
    let bad_anchor = FileJournalAnchor::open(&bad_anchor_path, address(), id(91))
        .expect("independent wrong anchor");
    bad_anchor
        .advance(JournalTip {
            cursor: 1,
            head: id(99),
        })
        .expect("valid MAC, wrong chain head");
    assert!(matches!(
        MailboxJournal::open_reconciling(
            &root,
            address(),
            signer.verifying_key(),
            id(90),
            limits,
            &bad_anchor,
        ),
        Err(JournalError::Rollback)
    ));
}

#[test]
fn private_anchor_survives_reopen_and_refuses_wrong_key_tamper_and_backward_move() {
    let dir = tempfile::tempdir().expect("anchor directory");
    let path = dir.path().join("mailbox-anchor");
    let anchor = FileJournalAnchor::open(&path, address(), id(91)).expect("genesis anchor");
    assert_eq!(anchor.tip(), JournalTip::genesis());
    let tip = JournalTip {
        cursor: 1,
        head: id(92),
    };
    anchor.advance(tip).expect("durable advance");
    assert!(matches!(anchor.advance(tip), Err(JournalError::Rollback)));
    drop(anchor);
    assert_eq!(
        FileJournalAnchor::open(&path, address(), id(91))
            .expect("reopen anchor")
            .tip(),
        tip
    );
    assert!(matches!(
        FileJournalAnchor::open(&path, address(), id(90)),
        Err(JournalError::Corrupt)
    ));
    let mut tampered = std::fs::read(&path).expect("anchor bytes");
    tampered[18] ^= 1;
    std::fs::write(&path, tampered).expect("tamper fixture");
    assert!(matches!(
        FileJournalAnchor::open(&path, address(), id(91)),
        Err(JournalError::Corrupt)
    ));
}

#[test]
fn binding_verification_rejects_tamper_identity_epoch_policy_time_and_assurance() {
    let authority = SigningKey::from_bytes(&id(30));
    let (signed, _) = signed_route(TransportPath::Direct, 31, &authority);

    let mut contexts = Vec::new();
    let mut wrong = binding_context();
    wrong.expected_issuer = PrincipalId::from_bytes(id(32));
    contexts.push((wrong, TransportBindingError::WrongIssuer));
    let mut wrong = binding_context();
    wrong.expected_address.mailbox = MailboxId::from_bytes(id(33));
    contexts.push((wrong, TransportBindingError::WrongAddress));
    let mut wrong = binding_context();
    wrong.expected_address.tenant = TenantId::from_bytes(id(34));
    contexts.push((wrong, TransportBindingError::WrongAddress));
    let mut wrong = binding_context();
    wrong.current_execution_epoch = ExecutionEpoch::new(8).expect("epoch");
    contexts.push((wrong, TransportBindingError::StaleExecutionEpoch));
    let mut wrong = binding_context();
    wrong.current_policy_epoch += 1;
    contexts.push((wrong, TransportBindingError::StalePolicyEpoch));
    let mut wrong = binding_context();
    wrong.now_unix_ms = signed.claims.expires_at_unix_ms;
    contexts.push((wrong, TransportBindingError::Expired));
    let mut wrong = binding_context();
    wrong.minimum_assurance = TransportAssurance::HostBlind;
    contexts.push((wrong, TransportBindingError::InsufficientAssurance));

    for (context, expected) in contexts {
        assert_eq!(
            authorize_route(&signed, &context, &authority.verifying_key()),
            Err(expected)
        );
    }

    let mut tampered = signed;
    tampered.claims.locator = RouteLocator::parse("memory://tampered").expect("locator");
    assert_eq!(
        authorize_route(&tampered, &binding_context(), &authority.verifying_key()),
        Err(TransportBindingError::SignatureInvalid)
    );
}

#[test]
fn binding_verification_rejects_revoked_binding() {
    let authority = SigningKey::from_bytes(&id(30));
    let (signed, _) = signed_route(TransportPath::Direct, 31, &authority);
    let mut context = binding_context();
    context.revoked_bindings.push(signed.claims.binding_id);

    assert_eq!(
        authorize_route(&signed, &context, &authority.verifying_key()),
        Err(TransportBindingError::Revoked)
    );
}

#[test]
fn rotating_the_binding_authority_key_retires_bindings_signed_under_the_old_one() {
    let old_authority = SigningKey::from_bytes(&id(30));
    let new_authority = SigningKey::from_bytes(&id(40));
    let (old_binding, _) = signed_route(TransportPath::Direct, 31, &old_authority);
    let (new_binding, _) = signed_route(TransportPath::Direct, 41, &new_authority);
    let context = binding_context();

    assert_eq!(
        authorize_route(&old_binding, &context, &new_authority.verifying_key()),
        Err(TransportBindingError::SignatureInvalid)
    );
    assert!(authorize_route(&new_binding, &context, &new_authority.verifying_key()).is_ok());
}

#[test]
fn overlay_orders_direct_then_customer_relay_and_requires_public_relay_opt_in() {
    let authority = SigningKey::from_bytes(&id(34));
    let (_, direct) = signed_route(TransportPath::Direct, 35, &authority);
    let (_, customer) = signed_route(TransportPath::CustomerRelay, 36, &authority);
    let (_, public) = signed_route(TransportPath::PublicRelay, 37, &authority);
    let mut overlay = InMemoryPeerOverlay::default();
    overlay.register(20, public.clone()).expect("register");
    overlay.register(10, customer.clone()).expect("register");
    overlay.register(0, direct.clone()).expect("register");
    let query = OverlayQuery {
        address: address(),
        execution_epoch: epoch(),
        policy_epoch: 12,
        now_unix_ms: NOW,
        relay_policy: RelayPolicy::default(),
    };
    assert_eq!(
        overlay.resolve(&query).expect("routes"),
        vec![direct, customer]
    );
    let routes = overlay
        .resolve(&OverlayQuery {
            relay_policy: RelayPolicy::PublicRelaysAllowed,
            ..query
        })
        .expect("routes");
    assert_eq!(routes.last(), Some(&public));
}

#[test]
fn relay_policy_defaults_to_no_public_relay_and_orders_path_classes() {
    use TransportPath::{CustomerRelay, Direct, PublicRelay};
    assert_eq!(RelayPolicy::default(), RelayPolicy::CustomerRelays);
    let admitted = |p: RelayPolicy| [Direct, CustomerRelay, PublicRelay].map(|t| p.allows(t));
    assert_eq!(admitted(RelayPolicy::DirectOnly), [true, false, false]);
    assert_eq!(admitted(RelayPolicy::CustomerRelays), [true, true, false]);
    assert_eq!(
        admitted(RelayPolicy::PublicRelaysAllowed),
        [true, true, true]
    );
}

#[test]
fn direct_only_policy_drops_customer_relay_routes() {
    let authority = SigningKey::from_bytes(&id(34));
    let (_, direct) = signed_route(TransportPath::Direct, 35, &authority);
    let (_, customer) = signed_route(TransportPath::CustomerRelay, 36, &authority);
    let mut overlay = InMemoryPeerOverlay::default();
    overlay.register(0, direct.clone()).expect("register");
    overlay.register(1, customer).expect("register");
    let query = OverlayQuery {
        address: address(),
        execution_epoch: epoch(),
        policy_epoch: 12,
        now_unix_ms: NOW,
        relay_policy: RelayPolicy::DirectOnly,
    };
    assert_eq!(overlay.resolve(&query).expect("routes"), vec![direct]);
}

#[test]
fn overlay_partition_shutdown_and_refusal_are_distinct() {
    let query = OverlayQuery {
        address: address(),
        execution_epoch: epoch(),
        policy_epoch: 12,
        now_unix_ms: NOW,
        relay_policy: RelayPolicy::default(),
    };
    let mut overlay = InMemoryPeerOverlay::default();
    assert_eq!(
        overlay.resolve(&query),
        Err(OverlayError::NoAuthorizedRoute)
    );
    overlay.set_state(OverlayState::Partitioned);
    assert_eq!(overlay.resolve(&query), Err(OverlayError::Partitioned));
    overlay.set_state(OverlayState::ShuttingDown);
    assert_eq!(overlay.resolve(&query), Err(OverlayError::ShuttingDown));
}

#[test]
fn coordinator_hint_selects_a_route_without_mutating_or_re_signing_the_envelope() {
    let authority = SigningKey::from_bytes(&id(38));
    let (binding, route) = signed_route(TransportPath::Direct, 39, &authority);
    let fixture = mailbox_fixture();
    let before = fixture.prepared.envelope().clone();
    let adapted = adapt_mvmd_route_hint(
        &MvmdRouteHint {
            placement_generation: 40,
            priority: 0,
            binding,
        },
        fixture.prepared.envelope(),
        &binding_context(),
        &authority.verifying_key(),
    )
    .expect("hint adapts");
    assert_eq!(adapted, route);
    assert_eq!(fixture.prepared.envelope(), &before);
}

#[test]
fn coordinator_hint_cannot_substitute_a_route_token() {
    let authority = SigningKey::from_bytes(&id(41));
    let (binding, _) = signed_route(TransportPath::Direct, 42, &authority);
    let fixture = mailbox_fixture();
    let mut envelope = fixture.prepared.envelope().clone();
    envelope.routing.destination_route_token = DestinationRouteToken::from_bytes(id(43));
    assert_eq!(
        adapt_mvmd_route_hint(
            &MvmdRouteHint {
                placement_generation: 1,
                priority: 0,
                binding,
            },
            &envelope,
            &binding_context(),
            &authority.verifying_key(),
        ),
        Err(RouteAdapterError::EnvelopeRouteMismatch)
    );
}

fn authorized_frame(route: &AuthorizedRoute) -> AuthorizedMailboxFrame {
    let fixture = mailbox_fixture();
    authorize_outbound(OutboundAuthorization {
        prepared: &fixture.prepared,
        capability: &fixture.capability,
        context: &fixture.context,
        capability_authority_key: &fixture.capability_authority.verifying_key(),
        route,
    })
    .expect("outbound authority")
}

#[test]
fn authorized_frame_retains_the_verified_capability_without_reencoding_the_envelope() {
    let authority = SigningKey::from_bytes(&id(53));
    let (_, route) = signed_route(TransportPath::Direct, 54, &authority);
    let mut fixture = mailbox_fixture();
    let frame = authorize_outbound(OutboundAuthorization {
        prepared: &fixture.prepared,
        capability: &fixture.capability,
        context: &fixture.context,
        capability_authority_key: &fixture.capability_authority.verifying_key(),
        route: &route,
    })
    .expect("outbound authority");
    let original = fixture.capability.clone();
    fixture.capability.signature[0] ^= 1;
    assert_eq!(
        frame.capability(),
        &original,
        "the verified grant is retained"
    );
    assert_eq!(
        decode_envelope(frame.as_bytes()).expect("canonical envelope"),
        *fixture.prepared.envelope(),
        "the envelope remains unchanged and separate from its capability"
    );
    assert_eq!(
        authorize_outbound(OutboundAuthorization {
            prepared: &fixture.prepared,
            capability: &fixture.capability,
            context: &fixture.context,
            capability_authority_key: &fixture.capability_authority.verifying_key(),
            route: &route,
        }),
        Err(OutboundAuthorizationError::Mailbox(
            MailboxError::CapabilitySignatureInvalid
        )),
        "tampered capability must never reach a transport"
    );
}

#[test]
fn authenticated_connection_is_not_mailbox_authority() {
    let authority = SigningKey::from_bytes(&id(44));
    let (_, route) = signed_route(TransportPath::Direct, 45, &authority);
    let transport = InMemoryPeerTransport::default();
    transport.register_route(route.route_id()).expect("route");
    let limits =
        ChannelLimits::new(MAX_ENCODED_ENVELOPE_BYTES, MAX_ENCODED_ENVELOPE_BYTES).expect("limits");
    let cancel = CancellationToken::default();
    let _channel = transport
        .connect(&route, limits, &cancel)
        .expect("transport authenticates");

    let mut fixture = mailbox_fixture();
    fixture.context.required_operation = MailboxOperation::Receive;
    assert_eq!(
        authorize_outbound(OutboundAuthorization {
            prepared: &fixture.prepared,
            capability: &fixture.capability,
            context: &fixture.context,
            capability_authority_key: &fixture.capability_authority.verifying_key(),
            route: &route,
        }),
        Err(OutboundAuthorizationError::SendOperationRequired)
    );
    assert!(transport.drain(route.route_id()).expect("drain").is_empty());
}

#[test]
fn direct_delivery_is_pass_by_value_bounded_and_cancelable() {
    let authority = SigningKey::from_bytes(&id(46));
    let (_, route) = signed_route(TransportPath::Direct, 47, &authority);
    let frame = authorized_frame(&route);
    let transport = InMemoryPeerTransport::default();
    transport.register_route(route.route_id()).expect("route");
    let limits =
        ChannelLimits::new(frame.encoded_len(), frame.encoded_len()).expect("exact limits");
    let cancel = CancellationToken::default();
    let mut channel = transport.connect(&route, limits, &cancel).expect("connect");
    channel.try_send(&frame, &cancel).expect("first frame");
    assert_eq!(
        channel.try_send(&frame, &cancel),
        Err(TransportError::Backpressured)
    );
    let delivered = transport.drain(route.route_id()).expect("drain");
    assert_eq!(delivered, vec![frame.bytes.clone()]);

    cancel.cancel();
    assert_eq!(
        channel.try_send(&frame, &cancel),
        Err(TransportError::Cancelled)
    );
}

#[test]
fn fallback_and_reconnect_are_deterministic_and_bounded() {
    let authority = SigningKey::from_bytes(&id(48));
    let (_, direct) = signed_route(TransportPath::Direct, 49, &authority);
    let (_, relay) = signed_route(TransportPath::CustomerRelay, 50, &authority);
    let transport = InMemoryPeerTransport::default();
    transport.register_route(direct.route_id()).expect("direct");
    transport.register_route(relay.route_id()).expect("relay");
    transport
        .script_connect(
            direct.route_id(),
            [ConnectAction::Partition, ConnectAction::Accept],
        )
        .expect("script");
    let limits = ChannelLimits::new(1024, 1024).expect("limits");
    let cancel = CancellationToken::default();
    connect_with_fallback(&transport, &[direct.clone(), relay], limits, &cancel)
        .expect("relay fallback");
    connect_with_fallback(&transport, &[direct], limits, &cancel).expect("reconnected direct path");
}

#[test]
fn refused_cancelled_and_shutting_down_connects_are_distinct() {
    let authority = SigningKey::from_bytes(&id(51));
    let (_, route) = signed_route(TransportPath::Direct, 52, &authority);
    let transport = InMemoryPeerTransport::default();
    transport.register_route(route.route_id()).expect("route");
    transport
        .script_connect(route.route_id(), [ConnectAction::Refuse])
        .expect("script");
    let limits = ChannelLimits::new(1, 1).expect("limits");
    let cancel = CancellationToken::default();
    assert!(matches!(
        transport.connect(&route, limits, &cancel),
        Err(TransportError::Refused)
    ));
    cancel.cancel();
    assert!(matches!(
        transport.connect(&route, limits, &cancel),
        Err(TransportError::Cancelled)
    ));
    let active = CancellationToken::default();
    transport.shutdown().expect("shutdown");
    assert!(matches!(
        transport.connect(&route, limits, &active),
        Err(TransportError::ShuttingDown)
    ));
}
