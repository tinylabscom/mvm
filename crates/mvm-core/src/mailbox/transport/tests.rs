use super::*;
use mvm_contract::protocol::mailbox::{
    AuthorizationDomainId, BootId, CapabilityId, CapabilityOperations, CausationId,
    CiphertextPadding, ContentType, CorrelationId, DeliveryId, EncryptionAlgorithm,
    EncryptionContext, MailboxCapabilityGrant, MailboxId, MailboxMessageKind, MailboxRoutingFrame,
    MessageId, OrderingScope, ReplayNonce, RevocationId, SequenceNumber, TenantId,
};

use crate::crypto::aead::Key;
use crate::mailbox::{SealRequest, sign_capability};

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
        allow_public_relays: false,
    };
    assert_eq!(
        overlay.resolve(&query).expect("routes"),
        vec![direct, customer]
    );
    let routes = overlay
        .resolve(&OverlayQuery {
            allow_public_relays: true,
            ..query
        })
        .expect("routes");
    assert_eq!(routes.last(), Some(&public));
}

#[test]
fn overlay_partition_shutdown_and_refusal_are_distinct() {
    let query = OverlayQuery {
        address: address(),
        execution_epoch: epoch(),
        policy_epoch: 12,
        now_unix_ms: NOW,
        allow_public_relays: false,
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
