//! The mission demo, scripted: three nodes (aircraft, ship, ground vehicle),
//! one deterministic compromise, and an evidence timeline.
//!
//! What is real: the launch gate (`LocalHostInterface` preflight plus the
//! per-workload ledger), quarantine and replacement with chain-signed audit
//! entries, the signed offline lease, the command replay gate, the reconnect
//! challenge, and the sealed mailbox envelope with its capability, replay and
//! execution-epoch checks. Each node writes its own signed audit chain.
//!
//! Mailbox delivery is real as far as one host: the ship's sealed envelope
//! crosses a Unix domain socket to the aircraft node's `MailboxService`, which
//! opens it and enqueues it under a bounded queue; a refusal comes back to the
//! sender as a typed reply. Between nodes it also crosses a loopback TCP
//! `PeerTransport` (`two_nodes_deliver_over_a_loopback_tcp_peer_transport`):
//! two nodes with separate state directories and audit chains, the sender
//! gated by a signed transport binding and the destination re-checking
//! signature, capability, epoch and replay. The guest mailbox port is served
//! by a separate host process (`mvm-mailbox`) in its own tests below.
//!
//! What is simulated, on purpose: no booted guest runs the mailbox
//! client or reads the queue (the guest end is a test driving the same
//! `send_frame` over a Firecracker-style mux), no Iroh or relay transport
//! (the TCP transport is loopback and the two nodes are threads of one test
//! process on one physical host; only the guest mailbox is a separate process), and the VMs (a launch is gated and
//! audited, but nothing boots). Only the aircraft node runs a service. Run
//! with `--nocapture` to read the timeline.

use ed25519_dalek::SigningKey;
use mvm_contract::protocol::mailbox::{
    AuthorizationDomainId, AuthorizationDomainRouteLabel, BootId, CapabilityId,
    CapabilityOperations, CausationId, CiphertextPadding, ContentType, CorrelationId, DeliveryId,
    DestinationRouteToken, EncryptionAlgorithm, EncryptionContext, ExecutionEpoch as MbEpoch,
    MailboxAddress, MailboxCapabilityGrant, MailboxEnvelopeHeader, MailboxId, MailboxMessageKind,
    MailboxOperation, MailboxRoutingFrame, MessageId, OrderingScope, PrincipalId, ProtocolVersion,
    ReplayNonce, ReplyRoute, RevocationId, SequenceNumber, SignatureAlgorithm, TenantId,
    TransportBindingId,
};
use mvm_core::crypto::aead::Key;
use mvm_core::host_interface::{
    Assurance, ExecutionEpoch, HostInterface, HostInterfaceError, HostPolicy, LaunchRequest,
    NodeState,
    lease::{CommandGate, LeaseOp, OfflineLease, Reconnect, SignedLease, answer_challenge},
    local::LocalHostInterface,
    workload::WorkloadLedger,
};
use mvm_core::mailbox::frame::{OutboxMessage, send_outbox_message};
use mvm_core::mailbox::transport::{
    AuthorizedRoute, CancellationToken, ChannelLimits, OutboundAuthorization, PeerTransport,
    RouteId, RouteLocator, TransportAssurance, TransportBindingClaims, TransportBindingContext,
    TransportBindingError, TransportError, TransportIdentity, TransportPath, authorize_outbound,
    authorize_route, prepare_mailbox_envelope, sign_transport_binding,
};
use mvm_core::mailbox::{MailboxError, OpenContext, SealRequest, seal_envelope, sign_capability};
use mvm_core::plan::ExecutionPlan;
use mvm_hostd::audit::{
    emitter::AuditEmitter,
    session::{EventFilter, workload_events},
};
use mvm_hostd::containment::{quarantine_workload, replace_workload};
use mvm_hostd::mailbox_service::{
    GuestSealer, MailboxLimits, MailboxPolicy, MailboxService, Refusal, send, serve_granted_guest,
};
use mvm_hostd::supervisor::verify_audit_chain;
#[path = "support/tcp_peer_transport.rs"]
mod tcp_peer_transport;
use std::io::{Read, Write};
use tcp_peer_transport::{TcpListenerLimits, TcpPeerListener, TcpPeerTransport};

const NOW: u64 = 1_000;

fn now() -> u64 {
    NOW
}

/// One simulated node: its own state directory, audit chain and host interface.
struct Node {
    name: &'static str,
    home: tempfile::TempDir,
    audit: tempfile::TempDir,
    audit_key: SigningKey,
    identity: SigningKey,
    emitter: AuditEmitter,
    host: LocalHostInterface,
    launches: std::cell::Cell<u32>,
}

impl Node {
    fn new(name: &'static str, seed: u8) -> Self {
        let audit = tempfile::tempdir().unwrap();
        let audit_key = SigningKey::from_bytes(&[seed; 32]);
        let emitter = AuditEmitter::with_dir(audit_key.clone(), audit.path()).unwrap();
        Self {
            name,
            home: tempfile::tempdir().unwrap(),
            audit,
            audit_key,
            identity: SigningKey::from_bytes(&[seed.wrapping_add(100); 32]),
            emitter,
            host: LocalHostInterface::new(name, HostPolicy::default(), Assurance::Software, now),
            launches: std::cell::Cell::new(0),
        }
    }

    fn plan(&self, workload: &str) -> ExecutionPlan {
        let n = self.launches.get();
        self.launches.set(n + 1);
        mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .plan_id(format!("plan-{}-{workload}-{n}", self.name))
            .workload(workload)
            .build()
    }

    /// Gate one launch through the ledger and the preflight, then audit it.
    fn launch(&self, workload: &str) -> Result<(), HostInterfaceError> {
        let plan = self.plan(workload);
        let verdict = WorkloadLedger::load_at(self.home.path())
            .and_then(|l| l.authorize_local_start(workload).map_err(Into::into))
            .and_then(|()| {
                self.host.authorize_workload(&LaunchRequest {
                    workload_id: workload.into(),
                    image_digest: plan.image.sha256.clone(),
                    epoch: self.host.current_epoch(),
                })
            });
        match &verdict {
            Ok(_) => {
                self.emitter.emit_admitted(&plan, "host:demo").unwrap();
                self.emitter.emit_launched(&plan, "simulated").unwrap();
            }
            Err(e) => self
                .emitter
                .emit_refused(&plan, "host_interface", &e.to_string())
                .unwrap(),
        }
        verdict.map(|_| ())
    }

    /// Record a refused action (mailbox, egress, secret) against a workload.
    fn record_denial(&self, workload: &str, stage: &str, reason: &str) {
        let plan = self.plan(workload);
        self.emitter.emit_refused(&plan, stage, reason).unwrap();
    }

    fn chain(&self) -> std::path::PathBuf {
        self.audit.path().join("local.jsonl")
    }

    fn lines(&self) -> Vec<String> {
        std::fs::read_to_string(self.chain())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn timeline(&self, workload: &str) -> Vec<String> {
        workload_events(&self.lines(), workload, &EventFilter::default())
            .unwrap()
            .into_iter()
            .map(|e| {
                let en = e.envelope.entry;
                let detail = en
                    .labels
                    .get("reason")
                    .or_else(|| en.labels.get("epoch"))
                    .cloned()
                    .unwrap_or_default();
                format!("{} {:<26} {detail}", en.plan_id, en.event)
            })
            .collect()
    }
}

// ---- mailbox fixtures: one ship -> aircraft channel -------------------------

fn domain() -> AuthorizationDomainId {
    AuthorizationDomainId::from_bytes([1; 32])
}
fn tenant() -> TenantId {
    TenantId::from_bytes([19; 32])
}
fn ship_principal() -> PrincipalId {
    PrincipalId::from_bytes([2; 32])
}
fn aircraft_principal() -> PrincipalId {
    PrincipalId::from_bytes([3; 32])
}
fn issuer() -> PrincipalId {
    PrincipalId::from_bytes([12; 32])
}
fn content_type() -> ContentType {
    ContentType::parse("application/vnd.mvm.prompt", 1).unwrap()
}
fn address() -> MailboxAddress {
    MailboxAddress {
        tenant: tenant(),
        authorization_domain: domain(),
        mailbox: MailboxId::from_bytes([4; 32]),
        recipient: aircraft_principal(),
    }
}

/// A sealed ship->aircraft message sent at `epoch` with message id `id`.
fn header(epoch: u64, id: u8) -> MailboxEnvelopeHeader {
    MailboxEnvelopeHeader {
        protocol_version: ProtocolVersion::V1,
        signature_algorithm: SignatureAlgorithm::ED25519,
        tenant: tenant(),
        authorization_domain: domain(),
        sender: ship_principal(),
        recipient: aircraft_principal(),
        mailbox: address().mailbox,
        sender_boot: BootId::from_bytes([5; 32]),
        execution_epoch: MbEpoch::new(epoch).unwrap(),
        message_id: MessageId::from_bytes([id; 32]),
        correlation_id: CorrelationId::from_bytes([7; 32]),
        causation_id: CausationId::from_bytes([8; 32]),
        kind: MailboxMessageKind::Call,
        reply_to: Some(ReplyRoute {
            address: address(),
            capability_id: CapabilityId::from_bytes([14; 32]),
        }),
        ordering_scope: OrderingScope::parse("interactive").unwrap(),
        sequence: SequenceNumber::new(u64::from(id)).unwrap(),
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
        nonce: ReplayNonce::from_bytes([id; 16]),
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

fn grant(operations: &[MailboxOperation]) -> MailboxCapabilityGrant {
    MailboxCapabilityGrant {
        protocol_version: ProtocolVersion::V1,
        signature_algorithm: SignatureAlgorithm::ED25519,
        capability_id: CapabilityId::from_bytes([10; 32]),
        issuer: issuer(),
        subject: ship_principal(),
        address: address(),
        operations: CapabilityOperations::from_operations(operations),
        message_kinds: vec![MailboxMessageKind::Call, MailboxMessageKind::Reply],
        content_types: vec![content_type()],
        max_payload_bytes: 1024,
        max_messages_per_minute: 60,
        max_outstanding_calls: 8,
        max_queue_contribution_bytes: 4096,
        minimum_execution_epoch: MbEpoch::new(1).unwrap(),
        maximum_execution_epoch: MbEpoch::new(9).unwrap(),
        policy_epoch: 4,
        not_before_unix_ms: 900,
        expires_at_unix_ms: 3_000,
        revocation_id: RevocationId::from_bytes([13; 32]),
        delegation_depth: 0,
    }
}

/// What the aircraft knows when it opens: the sender's current epoch.
fn context(current_epoch: u64) -> OpenContext {
    OpenContext {
        expected_tenant: tenant(),
        expected_authorization_domain: domain(),
        expected_mailbox: address().mailbox,
        expected_sender: ship_principal(),
        expected_recipient: aircraft_principal(),
        acting_principal: ship_principal(),
        expected_capability_issuer: issuer(),
        current_execution_epoch: MbEpoch::new(current_epoch).unwrap(),
        current_policy_epoch: 4,
        required_operation: MailboxOperation::Send,
        now_unix_ms: 1_500,
        accepted_content_types: vec![content_type()],
        revoked_capabilities: vec![],
    }
}

/// Ship -> aircraft over the aircraft node's mailbox socket. The aircraft's
/// service opens and queues; the ship only ever holds the socket path.
struct Channel {
    sender_key: SigningKey,
    authority_key: SigningKey,
    encryption_key: Key,
    service: MailboxService,
    socket: std::path::PathBuf,
}

const LIMITS: MailboxLimits = MailboxLimits {
    max_depth: 4,
    max_frame_bytes: 64 * 1024,
};

/// The host-held sealing material for a guest that may use `operations`.
fn sealer(channel: &Channel, operations: &[MailboxOperation]) -> GuestSealer {
    GuestSealer {
        encryption_key: Key::from_bytes([23; 32]),
        sender_key: channel.sender_key.clone(),
        authority_key: channel.authority_key.clone(),
        capability: grant(operations),
        header: header(1, 1),
        routing: routing(),
        sent: 0,
        intent_dir: None,
    }
}

/// What a guest leaves in its outbox: a recipient and a plaintext body.
fn outbox_message() -> OutboxMessage {
    OutboxMessage {
        recipient: aircraft_principal(),
        message_id: MessageId::from_bytes([25; 32]),
        body: b"hello".to_vec(),
    }
}

impl Channel {
    fn new(aircraft: &Node) -> Self {
        let (sender_key, authority_key) = (
            SigningKey::from_bytes(&[21; 32]),
            SigningKey::from_bytes(&[22; 32]),
        );
        let socket = aircraft.home.path().join("mailbox.sock");
        let service = MailboxService::bind(
            &socket,
            LIMITS,
            MailboxPolicy {
                context: context(1),
                encryption_key: Key::from_bytes([23; 32]),
                sender_key: sender_key.verifying_key(),
                authority_key: authority_key.verifying_key(),
            },
        )
        .unwrap();
        Self {
            sender_key,
            authority_key,
            encryption_key: Key::from_bytes([23; 32]),
            service,
            socket,
        }
    }

    /// Ship seals at `sent_epoch` and sends over the socket; the aircraft
    /// knows `current_epoch` and opens under a capability that grants
    /// `operations`. Returns what the aircraft's service queued.
    fn deliver(
        &mut self,
        sent_epoch: u64,
        current_epoch: u64,
        id: u8,
        operations: &[MailboxOperation],
    ) -> Result<Vec<u8>, Refusal> {
        self.service
            .set_current_epoch(MbEpoch::new(current_epoch).unwrap());
        let capability = sign_capability(grant(operations), &self.authority_key).unwrap();
        let envelope = seal_envelope(
            SealRequest {
                routing: routing(),
                header: header(sent_epoch, id),
                plaintext: b"hello",
            },
            &self.encryption_key,
            &self.sender_key,
        )
        .unwrap();
        send(&self.socket, &capability, &envelope)?;
        Ok(self
            .service
            .receive()
            .expect("an accepted message is queued"))
    }
}

fn refused(reason: MailboxError) -> Refusal {
    Refusal::Mailbox(reason.to_string())
}

#[test]
fn contain_terminate_and_rebuild() {
    let (aircraft, ship, ground) = (
        Node::new("aircraft", 1),
        Node::new("ship", 2),
        Node::new("ground", 3),
    );
    let mut channel = Channel::new(&aircraft);
    let send = [MailboxOperation::Send, MailboxOperation::Receive];

    // Act 1: each node launches its workloads under the preflight; the ship's
    // analyst and the aircraft collaborate over an approved mailbox.
    for node in [&aircraft, &ship, &ground] {
        node.launch("nav").expect("a clean node launches");
    }
    ship.launch("analyst").expect("analyst launches");
    assert_eq!(
        channel
            .deliver(1, 1, 1, &send)
            .expect("approved message opens"),
        b"hello"
    );

    // Act 2: the ship loses its uplink and keeps doing preauthorized local
    // work under a signed lease; it cannot use secrets or egress.
    let ops = SigningKey::from_bytes(&[50; 32]);
    let trusted = vec![("ops".to_string(), ops.verifying_key())];
    let lease = SignedLease::sign(
        OfflineLease {
            node_id: "ship".into(),
            policy_version: 4,
            issued_at: 100,
            not_after: 5_000,
            allowed: vec![LeaseOp::LocalLaunch, LeaseOp::Mailbox],
            max_queued_messages: 32,
        },
        "ops",
        &ops,
    )
    .unwrap()
    .verify(&trusted, "ship", NOW, 1)
    .expect("the ship holds a valid lease");
    lease
        .permits(LeaseOp::LocalLaunch, NOW)
        .expect("local work continues");
    lease
        .permits(LeaseOp::Mailbox, NOW)
        .expect("mailbox continues");
    ship.launch("nav")
        .expect("the ship launches offline under the lease");
    assert!(lease.permits(LeaseOp::Egress, NOW).is_err());

    // Act 3: the analyst is compromised (deterministically). It tries to send
    // without the Send grant, and to use a secret the lease does not allow.
    let denied = channel
        .deliver(1, 1, 2, &[MailboxOperation::Receive])
        .expect_err("a sender without the Send operation is refused");
    ship.record_denial("analyst", "mailbox", &format!("send refused: {denied}"));
    let secret = lease
        .permits(LeaseOp::SecretUse, NOW)
        .expect_err("secrets are outside the lease");
    ship.record_denial("analyst", "secret", &secret.to_string());
    assert!(
        channel.deliver(1, 1, 1, &send) == Err(refused(MailboxError::Replay)),
        "replaying an already-opened message is refused as a replay"
    );

    // Act 4: only the suspect is contained, on the command of the control
    // plane; a replayed copy of that command is rejected.
    let mut commands = CommandGate::new(ExecutionEpoch(1));
    commands
        .accept(ExecutionEpoch(1), 1)
        .expect("first command accepted");
    assert!(
        commands.accept(ExecutionEpoch(1), 1).is_err(),
        "replayed command refused"
    );
    let suspect = ship.plan("analyst");
    quarantine_workload(
        ship.home.path(),
        &ship.emitter,
        &suspect,
        "planted compromise",
    )
    .unwrap();
    // Terminate is the existing stop path; here the VM is simulated.
    assert!(
        ship.launch("analyst").is_err(),
        "the quarantined workload cannot relaunch"
    );
    ship.launch("nav")
        .expect("the bystander on the same node is unaffected");
    aircraft.launch("nav").expect("other nodes are unaffected");

    // Act 5: the replacement gets fresh authority; the old epoch stays dead.
    let epoch = replace_workload(ship.home.path(), &ship.emitter, &suspect).unwrap();
    assert_eq!(epoch.0, 2);
    ship.launch("analyst").expect("the replacement launches");
    assert!(
        channel.deliver(1, 2, 3, &send) == Err(refused(MailboxError::StaleExecutionEpoch)),
        "a message from the replaced workload's epoch is rejected as a stale epoch"
    );
    assert!(
        channel.deliver(2, 2, 4, &send).is_ok(),
        "the replacement's own epoch is accepted"
    );

    // The ship reconnects: nothing is authorized until a fresh challenge is
    // answered under the ship's own key.
    let (mut link, nonce) = Reconnect::begin();
    assert!(!link.is_authorized());
    let answer = answer_challenge(&ship.identity, &nonce);
    link.complete(
        &ship.identity.verifying_key(),
        &answer,
        NodeState::Active,
        4,
        4,
    )
    .expect("a fresh answer reauthorizes");
    assert!(link.is_authorized());

    // Act 6: the evidence. The chain verifies, and one ordered view shows the
    // launch, the denials, the containment and the replacement.
    for node in [&aircraft, &ship, &ground] {
        verify_audit_chain(&node.chain(), &node.audit_key.verifying_key())
            .unwrap_or_else(|e| panic!("{} chain must verify: {e:?}", node.name));
    }
    let timeline = ship.timeline("analyst");
    println!(
        "\nsimulated: mailbox delivery is a local Unix socket or a loopback TCP transport between node services in one test process, with the guest mailbox in a separate host process (no booted guest, no vsock guest service, no Iroh, no cross-host transport), VMs (gated and audited, none boot)"
    );
    println!("\n--- evidence timeline: ship / analyst ---");
    for line in &timeline {
        println!("{line}");
    }
    let events: Vec<&str> = timeline
        .iter()
        .map(|l| l.split_whitespace().nth(1).unwrap())
        .collect();
    assert_eq!(
        events,
        [
            "plan.admitted",
            "plan.launched",
            "plan.admission_refused", // mailbox send without the grant
            "plan.admission_refused", // secret outside the lease
            "workload.quarantined",
            "plan.admission_refused", // relaunch while quarantined
            "workload.replaced",
            "plan.admitted",
            "plan.launched",
        ]
    );
}

fn channel_with_one_node() -> (Node, Channel) {
    let aircraft = Node::new("aircraft", 1);
    let channel = Channel::new(&aircraft);
    (aircraft, channel)
}

#[test]
fn the_service_queue_is_bounded_and_refuses_synchronously() {
    let send_ops = [MailboxOperation::Send, MailboxOperation::Receive];
    let (_node, channel) = channel_with_one_node();
    // Fill the queue without draining it, then the next send is refused.
    let capability = sign_capability(grant(&send_ops), &channel.authority_key).unwrap();
    for id in 1..=LIMITS.max_depth as u8 {
        let envelope = seal_envelope(
            SealRequest {
                routing: routing(),
                header: header(1, id),
                plaintext: b"hello",
            },
            &channel.encryption_key,
            &channel.sender_key,
        )
        .unwrap();
        send(&channel.socket, &capability, &envelope).expect("within depth");
    }
    let envelope = seal_envelope(
        SealRequest {
            routing: routing(),
            header: header(1, 99),
            plaintext: b"hello",
        },
        &channel.encryption_key,
        &channel.sender_key,
    )
    .unwrap();
    assert_eq!(
        send(&channel.socket, &capability, &envelope),
        Err(Refusal::QueueFull(LIMITS.max_depth))
    );
    assert!(
        channel.service.receive().is_some(),
        "queued messages stay readable"
    );
    // Draining one slot lets the refused message through (it was never consumed as a replay).
    send(&channel.socket, &capability, &envelope).expect("space after a receive");
}

#[test]
fn a_guest_flooding_the_mailbox_port_is_refused_at_its_own_queue() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    let (node, channel) = channel_with_one_node();
    let mut sealer = sealer(
        &channel,
        &[MailboxOperation::Send, MailboxOperation::Receive],
    );
    let mux = node.home.path().join("fc.vsock");
    let listener = UnixListener::bind(&mux).unwrap();
    // A Firecracker-style mux: the guest end answers CONNECT, then sends.
    let guest = std::thread::spawn(move || {
        let mut verdicts = Vec::new();
        for n in 0..=LIMITS.max_depth {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            assert_eq!(line.trim(), "CONNECT 5257");
            (&stream).write_all(b"OK 1\n").unwrap();
            let mut stream = stream;
            let mut message = outbox_message();
            message.message_id = MessageId::from_bytes([n as u8 + 1; 32]);
            verdicts.push(send_outbox_message(&mut stream, &message));
        }
        verdicts
    });
    let absent = node.home.path().join("absent.sock");
    for _ in 0..=LIMITS.max_depth {
        channel
            .service
            .serve_guest(&absent, &mux, &mut sealer)
            .unwrap();
    }
    let verdicts = guest.join().unwrap();
    assert!(verdicts[..LIMITS.max_depth].iter().all(Result::is_ok));
    assert_eq!(
        verdicts[LIMITS.max_depth],
        Err(Refusal::QueueFull(LIMITS.max_depth))
    );
}

/// A guest whose workload has not written its outbox yet accepts the dial and
/// closes without a frame. That must not read as a served connection, or the
/// launch stops dialing and a later message is never forwarded.
#[test]
fn a_guest_that_closes_without_a_frame_is_dialed_again() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    let (node, channel) = channel_with_one_node();
    let mut sealer = sealer(&channel, &[MailboxOperation::Send]);
    let mux = node.home.path().join("fc.vsock");
    let listener = UnixListener::bind(&mux).unwrap();
    let guest = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        stream.write_all(b"OK 1\n").unwrap();
    });
    let absent = node.home.path().join("absent.sock");
    assert!(
        channel
            .service
            .serve_guest(&absent, &mux, &mut sealer)
            .is_err()
    );
    guest.join().unwrap();
}

#[test]
fn a_guest_without_the_send_operation_is_refused_across_the_port() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    let (node, channel) = channel_with_one_node();
    let mut sealer = sealer(&channel, &[MailboxOperation::Receive]);
    let mux = node.home.path().join("fc.vsock");
    let listener = UnixListener::bind(&mux).unwrap();
    let guest = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        stream.write_all(b"OK 1\n").unwrap();
        send_outbox_message(&mut stream, &outbox_message())
    });
    channel
        .service
        .serve_guest(&node.home.path().join("absent.sock"), &mux, &mut sealer)
        .unwrap();
    assert!(matches!(guest.join().unwrap(), Err(Refusal::Mailbox(_))));
    assert!(channel.service.receive().is_none(), "nothing was queued");
}

/// A plan, optionally carrying a mailbox grant for `channel`'s authority and
/// epoch 1. The host-held trust the test hands in names a different epoch and
/// a different authority, so only the grant can make a message open.
fn plan_and_trust(channel: &Channel, granted: bool) -> (ExecutionPlan, MailboxPolicy) {
    let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
    if granted {
        plan.mailbox = Some(mvm_contract::protocol::mailbox::MailboxGrant {
            mailbox: address().mailbox,
            authority_key: channel.authority_key.verifying_key().to_bytes(),
            epoch: MbEpoch::new(1).unwrap(),
        });
    }
    let trust = MailboxPolicy {
        context: context(7),
        encryption_key: Key::from_bytes([23; 32]),
        sender_key: channel.sender_key.verifying_key(),
        authority_key: SigningKey::from_bytes(&[99; 32]).verifying_key(),
    };
    (plan, trust)
}

/// The real guest forwarder, writing a plaintext message from its outbox,
/// against the real service, over the real framing: the grant decides whether
/// the host serves the port at all, and the host seals what the guest sent.
#[test]
fn a_signed_mailbox_grant_alone_makes_the_host_serve_the_guest_port() {
    use std::os::unix::net::UnixListener;

    let (node, channel) = channel_with_one_node();
    let ops = [MailboxOperation::Send, MailboxOperation::Receive];
    let outbox = node.home.path().join("outbox");
    std::fs::write(&outbox, outbox_message().encode()).unwrap();
    let per_port = node.home.path().join("port.sock");
    let socket = node.home.path().join("granted.sock");
    let absent_mux = node.home.path().join("absent-mux");

    // No grant: nothing is bound and the guest port is never dialed.
    let listener = UnixListener::bind(&per_port).unwrap();
    listener.set_nonblocking(true).unwrap();
    let (plan, trust) = plan_and_trust(&channel, false);
    let sealer_for = || {
        let mut sealer = sealer(&channel, &ops);
        let future = 4_000_000_000_000;
        sealer.capability.expires_at_unix_ms = future;
        sealer.header.expires_at_unix_ms = future;
        sealer.routing.expires_at_unix_ms = future;
        sealer
    };
    let none = serve_granted_guest(
        plan.mailbox.as_ref(),
        trust,
        sealer_for(),
        LIMITS,
        &socket,
        (&per_port, &absent_mux),
    );
    assert!(none.unwrap().is_none());
    assert!(!socket.exists(), "no service socket without a grant");
    assert!(
        listener.accept().is_err(),
        "the guest port was never dialed"
    );

    // A grant naming an authority the host does not hold is refused.
    let (mut plan, trust) = plan_and_trust(&channel, true);
    plan.mailbox.as_mut().unwrap().authority_key = [1; 32];
    let foreign = serve_granted_guest(
        plan.mailbox.as_ref(),
        trust,
        sealer_for(),
        LIMITS,
        &socket,
        (&per_port, &absent_mux),
    );
    assert!(foreign.is_err(), "a foreign authority key is not honored");

    // Grant present: the guest forwards plaintext, the host seals and queues.
    listener.set_nonblocking(false).unwrap();
    let guest = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        mvm_agentd::mailbox_outbox::forward_outbox(&mut stream, &outbox)
    });
    let (plan, trust) = plan_and_trust(&channel, true);
    let service = serve_granted_guest(
        plan.mailbox.as_ref(),
        trust,
        sealer_for(),
        LIMITS,
        &socket,
        (&per_port, &absent_mux),
    )
    .unwrap()
    .expect("a granted plan is served");
    assert_eq!(guest.join().unwrap(), Ok(()));
    assert_eq!(service.receive().unwrap(), b"hello");

    let expired = seal_envelope(
        SealRequest {
            routing: routing(),
            header: header(1, 2),
            plaintext: b"hello",
        },
        &channel.encryption_key,
        &channel.sender_key,
    )
    .unwrap();
    let capability = sign_capability(grant(&ops), &channel.authority_key).unwrap();
    assert_eq!(
        send(&socket, &capability, &expired),
        Err(refused(MailboxError::Expired)),
        "live admission must not reuse the clock captured when the service started"
    );
}

/// A host key directory in a tempdir: the signing key, its public half and the
/// operator template. Never the real `~/.mvm`.
fn host_keys(dir: &std::path::Path, seed: u8) {
    use std::os::unix::fs::PermissionsExt;
    let key = SigningKey::from_bytes(&[seed; 32]);
    let secret = dir.join("host-signer.ed25519");
    std::fs::write(&secret, key.to_bytes()).unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(dir.join("host-signer.pub"), key.verifying_key().to_bytes()).unwrap();
    let (mut capability, mut header, mut routing) =
        (grant(&[MailboxOperation::Send]), header(1, 1), routing());
    let far = 4_000_000_000_000;
    capability.not_before_unix_ms = 0;
    capability.expires_at_unix_ms = far;
    header.recipient = aircraft_principal();
    header.expires_at_unix_ms = far;
    routing.expires_at_unix_ms = far;
    let template = mvm_hostd::mailbox_launch::MailboxTemplate {
        capability,
        header,
        routing,
    };
    std::fs::write(
        dir.join("mailbox-template.json"),
        serde_json::to_vec(&template).unwrap(),
    )
    .unwrap();
}

fn granted_plan(authority_key: [u8; 32]) -> ExecutionPlan {
    let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
    plan.mailbox = Some(mvm_contract::protocol::mailbox::MailboxGrant {
        mailbox: address().mailbox,
        authority_key,
        epoch: MbEpoch::new(1).unwrap(),
    });
    plan
}

#[test]
fn a_restarted_mailbox_sealer_does_not_reuse_its_sender_boot() {
    use mvm_hostd::mailbox_launch::{authority_key_for, derive_launch_keys};

    let dir = tempfile::tempdir().unwrap();
    host_keys(dir.path(), 5);
    let authority = authority_key_for(dir.path(), &address().mailbox).unwrap();
    let grant = granted_plan(authority.to_bytes()).mailbox.unwrap();
    let keys = derive_launch_keys(dir.path(), &grant).unwrap();
    let (_, first) = keys.trust();
    let (_, restarted) = keys.trust();
    let first = first.with_grant(&grant).unwrap();
    let restarted = restarted.with_grant(&grant).unwrap();

    assert_ne!(
        first.header.sender_boot, restarted.header.sender_boot,
        "a fresh process starts its sequence at one but must not replay the prior boot's identity"
    );
}

/// The sealing keys are derived from the host key per mailbox: they differ
/// between mailboxes and hosts, and none is the host signing key.
#[test]
fn derived_mailbox_keys_differ_per_mailbox_and_are_not_the_host_key() {
    use mvm_hostd::mailbox_launch::{authority_key_for, host_trust};
    let (keys, other) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    host_keys(keys.path(), 5);
    host_keys(other.path(), 6);
    let (m1, m2) = (
        MailboxId::from_bytes([1; 32]),
        MailboxId::from_bytes([2; 32]),
    );
    let a1 = authority_key_for(keys.path(), &m1).unwrap();
    assert_ne!(a1, authority_key_for(keys.path(), &m2).unwrap());
    assert_ne!(a1, authority_key_for(other.path(), &m1).unwrap());
    assert_ne!(a1, SigningKey::from_bytes(&[5; 32]).verifying_key());

    let mut plan = granted_plan(a1.to_bytes());
    plan.mailbox.as_mut().unwrap().mailbox = m1;
    let grant = plan.mailbox.unwrap();
    let (policy, sealer) = host_trust(keys.path(), &grant).unwrap();
    assert_eq!(policy.authority_key, a1);
    assert_ne!(sealer.sender_key.to_bytes(), [5; 32]);
    assert_ne!(sealer.authority_key.to_bytes(), [5; 32]);
    assert_ne!(
        sealer.sender_key.to_bytes(),
        sealer.authority_key.to_bytes()
    );
    // An authority the host does not derive for this mailbox is refused.
    let mut foreign = grant;
    foreign.authority_key = authority_key_for(keys.path(), &m2).unwrap().to_bytes();
    assert!(host_trust(keys.path(), &foreign).is_err());
}

/// A granted plan's derived keys serve the guest port from their own thread
/// and queue what the guest sent.
#[test]
fn derived_keys_serve_the_guest_port_and_queue_what_the_guest_sent() {
    use mvm_hostd::mailbox_launch::{
        LAUNCH_LIMITS, ServePaths, authority_key_for, derive_launch_keys, serve_derived,
    };
    use std::os::unix::net::UnixListener;

    let dir = tempfile::tempdir().unwrap();
    host_keys(dir.path(), 5);
    let listener = UnixListener::bind(dir.path().join("port.sock")).unwrap();
    let authority = authority_key_for(dir.path(), &address().mailbox).unwrap();
    let grant = granted_plan(authority.to_bytes()).mailbox.unwrap();
    let keys = derive_launch_keys(dir.path(), &grant).unwrap();
    let outbox = dir.path().join("outbox");
    std::fs::write(&outbox, outbox_message().encode()).unwrap();
    let guest = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        mvm_agentd::mailbox_outbox::forward_outbox(&mut stream, &outbox)
    });
    let launch = serve_derived(
        grant,
        keys,
        ServePaths {
            socket: dir.path().join("mailbox.sock"),
            guest_port: dir.path().join("port.sock"),
            firecracker_mux: dir.path().join("absent-mux"),
            intent_dir: Some(dir.path().join("intents")),
        },
        LAUNCH_LIMITS,
    );
    assert_eq!(guest.join().unwrap(), Ok(()));
    let received = (0..100).find_map(|_| {
        launch.receive().or_else(|| {
            std::thread::sleep(std::time::Duration::from_millis(50));
            None
        })
    });
    assert_eq!(received.unwrap(), b"hello");
}

#[test]
fn a_running_guest_submits_again_after_its_first_message_was_consumed() {
    use mvm_hostd::mailbox_launch::{
        LAUNCH_LIMITS, ServePaths, authority_key_for, derive_launch_keys, serve_derived,
    };
    use std::os::unix::net::UnixListener;

    let dir = tempfile::tempdir().unwrap();
    host_keys(dir.path(), 5);
    let listener = UnixListener::bind(dir.path().join("port.sock")).unwrap();
    let authority = authority_key_for(dir.path(), &address().mailbox).unwrap();
    let grant = granted_plan(authority.to_bytes()).mailbox.unwrap();
    let keys = derive_launch_keys(dir.path(), &grant).unwrap();
    let outbox = dir.path().join("outbox");
    mvm_agentd::mailbox_outbox::write_outbox(&outbox, &outbox_message()).unwrap();
    let guest_outbox = outbox.clone();
    let guest = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            mvm_agentd::mailbox_outbox::wait_and_forward_outbox(&mut stream, &guest_outbox)
                .expect("guest submits pending operation");
        }
    });
    let launch = serve_derived(
        grant,
        keys,
        ServePaths {
            socket: dir.path().join("mailbox.sock"),
            guest_port: dir.path().join("port.sock"),
            firecracker_mux: dir.path().join("absent-mux"),
            intent_dir: Some(dir.path().join("intents")),
        },
        LAUNCH_LIMITS,
    );
    let receive = || {
        (0..100)
            .find_map(|_| {
                launch.receive().or_else(|| {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    None
                })
            })
            .expect("the live guest message arrives")
    };
    assert_eq!(receive(), b"hello");
    let next = OutboxMessage::new(aircraft_principal(), b"after-start".to_vec());
    mvm_agentd::mailbox_outbox::write_outbox(&outbox, &next).unwrap();
    assert_eq!(receive(), b"after-start");
    guest.join().unwrap();
}

#[test]
fn durable_local_destination_signs_only_after_journal_and_anchor_commit() {
    use mvm_contract::protocol::mailbox::DeliveryOutcome;
    use mvm_core::mailbox::journal::{FileJournalAnchor, JournalLimits, MailboxJournal};
    use mvm_hostd::mailbox_service::durable::{DurableMailboxService, send as send_durable};

    let (node, channel) = channel_with_one_node();
    let journal_dir = node.home.path().join("journal");
    let anchor_path = node.home.path().join("mailbox-anchor");
    let socket = node.home.path().join("durable.sock");
    let signer = channel.authority_key.clone();
    let authority = signer.verifying_key();
    let limits = JournalLimits {
        max_records: 2,
        max_bytes: 64 * 1024,
    };
    let mut header = header(1, 3);
    header.expires_at_unix_ms = 4_000_000_000_000;
    let mut routing = routing();
    routing.expires_at_unix_ms = header.expires_at_unix_ms;
    let mut capability_grant = grant(&[MailboxOperation::Send]);
    capability_grant.expires_at_unix_ms = header.expires_at_unix_ms;
    let mut undersized_grant = capability_grant.clone();
    undersized_grant.max_payload_bytes = 4;
    let undersized = sign_capability(undersized_grant, &signer).unwrap();
    let capability = sign_capability(capability_grant, &signer).unwrap();
    let envelope = seal_envelope(
        SealRequest {
            routing,
            header: header.clone(),
            plaintext: b"hello",
        },
        &channel.encryption_key,
        &channel.sender_key,
    )
    .unwrap();

    let start = || {
        let anchor = FileJournalAnchor::open(&anchor_path, address(), [91; 32])
            .expect("private local anchor");
        let journal = MailboxJournal::open(
            &journal_dir,
            address(),
            authority,
            [90; 32],
            limits,
            anchor.tip(),
        )
        .expect("journal recovery");
        DurableMailboxService::bind(
            &socket,
            LIMITS,
            MailboxPolicy {
                context: context(1),
                encryption_key: Key::from_bytes([23; 32]),
                sender_key: channel.sender_key.verifying_key(),
                authority_key: authority,
            },
            signer.clone(),
            journal,
            anchor,
        )
        .expect("destination listener")
    };

    let service = start();
    assert_eq!(
        send_durable(&socket, &undersized, &envelope, &header, &authority),
        Err(Refusal::Oversized(4)),
        "the signed payload ceiling is a terminal refusal, not a durable receipt"
    );
    let accepted = send_durable(&socket, &capability, &envelope, &header, &authority)
        .expect("destination signed durable verdict");
    assert_eq!(accepted.receipt.outcome, DeliveryOutcome::AcceptedDurable);
    let mut receive_grant = grant(&[MailboxOperation::Receive]);
    receive_grant.subject = aircraft_principal();
    receive_grant.capability_id = CapabilityId::from_bytes([88; 32]);
    receive_grant.expires_at_unix_ms = header.expires_at_unix_ms;
    let receive_capability = sign_capability(receive_grant, &signer).unwrap();
    let mut reader = context(1);
    reader.acting_principal = aircraft_principal();
    reader.required_operation = MailboxOperation::Receive;
    assert!(matches!(
        service.receive_next(&capability, &reader),
        Err(mvm_core::mailbox::journal::JournalError::Mailbox(
            MailboxError::WrongCapabilitySubject
        ))
    ));
    let pending = service
        .receive_next(&receive_capability, &reader)
        .expect("independent Receive authority")
        .expect("pending message");
    assert_eq!(pending.payload(), b"hello");
    let identity = pending.identity();
    service
        .acknowledge(identity, &receive_capability, &reader)
        .expect("durable ACK");
    assert!(
        service
            .receive_next(&receive_capability, &reader)
            .expect("after ACK")
            .is_none()
    );
    drop(service);
    let anchor = FileJournalAnchor::open(&anchor_path, address(), [91; 32])
        .expect("anchor survived destination restart");
    let tip = anchor.tip();
    assert_eq!(tip.cursor, 2, "acceptance and ACK each advanced the anchor");
    drop(anchor);
    let service = start();
    assert!(
        service
            .receive_next(&receive_capability, &reader)
            .expect("ACK survived restart")
            .is_none()
    );
    let duplicate = send_durable(&socket, &capability, &envelope, &header, &authority)
        .expect("retry after service restart");
    assert_eq!(duplicate.receipt.outcome, DeliveryOutcome::Duplicate);
    drop(service);
    let anchor = FileJournalAnchor::open(&anchor_path, address(), [91; 32])
        .expect("retry did not corrupt the anchor");
    assert_eq!(anchor.tip(), tip, "retry must not append a record");
}

#[test]
fn durable_mailbox_helper_process() {
    let Ok(root) = std::env::var("MVM_MAILBOX_TEST_ROOT") else {
        return;
    };
    use mvm_core::mailbox::journal::{FileJournalAnchor, JournalLimits, MailboxJournal};
    use mvm_hostd::mailbox_service::durable::DurableMailboxService;

    let root = std::path::Path::new(&root);
    let signer = SigningKey::from_bytes(&[22; 32]);
    let authority = signer.verifying_key();
    let anchor = FileJournalAnchor::open(&root.join("anchor"), address(), [91; 32])
        .expect("recover software anchor");
    let journal = MailboxJournal::open_reconciling(
        &root.join("journal"),
        address(),
        authority,
        [90; 32],
        JournalLimits {
            max_records: 2,
            max_bytes: 64 * 1024,
        },
        &anchor,
    )
    .expect("recover journal and dedup");
    let _service = DurableMailboxService::bind(
        &root.join("durable.sock"),
        LIMITS,
        MailboxPolicy {
            context: context(1),
            encryption_key: Key::from_bytes([23; 32]),
            sender_key: SigningKey::from_bytes(&[21; 32]).verifying_key(),
            authority_key: authority,
        },
        signer,
        journal,
        anchor,
    )
    .expect("bind destination");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

#[test]
fn a_killed_destination_reopens_its_anchor_and_deduplicates_the_retry() {
    use mvm_contract::protocol::mailbox::DeliveryOutcome;
    use mvm_core::mailbox::journal::FileJournalAnchor;
    use mvm_hostd::mailbox_service::durable::send as send_durable;

    let dir = tempfile::tempdir_in("/tmp").expect("short Unix socket path");
    let socket = dir.path().join("durable.sock");
    let signer = SigningKey::from_bytes(&[22; 32]);
    let authority = signer.verifying_key();
    let mut header = header(1, 3);
    header.expires_at_unix_ms = 4_000_000_000_000;
    let mut routing = routing();
    routing.expires_at_unix_ms = header.expires_at_unix_ms;
    let mut capability_grant = grant(&[MailboxOperation::Send]);
    capability_grant.expires_at_unix_ms = header.expires_at_unix_ms;
    let capability = sign_capability(capability_grant, &signer).unwrap();
    let envelope = seal_envelope(
        SealRequest {
            routing,
            header: header.clone(),
            plaintext: b"hello",
        },
        &Key::from_bytes([23; 32]),
        &SigningKey::from_bytes(&[21; 32]),
    )
    .unwrap();
    let launch = || {
        KillOnDrop(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "durable_mailbox_helper_process"])
                .env("MVM_MAILBOX_TEST_ROOT", dir.path())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("start destination process"),
            dir.path().join("child.log"),
        )
    };
    let submit = || {
        (0..100)
            .find_map(|_| {
                match send_durable(&socket, &capability, &envelope, &header, &authority) {
                    Ok(receipt) => Some(receipt),
                    Err(Refusal::Unavailable) => {
                        std::thread::sleep(std::time::Duration::from_millis(20));
                        None
                    }
                    Err(other) => panic!("unexpected destination refusal: {other}"),
                }
            })
            .expect("destination was ready within two seconds")
    };

    let mut process = launch();
    assert_eq!(submit().receipt.outcome, DeliveryOutcome::AcceptedDurable);
    process.0.kill().expect("crash destination");
    process.0.wait().expect("reap crashed process");
    drop(process);
    let anchor = FileJournalAnchor::open(&dir.path().join("anchor"), address(), [91; 32])
        .expect("anchor survives process crash");
    assert_eq!(
        anchor.tip().cursor,
        1,
        "the signed verdict followed durable commit"
    );
    drop(anchor);
    let _restarted = launch();
    assert_eq!(submit().receipt.outcome, DeliveryOutcome::Duplicate);
}

struct KillOnDrop(std::process::Child, std::path::PathBuf);

impl KillOnDrop {
    fn stderr(&self) -> String {
        std::fs::read_to_string(&self.1).unwrap_or_default()
    }

    /// Accept one connection within 20s, or fail with the child's stderr.
    fn accept(
        &mut self,
        listener: &std::os::unix::net::UnixListener,
    ) -> std::os::unix::net::UnixStream {
        listener.set_nonblocking(true).unwrap();
        for _ in 0..400 {
            if let Ok((stream, _)) = listener.accept() {
                stream.set_nonblocking(false).unwrap();
                return stream;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("the process never dialed; stderr:\n{}", self.stderr());
    }
}
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_mailbox_process(config: &[u8]) -> KillOnDrop {
    use std::io::Write;
    let (log_file, log) = tempfile::NamedTempFile::new().unwrap().keep().unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_mvm-mailbox"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(log_file)
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(config).unwrap();
    KillOnDrop(child, log)
}

/// The separate mailbox process, handed only derived keys and the guest's
/// paths on stdin, dials the guest's mailbox port and binds the VM's mailbox
/// socket; the host signing seed is in its config nowhere.
#[test]
fn the_mailbox_process_serves_a_granted_mailbox_from_derived_keys_alone() {
    use mvm_hostd::mailbox_process::build_config;
    use std::os::unix::net::UnixListener;

    let dir = tempfile::tempdir().unwrap();
    let keys = dir.path().join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    host_keys(&keys, 5);
    let state_dir = dir.path().join("vm");
    std::fs::create_dir_all(&state_dir).unwrap();
    let authority = mvm_hostd::mailbox_launch::authority_key_for(&keys, &address().mailbox)
        .unwrap()
        .to_bytes();
    let grant = granted_plan(authority).mailbox.unwrap();
    let config = build_config(&keys, &grant, &state_dir).unwrap();
    std::fs::create_dir_all(config.guest_port.parent().unwrap()).unwrap();
    let listener = UnixListener::bind(&config.guest_port).unwrap();
    let wire = serde_json::to_vec(&config).unwrap();
    let seed = std::fs::read(keys.join("host-signer.ed25519")).unwrap();
    assert!(
        !String::from_utf8_lossy(&wire).contains(&hex::encode(&seed)),
        "the seed is not in the process config"
    );

    let outbox = dir.path().join("outbox");
    std::fs::write(&outbox, outbox_message().encode()).unwrap();
    let mut process = spawn_mailbox_process(&wire);
    let mut stream = process.accept(&listener);
    assert_eq!(
        mvm_agentd::mailbox_outbox::forward_outbox(&mut stream, &outbox),
        Ok(())
    );
    assert!(
        (0..100).any(|_| {
            std::thread::sleep(std::time::Duration::from_millis(50));
            mvm_core::config::vm_mailbox_socket_at(&state_dir).exists()
        }),
        "the host service bound its socket; stderr:\n{}",
        process.stderr()
    );
    assert!(
        !outbox.exists(),
        "guest received a durable admission verdict"
    );
    assert!(state_dir.join("mailbox-anchor").exists());
    let record = std::fs::read(
        state_dir
            .join("mailbox-journal")
            .join("entry-00000000000000000001.bin"),
    )
    .expect("accepted canonical ciphertext is durable");
    assert!(
        !record.windows(5).any(|w| w == b"hello"),
        "the durable record never stores guest plaintext"
    );
    let later = OutboxMessage::new(aircraft_principal(), b"after-start".to_vec());
    mvm_agentd::mailbox_outbox::write_outbox(&outbox, &later).unwrap();
    let mut stream = process.accept(&listener);
    assert_eq!(
        mvm_agentd::mailbox_outbox::forward_outbox(&mut stream, &outbox),
        Ok(()),
        "the running process keeps serving the live guest"
    );
    assert!(
        state_dir
            .join("mailbox-journal")
            .join("entry-00000000000000000002.bin")
            .exists(),
        "a post-start operation committed durably"
    );
    process.0.kill().expect("crash the mailbox helper");
    process.0.wait().expect("reap the crashed helper");
    drop(process);
    mvm_agentd::mailbox_outbox::write_outbox(&outbox, &outbox_message()).unwrap();
    let mut restarted = spawn_mailbox_process(&wire);
    let forwarded = (0..8).any(|_| {
        let mut stream = restarted.accept(&listener);
        matches!(
            mvm_agentd::mailbox_outbox::forward_outbox(&mut stream, &outbox),
            Ok(())
        )
    });
    assert!(
        forwarded,
        "the same immutable guest operation must be reconciled after restart"
    );
    assert!(
        !state_dir
            .join("mailbox-journal")
            .join("entry-00000000000000000003.bin")
            .exists(),
        "a recovered duplicate does not create a second durable acceptance"
    );
}

#[test]
fn a_corrupt_mailbox_anchor_prevents_the_helper_from_reporting_ready() {
    use mvm_hostd::mailbox_process::build_config;

    let dir = tempfile::tempdir().unwrap();
    let keys = dir.path().join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    host_keys(&keys, 5);
    let state_dir = dir.path().join("vm");
    std::fs::create_dir_all(&state_dir).unwrap();
    let authority = mvm_hostd::mailbox_launch::authority_key_for(&keys, &address().mailbox)
        .unwrap()
        .to_bytes();
    let grant = granted_plan(authority).mailbox.unwrap();
    let config = build_config(&keys, &grant, &state_dir).unwrap();
    std::fs::write(state_dir.join("mailbox-anchor"), b"{").unwrap();
    let mut process = spawn_mailbox_process(&serde_json::to_vec(&config).unwrap());
    let status = (0..100).find_map(|_| {
        let exited = process.0.try_wait().unwrap();
        if exited.is_none() {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        exited
    });
    assert_eq!(
        status.and_then(|status| status.code()),
        Some(1),
        "a corrupt anchor must fail closed; stderr:\n{}",
        process.stderr()
    );
    assert!(
        !config.socket.exists(),
        "no mailbox endpoint may be published from a corrupt anchor"
    );
}

// ---- two nodes over a loopback TCP PeerTransport ----------------------------

fn tcp_limits() -> TcpListenerLimits {
    TcpListenerLimits {
        max_frame_bytes: 64 * 1024,
        max_pending_bytes: 128 * 1024,
        max_connections: 4,
        io_timeout: std::time::Duration::from_secs(2),
    }
}

/// A signed binding to the aircraft's listener, valid for `epoch` until `expires`.
fn route_to(
    addr: std::net::SocketAddr,
    epoch: u64,
    expires: i64,
    authority: &SigningKey,
) -> Result<AuthorizedRoute, TransportBindingError> {
    let r = routing();
    let claims = TransportBindingClaims {
        protocol_version: ProtocolVersion::V1,
        signature_algorithm: SignatureAlgorithm::ED25519,
        binding_id: r.transport_binding_id,
        issuer: issuer(),
        address: address(),
        execution_epoch: MbEpoch::new(epoch).unwrap(),
        transport_identity: TransportIdentity::from_bytes([9; 32]),
        route_id: RouteId::from_bytes([20; 32]),
        authorization_domain_route_label: r.authorization_domain_route_label,
        destination_route_token: r.destination_route_token,
        path: TransportPath::Direct,
        locator: RouteLocator::parse(addr.to_string()).unwrap(),
        assurance: TransportAssurance::IsolatedProduction,
        policy_epoch: 4,
        not_before_unix_ms: 900,
        expires_at_unix_ms: expires,
    };
    let signed = sign_transport_binding(claims, authority).unwrap();
    let ctx = TransportBindingContext {
        expected_issuer: issuer(),
        expected_address: address(),
        current_execution_epoch: MbEpoch::new(1).unwrap(),
        current_policy_epoch: 4,
        minimum_assurance: TransportAssurance::IsolatedProduction,
        now_unix_ms: 1_500,
        revoked_bindings: vec![],
    };
    authorize_route(&signed, &ctx, &authority.verifying_key())
}

#[test]
fn two_nodes_deliver_over_a_loopback_tcp_peer_transport() {
    let (aircraft, ship) = (Node::new("aircraft", 1), Node::new("ship", 2));
    let channel = Channel::new(&aircraft);
    let capability = sign_capability(grant(&[MailboxOperation::Send]), &channel.authority_key);
    let cancel = CancellationToken::default();
    let listener = TcpPeerListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        channel.socket.clone(),
        capability.unwrap(),
        tcp_limits(),
        cancel.clone(),
    )
    .unwrap();
    let addr = listener.local_addr();
    let transport = TcpPeerTransport {
        io_timeout: std::time::Duration::from_secs(2),
    };
    let limits = ChannelLimits::new(64 * 1024, 128 * 1024).unwrap();
    let transport_authority = SigningKey::from_bytes(&[24; 32]);
    let sender_cancel = CancellationToken::default();
    let frame_for = |id: u8, route: &AuthorizedRoute| {
        let prepared = prepare_mailbox_envelope(
            SealRequest {
                routing: routing(),
                header: header(1, id),
                plaintext: b"hello",
            },
            &channel.encryption_key,
            &channel.sender_key,
        )
        .unwrap();
        let capability =
            sign_capability(grant(&[MailboxOperation::Send]), &channel.authority_key).unwrap();
        authorize_outbound(OutboundAuthorization {
            prepared: &prepared,
            capability: &capability,
            context: &context(1),
            capability_authority_key: &channel.authority_key.verifying_key(),
            route,
        })
        .unwrap()
    };
    let route = route_to(addr, 1, 2_000, &transport_authority).unwrap();
    let mut peer = transport.connect(&route, limits, &sender_cancel).unwrap();

    // Delivery: the aircraft's queue holds the ship's plaintext, and the
    // aircraft's own chain records it.
    let frame = frame_for(1, &route);
    peer.try_send(&frame, &sender_cancel).unwrap();
    assert_eq!(channel.service.receive().unwrap(), b"hello");
    ship.emitter
        .emit_admitted(&ship.plan("mailbox"), "peer:aircraft")
        .unwrap();
    aircraft
        .emitter
        .emit_admitted(&aircraft.plan("mailbox"), "peer:ship")
        .unwrap();

    // Replay of the same frame is refused at the destination.
    assert_eq!(
        peer.try_send(&frame, &sender_cancel),
        Err(TransportError::Refused)
    );
    // A tampered frame and an oversize frame are refused at the destination.
    let raw = |body: &[u8], claimed: u32| {
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        let _ = s.write_all(&claimed.to_be_bytes());
        let _ = s.write_all(body);
        let mut reply = Vec::new();
        s.read_to_end(&mut reply).unwrap();
        serde_json::from_slice::<Result<(), Refusal>>(&reply).unwrap()
    };
    let mut tampered = frame_for(2, &route).as_bytes().to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(raw(&tampered, tampered.len() as u32).is_err());
    assert_eq!(raw(&[], 1 << 20), Err(Refusal::Oversized(64 * 1024)));
    assert!(
        channel.service.receive().is_none(),
        "nothing refused queued"
    );
    for reason in ["replay", "tampered", "oversize"] {
        aircraft.record_denial("mailbox", "peer_transport", reason);
    }

    // Binding refusals happen before a byte leaves the sender.
    assert_eq!(
        route_to(addr, 1, 1_500, &transport_authority).err(),
        Some(TransportBindingError::Expired)
    );
    assert_eq!(
        route_to(addr, 2, 2_000, &transport_authority).err(),
        Some(TransportBindingError::StaleExecutionEpoch)
    );
    // A frame larger than the channel bound never leaves the sender.
    let small = ChannelLimits::new(16, 32).unwrap();
    let mut tiny = transport.connect(&route, small, &sender_cancel).unwrap();
    assert_eq!(
        tiny.try_send(&frame, &sender_cancel),
        Err(TransportError::FrameTooLarge)
    );

    // Shutdown joins cleanly, and a partition fails closed with no delivery.
    drop(listener);
    assert!(cancel.is_cancelled());
    assert!(matches!(
        transport.connect(&route, limits, &sender_cancel),
        Err(TransportError::Partitioned)
    ));
    assert_eq!(
        peer.try_send(&frame_for(3, &route), &sender_cancel),
        Err(TransportError::Partitioned)
    );
    assert!(channel.service.receive().is_none());
    for node in [&aircraft, &ship] {
        verify_audit_chain(&node.chain(), &node.audit_key.verifying_key()).unwrap();
    }
    assert_eq!(aircraft.lines().len(), 4);
    assert_eq!(ship.lines().len(), 1);
}
