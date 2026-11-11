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
//! by a separate host process (`mvm-mailbox`) in its own hermetic tests below.
//!
//! What is simulated, on purpose: the three nodes are simulated nodes in one
//! test process, and their VMs are gated and audited but none boots here.
//! Between nodes there is no Iroh or relay and no cross-host transport; the
//! TCP transport is loopback inside this process. Only the aircraft node runs
//! a service. A booted guest's mailbox path is not exercised by this test: it
//! was witnessed by hand, separately, on a Firecracker host (many messages per
//! VM) and on an HVF host (macOS 26+ Apple Silicon; one message per VM, a
//! re-witness is pending), as recorded under "Demo status" in
//! `specs/contracts/host-interface-distributed-execution.md`. Neither is a CI
//! lane. Run with `--nocapture` to read the timeline.

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
    }
}

/// What a guest leaves in its outbox: a recipient and a plaintext body.
fn outbox_message() -> OutboxMessage {
    OutboxMessage {
        recipient: aircraft_principal(),
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
        "\nsimulated: the three nodes are simulated nodes in one test process; their VMs are gated and audited but none boots here; node-to-node mailbox delivery is a local Unix socket or a loopback TCP transport (no Iroh, no cross-host transport); the booted-guest mailbox path is wired through the backend capability on Firecracker and HVF and live-witnessed by separate manual runs, not CI lanes: many messages per VM on Firecracker, HVF re-witness pending, see Demo status in specs/contracts/host-interface-distributed-execution.md"
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
        for _ in 0..=LIMITS.max_depth {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            assert_eq!(line.trim(), "CONNECT 5257");
            (&stream).write_all(b"OK 1\n").unwrap();
            let mut stream = stream;
            verdicts.push(send_outbox_message(&mut stream, &outbox_message()));
        }
        verdicts
    });
    for _ in 0..=LIMITS.max_depth {
        channel
            .service
            .serve_guest(
                &mvm_core::vm_backend::HostDialRoute::Mux(mux.clone()),
                &mut sealer,
            )
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
    assert!(
        channel
            .service
            .serve_guest(
                &mvm_core::vm_backend::HostDialRoute::Mux(mux.clone()),
                &mut sealer
            )
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
        .serve_guest(
            &mvm_core::vm_backend::HostDialRoute::Mux(mux.clone()),
            &mut sealer,
        )
        .unwrap();
    assert!(matches!(guest.join().unwrap(), Err(Refusal::Mailbox(_))));
    assert!(channel.service.receive().is_none(), "nothing was queued");
}

/// What a guest that addresses `recipient` gets back, and what the host queued.
fn guest_sends_to(recipient: PrincipalId) -> (Result<(), Refusal>, Option<Vec<u8>>) {
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
        let message = OutboxMessage {
            recipient,
            body: b"hello".to_vec(),
        };
        send_outbox_message(&mut stream, &message)
    });
    channel
        .service
        .serve_guest(
            &mvm_core::vm_backend::HostDialRoute::Mux(mux.clone()),
            &mut sealer,
        )
        .unwrap();
    (guest.join().unwrap(), channel.service.receive())
}

/// A workload can address its mailbox without knowing the host-derived
/// recipient: the mailbox id or the all-zero recipient is sealed to the
/// template's recipient and delivered; any other value is still refused.
#[test]
fn a_guest_addresses_its_own_mailbox_without_the_derived_recipient() {
    use mvm_core::mailbox::frame::OWN_MAILBOX_RECIPIENT;

    let mailbox = PrincipalId::from_bytes(*address().mailbox.as_bytes());
    for named in [mailbox, PrincipalId::from_bytes(OWN_MAILBOX_RECIPIENT)] {
        assert_ne!(named, aircraft_principal(), "the guest does not know it");
        let (verdict, queued) = guest_sends_to(named);
        assert_eq!(verdict, Ok(()));
        assert_eq!(queued.as_deref(), Some(&b"hello"[..]));
    }
    let (verdict, queued) = guest_sends_to(PrincipalId::from_bytes([9; 32]));
    let Err(refusal) = verdict else {
        panic!("a recipient the policy does not name was sealed");
    };
    assert!(matches!(refusal, Refusal::Mailbox(_)));
    assert!(queued.is_none());
    // The only thing the guest reads back is a verdict, and it names no
    // recipient: the derived value stays with the host.
    let derived = aircraft_principal();
    let text = format!("{refusal:?}");
    assert!(!text.contains(&hex::encode(derived.as_bytes())), "{text}");
    assert!(
        !text.contains(&format!("{:?}", derived.as_bytes())),
        "{text}"
    );
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
    std::fs::create_dir(&outbox).unwrap();
    mvm_agentd::mailbox_outbox::write_outbox(&outbox, &outbox_message()).unwrap();
    let per_port = node.home.path().join("port.sock");
    let socket = node.home.path().join("granted.sock");

    // No grant: nothing is bound and the guest port is never dialed.
    let listener = UnixListener::bind(&per_port).unwrap();
    let route = mvm_core::vm_backend::HostDialRoute::PortSocket(per_port.clone());
    listener.set_nonblocking(true).unwrap();
    let (plan, trust) = plan_and_trust(&channel, false);
    let sealer_for = || sealer(&channel, &ops);
    let none = serve_granted_guest(
        plan.mailbox.as_ref(),
        trust,
        sealer_for(),
        LIMITS,
        &socket,
        &route,
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
    let refused = serve_granted_guest(
        plan.mailbox.as_ref(),
        trust,
        sealer_for(),
        LIMITS,
        &socket,
        &route,
    );
    assert!(refused.is_err(), "a foreign authority key is not honored");

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
        &route,
    )
    .unwrap()
    .expect("a granted plan is served");
    assert_eq!(guest.join().unwrap(), Ok(()));
    assert_eq!(service.receive().unwrap(), b"hello");
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

fn test_secret() -> mvm_core::crypto::aead::Key {
    mvm_core::crypto::aead::Key::from_bytes([5; 32])
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
    let a1 = authority_key_for(keys.path(), &m1, MbEpoch::new(1).unwrap()).unwrap();
    assert_ne!(
        a1,
        authority_key_for(keys.path(), &m2, MbEpoch::new(1).unwrap()).unwrap()
    );
    assert_ne!(
        a1,
        authority_key_for(other.path(), &m1, MbEpoch::new(1).unwrap()).unwrap()
    );
    assert_ne!(a1, SigningKey::from_bytes(&[5; 32]).verifying_key());

    let mut plan = granted_plan(a1.to_bytes());
    plan.mailbox.as_mut().unwrap().mailbox = m1;
    let grant = plan.mailbox.unwrap();
    let (policy, sealer) = host_trust(keys.path(), &grant, &test_secret()).unwrap();
    assert_eq!(policy.authority_key, a1);
    assert_ne!(sealer.sender_key.to_bytes(), [5; 32]);
    assert_ne!(sealer.authority_key.to_bytes(), [5; 32]);
    assert_ne!(
        sealer.sender_key.to_bytes(),
        sealer.authority_key.to_bytes()
    );
    // An authority the host does not derive for this mailbox is refused.
    let mut foreign = grant;
    foreign.authority_key = authority_key_for(keys.path(), &m2, MbEpoch::new(1).unwrap())
        .unwrap()
        .to_bytes();
    assert!(host_trust(keys.path(), &foreign, &test_secret()).is_err());
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
    let authority =
        authority_key_for(dir.path(), &address().mailbox, MbEpoch::new(1).unwrap()).unwrap();
    let grant = granted_plan(authority.to_bytes()).mailbox.unwrap();
    let keys = derive_launch_keys(dir.path(), &grant, &test_secret()).unwrap();
    let outbox = dir.path().join("outbox");
    std::fs::create_dir(&outbox).unwrap();
    mvm_agentd::mailbox_outbox::write_outbox(&outbox, &outbox_message()).unwrap();
    let guest = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        mvm_agentd::mailbox_outbox::forward_outbox(&mut stream, &outbox)
    });
    let launch = serve_derived(
        grant,
        keys,
        ServePaths {
            socket: dir.path().join("mailbox.sock"),
            route: mvm_core::vm_backend::HostDialRoute::PortSocket(dir.path().join("port.sock")),
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

/// One framed request to the mailbox socket as a host peer; the raw reply.
fn host_frame(socket: &std::path::Path, body: &[u8]) -> String {
    host_frame_on(
        &mut std::os::unix::net::UnixStream::connect(socket).unwrap(),
        body,
    )
}

/// Queue `bodies` through the guest port, in order, on a mux that answers
/// CONNECT. A body that is itself a read request is sent as the raw frame.
fn guest_sends(node: &Node, channel: &Channel, bodies: &[&[u8]]) -> Vec<Result<(), Refusal>> {
    use std::io::{BufRead, BufReader, Write};
    let mut sealer = sealer(channel, &[MailboxOperation::Send]);
    let mux = node.home.path().join("fc.vsock");
    let listener = std::os::unix::net::UnixListener::bind(&mux).unwrap();
    let owned: Vec<Vec<u8>> = bodies.iter().map(|b| b.to_vec()).collect();
    let guest = std::thread::spawn(move || {
        owned
            .iter()
            .map(|body| {
                let (stream, _) = listener.accept().unwrap();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut String::new())
                    .unwrap();
                (&stream).write_all(b"OK 1\n").unwrap();
                let mut stream = stream;
                if body.first() == Some(&b'{') {
                    let reply = host_frame_on(&mut stream, body);
                    serde_json::from_str::<Result<(), Refusal>>(&reply).unwrap()
                } else {
                    let message = OutboxMessage {
                        recipient: aircraft_principal(),
                        body: body.clone(),
                    };
                    send_outbox_message(&mut stream, &message)
                }
            })
            .collect::<Vec<_>>()
    });
    for _ in bodies {
        channel
            .service
            .serve_guest(
                &mvm_core::vm_backend::HostDialRoute::Mux(mux.clone()),
                &mut sealer,
            )
            .unwrap();
    }
    guest.join().unwrap()
}

fn host_frame_on(stream: &mut std::os::unix::net::UnixStream, body: &[u8]) -> String {
    use std::io::{Read, Write};
    // A service that refuses on length alone closes early; the verdict is still readable.
    let _ = stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .and_then(|()| stream.write_all(body));
    let mut reply = String::new();
    let _ = stream.read_to_string(&mut reply);
    reply
}

fn recv_message(socket: &std::path::Path) -> (Option<Vec<u8>>, u64, u64) {
    let got = mvm_hostd::mailbox_service::recv(socket).unwrap();
    let body = got.message.map(|m| hex::decode(m).unwrap());
    (body, got.accepted, got.read)
}

/// A host reader takes messages oldest first, with lifetime counts, and an
/// empty queue answers with none.
#[test]
fn a_host_reader_takes_the_queue_in_order_and_an_empty_queue_is_none() {
    let (node, channel) = channel_with_one_node();
    assert_eq!(recv_message(&channel.socket), (None, 0, 0));
    let verdicts = guest_sends(&node, &channel, &[b"first", b"second"]);
    assert!(verdicts.iter().all(Result::is_ok));
    assert_eq!(
        recv_message(&channel.socket),
        (Some(b"first".to_vec()), 2, 1)
    );
    assert_eq!(
        recv_message(&channel.socket),
        (Some(b"second".to_vec()), 2, 2)
    );
    assert_eq!(recv_message(&channel.socket), (None, 2, 2));
}

/// The read request is strict and bounded, and the guest's connection never
/// reaches it: a guest that sends one is refused and the queue is untouched.
#[test]
fn the_read_request_is_strict_bounded_and_not_reachable_by_the_guest() {
    use std::os::unix::fs::PermissionsExt as _;
    let (node, channel) = channel_with_one_node();
    let mode = std::fs::metadata(&channel.socket)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "the socket is owner-only");

    for bad in [
        &br#"{"request":"drain"}"#[..],
        br#"{"request":"recv","extra":1}"#,
        br#"{"request":"recv"} trailing"#,
        br#"{}"#,
    ] {
        let reply = host_frame(&channel.socket, bad);
        assert!(reply.contains("Malformed"), "{reply}");
    }
    let oversized = host_frame(&channel.socket, &vec![b'{'; LIMITS.max_frame_bytes + 1]);
    assert!(oversized.contains("Oversized"), "{oversized}");

    let verdicts = guest_sends(&node, &channel, &[b"kept", br#"{"request":"recv"}"#]);
    assert!(verdicts[0].is_ok() && verdicts[1].is_err());
    assert_eq!(
        recv_message(&channel.socket),
        (Some(b"kept".to_vec()), 1, 1)
    );
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

/// A mailbox process under `dir`, started for a granted mailbox, whose guest
/// has delivered its one message. Returns the process and the VM state dir.
fn served_mailbox_process(dir: &std::path::Path) -> (KillOnDrop, std::path::PathBuf) {
    use mvm_hostd::mailbox_process::build_config;
    use std::os::unix::net::UnixListener;

    let keys = dir.join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    host_keys(&keys, 5);
    let state_dir = dir.join("vm");
    std::fs::create_dir_all(&state_dir).unwrap();
    let authority = mvm_hostd::mailbox_launch::authority_key_for(
        &keys,
        &address().mailbox,
        MbEpoch::new(1).unwrap(),
    )
    .unwrap()
    .to_bytes();
    let grant = granted_plan(authority).mailbox.unwrap();
    let config = build_config(
        &keys,
        &grant,
        &state_dir,
        mvm_runtime::backend::AnyBackend::from_hypervisor("hvf")
            .host_dial_route(&state_dir, mvm_contract::protocol::mailbox::MAILBOX_PORT)
            .unwrap(),
    )
    .unwrap();
    let mvm_core::vm_backend::HostDialRoute::PortSocket(port_socket) = &config.route else {
        panic!("the HVF route is a per-port socket");
    };
    std::fs::create_dir_all(port_socket.parent().unwrap()).unwrap();
    let listener = UnixListener::bind(port_socket).unwrap();
    let wire = serde_json::to_vec(&config).unwrap();
    let seed = std::fs::read(keys.join("host-signer.ed25519")).unwrap();
    assert!(
        !String::from_utf8_lossy(&wire).contains(&hex::encode(&seed)),
        "the seed is not in the process config"
    );

    let outbox = dir.join("outbox");
    std::fs::create_dir(&outbox).unwrap();
    mvm_agentd::mailbox_outbox::write_outbox(&outbox, &outbox_message()).unwrap();
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
    (process, state_dir)
}

/// The separate mailbox process, handed only derived keys and the guest's
/// paths on stdin, dials the guest's mailbox port and binds the VM's mailbox
/// socket; the host signing seed is in its config nowhere.
#[test]
fn the_mailbox_process_serves_a_granted_mailbox_from_derived_keys_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (process, state_dir) = served_mailbox_process(dir.path());
    // The same process answers a host reader with what the guest sent.
    let socket = mvm_core::config::vm_mailbox_socket_at(&state_dir);
    let got = (0..100).find_map(|_| {
        let got = mvm_hostd::mailbox_service::recv(&socket).ok()?;
        got.message
            .is_none()
            .then(|| std::thread::sleep(std::time::Duration::from_millis(50)));
        got.message.map(|m| (m, got.accepted, got.read))
    });
    assert_eq!(
        got,
        Some((hex::encode("hello"), 1, 1)),
        "{}",
        process.stderr()
    );
    assert_eq!(
        mvm_hostd::mailbox_service::recv(&socket).unwrap().message,
        None
    );
}

/// Removing the VM's state directory, and with it the mailbox socket path,
/// ends a serving process: stopping its service must not need that path.
#[test]
fn the_mailbox_process_exits_when_its_vm_state_dir_is_removed() {
    let dir = tempfile::tempdir().unwrap();
    let (mut process, state_dir) = served_mailbox_process(dir.path());
    std::fs::remove_dir_all(&state_dir).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let status = loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the process outlived its VM; stderr:\n{}",
            process.stderr()
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    assert!(status.success(), "{status}");
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
