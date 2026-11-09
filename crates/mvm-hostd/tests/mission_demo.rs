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
//! sender as a typed reply.
//!
//! What is simulated, on purpose: no booted guest runs the mailbox
//! client or reads the queue (the guest end is a test driving the same
//! `send_frame` over a Firecracker-style mux), no cross-host
//! Iroh or relay transport (both ends share this process's host), and the VMs
//! (a launch is gated and audited, but nothing boots). Only the aircraft node
//! runs a service. Run with `--nocapture` to read the timeline.

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
        "\nsimulated: mailbox delivery is a local Unix socket between node services (no vsock guest service, no cross-host transport), VMs (gated and audited, none boot)"
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
    let sealer_for = || sealer(&channel, &ops);
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
    let refused = serve_granted_guest(
        plan.mailbox.as_ref(),
        trust,
        sealer_for(),
        LIMITS,
        &socket,
        (&per_port, &absent_mux),
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
        (&per_port, &absent_mux),
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

/// A granted plan through the launch helper serves the guest port from its
/// own thread and queues what the guest sent; a plan without a grant builds
/// and dials nothing.
#[test]
fn the_launch_helper_serves_a_granted_plan_and_builds_nothing_without_one() {
    use mvm_hostd::mailbox_launch::{MailboxPaths, authority_key_for, start_for_launch};
    use std::os::unix::net::UnixListener;

    let dir = tempfile::tempdir().unwrap();
    host_keys(dir.path(), 5);
    let paths = || MailboxPaths {
        keys_dir: dir.path().to_owned(),
        socket: dir.path().join("mailbox.sock"),
        guest_port: dir.path().join("port.sock"),
        firecracker_mux: dir.path().join("absent-mux"),
    };
    let listener = UnixListener::bind(dir.path().join("port.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();

    let mut plain = mvm_core::plan::test_support::PlanFixture::new().build();
    plain.mailbox = None;
    assert!(
        start_for_launch(plain.mailbox, paths(), LIMITS)
            .unwrap()
            .is_none()
    );
    assert!(!dir.path().join("mailbox.sock").exists());
    assert!(listener.accept().is_err(), "no grant, nothing dialed");

    let authority = authority_key_for(dir.path(), &address().mailbox).unwrap();
    let plan = granted_plan(authority.to_bytes());
    let outbox = dir.path().join("outbox");
    std::fs::write(&outbox, outbox_message().encode()).unwrap();
    listener.set_nonblocking(false).unwrap();
    let guest = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        mvm_agentd::mailbox_outbox::forward_outbox(&mut stream, &outbox)
    });
    let launch = start_for_launch(plan.mailbox, paths(), LIMITS)
        .unwrap()
        .unwrap();
    assert_eq!(guest.join().unwrap(), Ok(()));
    let received = (0..100).find_map(|_| {
        launch.receive().or_else(|| {
            std::thread::sleep(std::time::Duration::from_millis(50));
            None
        })
    });
    assert_eq!(received.unwrap(), b"hello");
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

    /// Wait for exit within 20s, or fail with the child's stderr.
    fn exit(&mut self) -> std::process::ExitStatus {
        for _ in 0..400 {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("the process never exited; stderr:\n{}", self.stderr());
    }
}
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_collector_only(home: &std::path::Path, config: serde_json::Value) -> KillOnDrop {
    use std::io::Write;
    let (log_file, log) = tempfile::NamedTempFile::new_in(home.parent().unwrap())
        .unwrap()
        .keep()
        .unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_mvm-network-endpoint"))
        .env("MVM_HOME", home)
        .env("HOME", home)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(log_file)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(config.to_string().as_bytes()).unwrap();
    KillOnDrop(child, log)
}

/// The per-VM process a launch spawns, handed only the signed grant and the
/// VM's state dir, serves that guest's mailbox from the host key directory
/// with telemetry off; given no mailbox and no telemetry it refuses to run.
#[test]
fn the_per_vm_process_serves_a_granted_mailbox_with_telemetry_off() {
    use std::os::unix::net::UnixListener;

    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let keys = mvm_core::config::mvm_keys_dir_at(&home);
    std::fs::create_dir_all(&keys).unwrap();
    host_keys(&keys, 5);
    let state_dir = dir.path().join("vm");
    std::fs::create_dir_all(&state_dir).unwrap();
    let port = mvm_core::config::vm_hvf_vsock_port_socket_at(
        &state_dir,
        mvm_contract::protocol::mailbox::MAILBOX_PORT,
    );
    std::fs::create_dir_all(port.parent().unwrap()).unwrap();
    let listener = UnixListener::bind(&port).unwrap();

    let authority = mvm_hostd::mailbox_launch::authority_key_for(&keys, &address().mailbox)
        .unwrap()
        .to_bytes();
    let grant = granted_plan(authority).mailbox.unwrap();
    let embed = mvm_hostd::mailbox_launch::MailboxEmbed {
        grant,
        state_dir: state_dir.clone(),
    };
    let outbox = dir.path().join("outbox");
    std::fs::write(&outbox, outbox_message().encode()).unwrap();
    let mut process = spawn_collector_only(
        &home,
        serde_json::json!({"telemetry_only": {
            "instance_id": "vm",
            "redaction": mvm_core::policy::RedactionPolicy::default(),
            "mailbox": embed,
        }}),
    );
    let mut stream = process.accept(&listener);
    assert_eq!(
        mvm_agentd::mailbox_outbox::forward_outbox(&mut stream, &outbox),
        Ok(())
    );
    let socket = mvm_core::config::vm_mailbox_socket_at(&state_dir);
    assert!(
        (0..100).any(|_| {
            std::thread::sleep(std::time::Duration::from_millis(50));
            socket.exists()
        }),
        "the host service bound its socket; stderr:\n{}",
        process.stderr()
    );

    let mut idle = spawn_collector_only(
        &home,
        serde_json::json!({"telemetry_only": {
            "instance_id": "vm",
            "redaction": mvm_core::policy::RedactionPolicy::default(),
        }}),
    );
    assert!(!idle.exit().success(), "nothing to serve");
}
