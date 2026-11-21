//! The final retention pass a helper runs once its workload is quarantined.

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::Ordering;

use ed25519_dalek::SigningKey;
use mvm_contract::protocol::mailbox::{
    AuthorizationDomainId, AuthorizationDomainRouteLabel, BootId, CapabilityId,
    CapabilityOperations, CausationId, CiphertextPadding, ContentType, CorrelationId, DeliveryId,
    DestinationRouteToken, EncryptionAlgorithm, EncryptionContext, ExecutionEpoch, MailboxAddress,
    MailboxCapabilityGrant, MailboxEnvelopeHeader, MailboxId, MailboxMessageKind, MailboxOperation,
    MailboxRoutingFrame, MessageId, OrderingScope, PrincipalId, ProtocolVersion, ReplayNonce,
    ReplyRoute, RevocationId, SequenceNumber, SignatureAlgorithm, TenantId, TransportBindingId,
};
use mvm_core::crypto::aead::Key;
use mvm_core::host_interface::workload::{CanonicalLedger, WorkloadChange, read_ledger_bytes_at};
use mvm_core::mailbox::frame::send_local_receipted_frame;
use mvm_core::mailbox::journal::{
    FileJournalAnchor, HistoryKeyCustody, HistoryKeyRef, JournalLimits, MailboxJournal,
};
use mvm_core::mailbox::{OpenContext, SealRequest, seal_envelope, sign_capability};

use std::sync::Arc;

use super::*;
use crate::mailbox_service::{MailboxLimits, MailboxPolicy};
use crate::policy_generation::coordinator;

const DESTINATION: &str = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";
const EXPIRY_AFTER_MS: i64 = 1_500;

struct Custody(HistoryKeyRef);

impl HistoryKeyCustody for Custody {
    fn load_existing(&self, reference: &HistoryKeyRef) -> std::result::Result<Key, JournalError> {
        if reference != &self.0 {
            return Err(JournalError::HistoryKeyMismatch);
        }
        Ok(Key::from_bytes([90; 32]))
    }
}

fn address() -> MailboxAddress {
    MailboxAddress {
        tenant: TenantId::from_bytes([19; 32]),
        authorization_domain: AuthorizationDomainId::from_bytes([1; 32]),
        mailbox: MailboxId::from_bytes([4; 32]),
        recipient: PrincipalId::from_bytes([3; 32]),
    }
}

fn content_type() -> ContentType {
    ContentType::parse("application/vnd.mvm.prompt", 1).unwrap()
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

fn header(expires: i64) -> MailboxEnvelopeHeader {
    MailboxEnvelopeHeader {
        protocol_version: ProtocolVersion::V1,
        signature_algorithm: SignatureAlgorithm::ED25519,
        tenant: address().tenant,
        authorization_domain: address().authorization_domain,
        sender: PrincipalId::from_bytes([2; 32]),
        recipient: address().recipient,
        mailbox: address().mailbox,
        sender_boot: BootId::from_bytes([5; 32]),
        execution_epoch: ExecutionEpoch::new(1).unwrap(),
        message_id: MessageId::from_bytes([1; 32]),
        correlation_id: CorrelationId::from_bytes([7; 32]),
        causation_id: CausationId::from_bytes([8; 32]),
        kind: MailboxMessageKind::Call,
        reply_to: Some(ReplyRoute {
            address: address(),
            capability_id: CapabilityId::from_bytes([14; 32]),
        }),
        ordering_scope: OrderingScope::parse("interactive").unwrap(),
        sequence: SequenceNumber::new(1).unwrap(),
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: expires,
        nonce: ReplayNonce::from_bytes([1; 16]),
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

fn routing(expires: i64) -> MailboxRoutingFrame {
    MailboxRoutingFrame {
        protocol_version: ProtocolVersion::V1,
        authorization_domain_route_label: AuthorizationDomainRouteLabel::from_bytes([15; 32]),
        destination_route_token: DestinationRouteToken::from_bytes([16; 32]),
        delivery_id: DeliveryId::from_bytes([17; 32]),
        ciphertext_len: 0,
        padding: CiphertextPadding::Exact,
        expires_at_unix_ms: expires,
        hop_limit: 8,
        transport_binding_id: TransportBindingId::from_bytes([18; 32]),
    }
}

fn send_grant(expires: i64) -> MailboxCapabilityGrant {
    MailboxCapabilityGrant {
        protocol_version: ProtocolVersion::V1,
        signature_algorithm: SignatureAlgorithm::ED25519,
        capability_id: CapabilityId::from_bytes([10; 32]),
        issuer: PrincipalId::from_bytes([12; 32]),
        subject: PrincipalId::from_bytes([2; 32]),
        address: address(),
        operations: CapabilityOperations::from_operations(&[MailboxOperation::Send]),
        message_kinds: vec![MailboxMessageKind::Call, MailboxMessageKind::Reply],
        content_types: vec![content_type()],
        max_payload_bytes: 1024,
        max_messages_per_minute: 60,
        max_outstanding_calls: 8,
        max_queue_contribution_bytes: 4096,
        minimum_execution_epoch: ExecutionEpoch::new(1).unwrap(),
        maximum_execution_epoch: ExecutionEpoch::new(9).unwrap(),
        policy_epoch: 4,
        not_before_unix_ms: 900,
        expires_at_unix_ms: expires,
        revocation_id: RevocationId::from_bytes([13; 32]),
        delegation_depth: 0,
    }
}

fn open_context() -> OpenContext {
    OpenContext {
        expected_tenant: address().tenant,
        expected_authorization_domain: address().authorization_domain,
        expected_mailbox: address().mailbox,
        expected_sender: PrincipalId::from_bytes([2; 32]),
        expected_recipient: address().recipient,
        acting_principal: PrincipalId::from_bytes([2; 32]),
        expected_capability_issuer: PrincipalId::from_bytes([12; 32]),
        current_execution_epoch: ExecutionEpoch::new(1).unwrap(),
        current_policy_epoch: 4,
        required_operation: MailboxOperation::Send,
        now_unix_ms: 1_500,
        accepted_content_types: vec![content_type()],
        revoked_capabilities: vec![],
    }
}

/// A coordinated local service holding one accepted message that is already
/// past its expiry.
struct Held {
    _env: mvm_core::util::test_env::TestEnv,
    home: tempfile::TempDir,
    coordinator: PathBuf,
    service: DurableMailboxService,
    retention: Arc<AtomicBool>,
    refused: Arc<AtomicBool>,
    socket: PathBuf,
    signer: SigningKey,
    sender: SigningKey,
}

fn held_message() -> Held {
    held_message_gated(false)
}

/// [`held_message`], with the service gated on workload `w` when `gated`.
fn held_message_gated(gated: bool) -> Held {
    let home = tempfile::tempdir_in("/tmp").unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    let coordinator = coordinator::serve_in_process(home.path()).unwrap();
    let (signer, sender) = (
        SigningKey::from_bytes(&[22; 32]),
        SigningKey::from_bytes(&[21; 32]),
    );
    let reference =
        HistoryKeyRef::new(address(), ExecutionEpoch::new(1).unwrap(), [30; 32], 1).unwrap();
    let Coordinated {
        anchor,
        refused,
        retention,
        ..
    } = coordinate(
        FileJournalAnchor::open(&home.path().join("anchor"), address(), [91; 32]).unwrap(),
        std::sync::Arc::new(CoordinatorSocket(coordinator.clone())),
        Destination {
            id: DESTINATION.into(),
            workload: "w".into(),
            epoch: ExecutionEpoch::new(1).unwrap(),
            key: SigningKey::from_bytes(&[9; 32]),
        },
    )
    .unwrap();
    let journal = MailboxJournal::open_local_with_custody(
        &home.path().join("journal"),
        reference,
        signer.verifying_key(),
        JournalLimits {
            max_records: 16,
            max_bytes: 64 * 1024,
        },
        &Custody(reference),
        &anchor,
        mvm_contract::protocol::mailbox::MailboxRetentionPolicy::new(10_000).unwrap(),
    )
    .unwrap();
    let socket = home.path().join("m.sock");
    let service = DurableMailboxService::bind_local(
        &socket,
        MailboxLimits {
            max_depth: 4,
            max_frame_bytes: 64 * 1024,
        },
        MailboxPolicy {
            context: open_context(),
            encryption_key: Key::from_bytes([23; 32]),
            sender_key: sender.verifying_key(),
            authority_key: signer.verifying_key(),
            unit_gate: gated.then(|| UnitGate::bind(home.path(), "w").unwrap()),
        },
        signer.clone(),
        journal,
        anchor,
    )
    .unwrap();
    let held = Held {
        _env: env,
        home,
        coordinator,
        service,
        retention,
        refused,
        socket,
        signer,
        sender,
    };
    send_numbered(&held, 1, now_ms() + EXPIRY_AFTER_MS).expect("accepted before it expires");
    std::thread::sleep(Duration::from_millis(EXPIRY_AFTER_MS as u64 + 200));
    held
}

/// Send message `n` to the held service, expiring at `expires`.
fn send_numbered(
    held: &Held,
    n: u8,
    expires: i64,
) -> std::result::Result<(), mvm_core::mailbox::frame::Refusal> {
    let header = MailboxEnvelopeHeader {
        message_id: MessageId::from_bytes([n; 32]),
        nonce: ReplayNonce::from_bytes([n; 16]),
        sequence: SequenceNumber::new(u64::from(n)).unwrap(),
        ..header(expires)
    };
    let envelope = seal_envelope(
        SealRequest {
            routing: routing(expires),
            header: header.clone(),
            plaintext: b"hello",
        },
        &Key::from_bytes([23; 32]),
        &held.sender,
    )
    .unwrap();
    let capability = sign_capability(send_grant(expires), &held.signer).unwrap();
    let mut stream = UnixStream::connect(&held.socket).unwrap();
    send_local_receipted_frame(
        &mut stream,
        &capability,
        &envelope,
        &header,
        &held.signer.verifying_key(),
    )
    .map(drop)
}

fn cursor(home: &Path) -> u64 {
    let bytes = read_ledger_bytes_at(home).unwrap().unwrap();
    serde_json::from_slice::<CanonicalLedger>(&bytes)
        .unwrap()
        .destinations[DESTINATION]
        .tip
        .cursor
}

fn quarantine(held: &Held) {
    coordinator::commit_workload(
        &held.coordinator,
        &WorkloadChange::Quarantine {
            workload: "w".into(),
        },
    )
    .unwrap();
}

#[test]
fn the_pass_expires_what_the_quarantine_would_otherwise_leave_and_exits_denied() {
    let held = held_message();
    let before = cursor(held.home.path());
    quarantine(&held);
    let exit = run_retention_pass(&held.service, &held.retention);
    assert_eq!(exit.kind(), ErrorKind::PermissionDenied);
    assert!(!held.refused.load(Ordering::SeqCst));
    assert!(
        cursor(held.home.path()) > before,
        "the expiry commit reached the ledger"
    );
    held.service
        .maintain_local()
        .expect("nothing is left to expire");
}

#[test]
fn without_the_mark_the_same_maintenance_is_refused_after_a_quarantine() {
    let held = held_message();
    let before = cursor(held.home.path());
    quarantine(&held);
    assert!(held.service.maintain_local().is_err());
    assert!(held.refused.load(Ordering::SeqCst));
    assert_eq!(cursor(held.home.path()), before);
}

#[test]
fn only_a_quarantine_denial_triggers_the_pass() {
    let held = held_message();
    let epoch = ExecutionEpoch::new(1).unwrap();
    assert!(!workload_is_quarantined(held.home.path(), "w", epoch));
    assert!(!workload_is_quarantined(
        &held.home.path().join("missing"),
        "w",
        epoch
    ));
    quarantine(&held);
    assert!(workload_is_quarantined(held.home.path(), "w", epoch));
    assert!(!workload_is_quarantined(held.home.path(), "other", epoch));
}

#[test]
fn a_gated_destination_refuses_a_new_message_once_its_workload_is_quarantined() {
    let held = held_message_gated(true);
    quarantine(&held);
    assert_eq!(
        send_numbered(&held, 2, now_ms() + 60_000),
        Err(mvm_core::mailbox::frame::Refusal::Mailbox(
            mvm_core::host_interface::Denial::WorkloadQuarantined("w".into()).to_string()
        ))
    );
    assert!(
        !held.refused.load(Ordering::SeqCst),
        "refused by the gate before any commit reached the coordinator"
    );
}

#[test]
fn a_gated_destination_refuses_its_old_epoch_once_its_workload_is_replaced() {
    let held = held_message_gated(true);
    assert_eq!(send_numbered(&held, 2, now_ms() + 60_000), Ok(()));
    coordinator::commit_workload(
        &held.coordinator,
        &WorkloadChange::Replace {
            workload: "w".into(),
            from_epoch: ExecutionEpoch::new(1).unwrap(),
        },
    )
    .unwrap();
    assert_eq!(
        send_numbered(&held, 3, now_ms() + 60_000),
        Err(mvm_core::mailbox::frame::Refusal::Mailbox(
            mvm_core::host_interface::Denial::StaleEpoch { got: 1, current: 2 }.to_string()
        ))
    );
}
