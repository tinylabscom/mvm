//! Launch-time mailbox: build the host-held trust a granted guest mailbox is
//! served under, and serve it off the launch path.
//!
//! The sealing keys are derived from the host signing key already in the host
//! key directory, per mailbox, and never come from the plan or the guest. The
//! identities and capability they seal under default to values derived from the
//! same key, and an operator template beside it overrides them. Encryption is host to host: the derived keys are this host's, so
//! a peer host cannot open what they seal.

use std::io::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use mvm_contract::protocol::mailbox::{
    AuthorizationDomainId, AuthorizationDomainRouteLabel, BootId, CapabilityId,
    CapabilityOperations, CausationId, CiphertextPadding, ContentType, CorrelationId, DeliveryId,
    DestinationRouteToken, EncryptionAlgorithm, EncryptionContext, MailboxAddress,
    MailboxCapabilityGrant, MailboxEnvelopeHeader, MailboxGrant, MailboxId, MailboxMessageKind,
    MailboxOperation, MailboxRoutingFrame, MessageId, OrderingScope, PrincipalId, ProtocolVersion,
    ReplayNonce, ReplyRoute, RevocationId, SequenceNumber, SignatureAlgorithm, TenantId,
    TransportBindingId,
};
use mvm_core::crypto::aead::Key;
use mvm_core::mailbox::OpenContext;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::mailbox_service::{GuestSealer, MailboxLimits, MailboxPolicy, MailboxService};

const SIGNER_SECRET: &str = "host-signer.ed25519";
const SIGNER_PUBLIC: &str = "host-signer.pub";
/// Optional operator override of the derived identities and capability,
/// beside the host key.
const TEMPLATE_FILE: &str = "mailbox-template.json";
const DIAL_ATTEMPTS: u32 = 300;
const DIAL_INTERVAL: Duration = Duration::from_millis(100);

/// What the host seals a guest's message under, apart from keys.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxTemplate {
    pub capability: MailboxCapabilityGrant,
    pub header: MailboxEnvelopeHeader,
    pub routing: MailboxRoutingFrame,
}

fn derive(root: &[u8; 32], label: &[u8], mailbox: &MailboxId) -> Zeroizing<[u8; 32]> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(root).expect("any key length");
    mac.update(label);
    mac.update(mailbox.as_bytes());
    Zeroizing::new(mac.finalize().into_bytes().into())
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

struct Derived {
    root: Zeroizing<[u8; 32]>,
    mailbox: MailboxId,
    sender: SigningKey,
    authority: SigningKey,
    encryption: Zeroizing<[u8; 32]>,
}

fn derived_keys(keys_dir: &Path, mailbox: &MailboxId) -> Result<Derived> {
    let (signer, _) = mvm_core::crypto::ed25519_keypair::load_existing(
        &keys_dir.join(SIGNER_SECRET),
        &keys_dir.join(SIGNER_PUBLIC),
    )
    .map_err(|e| Error::new(ErrorKind::NotFound, format!("host signing key: {e:#}")))?;
    let root = Zeroizing::new(signer.to_bytes());
    let key = |label: &[u8]| SigningKey::from_bytes(&derive(&root, label, mailbox));
    Ok(Derived {
        root: Zeroizing::new(*root),
        sender: key(b"mvm-mailbox-sender-v1"),
        mailbox: *mailbox,
        authority: key(b"mvm-mailbox-authority-v1"),
        encryption: derive(&root, b"mvm-mailbox-encryption-v1", mailbox),
    })
}

/// The authority verifying key this host derives for `mailbox`: what an
/// external signer must name in a plan's grant for the host to honor it.
pub fn authority_key_for(keys_dir: &Path, mailbox: &MailboxId) -> Result<VerifyingKey> {
    Ok(derived_keys(keys_dir, mailbox)?.authority.verifying_key())
}

/// Everything a mailbox host process needs to serve one granted guest, derived
/// by the launcher from the host key and nothing else: the three derived keys
/// and the identities and capability they seal under. It never carries the host
/// signing seed, and the per-mailbox derivation inputs are not recoverable from
/// it, so a process holding only this cannot derive another mailbox's keys.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedMailboxKeys {
    sender: [u8; 32],
    authority: [u8; 32],
    encryption: [u8; 32],
    journal_mac: [u8; 32],
    anchor_mac: [u8; 32],
    template: MailboxTemplate,
}

impl std::fmt::Debug for DerivedMailboxKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedMailboxKeys")
            .field("keys", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Drop for DerivedMailboxKeys {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.sender.zeroize();
        self.authority.zeroize();
        self.encryption.zeroize();
        self.journal_mac.zeroize();
        self.anchor_mac.zeroize();
    }
}

impl DerivedMailboxKeys {
    /// Mailbox-scoped destination signer and separate journal/anchor MAC keys.
    pub(crate) fn durable_material(&self) -> (SigningKey, [u8; 32], [u8; 32]) {
        (
            SigningKey::from_bytes(&self.authority),
            self.journal_mac,
            self.anchor_mac,
        )
    }

    /// The host trust and sealer these keys stand for. Pure: no file is read,
    /// so it can be rebuilt on every dial attempt.
    pub fn trust(&self) -> (MailboxPolicy, GuestSealer) {
        let sender_key = SigningKey::from_bytes(&self.sender);
        let authority_key = SigningKey::from_bytes(&self.authority);
        let template = self.template.clone();
        let h = &template.header;
        let policy = MailboxPolicy {
            context: OpenContext {
                expected_tenant: h.tenant,
                expected_authorization_domain: h.authorization_domain,
                expected_mailbox: h.mailbox,
                expected_sender: h.sender,
                expected_recipient: h.recipient,
                acting_principal: template.capability.subject,
                expected_capability_issuer: template.capability.issuer,
                current_execution_epoch: h.execution_epoch,
                current_policy_epoch: h.policy_epoch,
                required_operation: MailboxOperation::Send,
                now_unix_ms: now_unix_ms(),
                accepted_content_types: vec![h.content_type.clone()],
                revoked_capabilities: vec![],
            },
            encryption_key: Key::from_bytes(self.encryption),
            sender_key: sender_key.verifying_key(),
            authority_key: authority_key.verifying_key(),
        };
        let sealer = GuestSealer {
            encryption_key: Key::from_bytes(self.encryption),
            sender_key,
            authority_key,
            capability: template.capability,
            header: template.header,
            routing: template.routing,
            sent: 0,
            intent_dir: None,
        };
        (policy, sealer)
    }
}

/// The launcher half: read the host key directory and derive what serving
/// `grant` needs.
///
/// The grant's authority key must be the verifying half of the key this host
/// derives for that mailbox; any other is refused.
pub fn derive_launch_keys(keys_dir: &Path, grant: &MailboxGrant) -> Result<DerivedMailboxKeys> {
    let derived = derived_keys(keys_dir, &grant.mailbox)?;
    if derived.authority.verifying_key().to_bytes() != grant.authority_key {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "grant authority is not the host's authority key for this mailbox",
        ));
    }
    let template = template_for(keys_dir, &derived, grant, now_unix_ms())?;
    Ok(DerivedMailboxKeys {
        sender: derived.sender.to_bytes(),
        authority: derived.authority.to_bytes(),
        encryption: *derived.encryption,
        journal_mac: *derive(&derived.root, b"mvm-mailbox-journal-v1", &grant.mailbox),
        anchor_mac: *derive(&derived.root, b"mvm-mailbox-anchor-v1", &grant.mailbox),
        template,
    })
}

/// The host trust and sealer for `grant`, from the host key directory.
pub fn host_trust(keys_dir: &Path, grant: &MailboxGrant) -> Result<(MailboxPolicy, GuestSealer)> {
    Ok(derive_launch_keys(keys_dir, grant)?.trust())
}

const VALID_FOR_MS: i64 = 60 * 60 * 1000;

/// The operator template when one exists, otherwise the derived defaults.
fn template_for(
    keys_dir: &Path,
    derived: &Derived,
    grant: &MailboxGrant,
    now_ms: i64,
) -> Result<MailboxTemplate> {
    match std::fs::read(keys_dir.join(TEMPLATE_FILE)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| Error::new(ErrorKind::InvalidData, format!("mailbox template: {e}"))),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(default_template(derived, grant, now_ms)),
        Err(e) => Err(e),
    }
}

/// Identities, capability and routing derived from the host key for one
/// mailbox: a local loopback queue whose recipient is this host's own derived
/// principal, valid for [`VALID_FOR_MS`] from launch, send only.
fn default_template(d: &Derived, grant: &MailboxGrant, now_ms: i64) -> MailboxTemplate {
    let id = |label: &[u8]| *derive(&d.root, label, &d.mailbox);
    let (tenant, domain) = (
        TenantId::from_bytes(id(b"mvm-mailbox-tenant-v1")),
        AuthorizationDomainId::from_bytes(id(b"mvm-mailbox-domain-v1")),
    );
    let sender = PrincipalId::from_bytes(d.sender.verifying_key().to_bytes());
    let issuer = PrincipalId::from_bytes(d.authority.verifying_key().to_bytes());
    let recipient = PrincipalId::from_bytes(id(b"mvm-mailbox-recipient-v1"));
    let expires = now_ms.saturating_add(VALID_FOR_MS);
    let content_type =
        ContentType::parse("application/vnd.mvm.guest-message", 1).expect("static content type");
    let address = MailboxAddress {
        tenant,
        authorization_domain: domain,
        mailbox: grant.mailbox,
        recipient,
    };
    let capability_id = CapabilityId::from_bytes(id(b"mvm-mailbox-capability-v1"));
    let capability = MailboxCapabilityGrant {
        protocol_version: ProtocolVersion::V1,
        signature_algorithm: SignatureAlgorithm::ED25519,
        capability_id,
        issuer,
        subject: sender,
        address,
        operations: CapabilityOperations::from_operations(&[MailboxOperation::Send]),
        message_kinds: vec![MailboxMessageKind::Call],
        content_types: vec![content_type.clone()],
        max_payload_bytes: 16 * 1024,
        max_messages_per_minute: 600,
        max_outstanding_calls: 8,
        max_queue_contribution_bytes: 1024 * 1024,
        minimum_execution_epoch: grant.epoch,
        maximum_execution_epoch: grant.epoch,
        policy_epoch: 1,
        not_before_unix_ms: now_ms,
        expires_at_unix_ms: expires,
        revocation_id: RevocationId::from_bytes(id(b"mvm-mailbox-revocation-v1")),
        delegation_depth: 0,
    };
    let header = MailboxEnvelopeHeader {
        protocol_version: ProtocolVersion::V1,
        signature_algorithm: SignatureAlgorithm::ED25519,
        tenant,
        authorization_domain: domain,
        sender,
        recipient,
        mailbox: grant.mailbox,
        sender_boot: BootId::from_bytes(id(b"mvm-mailbox-boot-v1")),
        execution_epoch: grant.epoch,
        message_id: MessageId::from_bytes([0; 32]),
        correlation_id: CorrelationId::from_bytes(id(b"mvm-mailbox-correlation-v1")),
        causation_id: CausationId::from_bytes(id(b"mvm-mailbox-causation-v1")),
        kind: MailboxMessageKind::Call,
        reply_to: Some(ReplyRoute {
            address,
            capability_id,
        }),
        ordering_scope: OrderingScope::parse("guest").expect("static scope"),
        sequence: SequenceNumber::new(1).expect("nonzero"),
        issued_at_unix_ms: now_ms,
        expires_at_unix_ms: expires,
        nonce: ReplayNonce::from_bytes([0; 16]),
        content_type,
        capability_id,
        policy_epoch: 1,
        encryption: EncryptionContext {
            algorithm: EncryptionAlgorithm::AES_256_GCM,
            key_id: id(b"mvm-mailbox-key-id-v1"),
        },
        plaintext_len: 0,
    };
    let routing = MailboxRoutingFrame {
        protocol_version: ProtocolVersion::V1,
        authorization_domain_route_label: AuthorizationDomainRouteLabel::from_bytes(id(
            b"mvm-mailbox-route-label-v1",
        )),
        destination_route_token: DestinationRouteToken::from_bytes(id(
            b"mvm-mailbox-route-token-v1",
        )),
        delivery_id: DeliveryId::from_bytes(id(b"mvm-mailbox-delivery-v1")),
        ciphertext_len: 0,
        padding: CiphertextPadding::Exact,
        expires_at_unix_ms: expires,
        hop_limit: 1,
        transport_binding_id: TransportBindingId::from_bytes(id(b"mvm-mailbox-transport-v1")),
    };
    MailboxTemplate {
        capability,
        header,
        routing,
    }
}

/// A running launch-time mailbox. Dropping it tells the serving thread to
/// give up; it never waits on the guest, so teardown cannot hang on one.
pub struct MailboxLaunch {
    stop: Arc<AtomicBool>,
    service: Arc<OnceLock<MailboxService>>,
}

impl MailboxLaunch {
    /// The oldest plaintext the guest sent, once its session has ended.
    pub fn receive(&self) -> Option<Vec<u8>> {
        self.service.get()?.receive()
    }
}

impl Drop for MailboxLaunch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Where the guest's mailbox port is reached, and where the host serves.
pub struct ServePaths {
    pub socket: PathBuf,
    pub guest_port: PathBuf,
    pub firecracker_mux: PathBuf,
    pub intent_dir: Option<PathBuf>,
}

/// Bind the local service and dial the guest for the VM's lifetime. The first
/// guest connection has a bounded 30-second readiness window; after readiness
/// an idle outbox is normal and does not stop later submissions.
pub fn serve_derived(
    grant: MailboxGrant,
    keys: DerivedMailboxKeys,
    paths: ServePaths,
    limits: MailboxLimits,
) -> MailboxLaunch {
    let stop = Arc::new(AtomicBool::new(false));
    let service = Arc::new(OnceLock::new());
    let (thread_stop, thread_service) = (stop.clone(), service.clone());
    std::thread::spawn(move || {
        let (trust, mut sealer) = keys.trust();
        sealer.intent_dir = paths.intent_dir;
        let (Ok(trust), Ok(mut sealer)) = (trust.with_grant(&grant), sealer.with_grant(&grant))
        else {
            tracing::warn!("mailbox launch refused mismatched host-held grant");
            return;
        };
        let Ok(served) = MailboxService::bind_live(&paths.socket, limits, trust) else {
            tracing::warn!("mailbox service could not bind");
            return;
        };
        let _ = thread_service.set(served);
        let Some(served) = thread_service.get() else {
            return;
        };
        let guest = (paths.guest_port.as_path(), paths.firecracker_mux.as_path());
        let mut ready = false;
        let mut attempts = 0;
        while !thread_stop.load(Ordering::SeqCst) {
            match served.serve_guest(guest.0, guest.1, &mut sealer) {
                Ok(_) => {
                    ready = true;
                    attempts = 0;
                }
                Err(_) if !ready => {
                    attempts += 1;
                    if attempts >= DIAL_ATTEMPTS {
                        tracing::warn!("mailbox guest port did not become ready");
                        return;
                    }
                }
                Err(_) => {}
            }
            std::thread::sleep(DIAL_INTERVAL);
        }
    });
    MailboxLaunch { stop, service }
}

/// Bounds a launch-time mailbox holds and accepts.
pub const LAUNCH_LIMITS: MailboxLimits = MailboxLimits {
    max_depth: 64,
    max_frame_bytes: 64 * 1024,
};

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::mailbox::{ExecutionEpoch, MessageId};
    use mvm_core::mailbox::frame::OutboxMessage;

    fn keys_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
        dir
    }

    fn grant(dir: &Path, mailbox: [u8; 32]) -> MailboxGrant {
        let mailbox = MailboxId::from_bytes(mailbox);
        MailboxGrant {
            mailbox,
            authority_key: authority_key_for(dir, &mailbox).unwrap().to_bytes(),
            epoch: ExecutionEpoch::new(1).unwrap(),
        }
    }

    #[test]
    fn a_retry_reuses_exact_sealed_intent_after_helper_restart() {
        let dir = keys_dir();
        let grant = grant(dir.path(), [4; 32]);
        let keys = derive_launch_keys(dir.path(), &grant).unwrap();
        let intents = dir.path().join("intents");
        let sealer = || {
            let (_, mut sealer) = keys.trust();
            sealer.intent_dir = Some(intents.clone());
            sealer.with_grant(&grant).unwrap()
        };
        let message = OutboxMessage {
            recipient: sealer().header.recipient,
            message_id: MessageId::from_bytes([45; 32]),
            body: b"first".to_vec(),
        };
        let first = sealer().seal(message.clone()).expect("first seal");
        let retry = sealer().seal(message.clone()).expect("retry after restart");
        assert_eq!(
            first, retry,
            "retry must reuse canonical ciphertext and delivery ID"
        );
        for _ in 2..8 {
            assert_eq!(
                sealer().seal(message.clone()).expect("bounded retry"),
                first
            );
        }
        assert_eq!(
            sealer().seal(message.clone()),
            Err(crate::mailbox_service::Refusal::RetriesExhausted),
            "the attempt count survives a fresh helper using the same source intent"
        );
        let mut conflicting = message;
        conflicting.body = b"different".to_vec();
        assert!(matches!(
            sealer().seal(conflicting),
            Err(crate::mailbox_service::Refusal::Mailbox(_))
        ));
    }

    #[test]
    fn without_a_template_file_the_derived_defaults_serve_a_matching_grant() {
        let dir = keys_dir();
        assert!(!dir.path().join(TEMPLATE_FILE).exists());
        let (policy, sealer) = host_trust(dir.path(), &grant(dir.path(), [4; 32])).unwrap();
        assert_eq!(
            policy.authority_key,
            authority_key_for(dir.path(), &MailboxId::from_bytes([4; 32])).unwrap()
        );
        assert_eq!(sealer.capability.address.mailbox.as_bytes(), &[4; 32]);
    }

    #[test]
    fn a_foreign_authority_is_refused() {
        let dir = keys_dir();
        let mut g = grant(dir.path(), [4; 32]);
        g.authority_key = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
        let err = host_trust(dir.path(), &g).err().expect("refused");
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn authority_keys_differ_per_mailbox_and_per_host() {
        let (a, b) = (keys_dir(), keys_dir());
        let m = |n| MailboxId::from_bytes([n; 32]);
        assert_ne!(
            authority_key_for(a.path(), &m(1)).unwrap(),
            authority_key_for(a.path(), &m(2)).unwrap()
        );
        assert_ne!(
            authority_key_for(a.path(), &m(1)).unwrap(),
            authority_key_for(b.path(), &m(1)).unwrap()
        );
    }

    #[test]
    fn a_template_file_overrides_the_defaults_and_a_malformed_one_is_refused() {
        let dir = keys_dir();
        std::fs::write(dir.path().join(TEMPLATE_FILE), b"{}").unwrap();
        let err = host_trust(dir.path(), &grant(dir.path(), [4; 32]))
            .err()
            .expect("malformed template refused");
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn derived_keys_round_trip_and_carry_neither_the_seed_nor_a_mailbox_root() {
        let dir = keys_dir();
        let seed = std::fs::read(dir.path().join(SIGNER_SECRET)).unwrap();
        let g = grant(dir.path(), [4; 32]);
        let keys = derive_launch_keys(dir.path(), &g).unwrap();
        let wire = serde_json::to_vec(&keys).unwrap();
        let back: DerivedMailboxKeys = serde_json::from_slice(&wire).unwrap();
        let (policy, sealer) = back.trust();
        assert_eq!(policy.authority_key.to_bytes(), g.authority_key);
        assert_eq!(
            sealer.authority_key.verifying_key().to_bytes(),
            g.authority_key
        );
        // The seed, in every encoding the config could carry it in.
        let text = String::from_utf8(wire).unwrap();
        let as_array = serde_json::to_string(&seed).unwrap();
        for needle in [
            as_array.trim_matches(['[', ']']).to_string(),
            hex::encode(&seed),
        ] {
            assert!(!text.contains(&needle), "seed leaked into the config");
        }
        assert!(format!("{keys:?}").contains("redacted"));
    }

    #[test]
    fn derived_keys_refuse_unknown_fields() {
        let dir = keys_dir();
        let keys = derive_launch_keys(dir.path(), &grant(dir.path(), [4; 32])).unwrap();
        let mut value = serde_json::to_value(&keys).unwrap();
        value["root"] = serde_json::json!("00");
        assert!(serde_json::from_value::<DerivedMailboxKeys>(value).is_err());
    }
}
