//! Launch-time mailbox: build the host-held trust a granted guest mailbox is
//! served under, and serve it off the launch path.
//!
//! The sealing keys are derived from the host signing key already in the host
//! key directory, per mailbox, and never come from the plan or the guest. The
//! identities and capability they seal under default to values derived from the
//! same key, and an operator template beside it overrides them. Encryption is host to host: the derived keys are this host's, so
//! a peer host cannot open what they seal.
//!
//! The encryption key does not come from the signing seed at all: it derives
//! from a separate random root in the same directory, created on first use, so
//! the signing seed alone cannot open ciphertext and the encryption root alone
//! cannot forge a signature. It also mixes in a random per-epoch secret held only in the
//! VM's state directory and shredded when the VM stops or is replaced. Without
//! it the host signing seed alone cannot re-derive the key, so a frame sealed
//! under a terminated epoch stays sealed. The signing keys and identities do
//! not take it: the authority key is named in a signed plan before any VM
//! exists. The shred overwrites and unlinks the file; it is not a physical
//! wipe, and a filesystem may keep the old blocks.

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
    DestinationRouteToken, EncryptionAlgorithm, EncryptionContext, ExecutionEpoch, MailboxAddress,
    MailboxCapabilityGrant, MailboxEnvelopeHeader, MailboxGrant, MailboxId, MailboxMessageKind,
    MailboxOperation, MailboxRoutingFrame, MessageId, OrderingScope, PrincipalId, ProtocolVersion,
    ReplayNonce, ReplyRoute, RevocationId, SequenceNumber, SignatureAlgorithm, TenantId,
    TransportBindingId,
};
use mvm_core::crypto::aead::Key;
use mvm_core::mailbox::OpenContext;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::mailbox_service::{
    GuestSealer, MailboxLimits, MailboxPolicy, MailboxService, bind_grant,
};

const SIGNER_SECRET: &str = "host-signer.ed25519";
const SIGNER_PUBLIC: &str = "host-signer.pub";
/// The host-held random root the encryption key derives from, beside the
/// signing seed and never derived from it, so neither alone opens ciphertext.
const ENCRYPTION_ROOT: &str = "mailbox-encryption.root";
/// Optional operator override of the derived identities and capability,
/// beside the host key.
const TEMPLATE_FILE: &str = "mailbox-template.json";
/// Dials at the fast cadence while the guest is coming up or just sent a frame
/// (about 30 s), then at the slow one for as long as the VM lives, so a workload that writes its
/// outbox late is still forwarded without an idle VM being polled hard.
const FAST_DIAL_ATTEMPTS: u32 = 300;
const FAST_DIAL_INTERVAL: Duration = Duration::from_millis(100);
const SLOW_DIAL_INTERVAL: Duration = Duration::from_secs(2);
/// Pause after a served frame, so a burst is picked up without spinning.
const POST_FRAME_PAUSE: Duration = Duration::from_millis(10);

/// How long to wait after the `attempt`th failed dial (0-based).
fn dial_delay(attempt: u32, fast_attempts: u32) -> Duration {
    if attempt < fast_attempts {
        FAST_DIAL_INTERVAL
    } else {
        SLOW_DIAL_INTERVAL
    }
}

/// Sleep `delay` in short slices so a stop is noticed promptly.
fn sleep_unless_stopped(stop: &AtomicBool, delay: Duration) {
    let deadline = std::time::Instant::now() + delay;
    while !stop.load(Ordering::SeqCst) {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return;
        }
        std::thread::sleep(left.min(FAST_DIAL_INTERVAL));
    }
}

/// What the host seals a guest's message under, apart from keys.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxTemplate {
    pub capability: MailboxCapabilityGrant,
    pub header: MailboxEnvelopeHeader,
    pub routing: MailboxRoutingFrame,
}

/// One key or identity for `mailbox` at `epoch`. The epoch is an input, so a
/// replacement under a newer epoch holds different keys and cannot open, or be
/// opened by, anything sealed under an older one.
fn derive(
    root: &[u8; 32],
    label: &[u8],
    mailbox: &MailboxId,
    epoch: ExecutionEpoch,
) -> Zeroizing<[u8; 32]> {
    derive_with(root, label, mailbox, epoch, &[])
}

/// [`derive`] with `extra` mixed into the HMAC input after the epoch.
fn derive_with(
    root: &[u8; 32],
    label: &[u8],
    mailbox: &MailboxId,
    epoch: ExecutionEpoch,
    extra: &[u8],
) -> Zeroizing<[u8; 32]> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(root).expect("any key length");
    mac.update(label);
    mac.update(mailbox.as_bytes());
    mac.update(&epoch.get().to_be_bytes());
    mac.update(extra);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// Mint the random secret for a launch into `state_dir`, mode 0600. A file
/// left by an earlier run is shredded first, never reused: a launch always
/// seals under a secret nothing before it has seen.
pub fn mint_epoch_secret(state_dir: &Path) -> Result<Key> {
    shred_epoch_secret(state_dir)?;
    Key::load_or_create(&mvm_core::config::vm_mailbox_secret_at(state_dir))
}

/// Erase the per-epoch secret in `state_dir`, if any: overwritten with zeros,
/// flushed and unlinked.
pub fn shred_epoch_secret(state_dir: &Path) -> Result<()> {
    mvm_core::atomic_io::shred_file(&mvm_core::config::vm_mailbox_secret_at(state_dir))
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

struct Derived {
    root: Zeroizing<[u8; 32]>,
    mailbox: MailboxId,
    epoch: ExecutionEpoch,
    sender: SigningKey,
    authority: SigningKey,
}

fn derived_keys(keys_dir: &Path, mailbox: &MailboxId, epoch: ExecutionEpoch) -> Result<Derived> {
    let (signer, _) = mvm_core::crypto::ed25519_keypair::load_existing(
        &keys_dir.join(SIGNER_SECRET),
        &keys_dir.join(SIGNER_PUBLIC),
    )
    .map_err(|e| Error::new(ErrorKind::NotFound, format!("host signing key: {e:#}")))?;
    let root = Zeroizing::new(signer.to_bytes());
    let key = |label: &[u8]| SigningKey::from_bytes(&derive(&root, label, mailbox, epoch));
    Ok(Derived {
        root: Zeroizing::new(*root),
        sender: key(b"mvm-mailbox-sender-v1"),
        mailbox: *mailbox,
        epoch,
        authority: key(b"mvm-mailbox-authority-v1"),
    })
}

/// The authority verifying key this host derives for `mailbox` at `epoch`: what
/// an external signer must name in a plan's grant for the host to honor it. A
/// grant at one epoch naming another epoch's key is refused at launch.
pub fn authority_key_for(
    keys_dir: &Path,
    mailbox: &MailboxId,
    epoch: ExecutionEpoch,
) -> Result<VerifyingKey> {
    Ok(derived_keys(keys_dir, mailbox, epoch)?
        .authority
        .verifying_key())
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
    }
}

impl DerivedMailboxKeys {
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
        };
        (policy, sealer)
    }
}

/// The launcher half: read the host key directory and derive what serving
/// `grant` needs.
///
/// The grant's authority key must be the verifying half of the key this host
/// derives for that mailbox; any other is refused. `secret` is the launch's
/// per-epoch secret ([`mint_epoch_secret`]); the same seed with another secret
/// derives a different encryption key.
pub fn derive_launch_keys(
    keys_dir: &Path,
    grant: &MailboxGrant,
    secret: &Key,
) -> Result<DerivedMailboxKeys> {
    let derived = derived_keys(keys_dir, &grant.mailbox, grant.epoch)?;
    // After the signing seed above, so a wrong directory never mints a root.
    let encryption_root = Key::load_or_create(&keys_dir.join(ENCRYPTION_ROOT))?;
    let encryption = derive_with(
        encryption_root.expose_bytes(),
        b"mvm-mailbox-encryption-v1",
        &grant.mailbox,
        grant.epoch,
        secret.expose_bytes(),
    );
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
        encryption: *encryption,
        template,
    })
}

/// The host trust and sealer for `grant`, from the host key directory.
pub fn host_trust(
    keys_dir: &Path,
    grant: &MailboxGrant,
    secret: &Key,
) -> Result<(MailboxPolicy, GuestSealer)> {
    Ok(derive_launch_keys(keys_dir, grant, secret)?.trust())
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
    let id = |label: &[u8]| *derive(&d.root, label, &d.mailbox, d.epoch);
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
    /// The oldest plaintext the guest sent that has not been read.
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
    /// How the backend says the guest's mailbox port is dialed.
    pub route: mvm_core::vm_backend::HostDialRoute,
}

/// Bind the mailbox, then dial the guest's mailbox port from its own thread
/// for as long as the launch lives, serving every connection into the one
/// queue: every 100 ms for the first 30 s without a frame, every 2 s after,
/// and again straight away after each frame. Returns at once.
pub fn serve_derived(
    grant: MailboxGrant,
    keys: DerivedMailboxKeys,
    paths: ServePaths,
    limits: MailboxLimits,
) -> MailboxLaunch {
    serve_derived_with(grant, keys, paths, limits, FAST_DIAL_ATTEMPTS)
}

fn serve_derived_with(
    grant: MailboxGrant,
    keys: DerivedMailboxKeys,
    paths: ServePaths,
    limits: MailboxLimits,
    fast_attempts: u32,
) -> MailboxLaunch {
    let stop = Arc::new(AtomicBool::new(false));
    let service = Arc::new(OnceLock::new());
    let (thread_stop, thread_service) = (stop.clone(), service.clone());
    std::thread::spawn(move || {
        let mut attempt = 0u32;
        let (bound, mut sealer) = loop {
            if thread_stop.load(Ordering::SeqCst) {
                return;
            }
            let (trust, sealer) = keys.trust();
            match bind_grant(&grant, trust, sealer, limits, &paths.socket) {
                Ok(bound) => break bound,
                Err(_) => {
                    sleep_unless_stopped(&thread_stop, dial_delay(attempt, fast_attempts));
                    attempt = attempt.saturating_add(1);
                }
            }
        };
        let service = thread_service.get_or_init(|| bound);
        attempt = 0;
        while !thread_stop.load(Ordering::SeqCst) {
            // Ok means a frame arrived, delivered or refused; Err means the
            // guest had nothing yet (or was not up). Neither ends the loop.
            match service.serve_guest_until(&paths.route, &mut sealer, &thread_stop) {
                Ok(()) => {
                    attempt = 0;
                    sleep_unless_stopped(&thread_stop, POST_FRAME_PAUSE);
                }
                Err(_) => {
                    sleep_unless_stopped(&thread_stop, dial_delay(attempt, fast_attempts));
                    attempt = attempt.saturating_add(1);
                }
            }
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

    fn test_secret() -> mvm_core::crypto::aead::Key {
        mvm_core::crypto::aead::Key::from_bytes([5; 32])
    }

    fn keys_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
        dir
    }

    fn epoch(n: u64) -> ExecutionEpoch {
        ExecutionEpoch::new(n).unwrap()
    }

    fn grant_at(dir: &Path, mailbox: [u8; 32], n: u64) -> MailboxGrant {
        let mailbox = MailboxId::from_bytes(mailbox);
        MailboxGrant {
            mailbox,
            authority_key: authority_key_for(dir, &mailbox, epoch(n))
                .unwrap()
                .to_bytes(),
            epoch: epoch(n),
        }
    }

    fn grant(dir: &Path, mailbox: [u8; 32]) -> MailboxGrant {
        grant_at(dir, mailbox, 1)
    }

    #[test]
    fn the_epoch_secret_is_private_fresh_per_mint_and_shredded() {
        use std::os::unix::fs::PermissionsExt as _;
        let state = tempfile::tempdir().unwrap();
        let path = mvm_core::config::vm_mailbox_secret_at(state.path());
        let first = mint_epoch_secret(state.path()).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let second = mint_epoch_secret(state.path()).unwrap();
        assert_ne!(first.expose_bytes(), second.expose_bytes());
        shred_epoch_secret(state.path()).unwrap();
        assert!(!path.exists());
        shred_epoch_secret(state.path()).unwrap();
    }

    fn encryption_of(dir: &Path, g: &MailboxGrant, secret: &Key) -> [u8; 32] {
        derive_launch_keys(dir, g, secret).unwrap().encryption
    }

    #[test]
    fn the_encryption_key_follows_the_secret_the_root_and_the_epoch() {
        let dir = keys_dir();
        let g = grant(dir.path(), [4; 32]);
        let a = Key::from_bytes([1; 32]);
        let b = Key::from_bytes([2; 32]);
        assert_eq!(
            encryption_of(dir.path(), &g, &a),
            encryption_of(dir.path(), &g, &a)
        );
        assert_ne!(
            encryption_of(dir.path(), &g, &a),
            encryption_of(dir.path(), &g, &b)
        );
        let g2 = grant_at(dir.path(), [4; 32], 2);
        assert_ne!(
            encryption_of(dir.path(), &g, &a),
            encryption_of(dir.path(), &g2, &a)
        );
        // Same signing seed, another encryption root.
        let other = tempfile::tempdir().unwrap();
        for f in [SIGNER_SECRET, SIGNER_PUBLIC] {
            std::fs::copy(dir.path().join(f), other.path().join(f)).unwrap();
        }
        assert_ne!(
            encryption_of(dir.path(), &g, &a),
            encryption_of(other.path(), &g, &a)
        );
    }

    #[test]
    fn the_encryption_root_is_private_never_minted_without_a_signer_and_race_safe() {
        use std::os::unix::fs::PermissionsExt as _;
        let empty = tempfile::tempdir().unwrap();
        let g = grant(keys_dir().path(), [4; 32]);
        assert!(derive_launch_keys(empty.path(), &g, &Key::random()).is_err());
        assert!(!empty.path().join(ENCRYPTION_ROOT).exists());

        let dir = keys_dir();
        let g = grant(dir.path(), [4; 32]);
        let secret = Key::from_bytes([3; 32]);
        let results: Vec<_> = (0..8)
            .map(|_| {
                let (p, g, s) = (dir.path().to_path_buf(), g, Key::from_bytes([3; 32]));
                std::thread::spawn(move || encryption_of(&p, &g, &s))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();
        assert!(
            results
                .iter()
                .all(|r| *r == encryption_of(dir.path(), &g, &secret))
        );
        let mode = std::fs::metadata(dir.path().join(ENCRYPTION_ROOT))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn the_dial_schedule_is_fast_then_slow_and_bounded() {
        assert_eq!(dial_delay(0, 300), FAST_DIAL_INTERVAL);
        assert_eq!(dial_delay(299, 300), FAST_DIAL_INTERVAL);
        assert_eq!(dial_delay(300, 300), SLOW_DIAL_INTERVAL);
        assert_eq!(dial_delay(u32::MAX, 300), SLOW_DIAL_INTERVAL);
    }

    fn serve_paths(dir: &Path) -> ServePaths {
        ServePaths {
            socket: dir.join("mailbox.sock"),
            route: mvm_core::vm_backend::HostDialRoute::PortSocket(dir.join("port.sock")),
        }
    }

    #[test]
    fn a_frame_written_after_the_fast_window_is_still_delivered() {
        use std::os::unix::net::UnixListener;
        let dir = keys_dir();
        let grant = grant(dir.path(), [7; 32]);
        let keys = derive_launch_keys(dir.path(), &grant, &test_secret()).unwrap();
        // The guest port does not exist yet: every early dial fails, and with
        // a zero-length fast window all of them are on the slow schedule.
        let launch = serve_derived_with(grant, keys, serve_paths(dir.path()), LAUNCH_LIMITS, 0);
        std::thread::sleep(Duration::from_millis(300));
        let listener = UnixListener::bind(dir.path().join("port.sock")).unwrap();
        let outbox = dir.path().join("outbox");
        std::fs::create_dir(&outbox).unwrap();
        mvm_agentd::mailbox_outbox::write_outbox(
            &outbox,
            &mvm_core::mailbox::frame::OutboxMessage {
                recipient: mvm_contract::protocol::mailbox::PrincipalId::from_bytes([7; 32]),
                body: b"late".to_vec(),
            },
        )
        .unwrap();
        let guest = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            mvm_agentd::mailbox_outbox::forward_outbox(&mut stream, &outbox)
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while launch.receive().is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "late frame not served"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        guest.join().unwrap().unwrap();
    }

    #[test]
    fn dropping_the_launch_stops_an_idle_slow_dialer_promptly() {
        let dir = keys_dir();
        let grant = grant(dir.path(), [8; 32]);
        let keys = derive_launch_keys(dir.path(), &grant, &test_secret()).unwrap();
        let stop = {
            let launch = serve_derived_with(grant, keys, serve_paths(dir.path()), LAUNCH_LIMITS, 0);
            launch.stop.clone()
        };
        assert!(stop.load(Ordering::SeqCst));
        let started = std::time::Instant::now();
        sleep_unless_stopped(&stop, Duration::from_secs(60));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    type Verdict = std::result::Result<(), mvm_core::mailbox::frame::Refusal>;

    /// A guest that accepts every dial and forwards whatever its outbox holds.
    fn fake_guest(dir: &Path) -> (PathBuf, std::sync::mpsc::Receiver<Verdict>) {
        let listener = std::os::unix::net::UnixListener::bind(dir.join("port.sock")).unwrap();
        let outbox = dir.join("outbox");
        std::fs::create_dir(&outbox).unwrap();
        let (path, (tx, rx)) = (outbox.clone(), std::sync::mpsc::channel());
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let v = mvm_agentd::mailbox_outbox::forward_outbox(&mut stream, &path);
                if v != Err(mvm_core::mailbox::frame::Refusal::Malformed) {
                    let _ = tx.send(v);
                }
            }
        });
        (outbox, rx)
    }

    /// Leave a message for `recipient`, and return the verdict the host gave.
    fn send_one(
        outbox: &Path,
        rx: &std::sync::mpsc::Receiver<Verdict>,
        to: u8,
        body: &[u8],
    ) -> Verdict {
        let recipient = mvm_contract::protocol::mailbox::PrincipalId::from_bytes([to; 32]);
        let message = mvm_core::mailbox::frame::OutboxMessage {
            recipient,
            body: body.to_vec(),
        };
        mvm_agentd::mailbox_outbox::write_outbox(outbox, &message).unwrap();
        rx.recv_timeout(Duration::from_secs(20))
            .expect("no verdict")
    }

    fn launch_against(dir: &Path, limits: MailboxLimits) -> MailboxLaunch {
        let grant = grant(dir, [7; 32]);
        let keys = derive_launch_keys(dir, &grant, &test_secret()).unwrap();
        serve_derived_with(grant, keys, serve_paths(dir), limits, 300)
    }

    #[test]
    fn every_message_is_served_in_order_and_a_refusal_or_flood_changes_nothing() {
        let dir = keys_dir();
        let (outbox, rx) = fake_guest(dir.path());
        let limits = MailboxLimits {
            max_depth: 2,
            ..LAUNCH_LIMITS
        };
        let launch = launch_against(dir.path(), limits);
        assert!(send_one(&outbox, &rx, 9, b"wrong recipient").is_err());
        assert_eq!(send_one(&outbox, &rx, 7, b"first"), Ok(()));
        assert_eq!(send_one(&outbox, &rx, 7, b"second"), Ok(()));
        assert!(send_one(&outbox, &rx, 7, b"over the bound").is_err());
        assert_eq!(launch.receive().unwrap(), b"first");
        assert_eq!(launch.receive().unwrap(), b"second");
        assert!(launch.receive().is_none());
    }

    fn assert_dialer_exits_after_drop(launch: MailboxLaunch) {
        let stop = launch.stop.clone();
        drop(launch);
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while Arc::strong_count(&stop) > 1 {
            assert!(std::time::Instant::now() < deadline, "dialer still running");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn dropping_the_launch_ends_an_idle_dialer_and_one_stuck_on_a_silent_guest() {
        let idle = keys_dir();
        let (_outbox, _rx) = fake_guest(idle.path());
        assert_dialer_exits_after_drop(launch_against(idle.path(), LAUNCH_LIMITS));

        let silent = keys_dir();
        let listener = std::os::unix::net::UnixListener::bind(silent.path().join("port.sock"));
        let launch = launch_against(silent.path(), LAUNCH_LIMITS);
        let _held = listener.unwrap().accept().unwrap();
        // Bounded by the serve I/O timeout, not by the guest.
        assert_dialer_exits_after_drop(launch);
    }

    #[test]
    fn without_a_template_file_the_derived_defaults_serve_a_matching_grant() {
        let dir = keys_dir();
        assert!(!dir.path().join(TEMPLATE_FILE).exists());
        let (policy, sealer) =
            host_trust(dir.path(), &grant(dir.path(), [4; 32]), &test_secret()).unwrap();
        assert_eq!(
            policy.authority_key,
            authority_key_for(dir.path(), &MailboxId::from_bytes([4; 32]), epoch(1)).unwrap()
        );
        assert_eq!(sealer.capability.address.mailbox.as_bytes(), &[4; 32]);
    }

    #[test]
    fn keys_differ_per_epoch_and_are_deterministic_within_one() {
        let dir = keys_dir();
        let m = MailboxId::from_bytes([4; 32]);
        let at = |n| authority_key_for(dir.path(), &m, epoch(n)).unwrap();
        assert_eq!(at(1), at(1));
        assert_ne!(at(1), at(2));
        let (p1, _) = host_trust(
            dir.path(),
            &grant_at(dir.path(), [4; 32], 1),
            &test_secret(),
        )
        .unwrap();
        let (p2, _) = host_trust(
            dir.path(),
            &grant_at(dir.path(), [4; 32], 2),
            &test_secret(),
        )
        .unwrap();
        assert_ne!(p1.sender_key, p2.sender_key);
    }

    #[test]
    fn a_grant_at_one_epoch_naming_another_epochs_authority_is_refused() {
        let dir = keys_dir();
        let mut g = grant_at(dir.path(), [4; 32], 2);
        g.authority_key = grant_at(dir.path(), [4; 32], 1).authority_key;
        let err = host_trust(dir.path(), &g, &test_secret())
            .err()
            .expect("refused");
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn a_foreign_authority_is_refused() {
        let dir = keys_dir();
        let mut g = grant(dir.path(), [4; 32]);
        g.authority_key = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
        let err = host_trust(dir.path(), &g, &test_secret())
            .err()
            .expect("refused");
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn authority_keys_differ_per_mailbox_and_per_host() {
        let (a, b) = (keys_dir(), keys_dir());
        let m = |n| MailboxId::from_bytes([n; 32]);
        assert_ne!(
            authority_key_for(a.path(), &m(1), epoch(1)).unwrap(),
            authority_key_for(a.path(), &m(2), epoch(1)).unwrap()
        );
        assert_ne!(
            authority_key_for(a.path(), &m(1), epoch(1)).unwrap(),
            authority_key_for(b.path(), &m(1), epoch(1)).unwrap()
        );
    }

    #[test]
    fn a_template_file_overrides_the_defaults_and_a_malformed_one_is_refused() {
        let dir = keys_dir();
        std::fs::write(dir.path().join(TEMPLATE_FILE), b"{}").unwrap();
        let err = host_trust(dir.path(), &grant(dir.path(), [4; 32]), &test_secret())
            .err()
            .expect("malformed template refused");
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn derived_keys_round_trip_and_carry_neither_the_seed_nor_a_mailbox_root() {
        let dir = keys_dir();
        let seed = std::fs::read(dir.path().join(SIGNER_SECRET)).unwrap();
        let g = grant(dir.path(), [4; 32]);
        let keys = derive_launch_keys(dir.path(), &g, &test_secret()).unwrap();
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
        let keys =
            derive_launch_keys(dir.path(), &grant(dir.path(), [4; 32]), &test_secret()).unwrap();
        let mut value = serde_json::to_value(&keys).unwrap();
        value["root"] = serde_json::json!("00");
        assert!(serde_json::from_value::<DerivedMailboxKeys>(value).is_err());
    }
}
