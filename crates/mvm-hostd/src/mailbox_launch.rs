//! Launch-time mailbox: build the host-held trust a granted guest mailbox is
//! served under, and serve it off the launch path.
//!
//! The sealing keys are derived from the host signing key already in the host
//! key directory, per mailbox, and never come from the plan or the guest. The
//! identities and capability they seal under are an operator template beside
//! that key. Encryption is host to host: the derived keys are this host's, so
//! a peer host cannot open what they seal.

use std::io::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use mvm_contract::protocol::mailbox::{
    MailboxCapabilityGrant, MailboxEnvelopeHeader, MailboxGrant, MailboxId, MailboxRoutingFrame,
};
use mvm_core::crypto::aead::Key;
use mvm_core::mailbox::OpenContext;
use mvm_core::plan::ExecutionPlan;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::mailbox_service::{
    GuestSealer, MailboxLimits, MailboxPolicy, MailboxService, serve_granted_guest,
};

const SIGNER_SECRET: &str = "host-signer.ed25519";
const SIGNER_PUBLIC: &str = "host-signer.pub";
/// Operator-authored identities and capability, beside the host key.
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
        sender: key(b"mvm-mailbox-sender-v1"),
        authority: key(b"mvm-mailbox-authority-v1"),
        encryption: derive(&root, b"mvm-mailbox-encryption-v1", mailbox),
    })
}

/// The authority verifying key this host derives for `mailbox`: what an
/// external signer must name in a plan's grant for the host to honor it.
pub fn authority_key_for(keys_dir: &Path, mailbox: &MailboxId) -> Result<VerifyingKey> {
    Ok(derived_keys(keys_dir, mailbox)?.authority.verifying_key())
}

/// The host trust and sealer for `grant`, from the host key directory.
///
/// The grant's authority key must be the verifying half of the key this host
/// derives for that mailbox; any other is refused.
pub fn host_trust(keys_dir: &Path, grant: &MailboxGrant) -> Result<(MailboxPolicy, GuestSealer)> {
    let Derived {
        sender: sender_key,
        authority: authority_key,
        encryption,
    } = derived_keys(keys_dir, &grant.mailbox)?;
    let template: MailboxTemplate =
        serde_json::from_slice(&std::fs::read(keys_dir.join(TEMPLATE_FILE))?)
            .map_err(|e| Error::new(ErrorKind::InvalidData, format!("mailbox template: {e}")))?;
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
            required_operation: mvm_contract::protocol::mailbox::MailboxOperation::Send,
            now_unix_ms: now_unix_ms(),
            accepted_content_types: vec![h.content_type.clone()],
            revoked_capabilities: vec![],
        },
        encryption_key: Key::from_bytes(*encryption),
        sender_key: sender_key.verifying_key(),
        authority_key: authority_key.verifying_key(),
    };
    let sealer = GuestSealer {
        encryption_key: Key::from_bytes(*encryption),
        sender_key,
        authority_key,
        capability: template.capability,
        header: template.header,
        routing: template.routing,
        sent: 0,
    };
    if sealer.authority_key.verifying_key().to_bytes() != grant.authority_key {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "grant authority is not the host's authority key for this mailbox",
        ));
    }
    Ok((policy, sealer))
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
pub struct MailboxPaths {
    pub keys_dir: PathBuf,
    pub socket: PathBuf,
    pub guest_port: PathBuf,
    pub firecracker_mux: PathBuf,
}

/// Serve the guest mailbox for a launch, only when the signed plan grants one.
/// Returns at once: no grant yields `None` with nothing built or dialed; a
/// grant builds the host trust now (so a bad key or template is refused here)
/// and dials the guest from its own thread, waiting up to 30 s for the guest
/// to listen.
pub fn start_for_launch(
    plan: &ExecutionPlan,
    paths: MailboxPaths,
    limits: MailboxLimits,
) -> Result<Option<MailboxLaunch>> {
    let Some(grant) = plan.mailbox else {
        return Ok(None);
    };
    let mut first = Some(host_trust(&paths.keys_dir, &grant)?);
    let stop = Arc::new(AtomicBool::new(false));
    let service = Arc::new(OnceLock::new());
    let (thread_stop, thread_service) = (stop.clone(), service.clone());
    let plan = plan.clone();
    std::thread::spawn(move || {
        for _ in 0..DIAL_ATTEMPTS {
            if thread_stop.load(Ordering::SeqCst) {
                return;
            }
            let Ok((trust, sealer)) = first
                .take()
                .map_or_else(|| host_trust(&paths.keys_dir, &grant), Ok)
            else {
                return;
            };
            let guest = (paths.guest_port.as_path(), paths.firecracker_mux.as_path());
            match serve_granted_guest(&plan, trust, sealer, limits, &paths.socket, guest) {
                Ok(served) => {
                    if let Some(served) = served {
                        let _ = thread_service.set(served);
                    }
                    return;
                }
                Err(_) => std::thread::sleep(DIAL_INTERVAL),
            }
        }
    });
    Ok(Some(MailboxLaunch { stop, service }))
}
