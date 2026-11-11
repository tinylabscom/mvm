//! Cryptographic guest reader enrollment; the runtime owns boot/session provenance.
//!
//! A valid signature or a connected vsock peer alone is not Receive authority.
//! Callers must obtain the scope from an authenticated current guest boot and
//! persist one-time challenge use before publishing a lease.

use std::path::Path;

use anyhow::{Context as _, Result as AnyResult};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use mvm_contract::protocol::mailbox::{
    BootId, ConsumerSessionId, DELIVERY_ACK_SIGNATURE_DOMAIN, DELIVERY_LEASE_SIGNATURE_DOMAIN,
    ExecutionEpoch, MailboxAddress, MailboxDeliveryAck, MailboxDeliveryLease, MailboxEnvelope,
    MailboxEnvelopeHeader, MailboxGrant, MailboxGuestReaderEnrollment, MailboxGuestReaderScope,
    MailboxId, READER_ENROLLMENT_SIGNATURE_DOMAIN, RevocationId, SignedMailboxCapability,
    SignedMailboxDeliveryAck, SignedMailboxDeliveryLease, SignedMailboxGuestReaderEnrollment,
};
use rand::TryRng as _;

use super::{MailboxError, canonical_bytes, verify_capability_signature};

/// Name shared by the host writer and guest reader of one public boot binding.
pub const MAILBOX_READER_BOOT_FILE: &str = "mailbox-reader-boot.json";
/// Maximum encoded size before parsing a guest-visible boot binding.
pub const MAX_MAILBOX_READER_BOOT_BYTES: u64 = 2048;

/// Public plan/boot/ACK-key binding projected into one cold guest identity
/// drive and retained privately by the host for helper restart.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxReaderBootBinding {
    pub plan_id: crate::plan::PlanId,
    pub plan_nonce: crate::plan::Nonce,
    pub mailbox: MailboxId,
    pub authority_key: [u8; 32],
    pub execution_epoch: ExecutionEpoch,
    pub boot: BootId,
    pub guest_identity_key: [u8; 32],
    pub ack_public_key: [u8; 32],
}

impl MailboxReaderBootBinding {
    /// Mint a distinct boot ID for a content-addressed admitted plan.
    pub fn mint(
        plan: &crate::plan::ExecutionPlan,
        guest_identity: VerifyingKey,
        ack_public_key: [u8; 32],
    ) -> AnyResult<Self> {
        let grant = plan
            .mailbox
            .context("reader boot requires a mailbox grant")?;
        anyhow::ensure!(
            plan.plan_id == crate::plan::compute_plan_id(plan),
            "mailbox reader boot requires a content-addressed admitted plan"
        );
        VerifyingKey::from_bytes(&ack_public_key).context("invalid mailbox ACK public key")?;
        let mut boot = [0u8; 32];
        rand::rngs::SysRng
            .try_fill_bytes(&mut boot)
            .context("drawing system entropy for the mailbox reader boot")?;
        Ok(Self {
            plan_id: plan.plan_id.clone(),
            plan_nonce: plan.nonce.clone(),
            mailbox: grant.mailbox,
            authority_key: grant.authority_key,
            execution_epoch: grant.epoch,
            boot: BootId::from_bytes(boot),
            guest_identity_key: guest_identity.to_bytes(),
            ack_public_key,
        })
    }

    /// Persist the host-side public binding atomically before the guest boots.
    pub fn persist(&self, state_dir: &Path) -> AnyResult<()> {
        crate::private_fs::ensure_private_dir(state_dir)?;
        let bytes = serde_json::to_vec(self).context("encode mailbox reader boot binding")?;
        anyhow::ensure!(
            bytes.len() <= MAX_MAILBOX_READER_BOOT_BYTES as usize,
            "mailbox reader boot binding exceeds the encoded bound"
        );
        crate::atomic_io::write_private(&state_dir.join(MAILBOX_READER_BOOT_FILE), &bytes)
            .context("persist mailbox reader boot binding")
    }

    /// Reopen a bounded host record without following a symlink.
    pub fn load(state_dir: &Path) -> AnyResult<Self> {
        use std::io::Read as _;
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
        let path = state_dir.join(MAILBOX_READER_BOOT_FILE);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file()
                && metadata.nlink() == 1
                && metadata.len() <= MAX_MAILBOX_READER_BOOT_BYTES,
            "mailbox reader boot binding is not a bounded regular file"
        );
        let mut bytes = Vec::new();
        file.take(MAX_MAILBOX_READER_BOOT_BYTES + 1)
            .read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_MAILBOX_READER_BOOT_BYTES,
            "mailbox reader boot binding exceeds the encoded bound"
        );
        serde_json::from_slice(&bytes).context("decode mailbox reader boot binding")
    }

    /// Refuse a stale parent or moved mailbox before this boot can enroll.
    pub fn check_plan(&self, plan: &crate::plan::ExecutionPlan) -> AnyResult<()> {
        let grant = plan
            .mailbox
            .context("reader boot requires a mailbox grant")?;
        anyhow::ensure!(
            self.plan_id == plan.plan_id
                && self.plan_nonce == plan.nonce
                && self.mailbox == grant.mailbox
                && self.authority_key == grant.authority_key
                && self.execution_epoch == grant.epoch
                && self.boot.as_bytes() != &[0; 32]
                && self.ack_public_key != [0; 32]
                && self.guest_identity_key != [0; 32],
            "mailbox reader boot binding is stale or does not match the admitted plan"
        );
        VerifyingKey::from_bytes(&self.ack_public_key).context("invalid mailbox ACK public key")?;
        VerifyingKey::from_bytes(&self.guest_identity_key)
            .context("invalid guest identity public key")?;
        VerifyingKey::from_bytes(&self.authority_key)
            .context("invalid mailbox authority public key")?;
        Ok(())
    }
}

const READER_POSSESSION_SIGNATURE_DOMAIN: &[u8] = b"mvm.mailbox.reader-possession.v1\0";

/// Sign an enrollment with the destination authority. The caller must bind
/// its body to the verified plan and current authenticated guest boot first.
pub fn sign_guest_reader_enrollment(
    enrollment: MailboxGuestReaderEnrollment,
    authority: &SigningKey,
) -> Result<SignedMailboxGuestReaderEnrollment, MailboxError> {
    let signature = authority
        .sign(&canonical_bytes(
            READER_ENROLLMENT_SIGNATURE_DOMAIN,
            &enrollment,
        )?)
        .to_bytes()
        .to_vec();
    let signed = SignedMailboxGuestReaderEnrollment {
        enrollment,
        signature,
    };
    signed.encode()?;
    Ok(signed)
}

/// Verify the destination signature and independently signed Receive grant.
///
/// `scope` must come from an already authenticated current plan/boot/session.
/// The returned key is *not* reader authority until fresh possession is
/// proven and that session/challenge binding is persisted and replay-fenced.
pub fn verify_guest_reader_enrollment(
    signed: &SignedMailboxGuestReaderEnrollment,
    capability: &SignedMailboxCapability,
    scope: &MailboxGuestReaderScope<'_>,
    authority: &VerifyingKey,
    revoked: &[RevocationId],
) -> Result<VerifyingKey, MailboxError> {
    if scope.plan.authority_key != authority.to_bytes() {
        return Err(MailboxError::WrongCapabilityIssuer);
    }
    if scope.receive != &capability.grant {
        return Err(MailboxError::WrongCapability);
    }
    if revoked.contains(&capability.grant.revocation_id) {
        return Err(MailboxError::CapabilityRevoked);
    }
    verify_capability_signature(capability, authority)?;
    signed.check_scope(scope)?;
    signed.encode()?;
    let signature: [u8; 64] = signed
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| MailboxError::ReaderEnrollmentSignatureInvalid)?;
    authority
        .verify(
            &canonical_bytes(READER_ENROLLMENT_SIGNATURE_DOMAIN, &signed.enrollment)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| MailboxError::ReaderEnrollmentSignatureInvalid)?;
    VerifyingKey::from_bytes(&signed.enrollment.ack_public_key)
        .map_err(|_| MailboxError::ReaderKeyInvalid)
}

fn possession_bytes(
    signed: &SignedMailboxGuestReaderEnrollment,
    challenge: &[u8; 32],
) -> Result<Vec<u8>, MailboxError> {
    if *challenge == [0; 32] {
        return Err(MailboxError::ReaderPossessionInvalid);
    }
    signed.encode()?;
    canonical_bytes(READER_POSSESSION_SIGNATURE_DOMAIN, &(signed, challenge))
}

/// Respond to a destination-minted one-time challenge with the guest-held
/// mailbox key, never the FlowMux key or host sealing key.
pub fn sign_reader_possession(
    signed: &SignedMailboxGuestReaderEnrollment,
    challenge: &[u8; 32],
    key: &SigningKey,
) -> Result<[u8; 64], MailboxError> {
    if key.verifying_key().to_bytes() != signed.enrollment.ack_public_key {
        return Err(MailboxError::ReaderKeyInvalid);
    }
    Ok(key.sign(&possession_bytes(signed, challenge)?).to_bytes())
}

/// Verify possession only; the destination must also authenticate the live
/// boot/session, mint the nonce, and remember its single use durably.
pub fn verify_reader_possession(
    signed: &SignedMailboxGuestReaderEnrollment,
    challenge: &[u8; 32],
    signature: &[u8],
    key: &VerifyingKey,
) -> Result<(), MailboxError> {
    if key.to_bytes() != signed.enrollment.ack_public_key {
        return Err(MailboxError::ReaderKeyInvalid);
    }
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| MailboxError::ReaderPossessionInvalid)?;
    key.verify(
        &possession_bytes(signed, challenge)?,
        &Signature::from_bytes(&signature),
    )
    .map_err(|_| MailboxError::ReaderPossessionInvalid)
}

/// Sign a destination lease only after the referenced ciphertext and dedup
/// identity have committed. Signing alone does not publish the lease.
pub fn sign_delivery_lease(
    lease: MailboxDeliveryLease,
    authority: &SigningKey,
) -> Result<SignedMailboxDeliveryLease, MailboxError> {
    let signature = authority
        .sign(&canonical_bytes(DELIVERY_LEASE_SIGNATURE_DOMAIN, &lease)?)
        .to_bytes()
        .to_vec();
    let signed = SignedMailboxDeliveryLease { lease, signature };
    signed.encode()?;
    Ok(signed)
}

/// Already-authenticated destination facts for one leased ciphertext.
/// The runtime must derive these from its verified plan, active reader
/// session, current revocation state, and committed journal entry.
#[derive(Clone, Copy)]
pub struct ReaderDeliveryContext<'a> {
    pub plan: &'a MailboxGrant,
    pub capability: &'a SignedMailboxCapability,
    pub reader_scope: MailboxGuestReaderScope<'a>,
    pub consumer_session: ConsumerSessionId,
    pub now_unix_ms: i64,
    pub envelope: &'a MailboxEnvelope,
    pub header: &'a MailboxEnvelopeHeader,
    pub authority: &'a VerifyingKey,
    pub revoked: &'a [RevocationId],
}

/// Verify a lease against the exact committed ciphertext, a separate signed
/// Receive capability and an authenticated current consumer session.
pub fn verify_delivery_lease(
    signed: &SignedMailboxDeliveryLease,
    context: &ReaderDeliveryContext<'_>,
) -> Result<(), MailboxError> {
    let ReaderDeliveryContext {
        plan,
        capability,
        consumer_session,
        now_unix_ms,
        envelope,
        header,
        authority,
        revoked,
        ..
    } = context;
    if plan.authority_key != authority.to_bytes() {
        return Err(MailboxError::WrongCapabilityIssuer);
    }
    if revoked.contains(&capability.grant.revocation_id) {
        return Err(MailboxError::CapabilityRevoked);
    }
    verify_capability_signature(capability, authority)?;
    signed.check_scope(plan, &capability.grant, *consumer_session, *now_unix_ms)?;
    signed.encode()?;
    let lease = &signed.lease;
    let address = MailboxAddress {
        tenant: header.tenant,
        authorization_domain: header.authorization_domain,
        mailbox: header.mailbox,
        recipient: header.recipient,
    };
    if lease.address != address
        || lease.sender != header.sender
        || lease.sender_boot != header.sender_boot
        || lease.message_id != header.message_id
        || lease.delivery_id != envelope.routing.delivery_id
        || lease.execution_epoch != header.execution_epoch
        || lease.ciphertext_commitment != envelope.ciphertext_commitment
    {
        return Err(MailboxError::DeliveryLeaseMismatch);
    }
    let signature: [u8; 64] = signed
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| MailboxError::DeliveryLeaseSignatureInvalid)?;
    authority
        .verify(
            &canonical_bytes(DELIVERY_LEASE_SIGNATURE_DOMAIN, lease)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| MailboxError::DeliveryLeaseSignatureInvalid)
}

/// Sign one acknowledgement with the guest's independently enrolled mailbox
/// key; this does not assert that the destination committed the ACK.
pub fn sign_delivery_ack(
    ack: MailboxDeliveryAck,
    guest: &SigningKey,
) -> Result<SignedMailboxDeliveryAck, MailboxError> {
    let signature = guest
        .sign(&canonical_bytes(DELIVERY_ACK_SIGNATURE_DOMAIN, &ack)?)
        .to_bytes()
        .to_vec();
    let signed = SignedMailboxDeliveryAck { ack, signature };
    signed.encode()?;
    Ok(signed)
}

/// Verify the current signed enrollment, exact active lease and guest ACK.
/// The runtime must authenticate the supplied boot/session, prove possession
/// before disclosure, and durably fence ACK replay; this does not mutate state.
pub fn verify_delivery_ack(
    signed: &SignedMailboxDeliveryAck,
    active: &SignedMailboxDeliveryLease,
    context: &ReaderDeliveryContext<'_>,
    enrollment: &SignedMailboxGuestReaderEnrollment,
    guest: &VerifyingKey,
) -> Result<(), MailboxError> {
    if context.reader_scope.plan != context.plan
        || context.reader_scope.current_session != context.consumer_session
        || context.reader_scope.now_unix_ms != context.now_unix_ms
    {
        return Err(MailboxError::ReaderKeyInvalid);
    }
    let enrolled_key = verify_guest_reader_enrollment(
        enrollment,
        context.capability,
        &context.reader_scope,
        context.authority,
        context.revoked,
    )?;
    if enrolled_key != *guest {
        return Err(MailboxError::ReaderKeyInvalid);
    }
    if enrollment.enrollment.ack_public_key != guest.to_bytes()
        || enrollment.enrollment.consumer_session != context.consumer_session
        || enrollment.enrollment.consumer != context.capability.grant.subject
        || enrollment.enrollment.address != context.capability.grant.address
        || enrollment.enrollment.receive_capability_id != context.capability.grant.capability_id
        || enrollment.enrollment.execution_epoch != context.plan.epoch
        || enrollment.enrollment.policy_epoch != context.capability.grant.policy_epoch
    {
        return Err(MailboxError::ReaderKeyInvalid);
    }
    signed.check_scope(
        context.plan,
        &context.capability.grant,
        context.consumer_session,
        context.now_unix_ms,
    )?;
    signed.encode()?;
    if &signed.ack.lease != active {
        return Err(MailboxError::DeliveryLeaseMismatch);
    }
    verify_delivery_lease(active, context)?;
    let signature: [u8; 64] = signed
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| MailboxError::DeliveryAckSignatureInvalid)?;
    guest
        .verify(
            &canonical_bytes(DELIVERY_ACK_SIGNATURE_DOMAIN, &signed.ack)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| MailboxError::DeliveryAckSignatureInvalid)
}
