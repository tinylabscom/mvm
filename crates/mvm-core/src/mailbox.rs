//! Mailbox codec and cryptographic verification.
//!
//! The wire DTOs live in `mvm-contract`; this module owns the host-side
//! cryptographic work, bounded decoding, capability enforcement, and replay
//! seam. It performs no routing, storage, or network I/O.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mvm_contract::protocol::mailbox::{
    AES_256_GCM_ALGORITHM, AuthorizationDomainId, BootId, ContentType, DestinationReceipt,
    ED25519_ALGORITHM, ED25519_SIGNATURE_BYTES, ExecutionEpoch,
    LOCAL_DURABLE_RECEIPT_SIGNATURE_DOMAIN, MAILBOX_PROTOCOL_VERSION, MAX_ENCODED_ENVELOPE_BYTES,
    MAX_MAILBOX_PAYLOAD_BYTES, MailboxCapabilityGrant, MailboxContractError, MailboxDeliveryError,
    MailboxEnvelope, MailboxEnvelopeHeader, MailboxId, MailboxMessage, MailboxOperation,
    MailboxRoutingFrame, MessageId, PrincipalId, ProtocolVersion, RevocationId,
    SignedDestinationReceipt, SignedMailboxCapability, SignedMailboxMessage, TenantId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::aead::{self, Key};

const ENVELOPE_SIGNATURE_DOMAIN: &[u8] = b"mvm.mailbox.envelope.v1\0";
const CAPABILITY_SIGNATURE_DOMAIN: &[u8] = b"mvm.mailbox.capability.v1\0";
const RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"mvm.mailbox.receipt.v1\0";
const ENVELOPE_AEAD_DOMAIN: &[u8] = b"mvm.mailbox.payload.v1\0";

/// The one-frame exchange the guest and the host mailbox service share.
pub mod frame;

/// Bounded destination-side ciphertext journal and durable acceptance.
#[cfg(unix)]
pub mod journal;

/// Cryptographic guest reader enrollment, separate from transport admission.
pub mod reader;

/// Bounded, versioned guest-reader frames on the existing mailbox port.
pub mod reader_wire;

/// Overlay resolution and authenticated, bounded byte-transport seams.
pub mod transport;

/// Plaintext plus its complete immutable signed header.
pub struct SealRequest<'a> {
    pub routing: MailboxRoutingFrame,
    pub header: MailboxEnvelopeHeader,
    pub plaintext: &'a [u8],
}

/// Current state and expected identities used to authorize one open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenContext {
    pub expected_tenant: TenantId,
    pub expected_authorization_domain: AuthorizationDomainId,
    pub expected_mailbox: MailboxId,
    pub expected_sender: PrincipalId,
    pub expected_recipient: PrincipalId,
    pub acting_principal: PrincipalId,
    pub expected_capability_issuer: PrincipalId,
    pub current_execution_epoch: ExecutionEpoch,
    pub current_policy_epoch: u64,
    pub required_operation: MailboxOperation,
    pub now_unix_ms: i64,
    pub accepted_content_types: Vec<ContentType>,
    pub revoked_capabilities: Vec<RevocationId>,
}

/// Replay identity is scoped to the authenticated sender boot and execution
/// epoch. The durable implementation may retain the same tuple in a journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ReplayIdentity {
    sender: PrincipalId,
    sender_boot: BootId,
    execution_epoch: ExecutionEpoch,
    message_id: MessageId,
}

impl ReplayIdentity {
    #[must_use]
    pub fn from_header(header: &MailboxEnvelopeHeader) -> Self {
        Self {
            sender: header.sender,
            sender_boot: header.sender_boot,
            execution_epoch: header.execution_epoch,
            message_id: header.message_id,
        }
    }
}

/// Atomic replay check seam. Persistent mailbox stores implement this using
/// the same transaction that accepts a message.
pub trait ReplayProtector {
    /// Return `true` and record an unseen identity, or `false` for a replay.
    fn check_and_record(&mut self, identity: ReplayIdentity) -> bool;
}

/// Process-local replay protector for tests and ephemeral mailboxes.
#[derive(Debug, Default)]
pub struct InMemoryReplayProtector {
    seen: BTreeSet<ReplayIdentity>,
}

impl ReplayProtector for InMemoryReplayProtector {
    fn check_and_record(&mut self, identity: ReplayIdentity) -> bool {
        self.seen.insert(identity)
    }
}

/// Fail-closed mailbox verification errors. Variants intentionally contain no
/// payload data and are safe to map to stable audit codes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MailboxError {
    #[error("mailbox object could not be canonicalized")]
    Canonicalization,
    #[error("mailbox envelope encoding failed")]
    Encoding,
    #[error("mailbox envelope decoding failed")]
    Decoding,
    #[error("mailbox envelope exceeds the encoded-size bound")]
    EncodedSizeExceeded,
    #[error("unsupported mailbox protocol version")]
    UnsupportedProtocolVersion,
    #[error("unsupported mailbox signature algorithm")]
    UnsupportedSignatureAlgorithm,
    #[error("unsupported mailbox encryption algorithm")]
    UnsupportedEncryptionAlgorithm,
    #[error("unsupported mailbox content type")]
    UnsupportedContentType,
    #[error("mailbox contract bounds are invalid: {0}")]
    Contract(MailboxContractError),
    #[error("mailbox delivery contract is invalid: {0}")]
    DeliveryContract(MailboxDeliveryError),
    #[error("mailbox sender signature is invalid")]
    SignatureInvalid,
    #[error("mailbox capability signature is invalid")]
    CapabilitySignatureInvalid,
    #[error("destination receipt signature is invalid")]
    ReceiptSignatureInvalid,
    #[error("guest reader enrollment signature is invalid")]
    ReaderEnrollmentSignatureInvalid,
    #[error("guest reader key is invalid")]
    ReaderKeyInvalid,
    #[error("guest reader possession signature is invalid")]
    ReaderPossessionInvalid,
    #[error("destination delivery lease signature is invalid")]
    DeliveryLeaseSignatureInvalid,
    #[error("guest delivery ACK signature is invalid")]
    DeliveryAckSignatureInvalid,
    #[error("delivery lease does not identify the committed message")]
    DeliveryLeaseMismatch,
    #[error("mailbox ciphertext commitment is invalid")]
    CiphertextCommitmentInvalid,
    #[error("mailbox payload decryption failed")]
    DecryptionFailed,
    #[error("mailbox plaintext length is invalid")]
    PlaintextLengthMismatch,
    #[error("mailbox authorization domain does not match")]
    WrongAuthorizationDomain,
    #[error("mailbox tenant does not match")]
    WrongTenant,
    #[error("mailbox identity does not match")]
    WrongMailbox,
    #[error("mailbox sender does not match")]
    WrongSender,
    #[error("mailbox recipient does not match")]
    WrongRecipient,
    #[error("mailbox capability subject does not match the acting principal")]
    WrongCapabilitySubject,
    #[error("mailbox capability issuer does not match the trusted authority")]
    WrongCapabilityIssuer,
    #[error("mailbox capability identity does not match")]
    WrongCapability,
    #[error("mailbox capability does not grant the operation")]
    OperationNotAuthorized,
    #[error("mailbox capability does not grant the message kind")]
    MessageKindNotAuthorized,
    #[error("mailbox capability does not grant the content type")]
    ContentTypeNotAuthorized,
    #[error("mailbox capability payload bound was exceeded")]
    CapabilityPayloadExceeded,
    #[error("mailbox capability is not yet valid")]
    CapabilityNotYetValid,
    #[error("mailbox capability has expired")]
    CapabilityExpired,
    #[error("mailbox capability was revoked")]
    CapabilityRevoked,
    #[error("mailbox policy epoch is stale")]
    StalePolicyEpoch,
    #[error("mailbox execution epoch is stale")]
    StaleExecutionEpoch,
    #[error("mailbox message is not yet valid")]
    IssuedInFuture,
    #[error("mailbox message has expired")]
    Expired,
    #[error("mailbox message is a replay")]
    Replay,
}

impl From<MailboxContractError> for MailboxError {
    fn from(value: MailboxContractError) -> Self {
        Self::Contract(value)
    }
}

impl From<MailboxDeliveryError> for MailboxError {
    fn from(value: MailboxDeliveryError) -> Self {
        Self::DeliveryContract(value)
    }
}

fn canonical_bytes<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>, MailboxError> {
    let encoded = serde_jcs::to_vec(value).map_err(|_| MailboxError::Canonicalization)?;
    let mut bytes = Vec::with_capacity(domain.len().saturating_add(encoded.len()));
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

fn validate_inner_versions(header: &MailboxEnvelopeHeader) -> Result<(), MailboxError> {
    if header.protocol_version != ProtocolVersion(MAILBOX_PROTOCOL_VERSION) {
        return Err(MailboxError::UnsupportedProtocolVersion);
    }
    if header.signature_algorithm.0 != ED25519_ALGORITHM {
        return Err(MailboxError::UnsupportedSignatureAlgorithm);
    }
    if header.encryption.algorithm.0 != AES_256_GCM_ALGORITHM {
        return Err(MailboxError::UnsupportedEncryptionAlgorithm);
    }
    Ok(())
}

fn validate_outer_versions(envelope: &MailboxEnvelope) -> Result<(), MailboxError> {
    if envelope.routing.protocol_version.0 != MAILBOX_PROTOCOL_VERSION {
        return Err(MailboxError::UnsupportedProtocolVersion);
    }
    if envelope.encryption.algorithm.0 != AES_256_GCM_ALGORITHM {
        return Err(MailboxError::UnsupportedEncryptionAlgorithm);
    }
    Ok(())
}

fn validate_signed_object_versions(
    version: ProtocolVersion,
    signature_algorithm: mvm_contract::protocol::mailbox::SignatureAlgorithm,
) -> Result<(), MailboxError> {
    if version.0 != MAILBOX_PROTOCOL_VERSION {
        return Err(MailboxError::UnsupportedProtocolVersion);
    }
    if signature_algorithm.0 != ED25519_ALGORITHM {
        return Err(MailboxError::UnsupportedSignatureAlgorithm);
    }
    Ok(())
}

fn signature_from_slice(bytes: &[u8]) -> Result<Signature, MailboxError> {
    let signature: [u8; ED25519_SIGNATURE_BYTES] = bytes
        .try_into()
        .map_err(|_| MailboxError::SignatureInvalid)?;
    Ok(Signature::from_bytes(&signature))
}

#[derive(Serialize)]
struct EnvelopeAad<'a> {
    routing: &'a MailboxRoutingFrame,
    encryption: &'a mvm_contract::protocol::mailbox::EncryptionContext,
}

fn envelope_aad(envelope: &MailboxEnvelope) -> Result<Vec<u8>, MailboxError> {
    canonical_bytes(
        ENVELOPE_AEAD_DOMAIN,
        &EnvelopeAad {
            routing: &envelope.routing,
            encryption: &envelope.encryption,
        },
    )
}

/// Encrypt and sender-sign one immutable message.
pub fn seal_envelope(
    request: SealRequest<'_>,
    encryption_key: &Key,
    signing_key: &SigningKey,
) -> Result<MailboxEnvelope, MailboxError> {
    validate_inner_versions(&request.header)?;
    if request.routing.protocol_version.0 != MAILBOX_PROTOCOL_VERSION {
        return Err(MailboxError::UnsupportedProtocolVersion);
    }
    if request.plaintext.len() > MAX_MAILBOX_PAYLOAD_BYTES
        || request.header.plaintext_len as usize != request.plaintext.len()
    {
        return Err(MailboxError::PlaintextLengthMismatch);
    }
    if request.routing.expires_at_unix_ms != request.header.expires_at_unix_ms {
        return Err(MailboxError::Expired);
    }
    let message = MailboxMessage {
        header: request.header,
        payload: request.plaintext.to_vec(),
    };
    message.validate_bounds()?;
    let signature = signing_key.sign(&canonical_bytes(ENVELOPE_SIGNATURE_DOMAIN, &message)?);
    let signed_message = SignedMailboxMessage {
        message,
        signature: signature.to_bytes().to_vec(),
    };
    let inner = serde_jcs::to_vec(&signed_message).map_err(|_| MailboxError::Canonicalization)?;
    let ciphertext_len = u32::try_from(
        inner
            .len()
            .saturating_add(mvm_contract::protocol::mailbox::AES_256_GCM_OVERHEAD_BYTES),
    )
    .map_err(|_| MailboxError::EncodedSizeExceeded)?;
    let mut routing = request.routing;
    routing.ciphertext_len = ciphertext_len;
    let mut envelope = MailboxEnvelope {
        routing,
        encryption: signed_message.message.header.encryption.clone(),
        ciphertext_commitment: [0; 32],
        ciphertext: Vec::new(),
    };
    let aad = envelope_aad(&envelope)?;
    let ciphertext = aead::seal(encryption_key, &inner, &aad);
    let ciphertext_commitment: [u8; 32] = Sha256::digest(&ciphertext).into();
    envelope.ciphertext_commitment = ciphertext_commitment;
    envelope.ciphertext = ciphertext;
    envelope.validate_bounds()?;
    Ok(envelope)
}

/// Encode using JCS so the wire representation is deterministic.
pub fn encode_envelope(envelope: &MailboxEnvelope) -> Result<Vec<u8>, MailboxError> {
    envelope.validate_bounds()?;
    validate_outer_versions(envelope)?;
    let bytes = serde_jcs::to_vec(envelope).map_err(|_| MailboxError::Encoding)?;
    if bytes.len() > MAX_ENCODED_ENVELOPE_BYTES {
        return Err(MailboxError::EncodedSizeExceeded);
    }
    Ok(bytes)
}

/// Decode only after bounding the attacker-controlled frame.
pub fn decode_envelope(bytes: &[u8]) -> Result<MailboxEnvelope, MailboxError> {
    if bytes.len() > MAX_ENCODED_ENVELOPE_BYTES {
        return Err(MailboxError::EncodedSizeExceeded);
    }
    let envelope: MailboxEnvelope =
        serde_json::from_slice(bytes).map_err(|_| MailboxError::Decoding)?;
    envelope.validate_bounds()?;
    validate_outer_versions(&envelope)?;
    Ok(envelope)
}

/// Sign an authority-issued capability.
pub fn sign_capability(
    grant: MailboxCapabilityGrant,
    authority_key: &SigningKey,
) -> Result<SignedMailboxCapability, MailboxError> {
    grant.validate_bounds()?;
    validate_signed_object_versions(grant.protocol_version, grant.signature_algorithm)?;
    let signature = authority_key.sign(&canonical_bytes(CAPABILITY_SIGNATURE_DOMAIN, &grant)?);
    Ok(SignedMailboxCapability {
        grant,
        signature: signature.to_bytes().to_vec(),
    })
}

/// Verify an authority signature without yet applying message-specific scope.
pub fn verify_capability_signature(
    capability: &SignedMailboxCapability,
    authority_key: &VerifyingKey,
) -> Result<(), MailboxError> {
    capability.grant.validate_bounds()?;
    validate_signed_object_versions(
        capability.grant.protocol_version,
        capability.grant.signature_algorithm,
    )?;
    let signature: [u8; ED25519_SIGNATURE_BYTES] = capability
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| MailboxError::CapabilitySignatureInvalid)?;
    authority_key
        .verify(
            &canonical_bytes(CAPABILITY_SIGNATURE_DOMAIN, &capability.grant)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| MailboxError::CapabilitySignatureInvalid)
}

fn verify_identity_and_time(
    header: &MailboxEnvelopeHeader,
    context: &OpenContext,
) -> Result<(), MailboxError> {
    if header.tenant != context.expected_tenant {
        return Err(MailboxError::WrongTenant);
    }
    if header.authorization_domain != context.expected_authorization_domain {
        return Err(MailboxError::WrongAuthorizationDomain);
    }
    if header.mailbox != context.expected_mailbox {
        return Err(MailboxError::WrongMailbox);
    }
    if header.sender != context.expected_sender {
        return Err(MailboxError::WrongSender);
    }
    if header.recipient != context.expected_recipient {
        return Err(MailboxError::WrongRecipient);
    }
    if header.execution_epoch != context.current_execution_epoch {
        return Err(MailboxError::StaleExecutionEpoch);
    }
    if header.policy_epoch != context.current_policy_epoch {
        return Err(MailboxError::StalePolicyEpoch);
    }
    if context.now_unix_ms < header.issued_at_unix_ms {
        return Err(MailboxError::IssuedInFuture);
    }
    if context.now_unix_ms >= header.expires_at_unix_ms {
        return Err(MailboxError::Expired);
    }
    if !context
        .accepted_content_types
        .contains(&header.content_type)
    {
        return Err(MailboxError::UnsupportedContentType);
    }
    Ok(())
}

fn verify_capability_scope(
    header: &MailboxEnvelopeHeader,
    capability: &SignedMailboxCapability,
    context: &OpenContext,
    check_send_reference: bool,
) -> Result<(), MailboxError> {
    let grant = &capability.grant;
    if context.revoked_capabilities.contains(&grant.revocation_id) {
        return Err(MailboxError::CapabilityRevoked);
    }
    if check_send_reference && grant.capability_id != header.capability_id {
        return Err(MailboxError::WrongCapability);
    }
    if grant.issuer != context.expected_capability_issuer {
        return Err(MailboxError::WrongCapabilityIssuer);
    }
    if grant.address.tenant != header.tenant {
        return Err(MailboxError::WrongTenant);
    }
    if grant.subject != context.acting_principal {
        return Err(MailboxError::WrongCapabilitySubject);
    }
    if grant.address.authorization_domain != header.authorization_domain {
        return Err(MailboxError::WrongAuthorizationDomain);
    }
    if grant.address.mailbox != header.mailbox {
        return Err(MailboxError::WrongMailbox);
    }
    if grant.address.recipient != header.recipient {
        return Err(MailboxError::WrongRecipient);
    }
    if !grant.operations.allows(context.required_operation) {
        return Err(MailboxError::OperationNotAuthorized);
    }
    if !grant.message_kinds.contains(&header.kind) {
        return Err(MailboxError::MessageKindNotAuthorized);
    }
    if !grant.content_types.contains(&header.content_type) {
        return Err(MailboxError::ContentTypeNotAuthorized);
    }
    if header.plaintext_len > grant.max_payload_bytes {
        return Err(MailboxError::CapabilityPayloadExceeded);
    }
    if context.current_execution_epoch < grant.minimum_execution_epoch
        || context.current_execution_epoch > grant.maximum_execution_epoch
    {
        return Err(MailboxError::StaleExecutionEpoch);
    }
    if grant.policy_epoch != context.current_policy_epoch {
        return Err(MailboxError::StalePolicyEpoch);
    }
    if context.now_unix_ms < grant.not_before_unix_ms {
        return Err(MailboxError::CapabilityNotYetValid);
    }
    if context.now_unix_ms >= grant.expires_at_unix_ms {
        return Err(MailboxError::CapabilityExpired);
    }
    Ok(())
}

/// Authenticated header and plaintext from one successful canonical open.
/// This is verification under the supplied context, not a delivery receipt or
/// permission to skip a later admission check.
///
/// ```compile_fail
/// use mvm_contract::protocol::mailbox::MailboxEnvelopeHeader;
/// use mvm_core::mailbox::OpenedMailboxEnvelope;
/// fn forge(header: MailboxEnvelopeHeader, payload: Vec<u8>) -> OpenedMailboxEnvelope {
///     OpenedMailboxEnvelope { header, payload }
/// }
/// ```
#[derive(PartialEq, Eq)]
pub struct OpenedMailboxEnvelope {
    header: MailboxEnvelopeHeader,
    payload: Vec<u8>,
}

impl std::fmt::Debug for OpenedMailboxEnvelope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenedMailboxEnvelope")
            .finish_non_exhaustive()
    }
}

/// Compatibility name for a verified, opened mailbox message.
pub type OpenedMailboxMessage = OpenedMailboxEnvelope;

impl OpenedMailboxEnvelope {
    /// The exact signed header authenticated with these bytes.
    #[must_use]
    pub fn header(&self) -> &MailboxEnvelopeHeader {
        &self.header
    }

    /// The verified plaintext without copying it.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Consume the verified result, retaining the original plaintext allocation.
    #[must_use]
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

/// A fixed-size snapshot of the successful verifier's authenticated header and
/// supplied local context. This is historical verification data, not current
/// authorization, a journal commit, or permission to sign a durable receipt.
/// Accepted-content and revocation vectors are deliberately not retained.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifiedMailboxScope {
    tenant: TenantId,
    authorization_domain: AuthorizationDomainId,
    mailbox: MailboxId,
    sender: PrincipalId,
    recipient: PrincipalId,
    sender_boot: BootId,
    message_id: MessageId,
    capability_id: mvm_contract::protocol::mailbox::CapabilityId,
    encryption_key_id: [u8; 32],
    execution_epoch: ExecutionEpoch,
    policy_epoch: u64,
    expires_at_unix_ms: i64,
    acting_principal: PrincipalId,
    required_operation: MailboxOperation,
    capability_issuer: PrincipalId,
    current_execution_epoch: ExecutionEpoch,
    current_policy_epoch: u64,
    verified_at_unix_ms: i64,
}

impl std::fmt::Debug for VerifiedMailboxScope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedMailboxScope")
            .finish_non_exhaustive()
    }
}

impl VerifiedMailboxScope {
    #[must_use]
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    #[must_use]
    pub fn authorization_domain(&self) -> AuthorizationDomainId {
        self.authorization_domain
    }
    #[must_use]
    pub fn mailbox(&self) -> MailboxId {
        self.mailbox
    }
    #[must_use]
    pub fn sender(&self) -> PrincipalId {
        self.sender
    }
    #[must_use]
    pub fn recipient(&self) -> PrincipalId {
        self.recipient
    }
    #[must_use]
    pub fn sender_boot(&self) -> BootId {
        self.sender_boot
    }
    #[must_use]
    pub fn message_id(&self) -> MessageId {
        self.message_id
    }
    #[must_use]
    pub fn capability_id(&self) -> mvm_contract::protocol::mailbox::CapabilityId {
        self.capability_id
    }
    #[must_use]
    pub fn encryption_key_id(&self) -> [u8; 32] {
        self.encryption_key_id
    }
    #[must_use]
    pub fn execution_epoch(&self) -> ExecutionEpoch {
        self.execution_epoch
    }
    #[must_use]
    pub fn policy_epoch(&self) -> u64 {
        self.policy_epoch
    }
    #[must_use]
    pub fn expires_at_unix_ms(&self) -> i64 {
        self.expires_at_unix_ms
    }
    #[must_use]
    pub fn acting_principal(&self) -> PrincipalId {
        self.acting_principal
    }
    #[must_use]
    pub fn required_operation(&self) -> MailboxOperation {
        self.required_operation
    }
    #[must_use]
    pub fn capability_issuer(&self) -> PrincipalId {
        self.capability_issuer
    }
    #[must_use]
    pub fn current_execution_epoch(&self) -> ExecutionEpoch {
        self.current_execution_epoch
    }
    #[must_use]
    pub fn current_policy_epoch(&self) -> u64 {
        self.current_policy_epoch
    }
    #[must_use]
    pub fn verified_at_unix_ms(&self) -> i64 {
        self.verified_at_unix_ms
    }
}

/// Original ciphertext ownership plus exactly one canonical verified-open result.
/// The service may inspect plaintext; the journal receives only a narrow view.
/// No constructor accepts caller assertions of verification. This capsule is
/// neither Clone nor serializable/deserializable.
///
/// ```compile_fail
/// use mvm_core::mailbox::{OpenedMailboxEnvelope, VerifiedMailboxAdmission, VerifiedMailboxScope};
/// use mvm_contract::protocol::mailbox::MailboxEnvelope;
/// fn forge(envelope: MailboxEnvelope, opened: OpenedMailboxEnvelope, scope: VerifiedMailboxScope) -> VerifiedMailboxAdmission {
///     VerifiedMailboxAdmission { envelope, opened, scope }
/// }
/// ```
///
/// ```compile_fail
/// use mvm_core::mailbox::VerifiedMailboxAdmission;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<VerifiedMailboxAdmission>();
/// ```
///
/// ```compile_fail
/// use mvm_core::mailbox::VerifiedMailboxAdmission;
/// fn requires_serialize<T: serde::Serialize>() {}
/// requires_serialize::<VerifiedMailboxAdmission>();
/// ```
///
/// ```compile_fail
/// use mvm_core::mailbox::VerifiedMailboxAdmission;
/// fn requires_deserialize<T: serde::de::DeserializeOwned>() {}
/// requires_deserialize::<VerifiedMailboxAdmission>();
/// ```
pub struct VerifiedMailboxAdmission {
    envelope: MailboxEnvelope,
    opened: OpenedMailboxEnvelope,
    scope: VerifiedMailboxScope,
}

impl std::fmt::Debug for VerifiedMailboxAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedMailboxAdmission")
            .finish_non_exhaustive()
    }
}

impl VerifiedMailboxAdmission {
    /// Borrow only verified metadata and original ciphertext, never plaintext.
    #[must_use]
    pub fn journal_view(&self) -> JournalAdmissionView<'_> {
        JournalAdmissionView {
            envelope: &self.envelope,
            header: self.opened.header(),
            scope: &self.scope,
            replay_identity: ReplayIdentity::from_header(self.opened.header()),
        }
    }

    /// Service-facing plaintext access. A journal view intentionally has none.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.opened.payload()
    }

    /// Consume the capsule, preserving both original ciphertext and verified
    /// plaintext allocations. This does not create a journal or delivery result.
    #[must_use]
    pub fn into_parts(self) -> (MailboxEnvelope, OpenedMailboxEnvelope) {
        (self.envelope, self.opened)
    }
}

/// Ciphertext-only journal handoff borrowed from a canonical verified capsule.
/// Header and commitment are authenticated by canonical verification; the outer
/// envelope remains the exact admitted representation, including routing fields.
/// This view does not turn transport-mutable routing data into route authority.
/// A journal must still require actual destination/Receive scope, current
/// authorization, resource admission, durable commit, anchor and key custody.
/// In particular, a view verified for Send is not Receive admission authority.
///
/// ```compile_fail
/// use mvm_core::mailbox::{JournalAdmissionView, ReplayIdentity, VerifiedMailboxScope};
/// use mvm_contract::protocol::mailbox::{MailboxEnvelope, MailboxEnvelopeHeader};
/// fn forge<'a>(envelope: &'a MailboxEnvelope, header: &'a MailboxEnvelopeHeader, scope: &'a VerifiedMailboxScope) -> JournalAdmissionView<'a> {
///     JournalAdmissionView { envelope, header, scope, replay_identity: ReplayIdentity::from_header(header) }
/// }
/// ```
///
/// ```compile_fail
/// use mvm_core::mailbox::JournalAdmissionView;
/// fn plaintext<'a>(view: &'a JournalAdmissionView<'a>) -> &'a [u8] {
///     view.payload()
/// }
/// ```
pub struct JournalAdmissionView<'a> {
    envelope: &'a MailboxEnvelope,
    header: &'a MailboxEnvelopeHeader,
    scope: &'a VerifiedMailboxScope,
    replay_identity: ReplayIdentity,
}

impl std::fmt::Debug for JournalAdmissionView<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JournalAdmissionView")
            .finish_non_exhaustive()
    }
}

impl JournalAdmissionView<'_> {
    #[must_use]
    pub fn envelope(&self) -> &MailboxEnvelope {
        self.envelope
    }
    #[must_use]
    pub fn header(&self) -> &MailboxEnvelopeHeader {
        self.header
    }
    /// Data identity, not a replay reservation or durable admission token.
    #[must_use]
    pub fn replay_identity(&self) -> ReplayIdentity {
        self.replay_identity
    }
    #[must_use]
    pub fn ciphertext_commitment(&self) -> &[u8; 32] {
        &self.envelope.ciphertext_commitment
    }
    #[must_use]
    pub fn verified_scope(&self) -> &VerifiedMailboxScope {
        self.scope
    }
}

/// Take ownership of an envelope and run the existing canonical verifier once,
/// including its original replay decision. No ciphertext clone, second replay
/// check, alternative crypto path or context-vector clone is performed.
/// Verification under the supplied context is historical, not current permission.
/// No journal I/O, commit evidence or receipt authority is created here.
pub fn open_verified_admission(
    envelope: MailboxEnvelope,
    capability: &SignedMailboxCapability,
    context: &OpenContext,
    encryption_key: &Key,
    sender_key: &VerifyingKey,
    authority_key: &VerifyingKey,
    replay: &mut impl ReplayProtector,
) -> Result<VerifiedMailboxAdmission, MailboxError> {
    let opened = open_verified_envelope(
        &envelope,
        capability,
        context,
        encryption_key,
        sender_key,
        authority_key,
        replay,
    )?;
    let header = opened.header();
    let scope = VerifiedMailboxScope {
        tenant: header.tenant,
        authorization_domain: header.authorization_domain,
        mailbox: header.mailbox,
        sender: header.sender,
        recipient: header.recipient,
        sender_boot: header.sender_boot,
        message_id: header.message_id,
        capability_id: header.capability_id,
        encryption_key_id: header.encryption.key_id,
        execution_epoch: header.execution_epoch,
        policy_epoch: header.policy_epoch,
        expires_at_unix_ms: header.expires_at_unix_ms,
        acting_principal: context.acting_principal,
        required_operation: context.required_operation,
        capability_issuer: context.expected_capability_issuer,
        current_execution_epoch: context.current_execution_epoch,
        current_policy_epoch: context.current_policy_epoch,
        verified_at_unix_ms: context.now_unix_ms,
    };
    Ok(VerifiedMailboxAdmission {
        envelope,
        opened,
        scope,
    })
}

/// Verify an envelope and return its plaintext through the canonical open path.
pub fn open_envelope(
    envelope: &MailboxEnvelope,
    capability: &SignedMailboxCapability,
    context: &OpenContext,
    encryption_key: &Key,
    sender_key: &VerifyingKey,
    authority_key: &VerifyingKey,
    replay: &mut impl ReplayProtector,
) -> Result<Vec<u8>, MailboxError> {
    open_verified_envelope(
        envelope,
        capability,
        context,
        encryption_key,
        sender_key,
        authority_key,
        replay,
    )
    .map(OpenedMailboxEnvelope::into_payload)
}

/// Open the canonical envelope and retain its authenticated inner header.
///
/// `replay` must stage identity until journal commit; in-memory replay is
/// appropriate only for ephemeral delivery.
pub fn open_authenticated_envelope(
    envelope: &MailboxEnvelope,
    capability: &SignedMailboxCapability,
    context: &OpenContext,
    encryption_key: &Key,
    sender_key: &VerifyingKey,
    authority_key: &VerifyingKey,
    replay: &mut impl ReplayProtector,
) -> Result<OpenedMailboxMessage, MailboxError> {
    open_verified_envelope(
        envelope,
        capability,
        context,
        encryption_key,
        sender_key,
        authority_key,
        replay,
    )
}

/// Verify identities, signature, capability, current state, ciphertext, and replay.
pub fn open_verified_envelope(
    envelope: &MailboxEnvelope,
    capability: &SignedMailboxCapability,
    context: &OpenContext,
    encryption_key: &Key,
    sender_key: &VerifyingKey,
    authority_key: &VerifyingKey,
    replay: &mut impl ReplayProtector,
) -> Result<OpenedMailboxEnvelope, MailboxError> {
    envelope.validate_bounds()?;
    validate_outer_versions(envelope)?;
    let actual_commitment: [u8; 32] = Sha256::digest(&envelope.ciphertext).into();
    if actual_commitment != envelope.ciphertext_commitment {
        return Err(MailboxError::CiphertextCommitmentInvalid);
    }
    let inner = aead::open(
        encryption_key,
        &envelope.ciphertext,
        &envelope_aad(envelope)?,
    )
    .map_err(|_| MailboxError::DecryptionFailed)?;
    if inner.len() > MAX_ENCODED_ENVELOPE_BYTES {
        return Err(MailboxError::EncodedSizeExceeded);
    }
    let signed_message: SignedMailboxMessage =
        serde_json::from_slice(&inner).map_err(|_| MailboxError::Decoding)?;
    signed_message.validate_bounds()?;
    let signature = signature_from_slice(&signed_message.signature)?;
    sender_key
        .verify(
            &canonical_bytes(ENVELOPE_SIGNATURE_DOMAIN, &signed_message.message)?,
            &signature,
        )
        .map_err(|_| MailboxError::SignatureInvalid)?;
    let message = signed_message.message;
    message.validate_bounds()?;
    validate_inner_versions(&message.header)?;
    if message.header.encryption != envelope.encryption
        || message.header.expires_at_unix_ms != envelope.routing.expires_at_unix_ms
    {
        return Err(MailboxError::DecryptionFailed);
    }

    verify_identity_and_time(&message.header, context)?;
    verify_capability_signature(capability, authority_key)?;
    verify_capability_scope(&message.header, capability, context, true)?;

    if !replay.check_and_record(ReplayIdentity::from_header(&message.header)) {
        return Err(MailboxError::Replay);
    }
    Ok(OpenedMailboxEnvelope {
        header: message.header,
        payload: message.payload,
    })
}

/// Authorize a separate Receive capability for a verified signed message.
/// The header's capability ID names its original Send grant, not the reader's
/// independently issued Receive grant.
pub fn authorize_receive(
    header: &MailboxEnvelopeHeader,
    capability: &SignedMailboxCapability,
    context: &OpenContext,
    authority_key: &VerifyingKey,
) -> Result<(), MailboxError> {
    if context.required_operation != MailboxOperation::Receive {
        return Err(MailboxError::OperationNotAuthorized);
    }
    verify_identity_and_time(header, context)?;
    verify_capability_signature(capability, authority_key)?;
    verify_capability_scope(header, capability, context, false)
}

fn receipt_signature_domain(receipt: &DestinationReceipt) -> Result<&'static [u8], MailboxError> {
    receipt
        .validate_versioned_outcome()
        .map_err(MailboxError::Contract)?;
    if receipt.signature_algorithm.0 != ED25519_ALGORITHM {
        return Err(MailboxError::UnsupportedSignatureAlgorithm);
    }
    match receipt.protocol_version {
        ProtocolVersion::V1 => Ok(RECEIPT_SIGNATURE_DOMAIN),
        ProtocolVersion::V2 => Ok(LOCAL_DURABLE_RECEIPT_SIGNATURE_DOMAIN),
        _ => Err(MailboxError::UnsupportedProtocolVersion),
    }
}

/// Sign a destination receipt in its versioned outcome domain.
pub fn sign_receipt(
    receipt: DestinationReceipt,
    destination_key: &SigningKey,
) -> Result<SignedDestinationReceipt, MailboxError> {
    let domain = receipt_signature_domain(&receipt)?;
    let signature = destination_key.sign(&canonical_bytes(domain, &receipt)?);
    Ok(SignedDestinationReceipt {
        receipt,
        signature: signature.to_bytes().to_vec(),
    })
}

/// Verify a destination-signed acceptance receipt.
pub fn verify_receipt(
    signed: &SignedDestinationReceipt,
    destination_key: &VerifyingKey,
) -> Result<(), MailboxError> {
    let domain = receipt_signature_domain(&signed.receipt)?;
    let signature: [u8; ED25519_SIGNATURE_BYTES] = signed
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| MailboxError::ReceiptSignatureInvalid)?;
    destination_key
        .verify(
            &canonical_bytes(domain, &signed.receipt)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| MailboxError::ReceiptSignatureInvalid)
}
