//! Mailbox codec and cryptographic verification.
//!
//! The wire DTOs live in `mvm-contract`; this module owns the host-side
//! cryptographic work, bounded decoding, capability enforcement, and replay
//! seam. It performs no routing, storage, or network I/O.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mvm_contract::protocol::mailbox::{
    AES_256_GCM_ALGORITHM, AuthorizationDomainId, BootId, ContentType, DestinationReceipt,
    ED25519_ALGORITHM, ED25519_SIGNATURE_BYTES, ExecutionEpoch, MAILBOX_PROTOCOL_VERSION,
    MAX_ENCODED_ENVELOPE_BYTES, MAX_MAILBOX_PAYLOAD_BYTES, MailboxCapabilityGrant,
    MailboxContractError, MailboxEnvelope, MailboxEnvelopeHeader, MailboxId, MailboxMessage,
    MailboxOperation, MailboxRoutingFrame, MessageId, PrincipalId, ProtocolVersion, RevocationId,
    SignedDestinationReceipt, SignedMailboxCapability, SignedMailboxMessage, TenantId,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::crypto::aead::{self, Key};

const ENVELOPE_SIGNATURE_DOMAIN: &[u8] = b"mvm.mailbox.envelope.v1\0";
const CAPABILITY_SIGNATURE_DOMAIN: &[u8] = b"mvm.mailbox.capability.v1\0";
const RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"mvm.mailbox.receipt.v1\0";
const ENVELOPE_AEAD_DOMAIN: &[u8] = b"mvm.mailbox.payload.v1\0";

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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
    #[error("mailbox sender signature is invalid")]
    SignatureInvalid,
    #[error("mailbox capability signature is invalid")]
    CapabilitySignatureInvalid,
    #[error("destination receipt signature is invalid")]
    ReceiptSignatureInvalid,
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
) -> Result<(), MailboxError> {
    let grant = &capability.grant;
    if context.revoked_capabilities.contains(&grant.revocation_id) {
        return Err(MailboxError::CapabilityRevoked);
    }
    if grant.capability_id != header.capability_id {
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

/// Verify identities, signature, capability, current state, ciphertext, and
/// replay identity before returning plaintext.
pub fn open_envelope(
    envelope: &MailboxEnvelope,
    capability: &SignedMailboxCapability,
    context: &OpenContext,
    encryption_key: &Key,
    sender_key: &VerifyingKey,
    authority_key: &VerifyingKey,
    replay: &mut impl ReplayProtector,
) -> Result<Vec<u8>, MailboxError> {
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
    verify_capability_scope(&message.header, capability, context)?;

    if !replay.check_and_record(ReplayIdentity::from_header(&message.header)) {
        return Err(MailboxError::Replay);
    }
    Ok(message.payload)
}

/// Sign a destination receipt in a domain distinct from envelopes and grants.
pub fn sign_receipt(
    receipt: DestinationReceipt,
    destination_key: &SigningKey,
) -> Result<SignedDestinationReceipt, MailboxError> {
    validate_signed_object_versions(receipt.protocol_version, receipt.signature_algorithm)?;
    let signature = destination_key.sign(&canonical_bytes(RECEIPT_SIGNATURE_DOMAIN, &receipt)?);
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
    validate_signed_object_versions(
        signed.receipt.protocol_version,
        signed.receipt.signature_algorithm,
    )?;
    let signature: [u8; ED25519_SIGNATURE_BYTES] = signed
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| MailboxError::ReceiptSignatureInvalid)?;
    destination_key
        .verify(
            &canonical_bytes(RECEIPT_SIGNATURE_DOMAIN, &signed.receipt)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| MailboxError::ReceiptSignatureInvalid)
}
