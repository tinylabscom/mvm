//! Canonical mailbox wire types.
//!
//! This module is deliberately data-only and remains `no_std + alloc`.
//! Cryptography, clocks, replay storage, routing, and transport live in
//! `mvm_core::mailbox` and its runtime consumers.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// Current mailbox protocol version.
pub const MAILBOX_PROTOCOL_VERSION: u16 = 1;
/// Current signature algorithm identifier (Ed25519).
pub const ED25519_ALGORITHM: u16 = 1;
/// Current payload-encryption algorithm identifier (AES-256-GCM).
pub const AES_256_GCM_ALGORITHM: u16 = 1;
/// Maximum plaintext accepted by the version-one contract.
pub const MAX_MAILBOX_PAYLOAD_BYTES: usize = 1024 * 1024;
/// Maximum encoded envelope accepted before deserialization.
pub const MAX_ENCODED_ENVELOPE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum number of operations, kinds, or content types in one capability.
pub const MAX_CAPABILITY_LIST_ITEMS: usize = 32;
/// Ed25519 signature length.
pub const ED25519_SIGNATURE_BYTES: usize = 64;
/// AES-GCM framing overhead used by the runtime (`nonce || ciphertext || tag`).
pub const AES_256_GCM_OVERHEAD_BYTES: usize = 12 + 16;

macro_rules! fixed_id {
    ($name:ident, $size:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name([u8; $size]);

        impl $name {
            /// Construct from the canonical fixed-width representation.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $size]) -> Self {
                Self(bytes)
            }

            /// Borrow the canonical fixed-width representation.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $size] {
                &self.0
            }
        }
    };
}

fixed_id!(
    AuthorizationDomainId,
    32,
    "Tenant-scoped authorization domain, distinct from a fleet or route."
);
fixed_id!(
    TenantId,
    32,
    "Stable tenant identity containing authorization domains."
);
fixed_id!(MailboxId, 32, "Stable identity of one mailbox.");
fixed_id!(PrincipalId, 32, "Stable signing principal identity.");
fixed_id!(BootId, 32, "Fresh identity for one guest boot.");
fixed_id!(MessageId, 32, "Stable message identity across retries.");
fixed_id!(DeliveryId, 32, "Identity of one delivery attempt stream.");
fixed_id!(
    AuthorizationDomainRouteLabel,
    32,
    "Opaque authorization-domain label visible to mailbox routers."
);
fixed_id!(
    DestinationRouteToken,
    32,
    "Opaque destination lookup token; never mailbox authority."
);
fixed_id!(
    TransportBindingId,
    32,
    "Identity of one rotatable certified transport binding."
);
fixed_id!(
    CorrelationId,
    32,
    "Identity correlating one call and reply."
);
fixed_id!(
    CausationId,
    32,
    "Identity of the message that caused this one."
);
fixed_id!(CapabilityId, 32, "Identity of a signed capability grant.");
fixed_id!(
    RevocationId,
    32,
    "Identity used by capability revocation state."
);
fixed_id!(
    ReplayNonce,
    16,
    "Fresh sender nonce authenticated with the message; stable IDs, not this nonce, key replay detection."
);

/// Protocol version carried on every signed object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProtocolVersion(pub u16);

impl ProtocolVersion {
    pub const V1: Self = Self(MAILBOX_PROTOCOL_VERSION);
}

/// Signature algorithm carried on every signed object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignatureAlgorithm(pub u16);

impl SignatureAlgorithm {
    pub const ED25519: Self = Self(ED25519_ALGORITHM);
}

/// Payload-encryption algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptionAlgorithm(pub u16);

impl EncryptionAlgorithm {
    pub const AES_256_GCM: Self = Self(AES_256_GCM_ALGORITHM);
}

/// Monotonic activation generation for a mailbox owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct ExecutionEpoch(u64);

impl ExecutionEpoch {
    pub fn new(value: u64) -> Result<Self, MailboxContractError> {
        if value == 0 {
            return Err(MailboxContractError::ZeroExecutionEpoch);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for ExecutionEpoch {
    type Error = MailboxContractError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ExecutionEpoch> for u64 {
    fn from(value: ExecutionEpoch) -> Self {
        value.0
    }
}

/// Monotonic sequence within one declared ordering scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct SequenceNumber(u64);

impl SequenceNumber {
    pub fn new(value: u64) -> Result<Self, MailboxContractError> {
        if value == 0 {
            return Err(MailboxContractError::ZeroSequence);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for SequenceNumber {
    type Error = MailboxContractError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<SequenceNumber> for u64 {
    fn from(value: SequenceNumber) -> Self {
        value.0
    }
}

/// Address names authority and recipient, never a route or host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxAddress {
    pub tenant: TenantId,
    pub authorization_domain: AuthorizationDomainId,
    pub mailbox: MailboxId,
    pub recipient: PrincipalId,
}

/// Reply route carries both the address and the exact attenuated capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyRoute {
    pub address: MailboxAddress,
    pub capability_id: CapabilityId,
}

/// Versioned application content type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "ContentTypeWire", into = "ContentTypeWire")]
pub struct ContentType {
    name: String,
    version: u16,
}

impl ContentType {
    pub fn parse(name: impl Into<String>, version: u16) -> Result<Self, MailboxContractError> {
        let name = name.into();
        if name.is_empty() || name.len() > 127 {
            return Err(MailboxContractError::InvalidContentType);
        }
        if version == 0
            || !name.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'/' | b'.' | b'-' | b'+')
            })
            || !name.contains('/')
        {
            return Err(MailboxContractError::InvalidContentType);
        }
        Ok(Self { name, version })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentTypeWire {
    name: String,
    version: u16,
}

impl TryFrom<ContentTypeWire> for ContentType {
    type Error = MailboxContractError;

    fn try_from(value: ContentTypeWire) -> Result<Self, Self::Error> {
        Self::parse(value.name, value.version)
    }
}

impl From<ContentType> for ContentTypeWire {
    fn from(value: ContentType) -> Self {
        Self {
            name: value.name,
            version: value.version,
        }
    }
}

/// Named FIFO scope within a sender/mailbox/epoch tuple.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OrderingScope(String);

impl OrderingScope {
    pub fn parse(raw: impl Into<String>) -> Result<Self, MailboxContractError> {
        let raw = raw.into();
        if raw.is_empty()
            || raw.len() > 64
            || !raw.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b'.')
            })
        {
            return Err(MailboxContractError::InvalidOrderingScope);
        }
        Ok(Self(raw))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for OrderingScope {
    type Error = MailboxContractError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<OrderingScope> for String {
    fn from(value: OrderingScope) -> Self {
        value.0
    }
}

/// Application message semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailboxMessageKind {
    Call,
    Cast,
    Reply,
}

/// Capability operation checked independently from the message kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailboxOperation {
    Send,
    Receive,
    Reply,
    Monitor,
    Administer,
}

/// Compact operation set with a stable numeric wire representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilityOperations(u16);

impl CapabilityOperations {
    const SEND: u16 = 1 << 0;
    const RECEIVE: u16 = 1 << 1;
    const REPLY: u16 = 1 << 2;
    const MONITOR: u16 = 1 << 3;
    const ADMINISTER: u16 = 1 << 4;
    const ALL: u16 = Self::SEND | Self::RECEIVE | Self::REPLY | Self::MONITOR | Self::ADMINISTER;

    #[must_use]
    pub fn from_operations(operations: &[MailboxOperation]) -> Self {
        let mut bits = 0;
        for operation in operations {
            bits |= Self::bit(*operation);
        }
        Self(bits)
    }

    #[must_use]
    pub const fn allows(self, operation: MailboxOperation) -> bool {
        self.0 & Self::bit(operation) != 0
    }

    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.0 != 0 && self.0 & !Self::ALL == 0
    }

    const fn bit(operation: MailboxOperation) -> u16 {
        match operation {
            MailboxOperation::Send => Self::SEND,
            MailboxOperation::Receive => Self::RECEIVE,
            MailboxOperation::Reply => Self::REPLY,
            MailboxOperation::Monitor => Self::MONITOR,
            MailboxOperation::Administer => Self::ADMINISTER,
        }
    }
}

/// Explicit payload-encryption parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptionContext {
    pub algorithm: EncryptionAlgorithm,
    pub key_id: [u8; 32],
}

/// Header encrypted and authenticated inside the AEAD payload and bound by the
/// sender signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxEnvelopeHeader {
    pub protocol_version: ProtocolVersion,
    pub signature_algorithm: SignatureAlgorithm,
    pub tenant: TenantId,
    pub authorization_domain: AuthorizationDomainId,
    pub sender: PrincipalId,
    pub recipient: PrincipalId,
    pub mailbox: MailboxId,
    pub sender_boot: BootId,
    pub execution_epoch: ExecutionEpoch,
    pub message_id: MessageId,
    pub correlation_id: CorrelationId,
    pub causation_id: CausationId,
    pub kind: MailboxMessageKind,
    pub reply_to: Option<ReplyRoute>,
    pub ordering_scope: OrderingScope,
    pub sequence: SequenceNumber,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub nonce: ReplayNonce,
    pub content_type: ContentType,
    pub capability_id: CapabilityId,
    pub policy_epoch: u64,
    pub encryption: EncryptionContext,
    pub plaintext_len: u32,
}

/// Immutable inner value encrypted as a whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxMessage {
    pub header: MailboxEnvelopeHeader,
    #[serde(with = "base64_bytes")]
    pub payload: Vec<u8>,
}

/// Canonical sender-authenticated value encrypted inside [`MailboxEnvelope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedMailboxMessage {
    pub message: MailboxMessage,
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
}

impl SignedMailboxMessage {
    pub fn validate_bounds(&self) -> Result<(), MailboxContractError> {
        self.message.validate_bounds()?;
        if self.signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(MailboxContractError::InvalidSignatureLength);
        }
        Ok(())
    }
}

impl MailboxMessage {
    pub fn validate_bounds(&self) -> Result<(), MailboxContractError> {
        if self.payload.len() > MAX_MAILBOX_PAYLOAD_BYTES {
            return Err(MailboxContractError::PayloadTooLarge);
        }
        if self.header.plaintext_len as usize != self.payload.len() {
            return Err(MailboxContractError::PlaintextLengthMismatch);
        }
        if self.header.expires_at_unix_ms <= self.header.issued_at_unix_ms {
            return Err(MailboxContractError::InvalidTimeWindow);
        }
        match self.header.kind {
            MailboxMessageKind::Call if self.header.reply_to.is_none() => {
                return Err(MailboxContractError::MissingReplyRoute);
            }
            MailboxMessageKind::Cast | MailboxMessageKind::Reply
                if self.header.reply_to.is_some() =>
            {
                return Err(MailboxContractError::UnexpectedReplyRoute);
            }
            MailboxMessageKind::Call | MailboxMessageKind::Cast | MailboxMessageKind::Reply => {}
        }
        Ok(())
    }
}

/// Host-visible routing fields. No principal, mailbox, content, correlation,
/// capability, sequence, or payload-derived value appears here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxRoutingFrame {
    pub protocol_version: ProtocolVersion,
    pub authorization_domain_route_label: AuthorizationDomainRouteLabel,
    pub destination_route_token: DestinationRouteToken,
    pub delivery_id: DeliveryId,
    pub ciphertext_len: u32,
    pub padding: CiphertextPadding,
    pub expires_at_unix_ms: i64,
    pub hop_limit: u8,
    pub transport_binding_id: TransportBindingId,
}

/// Padding contract visible to routers without revealing payload semantics.
/// Version one emits exact-length ciphertext; future padded classes require a
/// protocol-versioned verifier rather than silently changing this meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CiphertextPadding {
    Exact,
}

/// Signed encrypted pass-by-value message with a host-blind inner value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxEnvelope {
    pub routing: MailboxRoutingFrame,
    pub encryption: EncryptionContext,
    pub ciphertext_commitment: [u8; 32],
    #[serde(with = "base64_bytes")]
    pub ciphertext: Vec<u8>,
}

impl MailboxEnvelope {
    pub fn validate_bounds(&self) -> Result<(), MailboxContractError> {
        if self.ciphertext.len() > MAX_ENCODED_ENVELOPE_BYTES {
            return Err(MailboxContractError::CiphertextTooLarge);
        }
        if self.routing.hop_limit == 0 {
            return Err(MailboxContractError::InvalidHopLimit);
        }
        if self.routing.ciphertext_len as usize != self.ciphertext.len() {
            return Err(MailboxContractError::CiphertextLengthMismatch);
        }
        Ok(())
    }
}

/// Capability body signed by the authorization-domain authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxCapabilityGrant {
    pub protocol_version: ProtocolVersion,
    pub signature_algorithm: SignatureAlgorithm,
    pub capability_id: CapabilityId,
    pub issuer: PrincipalId,
    pub subject: PrincipalId,
    pub address: MailboxAddress,
    pub operations: CapabilityOperations,
    pub message_kinds: Vec<MailboxMessageKind>,
    pub content_types: Vec<ContentType>,
    pub max_payload_bytes: u32,
    pub max_messages_per_minute: u32,
    pub max_outstanding_calls: u32,
    pub max_queue_contribution_bytes: u64,
    pub minimum_execution_epoch: ExecutionEpoch,
    pub maximum_execution_epoch: ExecutionEpoch,
    pub policy_epoch: u64,
    pub not_before_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub revocation_id: RevocationId,
    pub delegation_depth: u8,
}

impl MailboxCapabilityGrant {
    pub fn validate_bounds(&self) -> Result<(), MailboxContractError> {
        if !self.operations.is_valid()
            || self.message_kinds.is_empty()
            || self.message_kinds.len() > MAX_CAPABILITY_LIST_ITEMS
            || self.content_types.is_empty()
            || self.content_types.len() > MAX_CAPABILITY_LIST_ITEMS
            || self.max_payload_bytes == 0
            || self.max_payload_bytes as usize > MAX_MAILBOX_PAYLOAD_BYTES
            || self.max_messages_per_minute == 0
            || self.max_outstanding_calls == 0
            || self.max_queue_contribution_bytes == 0
        {
            return Err(MailboxContractError::InvalidCapabilityBounds);
        }
        if self.minimum_execution_epoch > self.maximum_execution_epoch {
            return Err(MailboxContractError::InvalidEpochRange);
        }
        if self.expires_at_unix_ms <= self.not_before_unix_ms {
            return Err(MailboxContractError::InvalidTimeWindow);
        }
        Ok(())
    }
}

/// Authority-signed capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedMailboxCapability {
    pub grant: MailboxCapabilityGrant,
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
}

/// Destination acceptance outcome; connection success is not acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryOutcome {
    AcceptedEphemeral,
    AcceptedDurable,
    Duplicate,
    Expired,
    Refused,
    Full,
    Unavailable,
    Late,
    DeadLettered,
}

/// Receipt body signed only by the destination mailbox authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationReceipt {
    pub protocol_version: ProtocolVersion,
    pub signature_algorithm: SignatureAlgorithm,
    pub delivery_id: DeliveryId,
    pub message_id: MessageId,
    pub address: MailboxAddress,
    pub execution_epoch: ExecutionEpoch,
    pub outcome: DeliveryOutcome,
    pub observed_at_unix_ms: i64,
    pub ciphertext_commitment: [u8; 32],
}

/// Signed destination receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDestinationReceipt {
    pub receipt: DestinationReceipt,
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
}

/// Data-only contract validation failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MailboxContractError {
    #[error("execution epoch must be nonzero")]
    ZeroExecutionEpoch,
    #[error("sequence number must be nonzero")]
    ZeroSequence,
    #[error("content type is invalid")]
    InvalidContentType,
    #[error("ordering scope is invalid")]
    InvalidOrderingScope,
    #[error("mailbox plaintext exceeds the protocol bound")]
    PayloadTooLarge,
    #[error("mailbox ciphertext exceeds the protocol bound")]
    CiphertextTooLarge,
    #[error("signature length is invalid")]
    InvalidSignatureLength,
    #[error("plaintext length does not match its signed header")]
    PlaintextLengthMismatch,
    #[error("time window is invalid")]
    InvalidTimeWindow,
    #[error("call message is missing its reply route")]
    MissingReplyRoute,
    #[error("cast message carries an unexpected reply route")]
    UnexpectedReplyRoute,
    #[error("routing hop limit must be nonzero")]
    InvalidHopLimit,
    #[error("ciphertext length does not match its authenticated routing frame")]
    CiphertextLengthMismatch,
    #[error("capability bounds are invalid")]
    InvalidCapabilityBounds,
    #[error("capability execution epoch range is invalid")]
    InvalidEpochRange,
}

impl MailboxContractError {
    /// Stable non-sensitive code suitable for logs and receipts.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ZeroExecutionEpoch => "zero_execution_epoch",
            Self::ZeroSequence => "zero_sequence",
            Self::InvalidContentType => "invalid_content_type",
            Self::InvalidOrderingScope => "invalid_ordering_scope",
            Self::PayloadTooLarge => "payload_too_large",
            Self::CiphertextTooLarge => "ciphertext_too_large",
            Self::InvalidSignatureLength => "invalid_signature_length",
            Self::PlaintextLengthMismatch => "plaintext_length_mismatch",
            Self::InvalidTimeWindow => "invalid_time_window",
            Self::MissingReplyRoute => "missing_reply_route",
            Self::UnexpectedReplyRoute => "unexpected_reply_route",
            Self::InvalidHopLimit => "invalid_hop_limit",
            Self::CiphertextLengthMismatch => "ciphertext_length_mismatch",
            Self::InvalidCapabilityBounds => "invalid_capability_bounds",
            Self::InvalidEpochRange => "invalid_epoch_range",
        }
    }
}

mod base64_bytes {
    use alloc::string::String;
    use alloc::vec::Vec;

    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(encoded.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

impl From<MailboxContractError> for String {
    fn from(value: MailboxContractError) -> Self {
        value.code().to_string()
    }
}
