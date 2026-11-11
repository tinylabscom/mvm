//! Canonical mailbox wire types.
//!
//! This module is deliberately data-only and remains `no_std + alloc`.
//! Cryptography, clocks, replay storage, routing, and transport live in
//! `mvm_core::mailbox` and its runtime consumers.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::plan::{Nonce, PlanId};

/// Dedicated mailbox vsock service. Its own port, so mailbox traffic never
/// shares a queue or credit with machine control (5252), `NetworkFlow` (5253),
/// telemetry (5254), display (5255) or GPU (5256).
pub const MAILBOX_PORT: u32 = 5257;
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
/// Maximum encoded delivery lease or ACK before parsing untrusted JSON.
pub const MAX_MAILBOX_DELIVERY_CONTROL_BYTES: usize = 16 * 1024;
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
fixed_id!(
    ConsumerSessionId,
    32,
    "Fresh MVM-bound authenticated reader session; a caller-supplied transport ID is not authority."
);
fixed_id!(
    DeliveryLeaseNonce,
    16,
    "Fresh nonce for one delivery lease."
);
fixed_id!(DeliveryAckNonce, 16, "Fresh nonce for one application ACK.");

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

/// Versioned ceiling on application reports, separate from the signed Send capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    try_from = "MailboxReportSendPolicyWire",
    into = "MailboxReportSendPolicyWire"
)]
pub struct MailboxReportSendPolicy {
    max_payload_bytes: u32,
}

impl MailboxReportSendPolicy {
    /// Refuses zero or values beyond the canonical plaintext ceiling.
    pub fn new(max_payload_bytes: u32) -> Result<Self, MailboxContractError> {
        if max_payload_bytes == 0 || u64::from(max_payload_bytes) > MAX_MAILBOX_PAYLOAD_BYTES as u64
        {
            return Err(MailboxContractError::InvalidReportPolicyBounds);
        }
        Ok(Self { max_payload_bytes })
    }

    #[must_use]
    pub const fn max_payload_bytes(self) -> u32 {
        self.max_payload_bytes
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MailboxReportSendPolicyWire {
    version: u16,
    max_payload_bytes: u32,
}

impl TryFrom<MailboxReportSendPolicyWire> for MailboxReportSendPolicy {
    type Error = MailboxContractError;

    fn try_from(wire: MailboxReportSendPolicyWire) -> Result<Self, Self::Error> {
        if wire.version != 1 {
            return Err(MailboxContractError::UnsupportedReportPolicyVersion);
        }
        Self::new(wire.max_payload_bytes)
    }
}

impl From<MailboxReportSendPolicy> for MailboxReportSendPolicyWire {
    fn from(policy: MailboxReportSendPolicy) -> Self {
        Self {
            version: 1,
            max_payload_bytes: policy.max_payload_bytes,
        }
    }
}

/// What a signed `ExecutionPlan` admits for one workload's mailbox: which
/// mailbox, the key whose capabilities are honored, and the execution epoch.
/// Presence grants that workload its own mailbox, including the ability for
/// the host to issue a separate boot-bound Receive capability. Absence grants
/// neither Send nor Receive. This grant is not itself a capability: the host
/// must still authenticate the current guest and sign each scoped operation.
/// Everything else the receiving node trusts (encryption and sender keys,
/// identities) is host-held and never rides in a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxGrant {
    pub mailbox: MailboxId,
    /// Ed25519 verifying key that must have signed any accepted capability.
    pub authority_key: [u8; 32],
    pub epoch: ExecutionEpoch,
    /// An absent policy does not authorize a typed application report. Omitted
    /// on older signed plans so their canonical bytes remain unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<MailboxReportSendPolicy>,
}

impl MailboxGrant {
    /// Check an application report against the signed plan's exact Cast shape.
    ///
    /// This does not verify the plan signature or the narrower signed Send
    /// capability, destination mailbox, current epoch, frame cap, or journal
    /// quota. Runtime must intersect all of those before admission.
    pub fn check_report_send(
        &self,
        kind: MailboxMessageKind,
        content_type: &ContentType,
        reply_to: Option<&ReplyRoute>,
        encoded_payload_bytes: usize,
    ) -> Result<(), MailboxContractError> {
        let policy = self.report.ok_or(MailboxContractError::ReportNotGranted)?;
        if kind != MailboxMessageKind::Cast || reply_to.is_some() {
            return Err(MailboxContractError::InvalidReportMessageKind);
        }
        if content_type.name() != crate::protocol::workload_report::WORKLOAD_REPORT_CONTENT_TYPE
            || content_type.version() != crate::protocol::workload_report::WORKLOAD_REPORT_VERSION
        {
            return Err(MailboxContractError::InvalidReportContentType);
        }
        if encoded_payload_bytes > policy.max_payload_bytes as usize {
            return Err(MailboxContractError::ReportPayloadTooLarge);
        }
        Ok(())
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

/// Versioned signature domains for guest reader enrollment, lease, and ACK.
pub const READER_ENROLLMENT_SIGNATURE_DOMAIN: &[u8] = b"mvm.mailbox.reader-enrollment.v1\0";
pub const DELIVERY_LEASE_SIGNATURE_DOMAIN: &[u8] = b"mvm.mailbox.delivery-lease.v1\0";
pub const DELIVERY_ACK_SIGNATURE_DOMAIN: &[u8] = b"mvm.mailbox.delivery-ack.v1\0";

/// Guest-held mailbox ACK key enrolled for one signed plan and fresh boot.
///
/// Host-prepared seeds are permitted only in the trusted-host profile. A
/// host-blind profile must instead release keys inside a measured guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxGuestReaderEnrollment {
    pub protocol_version: ProtocolVersion,
    pub signature_algorithm: SignatureAlgorithm,
    pub plan_id: PlanId,
    pub plan_nonce: Nonce,
    pub address: MailboxAddress,
    pub consumer: PrincipalId,
    pub consumer_boot: BootId,
    pub consumer_session: ConsumerSessionId,
    pub receive_capability_id: CapabilityId,
    pub ack_public_key: [u8; 32],
    pub execution_epoch: ExecutionEpoch,
    pub policy_epoch: u64,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}

/// Plan- and boot-derived expectations supplied by the verifying runtime.
///
/// Construct these only from an authenticated current execution; transport
/// claims and unverified plan JSON are not trusted sources of this context.
#[derive(Clone, Copy)]
pub struct MailboxGuestReaderScope<'a> {
    pub plan: &'a MailboxGrant,
    pub plan_id: &'a PlanId,
    pub plan_nonce: &'a Nonce,
    pub receive: &'a MailboxCapabilityGrant,
    pub current_boot: BootId,
    pub current_session: ConsumerSessionId,
    pub now_unix_ms: i64,
}

/// Enrollment signed by the authority pinned in the admitted mailbox grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedMailboxGuestReaderEnrollment {
    pub enrollment: MailboxGuestReaderEnrollment,
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
}

impl SignedMailboxGuestReaderEnrollment {
    fn validate_shape(&self) -> Result<(), MailboxDeliveryError> {
        let enrollment = &self.enrollment;
        if enrollment.protocol_version != ProtocolVersion::V1 {
            return Err(MailboxDeliveryError::UnsupportedVersion);
        }
        if enrollment.signature_algorithm != SignatureAlgorithm::ED25519 {
            return Err(MailboxDeliveryError::UnsupportedAlgorithm);
        }
        if self.signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(MailboxDeliveryError::InvalidSignatureLength);
        }
        if enrollment.plan_id.0.is_empty() || enrollment.plan_id.0.len() > 128 {
            return Err(MailboxDeliveryError::WrongPlanIdentity);
        }
        if enrollment.ack_public_key == [0; 32] {
            return Err(MailboxDeliveryError::InvalidReaderKey);
        }
        if enrollment.expires_at_unix_ms <= enrollment.issued_at_unix_ms {
            return Err(MailboxDeliveryError::InvalidTimeWindow);
        }
        Ok(())
    }

    /// Encodes a bounded enrollment; runtime still verifies its signature.
    pub fn encode(&self) -> Result<Vec<u8>, MailboxDeliveryError> {
        self.validate_shape()?;
        let bytes = serde_json::to_vec(self).map_err(|_| MailboxDeliveryError::Malformed)?;
        if bytes.len() > MAX_MAILBOX_DELIVERY_CONTROL_BYTES {
            return Err(MailboxDeliveryError::Oversized);
        }
        Ok(bytes)
    }

    /// Bounds an untrusted enrollment before parsing its JSON and signature.
    pub fn decode(bytes: &[u8]) -> Result<Self, MailboxDeliveryError> {
        if bytes.len() > MAX_MAILBOX_DELIVERY_CONTROL_BYTES {
            return Err(MailboxDeliveryError::Oversized);
        }
        let enrolled: Self =
            serde_json::from_slice(bytes).map_err(|_| MailboxDeliveryError::Malformed)?;
        enrolled.validate_shape()?;
        Ok(enrolled)
    }

    /// Checks structure against an authenticated current plan, boot, and reader.
    ///
    /// The runtime must verify this enrollment's signature under the plan's
    /// mailbox authority key, the Receive capability signature/revocation,
    /// and guest possession of the bound per-boot key before accepting an ACK.
    pub fn check_scope(
        &self,
        scope: &MailboxGuestReaderScope<'_>,
    ) -> Result<(), MailboxDeliveryError> {
        self.validate_shape()?;
        let enrolled = &self.enrollment;
        if enrolled.address.mailbox != scope.plan.mailbox {
            return Err(MailboxDeliveryError::WrongPlanMailbox);
        }
        if &enrolled.plan_id != scope.plan_id || &enrolled.plan_nonce != scope.plan_nonce {
            return Err(MailboxDeliveryError::WrongPlanIdentity);
        }
        if enrolled.execution_epoch != scope.plan.epoch
            || enrolled.execution_epoch < scope.receive.minimum_execution_epoch
            || enrolled.execution_epoch > scope.receive.maximum_execution_epoch
        {
            return Err(MailboxDeliveryError::StaleExecutionEpoch);
        }
        if enrolled.address != scope.receive.address {
            return Err(MailboxDeliveryError::WrongAddress);
        }
        if enrolled.consumer != scope.receive.subject {
            return Err(MailboxDeliveryError::WrongConsumer);
        }
        if enrolled.consumer_boot != scope.current_boot {
            return Err(MailboxDeliveryError::StaleConsumerBoot);
        }
        if enrolled.consumer_session != scope.current_session {
            return Err(MailboxDeliveryError::StaleConsumerSession);
        }
        if enrolled.receive_capability_id != scope.receive.capability_id {
            return Err(MailboxDeliveryError::WrongCapability);
        }
        if !scope.receive.operations.allows(MailboxOperation::Receive) {
            return Err(MailboxDeliveryError::ReceiveNotAuthorized);
        }
        if enrolled.policy_epoch != scope.receive.policy_epoch {
            return Err(MailboxDeliveryError::StalePolicyEpoch);
        }
        if scope.now_unix_ms < enrolled.issued_at_unix_ms
            || enrolled.issued_at_unix_ms < scope.receive.not_before_unix_ms
        {
            return Err(MailboxDeliveryError::NotYetValid);
        }
        if scope.now_unix_ms >= enrolled.expires_at_unix_ms
            || scope.now_unix_ms >= scope.receive.expires_at_unix_ms
            || enrolled.expires_at_unix_ms > scope.receive.expires_at_unix_ms
        {
            return Err(MailboxDeliveryError::Expired);
        }
        Ok(())
    }
}

/// One destination-issued lease to an authorized consumer of a specific message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxDeliveryLease {
    pub protocol_version: ProtocolVersion,
    pub signature_algorithm: SignatureAlgorithm,
    pub address: MailboxAddress,
    pub sender: PrincipalId,
    pub sender_boot: BootId,
    pub message_id: MessageId,
    pub delivery_id: DeliveryId,
    pub execution_epoch: ExecutionEpoch,
    pub consumer: PrincipalId,
    pub consumer_session: ConsumerSessionId,
    pub receive_capability_id: CapabilityId,
    pub policy_epoch: u64,
    pub ciphertext_commitment: [u8; 32],
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub lease_nonce: DeliveryLeaseNonce,
}

/// Lease signed by the destination mailbox authority, not by a transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedMailboxDeliveryLease {
    pub lease: MailboxDeliveryLease,
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
}

impl MailboxDeliveryLease {
    fn validate_shape(&self) -> Result<(), MailboxDeliveryError> {
        if self.protocol_version != ProtocolVersion::V1 {
            return Err(MailboxDeliveryError::UnsupportedVersion);
        }
        if self.signature_algorithm != SignatureAlgorithm::ED25519 {
            return Err(MailboxDeliveryError::UnsupportedAlgorithm);
        }
        if self.expires_at_unix_ms <= self.issued_at_unix_ms {
            return Err(MailboxDeliveryError::InvalidTimeWindow);
        }
        Ok(())
    }

    /// Checks data consistency with a verified plan and Receive capability.
    ///
    /// This does not verify signatures, authenticate the supplied current session,
    /// or check replay. The destination must do so before payload disclosure.
    pub fn check_scope(
        &self,
        plan: &MailboxGrant,
        receive: &MailboxCapabilityGrant,
        consumer_session: ConsumerSessionId,
        now_unix_ms: i64,
    ) -> Result<(), MailboxDeliveryError> {
        let lease = self;
        lease.validate_shape()?;
        if lease.address.mailbox != plan.mailbox {
            return Err(MailboxDeliveryError::WrongPlanMailbox);
        }
        if lease.execution_epoch != plan.epoch
            || lease.execution_epoch < receive.minimum_execution_epoch
            || lease.execution_epoch > receive.maximum_execution_epoch
        {
            return Err(MailboxDeliveryError::StaleExecutionEpoch);
        }
        if lease.address != receive.address {
            return Err(MailboxDeliveryError::WrongAddress);
        }
        if lease.consumer != receive.subject {
            return Err(MailboxDeliveryError::WrongConsumer);
        }
        if lease.consumer_session != consumer_session {
            return Err(MailboxDeliveryError::StaleConsumerSession);
        }
        if lease.receive_capability_id != receive.capability_id {
            return Err(MailboxDeliveryError::WrongCapability);
        }
        if !receive.operations.allows(MailboxOperation::Receive) {
            return Err(MailboxDeliveryError::ReceiveNotAuthorized);
        }
        if lease.policy_epoch != receive.policy_epoch {
            return Err(MailboxDeliveryError::StalePolicyEpoch);
        }
        if now_unix_ms < lease.issued_at_unix_ms
            || lease.issued_at_unix_ms < receive.not_before_unix_ms
            || now_unix_ms < receive.not_before_unix_ms
        {
            return Err(MailboxDeliveryError::NotYetValid);
        }
        if now_unix_ms >= lease.expires_at_unix_ms
            || now_unix_ms >= receive.expires_at_unix_ms
            || lease.expires_at_unix_ms > receive.expires_at_unix_ms
        {
            return Err(MailboxDeliveryError::Expired);
        }
        Ok(())
    }
}

impl SignedMailboxDeliveryLease {
    fn validate_shape(&self) -> Result<(), MailboxDeliveryError> {
        self.lease.validate_shape()?;
        if self.signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(MailboxDeliveryError::InvalidSignatureLength);
        }
        Ok(())
    }

    /// Encodes a bounded lease after checking its version and signature shape.
    pub fn encode(&self) -> Result<Vec<u8>, MailboxDeliveryError> {
        self.validate_shape()?;
        let bytes = serde_json::to_vec(self).map_err(|_| MailboxDeliveryError::Malformed)?;
        if bytes.len() > MAX_MAILBOX_DELIVERY_CONTROL_BYTES {
            return Err(MailboxDeliveryError::Oversized);
        }
        Ok(bytes)
    }

    /// Bounds untrusted input before parsing a destination-signed lease.
    pub fn decode(bytes: &[u8]) -> Result<Self, MailboxDeliveryError> {
        if bytes.len() > MAX_MAILBOX_DELIVERY_CONTROL_BYTES {
            return Err(MailboxDeliveryError::Oversized);
        }
        let lease: Self =
            serde_json::from_slice(bytes).map_err(|_| MailboxDeliveryError::Malformed)?;
        lease.validate_shape()?;
        Ok(lease)
    }

    /// Checks the signature length and structural scope, not signature validity.
    pub fn check_scope(
        &self,
        plan: &MailboxGrant,
        receive: &MailboxCapabilityGrant,
        consumer_session: ConsumerSessionId,
        now_unix_ms: i64,
    ) -> Result<(), MailboxDeliveryError> {
        self.validate_shape()?;
        self.lease
            .check_scope(plan, receive, consumer_session, now_unix_ms)
    }
}

/// Consumer-authored acknowledgement of the exact destination-signed lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxDeliveryAck {
    pub protocol_version: ProtocolVersion,
    pub signature_algorithm: SignatureAlgorithm,
    pub lease: SignedMailboxDeliveryLease,
    pub ack_nonce: DeliveryAckNonce,
    pub acknowledged_at_unix_ms: i64,
}

/// ACK signed by the Receive capability's consumer after application acceptance.
///
/// The consumer holds an independently scoped mailbox signing key: a local host
/// reader may hold one in host custody, a user holds their own, and a guest must
/// enroll a boot-bound key before guest ACK can be enabled. The FlowMux key is
/// not mailbox authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedMailboxDeliveryAck {
    pub ack: MailboxDeliveryAck,
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
}

/// One ACK operation per lease; changed signed ACK bytes conflict on retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxAckReplayIdentity {
    address: MailboxAddress,
    consumer: PrincipalId,
    consumer_session: ConsumerSessionId,
    delivery_id: DeliveryId,
    lease_nonce: DeliveryLeaseNonce,
}

impl SignedMailboxDeliveryAck {
    fn validate_shape(&self) -> Result<(), MailboxDeliveryError> {
        self.ack.lease.validate_shape()?;
        if self.ack.protocol_version != ProtocolVersion::V1 {
            return Err(MailboxDeliveryError::UnsupportedVersion);
        }
        if self.ack.signature_algorithm != SignatureAlgorithm::ED25519 {
            return Err(MailboxDeliveryError::UnsupportedAlgorithm);
        }
        if self.signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(MailboxDeliveryError::InvalidSignatureLength);
        }
        if self.ack.acknowledged_at_unix_ms < self.ack.lease.lease.issued_at_unix_ms
            || self.ack.acknowledged_at_unix_ms >= self.ack.lease.lease.expires_at_unix_ms
        {
            return Err(MailboxDeliveryError::AckOutsideLease);
        }
        Ok(())
    }

    /// Encodes a bounded ACK; runtime signature verification is still required.
    pub fn encode(&self) -> Result<Vec<u8>, MailboxDeliveryError> {
        self.validate_shape()?;
        let bytes = serde_json::to_vec(self).map_err(|_| MailboxDeliveryError::Malformed)?;
        if bytes.len() > MAX_MAILBOX_DELIVERY_CONTROL_BYTES {
            return Err(MailboxDeliveryError::Oversized);
        }
        Ok(bytes)
    }

    /// Bounds untrusted input before parsing a consumer-signed ACK.
    pub fn decode(bytes: &[u8]) -> Result<Self, MailboxDeliveryError> {
        if bytes.len() > MAX_MAILBOX_DELIVERY_CONTROL_BYTES {
            return Err(MailboxDeliveryError::Oversized);
        }
        let ack: Self =
            serde_json::from_slice(bytes).map_err(|_| MailboxDeliveryError::Malformed)?;
        ack.validate_shape()?;
        Ok(ack)
    }

    /// Stable key for the runtime's bounded, crash-recoverable ACK replay ledger.
    ///
    /// Use only after verifying both signatures and current reader authority.
    /// Retain the signed ACK commitment with this key: changing even the ACK
    /// nonce on retry is a conflict, not a second acknowledgement.
    #[must_use]
    pub fn replay_identity(&self) -> MailboxAckReplayIdentity {
        let lease = &self.ack.lease.lease;
        MailboxAckReplayIdentity {
            address: lease.address,
            consumer: lease.consumer,
            consumer_session: lease.consumer_session,
            delivery_id: lease.delivery_id,
            lease_nonce: lease.lease_nonce,
        }
    }

    /// Checks the nested lease and ACK time, not signatures or replay state.
    pub fn check_scope(
        &self,
        plan: &MailboxGrant,
        receive: &MailboxCapabilityGrant,
        consumer_session: ConsumerSessionId,
        now_unix_ms: i64,
    ) -> Result<(), MailboxDeliveryError> {
        self.validate_shape()?;
        self.ack
            .lease
            .check_scope(plan, receive, consumer_session, now_unix_ms)?;
        if self.ack.acknowledged_at_unix_ms > now_unix_ms {
            return Err(MailboxDeliveryError::AckOutsideLease);
        }
        Ok(())
    }
}

/// Data-only lease/ACK refusals; cryptographic and replay errors are runtime-owned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MailboxDeliveryError {
    #[error("delivery control frame exceeds the encoded bound")]
    Oversized,
    #[error("delivery control frame is malformed")]
    Malformed,
    #[error("delivery protocol version is unsupported")]
    UnsupportedVersion,
    #[error("delivery signature algorithm is unsupported")]
    UnsupportedAlgorithm,
    #[error("delivery signature length is invalid")]
    InvalidSignatureLength,
    #[error("delivery time window is invalid")]
    InvalidTimeWindow,
    #[error("delivery mailbox is absent from the signed plan")]
    WrongPlanMailbox,
    #[error("reader enrollment is bound to a different signed plan")]
    WrongPlanIdentity,
    #[error("delivery execution epoch is stale")]
    StaleExecutionEpoch,
    #[error("delivery address does not match the receive capability")]
    WrongAddress,
    #[error("delivery consumer does not match the receive capability")]
    WrongConsumer,
    #[error("reader enrollment is bound to a stale boot")]
    StaleConsumerBoot,
    #[error("delivery consumer session is stale")]
    StaleConsumerSession,
    #[error("reader enrollment signing key is invalid")]
    InvalidReaderKey,
    #[error("delivery receive capability does not match")]
    WrongCapability,
    #[error("receive operation is not authorized")]
    ReceiveNotAuthorized,
    #[error("delivery policy epoch is stale")]
    StalePolicyEpoch,
    #[error("delivery lease is not yet valid")]
    NotYetValid,
    #[error("delivery lease or capability has expired")]
    Expired,
    #[error("acknowledgement is outside its delivery lease")]
    AckOutsideLease,
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
    #[error("workload report policy version is unsupported")]
    UnsupportedReportPolicyVersion,
    #[error("workload report policy bounds are invalid")]
    InvalidReportPolicyBounds,
    #[error("workload report is not granted by the signed plan")]
    ReportNotGranted,
    #[error("workload report must be a cast without a reply route")]
    InvalidReportMessageKind,
    #[error("workload report content type is not granted")]
    InvalidReportContentType,
    #[error("workload report exceeds the signed plan ceiling")]
    ReportPayloadTooLarge,
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
            Self::UnsupportedReportPolicyVersion => "unsupported_report_policy_version",
            Self::InvalidReportPolicyBounds => "invalid_report_policy_bounds",
            Self::ReportNotGranted => "report_not_granted",
            Self::InvalidReportMessageKind => "invalid_report_message_kind",
            Self::InvalidReportContentType => "invalid_report_content_type",
            Self::ReportPayloadTooLarge => "report_payload_too_large",
        }
    }
}

mod base64_bytes {
    use alloc::string::String;
    use alloc::vec::Vec;

    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
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
