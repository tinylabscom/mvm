//! Versioned application results and errors carried as canonical mailbox payloads.
//!
//! This is content inside a `MailboxMessageKind::Cast`, not another envelope or
//! admission path. The receiver must verify the signed mailbox envelope and
//! match this identity to the admitted plan before trusting the report.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use crate::plan::{Nonce, PlanId};
use crate::protocol::mailbox::{ContentType, MAX_MAILBOX_PAYLOAD_BYTES, MessageId};

/// Content type used in the enclosing signed mailbox header.
pub const WORKLOAD_REPORT_CONTENT_TYPE: &str = "application/vnd.mvm.workload-report";
/// Version of the application report body, independent of the mailbox protocol.
pub const WORKLOAD_REPORT_VERSION: u16 = 1;

/// Identifies one report within an admitted execution and its mailbox message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportIdentity {
    pub plan_id: PlanId,
    pub plan_nonce: Nonce,
    pub message_id: MessageId,
}

/// Stable, payload-free application failure code.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ReportErrorCode(String);

impl core::fmt::Debug for ReportErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ReportErrorCode([redacted])")
    }
}

impl ReportErrorCode {
    /// Rejects free-form exception text; details belong in the encrypted payload.
    pub fn parse(value: &str) -> Result<Self, ReportError> {
        if value.is_empty()
            || value.len() > 64
            || !value.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.')
            })
        {
            return Err(ReportError::InvalidErrorCode);
        }
        Ok(Self(value.to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ReportErrorCode {
    type Error = ReportError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<ReportErrorCode> for String {
    fn from(value: ReportErrorCode) -> Self {
        value.0
    }
}

/// Application-authored outcome; host-observed exit and publication are separate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportKind {
    Result,
    Error { code: ReportErrorCode },
}

/// Bounded, immutable application content inside an authenticated mailbox cast.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ReportWire", into = "ReportWire")]
pub struct WorkloadReport {
    identity: ReportIdentity,
    kind: ReportKind,
    content_type: ContentType,
    payload: Vec<u8>,
}

impl core::fmt::Debug for WorkloadReport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WorkloadReport")
            .field("kind", &self.kind)
            .field("payload_len", &self.payload.len())
            .finish_non_exhaustive()
    }
}

impl WorkloadReport {
    /// Builds a report that fits the canonical mailbox plaintext bound.
    ///
    /// The transport frame and signed capability may impose a smaller limit;
    /// those are checked by destination admission, never assumed here.
    pub fn new(
        identity: ReportIdentity,
        kind: ReportKind,
        content_type: ContentType,
        payload: Vec<u8>,
    ) -> Result<Self, ReportError> {
        let report = Self {
            identity,
            kind,
            content_type,
            payload,
        };
        report.validate()?;
        Ok(report)
    }

    #[must_use]
    pub fn identity(&self) -> &ReportIdentity {
        &self.identity
    }

    /// Compares the untrusted report claim with identity from the verified plan and envelope.
    pub fn verify_identity(&self, expected: &ReportIdentity) -> Result<(), ReportError> {
        if &self.identity != expected {
            return Err(ReportError::WrongIdentity);
        }
        Ok(())
    }

    #[must_use]
    pub fn kind(&self) -> &ReportKind {
        &self.kind
    }

    #[must_use]
    pub fn content_type(&self) -> &ContentType {
        &self.content_type
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Encodes one complete report body; the caller must publish it as a Cast.
    pub fn encode(&self) -> Result<Vec<u8>, ReportError> {
        let bytes = serde_json::to_vec(self).map_err(|_| ReportError::Malformed)?;
        if bytes.len() > MAX_MAILBOX_PAYLOAD_BYTES {
            return Err(ReportError::Oversized);
        }
        Ok(bytes)
    }

    /// Bounds input before parsing an untrusted report body.
    pub fn decode(bytes: &[u8]) -> Result<Self, ReportError> {
        if bytes.len() > MAX_MAILBOX_PAYLOAD_BYTES {
            return Err(ReportError::Oversized);
        }
        let wire: ReportWire = serde_json::from_slice(bytes).map_err(|_| ReportError::Malformed)?;
        Self::try_from(wire)
    }

    fn validate(&self) -> Result<(), ReportError> {
        if self.identity.plan_id.0.is_empty() || self.identity.plan_id.0.len() > 128 {
            return Err(ReportError::InvalidPlanId);
        }
        if self.payload.len() > MAX_MAILBOX_PAYLOAD_BYTES {
            return Err(ReportError::Oversized);
        }
        self.encode().map(|_| ())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportWire {
    schema_version: u16,
    identity: ReportIdentity,
    kind: ReportKind,
    content_type: ContentType,
    payload_b64: String,
}

impl From<WorkloadReport> for ReportWire {
    fn from(report: WorkloadReport) -> Self {
        Self {
            schema_version: WORKLOAD_REPORT_VERSION,
            identity: report.identity,
            kind: report.kind,
            content_type: report.content_type,
            payload_b64: BASE64.encode(report.payload),
        }
    }
}

impl TryFrom<ReportWire> for WorkloadReport {
    type Error = ReportError;

    fn try_from(wire: ReportWire) -> Result<Self, Self::Error> {
        if wire.schema_version != WORKLOAD_REPORT_VERSION {
            return Err(ReportError::UnsupportedVersion);
        }
        if wire.payload_b64.len() > MAX_MAILBOX_PAYLOAD_BYTES {
            return Err(ReportError::Oversized);
        }
        let payload = BASE64
            .decode(wire.payload_b64.as_bytes())
            .map_err(|_| ReportError::Malformed)?;
        Self::new(wire.identity, wire.kind, wire.content_type, payload)
    }
}

/// Payload-free refusal when a report cannot be represented or admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReportError {
    #[error("workload report is malformed")]
    Malformed,
    #[error("workload report version is unsupported")]
    UnsupportedVersion,
    #[error("workload report error code is invalid")]
    InvalidErrorCode,
    #[error("workload report plan identity is invalid")]
    InvalidPlanId,
    #[error("workload report identity does not match admission")]
    WrongIdentity,
    #[error("workload report exceeds the mailbox plaintext limit")]
    Oversized,
}
