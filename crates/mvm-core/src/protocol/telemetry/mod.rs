//! Versioned guest telemetry records. These are observations, never authority.
//!
//! Memory profile: allocation-conscious worker-side wire representation, bounded
//! by text/list ceilings and a total JSON byte ceiling. Not an allocation-free
//! producer API. No recursive attribute values or guest-authored host identity.
//! Structural validation is not redaction: source and host policy must run too.

mod bounded;
mod record;

pub use bounded::{BoundedList, Text};
pub use record::{TelemetryRecord, TelemetryRecordBuilder};

use serde::{Deserialize, Serialize};

use crate::trace_context::TraceContext;

/// Dedicated telemetry service; never multiplexed onto control or audit queues.
pub const TELEMETRY_PORT: u32 = 5254;
/// Maximum JSON bytes for one record, before encryption.
pub const MAX_RECORD_BYTES: usize = 32 * 1024;
/// Maximum JSON object/array nesting, including unknown fields.
pub const MAX_RECORD_DEPTH: usize = 8;
/// Maximum attributes on one record.
pub const MAX_ATTRIBUTES: usize = 16;
/// Maximum links on a span-open record.
pub const MAX_LINKS: usize = 8;
/// Maximum raw bytes in one stdout/stderr record.
pub const MAX_STDIO_BYTES: usize = 4096;
/// Bounded label or attribute key.
pub type Label = Text<128>;
/// Bounded diagnostic/attribute text.
pub type Message = Text<2048>;
/// Bounded primitive attributes, without nested arrays/maps.
pub type Attributes = BoundedList<Attribute, MAX_ATTRIBUTES>;

/// Payload-free failures safe to report at an untrusted wire boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// Count or byte ceiling exceeded.
    #[error("telemetry capacity exceeded")]
    Capacity,
    /// Wrong version, unknown fields/variants or malformed data.
    #[error("invalid telemetry record")]
    Invalid,
    /// Missing required metadata or invalid producer/context identifier.
    #[error("invalid telemetry identity")]
    Identity,
}

/// Fresh nonzero producer incarnation; replaced after process start or restore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "[u8; 16]", into = "[u8; 16]")]
pub struct ProducerEpoch([u8; 16]);

impl ProducerEpoch {
    /// Validate an epoch minted using the runtime's cryptographic RNG.
    pub fn new(value: [u8; 16]) -> Result<Self, RecordError> {
        if value == [0; 16] {
            return Err(RecordError::Identity);
        }
        Ok(Self(value))
    }
}
impl TryFrom<[u8; 16]> for ProducerEpoch {
    type Error = RecordError;
    fn try_from(value: [u8; 16]) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl From<ProducerEpoch> for [u8; 16] {
    fn from(value: ProducerEpoch) -> Self {
        value.0
    }
}

/// Validated correlation context, reusing the product's trace/span identifiers.
/// Encoded as a canonical version-00 traceparent with flags 01; not permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Text<55>", into = "String")]
pub struct TraceReference(TraceContext);

impl TraceReference {
    /// Validate both identifiers before accepting correlation data.
    pub fn new(context: TraceContext) -> Result<Self, RecordError> {
        if context.trace_id.0 == [0; 16] || context.span_id.0 == [0; 8] {
            return Err(RecordError::Identity);
        }
        Ok(Self(context))
    }
    /// Borrow-free access to the existing context type.
    pub fn context(self) -> TraceContext {
        self.0
    }
}
impl TryFrom<Text<55>> for TraceReference {
    type Error = RecordError;
    fn try_from(value: Text<55>) -> Result<Self, Self::Error> {
        let context =
            TraceContext::parse_traceparent(value.as_str()).map_err(|_| RecordError::Identity)?;
        if context.to_traceparent() != value.as_str() {
            return Err(RecordError::Identity);
        }
        Self::new(context)
    }
}
impl From<TraceReference> for String {
    fn from(value: TraceReference) -> Self {
        value.0.to_traceparent()
    }
}

/// Finite floating-point attribute; JSON cannot represent NaN or infinities.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "f64", into = "f64")]
pub struct FiniteFloat(f64);
impl TryFrom<f64> for FiniteFloat {
    type Error = RecordError;
    fn try_from(value: f64) -> Result<Self, Self::Error> {
        if !value.is_finite() {
            return Err(RecordError::Invalid);
        }
        Ok(Self(value))
    }
}
impl From<FiniteFloat> for f64 {
    fn from(value: FiniteFloat) -> Self {
        value.0
    }
}

/// Closed, non-recursive typed attribute value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AttributeValue {
    /// Boolean value.
    Bool(bool),
    /// Signed integer without floating-point precision loss.
    Signed(i64),
    /// Unsigned integer without floating-point precision loss.
    Unsigned(u64),
    /// Finite floating-point value.
    Float(FiniteFloat),
    /// Bounded text after source policy.
    Text(Message),
}
impl AttributeValue {
    /// Construct a finite float or refuse values JSON cannot preserve.
    pub fn float(value: f64) -> Result<Self, RecordError> {
        Ok(Self::Float(value.try_into()?))
    }
}

/// One policy-approved key/value. Field count and string lengths are bounded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attribute {
    /// Source-policy-approved key.
    pub key: Label,
    /// Typed value; arbitrary user `Debug` formatting is not part of this contract.
    pub value: AttributeValue,
}

/// Guest source class, checked against host registration before retention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Guest control daemon.
    GuestAgent,
    /// Guest helper process.
    GuestHelper,
    /// Instrumented Rust workload.
    RustWorkload,
    /// Supported SDK adapter.
    Sdk,
    /// Workload pipe capture.
    Stdio,
    /// Authenticated initialization/boot producer.
    Init,
}

/// Structured severity shared by events and supported log adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// Most verbose.
    Trace,
    /// Diagnostic.
    Debug,
    /// Informational.
    Info,
    /// Warning.
    Warn,
    /// Error.
    Error,
}

/// Reported span result; missing close records remain incomplete on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanOutcome {
    /// No explicit success/error result.
    Unset,
    /// Explicit success.
    Ok,
    /// Explicit failure.
    Error,
}

/// Pipe identity, not an arbitrary descriptor or host stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StdioStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// Observable producer coverage. A startup record alone does not certify coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    /// Producer initialized.
    Started,
    /// Producer stopped cleanly.
    Stopped,
    /// Known interval without capture.
    Unavailable,
    /// Capture is partially impaired.
    Degraded,
}

/// Guest-owned loss stages. A guest cannot author host-retention/export loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestLossStage {
    /// Source policy.
    Source,
    /// Producer queue/field capture.
    Capture,
    /// Pipe drain handoff.
    Pipe,
    /// Guest transport worker.
    Transport,
}

/// Explicit reason for lost or transformed observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LossReason {
    /// Intentionally filtered.
    Filtered,
    /// Explicit sampling policy.
    Sampled,
    /// Record/field truncation.
    Truncated,
    /// Queue/count/byte ceiling.
    Capacity,
    /// Malformed or disallowed record.
    Rejected,
    /// Disconnection or capture failure.
    Unavailable,
}

/// Whether a loss summary can account for the entire observed interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TailState {
    /// Counts cover the observed loss interval.
    Known,
    /// A crash/partial write leaves additional loss unknowable.
    Unknown,
}

/// Closed telemetry signal family. No payload authorizes an operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecordBody {
    /// New span, including remote parent and causal links.
    SpanOpen {
        /// Span identity.
        context: TraceReference,
        /// Optional parent identity.
        parent: Option<TraceReference>,
        /// Policy-approved operation name.
        name: Label,
        /// Initial attributes.
        attributes: Attributes,
        /// Bounded causal links.
        links: BoundedList<TraceReference, MAX_LINKS>,
    },
    /// Incremental attributes for an existing span.
    SpanUpdate {
        /// Span identity.
        context: TraceReference,
        /// Changed attributes.
        attributes: Attributes,
    },
    /// Actual producer close, not a host-fabricated successful completion.
    SpanClose {
        /// Span identity.
        context: TraceReference,
        /// Explicit result.
        outcome: SpanOutcome,
    },
    /// Structured event, including events outside any span.
    Event {
        /// Optional correlation.
        context: Option<TraceReference>,
        /// Severity.
        level: Level,
        /// Policy-approved event name.
        name: Label,
        /// Typed event fields.
        attributes: Attributes,
    },
    /// Supported log record, distinct from a span or event.
    Log {
        /// Optional correlation.
        context: Option<TraceReference>,
        /// Severity.
        level: Level,
        /// Source-sanitized text.
        message: Message,
        /// Typed log fields.
        attributes: Attributes,
    },
    /// Source-sanitized binary pipe chunk; no UTF-8 assumption.
    Stdio {
        /// Pipe identity.
        stream: StdioStream,
        /// At most one bounded chunk.
        bytes: BoundedList<u8, MAX_STDIO_BYTES>,
    },
    /// Producer liveness or explicit capture gap.
    Coverage {
        /// Current status.
        state: CoverageState,
        /// Policy-approved machine-readable reason/source code.
        code: Label,
    },
    /// Delta since the producer's previous summary; never an ACK.
    Loss {
        /// Guest-owned stage.
        stage: GuestLossStage,
        /// Why observations were lost.
        reason: LossReason,
        /// Known lost record count.
        records: u64,
        /// Known lost byte count.
        bytes: u64,
        /// Completeness of these counts.
        tail: TailState,
    },
}
