//! Durable, transport-neutral agent session and event contract.
//!
//! This module owns the semantic boundary shared by a future gateway,
//! adapter, CLI, and SDK. It is deliberately not a storage or transport
//! implementation. Durable events contain hashes, identifiers, and references
//! to the existing transcript/audit records; prompt and live-output bytes
//! never enter the durable event model.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::stream::StreamKind;

/// Wire version of the agent session contract.
pub const AGENT_SESSION_PROTOCOL_VERSION: u16 = 1;
/// Maximum prompt accepted by the contract before adapter execution.
pub const MAX_PROMPT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum live delta accepted by one ephemeral event.
pub const MAX_LIVE_DELTA_BYTES: usize = 64 * 1024;
/// Maximum events returned by one history page.
pub const MAX_HISTORY_PAGE: u32 = 256;
const MAX_ID_BYTES: usize = 128;
const MAX_RETENTION_EVENTS: u32 = 100_000;
const MAX_RETENTION_BYTES: u64 = 256 * 1024 * 1024;

macro_rules! bounded_id {
    ($name:ident, $error:ident, $label:literal) => {
        #[doc = $label]
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        #[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
        pub struct $name(String);

        impl $name {
            /// Parse an identifier accepted on the public wire.
            pub fn parse(raw: impl Into<String>) -> Result<Self, $error> {
                let raw = raw.into();
                if raw.is_empty() {
                    return Err($error::Empty);
                }
                if raw.len() > MAX_ID_BYTES {
                    return Err($error::TooLong);
                }
                if !raw.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_' | b'.')
                }) {
                    return Err($error::IllegalCharacter);
                }
                if raw.starts_with('.')
                    || raw.ends_with('.')
                    || raw.contains("..")
                    || raw.contains("/")
                {
                    return Err($error::InvalidBoundary);
                }
                Ok(Self(raw))
            }

            /// Borrow the canonical wire representation.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl TryFrom<String> for $name {
            type Error = $error;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
        #[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
        pub enum $error {
            #[error("identifier is empty")]
            Empty,
            #[error("identifier exceeds the public length limit")]
            TooLong,
            #[error("identifier contains an illegal character")]
            IllegalCharacter,
            #[error("identifier has an invalid boundary")]
            InvalidBoundary,
        }
    };
}

bounded_id!(
    AgentSessionId,
    AgentSessionIdError,
    "Stable public agent-session identifier."
);
bounded_id!(
    AgentRequestId,
    AgentRequestIdError,
    "Stable public request identifier."
);
bounded_id!(
    IdempotencyKey,
    IdempotencyKeyError,
    "Caller-supplied retry key."
);

/// Lifecycle state of an agent session. This is intentionally distinct from
/// the machine session state used to keep a microVM alive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum AgentSessionState {
    Ready,
    Running,
    Canceling,
    Unloaded,
    Completed,
    Failed,
    Canceled,
    Deleted,
}

/// Bounded retention policy for durable agent events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct RetentionPolicy {
    /// Maximum number of durable events retained for reconnect.
    pub max_events: u32,
    /// Maximum approximate encoded size of retained durable events.
    pub max_bytes: u64,
    /// Optional age limit, in milliseconds, measured against event timestamps.
    pub max_age_ms: Option<u64>,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_events: 10_000,
            max_bytes: 32 * 1024 * 1024,
            max_age_ms: Some(30 * 24 * 60 * 60 * 1000),
        }
    }
}

impl RetentionPolicy {
    fn validate(self) -> Result<Self, AgentSessionError> {
        if self.max_events == 0 || self.max_events > MAX_RETENTION_EVENTS {
            return Err(AgentSessionError::new(
                AgentSessionErrorCode::LimitExceeded,
                "retention event limit is outside the supported bounds",
            ));
        }
        if self.max_bytes == 0 || self.max_bytes > MAX_RETENTION_BYTES {
            return Err(AgentSessionError::new(
                AgentSessionErrorCode::LimitExceeded,
                "retention byte limit is outside the supported bounds",
            ));
        }
        Ok(self)
    }
}

/// A command delivered to an adapter. The prompt is transient input and is
/// never copied into a durable event by this contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum AgentSessionCommand {
    Prompt {
        request_id: AgentRequestId,
        idempotency_key: IdempotencyKey,
        prompt: Vec<u8>,
    },
    Cancel {
        request_id: AgentRequestId,
        idempotency_key: IdempotencyKey,
    },
    Unload {
        request_id: AgentRequestId,
        idempotency_key: IdempotencyKey,
    },
    Restore {
        request_id: AgentRequestId,
        idempotency_key: IdempotencyKey,
    },
    Delete {
        request_id: AgentRequestId,
        idempotency_key: IdempotencyKey,
    },
}

impl AgentSessionCommand {
    fn request(&self) -> (&AgentRequestId, &IdempotencyKey) {
        match self {
            Self::Prompt {
                request_id,
                idempotency_key,
                ..
            }
            | Self::Cancel {
                request_id,
                idempotency_key,
            }
            | Self::Unload {
                request_id,
                idempotency_key,
            }
            | Self::Restore {
                request_id,
                idempotency_key,
            }
            | Self::Delete {
                request_id,
                idempotency_key,
            } => (request_id, idempotency_key),
        }
    }

    fn fingerprint(&self) -> [u8; 32] {
        match self {
            Self::Prompt {
                request_id, prompt, ..
            } => {
                let digest = Sha256::digest(prompt);
                fingerprint_from_digest(request_id, b"prompt\0", &digest)
            }
            Self::Cancel { request_id, .. } => {
                fingerprint_from_digest(request_id, b"cancel\0", &[])
            }
            Self::Unload { request_id, .. } => {
                fingerprint_from_digest(request_id, b"unload\0", &[])
            }
            Self::Restore { request_id, .. } => {
                fingerprint_from_digest(request_id, b"restore\0", &[])
            }
            Self::Delete { request_id, .. } => {
                fingerprint_from_digest(request_id, b"delete\0", &[])
            }
        }
    }
}

/// Public evidence that a transcript record and its audit commit already
/// exist. An adapter must construct this only after both stores have durably
/// committed; the journal then publishes a reference, never the bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CommittedOutput {
    /// Stream carrying the committed record.
    pub stream_kind: StreamKind,
    /// Monotonic sequence assigned by the transcript store.
    pub stream_sequence: u64,
    /// Hash of the committed transcript record.
    pub stream_record_hash: [u8; 32],
    /// Monotonic sequence assigned by the audit store.
    pub audit_sequence: u64,
    /// Hash of the committed audit entry.
    pub audit_entry_hash: [u8; 32],
}

/// Durable event payload. No variant contains prompt or output bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum DurableAgentSessionEvent {
    Opened {
        workload_digest: [u8; 32],
    },
    PromptAccepted {
        request_id: AgentRequestId,
        idempotency_key: IdempotencyKey,
        prompt_digest: [u8; 32],
    },
    PromptCompleted {
        request_id: AgentRequestId,
        result: PromptResult,
    },
    CancelRequested {
        request_id: AgentRequestId,
        idempotency_key: IdempotencyKey,
    },
    Canceled,
    Unloaded {
        request_id: AgentRequestId,
        idempotency_key: IdempotencyKey,
    },
    Restored {
        request_id: AgentRequestId,
        idempotency_key: IdempotencyKey,
    },
    Deleted {
        request_id: AgentRequestId,
        idempotency_key: IdempotencyKey,
    },
    Failed {
        code: AgentFailureCode,
    },
    OutputAvailable {
        output: CommittedOutput,
    },
    /// Policy and approval lifecycle data shares the session cursor instead
    /// of creating a second request/response stream.
    Approval {
        event: Box<crate::policy::approval::AgentApprovalEvent>,
    },
}

/// Result class for a completed prompt. Error detail is intentionally a
/// closed code vocabulary so adapter errors cannot leak data into history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum PromptResult {
    Succeeded,
    Failed,
    Canceled,
}

/// Adapter failure classes safe to expose in ordinary session history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum AgentFailureCode {
    AdapterFailure,
    PartialDelivery,
    UnsupportedVersion,
}

/// Live-only event payload. These envelopes are never added to journal
/// history and are safe to drop during reconnect; the cursor resumes from
/// the last durable event instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum EphemeralAgentSessionEvent {
    LiveDelta { payload: Vec<u8> },
    Progress { completed: u32, total: Option<u32> },
}

/// Versioned discriminated event envelope shared by all transports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct AgentSessionEventEnvelope {
    /// Wire version used to decode this envelope.
    pub protocol_version: u16,
    /// Stable public session identity.
    pub session_id: AgentSessionId,
    /// Sequence for durable events; absent for live-only events.
    pub durable_sequence: Option<u64>,
    /// Sequence for live-only events; absent for durable events.
    pub live_sequence: Option<u64>,
    /// UTC wall-clock timestamp supplied by the owning service.
    pub occurred_unix_ms: u64,
    /// Discriminated durable or ephemeral payload.
    pub event: AgentSessionEvent,
}

/// Durable or ephemeral event payload in the envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "durability", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum AgentSessionEvent {
    Durable { event: DurableAgentSessionEvent },
    Ephemeral { event: EphemeralAgentSessionEvent },
}

impl AgentSessionEventEnvelope {
    /// Validate version, sequence, and payload size invariants.
    pub fn validate(&self) -> Result<(), AgentSessionError> {
        if self.protocol_version != AGENT_SESSION_PROTOCOL_VERSION {
            return Err(AgentSessionError::new(
                AgentSessionErrorCode::UnsupportedVersion,
                "unsupported agent session protocol version",
            ));
        }
        match &self.event {
            AgentSessionEvent::Durable { event } => {
                if self.durable_sequence.is_none() || self.live_sequence.is_some() {
                    return Err(AgentSessionError::new(
                        AgentSessionErrorCode::MalformedEvent,
                        "durable events require only a durable sequence",
                    ));
                }
                if let DurableAgentSessionEvent::Approval { event } = event {
                    event
                        .validate()
                        .map_err(|code| AgentSessionError::new(code, "malformed approval event"))?;
                }
            }
            AgentSessionEvent::Ephemeral { event } => {
                if self.durable_sequence.is_some() || self.live_sequence.is_none() {
                    return Err(AgentSessionError::new(
                        AgentSessionErrorCode::MalformedEvent,
                        "ephemeral events require only a live sequence",
                    ));
                }
                if let EphemeralAgentSessionEvent::LiveDelta { payload } = event
                    && payload.len() > MAX_LIVE_DELTA_BYTES
                {
                    return Err(AgentSessionError::new(
                        AgentSessionErrorCode::LimitExceeded,
                        "live delta exceeds the bounded event size",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Cursor identifying the last durable event observed by a reader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct AgentSessionCursor {
    /// Session whose event stream the cursor addresses.
    pub session_id: AgentSessionId,
    /// Last durable sequence observed by the reader.
    pub durable_sequence: u64,
}

/// One bounded history response for reconnecting readers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct AgentSessionHistoryPage {
    /// Durable events after the requested cursor.
    pub events: Vec<AgentSessionEventEnvelope>,
    /// Cursor to use for the next page.
    pub next_cursor: AgentSessionCursor,
    /// Oldest durable sequence still retained by the journal.
    pub oldest_sequence: u64,
    /// Whether more retained events remain after this page.
    pub has_more: bool,
}

/// Stable error vocabulary for session, cursor, adapter, and delivery paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum AgentSessionErrorCode {
    MalformedEvent,
    StaleCursor,
    DuplicateRequest,
    AdapterFailure,
    Cancellation,
    PartialDelivery,
    Unauthorized,
    InvalidState,
    LimitExceeded,
    NotFound,
    UnsupportedVersion,
    SessionDeleted,
}

/// Sanitized error returned by contract operations. The message is owned by
/// the contract and never includes caller payloads or adapter diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct AgentSessionError {
    /// Stable machine-readable error class.
    pub code: AgentSessionErrorCode,
    /// Sanitized human-readable detail.
    pub message: String,
}

impl AgentSessionError {
    fn new(code: AgentSessionErrorCode, message: &str) -> Self {
        Self {
            code,
            message: message.to_string(),
        }
    }
}

impl fmt::Display for AgentSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl core::error::Error for AgentSessionError {}

impl fmt::Display for AgentSessionErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MalformedEvent => "malformed_event",
            Self::StaleCursor => "stale_cursor",
            Self::DuplicateRequest => "duplicate_request",
            Self::AdapterFailure => "adapter_failure",
            Self::Cancellation => "cancellation",
            Self::PartialDelivery => "partial_delivery",
            Self::Unauthorized => "unauthorized",
            Self::InvalidState => "invalid_state",
            Self::LimitExceeded => "limit_exceeded",
            Self::NotFound => "not_found",
            Self::UnsupportedVersion => "unsupported_version",
            Self::SessionDeleted => "session_deleted",
        })
    }
}

/// Result of applying a mutating command. A duplicate retry returns the
/// original sequence range with `applied = false`; adapters must not execute
/// the request again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct AgentCommandOutcome {
    /// False when this call was an idempotent retry.
    pub applied: bool,
    /// First durable sequence produced by the command.
    pub first_sequence: Option<u64>,
    /// Last durable sequence produced by the command.
    pub last_sequence: Option<u64>,
    /// State after the command or retry was resolved.
    pub state: AgentSessionState,
}

#[derive(Debug, Clone)]
struct SeenRequest {
    key: IdempotencyKey,
    fingerprint: [u8; 32],
    first_sequence: Option<u64>,
    last_sequence: Option<u64>,
}

/// In-memory reference state machine used by adapters and conformance tests.
/// A production adapter persists each returned durable envelope through the
/// existing transcript/audit stores before publishing it, then reconstructs
/// this state with [`Self::from_history`] after restart.
#[derive(Debug, Clone)]
pub struct AgentSessionJournal {
    session_id: AgentSessionId,
    state: AgentSessionState,
    retention: RetentionPolicy,
    events: Vec<AgentSessionEventEnvelope>,
    retained_bytes: u64,
    next_sequence: u64,
    next_live_sequence: u64,
    seen_requests: Vec<SeenRequest>,
    active_request: Option<AgentRequestId>,
}

impl AgentSessionJournal {
    /// Open a new session and append its first durable event.
    pub fn open(
        session_id: AgentSessionId,
        workload_digest: [u8; 32],
        now_unix_ms: u64,
        retention: RetentionPolicy,
    ) -> Result<(Self, AgentSessionEventEnvelope), AgentSessionError> {
        let retention = retention.validate()?;
        let mut journal = Self {
            session_id,
            state: AgentSessionState::Ready,
            retention,
            events: Vec::new(),
            retained_bytes: 0,
            next_sequence: 1,
            next_live_sequence: 1,
            seen_requests: Vec::new(),
            active_request: None,
        };
        let event = journal.append_durable(
            DurableAgentSessionEvent::Opened { workload_digest },
            now_unix_ms,
        )?;
        Ok((journal, event))
    }

    /// Rebuild state from a contiguous durable history after adapter restart.
    pub fn from_history(
        session_id: AgentSessionId,
        history: Vec<AgentSessionEventEnvelope>,
        retention: RetentionPolicy,
    ) -> Result<Self, AgentSessionError> {
        let retention = retention.validate()?;
        if history.is_empty() {
            return Err(AgentSessionError::new(
                AgentSessionErrorCode::NotFound,
                "session history is empty",
            ));
        }
        let mut journal = Self {
            session_id: session_id.clone(),
            state: AgentSessionState::Ready,
            retention,
            events: Vec::new(),
            retained_bytes: 0,
            next_sequence: 1,
            next_live_sequence: 1,
            seen_requests: Vec::new(),
            active_request: None,
        };
        for envelope in history {
            envelope.validate()?;
            if envelope.session_id != session_id
                || !matches!(envelope.event, AgentSessionEvent::Durable { .. })
                || envelope.durable_sequence != Some(journal.next_sequence)
            {
                return Err(AgentSessionError::new(
                    AgentSessionErrorCode::MalformedEvent,
                    "session history is not contiguous durable history",
                ));
            }
            if let AgentSessionEvent::Durable { event } = &envelope.event {
                let sequence = envelope
                    .durable_sequence
                    .expect("validated durable sequence");
                journal.replay_state(event, sequence)?;
            }
            journal.push_event(envelope)?;
            journal.next_sequence = journal.next_sequence.saturating_add(1);
        }
        Ok(journal)
    }

    /// Apply one idempotent command and return its durable sequence range.
    pub fn apply(
        &mut self,
        command: AgentSessionCommand,
        now_unix_ms: u64,
    ) -> Result<AgentCommandOutcome, AgentSessionError> {
        if matches!(self.state, AgentSessionState::Deleted) {
            return Err(AgentSessionError::new(
                AgentSessionErrorCode::SessionDeleted,
                "session has been deleted",
            ));
        }
        if let AgentSessionCommand::Prompt { prompt, .. } = &command
            && prompt.len() > MAX_PROMPT_BYTES
        {
            return Err(AgentSessionError::new(
                AgentSessionErrorCode::LimitExceeded,
                "prompt exceeds the bounded input size",
            ));
        }
        let (_, key) = command.request();
        let fingerprint = command.fingerprint();
        if let Some(previous) = self
            .seen_requests
            .iter()
            .find(|request| request.key == *key)
        {
            if previous.fingerprint != fingerprint {
                return Err(AgentSessionError::new(
                    AgentSessionErrorCode::DuplicateRequest,
                    "idempotency key was reused for a different request",
                ));
            }
            return Ok(AgentCommandOutcome {
                applied: false,
                first_sequence: previous.first_sequence,
                last_sequence: previous.last_sequence,
                state: self.state,
            });
        }

        let first = self.next_sequence;
        match &command {
            AgentSessionCommand::Prompt {
                request_id,
                idempotency_key,
                prompt,
            } => {
                if !matches!(
                    self.state,
                    AgentSessionState::Ready | AgentSessionState::Completed
                ) {
                    return Err(self.invalid_state());
                }
                let prompt_digest = Sha256::digest(prompt).into();
                self.append_durable(
                    DurableAgentSessionEvent::PromptAccepted {
                        request_id: request_id.clone(),
                        idempotency_key: idempotency_key.clone(),
                        prompt_digest,
                    },
                    now_unix_ms,
                )?;
                self.state = AgentSessionState::Running;
                self.active_request = Some(request_id.clone());
            }
            AgentSessionCommand::Cancel {
                request_id,
                idempotency_key,
            } => {
                if !matches!(
                    self.state,
                    AgentSessionState::Ready | AgentSessionState::Running
                ) {
                    return Err(self.invalid_state());
                }
                self.append_durable(
                    DurableAgentSessionEvent::CancelRequested {
                        request_id: request_id.clone(),
                        idempotency_key: idempotency_key.clone(),
                    },
                    now_unix_ms,
                )?;
                self.state = AgentSessionState::Canceling;
            }
            AgentSessionCommand::Unload {
                request_id,
                idempotency_key,
            } => {
                if !matches!(
                    self.state,
                    AgentSessionState::Ready
                        | AgentSessionState::Completed
                        | AgentSessionState::Canceled
                        | AgentSessionState::Failed
                ) {
                    return Err(self.invalid_state());
                }
                self.append_durable(
                    DurableAgentSessionEvent::Unloaded {
                        request_id: request_id.clone(),
                        idempotency_key: idempotency_key.clone(),
                    },
                    now_unix_ms,
                )?;
                self.state = AgentSessionState::Unloaded;
            }
            AgentSessionCommand::Restore {
                request_id,
                idempotency_key,
            } => {
                if !matches!(self.state, AgentSessionState::Unloaded) {
                    return Err(self.invalid_state());
                }
                self.append_durable(
                    DurableAgentSessionEvent::Restored {
                        request_id: request_id.clone(),
                        idempotency_key: idempotency_key.clone(),
                    },
                    now_unix_ms,
                )?;
                self.state = AgentSessionState::Ready;
            }
            AgentSessionCommand::Delete {
                request_id,
                idempotency_key,
            } => {
                self.append_durable(
                    DurableAgentSessionEvent::Deleted {
                        request_id: request_id.clone(),
                        idempotency_key: idempotency_key.clone(),
                    },
                    now_unix_ms,
                )?;
                self.state = AgentSessionState::Deleted;
            }
        }
        let last = self.next_sequence.saturating_sub(1);
        self.seen_requests.push(SeenRequest {
            key: key.clone(),
            fingerprint,
            first_sequence: Some(first),
            last_sequence: Some(last),
        });
        Ok(AgentCommandOutcome {
            applied: true,
            first_sequence: Some(first),
            last_sequence: Some(last),
            state: self.state,
        })
    }

    /// Complete the currently running prompt without storing result details.
    pub fn complete_prompt(
        &mut self,
        request_id: AgentRequestId,
        result: PromptResult,
        now_unix_ms: u64,
    ) -> Result<AgentSessionEventEnvelope, AgentSessionError> {
        if !matches!(self.state, AgentSessionState::Running) {
            return Err(self.invalid_state());
        }
        let expected_request = self.active_request.as_ref().ok_or_else(|| {
            AgentSessionError::new(
                AgentSessionErrorCode::MalformedEvent,
                "running session has no active request",
            )
        })?;
        if expected_request != &request_id {
            return Err(AgentSessionError::new(
                AgentSessionErrorCode::InvalidState,
                "completion does not match the active request",
            ));
        }
        let event = self.append_durable(
            DurableAgentSessionEvent::PromptCompleted { request_id, result },
            now_unix_ms,
        )?;
        self.state = match result {
            PromptResult::Succeeded => AgentSessionState::Completed,
            PromptResult::Failed => AgentSessionState::Failed,
            PromptResult::Canceled => AgentSessionState::Canceled,
        };
        self.active_request = None;
        Ok(event)
    }

    /// Confirm cancellation after the adapter has stopped execution.
    pub fn confirm_cancel(
        &mut self,
        now_unix_ms: u64,
    ) -> Result<AgentSessionEventEnvelope, AgentSessionError> {
        if !matches!(self.state, AgentSessionState::Canceling) {
            return Err(AgentSessionError::new(
                AgentSessionErrorCode::Cancellation,
                "session is not waiting for cancellation confirmation",
            ));
        }
        let event = self.append_durable(DurableAgentSessionEvent::Canceled, now_unix_ms)?;
        self.state = AgentSessionState::Canceled;
        self.active_request = None;
        Ok(event)
    }

    /// Publish a reference to an already committed transcript/audit record.
    pub fn record_committed_output(
        &mut self,
        output: CommittedOutput,
        now_unix_ms: u64,
    ) -> Result<AgentSessionEventEnvelope, AgentSessionError> {
        if matches!(self.state, AgentSessionState::Deleted) {
            return Err(AgentSessionError::new(
                AgentSessionErrorCode::SessionDeleted,
                "session has been deleted",
            ));
        }
        self.append_durable(
            DurableAgentSessionEvent::OutputAvailable { output },
            now_unix_ms,
        )
    }

    /// Append a policy or approval event to this session's durable history.
    /// The event shares the same monotonic cursor as every other durable
    /// session event and cannot be appended after deletion.
    pub fn record_approval_event(
        &mut self,
        event: crate::policy::approval::AgentApprovalEvent,
        now_unix_ms: u64,
    ) -> Result<AgentSessionEventEnvelope, AgentSessionError> {
        if matches!(self.state, AgentSessionState::Deleted) {
            return Err(AgentSessionError::new(
                AgentSessionErrorCode::SessionDeleted,
                "session has been deleted",
            ));
        }
        self.append_durable(
            DurableAgentSessionEvent::Approval {
                event: Box::new(event),
            },
            now_unix_ms,
        )
    }

    /// Produce a live-only event. It is never retained by this journal.
    pub fn live_delta(
        &mut self,
        payload: Vec<u8>,
        now_unix_ms: u64,
    ) -> Result<AgentSessionEventEnvelope, AgentSessionError> {
        if payload.len() > MAX_LIVE_DELTA_BYTES {
            return Err(AgentSessionError::new(
                AgentSessionErrorCode::LimitExceeded,
                "live delta exceeds the bounded event size",
            ));
        }
        let envelope = AgentSessionEventEnvelope {
            protocol_version: AGENT_SESSION_PROTOCOL_VERSION,
            session_id: self.session_id.clone(),
            durable_sequence: None,
            live_sequence: Some(self.next_live_sequence),
            occurred_unix_ms: now_unix_ms,
            event: AgentSessionEvent::Ephemeral {
                event: EphemeralAgentSessionEvent::LiveDelta { payload },
            },
        };
        envelope.validate()?;
        self.next_live_sequence = self.next_live_sequence.saturating_add(1);
        Ok(envelope)
    }

    /// Read durable history after `cursor`; `None` starts at the oldest event.
    pub fn history(
        &self,
        cursor: Option<AgentSessionCursor>,
        limit: u32,
    ) -> Result<AgentSessionHistoryPage, AgentSessionError> {
        if limit == 0 || limit > MAX_HISTORY_PAGE {
            return Err(AgentSessionError::new(
                AgentSessionErrorCode::LimitExceeded,
                "history page limit is outside the supported bounds",
            ));
        }
        let oldest = self
            .events
            .first()
            .and_then(|event| event.durable_sequence)
            .unwrap_or(self.next_sequence);
        let after = match cursor {
            Some(cursor) if cursor.session_id != self.session_id => {
                return Err(AgentSessionError::new(
                    AgentSessionErrorCode::MalformedEvent,
                    "cursor belongs to another session",
                ));
            }
            Some(cursor) if cursor.durable_sequence.saturating_add(1) < oldest => {
                return Err(AgentSessionError::new(
                    AgentSessionErrorCode::StaleCursor,
                    "cursor points before retained history",
                ));
            }
            Some(cursor) if cursor.durable_sequence >= self.next_sequence => {
                return Err(AgentSessionError::new(
                    AgentSessionErrorCode::MalformedEvent,
                    "cursor is ahead of session history",
                ));
            }
            Some(cursor) => cursor.durable_sequence,
            None => oldest.saturating_sub(1),
        };
        let start = self
            .events
            .iter()
            .position(|event| {
                event
                    .durable_sequence
                    .is_some_and(|sequence| sequence > after)
            })
            .unwrap_or(self.events.len());
        let limit = usize::try_from(limit).expect("history page limit fits usize");
        let end = core::cmp::min(start.saturating_add(limit), self.events.len());
        let events = self.events[start..end].to_vec();
        let last = events
            .last()
            .and_then(|event| event.durable_sequence)
            .unwrap_or(after);
        Ok(AgentSessionHistoryPage {
            events,
            next_cursor: AgentSessionCursor {
                session_id: self.session_id.clone(),
                durable_sequence: last,
            },
            oldest_sequence: oldest,
            has_more: end < self.events.len(),
        })
    }

    /// Current state of the journal.
    #[must_use]
    pub fn state(&self) -> AgentSessionState {
        self.state
    }

    /// Public session identity.
    #[must_use]
    pub fn session_id(&self) -> &AgentSessionId {
        &self.session_id
    }

    fn invalid_state(&self) -> AgentSessionError {
        AgentSessionError::new(
            AgentSessionErrorCode::InvalidState,
            "command is not valid in the current session state",
        )
    }

    fn append_durable(
        &mut self,
        event: DurableAgentSessionEvent,
        now_unix_ms: u64,
    ) -> Result<AgentSessionEventEnvelope, AgentSessionError> {
        let envelope = AgentSessionEventEnvelope {
            protocol_version: AGENT_SESSION_PROTOCOL_VERSION,
            session_id: self.session_id.clone(),
            durable_sequence: Some(self.next_sequence),
            live_sequence: None,
            occurred_unix_ms: now_unix_ms,
            event: AgentSessionEvent::Durable { event },
        };
        envelope.validate()?;
        self.push_event(envelope.clone())?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.evict(now_unix_ms);
        Ok(envelope)
    }

    fn push_event(&mut self, envelope: AgentSessionEventEnvelope) -> Result<(), AgentSessionError> {
        let bytes = serde_json::to_vec(&envelope).map_err(|_| {
            AgentSessionError::new(
                AgentSessionErrorCode::MalformedEvent,
                "durable event could not be encoded",
            )
        })?;
        let size = u64::try_from(bytes.len()).map_err(|_| {
            AgentSessionError::new(
                AgentSessionErrorCode::LimitExceeded,
                "durable event size cannot be represented",
            )
        })?;
        if size > self.retention.max_bytes {
            return Err(AgentSessionError::new(
                AgentSessionErrorCode::LimitExceeded,
                "durable event exceeds retention byte limit",
            ));
        }
        self.retained_bytes = self.retained_bytes.saturating_add(size);
        self.events.push(envelope);
        Ok(())
    }

    fn evict(&mut self, now_unix_ms: u64) {
        let max_events =
            usize::try_from(self.retention.max_events).expect("retention event limit fits usize");
        while self.events.len() > max_events
            || self.retained_bytes > self.retention.max_bytes
            || (!self.events.is_empty()
                && self.retention.max_age_ms.is_some_and(|age| {
                    now_unix_ms.saturating_sub(self.events[0].occurred_unix_ms) > age
                }))
        {
            if self.events.is_empty() {
                break;
            }
            let removed = self.events.remove(0);
            if let Ok(bytes) = serde_json::to_vec(&removed) {
                let size = u64::try_from(bytes.len()).expect("encoded event length fits u64");
                self.retained_bytes = self.retained_bytes.saturating_sub(size);
            }
        }
    }

    fn replay_state(
        &mut self,
        event: &DurableAgentSessionEvent,
        sequence: u64,
    ) -> Result<(), AgentSessionError> {
        if self.next_sequence == 1 && !matches!(event, DurableAgentSessionEvent::Opened { .. }) {
            return Err(AgentSessionError::new(
                AgentSessionErrorCode::MalformedEvent,
                "session history must begin with an open event",
            ));
        }
        match event {
            DurableAgentSessionEvent::Opened { .. } if self.next_sequence != 1 => {
                Err(AgentSessionError::new(
                    AgentSessionErrorCode::MalformedEvent,
                    "session has more than one open event",
                ))
            }
            DurableAgentSessionEvent::Opened { .. } => {
                self.state = AgentSessionState::Ready;
                Ok(())
            }
            DurableAgentSessionEvent::PromptAccepted {
                request_id,
                idempotency_key,
                prompt_digest,
            } => {
                if !matches!(
                    self.state,
                    AgentSessionState::Ready | AgentSessionState::Completed
                ) || self.active_request.is_some()
                {
                    return Err(AgentSessionError::new(
                        AgentSessionErrorCode::MalformedEvent,
                        "prompt was accepted in an invalid session state",
                    ));
                }
                self.state = AgentSessionState::Running;
                self.active_request = Some(request_id.clone());
                self.seen_requests.push(SeenRequest {
                    key: idempotency_key.clone(),
                    fingerprint: fingerprint_from_digest(request_id, b"prompt\0", prompt_digest),
                    first_sequence: Some(sequence),
                    last_sequence: Some(sequence),
                });
                Ok(())
            }
            DurableAgentSessionEvent::PromptCompleted {
                request_id, result, ..
            } => {
                if self.state != AgentSessionState::Running
                    || self.active_request.as_ref() != Some(request_id)
                {
                    return Err(AgentSessionError::new(
                        AgentSessionErrorCode::MalformedEvent,
                        "prompt completion does not match the active request",
                    ));
                }
                self.state = match result {
                    PromptResult::Succeeded => AgentSessionState::Completed,
                    PromptResult::Failed => AgentSessionState::Failed,
                    PromptResult::Canceled => AgentSessionState::Canceled,
                };
                self.active_request = None;
                Ok(())
            }
            DurableAgentSessionEvent::CancelRequested {
                request_id,
                idempotency_key,
            } => {
                if !matches!(
                    self.state,
                    AgentSessionState::Ready | AgentSessionState::Running
                ) {
                    return Err(AgentSessionError::new(
                        AgentSessionErrorCode::MalformedEvent,
                        "cancellation was requested in an invalid session state",
                    ));
                }
                self.state = AgentSessionState::Canceling;
                self.seen_requests.push(SeenRequest {
                    key: idempotency_key.clone(),
                    fingerprint: fingerprint_from_digest(request_id, b"cancel\0", &[]),
                    first_sequence: Some(sequence),
                    last_sequence: Some(sequence),
                });
                Ok(())
            }
            DurableAgentSessionEvent::Canceled => {
                if self.state != AgentSessionState::Canceling {
                    return Err(AgentSessionError::new(
                        AgentSessionErrorCode::MalformedEvent,
                        "cancellation completed without a cancellation request",
                    ));
                }
                self.state = AgentSessionState::Canceled;
                self.active_request = None;
                Ok(())
            }
            DurableAgentSessionEvent::Unloaded {
                request_id,
                idempotency_key,
            } => {
                if !matches!(
                    self.state,
                    AgentSessionState::Ready
                        | AgentSessionState::Completed
                        | AgentSessionState::Canceled
                        | AgentSessionState::Failed
                ) {
                    return Err(AgentSessionError::new(
                        AgentSessionErrorCode::MalformedEvent,
                        "unload was recorded in an invalid session state",
                    ));
                }
                self.state = AgentSessionState::Unloaded;
                self.record_replayed_command(request_id, idempotency_key, b"unload\0", sequence);
                Ok(())
            }
            DurableAgentSessionEvent::Restored {
                request_id,
                idempotency_key,
            } => {
                if self.state != AgentSessionState::Unloaded {
                    return Err(AgentSessionError::new(
                        AgentSessionErrorCode::MalformedEvent,
                        "restore was recorded in an invalid session state",
                    ));
                }
                self.state = AgentSessionState::Ready;
                self.record_replayed_command(request_id, idempotency_key, b"restore\0", sequence);
                Ok(())
            }
            DurableAgentSessionEvent::Deleted {
                request_id,
                idempotency_key,
            } => {
                if self.state == AgentSessionState::Deleted {
                    return Err(AgentSessionError::new(
                        AgentSessionErrorCode::MalformedEvent,
                        "session was deleted more than once",
                    ));
                }
                self.state = AgentSessionState::Deleted;
                self.record_replayed_command(request_id, idempotency_key, b"delete\0", sequence);
                Ok(())
            }
            DurableAgentSessionEvent::Failed { .. } => {
                self.state = AgentSessionState::Failed;
                Ok(())
            }
            DurableAgentSessionEvent::OutputAvailable { .. }
                if self.state != AgentSessionState::Deleted =>
            {
                Ok(())
            }
            DurableAgentSessionEvent::OutputAvailable { .. } => Err(AgentSessionError::new(
                AgentSessionErrorCode::MalformedEvent,
                "output was recorded after session deletion",
            )),
            DurableAgentSessionEvent::Approval { .. } => Ok(()),
        }
    }

    fn record_replayed_command(
        &mut self,
        request_id: &AgentRequestId,
        idempotency_key: &IdempotencyKey,
        operation: &[u8],
        sequence: u64,
    ) {
        self.seen_requests.push(SeenRequest {
            key: idempotency_key.clone(),
            fingerprint: fingerprint_from_digest(request_id, operation, &[]),
            first_sequence: Some(sequence),
            last_sequence: Some(sequence),
        });
    }
}

fn fingerprint_from_digest(
    request_id: &AgentRequestId,
    operation: &[u8],
    payload_digest: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(request_id.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(operation);
    hasher.update(payload_digest);
    hasher.finalize().into()
}

/// Hash a prompt without retaining its bytes.
#[must_use]
pub fn prompt_digest(prompt: &[u8]) -> [u8; 32] {
    Sha256::digest(prompt).into()
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn session() -> AgentSessionId {
        AgentSessionId::parse("session-1").expect("valid session id")
    }

    fn request(raw: &str) -> AgentRequestId {
        AgentRequestId::parse(raw).expect("valid request id")
    }

    fn key(raw: &str) -> IdempotencyKey {
        IdempotencyKey::parse(raw).expect("valid idempotency key")
    }

    fn prompt() -> AgentSessionCommand {
        AgentSessionCommand::Prompt {
            request_id: request("request-1"),
            idempotency_key: key("retry-1"),
            prompt: b"private prompt".to_vec(),
        }
    }

    #[test]
    fn every_public_event_round_trips() {
        let (mut journal, opened) =
            AgentSessionJournal::open(session(), [7; 32], 10, RetentionPolicy::default())
                .expect("open");
        let applied = journal.apply(prompt(), 11).expect("prompt");
        let completed = journal
            .complete_prompt(request("request-1"), PromptResult::Succeeded, 12)
            .expect("complete");
        let live = journal
            .live_delta(vec![b'l', b'i', b'v', b'e'], 13)
            .expect("live");
        for event in [opened, completed, live] {
            let json = serde_json::to_string(&event).expect("encode event");
            let back: AgentSessionEventEnvelope =
                serde_json::from_str(&json).expect("decode event");
            assert_eq!(event, back);
            back.validate().expect("valid event");
        }
        assert!(applied.applied);
    }

    #[test]
    fn prompt_bytes_are_digest_only_in_durable_history() {
        let (mut journal, _) =
            AgentSessionJournal::open(session(), [0; 32], 1, RetentionPolicy::default())
                .expect("open");
        journal.apply(prompt(), 2).expect("prompt");
        let page = journal.history(None, 10).expect("history");
        let json = serde_json::to_string(&page).expect("encode history");
        assert!(!json.contains("private prompt"));
        assert!(json.contains("prompt_digest"));
    }

    #[test]
    fn duplicate_retry_is_not_reexecuted_and_conflicting_key_is_rejected() {
        let (mut journal, _) =
            AgentSessionJournal::open(session(), [0; 32], 1, RetentionPolicy::default())
                .expect("open");
        let first = journal.apply(prompt(), 2).expect("first prompt");
        let retry = journal.apply(prompt(), 3).expect("retry prompt");
        assert!(first.applied);
        assert!(!retry.applied);
        assert_eq!(first.first_sequence, retry.first_sequence);
        let conflict = AgentSessionCommand::Prompt {
            request_id: request("request-2"),
            idempotency_key: key("retry-1"),
            prompt: b"other prompt".to_vec(),
        };
        assert_eq!(
            journal.apply(conflict, 4).expect_err("conflict").code,
            AgentSessionErrorCode::DuplicateRequest
        );
    }

    #[test]
    fn cursor_history_reconnects_and_restart_replays_state() {
        let policy = RetentionPolicy {
            max_events: 16,
            max_bytes: 1024 * 1024,
            max_age_ms: None,
        };
        let (mut journal, _) =
            AgentSessionJournal::open(session(), [0; 32], 1, policy).expect("open");
        journal.apply(prompt(), 2).expect("prompt");
        journal
            .complete_prompt(request("request-1"), PromptResult::Succeeded, 3)
            .expect("complete");
        let first_page = journal.history(None, 2).expect("first page");
        assert!(first_page.has_more);
        let second_page = journal
            .history(Some(first_page.next_cursor.clone()), 2)
            .expect("second page");
        assert_eq!(second_page.events.len(), 1);
        let rebuilt = AgentSessionJournal::from_history(
            session(),
            [first_page.events, second_page.events].concat(),
            policy,
        )
        .expect("rebuild after restart");
        assert_eq!(rebuilt.state(), AgentSessionState::Completed);
    }

    #[test]
    fn restart_restores_idempotency_for_prompt_and_cancel() {
        let policy = RetentionPolicy {
            max_events: 16,
            max_bytes: 1024 * 1024,
            max_age_ms: None,
        };
        let (mut journal, _) =
            AgentSessionJournal::open(session(), [0; 32], 1, policy).expect("open");
        let first_prompt = journal.apply(prompt(), 2).expect("prompt");
        let prompt_history = journal
            .history(None, MAX_HISTORY_PAGE)
            .expect("prompt history");
        let mut rebuilt =
            AgentSessionJournal::from_history(session(), prompt_history.events, policy)
                .expect("rebuild prompt");
        let prompt_retry = rebuilt.apply(prompt(), 3).expect("prompt retry");
        assert!(!prompt_retry.applied);
        assert_eq!(prompt_retry.first_sequence, first_prompt.first_sequence);

        let cancel = AgentSessionCommand::Cancel {
            request_id: request("cancel-1"),
            idempotency_key: key("cancel-retry-1"),
        };
        let first_cancel = rebuilt.apply(cancel.clone(), 5).expect("cancel");
        let cancel_history = rebuilt
            .history(None, MAX_HISTORY_PAGE)
            .expect("cancel history");
        let mut restarted =
            AgentSessionJournal::from_history(session(), cancel_history.events, policy)
                .expect("rebuild cancel");
        let cancel_retry = restarted.apply(cancel, 6).expect("cancel retry");
        assert!(!cancel_retry.applied);
        assert_eq!(cancel_retry.first_sequence, first_cancel.first_sequence);
    }

    #[test]
    fn retention_makes_old_cursor_stale_without_reusing_sequences() {
        let policy = RetentionPolicy {
            max_events: 2,
            max_bytes: 1024 * 1024,
            max_age_ms: None,
        };
        let (mut journal, _) =
            AgentSessionJournal::open(session(), [0; 32], 1, policy).expect("open");
        journal.apply(prompt(), 2).expect("prompt");
        journal
            .complete_prompt(request("request-1"), PromptResult::Succeeded, 3)
            .expect("complete");
        assert_eq!(
            journal
                .history(
                    Some(AgentSessionCursor {
                        session_id: session(),
                        durable_sequence: 0
                    }),
                    2
                )
                .expect_err("evicted cursor")
                .code,
            AgentSessionErrorCode::StaleCursor
        );
        let page = journal.history(None, 2).expect("remaining history");
        assert!(page.oldest_sequence > 1);
        assert!(
            page.events
                .iter()
                .all(|event| event.durable_sequence.unwrap_or(0) > 1)
        );
    }

    #[test]
    fn malformed_sequence_or_durability_is_rejected() {
        let mut envelope = AgentSessionEventEnvelope {
            protocol_version: AGENT_SESSION_PROTOCOL_VERSION,
            session_id: session(),
            durable_sequence: Some(1),
            live_sequence: Some(1),
            occurred_unix_ms: 1,
            event: AgentSessionEvent::Durable {
                event: DurableAgentSessionEvent::Canceled,
            },
        };
        assert_eq!(
            envelope.validate().expect_err("two sequences").code,
            AgentSessionErrorCode::MalformedEvent
        );
        envelope.durable_sequence = None;
        assert_eq!(
            envelope.validate().expect_err("missing live sequence").code,
            AgentSessionErrorCode::MalformedEvent
        );
    }

    #[test]
    fn committed_output_contains_hashes_but_not_payload() {
        let (mut journal, _) =
            AgentSessionJournal::open(session(), [0; 32], 1, RetentionPolicy::default())
                .expect("open");
        let event = journal
            .record_committed_output(
                CommittedOutput {
                    stream_kind: StreamKind::Stdout,
                    stream_sequence: 4,
                    stream_record_hash: [1; 32],
                    audit_sequence: 8,
                    audit_entry_hash: [2; 32],
                },
                2,
            )
            .expect("output reference");
        let json = serde_json::to_string(&event).expect("encode output reference");
        assert!(!json.contains("payload"));
        assert!(json.contains("stream_record_hash"));
    }
}
