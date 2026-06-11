//! Host services broker — wire envelope, error codes, and handler-config
//! enums.
//!
//! The types here cross every process boundary in the broker subprocess set
//! (`mvm-broker`, `mvm-host-signer`, `mvm-audit-signer`) plus the
//! supervisor's UDS proxies. They MUST stay in `mvm-core` so all four
//! processes can import them without pulling each other's runtime deps.
//! An algorithm-identifier byte pairs with these envelopes on the vsock
//! side.

use std::time::Duration;

use serde::{Deserialize, Serialize};

// ============================================================================
// ServiceId — `host.<name>.v<n>` reverse-DNS-like identifier
// ============================================================================

/// Reverse-DNS-like service identifier with a mandatory version segment.
///
/// Examples: `host.secrets.v1`, `host.time.v1`, `host.cost.v1`, `broker.v1`.
///
/// Strings are validated at construction so the gate code can rely on the
/// shape (in particular, the version segment is the rate-limiting parser
/// for the binding gate).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ServiceId(String);

impl ServiceId {
    /// Parse a `ServiceId` from a string. Validates the shape:
    /// `<name>(.<sub>)*.v<n>` where `<n>` is one or more ASCII digits.
    /// Two-segment forms like `broker.v1` are valid (the meta service);
    /// three-segment forms like `host.secrets.v1` are the common case
    /// for namespaced services.
    pub fn parse(raw: impl Into<String>) -> Result<Self, ServiceIdParseError> {
        let raw = raw.into();
        if raw.is_empty() {
            return Err(ServiceIdParseError::Empty);
        }
        // Must contain at least 2 dot-separated segments: `<name>.v<n>`.
        let parts: Vec<&str> = raw.split('.').collect();
        if parts.len() < 2 {
            return Err(ServiceIdParseError::MissingVersion);
        }
        let version = parts.last().expect("len >= 2 above");
        let Some(digits) = version.strip_prefix('v') else {
            return Err(ServiceIdParseError::MissingVersion);
        };
        if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
            return Err(ServiceIdParseError::MissingVersion);
        }
        // No empty segments anywhere (catches leading/trailing dots + `..`).
        if parts.iter().any(|p| p.is_empty()) {
            return Err(ServiceIdParseError::EmptySegment);
        }
        // Each segment must be ASCII alphanumeric + `-` only — keeps the
        // parser cheap and the audit-log entries readable.
        for part in &parts {
            if !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(ServiceIdParseError::IllegalCharacter);
            }
        }
        Ok(ServiceId(raw))
    }

    /// The canonical string form (e.g. `"host.secrets.v1"`).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ServiceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for ServiceId {
    type Error = ServiceIdParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<ServiceId> for String {
    fn from(value: ServiceId) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServiceIdParseError {
    #[error("ServiceId is empty")]
    Empty,
    #[error("ServiceId must end with a `.v<n>` version segment")]
    MissingVersion,
    #[error("ServiceId contains an empty segment (leading/trailing dot or `..`)")]
    EmptySegment,
    #[error("ServiceId contains a character outside [A-Za-z0-9-.]")]
    IllegalCharacter,
}

// ============================================================================
// CorrelationId — supervisor-assigned per-call identifier
// ============================================================================

/// Per-call correlation identifier, assigned by the supervisor at frame
/// ingress. Workload-supplied values are rewritten or rejected — this is
/// enforced at the broker gate, not by the type.
///
/// Wire form is a string for forward-compatibility (the supervisor today
/// formats ULIDs; a future change to Snowflake or other id format is a
/// serde-compatible widening as long as the value stays a string).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CorrelationId(String);

impl CorrelationId {
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ============================================================================
// ServiceCall — host-bound envelope
// ============================================================================

/// The host-bound envelope every broker call rides on.
///
/// The envelope itself is strictly typed (`deny_unknown_fields`); the
/// `payload` is `serde_json::Value` because per-handler payloads vary.
/// The handler's `parse_payload` step is the *real* schema gate for
/// payload contents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCall {
    pub service: ServiceId,
    pub verb: String,
    pub correlation_id: CorrelationId,
    pub payload: serde_json::Value,
}

// ============================================================================
// ServiceResponse — guest-bound envelope
// ============================================================================

/// The guest-bound envelope. Tagged variant; `Ok` carries the typed
/// response payload, `Err` carries a typed error code + message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServiceResponse {
    Ok {
        correlation_id: CorrelationId,
        payload: serde_json::Value,
    },
    Err {
        correlation_id: CorrelationId,
        code: ServiceErrorCode,
        message: String,
    },
}

impl ServiceResponse {
    pub fn correlation_id(&self) -> &CorrelationId {
        match self {
            ServiceResponse::Ok { correlation_id, .. } => correlation_id,
            ServiceResponse::Err { correlation_id, .. } => correlation_id,
        }
    }
}

// ============================================================================
// ServiceErrorCode — typed error vocabulary
// ============================================================================

/// Typed broker error codes. Audit log entries carry the code as a stable
/// snake_case string. New variants are additive; renames are wire-breaking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceErrorCode {
    /// The workload's `ExecutionPlan.services` did not bind this service.
    NotBound,
    /// The service exists in the static catalog but the verb is not
    /// implemented yet.
    NotImplemented,
    /// The handler's typed `parse_payload` rejected the payload shape.
    BadRequest,
    /// Token-bucket rate limit exceeded (gate 4).
    RateLimitExceeded,
    /// Lifetime quota for this `(workload, service)` exhausted.
    LifetimeQuotaExhausted,
    /// Bounded vsock receive queue at capacity.
    QueueFull,
    /// Handler response exceeded `response_size_cap()`.
    ResponseTooLarge,
    /// Handler call timed out per `call_timeout()`.
    Timeout,
    /// Handler-internal failure: dispatch panic, circuit-breaker open,
    /// downstream (e.g. mvmd) unavailable.
    Unavailable,
    /// Subprocess hasn't finished initial config + listener bring-up yet
    /// (bootstrap-order failure mode).
    NotReady,
    /// Service composition exceeded the depth cap.
    CompositionDepth,
    /// Service composition exceeded the width cap.
    CompositionWidth,
    /// Per-workload total-call/minute budget exceeded; escalates to audit
    /// + (optional) workload pause.
    ServiceCallAbuse,
    /// Operator revoked this workload's broker session.
    SessionRevoked,
    /// Catch-all for unexpected handler-internal errors. Never carries
    /// payload-derived information in the message.
    InternalError,
}

// ============================================================================
// Handler-side configuration enums
// ============================================================================

/// Per-handler idempotency contract. Different services tolerate different
/// retry semantics; the broker uses this to decide whether to dedup,
/// cache, or always mint fresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum Idempotency {
    /// Each call returns a fresh result. `host.secrets.v1` ships here so
    /// every credential has its own correlation + audit entry.
    MintFresh,
    /// Cache the most recent response for `ttl_ms` milliseconds.
    /// `host.cost.v1::workload` ships here at 1000ms.
    CacheRecent { ttl_ms: u32 },
    /// Reject a second call with the same `correlation_id`. The
    /// `host.audit.v1` host-logging service will ship here.
    DedupByCorrelation,
}

/// How fast the handler's audit entry needs to reach durable storage.
///
/// `PerCall` calls fsync before responding. `Batched(window)` queues the
/// entry synchronously (so a supervisor crash doesn't strand it) but
/// fsyncs in a window-driven background flush.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditDurability {
    PerCall,
    Batched(Duration),
}

impl AuditDurability {
    /// Default for non-secret services. 100ms is the standard flush window.
    pub fn default_batched() -> Self {
        AuditDurability::Batched(Duration::from_millis(100))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_id_accepts_canonical_forms() {
        for raw in [
            "host.secrets.v1",
            "host.time.v1",
            "host.cost.v1",
            "broker.v1",
            "host.logging.v2",
            "host.dev.echo.v1",
            "host.cost-aggregate.v3",
        ] {
            let id = ServiceId::parse(raw).expect(raw);
            assert_eq!(id.as_str(), raw);
        }
    }

    #[test]
    fn service_id_rejects_missing_version() {
        for raw in ["host.secrets", "host.secrets.v", "host.secrets.vX"] {
            assert_eq!(
                ServiceId::parse(raw).unwrap_err(),
                ServiceIdParseError::MissingVersion
            );
        }
    }

    #[test]
    fn service_id_rejects_empty_segments() {
        for raw in ["host..v1", ".host.v1", "host.v1."] {
            assert!(matches!(
                ServiceId::parse(raw).unwrap_err(),
                ServiceIdParseError::EmptySegment | ServiceIdParseError::MissingVersion
            ));
        }
    }

    #[test]
    fn service_id_rejects_illegal_characters() {
        for raw in ["host.secrets!.v1", "host.sec rets.v1", "host.секреты.v1"] {
            assert_eq!(
                ServiceId::parse(raw).unwrap_err(),
                ServiceIdParseError::IllegalCharacter
            );
        }
    }

    #[test]
    fn service_call_roundtrips_through_json() {
        let call = ServiceCall {
            service: ServiceId::parse("host.time.v1").unwrap(),
            verb: "now".into(),
            correlation_id: CorrelationId::new("01HBROKER0000000000000000"),
            payload: serde_json::json!({}),
        };
        let bytes = serde_json::to_vec(&call).unwrap();
        let parsed: ServiceCall = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, call);
    }

    #[test]
    fn service_call_rejects_unknown_envelope_fields() {
        let bad = serde_json::json!({
            "service": "host.time.v1",
            "verb": "now",
            "correlation_id": "01HBROKER0000000000000000",
            "payload": {},
            "extra": "field",
        });
        let err = serde_json::from_value::<ServiceCall>(bad).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn service_response_ok_roundtrips() {
        let r = ServiceResponse::Ok {
            correlation_id: CorrelationId::new("01HBROKER0000000000000000"),
            payload: serde_json::json!({"wall_ms": 1717000000000u64}),
        };
        let bytes = serde_json::to_vec(&r).unwrap();
        let parsed: ServiceResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn service_response_err_roundtrips() {
        let r = ServiceResponse::Err {
            correlation_id: CorrelationId::new("01HBROKER0000000000000000"),
            code: ServiceErrorCode::NotBound,
            message: "service host.secrets.v1 not bound to this workload".into(),
        };
        let bytes = serde_json::to_vec(&r).unwrap();
        let parsed: ServiceResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn service_error_code_round_trips_as_snake_case_strings() {
        for (code, expected) in [
            (ServiceErrorCode::NotBound, "\"not_bound\""),
            (ServiceErrorCode::NotImplemented, "\"not_implemented\""),
            (ServiceErrorCode::ResponseTooLarge, "\"response_too_large\""),
            (ServiceErrorCode::ServiceCallAbuse, "\"service_call_abuse\""),
            (ServiceErrorCode::CompositionDepth, "\"composition_depth\""),
        ] {
            let s = serde_json::to_string(&code).unwrap();
            assert_eq!(s, expected);
            let parsed: ServiceErrorCode = serde_json::from_str(&s).unwrap();
            assert_eq!(parsed, code);
        }
    }

    #[test]
    fn idempotency_round_trips() {
        for variant in [
            Idempotency::MintFresh,
            Idempotency::CacheRecent { ttl_ms: 1000 },
            Idempotency::DedupByCorrelation,
        ] {
            let s = serde_json::to_string(&variant).unwrap();
            let parsed: Idempotency = serde_json::from_str(&s).unwrap();
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn audit_durability_default_is_100ms() {
        assert_eq!(
            AuditDurability::default_batched(),
            AuditDurability::Batched(Duration::from_millis(100))
        );
    }
}
