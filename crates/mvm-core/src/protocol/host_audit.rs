//! `host.audit.v1` payload types — workload-emitted audit entries.
//!
//! Two verbs:
//!
//! - `emit` — one entry. Payload is [`EmitRequest`]; response is
//!   [`EmitResponse`] carrying the new `chain_head`.
//! - `emit_batch` — up to [`BROKER_AUDIT_BATCH_MAX`] entries totalling
//!   at most [`BROKER_AUDIT_BATCH_BYTES`]. Payload is
//!   [`EmitBatchRequest`]; response is [`EmitBatchResponse`] carrying
//!   the final `chain_head` plus a per-entry status array.
//!
//! Per-record cap: [`BROKER_AUDIT_RECORD_BYTES`]. Workloads exceeding
//! the cap get `ServiceErrorCode::BadRequest` on `emit`; on
//! `emit_batch`, the offending entry's slot carries
//! [`EmitErrorCode::RecordTooLarge`] and subsequent entries are
//! [`EmitBatchEntryStatus::Skipped`].
//!
//! `workload_id` and `tenant_id` are deliberately absent from the
//! payloads — the broker handler fills them in from the supervisor's
//! `ServiceCallCtx` so a workload can't spoof another workload's id.
//! `session_id` and `correlation_id` are also broker-filled.
//!
//! Per-entry `category` IS accepted but is forced to `workload_audit`
//! by the broker handler before forwarding to the audit-signer. A
//! workload that supplies any other category gets it overridden; the
//! payload still parses for forward-compat with future workload-side
//! tagging within the `workload_audit` umbrella.

use serde::{Deserialize, Serialize};

// ============================================================================
// Constants
// ============================================================================

/// Maximum bytes per entry (the JCS-canonical serialised form of
/// `fields`).
pub const BROKER_AUDIT_RECORD_BYTES: usize = 4096;

/// Maximum entries per `emit_batch` call.
pub const BROKER_AUDIT_BATCH_MAX: usize = 100;

/// Maximum total bytes across all entries in one `emit_batch` call.
pub const BROKER_AUDIT_BATCH_BYTES: usize = 256 * 1024;

/// Workload-side rate limit, tokens per second per workload.
pub const BROKER_AUDIT_TOKENS_PER_SEC: u32 = 20;

// ============================================================================
// Single-entry verb
// ============================================================================

/// Payload for `host.audit.v1::emit`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct EmitRequest {
    /// Wall-clock timestamp in RFC 3339 form. The broker handler
    /// records its own timestamp in addition for clock-jump detection.
    pub ts: String,
    /// Typed workload-supplied fields. The broker treats them as opaque
    /// JSON; they're carried verbatim into the chain entry's `fields`
    /// after the per-record byte-cap check.
    pub fields: serde_json::Value,
}

/// Response for `host.audit.v1::emit`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct EmitResponse {
    /// SHA-256-or-equivalent hash of the JCS-canonical chain entry
    /// bytes, signed by `mvm-audit-signer`'s chain key. This is the new
    /// chain head after the append.
    pub chain_head: String,
}

// ============================================================================
// Batch verb
// ============================================================================

/// Payload for `host.audit.v1::emit_batch`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct EmitBatchRequest {
    /// Entries to append, in order. Length capped at
    /// [`BROKER_AUDIT_BATCH_MAX`]; total bytes capped at
    /// [`BROKER_AUDIT_BATCH_BYTES`].
    pub entries: Vec<EmitRequest>,
}

/// Per-entry status in a batch response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EmitBatchEntryStatus {
    /// This entry was appended; carries the chain head as of the
    /// append.
    Ok { chain_head: String },
    /// This entry was rejected — the batch may have stopped at this
    /// entry depending on `stop_on_error`.
    Err {
        code: EmitErrorCode,
        message: String,
    },
    /// Batch stopped before this entry was processed (because an
    /// earlier entry failed). No append was attempted.
    Skipped,
}

/// Response for `host.audit.v1::emit_batch`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct EmitBatchResponse {
    /// Final chain head after the last successful append. Equal to the
    /// pre-batch chain head if every entry was rejected.
    pub chain_head: String,
    /// Per-entry status, one per input entry, in input order.
    pub statuses: Vec<EmitBatchEntryStatus>,
}

// ============================================================================
// Error codes
// ============================================================================

/// Per-entry error code for batch responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum EmitErrorCode {
    /// Entry serialises to more than [`BROKER_AUDIT_RECORD_BYTES`] bytes.
    RecordTooLarge,
    /// Entry parse failed (unknown fields, bad timestamp, etc.).
    InvalidEntry,
    /// Audit-signer rejected the entry (chain drift, fsync failure,
    /// internal error). Inspect `message` for the underlying code.
    AuditSignerError,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_request_roundtrips() {
        let req = EmitRequest {
            ts: "2026-05-28T00:00:00Z".into(),
            fields: serde_json::json!({"action": "rate_limit_breach", "count": 42}),
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let parsed: EmitRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn emit_request_rejects_unknown_fields() {
        let bad = serde_json::json!({
            "ts": "2026-05-28T00:00:00Z",
            "fields": {},
            "category": "workload_audit", // not permitted on the wire — broker forces it
        });
        let err = serde_json::from_value::<EmitRequest>(bad).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn emit_response_roundtrips() {
        let resp = EmitResponse {
            chain_head: "abc123".into(),
        };
        let bytes = serde_json::to_vec(&resp).unwrap();
        let parsed: EmitResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, resp);
    }

    #[test]
    fn emit_batch_request_roundtrips() {
        let req = EmitBatchRequest {
            entries: vec![
                EmitRequest {
                    ts: "2026-05-28T00:00:00Z".into(),
                    fields: serde_json::json!({"a": 1}),
                },
                EmitRequest {
                    ts: "2026-05-28T00:00:01Z".into(),
                    fields: serde_json::json!({"b": 2}),
                },
            ],
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let parsed: EmitBatchRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn emit_batch_entry_status_roundtrips() {
        let ok = EmitBatchEntryStatus::Ok {
            chain_head: "h1".into(),
        };
        let err = EmitBatchEntryStatus::Err {
            code: EmitErrorCode::RecordTooLarge,
            message: "entry exceeds 4 KiB".into(),
        };
        let skipped = EmitBatchEntryStatus::Skipped;
        for s in [ok, err, skipped] {
            let bytes = serde_json::to_vec(&s).unwrap();
            let parsed: EmitBatchEntryStatus = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(parsed, s);
        }
    }

    #[test]
    fn emit_error_codes_use_stable_snake_case() {
        for (code, expected) in [
            (EmitErrorCode::RecordTooLarge, "\"record_too_large\""),
            (EmitErrorCode::InvalidEntry, "\"invalid_entry\""),
            (EmitErrorCode::AuditSignerError, "\"audit_signer_error\""),
        ] {
            assert_eq!(serde_json::to_string(&code).unwrap(), expected);
        }
    }

    #[test]
    fn constants_match_adr_062() {
        assert_eq!(BROKER_AUDIT_RECORD_BYTES, 4096);
        assert_eq!(BROKER_AUDIT_BATCH_MAX, 100);
        assert_eq!(BROKER_AUDIT_BATCH_BYTES, 256 * 1024);
        assert_eq!(BROKER_AUDIT_TOKENS_PER_SEC, 20);
    }
}
