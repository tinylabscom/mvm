//! Audit-signer subprocess wire protocol.
//!
//! `mvm-audit-signer` is the **sole writer** to `~/.mvm/audit/<tenant>.jsonl`
//! and the **sole holder** of the audit chain-signing key. The supervisor
//! routes typed audit entries to it over a per-VM UDS; the subprocess
//! JCS-canonicalizes the entry, signs it, computes the new `prev_hash`,
//! persists `chain_head` to a secondary location, and appends to the
//! JSONL via an `O_APPEND`-only FD.
//!
//! The wire envelope is intentionally different from `ServiceCall` —
//! audit-signer is not a `ServiceHandler`-shaped multiplexer. It has one
//! verb (`append_entry`) plus a health-probe (`probe`). v1 audit
//! categories are passed as opaque strings so this crate doesn't have
//! to know the live `EventCategory` enum from `mvm-supervisor`; the
//! audit-signer's typed schema lives in its own crate.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ============================================================================
// AppendEntryRequest — supervisor → mvm-audit-signer
// ============================================================================

/// One typed audit entry the supervisor wants chain-signed and appended.
///
/// `category` is the live `EventCategory` variant name (snake_case;
/// e.g. `"plan_admitted"`, `"service_call"`, `"plan_oci_provenance"`).
/// The audit-signer ships an allow-list (per-tenant or workspace-wide)
/// and refuses unknown categories at admission rather than embedding the
/// supervisor's enum here — keeps the crate independence honest.
///
/// `fields` is a typed payload validated against the per-category schema
/// the audit-signer ships. Out-of-spec fields → `InvalidRequest`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case", deny_unknown_fields)]
pub enum AppendEntryRequest {
    AppendEntry {
        /// Per-call request id, echoed back in the response.
        request_id: String,
        /// Audit category (snake_case `EventCategory` variant name).
        category: String,
        /// Wall-clock timestamp in RFC 3339 form (the audit-signer also
        /// records its own monotonic timestamp for clock-jump detection).
        ts: String,
        /// Workload identifier the entry is being recorded for.
        workload_id: String,
        /// Tenant identifier — selects which per-tenant chain the entry
        /// appends to.
        tenant_id: String,
        /// Session identifier (rotates per session).
        session_id: String,
        /// Supervisor-assigned correlation id.
        correlation_id: String,
        /// Typed per-category fields. The audit-signer validates against
        /// the category's schema and rejects out-of-spec values.
        fields: serde_json::Value,
    },
    /// Health probe — used by the supervisor's admission ceremony
    /// to confirm the audit-signer is up before admitting the
    /// workload. Returns `Pong` on success.
    Probe { request_id: String },
}

impl AppendEntryRequest {
    pub fn request_id(&self) -> &str {
        match self {
            AppendEntryRequest::AppendEntry { request_id, .. }
            | AppendEntryRequest::Probe { request_id } => request_id,
        }
    }
}

// ============================================================================
// AppendEntryResponse — mvm-audit-signer → supervisor
// ============================================================================

/// Response.
///
/// `Ok` carries the new `chain_head` (the hash of the freshly-signed
/// entry — what the next entry's `prev_hash` must equal) and the
/// `entry_hash` (the same value, named separately for clarity at use
/// sites). `Err` carries a typed code.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AppendEntryResponse {
    Ok {
        request_id: String,
        /// SHA-256-or-equivalent hash of the JCS-canonical entry bytes,
        /// signed by the audit-signer's chain key. This is what the
        /// supervisor persists to the secondary chain-head location
        /// for anti-rollback.
        chain_head: String,
        /// The hash of *this* entry (same value as `chain_head` after a
        /// successful append; named separately so future versions can
        /// decouple if the chain-head representation changes).
        entry_hash: String,
        /// Signature algorithm — `SIG_ALG_ED25519` in the software path;
        /// `SIG_ALG_ECDSA_P256` reserved for the HW-enclave path.
        sig_alg: u8,
    },
    Pong {
        request_id: String,
    },
    Err {
        request_id: String,
        code: AuditSignerErrorCode,
        message: String,
    },
}

impl AppendEntryResponse {
    pub fn request_id(&self) -> &str {
        match self {
            AppendEntryResponse::Ok { request_id, .. }
            | AppendEntryResponse::Pong { request_id }
            | AppendEntryResponse::Err { request_id, .. } => request_id,
        }
    }
}

// ============================================================================
// AuditSignerErrorCode
// ============================================================================

/// Typed audit-signer error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSignerErrorCode {
    /// Subprocess still loading the chain key / opening the JSONL file.
    /// Admission ceremony's `Probe` returns this until ready.
    NotReady,
    /// Request envelope didn't pass schema gate, OR `fields` violates
    /// the per-category schema, OR `category` is unknown.
    InvalidRequest,
    /// `fsync` on the JSONL after append failed. Surfaced as a
    /// hard-fail; the supervisor must pause the workload. Append did
    /// **not** persist; supervisor should not treat the entry as
    /// recorded.
    FsyncFailed,
    /// The chain-head check found drift between the in-memory head and
    /// the secondary persistence location. A real rollback attempt or a
    /// disk-corruption event. Supervisor must
    /// pause the workload + halt admission until operator review.
    ChainDriftDetected,
    /// Catch-all. Never carries entry-content bytes in the message.
    InternalError,
}

// ============================================================================
// Signer helper protocol — host-agent daemon → resident per-tenant helper
// ============================================================================

/// Register a VM with the resident per-tenant signer helper.
///
/// Registration opens and owns that VM's workload chain in the helper process.
/// Subsequent append requests address the chain by server-derived `vm_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerHelperRegisterVm {
    /// Per-call request id, echoed back in the response.
    pub request_id: String,
    /// Server-derived VM identity. The guest never supplies this value.
    pub vm_id: String,
    /// Tenant this helper serves. Must match the helper's configured tenant.
    pub tenant_id: String,
    /// Workload identifier recorded in diagnostics and future admission logs.
    pub workload_id: String,
    /// Per-VM workload audit chain JSONL.
    pub workload_chain_path: PathBuf,
    /// Secondary persisted chain-head file for this VM.
    pub chain_head_secondary_path: PathBuf,
}

/// Deregister a VM from the resident signer helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerHelperDeregisterVm {
    /// Per-call request id, echoed back in the response.
    pub request_id: String,
    /// Server-derived VM identity to close and drop.
    pub vm_id: String,
}

/// One append routed through the resident signer helper.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerHelperAppendEntry {
    /// Per-call request id, echoed back in the response.
    pub request_id: String,
    /// Server-derived VM identity selecting the per-VM chain head.
    pub vm_id: String,
    /// Audit category (v1 forwards `workload_audit` for guest emissions).
    pub category: String,
    /// Wall-clock timestamp in RFC 3339 form.
    pub ts: String,
    /// Workload identifier the entry is being recorded for.
    pub workload_id: String,
    /// Tenant identifier. Must match the helper's configured tenant.
    pub tenant_id: String,
    /// Session identifier.
    pub session_id: String,
    /// Host-agent assigned correlation id.
    pub correlation_id: String,
    /// Typed per-category fields.
    pub fields: serde_json::Value,
}

/// Request accepted by a resident per-tenant signer helper.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case", deny_unknown_fields)]
pub enum SignerHelperRequest {
    /// Open/own a VM's workload chain.
    RegisterVm(SignerHelperRegisterVm),
    /// Flush/drop a VM's workload chain.
    DeregisterVm(SignerHelperDeregisterVm),
    /// Append a signed entry to a registered VM's chain.
    AppendEntry(SignerHelperAppendEntry),
    /// Health probe.
    Probe { request_id: String },
}

impl SignerHelperRequest {
    pub fn request_id(&self) -> &str {
        match self {
            SignerHelperRequest::RegisterVm(req) => &req.request_id,
            SignerHelperRequest::DeregisterVm(req) => &req.request_id,
            SignerHelperRequest::AppendEntry(req) => &req.request_id,
            SignerHelperRequest::Probe { request_id } => request_id,
        }
    }
}

/// Response from the resident per-tenant signer helper.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SignerHelperResponse {
    /// VM registration succeeded and the helper now owns its chain head.
    Registered {
        request_id: String,
        vm_id: String,
        chain_head: String,
    },
    /// VM deregistration succeeded. Unknown VMs are idempotently accepted.
    Deregistered { request_id: String, vm_id: String },
    /// Append succeeded.
    Ok {
        request_id: String,
        chain_head: String,
        entry_hash: String,
        sig_alg: u8,
    },
    /// Probe succeeded.
    Pong { request_id: String },
    /// Request was refused.
    Err {
        request_id: String,
        code: AuditSignerErrorCode,
        message: String,
    },
}

impl SignerHelperResponse {
    pub fn request_id(&self) -> &str {
        match self {
            SignerHelperResponse::Registered { request_id, .. }
            | SignerHelperResponse::Deregistered { request_id, .. }
            | SignerHelperResponse::Ok { request_id, .. }
            | SignerHelperResponse::Pong { request_id }
            | SignerHelperResponse::Err { request_id, .. } => request_id,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::security::{SIG_ALG_ECDSA_P256, SIG_ALG_ED25519};

    fn sample_append() -> AppendEntryRequest {
        AppendEntryRequest::AppendEntry {
            request_id: "req-001".into(),
            category: "plan".into(),
            ts: "2026-05-27T22:30:00Z".into(),
            workload_id: "wl-001".into(),
            tenant_id: "t-001".into(),
            session_id: "sess-001".into(),
            correlation_id: "01HBROKER0000000000000000".into(),
            fields: serde_json::json!({
                "service": "host.time.v1",
                "verb": "now",
                "outcome": "ok",
            }),
        }
    }

    #[test]
    fn append_entry_roundtrips() {
        let req = sample_append();
        let json = serde_json::to_vec(&req).unwrap();
        let parsed: AppendEntryRequest = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed, req);
        assert_eq!(parsed.request_id(), "req-001");
    }

    #[test]
    fn probe_roundtrips() {
        let req = AppendEntryRequest::Probe {
            request_id: "probe-1".into(),
        };
        let json = serde_json::to_vec(&req).unwrap();
        let parsed: AppendEntryRequest = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn append_request_rejects_unknown_verb() {
        let bad = serde_json::json!({
            "verb": "delete_entry",
            "request_id": "x",
            "category": "plan",
            "ts": "2026-05-27T00:00:00Z",
            "workload_id": "wl",
            "tenant_id": "t",
            "session_id": "s",
            "correlation_id": "c",
            "fields": {},
        });
        assert!(serde_json::from_value::<AppendEntryRequest>(bad).is_err());
    }

    #[test]
    fn append_request_rejects_unknown_envelope_fields() {
        let bad = serde_json::json!({
            "verb": "append_entry",
            "request_id": "x",
            "category": "plan",
            "ts": "2026-05-27T00:00:00Z",
            "workload_id": "wl",
            "tenant_id": "t",
            "session_id": "s",
            "correlation_id": "c",
            "fields": {},
            "extra": "should fail",
        });
        let err = serde_json::from_value::<AppendEntryRequest>(bad).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn append_response_ok_roundtrips_with_sig_alg() {
        let resp = AppendEntryResponse::Ok {
            request_id: "req-001".into(),
            chain_head: "abc123".into(),
            entry_hash: "abc123".into(),
            sig_alg: SIG_ALG_ED25519,
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let parsed: AppendEntryResponse = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed, resp);
    }

    #[test]
    fn append_response_ok_accepts_p256_alg_for_w8_path() {
        let resp = AppendEntryResponse::Ok {
            request_id: "req-w8".into(),
            chain_head: "def456".into(),
            entry_hash: "def456".into(),
            sig_alg: SIG_ALG_ECDSA_P256,
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let parsed: AppendEntryResponse = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed, resp);
    }

    #[test]
    fn append_response_err_roundtrips() {
        let resp = AppendEntryResponse::Err {
            request_id: "req-001".into(),
            code: AuditSignerErrorCode::FsyncFailed,
            message: "ENOSPC on tenant audit dir".into(),
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let parsed: AppendEntryResponse = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed, resp);
    }

    #[test]
    fn audit_signer_error_codes_use_stable_snake_case() {
        for (code, expected) in [
            (AuditSignerErrorCode::NotReady, "\"not_ready\""),
            (AuditSignerErrorCode::InvalidRequest, "\"invalid_request\""),
            (AuditSignerErrorCode::FsyncFailed, "\"fsync_failed\""),
            (
                AuditSignerErrorCode::ChainDriftDetected,
                "\"chain_drift_detected\"",
            ),
            (AuditSignerErrorCode::InternalError, "\"internal_error\""),
        ] {
            let s = serde_json::to_string(&code).unwrap();
            assert_eq!(s, expected);
        }
    }

    fn helper_register() -> SignerHelperRequest {
        SignerHelperRequest::RegisterVm(SignerHelperRegisterVm {
            request_id: "reg-1".into(),
            vm_id: "vm-1".into(),
            tenant_id: "local".into(),
            workload_id: "wl-1".into(),
            workload_chain_path: PathBuf::from("/audit/local.vm-1.workload.jsonl"),
            chain_head_secondary_path: PathBuf::from("/audit/local.vm-1.head"),
        })
    }

    #[test]
    fn signer_helper_register_roundtrips() {
        let req = helper_register();
        let json = serde_json::to_vec(&req).unwrap();
        let parsed: SignerHelperRequest = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed, req);
        assert_eq!(parsed.request_id(), "reg-1");
    }

    #[test]
    fn signer_helper_append_roundtrips() {
        let req = SignerHelperRequest::AppendEntry(SignerHelperAppendEntry {
            request_id: "append-1".into(),
            vm_id: "vm-1".into(),
            category: "workload_audit".into(),
            ts: "2026-06-17T00:00:00Z".into(),
            workload_id: "wl-1".into(),
            tenant_id: "local".into(),
            session_id: "sess-1".into(),
            correlation_id: "brk-1".into(),
            fields: serde_json::json!({"event": "ready"}),
        });
        let json = serde_json::to_vec(&req).unwrap();
        let parsed: SignerHelperRequest = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed, req);
        assert_eq!(parsed.request_id(), "append-1");
    }

    #[test]
    fn signer_helper_rejects_unknown_fields() {
        let bad = serde_json::json!({
            "verb": "register_vm",
            "request_id": "reg-1",
            "vm_id": "vm-1",
            "tenant_id": "local",
            "workload_id": "wl-1",
            "workload_chain_path": "/audit/local.vm-1.workload.jsonl",
            "chain_head_secondary_path": "/audit/local.vm-1.head",
            "extra": true,
        });
        let err = serde_json::from_value::<SignerHelperRequest>(bad).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn signer_helper_response_roundtrips() {
        let resp = SignerHelperResponse::Registered {
            request_id: "reg-1".into(),
            vm_id: "vm-1".into(),
            chain_head: "0".repeat(64),
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let parsed: SignerHelperResponse = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed, resp);
        assert_eq!(parsed.request_id(), "reg-1");
    }
}
