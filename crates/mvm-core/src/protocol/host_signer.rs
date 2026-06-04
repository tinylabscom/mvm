//! Host-signer subprocess wire protocol (Plan 104 §H-L1.1, ADR-061).
//!
//! The supervisor delegates **all** signing operations that touch the host
//! signer key to `mvm-host-signer` over a per-VM UDS. The key never enters
//! the supervisor's address space (or the broker / secrets-dispatcher /
//! audit-signer subprocesses). The host-signer holds the key alone — in
//! W1b.1 as a software in-memory key; in W8 as a hardware-enclave handle
//! (Apple Secure Enclave / Linux TPM 2.0 per Plan 104 §H-L2.1).
//!
//! The wire envelope is intentionally **different** from the broker's
//! `ServiceCall` (Plan 104 §protocol/broker.rs). The host-signer is not a
//! `ServiceHandler`-shaped multiplexer: it implements a small fixed verb
//! set (`sign_plan`, `sign_credential`) and the supervisor calls it
//! directly. Keeping the wire shape distinct from `ServiceCall` makes the
//! parser surface smaller and the audit-log boundary clearer (host-signer
//! events have their own `EventCategory` — they're not `ServiceCall`
//! entries).

use serde::{Deserialize, Serialize};

// ============================================================================
// SignRequest — supervisor → mvm-host-signer
// ============================================================================

/// What the supervisor is asking the host-signer to sign.
///
/// `SignPlan` carries `crate::plan::ExecutionPlan` bytes; the host-signer
/// treats the input as opaque bytes and does not parse them. ADR-062
/// dropped the `SignCredential` variant when `host.secrets.v1` was
/// removed from v1 scope; future verbs (PQC, attestation) extend this
/// enum via the algorithm-identifier byte in the response (Plan 104
/// §H-L4.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case", deny_unknown_fields)]
pub enum SignRequest {
    /// Sign an `ExecutionPlan` (Plan 104 §H-L1.1, claim 8). The
    /// supervisor's admission ceremony calls this once per workload.
    SignPlan {
        /// Canonical plan bytes. The supervisor is the sole caller and
        /// has its own validity-window check before calling.
        bytes: Vec<u8>,
        /// Supervisor-set request id, echoed back in the response so the
        /// supervisor can correlate async signs.
        request_id: String,
    },
}

impl SignRequest {
    pub fn request_id(&self) -> &str {
        match self {
            SignRequest::SignPlan { request_id, .. } => request_id,
        }
    }
}

// ============================================================================
// SignResponse — mvm-host-signer → supervisor
// ============================================================================

/// The response. `Ok` carries the signature bytes + the public key the
/// supervisor should use to verify (echo of what the host-signer
/// generated at boot). `Err` carries a typed code so callers can branch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SignResponse {
    Ok {
        request_id: String,
        /// Signature algorithm — one of [`SIG_ALG_ED25519`] or
        /// [`SIG_ALG_ECDSA_P256`]. Future PQC schemes assign new
        /// constants without a wire-format hard fork (Plan 104 §H-L4.1).
        sig_alg: u8,
        /// Raw signature bytes (length depends on `sig_alg`: 64 for
        /// Ed25519, 64-72 for ECDSA-P256 DER).
        signature: Vec<u8>,
        /// Host-signer public key bytes (the supervisor caches this at
        /// subprocess boot and re-verifies per call to detect mid-flight
        /// rotation).
        signer_pubkey: Vec<u8>,
    },
    Err {
        request_id: String,
        code: HostSignerErrorCode,
        message: String,
    },
}

impl SignResponse {
    pub fn request_id(&self) -> &str {
        match self {
            SignResponse::Ok { request_id, .. } | SignResponse::Err { request_id, .. } => {
                request_id
            }
        }
    }
}

// ============================================================================
// HostSignerErrorCode
// ============================================================================

/// Typed host-signer error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostSignerErrorCode {
    /// Subprocess is still loading the key (e.g. waiting on TPM init in
    /// W8). Caller should retry; supervisor should not pass this through
    /// as a permanent failure.
    NotReady,
    /// Request envelope didn't pass schema gate (length, field
    /// validation).
    InvalidRequest,
    /// Key material is unavailable — TPM unreachable, enclave error, or
    /// (W1b.1 software-fallback path) the in-memory key was never
    /// initialised. Caller treats as fatal for the current request;
    /// retry is doomed.
    KeyUnavailable,
    /// HW enclave returned an error (only emitted on the W8 enclave
    /// path; W1b.1 software path never sets this). Carries the
    /// enclave's error category in the message string for forensics.
    EnclaveError,
    /// Catch-all. Never carries request-content bytes in the message
    /// (Plan 104 §S9 redaction discipline).
    InternalError,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::security::{SIG_ALG_ECDSA_P256, SIG_ALG_ED25519};

    #[test]
    fn sign_plan_request_roundtrips() {
        let req = SignRequest::SignPlan {
            bytes: b"canonical-plan-bytes".to_vec(),
            request_id: "req-001".to_string(),
        };
        let json = serde_json::to_vec(&req).unwrap();
        let parsed: SignRequest = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed, req);
        assert_eq!(parsed.request_id(), "req-001");
    }

    #[test]
    fn sign_request_rejects_unknown_verb() {
        let bad = serde_json::json!({
            "verb": "sign_arbitrary",
            "bytes": [1, 2, 3],
            "request_id": "x",
        });
        assert!(serde_json::from_value::<SignRequest>(bad).is_err());
    }

    #[test]
    fn sign_request_rejects_unknown_fields() {
        let bad = serde_json::json!({
            "verb": "sign_plan",
            "bytes": [],
            "request_id": "x",
            "side_channel": "data",
        });
        let err = serde_json::from_value::<SignRequest>(bad).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn sign_response_ok_roundtrips_with_ed25519_alg() {
        let resp = SignResponse::Ok {
            request_id: "req-001".into(),
            sig_alg: SIG_ALG_ED25519,
            signature: vec![0u8; 64],
            signer_pubkey: vec![1u8; 32],
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let parsed: SignResponse = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed, resp);
    }

    #[test]
    fn sign_response_ok_accepts_ecdsa_p256_alg() {
        // The byte is reserved at W1b.1; the host-signer rejects it on
        // the verify side until W8 wires SE. But the envelope itself
        // round-trips so the wire surface is stable across W1b.1 → W8.
        let resp = SignResponse::Ok {
            request_id: "req-w8".into(),
            sig_alg: SIG_ALG_ECDSA_P256,
            signature: vec![0u8; 72],
            signer_pubkey: vec![1u8; 65],
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let parsed: SignResponse = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed, resp);
    }

    #[test]
    fn sign_response_err_roundtrips_with_typed_code() {
        let resp = SignResponse::Err {
            request_id: "req-001".into(),
            code: HostSignerErrorCode::NotReady,
            message: "TPM still initialising".into(),
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let parsed: SignResponse = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed, resp);
    }

    #[test]
    fn host_signer_error_codes_use_stable_snake_case() {
        for (code, expected) in [
            (HostSignerErrorCode::NotReady, "\"not_ready\""),
            (HostSignerErrorCode::InvalidRequest, "\"invalid_request\""),
            (HostSignerErrorCode::KeyUnavailable, "\"key_unavailable\""),
            (HostSignerErrorCode::EnclaveError, "\"enclave_error\""),
            (HostSignerErrorCode::InternalError, "\"internal_error\""),
        ] {
            let s = serde_json::to_string(&code).unwrap();
            assert_eq!(s, expected);
        }
    }
}
