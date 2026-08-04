//! Signed config envelope for subprocess startup.
//!
//! The supervisor signs each subprocess's `SubprocessConfig` bytes with
//! its config-signing key before writing them to the subprocess's stdin.
//! The subprocess unwraps the envelope, verifies the signature against
//! a pinned verifying key, and only then parses the inner config.
//!
//! Closes the subprocess config-injection gap (a compromised
//! supervisor): without this envelope, a UAF that survives long
//! enough to influence a *new* spawn can hand the subprocess a config
//! pointing audit-back-channel at `/dev/null` or the proxy UDS at a
//! sibling-workload's socket. With the envelope, the subprocess
//! refuses any config not signed by the expected key.
//!
//! This module ships alongside the supervisor-side
//! `crate::services::config_signer::ConfigSigner` helper (in
//! mvm-supervisor). The wiring follows separately:
//! - Each of the four subprocess crates updates its `config::parse` to
//!   call [`verify_envelope`] before deserialising the inner config;
//!   the unsigned `config::parse` is deleted per the no-backcompat rule.
//! - The production supervisor wires a `ConfigSigner` into
//!   `ProcessSpawner::with_config_signer` and the verifying key it
//!   produces is baked into / handed to each subprocess at build time.

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::security::SIG_ALG_ED25519;

pub use mvm_contract::protocol::signed_config::{SignedConfigEnvelope, SignedConfigError};

// ============================================================================
// Key id
// ============================================================================

/// Canonical key id for a verifying key — hex SHA-256 of the 32-byte
/// public key bytes.
///
/// A free function rather than an inherent method on
/// [`SignedConfigEnvelope`]: that type now lives in `mvm-contract`, and
/// the orphan rule forbids `mvm-core` from adding inherent `impl`s to a
/// foreign type.
pub fn key_id_for(verifying_key: &VerifyingKey) -> String {
    let bytes = verifying_key.to_bytes();
    let hash = Sha256::digest(bytes);
    hex_encode(&hash)
}

// ============================================================================
// Wrap + verify
// ============================================================================

/// Build an envelope from raw inner-config bytes + a precomputed
/// signature. Most callers will use the supervisor-side
/// `crate::services::config_signer::ConfigSigner` (in mvm-supervisor)
/// which does the signing too; this helper exists so other crates can
/// build an envelope for testing without the supervisor dep.
pub fn wrap_payload(
    payload: &[u8],
    sig_alg: u8,
    signer_key_id: String,
    signature: &[u8],
) -> SignedConfigEnvelope {
    SignedConfigEnvelope {
        sig_alg,
        signer_key_id,
        payload_b64: base64::engine::general_purpose::STANDARD.encode(payload),
        signature_b64: base64::engine::general_purpose::STANDARD.encode(signature),
    }
}

/// Serialize an envelope to bytes-on-stdin. Tiny wrapper around
/// `serde_json::to_vec` kept here so the choice of JSON vs (future)
/// CBOR/JCS lives in one place.
pub fn encode_envelope(envelope: &SignedConfigEnvelope) -> Vec<u8> {
    serde_json::to_vec(envelope).expect("serialise own struct")
}

/// Parse an envelope from bytes-on-stdin.
pub fn decode_envelope(bytes: &[u8]) -> Result<SignedConfigEnvelope, SignedConfigError> {
    serde_json::from_slice(bytes).map_err(|source| SignedConfigError::EnvelopeParse { source })
}

/// Verify an envelope against the expected verifying key. Returns the
/// raw (decoded) inner config bytes on success. The caller then
/// deserialises those bytes as its own `SubprocessConfig` shape.
///
/// The expected key is what the subprocess hardcodes (a build-time
/// constant). Passing the *expected* key here means the
/// subprocess won't accept signatures from any other key, even if the
/// envelope's `signer_key_id` happens to match a different valid key —
/// because we cross-check the id against the expected key's id before
/// verifying.
pub fn verify_envelope(
    envelope: &SignedConfigEnvelope,
    expected_verifying_key: &VerifyingKey,
) -> Result<Vec<u8>, SignedConfigError> {
    if envelope.sig_alg != SIG_ALG_ED25519 {
        return Err(SignedConfigError::UnsupportedAlgorithm {
            sig_alg: envelope.sig_alg,
        });
    }

    let expected_id = key_id_for(expected_verifying_key);
    if envelope.signer_key_id != expected_id {
        return Err(SignedConfigError::UnexpectedSignerKey {
            got: envelope.signer_key_id.clone(),
            expected: expected_id,
        });
    }

    let payload = base64::engine::general_purpose::STANDARD
        .decode(&envelope.payload_b64)
        .map_err(|source| SignedConfigError::BadEncoding {
            reason: source.to_string(),
        })?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&envelope.signature_b64)
        .map_err(|source| SignedConfigError::BadEncoding {
            reason: source.to_string(),
        })?;

    if sig_bytes.len() != 64 {
        return Err(SignedConfigError::BadSignatureLength {
            got: sig_bytes.len(),
            want: 64,
        });
    }
    let sig_arr: [u8; 64] = sig_bytes.try_into().expect("checked len above");
    let signature = Signature::from_bytes(&sig_arr);

    expected_verifying_key
        .verify(&payload, &signature)
        .map_err(|_| SignedConfigError::SignatureMismatch)?;

    Ok(payload)
}

// ============================================================================
// Helpers
// ============================================================================

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{:02x}", b);
    }
    out
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    use super::*;

    fn fresh_keys() -> (SigningKey, VerifyingKey) {
        let mut rng = OsRng;
        let sk = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rng, &mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn sign(payload: &[u8], sk: &SigningKey) -> SignedConfigEnvelope {
        let signature = sk.sign(payload);
        let signer_key_id = key_id_for(&sk.verifying_key());
        wrap_payload(
            payload,
            SIG_ALG_ED25519,
            signer_key_id,
            &signature.to_bytes(),
        )
    }

    #[test]
    fn happy_path_round_trip() {
        let (sk, vk) = fresh_keys();
        let payload = br#"{"workload_id":"wl-1","tenant_id":"t-1"}"#;
        let env = sign(payload, &sk);

        let bytes = encode_envelope(&env);
        let parsed = decode_envelope(&bytes).expect("envelope must parse");
        let recovered = verify_envelope(&parsed, &vk).expect("verify must succeed");
        assert_eq!(recovered, payload);
    }

    #[test]
    fn tampered_payload_is_refused() {
        let (sk, vk) = fresh_keys();
        let payload = br#"{"workload_id":"wl-1"}"#;
        let mut env = sign(payload, &sk);
        // Re-encode a different payload with the original signature.
        env.payload_b64 =
            base64::engine::general_purpose::STANDARD.encode(br#"{"workload_id":"wl-TAMPERED"}"#);
        let err = verify_envelope(&env, &vk).expect_err("tamper must refuse");
        match err {
            SignedConfigError::SignatureMismatch => {}
            other => panic!("expected SignatureMismatch, got {other:?}"),
        }
    }

    #[test]
    fn wrong_signer_key_is_refused_with_distinct_error_from_signature_mismatch() {
        let (sk_a, _) = fresh_keys();
        let (_, vk_b) = fresh_keys();
        let payload = b"hello";
        let env = sign(payload, &sk_a);
        // Verify against a different verifying key — should fail at
        // the signer-id mismatch step, not the verify step.
        let err = verify_envelope(&env, &vk_b).expect_err("wrong key must refuse");
        match err {
            SignedConfigError::UnexpectedSignerKey { .. } => {}
            other => panic!("expected UnexpectedSignerKey, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_algorithm_is_refused() {
        let (sk, vk) = fresh_keys();
        let payload = b"hi";
        let mut env = sign(payload, &sk);
        env.sig_alg = 0xFF;
        let err = verify_envelope(&env, &vk).expect_err("unsupported alg must refuse");
        match err {
            SignedConfigError::UnsupportedAlgorithm { sig_alg: 0xFF } => {}
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn malformed_envelope_bytes_refused() {
        let err = decode_envelope(b"not json").expect_err("must refuse");
        match err {
            SignedConfigError::EnvelopeParse { .. } => {}
            other => panic!("expected EnvelopeParse, got {other:?}"),
        }
    }

    #[test]
    fn envelope_rejects_unknown_fields() {
        let extra = serde_json::json!({
            "sig_alg": 1,
            "signer_key_id": "00".repeat(32),
            "payload_b64": "",
            "signature_b64": "",
            "extra": "field"
        });
        let bytes = serde_json::to_vec(&extra).unwrap();
        let err = decode_envelope(&bytes).expect_err("unknown field must refuse");
        match err {
            SignedConfigError::EnvelopeParse { source } => {
                assert!(source.to_string().contains("unknown field"));
            }
            other => panic!("expected EnvelopeParse, got {other:?}"),
        }
    }

    #[test]
    fn signature_length_check_runs_before_verify() {
        let (sk, vk) = fresh_keys();
        let payload = b"hi";
        let mut env = sign(payload, &sk);
        // Corrupt the signature to be 32 bytes instead of 64.
        env.signature_b64 = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 32]);
        let err = verify_envelope(&env, &vk).expect_err("wrong sig length must refuse");
        match err {
            SignedConfigError::BadSignatureLength { got: 32, want: 64 } => {}
            other => panic!("expected BadSignatureLength, got {other:?}"),
        }
    }

    #[test]
    fn key_id_is_deterministic_for_a_given_key() {
        let (_, vk) = fresh_keys();
        let id_a = key_id_for(&vk);
        let id_b = key_id_for(&vk);
        assert_eq!(id_a, id_b);
        assert_eq!(id_a.len(), 64); // 32-byte SHA-256 → 64 hex chars
    }

    #[test]
    fn empty_payload_round_trips() {
        let (sk, vk) = fresh_keys();
        let env = sign(b"", &sk);
        let recovered = verify_envelope(&env, &vk).expect("empty payload must verify");
        assert_eq!(recovered, b"");
    }
}
