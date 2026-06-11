//! Attestation report format.
//!
//! An `AttestationReport` is a signed envelope around an
//! `AttestationBody`. The body carries the data downstream verifiers
//! authenticate against:
//!
//! - `schema_version` — wire format version (currently 1). The
//!   verifier refuses anything > `SCHEMA_VERSION`.
//! - `boot_measurement` — hex SHA-256 of the boot integrity state.
//!   The boot-attestation tier ships the real measurement pipeline
//!   later; for v0 callers populate this from
//!   `BootMeasurement::placeholder()` and the comment trails point
//!   at the dm-verity root hash that will replace it.
//! - `identity_pubkey_hex` — the Ed25519 verifying key whose
//!   signature seals the body. Echoed inside the body (rather than
//!   sourced from a side channel) so the report is self-describing.
//! - `nonce_hex` — 24 random bytes generated per report. Verifiers
//!   that pin freshness (mvmd hosted) reject reports whose nonces
//!   they have seen before within an observation window.
//! - `hw_measurement` — optional `HwMeasurement` if a hardware
//!   provider produced one; `None` means "no hardware backend was
//!   asked for a quote" (the v0 default).
//!
//! The envelope reuses `crate::protocol::signing::SignedPayload`
//! verbatim — same canonical-JSON-then-Ed25519 pattern that
//! `mvm-plan` already uses for signed `ExecutionPlan`s.
//!
//! ## Signing pre-image
//!
//! `sign_report` serialises the `AttestationBody` to canonical
//! `serde_json` bytes (the field-order-stable encoding `serde_json`
//! emits by default), signs those bytes with Ed25519, and stores the
//! payload + sig together in the envelope. `verify_report` reverses
//! the process: it picks the trusted key whose `signer_id` matches
//! the envelope, validates the sig against the payload bytes, then
//! parses the body. The signature check happens *before* JSON parse,
//! so a tampered payload is rejected without ever exposing
//! `serde_json::from_slice` to attacker-controlled bytes.

use crate::crypto::attestation::error::AttestationError;
use crate::crypto::attestation::provider::HwMeasurement;
use crate::protocol::signing::SignedPayload;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// Latest schema version the verifier understands. Bumping this is a
/// non-`#[non_exhaustive]` breaking change — callers should expect
/// older verifiers to refuse newer reports with `UnsupportedSchema`.
pub const SCHEMA_VERSION: u32 = 1;

/// Default nonce length in bytes. 24 bytes = 192 bits of entropy —
/// enough to make a birthday collision in a single host's report
/// stream a non-event for any plausible replay-detection window.
pub const NONCE_BYTES: usize = 24;

/// The body of an attestation report — everything covered by the
/// Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationBody {
    pub schema_version: u32,
    /// SHA-256 hex of the boot integrity measurement. v0 ships a
    /// placeholder until the boot-attestation tier wires the real
    /// dm-verity root-hash pipeline; the field is here so the format
    /// is stable across the transition.
    pub boot_measurement: String,
    /// Hex of the Ed25519 verifying key whose signature seals this
    /// report. Echoed inside the body for self-describing reports;
    /// verifiers MUST cross-check this against the trusted-keys
    /// list.
    pub identity_pubkey_hex: String,
    /// Per-report random nonce. Hex-encoded; `NONCE_BYTES` raw bytes.
    pub nonce_hex: String,
    /// Optional hardware measurement (TPM2 / SEV-SNP / TDX). v0 keeps
    /// this `None` unless a feature-gated provider's `measure()` is
    /// invoked by the caller and folded into the body.
    pub hw_measurement: Option<HwMeasurement>,
}

impl AttestationBody {
    /// Build a body with a fresh random nonce.
    pub fn new(
        boot_measurement: impl Into<String>,
        identity: &VerifyingKey,
        hw_measurement: Option<HwMeasurement>,
    ) -> Self {
        let mut nonce = [0u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        Self {
            schema_version: SCHEMA_VERSION,
            boot_measurement: boot_measurement.into(),
            identity_pubkey_hex: hex_lower(&identity.to_bytes()),
            nonce_hex: hex_lower(&nonce),
            hw_measurement,
        }
    }
}

/// A signed attestation envelope. `serde(transparent)` matches the
/// same pattern `SignedExecutionPlan` uses in `mvm-plan` — same wire
/// shape, distinct type for the type checker.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AttestationReport(pub SignedPayload);

/// Sign an `AttestationBody` with the given identity key.
///
/// The body is encoded with `serde_json::to_vec` — field order and
/// formatting are stable, so verifiers round-trip on the same bytes
/// without needing a separate canonicaliser. The Ed25519 sig is
/// stored alongside the payload + signer_id inside the envelope.
pub fn sign_report(body: &AttestationBody, key: &SigningKey, signer_id: &str) -> AttestationReport {
    let payload = serde_json::to_vec(body).expect("AttestationBody must serialise to JSON");
    let signature: Signature = key.sign(&payload);
    AttestationReport(SignedPayload {
        payload,
        signature: signature.to_bytes().to_vec(),
        signer_id: signer_id.to_string(),
    })
}

/// Verify a signed report against a set of trusted keys.
///
/// Verification order: signer_id lookup → signature check → schema
/// version → body parse. Each gate happens before any
/// attacker-controlled bytes are exposed to the next stage, so an
/// attempt to smuggle a `schema_version: 2` body past a v1 verifier
/// is refused at the same gate that catches a bad sig.
///
/// `trusted_keys` is a `(signer_id, &VerifyingKey)` slice. An empty
/// slice always errors with `UnknownSigner`.
pub fn verify_report(
    report: &AttestationReport,
    trusted_keys: &[(&str, &VerifyingKey)],
) -> Result<AttestationBody, AttestationError> {
    let envelope = &report.0;

    let key = trusted_keys
        .iter()
        .find_map(|(id, k)| (*id == envelope.signer_id).then_some(*k))
        .ok_or_else(|| AttestationError::UnknownSigner(envelope.signer_id.clone()))?;

    let sig = Signature::from_slice(&envelope.signature).map_err(|e| {
        AttestationError::SignatureInvalid(format!("malformed signature bytes: {e}"))
    })?;
    key.verify(&envelope.payload, &sig)
        .map_err(|e| AttestationError::SignatureInvalid(format!("ed25519 verify: {e}")))?;

    // Read the schema version first so we refuse a future-versioned
    // body without exposing the full struct to `from_slice`.
    #[derive(Deserialize)]
    struct SchemaProbe {
        schema_version: u32,
    }
    let probe: SchemaProbe = serde_json::from_slice(&envelope.payload)
        .map_err(|e| AttestationError::Parse(format!("schema probe: {e}")))?;
    if probe.schema_version > SCHEMA_VERSION {
        return Err(AttestationError::UnsupportedSchema {
            found: probe.schema_version,
            supported: SCHEMA_VERSION,
        });
    }

    let body: AttestationBody = serde_json::from_slice(&envelope.payload)
        .map_err(|e| AttestationError::Parse(format!("body parse: {e}")))?;

    // Self-describing pubkey must match the trusted key the
    // signer_id resolved to. Without this check, an attacker who
    // controls the body's `identity_pubkey_hex` could mislead a
    // downstream tool into believing a different identity signed
    // the report.
    if body.identity_pubkey_hex.to_ascii_lowercase() != hex_lower(&key.to_bytes()) {
        return Err(AttestationError::SignatureInvalid(
            "identity_pubkey_hex in body does not match the trusted key for this signer_id"
                .to_string(),
        ));
    }

    Ok(body)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::attestation::provider::HwProviderKind;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn fresh_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn fresh_body(verifying: &VerifyingKey) -> AttestationBody {
        AttestationBody::new("ab".repeat(32), verifying, None)
    }

    #[test]
    fn body_round_trips_through_json() {
        let key = fresh_key();
        let body = fresh_body(&key.verifying_key());
        let s = serde_json::to_string(&body).unwrap();
        let back: AttestationBody = serde_json::from_str(&s).unwrap();
        assert_eq!(back, body);
    }

    #[test]
    fn body_includes_optional_hw_measurement_when_present() {
        let key = fresh_key();
        let hw = HwMeasurement {
            provider: HwProviderKind::Tpm2,
            measurement_hex: "cafebabe".to_string(),
        };
        let body = AttestationBody::new("00".repeat(32), &key.verifying_key(), Some(hw.clone()));
        assert_eq!(body.hw_measurement, Some(hw));
    }

    #[test]
    fn body_rejects_unknown_fields() {
        // serde(deny_unknown_fields) protects forward compat — a v2
        // body extension carrying an extra field must round-trip
        // through the parser only after a deliberate version bump.
        let key = fresh_key();
        let body = fresh_body(&key.verifying_key());
        let mut v: serde_json::Value = serde_json::to_value(&body).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("extra".into(), serde_json::json!("xx"));
        let s = serde_json::to_string(&v).unwrap();
        let parsed: Result<AttestationBody, _> = serde_json::from_str(&s);
        assert!(parsed.is_err(), "deny_unknown_fields must reject extras");
    }

    #[test]
    fn sign_then_verify_returns_original_body() {
        let key = fresh_key();
        let body = fresh_body(&key.verifying_key());
        let report = sign_report(&body, &key, "attest:host-a");
        let trusted = [("attest:host-a", &key.verifying_key())];
        let recovered = verify_report(&report, &trusted).unwrap();
        assert_eq!(recovered, body);
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let key = fresh_key();
        let body = fresh_body(&key.verifying_key());
        let mut report = sign_report(&body, &key, "attest:host-a");
        // Flip a byte inside the payload — sig must fail.
        report.0.payload[0] ^= 0x01;
        let trusted = [("attest:host-a", &key.verifying_key())];
        let err = verify_report(&report, &trusted).expect_err("tamper");
        assert!(
            matches!(err, AttestationError::SignatureInvalid(_)),
            "{err:?}"
        );
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let key = fresh_key();
        let body = fresh_body(&key.verifying_key());
        let mut report = sign_report(&body, &key, "attest:host-a");
        report.0.signature[0] ^= 0x01;
        let trusted = [("attest:host-a", &key.verifying_key())];
        let err = verify_report(&report, &trusted).expect_err("tamper");
        assert!(
            matches!(err, AttestationError::SignatureInvalid(_)),
            "{err:?}"
        );
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let key = fresh_key();
        let body = fresh_body(&key.verifying_key());
        let report = sign_report(&body, &key, "attest:host-a");
        // A different key registered for the same signer_id.
        let other = fresh_key();
        let trusted = [("attest:host-a", &other.verifying_key())];
        let err = verify_report(&report, &trusted).expect_err("wrong key");
        assert!(
            matches!(err, AttestationError::SignatureInvalid(_)),
            "{err:?}"
        );
    }

    #[test]
    fn verify_rejects_unknown_signer_id() {
        let key = fresh_key();
        let body = fresh_body(&key.verifying_key());
        let report = sign_report(&body, &key, "attest:unknown");
        let trusted = [("attest:host-a", &key.verifying_key())];
        let err = verify_report(&report, &trusted).expect_err("unknown signer");
        assert!(matches!(err, AttestationError::UnknownSigner(_)), "{err:?}");
    }

    #[test]
    fn verify_rejects_empty_trusted_keys() {
        let key = fresh_key();
        let body = fresh_body(&key.verifying_key());
        let report = sign_report(&body, &key, "attest:host-a");
        let trusted: [(&str, &VerifyingKey); 0] = [];
        let err = verify_report(&report, &trusted).expect_err("empty trust");
        assert!(matches!(err, AttestationError::UnknownSigner(_)), "{err:?}");
    }

    #[test]
    fn verify_rejects_future_schema_version() {
        let key = fresh_key();
        let body = fresh_body(&key.verifying_key());
        // Mutate the JSON to claim schema_version: 99, then re-sign
        // so the sig check passes — the post-sig schema gate must
        // refuse.
        let mut v: serde_json::Value = serde_json::to_value(&body).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("schema_version".into(), serde_json::json!(99));
        let payload = serde_json::to_vec(&v).unwrap();
        let sig = key.sign(&payload);
        let report = AttestationReport(SignedPayload {
            payload,
            signature: sig.to_bytes().to_vec(),
            signer_id: "attest:host-a".to_string(),
        });
        let trusted = [("attest:host-a", &key.verifying_key())];
        let err = verify_report(&report, &trusted).expect_err("v99");
        match err {
            AttestationError::UnsupportedSchema { found, supported } => {
                assert_eq!(found, 99);
                assert_eq!(supported, SCHEMA_VERSION);
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_mismatched_self_described_pubkey() {
        // Build a body that claims a different identity_pubkey_hex
        // than the one actually signing the report. Verifier must
        // refuse this — the body's self-description is a load-bearing
        // claim downstream tools may reuse without re-deriving from
        // the envelope.
        let key = fresh_key();
        let other = fresh_key();
        let mut body = fresh_body(&key.verifying_key());
        body.identity_pubkey_hex = hex_lower(&other.verifying_key().to_bytes());
        let report = sign_report(&body, &key, "attest:host-a");
        let trusted = [("attest:host-a", &key.verifying_key())];
        let err = verify_report(&report, &trusted).expect_err("mismatch");
        assert!(
            matches!(err, AttestationError::SignatureInvalid(_)),
            "{err:?}"
        );
    }
}
