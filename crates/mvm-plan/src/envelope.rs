//! Signed envelope around `ExecutionPlan`. Reuses the project's existing
//! Ed25519 key plumbing — same primitive as
//! `mvm_runtime::security::signing` — but bound to the plan's canonical
//! bytes, with a typed signer id and self-describing version field so
//! future formats can land without breaking deserialization of old
//! signatures.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::plan::ExecutionPlan;

/// Current envelope wire version. Bumping this is a load-bearing event:
/// old supervisors reject newer envelopes by design.
pub const ENVELOPE_VERSION: u32 = 1;

/// Wire format for a signed plan. The `payload_canonical` is the
/// canonical-JSON bytes of the `ExecutionPlan` that was signed; the
/// signature is over those bytes verbatim. Embedding the canonical
/// bytes (rather than the parsed plan) is what lets a verifier check
/// the signature without re-serializing — re-serialization would risk
/// non-canonical drift.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedExecutionPlan {
    pub envelope_version: u32,
    /// Canonical JSON bytes of the plan that was signed.
    #[serde(with = "base64_bytes")]
    pub payload_canonical: Vec<u8>,
    /// Ed25519 signature over `payload_canonical`.
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
    /// Identifier of the signing key — opaque to this crate; the
    /// supervisor maps it to a verifying key in its trust store.
    pub signer_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error(
        "unsupported envelope version: {0} (this build supports {})",
        ENVELOPE_VERSION
    )]
    UnsupportedVersion(u32),
    #[error("malformed signature: {reason}")]
    MalformedSignature { reason: String },
    #[error("payload re-parse failed: {0}")]
    PayloadParse(#[from] serde_json::Error),
    #[error("signature did not verify against the supplied key")]
    SignatureMismatch,
}

/// Sign a plan with `key`, attaching `signer_id` so the verifier knows
/// which entry in its trust store to consult.
pub fn sign_plan(
    plan: &ExecutionPlan,
    key: &SigningKey,
    signer_id: impl Into<String>,
) -> Result<SignedExecutionPlan, EnvelopeError> {
    let payload_canonical = plan.canonical_bytes()?;
    let signature = key.sign(&payload_canonical);
    Ok(SignedExecutionPlan {
        envelope_version: ENVELOPE_VERSION,
        payload_canonical,
        signature: signature.to_bytes().to_vec(),
        signer_id: signer_id.into(),
    })
}

/// Verify a signed envelope against `verifying_key`, returning the
/// inner parsed plan on success. The plan's *validity* (replay /
/// expiry) is checked separately in `replay::check_validity` — this
/// function only checks the cryptographic envelope.
pub fn verify_plan(
    signed: &SignedExecutionPlan,
    verifying_key: &VerifyingKey,
) -> Result<ExecutionPlan, EnvelopeError> {
    if signed.envelope_version != ENVELOPE_VERSION {
        return Err(EnvelopeError::UnsupportedVersion(signed.envelope_version));
    }

    if signed.signature.len() != 64 {
        return Err(EnvelopeError::MalformedSignature {
            reason: format!("expected 64 bytes, got {}", signed.signature.len()),
        });
    }
    let sig_bytes: [u8; 64] =
        signed
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| EnvelopeError::MalformedSignature {
                reason: "could not convert to [u8; 64]".to_string(),
            })?;
    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify(&signed.payload_canonical, &signature)
        .map_err(|_| EnvelopeError::SignatureMismatch)?;

    let plan: ExecutionPlan = serde_json::from_slice(&signed.payload_canonical)?;
    Ok(plan)
}

mod base64_bytes {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}
