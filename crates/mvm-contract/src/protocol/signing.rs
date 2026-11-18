use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// A signed payload: the raw bytes of the canonical JSON, the Ed25519
/// signature, and an identifier for which key produced the signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPayload {
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer_id: String,
}

/// Why a [`SignedPayload`] did not verify.
#[derive(Debug, thiserror::Error)]
pub enum SignedPayloadError {
    #[error("no trusted key matched signer_id {signer_id}")]
    UnknownSigner { signer_id: String },
    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),
    #[error("schema version {found} is newer than this build supports ({supported})")]
    UnsupportedSchema { found: u32, supported: u32 },
    #[error("payload parse failed: {0}")]
    Parse(String),
}

/// Verify an Ed25519 [`SignedPayload`] against `(signer_id, key)` pairs and
/// parse its body.
///
/// The order is signer lookup, signature, then a probe of the body's
/// `schema_version` field, then the full parse, so no attacker-controlled
/// bytes are deserialised before the signature holds and a body newer than
/// `supported_schema` is refused before its fields are read. An empty
/// `trusted_keys` always refuses with `UnknownSigner`.
pub fn verify_signed_payload<T: DeserializeOwned>(
    envelope: &SignedPayload,
    trusted_keys: &[(&str, &VerifyingKey)],
    supported_schema: u32,
) -> Result<T, SignedPayloadError> {
    let key = trusted_keys
        .iter()
        .find_map(|(id, k)| (*id == envelope.signer_id).then_some(*k))
        .ok_or_else(|| SignedPayloadError::UnknownSigner {
            signer_id: envelope.signer_id.clone(),
        })?;

    let signature = Signature::from_slice(&envelope.signature).map_err(|e| {
        SignedPayloadError::SignatureInvalid(format!("malformed signature bytes: {e}"))
    })?;
    key.verify(&envelope.payload, &signature)
        .map_err(|e| SignedPayloadError::SignatureInvalid(e.to_string()))?;

    #[derive(Deserialize)]
    struct VersionProbe {
        schema_version: u32,
    }
    let probe: VersionProbe = serde_json::from_slice(&envelope.payload)
        .map_err(|e| SignedPayloadError::Parse(format!("schema_version probe failed: {e}")))?;
    if probe.schema_version > supported_schema {
        return Err(SignedPayloadError::UnsupportedSchema {
            found: probe.schema_version,
            supported: supported_schema,
        });
    }

    serde_json::from_slice(&envelope.payload).map_err(|e| SignedPayloadError::Parse(e.to_string()))
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::*;

    #[test]
    fn test_signed_payload_serialization() {
        let sp = SignedPayload {
            payload: b"test data".to_vec(),
            signature: vec![0u8; 64],
            signer_id: "test-signer".to_string(),
        };
        let json = serde_json::to_string(&sp).unwrap();
        let parsed: SignedPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.payload, b"test data");
        assert_eq!(parsed.signature.len(), 64);
        assert_eq!(parsed.signer_id, "test-signer");
    }
}
