//! Strongly-typed Rekor entry body structures
//!
//! This module provides typed representations of the canonicalized body
//! content for different Rekor entry types and versions.

use serde::{Deserialize, Serialize};
use sigstore_types::encoding::base64_bytes;
use sigstore_types::{
    DerCertificate, DerPublicKey, HashAlgorithm, HexHash, PayloadBytes, PemContent, SignatureBytes,
};

/// Parsed Rekor entry body
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RekorEntryBody {
    /// HashedRekord v0.0.1
    HashedRekordV001(HashedRekordV001Body),
    /// HashedRekord v0.0.2
    HashedRekordV002(HashedRekordV002Body),
    /// DSSE v0.0.1
    DsseV001(DsseV001Body),
    /// DSSE v0.0.2
    DsseV002(DsseV002Body),
    /// Intoto v0.0.2
    IntotoV002(IntotoV002Body),
}

// ============================================================================
// HashedRekord v0.0.1
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordV001Body {
    pub spec: HashedRekordV001Spec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordV001Spec {
    pub data: HashedRekordV001Data,
    pub signature: HashedRekordV001Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordV001Data {
    pub hash: HashValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashValue {
    pub algorithm: HashAlgorithm,
    /// Hex-encoded hash value (used in v0.0.1)
    pub value: HexHash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashedRekordV001Signature {
    /// Base64-encoded signature
    pub content: SignatureBytes,
    pub public_key: PublicKeyContent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyContent {
    /// Base64-encoded PEM public key (double-encoded: base64 of PEM text)
    pub content: PemContent,
}

impl PublicKeyContent {
    /// Parse the PEM content and return a DER certificate
    pub fn to_certificate(&self) -> Result<DerCertificate, crate::error::Error> {
        let pem_bytes = self.content.as_bytes();
        let pem_str = String::from_utf8(pem_bytes.to_vec()).map_err(|e| {
            crate::error::Error::InvalidResponse(format!("PEM not valid UTF-8: {}", e))
        })?;
        DerCertificate::from_pem(&pem_str).map_err(|e| {
            crate::error::Error::InvalidResponse(format!("failed to parse certificate PEM: {}", e))
        })
    }
}

// ============================================================================
// HashedRekord v0.0.2
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordV002Body {
    pub spec: HashedRekordV002Spec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashedRekordV002Spec {
    pub hashed_rekord_v002: HashedRekordV002Data,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordV002Data {
    pub data: HashedRekordV002DataInner,
    pub signature: HashedRekordV002Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordV002DataInner {
    /// Base64-encoded hash digest
    #[serde(with = "base64_bytes")]
    pub digest: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordV002Signature {
    /// Base64-encoded signature
    pub content: SignatureBytes,
    pub verifier: HashedRekordV002Verifier,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashedRekordV002Verifier {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_certificate: Option<X509CertificateRaw>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PublicKeyRaw>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X509CertificateRaw {
    /// DER-encoded certificate
    pub raw_bytes: DerCertificate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyRaw {
    /// DER-encoded public key
    pub raw_bytes: DerPublicKey,
}

// ============================================================================
// DSSE v0.0.1
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseV001Body {
    pub spec: DsseV001Spec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseV001Spec {
    pub envelope_hash: EnvelopeHash,
    pub payload_hash: PayloadHashV001,
    pub signatures: Vec<DsseV001Signature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeHash {
    pub algorithm: HashAlgorithm,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadHashV001 {
    pub algorithm: HashAlgorithm,
    /// Hash value (hex or base64-encoded depending on algorithm)
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseV001Signature {
    /// Signature bytes
    pub signature: SignatureBytes,
    /// PEM-encoded certificate (base64-encoded)
    pub verifier: PemContent,
}

impl DsseV001Signature {
    /// Parse the PEM verifier and return a DER certificate
    pub fn to_certificate(&self) -> Result<DerCertificate, crate::error::Error> {
        let pem_bytes = self.verifier.as_bytes();
        let pem_str = String::from_utf8(pem_bytes.to_vec()).map_err(|e| {
            crate::error::Error::InvalidResponse(format!("PEM not valid UTF-8: {}", e))
        })?;
        DerCertificate::from_pem(&pem_str).map_err(|e| {
            crate::error::Error::InvalidResponse(format!("failed to parse certificate PEM: {}", e))
        })
    }
}

// ============================================================================
// DSSE v0.0.2
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseV002Body {
    pub spec: DsseV002Spec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseV002Spec {
    pub dsse_v002: DsseV002Data,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseV002Data {
    pub payload_hash: PayloadHash,
    pub signatures: Vec<DsseV002Signature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadHash {
    pub algorithm: HashAlgorithm,
    /// Base64-encoded hash digest
    #[serde(with = "base64_bytes")]
    pub digest: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseV002Signature {
    /// Signature bytes
    pub content: SignatureBytes,
    /// Verifier information (certificate and key details)
    pub verifier: DsseV002Verifier,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseV002Verifier {
    /// Key algorithm details (e.g., "PKIX_ECDSA_P256_SHA_256")
    pub key_details: String,
    /// X.509 certificate information
    pub x509_certificate: X509CertificateRaw,
}

// ============================================================================
// Intoto v0.0.2
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntotoV002Body {
    pub spec: IntotoV002Spec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntotoV002Spec {
    pub content: IntotoV002Content,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntotoV002Content {
    pub envelope: IntotoEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntotoEnvelope {
    /// Payload bytes (actually double-encoded in Rekor)
    pub payload: PayloadBytes,
    pub signatures: Vec<IntotoSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntotoSignature {
    /// Signature bytes (double-encoded in Rekor)
    pub sig: SignatureBytes,
}

// ============================================================================
// Helper functions
// ============================================================================

impl RekorEntryBody {
    /// Parse a Rekor entry body from base64-encoded JSON
    pub fn from_base64_json(
        base64_body: &str,
        kind: &str,
        version: &str,
    ) -> Result<Self, crate::error::Error> {
        // Decode base64
        let body_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, base64_body)
                .map_err(|e| {
                    crate::error::Error::InvalidResponse(format!("failed to decode body: {}", e))
                })?;

        // Convert to UTF-8 string
        let body_str = String::from_utf8(body_bytes).map_err(|e| {
            crate::error::Error::InvalidResponse(format!("body is not valid UTF-8: {}", e))
        })?;

        // Parse based on kind and version
        match (kind, version) {
            ("hashedrekord", "0.0.1") => {
                let body: HashedRekordV001Body = serde_json::from_str(&body_str).map_err(|e| {
                    crate::error::Error::InvalidResponse(format!(
                        "failed to parse hashedrekord v0.0.1 body: {}",
                        e
                    ))
                })?;
                Ok(RekorEntryBody::HashedRekordV001(body))
            }
            ("hashedrekord", "0.0.2") => {
                let body: HashedRekordV002Body = serde_json::from_str(&body_str).map_err(|e| {
                    crate::error::Error::InvalidResponse(format!(
                        "failed to parse hashedrekord v0.0.2 body: {}",
                        e
                    ))
                })?;
                Ok(RekorEntryBody::HashedRekordV002(body))
            }
            ("dsse", "0.0.1") => {
                let body: DsseV001Body = serde_json::from_str(&body_str).map_err(|e| {
                    crate::error::Error::InvalidResponse(format!(
                        "failed to parse dsse v0.0.1 body: {}",
                        e
                    ))
                })?;
                Ok(RekorEntryBody::DsseV001(body))
            }
            ("dsse", "0.0.2") => {
                let body: DsseV002Body = serde_json::from_str(&body_str).map_err(|e| {
                    crate::error::Error::InvalidResponse(format!(
                        "failed to parse dsse v0.0.2 body: {}",
                        e
                    ))
                })?;
                Ok(RekorEntryBody::DsseV002(body))
            }
            ("intoto", "0.0.2") => {
                let body: IntotoV002Body = serde_json::from_str(&body_str).map_err(|e| {
                    crate::error::Error::InvalidResponse(format!(
                        "failed to parse intoto v0.0.2 body: {}",
                        e
                    ))
                })?;
                Ok(RekorEntryBody::IntotoV002(body))
            }
            _ => Err(crate::error::Error::InvalidResponse(format!(
                "unsupported entry kind/version: {}/{}",
                kind, version
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hashedrekord_v001() {
        let body_json = r#"{
            "spec": {
                "data": {
                    "hash": {
                        "algorithm": "sha256",
                        "value": "abcd1234"
                    }
                },
                "signature": {
                    "content": "c2lnbmF0dXJl",
                    "publicKey": {
                        "content": "cHVibGlja2V5"
                    }
                }
            }
        }"#;

        let base64_body = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            body_json.as_bytes(),
        );

        let body = RekorEntryBody::from_base64_json(&base64_body, "hashedrekord", "0.0.1");
        assert!(body.is_ok());
    }
}
