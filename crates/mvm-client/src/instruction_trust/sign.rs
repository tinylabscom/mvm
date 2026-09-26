//! Keyed signatures for instruction files.
//!
//! A keyed signature is a small JSON envelope beside the file
//! (`<file>.mvmsig.json`) naming the key, the file's SHA-256, and an Ed25519
//! signature over that digest. It is not a Sigstore bundle, and does not
//! pretend to be one: a Sigstore bundle's verification requires a
//! transparency-log inclusion proof, which a local key cannot produce without
//! a network round trip to a public log. Keyless signing, which does have one,
//! happens in CI with `cosign sign-blob --new-bundle-format`.
//!
//! The signed message is domain-separated so an instruction-file signature
//! can never be replayed as a signature over anything else the same key signs
//! (the host key also signs execution plans and audit entries).

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mvm_core::plan::bundle::{
    KeyId, key_id_from_pubkey, signature_from_base64, signature_to_base64,
};
use serde::{Deserialize, Serialize};

use super::{KEYED_SIDECAR_SUFFIX, sidecar_path};

/// Prefix of every keyed instruction-file signing message.
const SIGNING_CONTEXT: &[u8] = b"mvm.instruction-file.v1\0";

/// The keyed signature envelope written beside an instruction file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyedSignature {
    /// `key_id` of the signing key (see `mvmctl trust list`).
    pub key_id: String,
    /// SHA-256 of the signed file, lowercase hex.
    pub sha256: String,
    /// Base64 Ed25519 signature over the domain-separated digest.
    pub signature: String,
}

/// Why a keyed envelope was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyedSignatureError {
    #[error("signature envelope is malformed: {0}")]
    Malformed(String),
    #[error("the file's digest is not the one that was signed (file changed after signing)")]
    DigestMismatch,
    #[error("signature does not verify under key {0}")]
    BadSignature(String),
}

/// The exact bytes a keyed signature covers for a file with this digest.
#[must_use]
pub fn signing_message(sha256_hex: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNING_CONTEXT.len() + sha256_hex.len());
    message.extend_from_slice(SIGNING_CONTEXT);
    message.extend_from_slice(sha256_hex.as_bytes());
    message
}

impl KeyedSignature {
    /// Sign a file whose digest is `sha256_hex`.
    #[must_use]
    pub fn sign(sha256_hex: &str, key: &SigningKey) -> Self {
        let signature = key.sign(&signing_message(sha256_hex));
        Self {
            key_id: key_id_from_pubkey(&key.verifying_key()).0,
            sha256: sha256_hex.to_string(),
            signature: signature_to_base64(&signature.to_bytes()),
        }
    }

    /// Parse an envelope.
    pub fn from_json(bytes: &[u8]) -> Result<Self, KeyedSignatureError> {
        serde_json::from_slice(bytes).map_err(|e| KeyedSignatureError::Malformed(e.to_string()))
    }

    /// The signing key's id.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        KeyId(self.key_id.clone())
    }

    /// Check this envelope covers a file with `sha256_hex` and was signed by
    /// `key`. The digest is compared first, so an edited file reports as
    /// edited rather than as a bad signature.
    pub fn verify(&self, sha256_hex: &str, key: &VerifyingKey) -> Result<(), KeyedSignatureError> {
        if !self.sha256.eq_ignore_ascii_case(sha256_hex) {
            return Err(KeyedSignatureError::DigestMismatch);
        }
        let bytes = signature_from_base64(&self.signature).ok_or_else(|| {
            KeyedSignatureError::Malformed("signature is not 64 base64 bytes".to_string())
        })?;
        key.verify(
            &signing_message(&sha256_hex.to_ascii_lowercase()),
            &Signature::from_bytes(&bytes),
        )
        .map_err(|_| KeyedSignatureError::BadSignature(self.key_id.clone()))
    }
}

/// Sign `file` with `key`, writing `<file>.mvmsig.json` beside it, and return
/// the sidecar path.
///
/// The sidecar is written to a temporary name and renamed into place, so a
/// verifier never reads a half-written envelope.
pub fn sign_file(file: &Path, key: &SigningKey) -> anyhow::Result<PathBuf> {
    use anyhow::Context as _;
    let sha256 = mvm_core::crypto::image_verify::sha256_file(file)
        .with_context(|| format!("hashing {}", file.display()))?;
    let envelope = KeyedSignature::sign(&sha256, key);
    let sidecar = sidecar_path(file, KEYED_SIDECAR_SUFFIX);
    let staged = sidecar_path(file, &format!("{KEYED_SIDECAR_SUFFIX}.tmp"));
    let mut body = serde_json::to_vec_pretty(&envelope).expect("an envelope serializes");
    body.push(b'\n');
    std::fs::write(&staged, body).with_context(|| format!("writing {}", staged.display()))?;
    std::fs::rename(&staged, &sidecar)
        .with_context(|| format!("moving signature into place at {}", sidecar.display()))?;
    Ok(sidecar)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    const DIGEST: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    #[test]
    fn a_signature_verifies_under_its_own_key_and_digest() {
        let envelope = KeyedSignature::sign(DIGEST, &key(1));
        envelope.verify(DIGEST, &key(1).verifying_key()).unwrap();
        assert_eq!(
            envelope.key_id(),
            key_id_from_pubkey(&key(1).verifying_key())
        );
    }

    #[test]
    fn another_key_or_another_digest_is_refused() {
        let envelope = KeyedSignature::sign(DIGEST, &key(1));
        assert_eq!(
            envelope.verify(DIGEST, &key(2).verifying_key()),
            Err(KeyedSignatureError::BadSignature(envelope.key_id.clone()))
        );
        let other = "0".repeat(64);
        assert_eq!(
            envelope.verify(&other, &key(1).verifying_key()),
            Err(KeyedSignatureError::DigestMismatch)
        );
    }

    #[test]
    fn a_digest_rewritten_inside_the_envelope_breaks_the_signature() {
        let mut envelope = KeyedSignature::sign(DIGEST, &key(1));
        let other = "1".repeat(64);
        envelope.sha256 = other.clone();
        assert!(matches!(
            envelope.verify(&other, &key(1).verifying_key()),
            Err(KeyedSignatureError::BadSignature(_))
        ));
    }

    #[test]
    fn the_signature_is_domain_separated_from_a_bare_digest_signature() {
        let bare = key(1).sign(DIGEST.as_bytes());
        let envelope = KeyedSignature {
            key_id: key_id_from_pubkey(&key(1).verifying_key()).0,
            sha256: DIGEST.to_string(),
            signature: signature_to_base64(&bare.to_bytes()),
        };
        assert!(envelope.verify(DIGEST, &key(1).verifying_key()).is_err());
    }

    #[test]
    fn envelopes_round_trip_and_refuse_unknown_fields() {
        let envelope = KeyedSignature::sign(DIGEST, &key(3));
        let json = serde_json::to_vec(&envelope).unwrap();
        assert_eq!(KeyedSignature::from_json(&json).unwrap(), envelope);

        let mut value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        value["trusted"] = serde_json::Value::Bool(true);
        let err = KeyedSignature::from_json(value.to_string().as_bytes()).unwrap_err();
        assert!(matches!(err, KeyedSignatureError::Malformed(_)));
        assert!(matches!(
            KeyedSignature::from_json(br#"{"key_id":"x","sha256":"y"}"#),
            Err(KeyedSignatureError::Malformed(_))
        ));
    }

    #[test]
    fn signing_a_file_writes_a_verifiable_sidecar_beside_it() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("CLAUDE.md");
        std::fs::write(&file, b"be careful\n").unwrap();
        let sidecar = sign_file(&file, &key(4)).unwrap();
        assert_eq!(sidecar, dir.path().join("CLAUDE.md.mvmsig.json"));
        let envelope = KeyedSignature::from_json(&std::fs::read(&sidecar).unwrap()).unwrap();
        let digest = mvm_core::crypto::image_verify::sha256_file(&file).unwrap();
        envelope.verify(&digest, &key(4).verifying_key()).unwrap();
        assert!(
            !dir.path().join("CLAUDE.md.mvmsig.json.tmp").exists(),
            "no staging file is left behind"
        );
    }

    #[test]
    fn signing_a_missing_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(sign_file(&dir.path().join("absent.md"), &key(5)).is_err());
    }
}
