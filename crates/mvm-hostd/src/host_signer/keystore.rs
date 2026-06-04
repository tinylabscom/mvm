//! Software-fallback in-memory keystore (W1b.1).
//!
//! Holds an Ed25519 signing key + its public form. Generated at
//! subprocess boot via `OsRng` (or loaded from a file when the W1b.1
//! `software_key_path` config is set for dev workflows). Wrapped in
//! `zeroize::Zeroizing` so a drop wipes the key bytes from memory.
//!
//! W8 replaces this module with `enclave.rs` — same `Keystore` API,
//! the inner sign call delegates to Apple Secure Enclave (P-256) on
//! macOS or `tpm2-tss` (Ed25519 or P-256 depending on TPM) on Linux.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use mvm_core::protocol::host_signer::HostSignerErrorCode;
use mvm_core::security::SIG_ALG_ED25519;
use rand::rngs::OsRng;

/// A software-only host signer. Threaded into the server via `Arc`;
/// safe to share across the tokio spawn boundary.
///
/// `Debug` is delegated to `SigningKey`'s redacting Debug impl —
/// `ed25519-dalek` v2 prints `SigningKey(<redacted>)` rather than the
/// raw bytes, so a `dbg!()` of a `Keystore` cannot leak the key.
#[derive(Debug)]
pub struct Keystore {
    /// The signing half. `SigningKey` zeroizes on drop.
    signing_key: SigningKey,
    /// Cached public key bytes (32 for Ed25519). The supervisor caches
    /// these at subprocess boot and re-verifies per call.
    pub_key_bytes: Vec<u8>,
}

impl Keystore {
    /// Generate a fresh in-memory key from `OsRng`.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let pub_key_bytes = signing_key.verifying_key().to_bytes().to_vec();
        Self {
            signing_key,
            pub_key_bytes,
        }
    }

    /// Load a key from a 32-byte file (W1b.1 dev workflows only; tests
    /// use it to assert deterministic signatures). Refuses any file
    /// whose contents aren't exactly 32 bytes.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("mvm-host-signer key file read failed: {}", path.display()))?;
        let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            anyhow::anyhow!("mvm-host-signer key file must be 32 bytes; got {}", v.len())
        })?;
        let signing_key = SigningKey::from_bytes(&arr);
        let pub_key_bytes = signing_key.verifying_key().to_bytes().to_vec();
        Ok(Self {
            signing_key,
            pub_key_bytes,
        })
    }

    /// Sign opaque bytes. Returns the raw signature + `SIG_ALG_ED25519`.
    /// The caller is responsible for the canonical form of `bytes`
    /// (Plan 104 §S28 JCS for credentials, ExecutionPlan's own
    /// canonical form for plans).
    pub fn sign(&self, bytes: &[u8]) -> SignResult {
        let signature = self.signing_key.sign(bytes);
        SignResult {
            sig_alg: SIG_ALG_ED25519,
            signature: signature.to_bytes().to_vec(),
            pub_key_bytes: self.pub_key_bytes.clone(),
        }
    }

    /// Public key bytes (32 for Ed25519). Cheap clone.
    pub fn pub_key(&self) -> Vec<u8> {
        self.pub_key_bytes.clone()
    }
}

/// Output of a software-path sign.
pub struct SignResult {
    pub sig_alg: u8,
    pub signature: Vec<u8>,
    pub pub_key_bytes: Vec<u8>,
}

/// Lazy wrapper that lets `server.rs` carry a `Keystore` behind an
/// `Arc<dyn ...>` boundary without forcing the trait surface yet.
/// (The W8 enclave path will define a `KeystoreProvider` trait that
/// both this software path and the enclave path implement.)
pub type SharedKeystore = Arc<Keystore>;

/// Map an `anyhow::Error` to a typed [`HostSignerErrorCode`]. W1b.1 is
/// permissive (everything → `InternalError`); W8's enclave path can
/// extend this with `EnclaveError` mapping.
pub fn classify_error(_err: &anyhow::Error) -> HostSignerErrorCode {
    HostSignerErrorCode::InternalError
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Verifier, VerifyingKey};

    use super::*;

    #[test]
    fn generate_and_sign_then_verify_roundtrip() {
        let store = Keystore::generate();
        let msg = b"canonical-bytes-to-sign";
        let result = store.sign(msg);
        assert_eq!(result.sig_alg, SIG_ALG_ED25519);
        assert_eq!(result.signature.len(), 64);
        assert_eq!(result.pub_key_bytes.len(), 32);

        // Reconstruct the verifying key from the bytes and verify.
        let pub_arr: [u8; 32] = result.pub_key_bytes.try_into().unwrap();
        let verify_key = VerifyingKey::from_bytes(&pub_arr).unwrap();
        let sig_arr: [u8; 64] = result.signature.try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        verify_key.verify(msg, &sig).expect("signature must verify");
    }

    #[test]
    fn load_from_file_round_trip_yields_stable_pub_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, [7u8; 32]).unwrap();

        let store_a = Keystore::load_from_file(&path).unwrap();
        let store_b = Keystore::load_from_file(&path).unwrap();
        assert_eq!(store_a.pub_key(), store_b.pub_key());

        let msg = b"stability-check";
        let result_a = store_a.sign(msg);
        let result_b = store_b.sign(msg);
        assert_eq!(result_a.signature, result_b.signature);
    }

    #[test]
    fn load_from_file_rejects_wrong_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("badkey");
        std::fs::write(&path, [0u8; 16]).unwrap();
        let err = Keystore::load_from_file(&path).unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
    }
}
