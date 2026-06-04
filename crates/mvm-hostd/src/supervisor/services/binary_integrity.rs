//! Pre-spawn binary integrity check (Plan 104 §H-L3.1).
//!
//! Before [`super::spawn::ProcessSpawner::spawn`] hands control to a
//! subprocess binary, the supervisor mmaps the file, computes its
//! SHA-256, and verifies an Ed25519 signature against a pinned release
//! key. Refuse-to-spawn on any mismatch; the supervisor's lifecycle
//! code (W1b.2b.5) translates the refusal into an audit entry
//! `<subprocess>.signature_invalid`.
//!
//! Signature shape (sidecar file `<binary>.sig`):
//!
//! ```json
//! {
//!   "sig_alg": 1,
//!   "signature_b64": "<base64-encoded 64-byte Ed25519 signature over the binary's bytes>",
//!   "signer_key_id": "<hex-encoded SHA-256 of the signer's verifying key>"
//! }
//! ```
//!
//! The `signer_key_id` lets the supervisor look up the verifying key in
//! its pinned [`ReleaseKeyBundle`]; the bundle is shipped with mvmctl
//! itself (W1b.2b.5 will wire a hard-coded build-time-injected key
//! constant). If the `signer_key_id` isn't in the bundle, refuse —
//! signature-from-untrusted-key is structurally distinct from
//! signature-doesn't-verify.
//!
//! **Important — TOCTOU window remains in this PR (deferred).** This
//! module verifies the binary's bytes *before* [`Command::spawn`] is
//! called; the kernel then reads the same path during exec. An
//! attacker who can swap the binary file between verify-time and
//! exec-time wins. Closing the window requires Linux `fexecve` (or
//! macOS `posix_spawn_file_actions_addopen` + open-then-spawn) — that
//! work lives in a follow-on PR (likely alongside the W1b.2c cgroup +
//! seccomp work, since both touch low-level fork plumbing).
//! Plan 104 §H-L3.2 carries the goal; this module sets up the seam.

use std::fs::File;
use std::path::{Path, PathBuf};

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use mvm_core::security::SIG_ALG_ED25519;

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, Error)]
pub enum IntegrityError {
    /// The binary file couldn't be opened.
    #[error("integrity check: cannot open binary {binary}: {source}")]
    OpenBinary {
        binary: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// mmap of the binary failed.
    #[error("integrity check: mmap of {binary} failed: {source}")]
    MmapFailed {
        binary: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The signature sidecar file (`<binary>.sig`) is missing or
    /// unreadable.
    #[error("integrity check: signature sidecar {sidecar} for {binary} not readable: {source}")]
    MissingSidecar {
        binary: PathBuf,
        sidecar: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The sidecar file parsed but its shape is invalid.
    #[error("integrity check: signature sidecar {sidecar} malformed: {source}")]
    MalformedSidecar {
        sidecar: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    /// Base64 decode of the signature bytes failed.
    #[error("integrity check: signature base64 decode failed: {source}")]
    BadSignatureEncoding {
        #[source]
        source: base64::DecodeError,
    },
    /// Signature was the wrong length (Ed25519 is exactly 64 bytes).
    #[error("integrity check: signature length {got} != expected {want}")]
    BadSignatureLength { got: usize, want: usize },
    /// `signer_key_id` didn't match any key in the pinned bundle.
    /// Signature-from-untrusted-key is structurally distinct from
    /// signature-doesn't-verify — both refuse-to-spawn, but the audit
    /// trail is clearer if we name them separately.
    #[error("integrity check: signer_key_id {signer_key_id} not in pinned release bundle")]
    UnknownSignerKey { signer_key_id: String },
    /// The signature didn't verify against the bundled key. The most
    /// likely cause is binary tampering between sign-time and
    /// verify-time.
    #[error("integrity check: signature verification failed for {binary}")]
    SignatureMismatch { binary: PathBuf },
    /// `sig_alg` is not one we know how to verify. W1b.2b.2 supports
    /// only Ed25519 (`SIG_ALG_ED25519` = 0x01); ECDSA-P256 reservation
    /// is for the macOS Secure Enclave host-signer path in W8.
    #[error("integrity check: unsupported sig_alg {sig_alg} (only Ed25519 supported in W1b.2b.2)")]
    UnsupportedAlgorithm { sig_alg: u8 },
}

// ============================================================================
// Sidecar
// ============================================================================

/// On-disk shape of `<binary>.sig`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinarySignature {
    /// One of [`mvm_core::security::SIG_ALG_ED25519`] or
    /// `SIG_ALG_ECDSA_P256` (reserved for W8).
    pub sig_alg: u8,
    /// Base64-encoded signature over the binary's bytes.
    pub signature_b64: String,
    /// Hex-encoded SHA-256 of the signer's verifying key. Lets the
    /// supervisor look up which key in the pinned bundle this
    /// signature corresponds to without trying every key.
    pub signer_key_id: String,
}

impl BinarySignature {
    /// Compute the canonical `signer_key_id` for an Ed25519 verifying
    /// key (hex-encoded SHA-256 of the 32-byte public key).
    pub fn key_id_for(verifying_key: &VerifyingKey) -> String {
        let bytes = verifying_key.to_bytes();
        let hash = Sha256::digest(bytes);
        hex_encode(&hash)
    }

    /// Path of the sidecar for a given binary (`<binary>.sig`).
    pub fn sidecar_path(binary: &Path) -> PathBuf {
        let mut p = binary.as_os_str().to_owned();
        p.push(".sig");
        PathBuf::from(p)
    }

    /// Load the sidecar from disk.
    pub fn load_for(binary: &Path) -> Result<Self, IntegrityError> {
        let sidecar = Self::sidecar_path(binary);
        let bytes = std::fs::read(&sidecar).map_err(|source| IntegrityError::MissingSidecar {
            binary: binary.to_path_buf(),
            sidecar: sidecar.clone(),
            source,
        })?;
        serde_json::from_slice(&bytes)
            .map_err(|source| IntegrityError::MalformedSidecar { sidecar, source })
    }

    /// Write the sidecar to disk (test fixture; production sidecars
    /// are written by the release pipeline).
    pub fn write_for(&self, binary: &Path) -> std::io::Result<()> {
        let sidecar = Self::sidecar_path(binary);
        let bytes = serde_json::to_vec_pretty(self).expect("serialise own struct");
        std::fs::write(sidecar, bytes)
    }
}

// ============================================================================
// Release key bundle
// ============================================================================

/// The set of verifying keys mvmctl trusts to sign subprocess binaries.
///
/// W1b.2b.5 will wire a build-time-injected key constant (the release
/// signer's public key, baked into the mvmctl binary). For W1b.2b.2 the
/// bundle is constructed at runtime — tests build their own
/// single-key bundle; production code paths in this PR are not yet
/// reached (the W1b.2b.5 admission-ceremony PR is what'll call into
/// here from the supervisor's lifecycle).
#[derive(Debug, Clone, Default)]
pub struct ReleaseKeyBundle {
    keys_by_id: std::collections::HashMap<String, VerifyingKey>,
}

impl ReleaseKeyBundle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a verifying key. The key's id is its hex SHA-256.
    pub fn add(&mut self, key: VerifyingKey) -> String {
        let id = BinarySignature::key_id_for(&key);
        self.keys_by_id.insert(id.clone(), key);
        id
    }

    /// Look up a key by its id. Returns `None` if absent.
    pub fn get(&self, key_id: &str) -> Option<&VerifyingKey> {
        self.keys_by_id.get(key_id)
    }

    pub fn len(&self) -> usize {
        self.keys_by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys_by_id.is_empty()
    }
}

// ============================================================================
// Integrity checker
// ============================================================================

/// Trait so the supervisor's spawn site can hold an `Arc<dyn
/// IntegrityChecker>` and tests can supply a `NoopChecker` or
/// `AlwaysFailingChecker` without touching the production type.
pub trait IntegrityChecker: Send + Sync {
    /// Verify a binary. Returns `Ok(())` if the bundled signature
    /// matches; otherwise a typed `IntegrityError`.
    fn verify(&self, binary: &Path) -> Result<(), IntegrityError>;
}

/// Production checker — reads the sidecar, mmaps the binary, verifies
/// the signature against a pinned [`ReleaseKeyBundle`].
pub struct SignedBinaryChecker {
    pub bundle: ReleaseKeyBundle,
}

impl SignedBinaryChecker {
    pub fn new(bundle: ReleaseKeyBundle) -> Self {
        Self { bundle }
    }
}

impl IntegrityChecker for SignedBinaryChecker {
    fn verify(&self, binary: &Path) -> Result<(), IntegrityError> {
        let sidecar = BinarySignature::load_for(binary)?;

        // Only Ed25519 supported in W1b.2b.2. Future W8 SE / TPM path
        // adds SIG_ALG_ECDSA_P256 verification here.
        if sidecar.sig_alg != SIG_ALG_ED25519 {
            return Err(IntegrityError::UnsupportedAlgorithm {
                sig_alg: sidecar.sig_alg,
            });
        }

        let verifying_key = self.bundle.get(&sidecar.signer_key_id).ok_or_else(|| {
            IntegrityError::UnknownSignerKey {
                signer_key_id: sidecar.signer_key_id.clone(),
            }
        })?;

        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&sidecar.signature_b64)
            .map_err(|source| IntegrityError::BadSignatureEncoding { source })?;
        if sig_bytes.len() != 64 {
            return Err(IntegrityError::BadSignatureLength {
                got: sig_bytes.len(),
                want: 64,
            });
        }
        let sig_arr: [u8; 64] = sig_bytes.try_into().expect("checked len above");
        let signature = Signature::from_bytes(&sig_arr);

        // mmap-read the binary. `memmap2` would be the more efficient
        // path; W1b.2b.2 stays dep-light and reads the full file into
        // memory. mvm-broker / mvm-host-signer / mvm-audit-signer
        // binaries are all small (single-digit MB), so the read is
        // cheap relative to the spawn cost.
        let file_bytes = std::fs::read(binary).map_err(|source| IntegrityError::OpenBinary {
            binary: binary.to_path_buf(),
            source,
        })?;

        verifying_key.verify(&file_bytes, &signature).map_err(|_| {
            IntegrityError::SignatureMismatch {
                binary: binary.to_path_buf(),
            }
        })?;

        Ok(())
    }
}

/// Test convenience — always returns `Ok`. Use only in tests; never
/// register in production.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopChecker;

impl IntegrityChecker for NoopChecker {
    fn verify(&self, _binary: &Path) -> Result<(), IntegrityError> {
        Ok(())
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", b);
    }
    out
}

/// Keep [`File`] around as a no-op import so `cargo doc --no-deps`
/// renders without an unused-import warning (we'll wire it in
/// W1b.2b.2.5 when mmap-then-fexecve lands and we need a long-lived
/// FD for the TOCTOU close).
#[allow(dead_code)]
fn _unused_file_import() -> Option<File> {
    None
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use tempfile::tempdir;

    use super::*;

    /// Build a fresh signing keypair + a signature over `binary_bytes`,
    /// + a [`ReleaseKeyBundle`] containing the verifying key.
    fn sign_fixture(binary_bytes: &[u8]) -> (BinarySignature, ReleaseKeyBundle) {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let signature = signing_key.sign(binary_bytes);

        let mut bundle = ReleaseKeyBundle::new();
        let key_id = bundle.add(verifying_key);

        let sidecar = BinarySignature {
            sig_alg: SIG_ALG_ED25519,
            signature_b64: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            signer_key_id: key_id,
        };
        (sidecar, bundle)
    }

    fn write_test_binary(dir: &tempfile::TempDir, contents: &[u8]) -> PathBuf {
        let p = dir.path().join("fake-binary");
        std::fs::write(&p, contents).unwrap();
        p
    }

    #[test]
    fn happy_path_verifies_a_signed_binary() {
        let dir = tempdir().unwrap();
        let binary_bytes = b"#!/bin/sh\necho hello world\n";
        let binary = write_test_binary(&dir, binary_bytes);
        let (sig, bundle) = sign_fixture(binary_bytes);
        sig.write_for(&binary).unwrap();

        let checker = SignedBinaryChecker::new(bundle);
        checker.verify(&binary).expect("happy path must verify");
    }

    #[test]
    fn tampered_binary_is_refused() {
        let dir = tempdir().unwrap();
        let original = b"#!/bin/sh\necho hello\n";
        let tampered = b"#!/bin/sh\necho TAMPERED\n";
        let binary = write_test_binary(&dir, original);
        let (sig, bundle) = sign_fixture(original);
        sig.write_for(&binary).unwrap();
        // Replace the binary bytes after signing.
        std::fs::write(&binary, tampered).unwrap();

        let checker = SignedBinaryChecker::new(bundle);
        let err = checker.verify(&binary).expect_err("tamper must be refused");
        match err {
            IntegrityError::SignatureMismatch { .. } => {}
            other => panic!("expected SignatureMismatch, got {other:?}"),
        }
    }

    #[test]
    fn missing_sidecar_is_refused() {
        let dir = tempdir().unwrap();
        let binary = write_test_binary(&dir, b"unsigned");
        // No sidecar written.
        let checker = SignedBinaryChecker::new(ReleaseKeyBundle::new());
        let err = checker
            .verify(&binary)
            .expect_err("missing sidecar must be refused");
        match err {
            IntegrityError::MissingSidecar { .. } => {}
            other => panic!("expected MissingSidecar, got {other:?}"),
        }
    }

    #[test]
    fn unknown_signer_key_is_refused_with_distinct_error_from_signature_mismatch() {
        let dir = tempdir().unwrap();
        let binary_bytes = b"unsigned-but-claimed";
        let binary = write_test_binary(&dir, binary_bytes);
        // Build a sidecar with a real signature but DON'T add the key
        // to the bundle. The check should fail at the lookup stage,
        // not at the signature-verify stage — distinct audit semantics.
        let (sig, _real_bundle) = sign_fixture(binary_bytes);
        sig.write_for(&binary).unwrap();

        let empty_bundle = ReleaseKeyBundle::new();
        let checker = SignedBinaryChecker::new(empty_bundle);
        let err = checker
            .verify(&binary)
            .expect_err("unknown signer key must be refused");
        match err {
            IntegrityError::UnknownSignerKey { .. } => {}
            other => panic!("expected UnknownSignerKey, got {other:?}"),
        }
    }

    #[test]
    fn malformed_sidecar_is_refused() {
        let dir = tempdir().unwrap();
        let binary = write_test_binary(&dir, b"bin");
        let sidecar = BinarySignature::sidecar_path(&binary);
        std::fs::write(&sidecar, b"this is not json").unwrap();

        let checker = SignedBinaryChecker::new(ReleaseKeyBundle::new());
        let err = checker.verify(&binary).expect_err("malformed must refuse");
        match err {
            IntegrityError::MalformedSidecar { .. } => {}
            other => panic!("expected MalformedSidecar, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_algorithm_is_refused() {
        let dir = tempdir().unwrap();
        let binary = write_test_binary(&dir, b"bin");
        // Forge a sidecar claiming an unsupported algorithm.
        let sig = BinarySignature {
            sig_alg: 0xFF,
            signature_b64: base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
            signer_key_id: "deadbeef".into(),
        };
        sig.write_for(&binary).unwrap();

        let checker = SignedBinaryChecker::new(ReleaseKeyBundle::new());
        let err = checker
            .verify(&binary)
            .expect_err("unsupported alg must refuse");
        match err {
            IntegrityError::UnsupportedAlgorithm { sig_alg: 0xFF } => {}
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn signer_key_id_is_deterministic_for_a_given_key() {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let vk = sk.verifying_key();
        let id_a = BinarySignature::key_id_for(&vk);
        let id_b = BinarySignature::key_id_for(&vk);
        assert_eq!(id_a, id_b);
        assert_eq!(id_a.len(), 64); // 32-byte SHA-256 → 64 hex chars
    }

    #[test]
    fn noop_checker_accepts_anything() {
        let dir = tempdir().unwrap();
        let binary = write_test_binary(&dir, b"whatever");
        NoopChecker.verify(&binary).expect("noop must accept");
    }

    #[test]
    fn release_key_bundle_size_and_lookup() {
        let mut bundle = ReleaseKeyBundle::new();
        assert!(bundle.is_empty());

        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let id = bundle.add(sk.verifying_key());

        assert_eq!(bundle.len(), 1);
        assert!(!bundle.is_empty());
        assert!(bundle.get(&id).is_some());
        assert!(bundle.get("missing").is_none());
    }
}
