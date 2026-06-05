//! One AES-256-GCM entry point for every at-rest call site.
//!
//! `snapshot_crypto` (single-shot byte slices) and `snapshot_encryption`
//! (chunked files) both used to reach for `Aes256Gcm` directly, each
//! generating its own nonce. They now funnel through [`seal`] / [`open`]
//! so the wire format and — the part that actually matters — the nonce
//! discipline live in exactly one place.
//!
//! Wire: `nonce (12) ‖ ciphertext ‖ tag (16)`.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use zeroize::Zeroize;

/// Nonce size for AES-256-GCM: 96 bits / 12 bytes.
pub const NONCE_SIZE: usize = 12;

/// Authentication tag size: 128 bits / 16 bytes.
pub const TAG_SIZE: usize = 16;

/// Required key size: 256 bits / 32 bytes.
pub const KEY_SIZE: usize = 32;

/// Errors surfaced by [`open`] and [`Key::from_slice`].
#[derive(Debug, thiserror::Error)]
pub enum AeadError {
    /// A key slice was not exactly [`KEY_SIZE`] bytes.
    #[error("AES-256-GCM key must be {KEY_SIZE} bytes, got {0}")]
    KeySize(usize),
    /// Framed input was shorter than a bare nonce + tag — can't possibly
    /// be a valid AEAD frame.
    #[error("AEAD input too short: {got} bytes (minimum {} for nonce+tag)", NONCE_SIZE + TAG_SIZE)]
    TooShort { got: usize },
    /// GCM tag did not verify: wrong key, or the ciphertext/nonce/tag was
    /// tampered with. The single failure mode a caller must fail closed on.
    #[error("authentication tag mismatch — wrong key or tampered ciphertext")]
    Auth,
}

/// An AES-256-GCM key.
///
/// A newtype rather than a bare `[u8; 32]` so a key can't be passed where
/// a signing key or arbitrary buffer is wanted, and so the zeroize-on-drop
/// lives in one spot instead of at every call site.
pub struct Key([u8; KEY_SIZE]);

impl Key {
    /// Wrap an owned 32-byte key.
    pub fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Key(bytes)
    }

    /// Build from a slice; errors unless it is exactly [`KEY_SIZE`] bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, AeadError> {
        let arr: [u8; KEY_SIZE] = bytes
            .try_into()
            .map_err(|_| AeadError::KeySize(bytes.len()))?;
        Ok(Key(arr))
    }

    /// Fresh random key drawn from the OS CSPRNG.
    pub fn random() -> Self {
        let generic = Aes256Gcm::generate_key(&mut OsRng);
        let mut bytes = [0u8; KEY_SIZE];
        bytes.copy_from_slice(&generic);
        Key(bytes)
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Seal `plaintext` under `key`, returning `nonce ‖ ciphertext ‖ tag`.
///
/// The nonce is drawn fresh from the OS CSPRNG on every call and is never
/// caller-supplied: nonce reuse under one key is catastrophic for GCM
/// (it leaks the XOR of two plaintexts and the authentication key), so the
/// only safe API is one that owns nonce generation.
///
/// Infallible: AES-GCM encryption of an in-memory buffer cannot fail for
/// any plaintext small enough to hold in a `Vec` — the lone documented
/// error is exceeding GCM's ~64 GiB message ceiling, which would OOM first.
pub fn seal(key: &Key, plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(&key.0.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("AES-256-GCM seal of an in-memory buffer cannot fail");

    let mut out = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Open a `nonce ‖ ciphertext ‖ tag` frame produced by [`seal`].
///
/// Returns [`AeadError::Auth`] on any tag mismatch (wrong key, tampered
/// bytes) and [`AeadError::TooShort`] when the frame can't hold a nonce
/// and tag.
pub fn open(key: &Key, framed: &[u8]) -> Result<Vec<u8>, AeadError> {
    if framed.len() < NONCE_SIZE + TAG_SIZE {
        return Err(AeadError::TooShort { got: framed.len() });
    }
    let (nonce_bytes, ciphertext) = framed.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(&key.0.into());
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| AeadError::Auth)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_and_reject_tamper() {
        let k = Key::random();
        let mut ct = seal(&k, b"snapshot bytes");
        assert_eq!(open(&k, &ct).unwrap(), b"snapshot bytes");
        ct[20] ^= 1; // flip one ciphertext byte
        assert!(matches!(open(&k, &ct), Err(AeadError::Auth)));
    }

    #[test]
    fn roundtrip_empty_plaintext() {
        let k = Key::random();
        let ct = seal(&k, b"");
        assert_eq!(ct.len(), NONCE_SIZE + TAG_SIZE); // nonce + tag, no body
        assert_eq!(open(&k, &ct).unwrap(), b"");
    }

    #[test]
    fn wrong_key_fails_auth() {
        let k1 = Key::random();
        let k2 = Key::random();
        let ct = seal(&k1, b"secret");
        assert!(matches!(open(&k2, &ct), Err(AeadError::Auth)));
    }

    #[test]
    fn fresh_nonce_per_seal() {
        let k = Key::random();
        let a = seal(&k, b"same");
        let b = seal(&k, b"same");
        assert_ne!(a, b, "each seal must draw a fresh nonce");
    }

    #[test]
    fn open_rejects_short_frame() {
        let k = Key::random();
        let err = open(&k, &[0u8; NONCE_SIZE + TAG_SIZE - 1]).unwrap_err();
        assert!(matches!(err, AeadError::TooShort { .. }));
    }

    #[test]
    fn from_slice_rejects_wrong_length() {
        assert!(matches!(
            Key::from_slice(&[0u8; 16]),
            Err(AeadError::KeySize(16))
        ));
        assert!(Key::from_slice(&[0u8; KEY_SIZE]).is_ok());
    }

    #[test]
    fn output_size_is_nonce_plus_plaintext_plus_tag() {
        let k = Key::random();
        let ct = seal(&k, b"test");
        assert_eq!(ct.len(), NONCE_SIZE + 4 + TAG_SIZE);
    }
}
