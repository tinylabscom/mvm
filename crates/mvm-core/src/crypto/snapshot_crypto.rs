//! AES-256-GCM primitives for snapshot and volume encryption.
//!
//! Phase 2 of the migration (plan 60:1703) builds tenant-scoped
//! encryption-at-rest on top of these primitives. The wire format is
//! `[12-byte nonce][ciphertext + 16-byte tag]`; the API only takes
//! and returns byte slices — file-bound wrappers are deferred to
//! Phase 2 proper so they can sit on `mvm-storage::VolumeBackend`
//! (Sprint 49 / plan 45) rather than re-deriving an earlier shape.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use anyhow::Result;

/// Nonce size for AES-256-GCM: 96 bits / 12 bytes.
pub const NONCE_SIZE: usize = 12;

/// Authentication tag size: 128 bits / 16 bytes.
pub const TAG_SIZE: usize = 16;

/// Required key size: 256 bits / 32 bytes.
pub const KEY_SIZE: usize = 32;

/// Encrypt `plaintext` under `key`.
///
/// Returns `[12-byte nonce || ciphertext || 16-byte tag]`. The nonce
/// is freshly generated from `OsRng` for every call; never reuse a
/// nonce under the same key.
pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.len() != KEY_SIZE {
        anyhow::bail!(
            "AES-256-GCM key must be {KEY_SIZE} bytes, got {}",
            key.len()
        );
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("Failed to create cipher: {}", e))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    let mut out = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt `encrypted` under `key`.
///
/// `encrypted` must be `[12-byte nonce || ciphertext || 16-byte tag]`.
/// Authentication failure (wrong key, tampered ciphertext, truncated
/// tag) returns an error; success returns the recovered plaintext.
pub fn decrypt(encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.len() != KEY_SIZE {
        anyhow::bail!(
            "AES-256-GCM key must be {KEY_SIZE} bytes, got {}",
            key.len()
        );
    }
    if encrypted.len() < NONCE_SIZE + TAG_SIZE {
        anyhow::bail!(
            "Encrypted payload too short: {} bytes (minimum {})",
            encrypted.len(),
            NONCE_SIZE + TAG_SIZE
        );
    }

    let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("Failed to create cipher: {}", e))?;
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed: authentication tag mismatch"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; KEY_SIZE] {
        [
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x00, 0x99,
        ]
    }

    #[test]
    fn roundtrip_basic() {
        let key = test_key();
        let plaintext = b"Hello, snapshot encryption!";
        let encrypted = encrypt(plaintext, &key).unwrap();
        assert_eq!(decrypt(&encrypted, &key).unwrap(), plaintext);
    }

    #[test]
    fn roundtrip_empty() {
        let key = test_key();
        let encrypted = encrypt(b"", &key).unwrap();
        assert_eq!(decrypt(&encrypted, &key).unwrap(), b"");
    }

    #[test]
    fn roundtrip_large() {
        let key = test_key();
        let plaintext = vec![0xABu8; 1024 * 1024];
        let encrypted = encrypt(&plaintext, &key).unwrap();
        assert_eq!(decrypt(&encrypted, &key).unwrap(), plaintext);
    }

    #[test]
    fn ciphertext_does_not_contain_plaintext() {
        let key = test_key();
        let plaintext = b"RECOGNIZABLE_PATTERN_12345";
        let encrypted = encrypt(plaintext, &key).unwrap();
        assert!(
            !String::from_utf8_lossy(&encrypted).contains("RECOGNIZABLE_PATTERN_12345"),
            "plaintext leaked into ciphertext"
        );
    }

    #[test]
    fn nonce_uniqueness_across_calls() {
        let key = test_key();
        let plaintext = b"same data";
        let enc1 = encrypt(plaintext, &key).unwrap();
        let enc2 = encrypt(plaintext, &key).unwrap();
        assert_ne!(enc1, enc2, "fresh nonce must differ across calls");
        assert_eq!(decrypt(&enc1, &key).unwrap(), plaintext);
        assert_eq!(decrypt(&enc2, &key).unwrap(), plaintext);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key = test_key();
        let mut wrong = test_key();
        wrong[0] ^= 0xFF;
        let encrypted = encrypt(b"secret data", &key).unwrap();
        let err = decrypt(&encrypted, &wrong).unwrap_err();
        assert!(err.to_string().contains("authentication tag"));
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let key = test_key();
        let mut encrypted = encrypt(b"secret data", &key).unwrap();
        let tamper_idx = NONCE_SIZE + 1;
        assert!(encrypted.len() > tamper_idx);
        encrypted[tamper_idx] ^= 0xFF;
        assert!(decrypt(&encrypted, &key).is_err());
    }

    #[test]
    fn rejects_short_key() {
        let short = [0u8; 16];
        assert!(encrypt(b"data", &short).is_err());
        assert!(decrypt(&[0u8; 40], &short).is_err());
    }

    #[test]
    fn rejects_truncated_ciphertext() {
        let key = test_key();
        let too_short = [0u8; NONCE_SIZE + TAG_SIZE - 1];
        assert!(decrypt(&too_short, &key).is_err());
    }

    #[test]
    fn output_size_is_nonce_plus_plaintext_plus_tag() {
        let key = test_key();
        let plaintext = b"test";
        let encrypted = encrypt(plaintext, &key).unwrap();
        assert_eq!(encrypted.len(), NONCE_SIZE + plaintext.len() + TAG_SIZE);
    }
}
