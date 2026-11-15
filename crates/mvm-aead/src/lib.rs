//! Concrete AES-256-GCM calls, optimized independently of the protocol owners.
//!
//! Callers retain key custody, nonce generation, framing, and admission.
//! This internal crate delegates cryptography to `aes-gcm` unchanged.

#![forbid(unsafe_code)]

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

pub use aes_gcm::Error;

/// Encrypt bytes and append the authentication tag.
///
/// The caller must supply a nonce never previously used with this key.
/// Associated data is authenticated, not included in the returned bytes.
///
/// # Errors
/// Returns an error if the input exceeds AES-GCM's message-length limit.
pub fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    Aes256Gcm::new(&(*key).into()).encrypt(
        &Nonce::from(*nonce),
        Payload {
            msg: plaintext,
            aad,
        },
    )
}

/// Authenticate and decrypt ciphertext with its appended authentication tag.
///
/// # Errors
/// Returns an error for a wrong key, nonce, associated data, truncated tag,
/// tampered ciphertext, or input exceeding AES-GCM's message-length limit.
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    Aes256Gcm::new(&(*key).into()).decrypt(
        &Nonce::from(*nonce),
        Payload {
            msg: ciphertext,
            aad,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes256_gcm_zero_key_vector() {
        let expected = [
            0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3,
            0x9d, 0x18, 0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5,
            0xd4, 0x8a, 0xb9, 0x19,
        ];
        assert_eq!(
            encrypt(&[0; 32], &[0; 12], &[0; 16], &[]).unwrap(),
            expected
        );
        assert_eq!(
            decrypt(&[0; 32], &[0; 12], &expected, &[]).unwrap(),
            [0; 16]
        );
    }

    #[test]
    fn authenticates_every_input_and_handles_empty_plaintext() {
        let key = [42; 32];
        let nonce = [7; 12];
        for plaintext in [b"".as_slice(), b"payload".as_slice()] {
            let ciphertext = encrypt(&key, &nonce, plaintext, b"context").unwrap();
            assert_eq!(
                decrypt(&key, &nonce, &ciphertext, b"context").unwrap(),
                plaintext
            );
            assert!(decrypt(&[0; 32], &nonce, &ciphertext, b"context").is_err());
            assert!(decrypt(&key, &[0; 12], &ciphertext, b"context").is_err());
            assert!(decrypt(&key, &nonce, &ciphertext, b"wrong").is_err());
            assert!(decrypt(&key, &nonce, &ciphertext[..15], b"context").is_err());
            for index in 0..ciphertext.len() {
                let mut tampered = ciphertext.clone();
                tampered[index] ^= 1;
                assert!(decrypt(&key, &nonce, &tampered, b"context").is_err());
            }
        }
    }
}
