//! Authenticated encryption with associated data and algorithm-specific inputs.
//!
//! Callers retain key custody, nonce generation, framing, and admission.
//! The AES-256-GCM implementation delegates cryptography to `aes-gcm`.

use aes_gcm::aead::{Aead as _, KeyInit, Payload};
use aes_gcm::{Aes256Gcm as Cipher, Nonce};

/// AES-256-GCM authentication or message-length failure.
pub use aes_gcm::Error;

/// An authenticated-encryption algorithm with its own key, nonce, and error types.
///
/// Implementations authenticate the nonce, associated data, and entire ciphertext
/// before returning plaintext. They borrow keys and nonces for each operation;
/// callers remain responsible for key custody and nonce uniqueness.
pub trait Aead {
    /// The algorithm's key representation.
    type Key;
    /// The algorithm's nonce representation.
    type Nonce;
    /// Authentication, input-limit, or implementation-specific failures.
    type Error: std::error::Error;

    /// Encrypt bytes and append the algorithm's authentication tag.
    ///
    /// The nonce must never have been used with this key. Associated data is
    /// authenticated but is not included in the returned bytes.
    ///
    /// # Errors
    /// Returns an error if the input exceeds the algorithm's limits or the
    /// operation cannot be completed.
    fn encrypt(
        &self,
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    /// Authenticate and decrypt ciphertext with its appended authentication tag.
    ///
    /// # Errors
    /// Returns an error for failed authentication, malformed input, exceeded
    /// algorithm limits, or an operation that cannot be completed. Authentication
    /// failure must not return any plaintext.
    fn decrypt(
        &self,
        key: &Self::Key,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
}

/// AES-256-GCM with a 32-byte key, 12-byte nonce, and 16-byte authentication tag.
///
/// This stateless implementation keeps the concrete cipher instantiation in
/// the optimized crypto crate, even when called from an unoptimized protocol.
#[derive(Debug, Clone, Copy, Default)]
pub struct Aes256Gcm;

impl Aead for Aes256Gcm {
    type Key = [u8; 32];
    type Nonce = [u8; 12];
    type Error = Error;

    fn encrypt(
        &self,
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        Cipher::new(&(*key).into()).encrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
    }

    fn decrypt(
        &self,
        key: &Self::Key,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        Cipher::new(&(*key).into()).decrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
    }
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
            Aes256Gcm
                .encrypt(&[0; 32], &[0; 12], &[0; 16], &[])
                .unwrap(),
            expected
        );
        assert_eq!(
            Aes256Gcm
                .decrypt(&[0; 32], &[0; 12], &expected, &[])
                .unwrap(),
            [0; 16]
        );
    }

    #[test]
    fn authenticates_every_input_and_handles_empty_plaintext() {
        let key = [42; 32];
        let nonce = [7; 12];
        let algorithm = Aes256Gcm;
        for plaintext in [b"".as_slice(), b"payload".as_slice()] {
            let ciphertext = algorithm
                .encrypt(&key, &nonce, plaintext, b"context")
                .unwrap();
            assert_eq!(
                algorithm
                    .decrypt(&key, &nonce, &ciphertext, b"context")
                    .unwrap(),
                plaintext
            );
            assert!(
                algorithm
                    .decrypt(&[0; 32], &nonce, &ciphertext, b"context")
                    .is_err()
            );
            assert!(
                algorithm
                    .decrypt(&key, &[0; 12], &ciphertext, b"context")
                    .is_err()
            );
            assert!(
                algorithm
                    .decrypt(&key, &nonce, &ciphertext, b"wrong")
                    .is_err()
            );
            assert!(
                algorithm
                    .decrypt(&key, &nonce, &ciphertext[..15], b"context")
                    .is_err()
            );
            for index in 0..ciphertext.len() {
                let mut tampered = ciphertext.clone();
                tampered[index] ^= 1;
                assert!(
                    algorithm
                        .decrypt(&key, &nonce, &tampered, b"context")
                        .is_err()
                );
            }
        }
    }
}
