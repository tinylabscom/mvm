use std::io;

use mvm_crypto::aead::{Aead, Aes256Gcm, Error};

#[test]
fn aes256_gcm_supports_trait_object_dispatch() {
    let algorithm: &dyn Aead<Key = [u8; 32], Nonce = [u8; 12], Error = Error> = &Aes256Gcm;
    let key = [42; 32];
    let nonce = [7; 12];
    let ciphertext = algorithm
        .encrypt(&key, &nonce, b"payload", b"context")
        .unwrap();

    assert_eq!(
        algorithm
            .decrypt(&key, &nonce, &ciphertext, b"context")
            .unwrap(),
        b"payload"
    );
    assert!(
        algorithm
            .decrypt(&key, &nonce, &ciphertext, b"wrong")
            .is_err()
    );
}

// A refusing test double, not a cryptographic implementation.
struct UnavailableAlgorithm;

impl Aead for UnavailableAlgorithm {
    type Key = [u8; 16];
    type Nonce = [u8; 24];
    type Error = io::Error;

    fn encrypt(
        &self,
        _key: &Self::Key,
        _nonce: &Self::Nonce,
        _plaintext: &[u8],
        _aad: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn decrypt(
        &self,
        _key: &Self::Key,
        _nonce: &Self::Nonce,
        _ciphertext: &[u8],
        _aad: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

#[test]
fn downstream_implementations_choose_key_nonce_and_error_types() {
    let algorithm: &dyn Aead<Key = [u8; 16], Nonce = [u8; 24], Error = io::Error> =
        &UnavailableAlgorithm;
    let key = [0; 16];
    let nonce = [0; 24];

    assert_eq!(
        algorithm
            .encrypt(&key, &nonce, b"payload", b"context")
            .unwrap_err()
            .kind(),
        io::ErrorKind::Unsupported
    );
    assert_eq!(
        algorithm
            .decrypt(&key, &nonce, b"ciphertext", b"context")
            .unwrap_err()
            .kind(),
        io::ErrorKind::Unsupported
    );
}
