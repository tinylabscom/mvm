//! One AES-256-GCM entry point for every at-rest call site.
//!
//! `snapshot_crypto` (single-shot byte slices) and `snapshot_encryption`
//! (chunked files) both used to reach for `Aes256Gcm` directly, each
//! generating its own nonce. They now funnel through [`seal`] / [`open`]
//! so the wire format and — the part that actually matters — the nonce
//! discipline live in exactly one place.
//!
//! Wire: `nonce (12) ‖ ciphertext ‖ tag (16)`.
//!
//! Both take associated data: caller context that is authenticated but not
//! stored in the frame. Callers with no context pass `&[]`; that frame is
//! byte-for-byte what this module wrote before associated data existed.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::Rng;
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
        let mut bytes = [0u8; KEY_SIZE];
        rand::rng().fill_bytes(&mut bytes);
        Key(bytes)
    }

    /// Wrap this key's bytes under a key-encryption key, returning the AEAD
    /// frame. The raw bytes never leave the type — the inverse is
    /// [`Key::unwrap_under`]. Used to store a data key encrypted at rest.
    /// `aad` binds the wrapped key to a context; it unwraps only in that same
    /// context.
    pub fn wrap_under(&self, kek: &Key, aad: &[u8]) -> Vec<u8> {
        seal(kek, &self.0, aad)
    }

    /// Recover a key wrapped by [`Key::wrap_under`]. Fails closed on a wrong
    /// KEK or tampered frame (via [`open`]) or a wrong unwrapped length.
    pub fn unwrap_under(kek: &Key, framed: &[u8], aad: &[u8]) -> Result<Key, AeadError> {
        let bytes = zeroize::Zeroizing::new(open(kek, framed, aad)?);
        Key::from_slice(&bytes)
    }

    /// Whether this key's bytes equal `other`, compared in constant time.
    /// Lets a caller refuse to use one secret for two primitives without the
    /// raw bytes leaving this type.
    pub(crate) fn same_bytes_as(&self, other: &[u8; KEY_SIZE]) -> bool {
        super::constant_time::constant_time_eq(&self.0, other)
    }

    /// Load the key at `path`, minting and persisting a fresh random one
    /// (mode 0600) if the file does not exist yet.
    ///
    /// Safe for any number of processes or threads to call at once: the new
    /// key is linked into place whole and without replacing an existing file,
    /// and every caller returns the key read back from disk. A caller whose
    /// freshly minted key lost that race therefore returns the winner's key,
    /// never its own, so nothing is ever sealed under a key that does not
    /// match the file. The parent directory must already exist.
    pub fn load_or_create(path: &std::path::Path) -> std::io::Result<Key> {
        crate::atomic_io::load_or_create_private(
            path,
            || zeroize::Zeroizing::new(Key::random().0.to_vec()),
            Key::load,
        )
    }

    /// Load a key persisted by [`Key::load_or_create`]; a wrong-length file
    /// is an `InvalidData` error.
    pub fn load(path: &std::path::Path) -> std::io::Result<Key> {
        let bytes = zeroize::Zeroizing::new(std::fs::read(path)?);
        Key::from_slice(&bytes).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
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
///
/// `aad` is authenticated but not written into the frame; [`open`] must be
/// handed the same bytes.
pub fn seal(key: &Key, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(&key.0.into());
    let mut nonce_arr = [0u8; NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce_arr);
    let nonce = Nonce::from(nonce_arr);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
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
///
/// A different `aad` from the one sealed with fails as [`AeadError::Auth`].
pub fn open(key: &Key, framed: &[u8], aad: &[u8]) -> Result<Vec<u8>, AeadError> {
    if framed.len() < NONCE_SIZE + TAG_SIZE {
        return Err(AeadError::TooShort { got: framed.len() });
    }
    let (nonce_bytes, ciphertext) = framed.split_at(NONCE_SIZE);
    let nonce = Nonce::from(
        <[u8; NONCE_SIZE]>::try_from(nonce_bytes).expect("split_at(NONCE_SIZE) guarantees length"),
    );
    let cipher = Aes256Gcm::new(&key.0.into());
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AeadError::Auth)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_and_reject_tamper() {
        let k = Key::random();
        let mut ct = seal(&k, b"snapshot bytes", &[]);
        assert_eq!(open(&k, &ct, &[]).unwrap(), b"snapshot bytes");
        ct[20] ^= 1; // flip one ciphertext byte
        assert!(matches!(open(&k, &ct, &[]), Err(AeadError::Auth)));
    }

    #[test]
    fn key_wrap_unwrap_roundtrips_and_rejects_wrong_kek() {
        let kek = Key::from_bytes([7u8; KEY_SIZE]);
        let data = Key::from_bytes([42u8; KEY_SIZE]);
        let framed = data.wrap_under(&kek, &[]);
        // Same KEK recovers an identical key (proven by an equal re-wrap is not
        // possible — random nonce — so prove via a seal/open round-trip).
        let recovered = Key::unwrap_under(&Key::from_bytes([7u8; KEY_SIZE]), &framed, &[]).unwrap();
        let blob = seal(&recovered, b"hi", &[]);
        assert_eq!(open(&data, &blob, &[]).unwrap(), b"hi");
        // Wrong KEK fails closed.
        assert!(matches!(
            Key::unwrap_under(&Key::from_bytes([9u8; KEY_SIZE]), &framed, &[]),
            Err(AeadError::Auth)
        ));
    }

    #[test]
    fn roundtrip_empty_plaintext() {
        let k = Key::random();
        let ct = seal(&k, b"", &[]);
        assert_eq!(ct.len(), NONCE_SIZE + TAG_SIZE); // nonce + tag, no body
        assert_eq!(open(&k, &ct, &[]).unwrap(), b"");
    }

    #[test]
    fn wrong_key_fails_auth() {
        let k1 = Key::random();
        let k2 = Key::random();
        let ct = seal(&k1, b"secret", &[]);
        assert!(matches!(open(&k2, &ct, &[]), Err(AeadError::Auth)));
    }

    #[test]
    fn fresh_nonce_per_seal() {
        let k = Key::random();
        let a = seal(&k, b"same", &[]);
        let b = seal(&k, b"same", &[]);
        assert_ne!(a, b, "each seal must draw a fresh nonce");
    }

    #[test]
    fn open_rejects_short_frame() {
        let k = Key::random();
        let err = open(&k, &[0u8; NONCE_SIZE + TAG_SIZE - 1], &[]).unwrap_err();
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

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn load_or_create_mints_an_owner_only_key_once() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kek.bin");
        let first = Key::load_or_create(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), first.0);
        let again = Key::load_or_create(&path).unwrap();
        assert_eq!(again.0, first.0, "an existing key is loaded, not replaced");
    }

    #[test]
    fn load_or_create_refuses_a_wrong_length_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kek.bin");
        std::fs::write(&path, [0u8; 7]).unwrap();
        let err = Key::load_or_create(&path)
            .err()
            .expect("a 7-byte key is refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(std::fs::read(&path).unwrap(), [0u8; 7], "not overwritten");
    }

    /// Set in a child copy of this test binary: the key path to mint, and a
    /// file whose appearance is the signal to start, so every child reaches
    /// the race at the same moment.
    const CHILD_KEY_PATH_ENV: &str = "MVM_AEAD_TEST_CHILD_KEY_PATH";
    const CHILD_START_PATH_ENV: &str = "MVM_AEAD_TEST_CHILD_START_PATH";

    /// Several processes minting the same key file at once must all end up
    /// holding the key the file holds. Each child is this test binary
    /// re-run on this one test with the child variables set.
    #[test]
    fn concurrent_processes_agree_on_one_key() {
        if let Ok(path) = std::env::var(CHILD_KEY_PATH_ENV) {
            let start = std::path::PathBuf::from(std::env::var(CHILD_START_PATH_ENV).unwrap());
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while !start.exists() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "start signal never came"
                );
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let key = Key::load_or_create(std::path::Path::new(&path)).unwrap();
            println!("KEY={}", hex(&key.0));
            return;
        }

        const CHILDREN: usize = 8;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transcript-kek.bin");
        let start = dir.path().join("start");
        let exe = std::env::current_exe().unwrap();
        let children: Vec<_> = (0..CHILDREN)
            .map(|_| {
                std::process::Command::new(&exe)
                    .args([
                        "--exact",
                        "crypto::aead::tests::concurrent_processes_agree_on_one_key",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(CHILD_KEY_PATH_ENV, &path)
                    .env(CHILD_START_PATH_ENV, &start)
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .unwrap()
            })
            .collect();
        std::fs::write(&start, b"").unwrap();

        let mut reported = Vec::new();
        for child in children {
            let out = child.wait_with_output().unwrap();
            assert!(out.status.success(), "child failed: {out:?}");
            let stdout = String::from_utf8(out.stdout).unwrap();
            // libtest prints the test name on the same line before the
            // child's own output, so the marker is not at a line start.
            let key: String = stdout
                .split("KEY=")
                .nth(1)
                .unwrap_or_else(|| panic!("child printed no key: {stdout}"))
                .chars()
                .take(KEY_SIZE * 2)
                .collect();
            reported.push(key);
        }
        let on_disk = hex(&std::fs::read(&path).unwrap());
        assert_eq!(on_disk.len(), KEY_SIZE * 2);
        assert!(
            reported.iter().all(|key| *key == on_disk),
            "every process must hold the key on disk: {reported:?} vs {on_disk}"
        );
    }

    #[test]
    fn aad_round_trips_and_refuses_a_different_context() {
        let k = Key::random();
        let ct = seal(&k, b"body", b"context-a");
        assert_eq!(open(&k, &ct, b"context-a").unwrap(), b"body");
        assert!(matches!(open(&k, &ct, b"context-b"), Err(AeadError::Auth)));
        assert!(matches!(open(&k, &ct, &[]), Err(AeadError::Auth)));
    }

    #[test]
    fn an_empty_aad_frame_has_the_original_layout() {
        // A frame sealed with no associated data is plain AES-256-GCM over
        // the plaintext, which is what every frame written before associated
        // data existed is: open it with the cipher directly.
        let k = Key::from_bytes([3u8; KEY_SIZE]);
        let framed = seal(&k, b"legacy", &[]);
        let (nonce, ct) = framed.split_at(NONCE_SIZE);
        let cipher = Aes256Gcm::new(&k.0.into());
        let nonce = Nonce::from(<[u8; NONCE_SIZE]>::try_from(nonce).unwrap());
        assert_eq!(cipher.decrypt(&nonce, ct).unwrap(), b"legacy");
    }

    #[test]
    fn context_bound_key_wrap_refuses_another_context() {
        let kek = Key::from_bytes([1u8; KEY_SIZE]);
        let data = Key::from_bytes([2u8; KEY_SIZE]);
        let framed = data.wrap_under(&kek, b"ctx");
        let recovered = Key::unwrap_under(&kek, &framed, b"ctx").unwrap();
        assert_eq!(recovered.0, data.0);
        assert!(matches!(
            Key::unwrap_under(&kek, &framed, b"other"),
            Err(AeadError::Auth)
        ));
        assert!(matches!(
            Key::unwrap_under(&kek, &framed, &[]),
            Err(AeadError::Auth)
        ));
    }

    #[test]
    fn output_size_is_nonce_plus_plaintext_plus_tag() {
        let k = Key::random();
        let ct = seal(&k, b"test", &[]);
        assert_eq!(ct.len(), NONCE_SIZE + 4 + TAG_SIZE);
    }
}
