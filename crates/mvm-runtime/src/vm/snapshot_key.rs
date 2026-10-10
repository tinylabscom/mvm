//! Admission of the key that encrypts instance snapshots.
//!
//! An instance snapshot holds a guest's memory, so it is always encrypted.
//! A pause resolves and validates the key here before it asks the VMM to
//! capture anything, and carries the admitted [`SnapshotKey`] through to
//! encryption, so a missing, unreadable, or malformed key refuses the pause
//! instead of leaving guest memory on disk in the clear.
//!
//! Resolution order:
//!
//! 1. `MVM_TENANT_KEY_LOCAL`, when it is set. Setting it is an explicit
//!    selection, for development, CI, and recovery: it is the only source
//!    consulted, so a malformed value is refused rather than skipped in
//!    favour of another key.
//! 2. The OS keystore entry `mvm`/`local`, when a keystore backend is
//!    reachable.
//! 3. `/var/lib/mvm/keys/local.key`, when that directory exists.
//!
//! A source that holds no key is skipped. A source that cannot be read, or
//! holds something that is not a 32-byte key, stops resolution: falling
//! through to another key would encrypt under a key the operator did not
//! choose. Errors name the source and what to fix, and never carry the
//! provider's own error text, which can quote key material.

use std::fmt;

use mvm_core::crypto::keystore::{DEFAULT_KEYS_DIR, EnvKeyProvider, KeyLookupFailure, KeyProvider};
use mvm_core::crypto::snapshot_encryption::KEY_SIZE;
use secrecy::{ExposeSecret, SecretBox};

/// Tenant id used for snapshot encryption in mvm's single-host posture.
/// Every instance snapshot belongs to the local tenant; mvmd's multi-tenant
/// path supplies its own tenant id.
pub const SNAPSHOT_TENANT_ID: &str = "local";

/// Environment variable that explicitly selects the snapshot key. When set,
/// it wins over every other source and is the only one consulted.
pub const SNAPSHOT_TENANT_KEY_ENV: &str = "MVM_TENANT_KEY_LOCAL";

/// Where a snapshot key was looked up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotKeySource {
    /// [`SNAPSHOT_TENANT_KEY_ENV`].
    Explicit,
    /// The OS keystore entry `mvm`/[`SNAPSHOT_TENANT_ID`].
    Keystore,
    /// `<DEFAULT_KEYS_DIR>/<SNAPSHOT_TENANT_ID>.key`.
    KeyFile,
}

impl fmt::Display for SnapshotKeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Explicit => write!(f, "{SNAPSHOT_TENANT_KEY_ENV}"),
            Self::Keystore => write!(f, "the OS keystore entry mvm/{SNAPSHOT_TENANT_ID}"),
            Self::KeyFile => write!(f, "{DEFAULT_KEYS_DIR}/{SNAPSHOT_TENANT_ID}.key"),
        }
    }
}

/// How to provision a snapshot key, quoted by every refusal.
const SETUP: &str = "Provision a 32-byte key: set MVM_TENANT_KEY_LOCAL to 64 hex \
                     characters, or write the 32 raw bytes to \
                     /var/lib/mvm/keys/local.key with mode 0600. Keep the key: an \
                     encrypted snapshot cannot be resumed without it.";

/// Why no snapshot key could be admitted. Every variant is secret-free.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotKeyError {
    /// No source holds a key.
    #[error("instance snapshots are always encrypted, and no snapshot key is configured. {SETUP}")]
    Missing,
    /// A source exists but could not be read.
    #[error(
        "the snapshot key in {origin} could not be read (the keystore is locked or failing, \
         or the key file cannot be opened); refusing to continue without it. Make the source \
         readable by this user and retry"
    )]
    Unavailable { origin: SnapshotKeySource },
    /// A source holds something that is not a usable key.
    #[error(
        "the snapshot key in {origin} is not a usable key: it must be exactly 32 bytes, as 64 \
         hex characters in {SNAPSHOT_TENANT_KEY_ENV} or the keystore, or as raw bytes in a key \
         file of mode 0600 or 0400. {SETUP}"
    )]
    Invalid { origin: SnapshotKeySource },
}

/// A validated 32-byte snapshot encryption key. Zeroized on drop, never
/// printed.
pub struct SnapshotKey(SecretBox<Vec<u8>>);

impl SnapshotKey {
    /// Admit `bytes` as a snapshot key. `None` unless it is exactly
    /// [`KEY_SIZE`] bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Option<Self> {
        (bytes.len() == KEY_SIZE).then(|| Self(SecretBox::new(Box::new(bytes))))
    }

    /// The key bytes, for the AEAD.
    pub(crate) fn expose(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl fmt::Debug for SnapshotKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SnapshotKey([REDACTED])")
    }
}

/// Resolves the snapshot key from an ordered list of sources.
pub struct SnapshotKeyResolver {
    sources: Vec<(SnapshotKeySource, Box<dyn KeyProvider>)>,
}

impl SnapshotKeyResolver {
    /// A resolver with no sources; add them in priority order with
    /// [`SnapshotKeyResolver::source`].
    pub fn empty() -> Self {
        Self {
            sources: Vec::new(),
        }
    }

    /// Append a source, consulted after every source added before it.
    pub fn source(mut self, origin: SnapshotKeySource, provider: Box<dyn KeyProvider>) -> Self {
        self.sources.push((origin, provider));
        self
    }

    /// The sources this host offers, in the order the module documents.
    pub fn host() -> Self {
        if std::env::var_os(SNAPSHOT_TENANT_KEY_ENV).is_some() {
            return Self::empty().source(SnapshotKeySource::Explicit, Box::new(EnvKeyProvider));
        }
        Self::host_stores()
    }

    /// The keystore and key-file sources. Unit tests never consult the
    /// developer's real keystore or key directory.
    #[cfg(not(test))]
    fn host_stores() -> Self {
        use mvm_core::crypto::keystore::{FileKeyProvider, KeyringProvider};
        let mut resolver = Self::empty();
        if KeyringProvider::backend_reachable() {
            resolver = resolver.source(SnapshotKeySource::Keystore, Box::new(KeyringProvider));
        }
        if FileKeyProvider::keys_dir_present(std::path::Path::new(DEFAULT_KEYS_DIR)) {
            resolver = resolver.source(
                SnapshotKeySource::KeyFile,
                Box::new(FileKeyProvider::default()),
            );
        }
        resolver
    }

    #[cfg(test)]
    fn host_stores() -> Self {
        Self::empty()
    }

    /// Resolve and validate the key, or say why there is none.
    pub fn admit(&self) -> Result<SnapshotKey, SnapshotKeyError> {
        for (origin, provider) in &self.sources {
            match provider.get_data_key(SNAPSHOT_TENANT_ID) {
                Ok(key) => {
                    return SnapshotKey::from_bytes(key.expose_secret().clone())
                        .ok_or(SnapshotKeyError::Invalid { origin: *origin });
                }
                Err(err) => match KeyLookupFailure::classify(&err) {
                    KeyLookupFailure::NotConfigured => continue,
                    KeyLookupFailure::Unavailable => {
                        return Err(SnapshotKeyError::Unavailable { origin: *origin });
                    }
                    KeyLookupFailure::Invalid => {
                        return Err(SnapshotKeyError::Invalid { origin: *origin });
                    }
                },
            }
        }
        Err(SnapshotKeyError::Missing)
    }
}

/// Admit the snapshot key from this host's sources.
pub fn admit_host_snapshot_key() -> Result<SnapshotKey, SnapshotKeyError> {
    SnapshotKeyResolver::host().admit()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    const KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// A provider that answers every lookup the same way.
    struct Fixed(fn() -> anyhow::Result<SecretBox<Vec<u8>>>);

    impl KeyProvider for Fixed {
        fn get_data_key(&self, _tenant_id: &str) -> anyhow::Result<SecretBox<Vec<u8>>> {
            (self.0)()
        }
    }

    fn key_of(byte: u8) -> anyhow::Result<SecretBox<Vec<u8>>> {
        Ok(SecretBox::new(Box::new(vec![byte; KEY_SIZE])))
    }

    fn absent() -> anyhow::Result<SecretBox<Vec<u8>>> {
        Err(anyhow::Error::new(std::env::VarError::NotPresent).context("no key"))
    }

    /// A failing source whose error text carries a secret-looking value, so
    /// a test can check it never reaches the refusal.
    fn locked() -> anyhow::Result<SecretBox<Vec<u8>>> {
        Err(anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "denied while holding s3cr3t-key-material",
        )))
    }

    fn malformed() -> anyhow::Result<SecretBox<Vec<u8>>> {
        anyhow::bail!("Invalid hex byte: s3cr3t-key-material")
    }

    fn short() -> anyhow::Result<SecretBox<Vec<u8>>> {
        Ok(SecretBox::new(Box::new(vec![1; KEY_SIZE - 1])))
    }

    fn resolver(first: fn() -> anyhow::Result<SecretBox<Vec<u8>>>) -> SnapshotKeyResolver {
        SnapshotKeyResolver::empty()
            .source(SnapshotKeySource::Keystore, Box::new(Fixed(first)))
            .source(SnapshotKeySource::KeyFile, Box::new(Fixed(|| key_of(9))))
    }

    #[test]
    fn the_first_configured_source_supplies_the_key() {
        let key = resolver(|| key_of(7)).admit().expect("admitted");
        assert_eq!(key.expose(), [7; KEY_SIZE]);
    }

    #[test]
    fn a_source_with_no_key_is_skipped() {
        let key = resolver(absent).admit().expect("admitted");
        assert_eq!(key.expose(), [9; KEY_SIZE]);
    }

    #[test]
    fn no_configured_source_is_missing() {
        let none = SnapshotKeyResolver::empty()
            .source(SnapshotKeySource::Keystore, Box::new(Fixed(absent)))
            .admit()
            .unwrap_err();
        assert_eq!(none, SnapshotKeyError::Missing);
        assert_eq!(
            SnapshotKeyResolver::empty().admit().unwrap_err(),
            SnapshotKeyError::Missing
        );
        let message = none.to_string();
        assert!(message.contains(SNAPSHOT_TENANT_KEY_ENV), "{message}");
        assert!(message.contains("/var/lib/mvm/keys/local.key"), "{message}");
    }

    /// A failing source stops resolution: the next source's key is not used.
    #[test]
    fn an_unreadable_source_fails_closed_without_its_error_text() {
        let err = resolver(locked).admit().unwrap_err();
        assert_eq!(
            err,
            SnapshotKeyError::Unavailable {
                origin: SnapshotKeySource::Keystore
            }
        );
        assert!(!format!("{err} {err:?}").contains("s3cr3t"), "{err}");
    }

    #[test]
    fn a_malformed_or_short_key_is_invalid_without_its_error_text() {
        for bad in [malformed as fn() -> _, short] {
            let err = resolver(bad).admit().unwrap_err();
            assert_eq!(
                err,
                SnapshotKeyError::Invalid {
                    origin: SnapshotKeySource::Keystore
                }
            );
            assert!(!format!("{err} {err:?}").contains("s3cr3t"), "{err}");
        }
    }

    #[test]
    fn the_explicit_variable_is_the_only_source_when_set() {
        let mut env = TestEnv::new();
        env.set(SNAPSHOT_TENANT_KEY_ENV, KEY_HEX);
        let key = admit_host_snapshot_key().expect("admitted");
        assert_eq!(key.expose()[..2], [0x01, 0x23]);
    }

    /// A malformed explicit key is refused, never skipped for another
    /// source, and the refusal does not echo any of it.
    #[test]
    fn a_malformed_explicit_key_is_refused_and_not_echoed() {
        let mut env = TestEnv::new();
        let bad = "q7".repeat(KEY_SIZE);
        env.set(SNAPSHOT_TENANT_KEY_ENV, &bad);
        let err = admit_host_snapshot_key().unwrap_err();
        assert_eq!(
            err,
            SnapshotKeyError::Invalid {
                origin: SnapshotKeySource::Explicit
            }
        );
        assert!(!err.to_string().contains("q7"), "{err}");
    }

    #[test]
    fn an_unset_explicit_key_on_a_bare_host_is_missing() {
        let mut env = TestEnv::new();
        env.remove(SNAPSHOT_TENANT_KEY_ENV);
        assert_eq!(
            admit_host_snapshot_key().unwrap_err(),
            SnapshotKeyError::Missing
        );
    }

    #[test]
    fn a_key_is_exactly_thirty_two_bytes_and_never_printed() {
        assert!(SnapshotKey::from_bytes(vec![0; KEY_SIZE - 1]).is_none());
        assert!(SnapshotKey::from_bytes(vec![0; KEY_SIZE + 1]).is_none());
        let key = SnapshotKey::from_bytes(vec![0xab; KEY_SIZE]).expect("valid");
        assert_eq!(format!("{key:?}"), "SnapshotKey([REDACTED])");
    }
}
