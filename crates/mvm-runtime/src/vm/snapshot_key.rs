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
//! 4. `local.key` under the mvm key directory (`~/.mvm/keys/` unless
//!    `MVM_HOME` moves it), the key mvm provisions for itself. Only the host
//!    snapshot key is looked up there; a tenant's own key never is.
//!
//! A host with none of these has no key, and a pause refuses. `mvmctl
//! bootstrap` and `mvmctl pool warm` provision the fourth source when every
//! source is empty ([`ensure_host_snapshot_key`]): 32 random bytes, mode 0600,
//! written only where no file exists, so an existing key is never replaced.
//!
//! A source that holds no key is skipped. A source that cannot be read, or
//! holds something that is not a 32-byte key, stops resolution: falling
//! through to another key would encrypt under a key the operator did not
//! choose. Errors name the source and what to fix, and never carry the
//! provider's own error text, which can quote key material.

use std::fmt;
use std::path::{Path, PathBuf};

use mvm_core::crypto::keystore::{
    DEFAULT_KEYS_DIR, EnvKeyProvider, FileKeyProvider, KeyLookupFailure, KeyProvider,
};
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
    /// `<mvm_keys_dir>/<SNAPSHOT_TENANT_ID>.key`, the key mvm provisions.
    HomeKeyFile,
}

impl fmt::Display for SnapshotKeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Explicit => write!(f, "{SNAPSHOT_TENANT_KEY_ENV}"),
            Self::Keystore => write!(f, "the OS keystore entry mvm/{SNAPSHOT_TENANT_ID}"),
            Self::KeyFile => write!(f, "{DEFAULT_KEYS_DIR}/{SNAPSHOT_TENANT_ID}.key"),
            Self::HomeKeyFile => write!(
                f,
                "{}",
                home_key_path(&mvm_core::config::mvm_keys_dir()).display()
            ),
        }
    }
}

/// How to provision a snapshot key, quoted by every refusal.
const SETUP: &str = "Run `mvmctl bootstrap` to provision one under the mvm key \
                     directory, set MVM_TENANT_KEY_LOCAL to 64 hex characters, or \
                     write the 32 raw bytes to /var/lib/mvm/keys/local.key with mode \
                     0600. Keep the key: an encrypted snapshot cannot be resumed \
                     without it.";

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
        Self::host_for(SNAPSHOT_TENANT_ID)
    }

    /// The sources this host offers for `tenant_id`'s key, in the same order:
    /// its explicit variable alone when that is set, else the keystore and
    /// the key directory.
    pub fn host_for(tenant_id: &str) -> Self {
        if explicit_key_selected(tenant_id) {
            return Self::explicit();
        }
        let stores = Self::host_stores();
        if tenant_id == SNAPSHOT_TENANT_ID {
            stores.home_key_file(&mvm_core::config::mvm_keys_dir())
        } else {
            stores
        }
    }

    /// The explicit variable alone.
    fn explicit() -> Self {
        Self::empty().source(SnapshotKeySource::Explicit, Box::new(EnvKeyProvider))
    }

    /// Append the host snapshot key mvm provisions under `keys_dir`. A
    /// missing directory or file holds no key and is skipped; a file another
    /// user could read is refused, never skipped.
    fn home_key_file(self, keys_dir: &Path) -> Self {
        self.source(
            SnapshotKeySource::HomeKeyFile,
            Box::new(FileKeyProvider::with_dir(keys_dir)),
        )
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
        self.admit_for(SNAPSHOT_TENANT_ID)
    }

    /// Resolve and validate `tenant_id`'s key from these sources, with the
    /// same stop-on-unreadable rule as [`SnapshotKeyResolver::admit`].
    pub fn admit_for(&self, tenant_id: &str) -> Result<SnapshotKey, SnapshotKeyError> {
        self.admit_naming_source(tenant_id).map(|(key, _)| key)
    }

    /// [`SnapshotKeyResolver::admit_for`], also naming the source that
    /// supplied the key.
    pub fn admit_naming_source(
        &self,
        tenant_id: &str,
    ) -> Result<(SnapshotKey, SnapshotKeySource), SnapshotKeyError> {
        for (origin, provider) in &self.sources {
            match provider.get_data_key(tenant_id) {
                Ok(key) => {
                    return SnapshotKey::from_bytes(key.expose_secret().clone())
                        .map(|key| (key, *origin))
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

/// Whether `tenant_id`'s explicit variable is set, which makes it the only
/// source consulted.
fn explicit_key_selected(tenant_id: &str) -> bool {
    std::env::var_os(EnvKeyProvider::variable_for(tenant_id)).is_some()
}

/// The host snapshot key file under `keys_dir`.
fn home_key_path(keys_dir: &Path) -> PathBuf {
    keys_dir.join(format!("{SNAPSHOT_TENANT_ID}.key"))
}

/// What [`ensure_host_snapshot_key`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostSnapshotKey {
    /// A source already held a usable key. Nothing was written.
    Existing(SnapshotKeySource),
    /// No source held a key, so one was minted at this path.
    Created(PathBuf),
}

/// Why the host snapshot key could neither be admitted nor provisioned.
/// Secret-free.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotKeyProvisionError {
    /// A source holds a key that cannot be used. It is left exactly as it
    /// is: replacing it would orphan every snapshot sealed under it.
    #[error(transparent)]
    Refused(#[from] SnapshotKeyError),
    /// The key file could not be written.
    #[error("could not provision the host snapshot key at {}: {source}", path.display())]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Admit the host snapshot key, provisioning one under the mvm key directory
/// when no source holds any.
///
/// An explicit `MVM_TENANT_KEY_LOCAL` is the only source consulted when set,
/// so it is never shadowed and nothing is written. Otherwise a key any source
/// already holds is used as it is, and a source holding an unusable key
/// (wrong length, a file another user could read) refuses rather than being
/// replaced. Only when every source is empty are 32 random bytes written to
/// `<mvm_keys_dir>/local.key` at mode 0600, without replacing a file a
/// concurrent caller published first, and the creation is audited.
pub fn ensure_host_snapshot_key() -> Result<HostSnapshotKey, SnapshotKeyProvisionError> {
    if explicit_key_selected(SNAPSHOT_TENANT_ID) {
        let (_, origin) =
            SnapshotKeyResolver::explicit().admit_naming_source(SNAPSHOT_TENANT_ID)?;
        return Ok(HostSnapshotKey::Existing(origin));
    }
    ensure_with(
        SnapshotKeyResolver::host_stores(),
        &mvm_core::config::mvm_keys_dir(),
    )
}

/// [`ensure_host_snapshot_key`] over explicit system sources and key
/// directory.
fn ensure_with(
    stores: SnapshotKeyResolver,
    keys_dir: &Path,
) -> Result<HostSnapshotKey, SnapshotKeyProvisionError> {
    let resolver = stores.home_key_file(keys_dir);
    match resolver.admit_naming_source(SNAPSHOT_TENANT_ID) {
        Ok((_, origin)) => return Ok(HostSnapshotKey::Existing(origin)),
        Err(SnapshotKeyError::Missing) => {}
        Err(refusal) => return Err(refusal.into()),
    }
    let path = home_key_path(keys_dir);
    let written =
        mint_key_file(keys_dir, &path).map_err(|source| SnapshotKeyProvisionError::Write {
            path: path.clone(),
            source,
        })?;
    // Admit what is on disk, whichever process published it, so the key this
    // host goes on to use is the one every later lookup finds.
    resolver.admit_naming_source(SNAPSHOT_TENANT_ID)?;
    Ok(match written {
        mvm_core::atomic_io::NewFile::Created => {
            mvm_core::policy::audit::event(
                mvm_core::policy::audit::LocalAuditKind::SnapshotKeyCreated,
            )
            .detail(format!("path={}", path.display()))
            .emit();
            HostSnapshotKey::Created(path)
        }
        mvm_core::atomic_io::NewFile::AlreadyPresent => {
            HostSnapshotKey::Existing(SnapshotKeySource::HomeKeyFile)
        }
    })
}

/// Write 32 fresh random bytes to `path` at mode 0600, inside a 0700
/// `keys_dir`, unless a file is already there.
fn mint_key_file(keys_dir: &Path, path: &Path) -> std::io::Result<mvm_core::atomic_io::NewFile> {
    use rand::Rng as _;
    mvm_core::config::create_private_dir(keys_dir)?;
    let mut key = zeroize::Zeroizing::new([0u8; KEY_SIZE]);
    rand::rng().fill_bytes(key.as_mut_slice());
    mvm_core::atomic_io::write_private_new(path, key.as_slice())
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
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
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

    // ── Provisioning ────────────────────────────────────────────────────

    use std::os::unix::fs::PermissionsExt as _;

    /// A fresh mvm home with no explicit key, for the provisioning tests.
    fn fresh_home() -> (TestEnv, tempfile::TempDir) {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        env.remove(SNAPSHOT_TENANT_KEY_ENV);
        (env, home)
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn plant_key(bytes: &[u8], mode: u32) -> PathBuf {
        let dir = mvm_core::config::mvm_keys_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let path = home_key_path(&dir);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn a_fresh_home_is_provisioned_a_private_key_and_the_creation_is_audited() {
        let (_env, home) = fresh_home();
        let path = home.path().join("keys").join("local.key");

        let outcome = ensure_host_snapshot_key().expect("provisioned");

        assert_eq!(outcome, HostSnapshotKey::Created(path.clone()));
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(mode_of(&mvm_core::config::mvm_keys_dir()), 0o700);
        assert_eq!(mode_of(home.path()), 0o700);
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), KEY_SIZE);
        assert_ne!(bytes, vec![0; KEY_SIZE], "minted from the CSPRNG");
        let admitted = admit_host_snapshot_key().expect("the provisioned key is admitted");
        assert_eq!(admitted.expose(), bytes.as_slice());

        let log = std::fs::read_to_string(mvm_core::policy::audit::default_audit_log())
            .expect("creation audited");
        assert!(log.contains("snapshot_key_created"), "{log}");
        assert!(log.contains(&path.display().to_string()), "{log}");
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!log.contains(&hex), "the audit entry never carries the key");
    }

    #[test]
    fn an_existing_key_is_reused_byte_for_byte_and_never_rewritten() {
        let (_env, _home) = fresh_home();
        let path = plant_key(&[5; KEY_SIZE], 0o600);

        for _ in 0..2 {
            assert_eq!(
                ensure_host_snapshot_key().expect("admitted"),
                HostSnapshotKey::Existing(SnapshotKeySource::HomeKeyFile)
            );
            assert_eq!(std::fs::read(&path).unwrap(), vec![5; KEY_SIZE]);
        }
        assert_eq!(admit_host_snapshot_key().unwrap().expose(), [5; KEY_SIZE]);
        assert!(
            !Path::new(&mvm_core::policy::audit::default_audit_log()).exists(),
            "reusing a key creates nothing to audit"
        );
    }

    #[test]
    fn a_provisioned_key_is_reused_on_the_next_call() {
        let (_env, _home) = fresh_home();
        let HostSnapshotKey::Created(path) = ensure_host_snapshot_key().unwrap() else {
            panic!("a fresh home is provisioned");
        };
        let first = std::fs::read(&path).unwrap();
        assert_eq!(
            ensure_host_snapshot_key().unwrap(),
            HostSnapshotKey::Existing(SnapshotKeySource::HomeKeyFile)
        );
        assert_eq!(std::fs::read(&path).unwrap(), first);
    }

    #[test]
    fn a_key_another_user_could_read_is_refused_and_left_alone() {
        let (_env, _home) = fresh_home();
        for (mode, bytes) in [(0o644, vec![3; KEY_SIZE]), (0o600, vec![3; KEY_SIZE - 1])] {
            let path = plant_key(&bytes, mode);

            let err = ensure_host_snapshot_key().expect_err("refused");

            assert!(
                matches!(
                    err,
                    SnapshotKeyProvisionError::Refused(SnapshotKeyError::Invalid {
                        origin: SnapshotKeySource::HomeKeyFile
                    })
                ),
                "{err:?}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), bytes, "never overwritten");
            assert_eq!(mode_of(&path), mode, "never re-permissioned");
            assert_eq!(
                admit_host_snapshot_key().unwrap_err(),
                SnapshotKeyError::Invalid {
                    origin: SnapshotKeySource::HomeKeyFile
                }
            );
        }
    }

    #[test]
    fn the_explicit_variable_wins_and_nothing_is_provisioned() {
        let (mut env, home) = fresh_home();
        env.set(SNAPSHOT_TENANT_KEY_ENV, KEY_HEX);
        plant_key(&[5; KEY_SIZE], 0o600);

        assert_eq!(
            ensure_host_snapshot_key().expect("admitted"),
            HostSnapshotKey::Existing(SnapshotKeySource::Explicit)
        );
        assert_eq!(
            admit_host_snapshot_key().unwrap().expose()[..2],
            [0x01, 0x23]
        );

        std::fs::remove_dir_all(home.path().join("keys")).unwrap();
        ensure_host_snapshot_key().expect("admitted");
        assert!(
            !home.path().join("keys").exists(),
            "an override provisions nothing"
        );
    }

    #[test]
    fn a_malformed_explicit_key_is_refused_rather_than_provisioned_around() {
        let (mut env, home) = fresh_home();
        env.set(SNAPSHOT_TENANT_KEY_ENV, "q7".repeat(KEY_SIZE));
        assert!(matches!(
            ensure_host_snapshot_key().unwrap_err(),
            SnapshotKeyProvisionError::Refused(SnapshotKeyError::Invalid {
                origin: SnapshotKeySource::Explicit
            })
        ));
        assert!(!home.path().join("keys").exists());
    }

    /// A key a stronger source holds is used, and the key directory is not
    /// touched.
    #[test]
    fn a_key_in_another_source_is_used_without_provisioning() {
        let dir = tempfile::tempdir().unwrap();
        let stores = SnapshotKeyResolver::empty()
            .source(SnapshotKeySource::Keystore, Box::new(Fixed(|| key_of(7))));
        assert_eq!(
            ensure_with(stores, dir.path()).unwrap(),
            HostSnapshotKey::Existing(SnapshotKeySource::Keystore)
        );
        assert!(!home_key_path(dir.path()).exists());
    }

    /// A tenant's key is never looked up in the key directory mvm
    /// provisions for the host.
    #[test]
    fn a_tenant_is_never_resolved_from_the_provisioned_host_key_directory() {
        let (mut env, _home) = fresh_home();
        env.remove("MVM_TENANT_KEY_ACME");
        let dir = mvm_core::config::mvm_keys_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let tenant_key = dir.join("acme.key");
        std::fs::write(&tenant_key, [4; KEY_SIZE]).unwrap();
        std::fs::set_permissions(&tenant_key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            SnapshotKeyResolver::host_for("acme")
                .admit_for("acme")
                .unwrap_err(),
            SnapshotKeyError::Missing
        );
    }
}
