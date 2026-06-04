//! Tenant key provisioning for the Phase 2 encryption-at-rest path.
//!
//! `KeyProvider` is the trait every encryption-at-rest caller
//! consumes; three impls layer from dev-friendly to ops-friendly:
//!
//! - [`EnvKeyProvider`] reads `MVM_TENANT_KEY_<TENANT_ID>` (hex).
//!   Dev / CI use only — never in production.
//! - [`FileKeyProvider`] reads raw 32 bytes from
//!   `/var/lib/mvm/keys/<tenant_id>.key`, mode 0600 / 0400. Node-
//!   local key provisioning for fleets that pre-distribute keys via
//!   config management.
//! - [`KeyringProvider`] reads a hex-encoded key from the
//!   OS-native keystore (macOS Keychain, Linux Secret Service,
//!   Windows Credential Manager). Lives at service=`"mvm"`,
//!   user=`<tenant_id>`. Plan 63 W3.
//!
//! [`default_provider`] auto-detects the providers available on the
//! current host and tries them in strength order for each tenant:
//! KeyringProvider if a backend is reachable, FileKeyProvider if
//! `/var/lib/mvm/keys/` exists, then EnvKeyProvider for dev / CI.
//!
//! Returned keys wrap `SecretBox<Vec<u8>>` — guarantees zeroize-on-
//! drop AND forbids accidental `Debug`/`Display` at compile time (you
//! must explicitly call `.expose_secret()` to read the bytes).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use secrecy::SecretBox;

/// Required key size for AES-256-GCM: 256 bits / 32 bytes.
pub const KEY_SIZE: usize = 32;

/// Default base directory for [`FileKeyProvider`] when no override
/// is supplied. Per-tenant key files live at
/// `<KEYS_DIR>/<tenant_id>.key` as raw 32 bytes.
pub const DEFAULT_KEYS_DIR: &str = "/var/lib/mvm/keys";

/// Service name passed to the OS-native keystore by
/// [`KeyringProvider`]. macOS Keychain, Linux Secret Service, and
/// Windows Credential Manager all key entries by `(service, user)`;
/// the user half is the tenant id.
pub const KEYRING_SERVICE: &str = "mvm";

/// macOS Keychain item-target used for disambiguation when multiple
/// generic-password items share `(service, user)`. Passed via
/// `keyring::Entry::new_with_target` on macOS to keep mvm entries
/// confined to one logical group.
pub const KEYRING_TARGET: &str = "mvm-tenant-keys";

/// Resolves a tenant's data-encryption key.
pub trait KeyProvider: Send + Sync {
    /// Return the data encryption key for `tenant_id`. Returned bytes
    /// are wrapped in `SecretBox` so material is wiped on drop and
    /// cannot be accidentally logged.
    fn get_data_key(&self, tenant_id: &str) -> Result<SecretBox<Vec<u8>>>;
}

/// Reads keys from `MVM_TENANT_KEY_<TENANT_ID>` (hex-encoded, 64
/// chars for 32 bytes). Hyphens in tenant IDs become underscores in
/// the env var name and the ID is uppercased.
pub struct EnvKeyProvider;

impl KeyProvider for EnvKeyProvider {
    fn get_data_key(&self, tenant_id: &str) -> Result<SecretBox<Vec<u8>>> {
        validate_shell_id(tenant_id)
            .with_context(|| format!("Invalid tenant_id for key lookup: {tenant_id:?}"))?;
        let var = format!(
            "MVM_TENANT_KEY_{}",
            tenant_id.to_uppercase().replace('-', "_")
        );
        let hex = std::env::var(&var)
            .with_context(|| format!("Missing encryption key env var: {var}"))?;
        let key = hex_decode(&hex).with_context(|| format!("Invalid hex in {var}"))?;
        if key.len() != KEY_SIZE {
            anyhow::bail!(
                "Tenant key in {var} must be {KEY_SIZE} bytes ({} hex chars), got {} bytes",
                KEY_SIZE * 2,
                key.len()
            );
        }
        Ok(SecretBox::new(Box::new(key)))
    }
}

/// Reads raw 32-byte keys from `<keys_dir>/<tenant_id>.key`.
/// Refuses to read files whose mode is looser than `0600` / `0400`
/// — provisioning workflows that drop keys on disk must tighten
/// perms first.
///
/// Construct via [`FileKeyProvider::default`] (uses
/// [`DEFAULT_KEYS_DIR`]) or [`FileKeyProvider::with_dir`] for tests
/// / non-standard installs.
pub struct FileKeyProvider {
    keys_dir: PathBuf,
}

impl FileKeyProvider {
    /// Override the keys directory. Tests use this with a tempdir.
    pub fn with_dir(keys_dir: impl Into<PathBuf>) -> Self {
        Self {
            keys_dir: keys_dir.into(),
        }
    }

    /// Returns true if the keys directory exists and is a directory.
    /// Cheap — used by [`default_provider`] to decide whether to
    /// instantiate `FileKeyProvider` at all.
    pub fn keys_dir_present(keys_dir: &Path) -> bool {
        keys_dir.is_dir()
    }
}

impl Default for FileKeyProvider {
    fn default() -> Self {
        Self::with_dir(DEFAULT_KEYS_DIR)
    }
}

impl KeyProvider for FileKeyProvider {
    fn get_data_key(&self, tenant_id: &str) -> Result<SecretBox<Vec<u8>>> {
        validate_shell_id(tenant_id)
            .with_context(|| format!("Invalid tenant_id for key lookup: {tenant_id:?}"))?;
        let path = self.keys_dir.join(format!("{tenant_id}.key"));
        let meta = std::fs::metadata(&path)
            .with_context(|| format!("stat key file {}", path.display()))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 && mode != 0o400 {
            anyhow::bail!(
                "key file {} has mode 0{mode:o}; refuse to read (require 0600 or 0400)",
                path.display(),
            );
        }
        let bytes =
            std::fs::read(&path).with_context(|| format!("read key file {}", path.display()))?;
        if bytes.len() != KEY_SIZE {
            anyhow::bail!(
                "key file {} is {} bytes (expected {KEY_SIZE})",
                path.display(),
                bytes.len(),
            );
        }
        Ok(SecretBox::new(Box::new(bytes)))
    }
}

/// Reads hex-encoded keys from the OS-native keystore. The keystore
/// entry uses `(KEYRING_SERVICE, tenant_id)` keyed against
/// [`KEYRING_TARGET`] on macOS for item-disambiguation.
///
/// Construct via [`KeyringProvider::default`]. Falls back to
/// `Entry::new` on non-macOS where `new_with_target` is unnecessary.
pub struct KeyringProvider;

impl KeyringProvider {
    /// Open the keyring entry for a given tenant. Used by both
    /// `get_data_key` here and by W4's `mvmctl secret` CLI.
    pub fn entry(tenant_id: &str) -> Result<keyring::Entry> {
        validate_shell_id(tenant_id)
            .with_context(|| format!("Invalid tenant_id for keyring lookup: {tenant_id:?}"))?;
        #[cfg(target_os = "macos")]
        {
            keyring::Entry::new_with_target(KEYRING_TARGET, KEYRING_SERVICE, tenant_id)
                .with_context(|| {
                    format!("opening macOS Keychain entry for {KEYRING_SERVICE}:{tenant_id}")
                })
        }
        #[cfg(not(target_os = "macos"))]
        {
            keyring::Entry::new(KEYRING_SERVICE, tenant_id)
                .with_context(|| format!("opening keyring entry for {KEYRING_SERVICE}:{tenant_id}"))
        }
    }

    /// Cheap reachability check: can we construct an [`keyring::Entry`]
    /// at all on this host? Used by [`default_provider`] to decide
    /// whether to layer `KeyringProvider` first.
    pub fn backend_reachable() -> bool {
        // Constructing an entry doesn't talk to the backend yet on
        // every OS; this is a heuristic that the keyring crate's
        // constructor succeeds (i.e., a backend is compiled in and
        // reachable). False positives are acceptable — a real
        // `get_password` may still fail with NoEntry; callers fall
        // through to the next provider.
        Self::entry("__mvm_probe__").is_ok()
    }
}

impl Default for KeyringProvider {
    fn default() -> Self {
        Self
    }
}

impl KeyProvider for KeyringProvider {
    fn get_data_key(&self, tenant_id: &str) -> Result<SecretBox<Vec<u8>>> {
        let entry = Self::entry(tenant_id)?;
        let hex = entry
            .get_password()
            .with_context(|| format!("reading keyring entry for {tenant_id}"))?;
        let key = hex_decode(&hex)
            .with_context(|| format!("decoding hex key from keyring for {tenant_id}"))?;
        if key.len() != KEY_SIZE {
            anyhow::bail!(
                "keyring entry for {tenant_id} decoded to {} bytes (expected {KEY_SIZE})",
                key.len()
            );
        }
        Ok(SecretBox::new(Box::new(key)))
    }
}

/// Ordered fallback provider used by [`default_provider`].
struct FallbackKeyProvider {
    providers: Vec<Box<dyn KeyProvider>>,
}

impl FallbackKeyProvider {
    fn new(providers: Vec<Box<dyn KeyProvider>>) -> Self {
        Self { providers }
    }
}

impl KeyProvider for FallbackKeyProvider {
    fn get_data_key(&self, tenant_id: &str) -> Result<SecretBox<Vec<u8>>> {
        let mut errors = Vec::new();
        for provider in &self.providers {
            match provider.get_data_key(tenant_id) {
                Ok(key) => return Ok(key),
                Err(err) => errors.push(err.to_string()),
            }
        }
        Err(anyhow::anyhow!(
            "no tenant data-encryption key found for {tenant_id}: {}",
            errors.join(" | ")
        ))
    }
}

/// Auto-select the available providers for the current host.
///
/// Order is biased toward stronger sources first and falls through
/// per tenant when a stronger backend has no key configured:
///
/// 1. [`KeyringProvider`] — if an OS-native keystore entry can be
///    constructed (macOS Keychain / Linux Secret Service /
///    Windows Cred Mgr).
/// 2. [`FileKeyProvider`] — if [`DEFAULT_KEYS_DIR`] exists.
/// 3. [`EnvKeyProvider`] — last resort; dev / CI only.
///
/// The function never fails — it always returns a fallback provider,
/// even if no key is actually configured for any tenant. Whether a
/// specific tenant key exists is the question [`has_key`] answers.
pub fn default_provider() -> Box<dyn KeyProvider> {
    let mut providers: Vec<Box<dyn KeyProvider>> = Vec::new();
    if KeyringProvider::backend_reachable() {
        providers.push(Box::new(KeyringProvider));
    }
    if FileKeyProvider::keys_dir_present(Path::new(DEFAULT_KEYS_DIR)) {
        providers.push(Box::new(FileKeyProvider::default()));
    }
    providers.push(Box::new(EnvKeyProvider));
    Box::new(FallbackKeyProvider::new(providers))
}

/// Returns true if [`default_provider`] can successfully resolve a
/// key for `tenant_id`. Used by encryption-at-rest call sites to
/// decide whether to switch on LUKS for a data volume.
pub fn has_key(tenant_id: &str) -> bool {
    default_provider().get_data_key(tenant_id).is_ok()
}

/// Reject any identifier that can't safely be interpolated into a
/// shell command, filesystem path, or env-var name. Accepts only
/// `[A-Za-z0-9_-]` and a non-empty string.
pub fn validate_shell_id(s: &str) -> Result<()> {
    if s.is_empty() {
        anyhow::bail!("identifier must not be empty");
    }
    if let Some(bad) = s
        .chars()
        .find(|c| !c.is_alphanumeric() && *c != '-' && *c != '_')
    {
        anyhow::bail!(
            "identifier contains unsafe character {bad:?} — only alphanumeric, '-', '_' allowed"
        );
    }
    Ok(())
}

/// Hex-decode an even-length ASCII string into bytes.
fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        anyhow::bail!("Hex string has odd length: {}", hex.len());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let s = std::str::from_utf8(chunk)?;
        let byte = u8::from_str_radix(s, 16).with_context(|| format!("Invalid hex byte: {s}"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_KEY_HEX: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    #[test]
    fn hex_decode_valid() {
        assert_eq!(
            hex_decode("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(hex_decode("00ff").unwrap(), vec![0x00, 0xff]);
    }

    #[test]
    fn hex_decode_empty_is_empty() {
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn hex_decode_odd_length_rejected() {
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn hex_decode_invalid_chars_rejected() {
        assert!(hex_decode("zzzz").is_err());
    }

    #[test]
    fn env_provider_missing_var() {
        unsafe { std::env::remove_var("MVM_TENANT_KEY_ACME") };
        assert!(EnvKeyProvider.get_data_key("acme").is_err());
    }

    #[test]
    fn env_provider_returns_secret_key_of_right_length() {
        use secrecy::ExposeSecret;
        unsafe { std::env::set_var("MVM_TENANT_KEY_TESTX", VALID_KEY_HEX) };
        let key = EnvKeyProvider.get_data_key("testx").unwrap();
        // `expose_secret()` is the only path to the bytes — that's
        // the point of SecretBox.
        assert_eq!(key.expose_secret().len(), KEY_SIZE);
        unsafe { std::env::remove_var("MVM_TENANT_KEY_TESTX") };
    }

    #[test]
    fn env_provider_uppercases_and_swaps_hyphens_to_secret() {
        use secrecy::ExposeSecret;
        unsafe { std::env::set_var("MVM_TENANT_KEY_FOO_BAR", VALID_KEY_HEX) };
        let key = EnvKeyProvider.get_data_key("foo-bar").unwrap();
        assert_eq!(key.expose_secret().len(), KEY_SIZE);
        unsafe { std::env::remove_var("MVM_TENANT_KEY_FOO_BAR") };
    }

    #[test]
    fn env_provider_rejects_wrong_length_key() {
        unsafe { std::env::set_var("MVM_TENANT_KEY_BADLEN", "deadbeef") };
        let err = EnvKeyProvider.get_data_key("badlen").unwrap_err();
        assert!(err.to_string().contains("must be 32 bytes"), "got: {err}");
        unsafe { std::env::remove_var("MVM_TENANT_KEY_BADLEN") };
    }

    #[test]
    fn env_provider_rejects_invalid_tenant_id() {
        // Path traversal / shell-injection candidates must be rejected
        // *before* any env lookup happens.
        assert!(EnvKeyProvider.get_data_key("../../etc").is_err());
        assert!(EnvKeyProvider.get_data_key("foo;rm").is_err());
    }

    #[test]
    fn validate_shell_id_accepts_alphanumeric_dash_underscore() {
        assert!(validate_shell_id("acme").is_ok());
        assert!(validate_shell_id("tenant-1").is_ok());
        assert!(validate_shell_id("my_tenant_99").is_ok());
        assert!(validate_shell_id("ABC123").is_ok());
    }

    #[test]
    fn validate_shell_id_rejects_empty() {
        assert!(validate_shell_id("").is_err());
    }

    #[test]
    fn validate_shell_id_rejects_shell_metachars() {
        assert!(validate_shell_id("foo;rm -rf /").is_err());
        assert!(validate_shell_id("foo|bar").is_err());
        assert!(validate_shell_id("foo`bar`").is_err());
        assert!(validate_shell_id("foo$bar").is_err());
    }

    #[test]
    fn validate_shell_id_rejects_whitespace() {
        assert!(validate_shell_id("foo bar").is_err());
        assert!(validate_shell_id("foo\tbar").is_err());
    }

    #[test]
    fn validate_shell_id_rejects_dot_and_slash() {
        assert!(validate_shell_id("foo.bar").is_err());
        assert!(validate_shell_id("../../etc/passwd").is_err());
    }

    // ──────────────────────────────────────────────────────────────
    // FileKeyProvider (W3)
    // ──────────────────────────────────────────────────────────────

    fn write_key_file(dir: &Path, tenant: &str, bytes: &[u8], mode: u32) -> PathBuf {
        use std::os::unix::fs::OpenOptionsExt;
        let path = dir.join(format!("{tenant}.key"));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut f, bytes).unwrap();
        path
    }

    #[test]
    fn file_key_provider_reads_0600_key() {
        use secrecy::ExposeSecret;
        let tmp = tempfile::tempdir().unwrap();
        let key_bytes = [7u8; KEY_SIZE];
        write_key_file(tmp.path(), "acme", &key_bytes, 0o600);

        let provider = FileKeyProvider::with_dir(tmp.path());
        let key = provider.get_data_key("acme").unwrap();
        assert_eq!(key.expose_secret().as_slice(), &key_bytes);
    }

    #[test]
    fn file_key_provider_reads_0400_key() {
        use secrecy::ExposeSecret;
        let tmp = tempfile::tempdir().unwrap();
        let key_bytes = [9u8; KEY_SIZE];
        write_key_file(tmp.path(), "acme", &key_bytes, 0o400);

        let provider = FileKeyProvider::with_dir(tmp.path());
        let key = provider.get_data_key("acme").unwrap();
        assert_eq!(key.expose_secret().as_slice(), &key_bytes);
    }

    #[test]
    fn file_key_provider_rejects_world_readable() {
        // mode 0644 is the canonical "looks fine, isn't" — refuse
        // to read rather than silently expose the key bytes.
        let tmp = tempfile::tempdir().unwrap();
        write_key_file(tmp.path(), "acme", &[0u8; KEY_SIZE], 0o644);

        let provider = FileKeyProvider::with_dir(tmp.path());
        let err = provider.get_data_key("acme").unwrap_err();
        let s = err.to_string();
        assert!(
            s.contains("mode 0644") && s.contains("refuse"),
            "want clear refusal mentioning the bad mode; got {s}"
        );
    }

    #[test]
    fn file_key_provider_rejects_wrong_length() {
        let tmp = tempfile::tempdir().unwrap();
        write_key_file(tmp.path(), "acme", b"only-eight-bytes", 0o600);

        let provider = FileKeyProvider::with_dir(tmp.path());
        let err = provider.get_data_key("acme").unwrap_err();
        assert!(
            err.to_string().contains(&format!("expected {KEY_SIZE}")),
            "want size mismatch error, got {err}"
        );
    }

    #[test]
    fn file_key_provider_missing_file_errors_clearly() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = FileKeyProvider::with_dir(tmp.path());
        let err = provider.get_data_key("nobody").unwrap_err();
        // The OS-level "no such file" wrapped in our context.
        let s = err.to_string();
        assert!(s.contains("stat key file") || s.contains("nobody"));
    }

    #[test]
    fn file_key_provider_rejects_unsafe_tenant_id() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = FileKeyProvider::with_dir(tmp.path());
        // validate_shell_id should refuse before any fs::metadata
        // call — guards against `../../etc/passwd`-style tenants.
        assert!(provider.get_data_key("../../etc").is_err());
        assert!(provider.get_data_key("foo;rm").is_err());
    }

    #[test]
    fn file_key_provider_keys_dir_present_returns_false_for_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let bogus = tmp.path().join("does-not-exist");
        assert!(!FileKeyProvider::keys_dir_present(&bogus));
        assert!(FileKeyProvider::keys_dir_present(tmp.path()));
    }

    // ──────────────────────────────────────────────────────────────
    // KeyringProvider (W3)
    //
    // The keyring crate's behaviour depends on a backend being
    // reachable (macOS Keychain / Linux Secret Service via D-Bus /
    // Windows Cred Mgr). CI Linux runners typically have no D-Bus
    // session, so these tests are written to *not* require a live
    // backend — they exercise the validation guards and the
    // backend-reachable probe's structure.
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn keyring_provider_rejects_unsafe_tenant_id_before_backend_call() {
        // Even if no backend is reachable, validate_shell_id should
        // fail first — the test never touches the keystore.
        let provider = KeyringProvider;
        assert!(provider.get_data_key("../../etc").is_err());
        assert!(provider.get_data_key("foo;rm").is_err());
    }

    #[test]
    fn keyring_provider_entry_constructor_validates_tenant() {
        // The entry() constructor must reject shell-unsafe tenant
        // names *before* hitting the keyring backend, so CLI surfaces
        // that take a tenant flag can't escape through it.
        assert!(KeyringProvider::entry("").is_err());
        assert!(KeyringProvider::entry("foo bar").is_err());
        assert!(KeyringProvider::entry("../../etc").is_err());
    }

    // ──────────────────────────────────────────────────────────────
    // default_provider + has_key (W3)
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn default_provider_returns_some_provider_always() {
        // Either a keyring or file or env provider — never panics.
        // We don't assert *which* impl since that depends on the
        // host's keystore availability + filesystem layout.
        let _provider = default_provider();
    }

    #[test]
    fn default_provider_falls_back_to_env_key_for_tenant() {
        use secrecy::ExposeSecret;

        let tenant = "mvm-test-env-fallback";
        let var = "MVM_TENANT_KEY_MVM_TEST_ENV_FALLBACK";
        unsafe { std::env::set_var(var, VALID_KEY_HEX) };
        let key = default_provider().get_data_key(tenant).unwrap();
        assert_eq!(key.expose_secret().len(), KEY_SIZE);
        unsafe { std::env::remove_var(var) };
    }

    #[test]
    fn has_key_returns_false_for_unconfigured_tenant() {
        // Pick a tenant id no test ever writes a key for. Cleanup
        // any straggler env var defensively.
        let tenant = "mvm-test-unconfigured-tenant-xyz";
        unsafe {
            std::env::remove_var(format!(
                "MVM_TENANT_KEY_{}",
                tenant.to_uppercase().replace('-', "_")
            ));
        }
        assert!(!has_key(tenant));
    }
}
