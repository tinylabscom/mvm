//! Tenant secret storage.
//!
//! Operators provision tenant-scoped secrets (API tokens, OAuth
//! refresh tokens, webhook signing secrets, etc.) via `mvmctl
//! secret put`. The supervisor surfaces them inside a workload's
//! sandbox via `/run/mvm-secrets/<name>` at admission time (the
//! `mvm-supervisor::keystore::SecretGrant`).
//!
//! ## Storage backends
//!
//! - [`FileSecretStore`] — primary; works on every supported host.
//!   Each secret lives at `<base>/<tenant>/<name>` with mode 0600,
//!   parent dirs mode 0700, and AES-256-GCM encrypted contents.
//!   Enumeration is a directory scan.
//! - [`KeyringSecretStore`] — used when the OS-native keystore is
//!   reachable. Each secret lives at the keyring entry
//!   `(service="mvm-secrets", user="<tenant>:<name>")`. An index
//!   sidecar at `<base>/<tenant>.json` mirrors the names so `ls`
//!   doesn't depend on backend-specific enumeration (the `keyring`
//!   crate's enumeration is uneven across backends).
//!
//! [`default_secret_store`] auto-picks an aggregate backend when
//! Keyring is reachable: writes prefer Keyring, while reads,
//! listing, and deletion keep file-backed secrets visible. Set
//! `MVM_SECRET_STORE_BACKEND=file` to pin the file backend
//! (escape hatch for hosts where the keyring's
//! reachability probe lies — Linux CI runners with `libsecret`
//! headers but no live `secret-service` daemon are the canonical
//! case).
//!
//! ## Why two backends
//!
//! `KeyringSecretStore` stores values inside macOS Keychain / Linux
//! Secret Service / Windows Credential Manager — the OS keystore
//! is the strongest at-rest protection available on a non-attested
//! host. But CI Linux runners typically have no D-Bus session;
//! `FileSecretStore` is the dependable fallback that works
//! everywhere, but values are still encrypted before touching disk.
//!
//! ## What this module does NOT do
//!
//! - **Inject secrets into VMs.** That's the supervisor's
//!   `KeystoreReleaser`. This module is the operator-facing CRUD
//!   surface; the supervisor pulls from it at admission.
//! - **Multi-host replication.** Single-host only; mvmd's secret
//!   service handles fleets.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::keystore::validate_shell_id;
use crate::crypto::snapshot_crypto;

/// Service name for OS-native keyring entries. Distinct from
/// `crate::crypto::keystore::KEYRING_SERVICE` so per-tenant master
/// keys and per-name tenant secrets don't collide.
pub const KEYRING_SERVICE: &str = "mvm-secrets";
#[cfg(target_os = "macos")]
const KEYRING_TARGET: &str = "mvm-tenant-secrets";

/// Default base dir for [`FileSecretStore`]:
/// `~/.mvm/secrets/`. Per-tenant subdir mode 0700, per-secret file
/// mode 0600.
pub fn default_secrets_dir() -> Result<PathBuf> {
    Ok(crate::config::mvm_data_dir_strict()?.join("secrets"))
}

const FILE_SECRET_MAGIC: &[u8] = b"MVMS1\0";
const FILE_STORE_KEY_FILENAME: &str = ".secret-store.key";
const FILE_STORE_KEYRING_SERVICE: &str = "mvm-secret-store";
#[cfg(target_os = "macos")]
const FILE_STORE_KEYRING_TARGET: &str = "mvm-file-secret-store";
const FILE_STORE_KEYRING_USER: &str = "file-backend-key";

/// Multi-key tenant-scoped secret store. Separate from
/// [`crate::crypto::keystore::KeyProvider`] (which is single-key, tenant-
/// scoped, used for the per-tenant *master DEK*).
pub trait SecretStore: Send + Sync {
    /// Store `value` under `(tenant, name)`. Overwrites any
    /// existing value silently — operators rotating a token want
    /// `put` to be a no-fuss replace.
    fn put(&self, tenant: &str, name: &str, value: &SecretBox<String>) -> Result<()>;

    /// Resolve the value stored at `(tenant, name)`. Fails if no
    /// entry exists.
    fn get(&self, tenant: &str, name: &str) -> Result<SecretBox<String>>;

    /// Remove `(tenant, name)`. Fails if the entry doesn't exist —
    /// callers that want "idempotent rm" should check `list` first.
    fn delete(&self, tenant: &str, name: &str) -> Result<()>;

    /// List every secret name stored for `tenant`. Returns an empty
    /// vec when the tenant has no secrets. Does **not** return
    /// values — values never leave the store except via `get`.
    fn list(&self, tenant: &str) -> Result<Vec<String>>;
}

/// File-backed secret store. The primary cross-platform impl —
/// works on every host because it depends only on the local
/// filesystem.
///
/// Layout: `<base>/<tenant>/<name>`. Per-secret file mode 0600;
/// per-tenant dir mode 0700. The base dir is created lazily on
/// first write.
pub struct FileSecretStore {
    base: PathBuf,
    key_path: PathBuf,
    keyring_user: String,
    use_keyring_key: bool,
}

impl FileSecretStore {
    pub fn with_dir(base: impl Into<PathBuf>) -> Self {
        Self::with_dir_and_keyring(base, false)
    }

    fn with_dir_and_keyring(base: impl Into<PathBuf>, use_keyring_key: bool) -> Self {
        let base = base.into();
        let key_path = default_key_path_for_base(&base);
        let keyring_user = keyring_user_for_base(&base);
        Self {
            base,
            key_path,
            keyring_user,
            use_keyring_key,
        }
    }

    fn tenant_dir(&self, tenant: &str) -> Result<PathBuf> {
        validate_shell_id(tenant)
            .with_context(|| format!("Invalid tenant_id for secret lookup: {tenant:?}"))?;
        Ok(self.base.join(tenant))
    }

    fn secret_path(&self, tenant: &str, name: &str) -> Result<PathBuf> {
        validate_shell_id(name).with_context(|| format!("Invalid secret name: {name:?}"))?;
        Ok(self.tenant_dir(tenant)?.join(name))
    }

    fn ensure_tenant_dir(&self, tenant: &str) -> Result<PathBuf> {
        let dir = self.tenant_dir(tenant)?;
        if !dir.exists() {
            fs::create_dir_all(&dir)
                .with_context(|| format!("creating tenant secret dir {}", dir.display()))?;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod 0700 {}", dir.display()))?;
        }
        Ok(dir)
    }

    fn load_or_init_key(&self) -> Result<SecretBox<Vec<u8>>> {
        if self.use_keyring_key
            && let Ok(key) = load_or_init_keyring_key(&self.keyring_user)
        {
            return Ok(key);
        }
        load_or_init_file_key(&self.key_path)
    }
}

impl Default for FileSecretStore {
    fn default() -> Self {
        // Falls back to `./.mvm/secrets/` if $HOME is unset; callers
        // that care about absolute paths should construct via
        // `with_dir(default_secrets_dir()?)` and surface the env
        // error.
        let base = default_secrets_dir().unwrap_or_else(|_| PathBuf::from(".mvm").join("secrets"));
        Self::with_dir(base)
    }
}

impl SecretStore for FileSecretStore {
    fn put(&self, tenant: &str, name: &str, value: &SecretBox<String>) -> Result<()> {
        self.ensure_tenant_dir(tenant)?;
        let path = self.secret_path(tenant, name)?;
        let tmp = path.with_extension("tmp");
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .with_context(|| format!("creating {}", tmp.display()))?;
            let key = self.load_or_init_key()?;
            let encoded =
                encrypt_file_secret(value.expose_secret().as_bytes(), key.expose_secret())
                    .context("encrypting secret for file store")?;
            f.write_all(&encoded)
                .with_context(|| format!("writing {}", tmp.display()))?;
            f.sync_all().ok();
        }
        fs::rename(&tmp, &path)
            .with_context(|| format!("atomic rename {} → {}", tmp.display(), path.display()))?;
        Ok(())
    }

    fn get(&self, tenant: &str, name: &str) -> Result<SecretBox<String>> {
        let path = self.secret_path(tenant, name)?;
        let meta = fs::metadata(&path).with_context(|| {
            format!(
                "no secret '{name}' for tenant '{tenant}' (path {})",
                path.display()
            )
        })?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            anyhow::bail!("secret {} has mode 0{mode:o}; require 0600", path.display());
        }
        let bytes =
            fs::read(&path).with_context(|| format!("reading secret {}", path.display()))?;
        let key = self.load_or_init_key()?;
        let plaintext = decrypt_file_secret(&bytes, key.expose_secret())
            .with_context(|| format!("decrypting secret {}", path.display()))?;
        let s = String::from_utf8(plaintext)
            .with_context(|| format!("secret {} is not valid UTF-8", path.display()))?;
        Ok(SecretBox::new(Box::new(s)))
    }

    fn delete(&self, tenant: &str, name: &str) -> Result<()> {
        let path = self.secret_path(tenant, name)?;
        fs::remove_file(&path).with_context(|| format!("removing secret {}", path.display()))?;
        Ok(())
    }

    fn list(&self, tenant: &str) -> Result<Vec<String>> {
        let dir = self.tenant_dir(tenant)?;
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in fs::read_dir(&dir).with_context(|| format!("listing {}", dir.display()))? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy().to_string();
            // Skip the `.tmp` files our atomic-write helper may
            // leave behind on crash; they're not real secrets.
            if name.ends_with(".tmp") {
                continue;
            }
            if name == FILE_STORE_KEY_FILENAME {
                continue;
            }
            names.push(name);
        }
        names.sort();
        Ok(names)
    }
}

fn default_key_path_for_base(base: &Path) -> PathBuf {
    if base.file_name().is_some_and(|name| name == "secrets")
        && let Some(parent) = base.parent()
    {
        return parent.join(FILE_STORE_KEY_FILENAME);
    }
    base.join(FILE_STORE_KEY_FILENAME)
}

fn keyring_user_for_base(base: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(base.as_os_str().as_encoded_bytes());
    format!(
        "{}:{}",
        FILE_STORE_KEYRING_USER,
        hex_encode(&hasher.finalize())
    )
}

fn load_or_init_keyring_key(user: &str) -> Result<SecretBox<Vec<u8>>> {
    let entry = file_store_keyring_entry(user)?;
    match entry.get_password() {
        Ok(hex) => {
            let key = hex_decode(&hex).context("decoding file secret-store key")?;
            validate_file_store_key_len(&key)?;
            Ok(SecretBox::new(Box::new(key)))
        }
        Err(keyring::Error::NoEntry) => {
            let mut key = Zeroizing::new(vec![0u8; snapshot_crypto::KEY_SIZE]);
            rand::thread_rng().fill_bytes(&mut key);
            let encoded = hex_encode(&key);
            entry
                .set_password(&encoded)
                .context("writing file secret-store keyring entry")?;
            let stored = entry
                .get_password()
                .context("verifying file secret-store keyring entry")?;
            if stored != encoded {
                anyhow::bail!("file secret-store keyring entry failed read-after-write check");
            }
            Ok(SecretBox::new(Box::new(key.to_vec())))
        }
        Err(err) => Err(err).context("reading file secret-store keyring entry"),
    }
}

fn file_store_keyring_entry(user: &str) -> Result<keyring::Entry> {
    #[cfg(target_os = "macos")]
    {
        keyring::Entry::new_with_target(FILE_STORE_KEYRING_TARGET, FILE_STORE_KEYRING_SERVICE, user)
            .context("opening macOS file secret-store keyring entry")
    }
    #[cfg(not(target_os = "macos"))]
    {
        keyring::Entry::new(FILE_STORE_KEYRING_SERVICE, user)
            .context("opening file secret-store keyring entry")
    }
}

fn load_or_init_file_key(path: &Path) -> Result<SecretBox<Vec<u8>>> {
    match fs::metadata(path) {
        Ok(meta) => {
            let mode = meta.permissions().mode() & 0o777;
            if mode != 0o600 {
                anyhow::bail!(
                    "secret-store key {} has mode 0{mode:o}; require 0600",
                    path.display()
                );
            }
            let key = fs::read(path)
                .with_context(|| format!("reading secret-store key {}", path.display()))?;
            validate_file_store_key_len(&key)?;
            Ok(SecretBox::new(Box::new(key)))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                    .with_context(|| format!("chmod 0700 {}", parent.display()))?;
            }
            let mut key = Zeroizing::new(vec![0u8; snapshot_crypto::KEY_SIZE]);
            rand::thread_rng().fill_bytes(&mut key);
            {
                let mut f = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .with_context(|| format!("creating secret-store key {}", path.display()))?;
                f.write_all(&key)
                    .with_context(|| format!("writing secret-store key {}", path.display()))?;
                f.sync_all().ok();
            }
            Ok(SecretBox::new(Box::new(key.to_vec())))
        }
        Err(e) => Err(e).with_context(|| format!("stat secret-store key {}", path.display())),
    }
}

fn validate_file_store_key_len(key: &[u8]) -> Result<()> {
    if key.len() != snapshot_crypto::KEY_SIZE {
        anyhow::bail!(
            "secret-store key must be {} bytes, got {}",
            snapshot_crypto::KEY_SIZE,
            key.len()
        );
    }
    Ok(())
}

fn encrypt_file_secret(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let ciphertext = snapshot_crypto::encrypt(plaintext, key)?;
    let mut out = Vec::with_capacity(FILE_SECRET_MAGIC.len() + ciphertext.len());
    out.extend_from_slice(FILE_SECRET_MAGIC);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_file_secret(encoded: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let ciphertext = encoded.strip_prefix(FILE_SECRET_MAGIC).ok_or_else(|| {
        anyhow::anyhow!(
            "legacy plaintext or unknown secret-store record; replace it with `mvmctl secret put`"
        )
    })?;
    snapshot_crypto::decrypt(ciphertext, key)
}

fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        anyhow::bail!("hex string has odd length: {}", hex.len());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let s = std::str::from_utf8(chunk)?;
        let byte = u8::from_str_radix(s, 16).with_context(|| format!("invalid hex byte: {s}"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// OS-native keystore backend. Each secret entry lives at
/// `(KEYRING_SERVICE, "<tenant>:<name>")`. Names are mirrored to a
/// sidecar JSON index at `<index_dir>/<tenant>.json` so [`list`]
/// returns a deterministic answer independent of backend-specific
/// enumeration behavior.
pub struct KeyringSecretStore {
    /// Where the per-tenant name-index JSON lives. v0 reuses the
    /// same `~/.mvm/secrets/` root as `FileSecretStore` — switching
    /// between backends is a configuration choice, not a layout
    /// migration.
    index_dir: PathBuf,
}

impl KeyringSecretStore {
    pub fn with_dir(index_dir: impl Into<PathBuf>) -> Self {
        Self {
            index_dir: index_dir.into(),
        }
    }

    fn entry(tenant: &str, name: &str) -> Result<keyring::Entry> {
        validate_shell_id(tenant)
            .with_context(|| format!("Invalid tenant for secret entry: {tenant:?}"))?;
        validate_shell_id(name).with_context(|| format!("Invalid secret name: {name:?}"))?;
        let user = format!("{tenant}:{name}");
        #[cfg(target_os = "macos")]
        {
            keyring::Entry::new_with_target(KEYRING_TARGET, KEYRING_SERVICE, &user)
                .with_context(|| format!("opening macOS keyring entry {KEYRING_SERVICE}:{user}"))
        }
        #[cfg(not(target_os = "macos"))]
        {
            keyring::Entry::new(KEYRING_SERVICE, &user)
                .with_context(|| format!("opening keyring entry {KEYRING_SERVICE}:{user}"))
        }
    }

    fn index_path(&self, tenant: &str) -> Result<PathBuf> {
        validate_shell_id(tenant)
            .with_context(|| format!("Invalid tenant for secret index: {tenant:?}"))?;
        Ok(self.index_dir.join(format!("{tenant}.json")))
    }

    fn load_index(&self, tenant: &str) -> Result<Vec<String>> {
        let path = self.index_path(tenant)?;
        if !path.exists() {
            return Ok(Vec::new());
        }
        let raw =
            fs::read(&path).with_context(|| format!("reading secret index {}", path.display()))?;
        serde_json::from_slice(&raw)
            .with_context(|| format!("parsing secret index {}", path.display()))
    }

    fn save_index(&self, tenant: &str, names: &[String]) -> Result<()> {
        let path = self.index_path(tenant)?;
        if let Some(parent) = path.parent()
            && !parent.exists()
        {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod 0700 {}", parent.display()))?;
        }
        let tmp = path.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(names).context("serialize index")?;
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .with_context(|| format!("creating {}", tmp.display()))?;
            f.write_all(&json)
                .with_context(|| format!("writing {}", tmp.display()))?;
            f.sync_all().ok();
        }
        fs::rename(&tmp, &path)
            .with_context(|| format!("atomic rename {} → {}", tmp.display(), path.display()))?;
        Ok(())
    }
}

impl Default for KeyringSecretStore {
    fn default() -> Self {
        let base = default_secrets_dir().unwrap_or_else(|_| PathBuf::from(".mvm").join("secrets"));
        Self::with_dir(base)
    }
}

impl SecretStore for KeyringSecretStore {
    fn put(&self, tenant: &str, name: &str, value: &SecretBox<String>) -> Result<()> {
        let entry = Self::entry(tenant, name)?;
        entry
            .set_password(value.expose_secret())
            .with_context(|| format!("writing keyring entry for {tenant}:{name}"))?;
        let stored = entry
            .get_password()
            .with_context(|| format!("verifying keyring entry for {tenant}:{name}"))?;
        if stored != value.expose_secret().as_str() {
            anyhow::bail!("keyring entry for {tenant}:{name} failed read-after-write check");
        }
        // Update the index. Read-modify-write; if the entry write
        // succeeded but this fails the secret IS stored but won't
        // show up in `ls` until the next put — operators see this
        // via the error chain and can re-run.
        let mut names = self.load_index(tenant)?;
        if !names.iter().any(|n| n == name) {
            names.push(name.to_string());
            names.sort();
            self.save_index(tenant, &names)?;
        }
        Ok(())
    }

    fn get(&self, tenant: &str, name: &str) -> Result<SecretBox<String>> {
        let entry = Self::entry(tenant, name)?;
        let value = entry
            .get_password()
            .with_context(|| format!("reading keyring entry for {tenant}:{name}"))?;
        Ok(SecretBox::new(Box::new(value)))
    }

    fn delete(&self, tenant: &str, name: &str) -> Result<()> {
        let entry = Self::entry(tenant, name)?;
        entry
            .delete_credential()
            .with_context(|| format!("deleting keyring entry for {tenant}:{name}"))?;
        let names = self.load_index(tenant)?;
        let pruned: Vec<String> = names.into_iter().filter(|n| n != name).collect();
        self.save_index(tenant, &pruned)?;
        Ok(())
    }

    fn list(&self, tenant: &str) -> Result<Vec<String>> {
        self.load_index(tenant)
    }
}

/// Auto backend that prefers the OS keyring but keeps file-backed
/// secrets visible. This avoids a split-brain operator experience
/// when the keyring reachability probe changes across invocations
/// or an older secret already exists in the file backend.
#[derive(Default)]
struct AutoSecretStore {
    keyring: KeyringSecretStore,
    file: FileSecretStore,
}

impl SecretStore for AutoSecretStore {
    fn put(&self, tenant: &str, name: &str, value: &SecretBox<String>) -> Result<()> {
        match self.keyring.put(tenant, name, value) {
            Ok(()) if self.keyring.get(tenant, name).is_ok() => Ok(()),
            Ok(()) | Err(_) => self.file.put(tenant, name, value),
        }
    }

    fn get(&self, tenant: &str, name: &str) -> Result<SecretBox<String>> {
        match self.keyring.get(tenant, name) {
            Ok(value) => Ok(value),
            Err(keyring_err) if is_missing_secret_error(&keyring_err) => {
                self.file.get(tenant, name)
            }
            Err(keyring_err) => self.file.get(tenant, name).or(Err(keyring_err)),
        }
    }

    fn delete(&self, tenant: &str, name: &str) -> Result<()> {
        let keyring_result = self.keyring.delete(tenant, name);
        let file_result = self.file.delete(tenant, name);
        match (keyring_result, file_result) {
            (Ok(()), _) | (_, Ok(())) => Ok(()),
            (Err(keyring_err), Err(file_err)) if is_missing_secret_error(&keyring_err) => {
                Err(file_err)
            }
            (Err(keyring_err), Err(_)) => Err(keyring_err),
        }
    }

    fn list(&self, tenant: &str) -> Result<Vec<String>> {
        let mut names = self.keyring.list(tenant).unwrap_or_default();
        names.extend(self.file.list(tenant).unwrap_or_default());
        names.sort();
        names.dedup();
        Ok(names)
    }
}

fn is_missing_secret_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<keyring::Error>()
            .is_some_and(|e| matches!(e, keyring::Error::NoEntry))
            || cause.to_string().contains("no secret")
    })
}

/// Env-var override for [`default_secret_store`]. Accepted values
/// (case-insensitive): `file`, `keyring`, `auto`. Anything else is
/// treated as `auto` with a `tracing::warn`. Documented in the
/// security model section of CLAUDE.md as the escape hatch for
/// hosts where the keyring backend is unreliable (CI Linux runners
/// without a Secret Service, headless servers, etc).
pub const BACKEND_ENV: &str = "MVM_SECRET_STORE_BACKEND";

/// Auto-pick the best available SecretStore for the current host,
/// honoring the [`BACKEND_ENV`] override.
///
/// Order (when env is `auto` or unset): an aggregate store that
/// prefers KeyringSecretStore but keeps FileSecretStore entries
/// visible if the OS keystore backend is reachable, else
/// FileSecretStore. Mirrors [`crate::crypto::keystore::default_provider`]
/// while avoiding backend split-brain across CLI invocations.
///
/// On a host whose keyring's `Entry::new` succeeds but `set_password`
/// later fails (Linux runner with `libsecret` headers but no
/// `secret-service` daemon), set `MVM_SECRET_STORE_BACKEND=file` to
/// pin the file backend up-front.
pub fn default_secret_store() -> Box<dyn SecretStore> {
    match std::env::var(BACKEND_ENV).ok().as_deref() {
        Some(v) if v.eq_ignore_ascii_case("file") => {
            let base =
                default_secrets_dir().unwrap_or_else(|_| PathBuf::from(".mvm").join("secrets"));
            return Box::new(FileSecretStore::with_dir(base));
        }
        Some(v) if v.eq_ignore_ascii_case("keyring") => {
            return Box::new(KeyringSecretStore::default());
        }
        Some(v) if !v.is_empty() && !v.eq_ignore_ascii_case("auto") => {
            tracing::warn!(
                value = v,
                env = BACKEND_ENV,
                "unrecognized secret-store backend; falling back to auto"
            );
        }
        _ => {}
    }
    if crate::crypto::keystore::KeyringProvider::backend_reachable() {
        return Box::new(AutoSecretStore::default());
    }
    Box::new(FileSecretStore::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_value(s: &str) -> SecretBox<String> {
        SecretBox::new(Box::new(s.to_string()))
    }

    // ──────────────────────────────────────────────────────────────
    // FileSecretStore — exercised on every host
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn file_put_get_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(tmp.path());
        store
            .put("acme", "api_token", &mk_value("supersecret-xyz"))
            .unwrap();
        let got = store.get("acme", "api_token").unwrap();
        assert_eq!(got.expose_secret(), "supersecret-xyz");
    }

    #[test]
    fn file_put_stores_ciphertext_not_plaintext() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(tmp.path());
        store
            .put("acme", "api_token", &mk_value("supersecret-xyz"))
            .unwrap();
        let path = tmp.path().join("acme").join("api_token");
        let raw = fs::read(path).unwrap();
        assert!(raw.starts_with(FILE_SECRET_MAGIC));
        assert!(
            !String::from_utf8_lossy(&raw).contains("supersecret-xyz"),
            "plaintext leaked into file-backed secret record"
        );
    }

    #[test]
    fn file_get_rejects_tampered_ciphertext() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(tmp.path());
        store.put("acme", "k", &mk_value("v")).unwrap();
        let path = tmp.path().join("acme").join("k");
        let mut raw = fs::read(&path).unwrap();
        let last = raw.last_mut().expect("encrypted record is non-empty");
        *last ^= 0xff;
        fs::write(&path, raw).unwrap();
        let err = store.get("acme", "k").unwrap_err();
        assert!(err.to_string().contains("decrypting secret"), "got: {err}");
    }

    #[test]
    fn file_get_rejects_legacy_plaintext_record() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(tmp.path());
        let dir = tmp.path().join("acme");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("k");
        fs::write(&path, b"plaintext").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let err = store.get("acme", "k").unwrap_err();
        let err = format!("{err:#}");
        assert!(
            err.contains("legacy plaintext") || err.contains("unknown secret-store record"),
            "got: {err}"
        );
    }

    #[test]
    fn file_store_key_is_created_at_0600() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(tmp.path());
        store.put("acme", "k", &mk_value("v")).unwrap();
        let mode = fs::metadata(tmp.path().join(FILE_STORE_KEY_FILENAME))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn file_store_key_with_loose_permissions_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join(FILE_STORE_KEY_FILENAME);
        fs::write(&key_path, [0u8; snapshot_crypto::KEY_SIZE]).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();
        let store = FileSecretStore::with_dir(tmp.path());
        let err = store.put("acme", "k", &mk_value("v")).unwrap_err();
        assert!(err.to_string().contains("require 0600"), "got: {err}");
    }

    #[test]
    fn file_store_key_hex_round_trips() {
        let bytes = [0x00, 0x7f, 0x80, 0xff];
        let encoded = hex_encode(&bytes);
        assert_eq!(encoded, "007f80ff");
        assert_eq!(hex_decode(&encoded).unwrap(), bytes);
    }

    #[test]
    fn file_store_keyring_user_is_scoped_to_base_path() {
        let first = keyring_user_for_base(Path::new("/tmp/mvm-a/secrets"));
        let second = keyring_user_for_base(Path::new("/tmp/mvm-b/secrets"));
        assert_ne!(first, second);
        assert!(first.starts_with(FILE_STORE_KEYRING_USER));
    }

    #[test]
    fn auto_store_reads_file_backed_secret_when_keyring_misses() {
        let tmp = tempfile::tempdir().unwrap();
        let file_dir = tmp.path().join("file");
        let store = AutoSecretStore {
            keyring: KeyringSecretStore::with_dir(tmp.path().join("index")),
            file: FileSecretStore::with_dir(&file_dir),
        };
        store.file.put("acme", "k", &mk_value("v")).unwrap();
        let got = store.get("acme", "k").unwrap();
        assert_eq!(got.expose_secret(), "v");
    }

    #[test]
    fn auto_store_lists_file_backed_secret_when_keyring_index_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let store = AutoSecretStore {
            keyring: KeyringSecretStore::with_dir(tmp.path().join("index")),
            file: FileSecretStore::with_dir(tmp.path().join("file")),
        };
        store.file.put("acme", "k", &mk_value("v")).unwrap();
        assert_eq!(store.list("acme").unwrap(), vec!["k"]);
    }

    #[test]
    fn file_put_overwrites_silently() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(tmp.path());
        store.put("acme", "k", &mk_value("v1")).unwrap();
        store.put("acme", "k", &mk_value("v2")).unwrap();
        assert_eq!(store.get("acme", "k").unwrap().expose_secret(), "v2");
    }

    #[test]
    fn file_get_returns_clear_error_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(tmp.path());
        let err = store.get("acme", "nope").unwrap_err();
        let s = err.to_string();
        assert!(
            s.contains("nope") || s.contains("acme"),
            "want context with tenant or name; got: {s}"
        );
    }

    #[test]
    fn file_get_refuses_world_readable() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(tmp.path());
        store.put("acme", "k", &mk_value("v")).unwrap();
        let path = tmp.path().join("acme").join("k");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let err = store.get("acme", "k").unwrap_err();
        assert!(err.to_string().contains("0644"), "got: {}", err);
    }

    #[test]
    fn file_delete_removes_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(tmp.path());
        store.put("acme", "k", &mk_value("v")).unwrap();
        store.delete("acme", "k").unwrap();
        assert!(store.get("acme", "k").is_err());
    }

    #[test]
    fn file_delete_errors_on_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(tmp.path());
        assert!(store.delete("acme", "missing").is_err());
    }

    #[test]
    fn file_list_returns_sorted_names() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(tmp.path());
        store.put("acme", "zeta", &mk_value("v")).unwrap();
        store.put("acme", "alpha", &mk_value("v")).unwrap();
        store.put("acme", "mike", &mk_value("v")).unwrap();
        let names = store.list("acme").unwrap();
        assert_eq!(names, vec!["alpha", "mike", "zeta"]);
    }

    #[test]
    fn file_list_returns_empty_for_unknown_tenant() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(tmp.path());
        assert!(store.list("nobody").unwrap().is_empty());
    }

    #[test]
    fn file_list_does_not_include_atomic_tmp_files() {
        // If a put crashes between create+rename, a stray .tmp may
        // be left behind. `ls` must not surface it as a real
        // secret — would confuse operators and break automation.
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(tmp.path());
        let dir = tmp.path().join("acme");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("real"), b"v").unwrap();
        fs::write(dir.join("stray.tmp"), b"v").unwrap();
        assert_eq!(store.list("acme").unwrap(), vec!["real"]);
    }

    #[test]
    fn file_rejects_unsafe_tenant_id() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(tmp.path());
        assert!(store.put("../../etc", "k", &mk_value("v")).is_err());
        assert!(store.put("acme;rm", "k", &mk_value("v")).is_err());
        assert!(store.list("../../etc").is_err());
    }

    #[test]
    fn file_rejects_unsafe_secret_name() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(tmp.path());
        // Name validation matches tenant validation —
        // shell-injection-style names must be refused.
        assert!(store.put("acme", "../../etc", &mk_value("v")).is_err());
        assert!(store.put("acme", "foo bar", &mk_value("v")).is_err());
    }

    #[test]
    fn file_put_creates_tenant_dir_at_0700() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(tmp.path());
        store.put("acme", "k", &mk_value("v")).unwrap();
        let mode = fs::metadata(tmp.path().join("acme"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn file_put_creates_secret_at_0600() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(tmp.path());
        store.put("acme", "k", &mk_value("v")).unwrap();
        let mode = fs::metadata(tmp.path().join("acme").join("k"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    // ──────────────────────────────────────────────────────────────
    // default_secret_store — backend selection
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn default_secret_store_returns_some_impl() {
        // Doesn't panic regardless of host keyring availability.
        let _store = default_secret_store();
    }

    /// End-to-end behavior of the env-var override is exercised by
    /// the integration tests in `tests/audit_emissions_live.rs` (the
    /// sandbox sets `MVM_SECRET_STORE_BACKEND=file` and asserts the
    /// `~/.mvm/audit/secrets.jsonl` shape, which only writes if the
    /// file backend actually took effect). The override threading
    /// goes through `std::env::var`, which is process-global; an
    /// in-process unit test would race with parallel tests that read
    /// `HOME` (we'd have to redirect HOME to observe a file write).
    /// Pinning happens at the CLI subprocess boundary instead.

    // ──────────────────────────────────────────────────────────────
    // KeyringSecretStore index — backend-independent tests
    //
    // Live keyring tests require a backend (D-Bus, Keychain, Cred
    // Mgr) that CI Linux runners often don't have. The substrate
    // tests here exercise the JSON index that powers `list` and
    // the validation guards on (tenant, name).
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn keyring_index_round_trips_through_save_load() {
        let tmp = tempfile::tempdir().unwrap();
        let store = KeyringSecretStore::with_dir(tmp.path());
        store
            .save_index("acme", &["b".to_string(), "a".to_string()])
            .unwrap();
        let loaded = store.load_index("acme").unwrap();
        assert_eq!(loaded, vec!["b", "a"]);
    }

    #[test]
    fn keyring_index_is_empty_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let store = KeyringSecretStore::with_dir(tmp.path());
        assert!(store.load_index("nobody").unwrap().is_empty());
    }

    #[test]
    fn keyring_entry_validates_tenant_and_name() {
        // The shape validator runs before any keyring backend call,
        // so these reject without needing a live keystore.
        assert!(KeyringSecretStore::entry("../etc", "k").is_err());
        assert!(KeyringSecretStore::entry("acme", "../etc").is_err());
        assert!(KeyringSecretStore::entry("foo bar", "k").is_err());
        assert!(KeyringSecretStore::entry("acme", "").is_err());
    }
}
