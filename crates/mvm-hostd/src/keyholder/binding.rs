//! Plan 129 / ADR-067 §2 + §4 — local binding metadata for a named secret.
//!
//! `mvmctl secret set --host --type` records, per (tenant, name), the
//! auth-type and the destination allow-list: the operator's local
//! definition of *where* a secret may go and *how* it is used. The value
//! itself lives in [`mvm_core::crypto::secret_store::SecretStore`]; this
//! carries metadata only — **no secret bytes** — so `mvmctl secret ls`
//! can show name/type/hosts without a `get`, and the keyholder
//! (Phase C/D) can consult the binding it enforces against.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use anyhow::{Context, Result};
use mvm_core::config::mvm_data_dir_strict;
use mvm_core::crypto::keystore::validate_shell_id;
use mvm_sdk::ir::AuthType;
use serde::{Deserialize, Serialize};

/// Per-(tenant, name) binding metadata. No secret bytes — safe to print.
// allow(secret-debug): metadata only — auth_type + allowed_hosts. The
// secret value lives in `SecretStore`, never here; Debug prints the
// destination policy, which `mvmctl secret ls` already shows in cleartext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretBindingMeta {
    /// How the keyholder uses the secret on egress (signer vs injector).
    pub auth_type: AuthType,
    /// Destinations the substituted credential may reach (claim 12).
    /// `*.` subdomain wildcards per [`mvm_sdk::ir::host_matches`].
    pub allowed_hosts: Vec<String>,
}

/// Storage for [`SecretBindingMeta`], keyed by (tenant, name). Parallel
/// to the value store: the value lives in `SecretStore`, the binding here.
pub trait BindingStore: Send + Sync {
    fn put(&self, tenant: &str, name: &str, meta: &SecretBindingMeta) -> Result<()>;
    /// `Ok(None)` when no binding is recorded — a secret stored via the
    /// Plan 63 `put` path has a value but no egress binding.
    fn get(&self, tenant: &str, name: &str) -> Result<Option<SecretBindingMeta>>;
    /// Idempotent: removing an absent binding is not an error.
    fn delete(&self, tenant: &str, name: &str) -> Result<()>;
}

/// File-backed binding store. Layout: `<base>/<tenant>/<name>.json`,
/// per-file mode 0600, per-tenant dir mode 0700 — mirrors
/// [`mvm_core::crypto::secret_store::FileSecretStore`]. Default base is
/// `~/.mvm/secret-bindings/`.
pub struct FileBindingStore {
    base: PathBuf,
}

impl FileBindingStore {
    pub fn with_dir(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    /// `~/.mvm/secret-bindings/` (honors `MVM_DATA_DIR`).
    pub fn default_location() -> Result<Self> {
        Ok(Self {
            base: mvm_data_dir_strict()?.join("secret-bindings"),
        })
    }

    fn path(&self, tenant: &str, name: &str) -> Result<PathBuf> {
        validate_shell_id(tenant).with_context(|| format!("invalid tenant id {tenant:?}"))?;
        validate_shell_id(name).with_context(|| format!("invalid secret name {name:?}"))?;
        Ok(self.base.join(tenant).join(format!("{name}.json")))
    }
}

impl BindingStore for FileBindingStore {
    fn put(&self, tenant: &str, name: &str, meta: &SecretBindingMeta) -> Result<()> {
        let path = self.path(tenant, name)?;
        let dir = path.parent().expect("path has tenant parent");
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", dir.display()))?;
        let json = serde_json::to_vec_pretty(meta).context("serializing binding metadata")?;
        // Write 0600 then rename so a concurrent reader never sees a
        // half-written file.
        let tmp = path.with_extension("json.tmp");
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("opening {}", tmp.display()))?;
        f.write_all(&json)
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.sync_all().ok();
        fs::rename(&tmp, &path)
            .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
        Ok(())
    }

    fn get(&self, tenant: &str, name: &str) -> Result<Option<SecretBindingMeta>> {
        let path = self.path(tenant, name)?;
        match fs::read(&path) {
            Ok(bytes) => {
                let meta = serde_json::from_slice(&bytes)
                    .with_context(|| format!("parsing binding {}", path.display()))?;
                Ok(Some(meta))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow::Error::from(e).context(format!("reading {}", path.display()))),
        }
    }

    fn delete(&self, tenant: &str, name: &str) -> Result<()> {
        let path = self.path(tenant, name)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(anyhow::Error::from(e).context(format!("removing {}", path.display()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn meta() -> SecretBindingMeta {
        SecretBindingMeta {
            auth_type: AuthType::Bearer,
            allowed_hosts: vec!["api.openai.com".into()],
        }
    }

    #[test]
    fn put_get_roundtrip() {
        let dir = tempdir().unwrap();
        let store = FileBindingStore::with_dir(dir.path());
        store.put("local", "openai", &meta()).unwrap();
        assert_eq!(store.get("local", "openai").unwrap(), Some(meta()));
    }

    #[test]
    fn get_missing_is_none() {
        let dir = tempdir().unwrap();
        let store = FileBindingStore::with_dir(dir.path());
        assert_eq!(store.get("local", "absent").unwrap(), None);
    }

    #[test]
    fn delete_is_idempotent() {
        let dir = tempdir().unwrap();
        let store = FileBindingStore::with_dir(dir.path());
        store.put("local", "openai", &meta()).unwrap();
        store.delete("local", "openai").unwrap();
        assert_eq!(store.get("local", "openai").unwrap(), None);
        store.delete("local", "openai").unwrap(); // second remove: no error
    }

    #[test]
    fn binding_file_is_0600() {
        let dir = tempdir().unwrap();
        let store = FileBindingStore::with_dir(dir.path());
        store.put("local", "openai", &meta()).unwrap();
        let path = dir.path().join("local").join("openai.json");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn rejects_unsafe_name() {
        let dir = tempdir().unwrap();
        let store = FileBindingStore::with_dir(dir.path());
        assert!(store.put("local", "../escape", &meta()).is_err());
    }
}
