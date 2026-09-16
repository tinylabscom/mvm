//! Local binding metadata for a named secret.
//!
//! `mvmctl secret set --host --type` records, per (tenant, name), the
//! auth-type and the destination allow-list: the operator's local
//! definition of *where* a secret may go and *how* it is used. The value
//! itself lives in [`crate::crypto::secret_store::SecretStore`]; this
//! carries metadata only — **no secret bytes** — so `mvmctl secret ls`
//! can show name/type/hosts without a `get`, and the keyholder
//! can consult the binding it enforces against.
//!
//! It sits this low because two layers read it. The keyholder resolves a
//! credential against it on the egress path, and the launch path reads the same
//! `allowed_hosts` to name-constrain the per-VM egress CA before the guest
//! boots — and that launcher sits below the keyholder. One store, read from
//! both, so a binding cannot say one thing to the certificate and another to
//! the enforcement.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use anyhow::{Context, Result};
use mvm_contract::ir::{AuthType, Sigv4Params};
use serde::{Deserialize, Serialize};

use crate::config::mvm_home_strict;
use crate::crypto::keystore::validate_shell_id;

/// Per-(tenant, name) binding metadata. No secret bytes — safe to print.
// allow(secret-debug): metadata only — auth_type + allowed_hosts. The
// secret value lives in `SecretStore`, never here; Debug prints the
// destination policy, which `mvmctl secret ls` already shows in cleartext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretBindingMeta {
    /// How the keyholder uses the secret on egress (signer vs injector).
    pub auth_type: AuthType,
    /// Destinations the substituted credential may reach (claim 12).
    /// `*.` subdomain wildcards per [`mvm_contract::ir::host_matches`].
    pub allowed_hosts: Vec<String>,
    /// Non-secret SigV4 params (access-key id + credential scope), set only for
    /// `auth_type = Sigv4`. The secret-access-key (the signing key) stays in the
    /// value store; these are reconstructed onto the `SecretRef` at admission so
    /// the forward-path signer can name the credential scope. `None` otherwise.
    #[serde(default)]
    pub sigv4: Option<Sigv4Params>,
    /// The catalog entry this binding was authored from, when it was authored
    /// with `--provider`. Display and audit only — enforcement reads
    /// `allowed_hosts`, which was resolved once at `set` time. Recording the
    /// name rather than consulting it later is what keeps a catalog edit from
    /// silently widening a binding that already exists.
    #[serde(default)]
    pub provider: Option<String>,
}

/// Storage for [`SecretBindingMeta`], keyed by (tenant, name). Parallel
/// to the value store: the value lives in `SecretStore`, the binding here.
pub trait BindingStore: Send + Sync {
    fn put(&self, tenant: &str, name: &str, meta: &SecretBindingMeta) -> Result<()>;
    /// `Ok(None)` when no binding is recorded — a secret stored via the
    /// value-store `put` path has a value but no egress binding.
    fn get(&self, tenant: &str, name: &str) -> Result<Option<SecretBindingMeta>>;
    /// Idempotent: removing an absent binding is not an error.
    fn delete(&self, tenant: &str, name: &str) -> Result<()>;
}

/// Every destination the `Keystore`-sourced entries of `plan_secrets` admit,
/// de-duplicated, in plan order.
///
/// This is the same walk admission does to build the substitution registry, and
/// deliberately so: the per-VM egress certificate is name-constrained to exactly
/// the hosts the registry will later agree are bound, so the certificate and the
/// enforcement cannot describe different destination sets.
///
/// `External` sources are skipped — they resolve on another path and bind no
/// destination here. A `Keystore` secret with no recorded binding is an error
/// rather than an empty host list: a certificate permitting nothing, minted for
/// a workload whose endpoint would go on to refuse the same flow anyway, is a
/// failure worth naming at launch.
pub fn bound_hosts(
    plan_secrets: &[crate::plan::SecretBinding],
    tenant: &str,
    bindings: &dyn BindingStore,
) -> Result<Vec<String>> {
    let mut hosts: Vec<String> = Vec::new();
    for secret in plan_secrets {
        let crate::plan::SecretSource::Keystore { address } = &secret.source else {
            continue;
        };
        let meta = bindings.get(tenant, address)?.with_context(|| {
            format!(
                "secret `{address}` has no local binding; run \
                 `mvmctl secret set {address} --host <h> --type <t>`"
            )
        })?;
        for host in meta.allowed_hosts {
            if !hosts.contains(&host) {
                hosts.push(host);
            }
        }
    }
    Ok(hosts)
}

/// File-backed binding store. Layout: `<base>/<tenant>/<name>.json`,
/// per-file mode 0600, per-tenant dir mode 0700 — mirrors
/// [`crate::crypto::secret_store::FileSecretStore`]. Default base is
/// `~/.mvm/secret-bindings/`.
pub struct FileBindingStore {
    base: PathBuf,
}

impl FileBindingStore {
    pub fn with_dir(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    /// `~/.mvm/secret-bindings/` (honors `MVM_HOME`).
    pub fn default_location() -> Result<Self> {
        Ok(Self {
            base: mvm_home_strict()?.join("secret-bindings"),
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
            sigv4: None,
            provider: None,
        }
    }

    #[test]
    fn sigv4_binding_roundtrips_with_params() {
        let dir = tempdir().unwrap();
        let store = FileBindingStore::with_dir(dir.path());
        let m = SecretBindingMeta {
            auth_type: AuthType::Sigv4,
            allowed_hosts: vec!["s3.us-east-1.amazonaws.com".into()],
            sigv4: Some(Sigv4Params {
                access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
                region: "us-east-1".into(),
                service: "s3".into(),
            }),
            provider: None,
        };
        store.put("local", "aws", &m).unwrap();
        assert_eq!(store.get("local", "aws").unwrap(), Some(m));
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

    fn keystore_secret(name: &str, address: &str) -> crate::plan::SecretBinding {
        crate::plan::SecretBinding {
            name: name.into(),
            source: crate::plan::SecretSource::Keystore {
                address: address.into(),
            },
        }
    }

    #[test]
    fn a_plan_with_no_keystore_secrets_binds_no_destination() {
        let dir = tempdir().unwrap();
        let store = FileBindingStore::with_dir(dir.path());
        let external = crate::plan::SecretBinding {
            name: "VAULT_TOKEN".into(),
            source: crate::plan::SecretSource::External {
                provider: "vault".into(),
                path: "kv/token".into(),
            },
        };
        assert!(
            bound_hosts(&[external], "local", &store)
                .unwrap()
                .is_empty()
        );
        assert!(bound_hosts(&[], "local", &store).unwrap().is_empty());
    }

    #[test]
    fn a_plan_secret_with_no_recorded_binding_is_refused() {
        let dir = tempdir().unwrap();
        let store = FileBindingStore::with_dir(dir.path());
        let err = bound_hosts(
            &[keystore_secret("OPENAI_API_KEY", "openai")],
            "local",
            &store,
        )
        .expect_err("an unbound plan secret must not resolve to an empty host set");
        assert!(
            format!("{err}").contains("openai"),
            "the refusal must name the secret an operator has to bind: {err}"
        );
    }
}
