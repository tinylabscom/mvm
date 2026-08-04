//! Write-only local secret lifecycle service.
//!
//! Composes `SecretStore`, binding metadata, reference checks, and audit
//! emission behind one canonical service. The service exposes metadata
//! only — no reveal path, no serializable type carrying secret material.
//!
//! ## Write-only contract
//!
//! Values go in as [`SecretValueInput`] (redacted `Debug`, zeroize-on-drop,
//! no accessor outside this crate) and never come back out: there is no
//! method that returns, prints, serializes, or logs a stored value. Every
//! read-shaped operation ([`SecretService::list`],
//! [`SecretService::metadata`], [`SecretService::references`]) returns
//! names, auth types, destination allow-lists, reference metadata, and
//! timestamps only. Guests receive opaque placeholders; the host-side
//! egress substitution path is the only place a value is resolved.
//!
//! ## Composition
//!
//! - Values: [`mvm_core::crypto::secret_store::SecretStore`] (OS keyring
//!   preferred, encrypted file store everywhere else — the existing
//!   backend selection and migration behavior is reused verbatim).
//! - Bindings: [`mvm_hostd::keyholder::BindingStore`] — the auth-type +
//!   destination allow-list the egress proxy enforces.
//! - References: [`refs`] — per-machine sidecars naming which secrets a
//!   persistent machine uses (metadata only, never values).
//! - Audit: [`SecretAudit`] — JSONL + best-effort chain-signed entries for
//!   create, replace, bind, unbind, remove, and refusals.
//!
//! ## Fail-closed posture
//!
//! [`SecretService::remove`] refuses while any existing persistent machine
//! references the secret. [`SecretService::validate_for_admission`] fails
//! closed on missing secrets, missing or malformed bindings, destinations
//! outside the binding allow-list, and cross-scope references.

pub mod audit;
pub mod input;
pub mod refs;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use mvm_core::crypto::secret_store::{self, SecretStore};
use mvm_hostd::keyholder::{BindingStore, FileBindingStore};
use mvm_protocol::ir::host_matches;
use serde::Serialize;

pub use audit::SecretAudit;
pub use input::SecretValueInput;
pub use mvm_hostd::keyholder::SecretBindingMeta;
pub use mvm_protocol::ir::{AuthType, Sigv4Params};
pub use refs::{MachineSecretRef, MachineSecretRefSet};

/// Typed refusals and failures for secret lifecycle operations. Never
/// carries secret material — every variant names scopes, names, hosts,
/// and machines only.
#[derive(Debug, thiserror::Error)]
pub enum SecretServiceError {
    #[error("secret '{name}' does not exist in scope '{tenant}'")]
    MissingSecret { tenant: String, name: String },
    #[error(
        "secret '{name}' in scope '{tenant}' has no egress binding; \
         bind it to a destination and auth type first"
    )]
    MissingBinding { tenant: String, name: String },
    #[error("invalid binding for secret '{name}' in scope '{tenant}': {reason}")]
    InvalidBinding {
        tenant: String,
        name: String,
        reason: String,
    },
    #[error(
        "destination '{destination}' is not in the allow-list bound to \
         secret '{name}' in scope '{tenant}'"
    )]
    UnauthorizedDestination {
        tenant: String,
        name: String,
        destination: String,
    },
    #[error(
        "machine scope '{machine_tenant}' cannot reference secret '{name}' \
         in scope '{secret_tenant}' (cross-scope references are refused)"
    )]
    CrossScope {
        machine_tenant: String,
        secret_tenant: String,
        name: String,
    },
    #[error(
        "refusing to remove secret '{name}' in scope '{tenant}': still \
         referenced by persistent machine(s) {machines:?}; remove or update \
         those machines first"
    )]
    ReferencedByMachines {
        tenant: String,
        name: String,
        machines: Vec<String>,
    },
    #[error(transparent)]
    Storage(#[from] anyhow::Error),
}

/// Whether a [`SecretService::put`] created a new secret or replaced an
/// existing value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    Created,
    Replaced,
}

/// Non-secret description of one stored secret: name, scope, egress binding
/// (auth type + destination allow-list + SigV4 scope), and the persistent
/// machines that reference it. Serializable for UI consumption because it is
/// structurally incapable of carrying a value.
// allow(secret-debug): metadata only — name, scope, binding policy, and
// referencing machine names. The value lives in `SecretStore` and no field
// here can hold it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecretMetadata {
    pub tenant: String,
    pub name: String,
    /// Egress binding, when one is recorded. `None` for value-only secrets.
    pub binding: Option<SecretBindingMeta>,
    /// Names of existing persistent machines referencing this secret.
    pub referenced_by: Vec<String>,
}

/// Builder for [`SecretService`]. Unset seams fall back to the production
/// defaults (default store selection, `~/.mvm/secret-bindings/`,
/// `~/.mvm/machines/`, no audit sink).
#[derive(Default)]
pub struct SecretServiceBuilder {
    store: Option<Arc<dyn SecretStore>>,
    bindings: Option<Arc<dyn BindingStore>>,
    machines_root: Option<PathBuf>,
    audit: Option<SecretAudit>,
}

impl SecretServiceBuilder {
    pub fn store(mut self, store: Arc<dyn SecretStore>) -> Self {
        self.store = Some(store);
        self
    }

    pub fn bindings(mut self, bindings: Arc<dyn BindingStore>) -> Self {
        self.bindings = Some(bindings);
        self
    }

    pub fn machines_root(mut self, root: PathBuf) -> Self {
        self.machines_root = Some(root);
        self
    }

    pub fn audit(mut self, audit: SecretAudit) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Finish the build, filling unset seams with production defaults.
    /// The default audit sink is disabled — use [`SecretService::local`]
    /// for the fully wired local service.
    pub fn build(self) -> Result<SecretService, SecretServiceError> {
        let store = match self.store {
            Some(s) => s,
            None => Arc::from(secret_store::default_secret_store()),
        };
        let bindings: Arc<dyn BindingStore> = match self.bindings {
            Some(b) => b,
            None => Arc::new(
                FileBindingStore::default_location().context("resolving binding store location")?,
            ),
        };
        let machines_root = self
            .machines_root
            .unwrap_or_else(mvm_core::config::machine_state_root);
        let audit = self.audit.unwrap_or_else(SecretAudit::disabled);
        Ok(SecretService {
            store,
            bindings,
            machines_root,
            audit,
        })
    }
}

/// The canonical local secret lifecycle service. One instance fronts value
/// storage, egress bindings, machine references, and audit for every local
/// consumer (CLI, studio, SDKs).
pub struct SecretService {
    store: Arc<dyn SecretStore>,
    bindings: Arc<dyn BindingStore>,
    machines_root: PathBuf,
    audit: SecretAudit,
}

impl SecretService {
    /// The fully wired local service: default stores (honoring `MVM_HOME`
    /// and the keyring/file selection), JSONL audit at
    /// `~/.mvm/audit/secrets.jsonl`, and a best-effort chain recorder.
    pub fn local() -> Result<Self, SecretServiceError> {
        Self::builder()
            .audit(
                SecretAudit::default_local()
                    .context("resolving secret audit sink")?
                    .with_recorder_best_effort(),
            )
            .build()
    }

    pub fn builder() -> SecretServiceBuilder {
        SecretServiceBuilder::default()
    }

    // ── Metadata reads ────────────────────────────────────────────────

    /// Non-secret metadata for every secret in `tenant`, sorted by name.
    pub fn list(&self, tenant: &str) -> Result<Vec<SecretMetadata>, SecretServiceError> {
        let result = self.store.list(tenant);
        self.audit.record("list", tenant, "*", &result)?;
        let mut names = result?;
        names.sort();
        names
            .into_iter()
            .map(|name| self.metadata_row(tenant, &name))
            .collect()
    }

    /// Non-secret metadata for one secret, or `None` when it doesn't exist.
    ///
    /// Audit fidelity: a present secret records outcome `ok`, an absent one
    /// records `miss`, and a store/row failure records `err` — so probes for
    /// absent secrets are distinguishable from hits and from storage faults.
    pub fn metadata(
        &self,
        tenant: &str,
        name: &str,
    ) -> Result<Option<SecretMetadata>, SecretServiceError> {
        let result = (|| -> Result<Option<SecretMetadata>, SecretServiceError> {
            if !self.secret_exists(tenant, name)? {
                return Ok(None);
            }
            self.metadata_row(tenant, name).map(Some)
        })();
        match &result {
            Ok(Some(_)) => self.audit.record_outcome("get", tenant, name, "ok", None)?,
            Ok(None) => self
                .audit
                .record_outcome("get", tenant, name, "miss", None)?,
            Err(e) => {
                self.audit
                    .record_outcome("get", tenant, name, "err", Some(&e.to_string()))?
            }
        }
        result
    }

    fn metadata_row(&self, tenant: &str, name: &str) -> Result<SecretMetadata, SecretServiceError> {
        let binding = self.bindings.get(tenant, name)?;
        let referenced_by = refs::machines_referencing(&self.machines_root, tenant, name)?;
        Ok(SecretMetadata {
            tenant: tenant.to_string(),
            name: name.to_string(),
            binding,
            referenced_by,
        })
    }

    // ── Value lifecycle ───────────────────────────────────────────────

    /// Create or replace the value stored at `(tenant, name)`. The input is
    /// consumed and its plaintext buffer zeroized as soon as the encrypted
    /// store write returns. Emits `secret.create` or `secret.replace`.
    pub fn put(
        &self,
        tenant: &str,
        name: &str,
        value: SecretValueInput,
    ) -> Result<PutOutcome, SecretServiceError> {
        // A store failure here must surface, not silently mislabel a replace
        // as a create; the failed attempt is still audited (labeled `create`,
        // since the prior state is unknowable when the store can't be read).
        let existed = match self.secret_exists(tenant, name) {
            Ok(existed) => existed,
            Err(e) => {
                self.audit
                    .record("create", tenant, name, &Err::<(), _>(&e))?;
                return Err(e);
            }
        };
        let action = if existed { "replace" } else { "create" };
        let result = self.store.put(tenant, name, value.storage_value());
        // Consume the input now: the plaintext is zeroized here, immediately
        // after storage, regardless of the write's outcome.
        drop(value);
        self.audit.record(action, tenant, name, &result)?;
        result?;
        Ok(if existed {
            PutOutcome::Replaced
        } else {
            PutOutcome::Created
        })
    }

    /// Remove `(tenant, name)` — value and binding. Refuses (and audits the
    /// refusal) while any existing persistent machine references the secret;
    /// there is deliberately no force path.
    pub fn remove(&self, tenant: &str, name: &str) -> Result<(), SecretServiceError> {
        let referencing = refs::machines_referencing(&self.machines_root, tenant, name)?;
        if !referencing.is_empty() {
            let err = SecretServiceError::ReferencedByMachines {
                tenant: tenant.to_string(),
                name: name.to_string(),
                machines: referencing,
            };
            self.audit
                .record("remove_refused", tenant, name, &Err::<(), _>(&err))?;
            return Err(err);
        }
        let result = self.store.delete(tenant, name);
        self.audit.record("remove", tenant, name, &result)?;
        result?;
        // Drop the binding too so a later re-create of the same name can't
        // inherit a stale allow-list. Idempotent — absent binding is fine.
        self.bindings.delete(tenant, name)?;
        Ok(())
    }

    // ── Binding lifecycle ─────────────────────────────────────────────

    /// Record the egress binding for an existing secret: how it
    /// authenticates and which destinations the substituted credential may
    /// reach. Fails closed when the secret has no stored value (a binding
    /// without a value would admit nothing and mask an operator mistake).
    pub fn bind(
        &self,
        tenant: &str,
        name: &str,
        meta: SecretBindingMeta,
    ) -> Result<(), SecretServiceError> {
        let result = (|| -> Result<(), SecretServiceError> {
            if !self.secret_exists(tenant, name)? {
                return Err(SecretServiceError::MissingSecret {
                    tenant: tenant.to_string(),
                    name: name.to_string(),
                });
            }
            validate_binding_meta(tenant, name, &meta)?;
            self.bindings.put(tenant, name, &meta)?;
            Ok(())
        })();
        self.audit.record("bind", tenant, name, &result)?;
        result
    }

    /// Remove the egress binding, keeping the value. Idempotent.
    pub fn unbind(&self, tenant: &str, name: &str) -> Result<(), SecretServiceError> {
        let result = self.bindings.delete(tenant, name);
        self.audit.record("unbind", tenant, name, &result)?;
        result?;
        Ok(())
    }

    // ── Persistent-machine references ─────────────────────────────────

    /// Names of existing persistent machines that reference `(tenant, name)`.
    pub fn references(&self, tenant: &str, name: &str) -> Result<Vec<String>, SecretServiceError> {
        Ok(refs::machines_referencing(
            &self.machines_root,
            tenant,
            name,
        )?)
    }

    /// Persist `machine`'s full secret-reference set (metadata only — the
    /// record cannot carry values). Replaces any previous record.
    pub fn record_machine_references(
        &self,
        machine: &str,
        references: &[MachineSecretRef],
    ) -> Result<(), SecretServiceError> {
        Ok(refs::record_refs(&self.machines_root, machine, references)?)
    }

    /// Drop `machine`'s secret-reference record. Idempotent.
    pub fn clear_machine_references(&self, machine: &str) -> Result<(), SecretServiceError> {
        Ok(refs::clear_refs(&self.machines_root, machine)?)
    }

    /// Fail-closed admission validation for a machine's secret references.
    ///
    /// For each reference: the machine's scope must match the secret's
    /// scope, the secret must exist, an egress binding must be recorded and
    /// well-formed, and every destination the reference names must be
    /// admitted by the binding's allow-list. The first violation is
    /// returned; a machine with any invalid reference must not boot.
    pub fn validate_for_admission(
        &self,
        machine_tenant: &str,
        references: &[MachineSecretRef],
    ) -> Result<(), SecretServiceError> {
        for r in references {
            if r.tenant != machine_tenant {
                return Err(SecretServiceError::CrossScope {
                    machine_tenant: machine_tenant.to_string(),
                    secret_tenant: r.tenant.clone(),
                    name: r.name.clone(),
                });
            }
            if !self.secret_exists(&r.tenant, &r.name)? {
                return Err(SecretServiceError::MissingSecret {
                    tenant: r.tenant.clone(),
                    name: r.name.clone(),
                });
            }
            let Some(meta) = self.bindings.get(&r.tenant, &r.name)? else {
                return Err(SecretServiceError::MissingBinding {
                    tenant: r.tenant.clone(),
                    name: r.name.clone(),
                });
            };
            validate_binding_meta(&r.tenant, &r.name, &meta)?;
            for destination in &r.destinations {
                if !meta
                    .allowed_hosts
                    .iter()
                    .any(|p| host_matches(p, destination))
                {
                    return Err(SecretServiceError::UnauthorizedDestination {
                        tenant: r.tenant.clone(),
                        name: r.name.clone(),
                        destination: destination.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    // ── Internals ─────────────────────────────────────────────────────

    /// Presence check via enumeration — never decrypts or touches a value.
    /// A store failure propagates rather than reading as "absent": treating
    /// an IO error as `false` would let `get` claim a stored secret is not
    /// set and let `put` mislabel a replace as a create.
    fn secret_exists(&self, tenant: &str, name: &str) -> Result<bool, SecretServiceError> {
        let names = self.store.list(tenant)?;
        Ok(names.iter().any(|n| n == name))
    }
}

/// Structural validation for an egress binding: at least one non-empty
/// destination, and the SigV4 scope present exactly when the auth type is
/// SigV4 (present otherwise it would be silently ignored; absent for SigV4
/// the signer could not name the credential scope).
pub fn validate_binding_meta(
    tenant: &str,
    name: &str,
    meta: &SecretBindingMeta,
) -> Result<(), SecretServiceError> {
    let invalid = |reason: &str| SecretServiceError::InvalidBinding {
        tenant: tenant.to_string(),
        name: name.to_string(),
        reason: reason.to_string(),
    };
    if meta.allowed_hosts.is_empty() {
        return Err(invalid("destination allow-list is empty"));
    }
    if meta.allowed_hosts.iter().any(|h| h.trim().is_empty()) {
        return Err(invalid("destination allow-list contains an empty host"));
    }
    match (meta.auth_type, &meta.sigv4) {
        (AuthType::Sigv4, None) => Err(invalid("sigv4 auth type requires sigv4 scope params")),
        (AuthType::Sigv4, Some(p))
            if p.access_key_id.is_empty() || p.region.is_empty() || p.service.is_empty() =>
        {
            Err(invalid("sigv4 scope params must be non-empty"))
        }
        (AuthType::Sigv4, Some(_)) => Ok(()),
        (_, Some(_)) => Err(invalid("sigv4 scope params are only valid for sigv4 auth")),
        (_, None) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::crypto::secret_store::FileSecretStore;
    use mvm_hostd::keyholder::FileBindingStore;
    use tempfile::TempDir;

    struct Fixture {
        _tmp: TempDir,
        service: SecretService,
        audit_path: PathBuf,
        bindings_dir: PathBuf,
        machines_root: PathBuf,
    }

    fn fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let store_dir = tmp.path().join("secrets");
        let bindings_dir = tmp.path().join("bindings");
        let machines_root = tmp.path().join("machines");
        let audit_path = tmp.path().join("secrets.jsonl");
        let service = SecretService::builder()
            .store(Arc::new(FileSecretStore::with_dir(&store_dir)))
            .bindings(Arc::new(FileBindingStore::with_dir(&bindings_dir)))
            .machines_root(machines_root.clone())
            .audit(SecretAudit::with_path(audit_path.clone()))
            .build()
            .unwrap();
        Fixture {
            _tmp: tmp,
            service,
            audit_path,
            bindings_dir,
            machines_root,
        }
    }

    fn audit_text(f: &Fixture) -> String {
        std::fs::read_to_string(&f.audit_path).unwrap_or_default()
    }

    fn bearer_binding(hosts: &[&str]) -> SecretBindingMeta {
        SecretBindingMeta {
            auth_type: AuthType::Bearer,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
            sigv4: None,
        }
    }

    fn machine_with_ref(f: &Fixture, machine: &str, tenant: &str, name: &str) {
        let dir = f.machines_root.join(machine);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("machine.json"), b"{}").unwrap();
        f.service
            .record_machine_references(
                machine,
                &[MachineSecretRef {
                    tenant: tenant.into(),
                    name: name.into(),
                    placeholder_var: Some("API_KEY".into()),
                    destinations: vec!["api.openai.com".into()],
                }],
            )
            .unwrap();
    }

    // ── Value lifecycle ───────────────────────────────────────────────

    #[test]
    fn put_creates_then_replaces_with_distinct_audit_actions() {
        let f = fixture();
        let first = f
            .service
            .put("local", "openai", SecretValueInput::new("sk-one".into()))
            .unwrap();
        assert_eq!(first, PutOutcome::Created);
        let second = f
            .service
            .put("local", "openai", SecretValueInput::new("sk-two".into()))
            .unwrap();
        assert_eq!(second, PutOutcome::Replaced);

        let log = audit_text(&f);
        assert!(log.contains("\"action\":\"create\""), "got: {log}");
        assert!(log.contains("\"action\":\"replace\""), "got: {log}");
        // Neither plaintext value ever reaches the audit stream.
        assert!(!log.contains("sk-one"));
        assert!(!log.contains("sk-two"));
    }

    #[test]
    fn put_with_unsafe_tenant_fails_and_audits_the_error() {
        let f = fixture();
        let err = f
            .service
            .put("../etc", "k", SecretValueInput::new("v".into()))
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Invalid tenant_id") || msg.contains("alphanumeric"),
            "got: {msg}"
        );
        let log = audit_text(&f);
        assert!(log.contains("\"outcome\":\"err\""));
        assert!(log.contains("\"tenant\":\"../etc\""));
        assert!(!log.contains("\"v\""));
    }

    #[test]
    fn remove_deletes_value_and_binding() {
        let f = fixture();
        f.service
            .put("local", "openai", SecretValueInput::new("sk".into()))
            .unwrap();
        f.service
            .bind("local", "openai", bearer_binding(&["api.openai.com"]))
            .unwrap();
        f.service.remove("local", "openai").unwrap();
        assert!(f.service.list("local").unwrap().is_empty());
        assert!(f.service.metadata("local", "openai").unwrap().is_none());
        let log = audit_text(&f);
        assert!(log.contains("\"action\":\"remove\""));
    }

    #[test]
    fn remove_missing_secret_is_an_error() {
        let f = fixture();
        assert!(f.service.remove("local", "absent").is_err());
    }

    // ── Referenced-delete refusal ─────────────────────────────────────

    #[test]
    fn remove_refused_while_a_persistent_machine_references_the_secret() {
        let f = fixture();
        f.service
            .put("local", "openai", SecretValueInput::new("sk".into()))
            .unwrap();
        machine_with_ref(&f, "web", "local", "openai");

        let err = f.service.remove("local", "openai").unwrap_err();
        match &err {
            SecretServiceError::ReferencedByMachines { machines, .. } => {
                assert_eq!(machines, &vec!["web".to_string()]);
            }
            other => panic!("expected ReferencedByMachines, got {other:?}"),
        }
        // Value survives the refusal.
        assert_eq!(f.service.list("local").unwrap().len(), 1);
        // Refusal is audited, without the value.
        let log = audit_text(&f);
        assert!(log.contains("\"action\":\"remove_refused\""), "got: {log}");
        assert!(log.contains("\"outcome\":\"err\""));
        assert!(!log.contains("\"sk\""));
    }

    #[test]
    fn remove_succeeds_after_references_are_cleared() {
        let f = fixture();
        f.service
            .put("local", "openai", SecretValueInput::new("sk".into()))
            .unwrap();
        machine_with_ref(&f, "web", "local", "openai");
        assert!(f.service.remove("local", "openai").is_err());
        f.service.clear_machine_references("web").unwrap();
        f.service.remove("local", "openai").unwrap();
    }

    // ── Binding lifecycle ─────────────────────────────────────────────

    #[test]
    fn bind_records_metadata_and_never_the_value() {
        let f = fixture();
        f.service
            .put(
                "local",
                "openai",
                SecretValueInput::new("sk-live-zzz".into()),
            )
            .unwrap();
        f.service
            .bind("local", "openai", bearer_binding(&["api.openai.com"]))
            .unwrap();

        let meta = f.service.metadata("local", "openai").unwrap().unwrap();
        let binding = meta.binding.expect("binding recorded");
        assert_eq!(binding.auth_type, AuthType::Bearer);
        assert_eq!(binding.allowed_hosts, vec!["api.openai.com"]);

        // The binding sidecar on disk carries metadata only.
        let sidecar =
            std::fs::read_to_string(f.bindings_dir.join("local").join("openai.json")).unwrap();
        assert!(
            !sidecar.contains("sk-live-zzz"),
            "binding sidecar must not contain the value: {sidecar}"
        );
        let log = audit_text(&f);
        assert!(log.contains("\"action\":\"bind\""));
        assert!(!log.contains("sk-live-zzz"));
    }

    #[test]
    fn bind_refuses_a_secret_without_a_stored_value() {
        let f = fixture();
        let err = f
            .service
            .bind("local", "ghost", bearer_binding(&["api.example.com"]))
            .unwrap_err();
        assert!(matches!(err, SecretServiceError::MissingSecret { .. }));
        // The refusal is audited.
        assert!(audit_text(&f).contains("\"action\":\"bind\""));
        assert!(audit_text(&f).contains("\"outcome\":\"err\""));
    }

    #[test]
    fn bind_refuses_empty_destination_list() {
        let f = fixture();
        f.service
            .put("local", "k", SecretValueInput::new("v".into()))
            .unwrap();
        let err = f
            .service
            .bind("local", "k", bearer_binding(&[]))
            .unwrap_err();
        assert!(matches!(err, SecretServiceError::InvalidBinding { .. }));
    }

    #[test]
    fn unbind_keeps_the_value_and_is_idempotent() {
        let f = fixture();
        f.service
            .put("local", "openai", SecretValueInput::new("sk".into()))
            .unwrap();
        f.service
            .bind("local", "openai", bearer_binding(&["api.openai.com"]))
            .unwrap();
        f.service.unbind("local", "openai").unwrap();
        let meta = f.service.metadata("local", "openai").unwrap().unwrap();
        assert!(meta.binding.is_none());
        assert_eq!(f.service.list("local").unwrap().len(), 1);
        f.service.unbind("local", "openai").unwrap(); // second: no error
        assert!(audit_text(&f).contains("\"action\":\"unbind\""));
    }

    // ── Metadata reads ────────────────────────────────────────────────

    #[test]
    fn list_returns_metadata_rows_without_values() {
        let f = fixture();
        f.service
            .put(
                "local",
                "openai",
                SecretValueInput::new("sk-live-zzz".into()),
            )
            .unwrap();
        f.service
            .bind("local", "openai", bearer_binding(&["api.openai.com"]))
            .unwrap();
        f.service
            .put("local", "plain", SecretValueInput::new("p-val".into()))
            .unwrap();

        let rows = f.service.list("local").unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "openai");
        assert!(rows[0].binding.is_some());
        assert_eq!(rows[1].name, "plain");
        assert!(rows[1].binding.is_none());

        // Serialized metadata carries no value under any field name.
        let json = serde_json::to_string(&rows).unwrap();
        assert!(!json.contains("sk-live-zzz"), "got: {json}");
        assert!(!json.contains("p-val"), "got: {json}");
        assert!(!json.contains("\"value\""), "got: {json}");
        // Debug output carries no value either.
        let debug = format!("{rows:?}");
        assert!(!debug.contains("sk-live-zzz"));
        assert!(!debug.contains("p-val"));
    }

    #[test]
    fn metadata_reports_referencing_machines() {
        let f = fixture();
        f.service
            .put("local", "openai", SecretValueInput::new("sk".into()))
            .unwrap();
        machine_with_ref(&f, "web", "local", "openai");
        let meta = f.service.metadata("local", "openai").unwrap().unwrap();
        assert_eq!(meta.referenced_by, vec!["web"]);
    }

    #[test]
    fn metadata_for_missing_secret_is_none_and_audited_as_miss() {
        let f = fixture();
        assert!(f.service.metadata("local", "absent").unwrap().is_none());
        // A probe for an absent secret is distinguishable in the audit
        // stream: outcome `miss`, not `ok`.
        let log = audit_text(&f);
        assert!(log.contains("\"action\":\"get\""), "got: {log}");
        assert!(log.contains("\"outcome\":\"miss\""), "got: {log}");
        assert!(!log.contains("\"outcome\":\"ok\""), "got: {log}");
    }

    #[test]
    fn metadata_hit_is_audited_as_ok() {
        let f = fixture();
        f.service
            .put("local", "openai", SecretValueInput::new("sk".into()))
            .unwrap();
        f.service.metadata("local", "openai").unwrap().unwrap();
        let last = audit_text(&f).lines().last().unwrap().to_string();
        assert!(last.contains("\"action\":\"get\""), "got: {last}");
        assert!(last.contains("\"outcome\":\"ok\""), "got: {last}");
    }

    // ── Store-failure propagation ─────────────────────────────────────

    /// A value store whose every operation fails, standing in for an
    /// unreachable keyring or unreadable secrets dir.
    struct FailingStore;

    impl SecretStore for FailingStore {
        fn put(
            &self,
            _tenant: &str,
            _name: &str,
            _value: &secrecy::SecretBox<String>,
        ) -> anyhow::Result<()> {
            anyhow::bail!("store offline")
        }
        fn get(&self, _tenant: &str, _name: &str) -> anyhow::Result<secrecy::SecretBox<String>> {
            anyhow::bail!("store offline")
        }
        fn delete(&self, _tenant: &str, _name: &str) -> anyhow::Result<()> {
            anyhow::bail!("store offline")
        }
        fn list(&self, _tenant: &str) -> anyhow::Result<Vec<String>> {
            anyhow::bail!("store offline")
        }
    }

    fn failing_fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let bindings_dir = tmp.path().join("bindings");
        let machines_root = tmp.path().join("machines");
        let audit_path = tmp.path().join("secrets.jsonl");
        let service = SecretService::builder()
            .store(Arc::new(FailingStore))
            .bindings(Arc::new(FileBindingStore::with_dir(&bindings_dir)))
            .machines_root(machines_root.clone())
            .audit(SecretAudit::with_path(audit_path.clone()))
            .build()
            .unwrap();
        Fixture {
            _tmp: tmp,
            service,
            audit_path,
            bindings_dir,
            machines_root,
        }
    }

    #[test]
    fn metadata_store_error_propagates_instead_of_reading_as_absent() {
        // An IO failure must not make a probe claim "not set".
        let f = failing_fixture();
        let err = f.service.metadata("local", "openai").unwrap_err();
        assert!(err.to_string().contains("store offline"), "got: {err}");
        let log = audit_text(&f);
        assert!(log.contains("\"action\":\"get\""), "got: {log}");
        assert!(log.contains("\"outcome\":\"err\""), "got: {log}");
        assert!(!log.contains("\"outcome\":\"miss\""), "got: {log}");
    }

    #[test]
    fn put_store_error_on_existence_check_propagates_and_is_audited() {
        // The prior state is unknowable when the store can't be read, so the
        // attempt fails (never a silently mislabeled create/replace) and the
        // failure lands in the audit stream.
        let f = failing_fixture();
        let err = f
            .service
            .put("local", "openai", SecretValueInput::new("sk".into()))
            .unwrap_err();
        assert!(err.to_string().contains("store offline"), "got: {err}");
        let log = audit_text(&f);
        assert!(log.contains("\"action\":\"create\""), "got: {log}");
        assert!(log.contains("\"outcome\":\"err\""), "got: {log}");
        assert!(!log.contains("\"sk\""), "no value in audit: {log}");
    }

    #[test]
    fn bind_store_error_fails_closed() {
        // A store failure during the existence check refuses the binding
        // rather than admitting or misreporting a missing secret.
        let f = failing_fixture();
        let err = f
            .service
            .bind("local", "openai", bearer_binding(&["api.openai.com"]))
            .unwrap_err();
        assert!(matches!(err, SecretServiceError::Storage(_)), "got: {err}");
        assert!(
            !f.bindings_dir.join("local").join("openai.json").exists(),
            "no binding may land when the store is unreadable"
        );
    }

    // ── Admission validation ──────────────────────────────────────────

    fn admission_ref(tenant: &str, name: &str, destinations: &[&str]) -> MachineSecretRef {
        MachineSecretRef {
            tenant: tenant.into(),
            name: name.into(),
            placeholder_var: Some("API_KEY".into()),
            destinations: destinations.iter().map(|d| d.to_string()).collect(),
        }
    }

    #[test]
    fn admission_accepts_a_valid_bound_reference() {
        let f = fixture();
        f.service
            .put("local", "openai", SecretValueInput::new("sk".into()))
            .unwrap();
        f.service
            .bind(
                "local",
                "openai",
                bearer_binding(&["api.openai.com", "*.openai.com"]),
            )
            .unwrap();
        f.service
            .validate_for_admission(
                "local",
                &[admission_ref("local", "openai", &["api.openai.com"])],
            )
            .unwrap();
        // Wildcard subdomain admitted too.
        f.service
            .validate_for_admission(
                "local",
                &[admission_ref("local", "openai", &["eu.openai.com"])],
            )
            .unwrap();
    }

    #[test]
    fn admission_fails_closed_on_missing_secret() {
        let f = fixture();
        let err = f
            .service
            .validate_for_admission("local", &[admission_ref("local", "ghost", &[])])
            .unwrap_err();
        assert!(matches!(err, SecretServiceError::MissingSecret { .. }));
    }

    #[test]
    fn admission_fails_closed_on_missing_binding() {
        let f = fixture();
        f.service
            .put("local", "openai", SecretValueInput::new("sk".into()))
            .unwrap();
        let err = f
            .service
            .validate_for_admission("local", &[admission_ref("local", "openai", &[])])
            .unwrap_err();
        assert!(matches!(err, SecretServiceError::MissingBinding { .. }));
    }

    #[test]
    fn admission_refuses_unauthorized_destination() {
        let f = fixture();
        f.service
            .put("local", "openai", SecretValueInput::new("sk".into()))
            .unwrap();
        f.service
            .bind("local", "openai", bearer_binding(&["api.openai.com"]))
            .unwrap();
        let err = f
            .service
            .validate_for_admission(
                "local",
                &[admission_ref("local", "openai", &["evil.example.com"])],
            )
            .unwrap_err();
        match &err {
            SecretServiceError::UnauthorizedDestination { destination, .. } => {
                assert_eq!(destination, "evil.example.com");
            }
            other => panic!("expected UnauthorizedDestination, got {other:?}"),
        }
    }

    #[test]
    fn admission_refuses_cross_scope_references() {
        let f = fixture();
        f.service
            .put("acme", "openai", SecretValueInput::new("sk".into()))
            .unwrap();
        f.service
            .bind("acme", "openai", bearer_binding(&["api.openai.com"]))
            .unwrap();
        let err = f
            .service
            .validate_for_admission(
                "local",
                &[admission_ref("acme", "openai", &["api.openai.com"])],
            )
            .unwrap_err();
        assert!(matches!(err, SecretServiceError::CrossScope { .. }));
    }

    // ── Binding validation ────────────────────────────────────────────

    #[test]
    fn binding_meta_requires_sigv4_scope_exactly_for_sigv4() {
        let sigv4 = Sigv4Params {
            access_key_id: "AKIA".into(),
            region: "us-east-1".into(),
            service: "s3".into(),
        };
        // SigV4 without scope → refused.
        let missing = SecretBindingMeta {
            auth_type: AuthType::Sigv4,
            allowed_hosts: vec!["s3.amazonaws.com".into()],
            sigv4: None,
        };
        assert!(validate_binding_meta("local", "aws", &missing).is_err());
        // SigV4 with scope → accepted.
        let good = SecretBindingMeta {
            auth_type: AuthType::Sigv4,
            allowed_hosts: vec!["s3.amazonaws.com".into()],
            sigv4: Some(sigv4.clone()),
        };
        validate_binding_meta("local", "aws", &good).unwrap();
        // Non-SigV4 carrying scope → refused (would be silently ignored).
        let stray = SecretBindingMeta {
            auth_type: AuthType::Bearer,
            allowed_hosts: vec!["api.example.com".into()],
            sigv4: Some(sigv4),
        };
        assert!(validate_binding_meta("local", "k", &stray).is_err());
    }

    // ── No-leak invariants across error surfaces ──────────────────────

    #[test]
    fn error_display_and_debug_never_carry_values() {
        let f = fixture();
        f.service
            .put(
                "local",
                "openai",
                SecretValueInput::new("sk-live-zzz".into()),
            )
            .unwrap();
        machine_with_ref(&f, "web", "local", "openai");
        let err = f.service.remove("local", "openai").unwrap_err();
        let display = err.to_string();
        let debug = format!("{err:?}");
        assert!(!display.contains("sk-live-zzz"), "got: {display}");
        assert!(!debug.contains("sk-live-zzz"), "got: {debug}");

        // The persisted machine sidecar never carries the value either.
        let sidecar = std::fs::read_to_string(
            f.machines_root
                .join("web")
                .join(refs::MACHINE_SECRET_REFS_FILENAME),
        )
        .unwrap();
        assert!(!sidecar.contains("sk-live-zzz"), "got: {sidecar}");
    }
}
