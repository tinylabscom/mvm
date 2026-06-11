//! `mvmctl secret put/set/get/ls/rm` CLI surface.
//!
//! Local CRUD for secret namespaces. Values never appear in
//! logs, error chains, or process listings — `put`/`set` accept the
//! value via an interactive hidden prompt, stdin, flag, or file;
//! `get` verifies that a secret exists but never prints the stored
//! value.
//!
//! `set` is `put` plus an egress binding: it
//! records, in a parallel [`mvm_hostd::keyholder::FileBindingStore`], the
//! auth-type and destination allow-list for a secret whose value the host
//! egress proxy substitutes toward bound destinations only (never the
//! guest). `ls` surfaces that binding (type + hosts) but never the value.
//!
//! ## Audit
//!
//! Every put/get/delete/list emits one JSON line to
//! `~/.mvm/audit/secrets.jsonl` carrying
//! `(timestamp, action, namespace, name, outcome, pid,
//! secret_visibility, storage_security, error?)`. Values are never
//! logged. When the chain recorder is available, the same posture
//! labels are emitted on the chain-signed `secret.*` event.
//!
//! ## Backend choice
//!
//! Goes through [`secret_store::default_secret_store`]:
//! - Auto store when the OS keystore is reachable: writes prefer
//!   `KeyringSecretStore`, while reads/lists/deletes keep
//!   file-backed secrets visible.
//! - `FileSecretStore` everywhere else (CI Linux, headless hosts).
//!
//! Tests inject `FileSecretStore::with_dir` + `FileBindingStore::with_dir`
//! via [`run_with_stores`].

use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Args as ClapArgs, Subcommand, ValueEnum};
use mvm_core::crypto::secret_store::{self, SecretStore};
use mvm_core::plan::TenantId;
use mvm_hostd::keyholder::{BindingStore, FileBindingStore, SecretBindingMeta};
use mvm_hostd::supervisor::{EventCategory, FileAuditSigner, Recorder};
use mvm_sdk::ir::AuthType;
use secrecy::SecretBox;

use mvm_core::user_config::MvmConfig;

use super::Cli;
use crate::commands::vm::audit_chain::default_audit_dir;
use crate::commands::vm::host_signer;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: SecretAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum SecretAction {
    /// Store or replace a local secret. With no value source,
    /// prompts interactively when stdin is a TTY or reads piped
    /// stdin otherwise. Explicit sources remain available:
    /// `--value <V>` (inline, shell-history risk), `--value -`
    /// (read from stdin), or `--value-file <PATH>`.
    Put {
        /// Name to store the secret under (alphanumeric + `_-`).
        name: String,
        /// Local namespace for this secret. Fleet tenant secrets are managed by mvmd.
        #[arg(long, default_value = "local")]
        tenant: String,
        /// Inline value. Pass `-` to read from stdin (preferred
        /// when scripting; avoids shell-history exposure).
        #[arg(long, conflicts_with = "value_file")]
        value: Option<String>,
        /// Read value from a file on disk.
        #[arg(long)]
        value_file: Option<PathBuf>,
    },

    /// Check whether a local secret exists. Never prints the raw
    /// secret value.
    Get {
        name: String,
        #[arg(long, default_value = "local")]
        tenant: String,
    },

    /// Define a local secret with its egress binding: store the value
    /// *and* record where the substituted credential may go and how it
    /// authenticates. The value never
    /// enters the guest — the host egress proxy substitutes it toward a
    /// bound destination only. Value source as for `put` (interactive
    /// prompt / piped stdin / `--value -` / `--value-file`); never pass
    /// the value inline in scripts (it lands in the process table).
    Set {
        /// Name to store the secret under (alphanumeric + `_-`).
        name: String,
        /// Local namespace. Fleet tenant secrets are managed by mvmd.
        #[arg(long, default_value = "local")]
        tenant: String,
        /// Destination the credential may reach (claim 12). Repeatable;
        /// at least one required. `*.` subdomain wildcards supported.
        #[arg(long = "host", required = true)]
        hosts: Vec<String>,
        /// How the credential authenticates outbound requests.
        #[arg(long = "type", value_enum)]
        auth_type: AuthTypeArg,
        /// Inline value. Pass `-` to read from stdin (preferred when
        /// scripting; avoids shell-history exposure).
        #[arg(long, conflicts_with = "value_file")]
        value: Option<String>,
        /// Read value from a file on disk.
        #[arg(long)]
        value_file: Option<PathBuf>,
    },

    /// List secret names stored for a tenant. Bound secrets (defined via
    /// `set`) also show their auth-type and destination allow-list;
    /// never the value.
    Ls {
        #[arg(long, default_value = "local")]
        tenant: String,
    },

    /// Remove a tenant secret.
    Rm {
        name: String,
        #[arg(long, default_value = "local")]
        tenant: String,
    },
}

/// Clap mirror of [`mvm_sdk::ir::AuthType`] — kept local so the CLI owns
/// the clap dependency and `mvm-sdk` (a build-time crate) does not.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::commands) enum AuthTypeArg {
    Sigv4,
    Hmac,
    Bearer,
    Basic,
}

impl From<AuthTypeArg> for AuthType {
    fn from(a: AuthTypeArg) -> Self {
        match a {
            AuthTypeArg::Sigv4 => AuthType::Sigv4,
            AuthTypeArg::Hmac => AuthType::Hmac,
            AuthTypeArg::Bearer => AuthType::Bearer,
            AuthTypeArg::Basic => AuthType::Basic,
        }
    }
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let store = secret_store::default_secret_store();
    let bindings = FileBindingStore::default_location()?;
    run_with_stores(store.as_ref(), &bindings, args)
}

/// Same dispatch as [`run`] but takes injected stores. Test seam for
/// `FileSecretStore::with_dir(<tempdir>)` + `FileBindingStore::with_dir`.
pub(in crate::commands) fn run_with_stores(
    store: &dyn SecretStore,
    bindings: &dyn BindingStore,
    args: Args,
) -> Result<()> {
    let audit = AuditLog::default()?.with_optional_recorder();
    match args.action {
        SecretAction::Put {
            name,
            tenant,
            value,
            value_file,
        } => cmd_put(store, &audit, tenant, name, value, value_file),
        SecretAction::Set {
            name,
            tenant,
            hosts,
            auth_type,
            value,
            value_file,
        } => cmd_set(
            store,
            bindings,
            &audit,
            SetArgs {
                tenant,
                name,
                hosts,
                auth_type: auth_type.into(),
                value,
                value_file,
            },
        ),
        SecretAction::Get { name, tenant } => cmd_get(store, &audit, tenant, name),
        SecretAction::Ls { tenant } => cmd_ls(store, bindings, &audit, tenant),
        SecretAction::Rm { name, tenant } => cmd_rm(store, bindings, &audit, tenant, name),
    }
}

// ============================================================================
// Subcommand handlers
// ============================================================================

fn cmd_put(
    store: &dyn SecretStore,
    audit: &AuditLog,
    tenant: String,
    name: String,
    value: Option<String>,
    value_file: Option<PathBuf>,
) -> Result<()> {
    let result = (|| {
        let raw = resolve_value(value, value_file, &name)?;
        let secret = SecretBox::new(Box::new(raw));
        store.put(&tenant, &name, &secret)
    })();
    audit.record("put", &tenant, &name, &result)?;
    result?;
    eprintln!("Stored secret '{name}' for tenant '{tenant}'.");
    Ok(())
}

/// The `secret set` inputs, bundled to keep [`cmd_set`] under the
/// argument-count lint (never suppressed — see CLAUDE.md).
struct SetArgs {
    tenant: String,
    name: String,
    hosts: Vec<String>,
    auth_type: AuthType,
    value: Option<String>,
    value_file: Option<PathBuf>,
}

fn cmd_set(
    store: &dyn SecretStore,
    bindings: &dyn BindingStore,
    audit: &AuditLog,
    set: SetArgs,
) -> Result<()> {
    let SetArgs {
        tenant,
        name,
        hosts,
        auth_type,
        value,
        value_file,
    } = set;
    let result = (|| -> Result<()> {
        let raw = resolve_value(value, value_file, &name)?;
        let secret = SecretBox::new(Box::new(raw));
        store.put(&tenant, &name, &secret)?;
        // Binding after value: if the value write fails we never record a
        // binding for a secret that isn't there.
        bindings.put(
            &tenant,
            &name,
            &SecretBindingMeta {
                auth_type,
                allowed_hosts: hosts,
                sigv4: None,
            },
        )
    })();
    audit.record("set", &tenant, &name, &result)?;
    result?;
    eprintln!("Defined secret '{name}' for tenant '{tenant}'.");
    Ok(())
}

fn cmd_get(store: &dyn SecretStore, audit: &AuditLog, tenant: String, name: String) -> Result<()> {
    let result = store.get(&tenant, &name);
    audit.record("get", &tenant, &name, &result.as_ref().map(|_| ()))?;
    result?;
    println!("Secret '{name}' is set for tenant '{tenant}'.");
    Ok(())
}

fn cmd_ls(
    store: &dyn SecretStore,
    bindings: &dyn BindingStore,
    audit: &AuditLog,
    tenant: String,
) -> Result<()> {
    let result = store.list(&tenant);
    audit.record("list", &tenant, "*", &result.as_ref().map(|_| ()))?;
    let names = result?;
    if names.is_empty() {
        eprintln!("No secrets stored for tenant '{tenant}'.");
        return Ok(());
    }
    for name in &names {
        // Name + (for bound secrets) auth-type and destination
        // allow-list. Never the value, and never anything value-derived:
        // the binding is operator-declared metadata.
        let binding = bindings.get(&tenant, name)?;
        println!("{}", ls_line(name, binding.as_ref()));
    }
    Ok(())
}

/// Render one `secret ls` row. Pure so it is unit-testable without
/// capturing stdout — and structurally incapable of leaking the value,
/// which is never an input.
fn ls_line(name: &str, binding: Option<&SecretBindingMeta>) -> String {
    match binding {
        Some(b) => format!(
            "{name}\ttype={}\thosts={}",
            auth_type_label(b.auth_type),
            b.allowed_hosts.join(",")
        ),
        None => name.to_string(),
    }
}

fn auth_type_label(t: AuthType) -> &'static str {
    match t {
        AuthType::Sigv4 => "sigv4",
        AuthType::Hmac => "hmac",
        AuthType::Bearer => "bearer",
        AuthType::Basic => "basic",
    }
}

fn cmd_rm(
    store: &dyn SecretStore,
    bindings: &dyn BindingStore,
    audit: &AuditLog,
    tenant: String,
    name: String,
) -> Result<()> {
    let result = store.delete(&tenant, &name);
    audit.record("delete", &tenant, &name, &result)?;
    result?;
    // Drop the binding too so a re-`put` of the same name can't inherit a
    // stale allow-list. Idempotent — absent binding is fine.
    bindings.delete(&tenant, &name)?;
    eprintln!("Removed secret '{name}' for tenant '{tenant}'.");
    Ok(())
}

// ============================================================================
// Value resolution — flag / stdin / file
// ============================================================================

fn resolve_value(
    value: Option<String>,
    value_file: Option<PathBuf>,
    secret_name: &str,
) -> Result<String> {
    match (value, value_file) {
        (Some(v), None) if v == "-" => read_secret_from_stdin(),
        (Some(v), None) => Ok(v),
        (None, Some(path)) => std::fs::read_to_string(&path)
            .with_context(|| format!("reading secret value from {}", path.display())),
        (None, None) => read_secret_from_prompt_or_stdin(secret_name),
        (Some(_), Some(_)) => {
            // Clap should prevent this via conflicts_with, but
            // double-check at runtime in case the API drifts.
            anyhow::bail!("--value and --value-file are mutually exclusive")
        }
    }
}

fn read_secret_from_prompt_or_stdin(secret_name: &str) -> Result<String> {
    if std::io::stdin().is_terminal() {
        inquire::Password::new(&format!("Secret value for '{secret_name}'"))
            .without_confirmation()
            .prompt()
            .context("reading secret value from interactive prompt")
    } else {
        read_secret_from_stdin()
    }
}

fn read_secret_from_stdin() -> Result<String> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("reading secret value from stdin")?;
    // Strip a single trailing newline — `echo "x" | mvmctl
    // secret put …` shouldn't include the LF in the stored value.
    if buf.ends_with('\n') {
        buf.pop();
        if buf.ends_with('\r') {
            buf.pop();
        }
    }
    Ok(buf)
}

// ============================================================================
// Audit log — minimal per-action JSONL stream
// ============================================================================

const AUDIT_FILENAME: &str = "secrets.jsonl";
const SECRET_VISIBILITY_AUDIT_VALUE: &str = "write_only";
const STORAGE_SECURITY_AUDIT_VALUE: &str = "encrypted_at_rest";

/// Resolve `~/.mvm/audit/secrets.jsonl`. Falls back to a no-op log
/// when `$HOME` is unset (CI sandboxes, daemons without a home dir)
/// rather than failing the whole command — secret CRUD should keep
/// working even when the audit destination is unreachable.
///
/// Dual-emit: when a [`Recorder`] is wired (via
/// [`AuditLog::with_optional_recorder`]), every successful action
/// also emits a chain-signed `secret.<verb>` entry through the
/// chain-signed audit stream. The original JSONL stream stays — operators
/// reading `~/.mvm/audit/secrets.jsonl` see the same shape; the Recorder
/// is purely additive.
pub(crate) struct AuditLog {
    path: Option<PathBuf>,
    recorder: Option<Recorder>,
}

impl AuditLog {
    pub(crate) fn default() -> Result<Self> {
        // No `$HOME` → no-op log (CI sandboxes, daemons without a home
        // dir). MVM_DATA_DIR is honored by mvm_audit_dir when set.
        if std::env::var_os("HOME").is_none() && std::env::var_os("MVM_DATA_DIR").is_none() {
            return Ok(Self {
                path: None,
                recorder: None,
            });
        }
        let dir = mvm_core::config::mvm_audit_dir();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating audit dir {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok();
        }
        Ok(Self {
            path: Some(dir.join(AUDIT_FILENAME)),
            recorder: None,
        })
    }

    /// Best-effort: attach a Recorder backed by the host signer's
    /// chain-signed audit stream. Failures (no `$HOME`, host signer
    /// not initialized, loose perms) leave the recorder unset and
    /// log a `tracing::warn` — secret CRUD continues to work; the
    /// extra chain-signed entry just doesn't land.
    pub(crate) fn with_optional_recorder(mut self) -> Self {
        match build_secret_recorder() {
            Ok(rec) => self.recorder = Some(rec),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "plan 60 Phase 4 secret recorder not wired; \
                     falling back to JSONL-only audit"
                );
            }
        }
        self
    }

    /// Test seam — write to an injected path.
    #[cfg(test)]
    pub(crate) fn with_path(path: PathBuf) -> Self {
        Self {
            path: Some(path),
            recorder: None,
        }
    }

    /// Test seam — inject both a path and a pre-built Recorder for
    /// dual-emit testing.
    #[cfg(test)]
    pub(crate) fn with_path_and_recorder(path: PathBuf, recorder: Recorder) -> Self {
        Self {
            path: Some(path),
            recorder: Some(recorder),
        }
    }

    pub(crate) fn record<T, E>(
        &self,
        action: &str,
        tenant: &str,
        name: &str,
        outcome: &std::result::Result<T, E>,
    ) -> Result<()>
    where
        E: std::fmt::Display,
    {
        let (outcome_str, error) = match outcome {
            Ok(_) => ("ok", None),
            Err(e) => ("err", Some(e.to_string())),
        };
        if let Some(ref path) = self.path {
            let entry = serde_json::json!({
                "timestamp": Utc::now().to_rfc3339(),
                "action": action,
                "tenant": tenant,
                "name": name,
                "outcome": outcome_str,
                "pid": std::process::id(),
                "secret_visibility": SECRET_VISIBILITY_AUDIT_VALUE,
                "storage_security": STORAGE_SECURITY_AUDIT_VALUE,
                "error": error,
            });
            let mut line = serde_json::to_vec(&entry).context("serialize audit entry")?;
            line.push(b'\n');
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)
                .with_context(|| format!("opening audit log {}", path.display()))?;
            f.write_all(&line)
                .with_context(|| format!("writing audit entry to {}", path.display()))?;
        }
        // Dual-emit through Recorder. Audit-side failures are
        // surfaced as warnings, not propagated — operator-secret CRUD
        // must not fail because the chain-signed stream is unreachable
        // (matches `audit_chain::AuditEmitter`'s posture).
        if let Some(ref rec) = self.recorder {
            emit_through_recorder(rec, action, tenant, name, outcome_str, error.as_deref());
        }
        Ok(())
    }
}

/// Build a Recorder backed by `FileAuditSigner` rooted at
/// `~/.mvm/audit/`. The host signing key is read via
/// `host_signer::load_or_init`; the default tenant the recorder uses
/// for the unbound entry's required `tenant` field is `"local"` (matches
/// the secret command's default tenant). The per-action tenant is
/// captured in the entry's labels.
fn build_secret_recorder() -> Result<Recorder> {
    let signer = host_signer::load_or_init().context("loading host signer for secret recorder")?;
    let audit_dir = default_audit_dir()?;
    let file_signer = FileAuditSigner::open(signer.signing, &audit_dir)
        .with_context(|| format!("opening FileAuditSigner at {}", audit_dir.display()))?;
    Ok(Recorder::new(
        Arc::new(file_signer),
        TenantId("local".to_string()),
    ))
}

fn emit_through_recorder(
    recorder: &Recorder,
    action: &str,
    tenant: &str,
    name: &str,
    outcome: &str,
    error: Option<&str>,
) {
    let event = format!("secret.{action}");
    let mut extras: Vec<(String, String)> = vec![
        ("tenant".to_string(), tenant.to_string()),
        ("name".to_string(), name.to_string()),
        ("outcome".to_string(), outcome.to_string()),
        ("pid".to_string(), std::process::id().to_string()),
        (
            "secret_visibility".to_string(),
            SECRET_VISIBILITY_AUDIT_VALUE.to_string(),
        ),
        (
            "storage_security".to_string(),
            STORAGE_SECURITY_AUDIT_VALUE.to_string(),
        ),
    ];
    if let Some(err) = error {
        extras.push(("error".to_string(), err.to_string()));
    }
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::warn!(error = %e, "building tokio runtime for secret audit emit");
            return;
        }
    };
    if let Err(e) = rt.block_on(recorder.record_unbound(EventCategory::Secret, event, extras)) {
        tracing::warn!(
            error = %e,
            action = action,
            "Recorder dual-emit failed for secret event"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::crypto::secret_store::FileSecretStore;

    fn temp_audit() -> (tempfile::TempDir, AuditLog) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("secrets.jsonl");
        (tmp, AuditLog::with_path(path))
    }

    fn temp_bindings() -> (tempfile::TempDir, FileBindingStore) {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileBindingStore::with_dir(tmp.path());
        (tmp, store)
    }

    fn read_audit(audit: &AuditLog) -> String {
        let path = audit.path.as_ref().expect("audit has path");
        std::fs::read_to_string(path).unwrap_or_default()
    }

    // ──────────────────────────────────────────────────────────────
    // Audit invariants
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn audit_log_records_put_action_with_tenant_and_name() {
        let (_dir, audit) = temp_audit();
        let res: Result<()> = Ok(());
        audit.record("put", "acme", "api_token", &res).unwrap();
        let log = read_audit(&audit);
        assert!(log.contains("\"action\":\"put\""), "got: {log}");
        assert!(log.contains("\"tenant\":\"acme\""));
        assert!(log.contains("\"name\":\"api_token\""));
        assert!(log.contains("\"outcome\":\"ok\""));
        assert!(log.contains("\"secret_visibility\":\"write_only\""));
        assert!(log.contains("\"storage_security\":\"encrypted_at_rest\""));
    }

    #[test]
    fn audit_log_never_carries_value_field() {
        // The audit entry shape must not include any field named
        // `value` or similar — even on failure. If a future
        // refactor accidentally adds the value to the entry, this
        // test catches it.
        let (_dir, audit) = temp_audit();
        let res: Result<()> = Err(anyhow::anyhow!("boom"));
        audit.record("put", "acme", "tok", &res).unwrap();
        let log = read_audit(&audit);
        assert!(!log.contains("\"value\""));
        assert!(!log.contains("\"plaintext\""));
        assert!(log.contains("\"outcome\":\"err\""));
        assert!(log.contains("\"error\":\"boom\""));
        assert!(log.contains("\"secret_visibility\":\"write_only\""));
        assert!(log.contains("\"storage_security\":\"encrypted_at_rest\""));
    }

    #[test]
    fn audit_log_includes_pid() {
        let (_dir, audit) = temp_audit();
        let res: Result<()> = Ok(());
        audit.record("get", "acme", "tok", &res).unwrap();
        let log = read_audit(&audit);
        // pid is process id at time of record; just assert the
        // field exists with a numeric value.
        assert!(log.contains("\"pid\":"));
    }

    // ──────────────────────────────────────────────────────────────
    // Value resolution
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn resolve_value_inline_returns_value() {
        let v = resolve_value(Some("hello".into()), None, "api_token").unwrap();
        assert_eq!(v, "hello");
    }

    #[test]
    fn resolve_value_file_reads_file_contents() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"from-file").unwrap();
        let v = resolve_value(None, Some(tmp.path().to_path_buf()), "api_token").unwrap();
        assert_eq!(v, "from-file");
    }

    #[test]
    fn resolve_value_rejects_inline_and_file_together() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let err = resolve_value(
            Some("inline".into()),
            Some(tmp.path().to_path_buf()),
            "api_token",
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("--value and --value-file are mutually exclusive"),
            "got: {err}"
        );
    }

    // ──────────────────────────────────────────────────────────────
    // Subcommand handlers — happy paths
    //
    // `cmd_get` is intentionally a presence check only: it verifies
    // the entry exists but never exposes the raw value.
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn cmd_put_then_ls_shows_name() {
        let tmp_store = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(tmp_store.path());
        let (_audit_dir, audit) = temp_audit();
        cmd_put(
            &store,
            &audit,
            "acme".into(),
            "api_token".into(),
            Some("secret-xyz".into()),
            None,
        )
        .unwrap();
        let names = store.list("acme").unwrap();
        assert_eq!(names, vec!["api_token"]);
    }

    #[test]
    fn cmd_rm_after_put_clears_name() {
        let tmp_store = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(tmp_store.path());
        let (_bind_dir, bindings) = temp_bindings();
        let (_audit_dir, audit) = temp_audit();
        cmd_put(
            &store,
            &audit,
            "acme".into(),
            "k".into(),
            Some("v".into()),
            None,
        )
        .unwrap();
        cmd_rm(&store, &bindings, &audit, "acme".into(), "k".into()).unwrap();
        assert!(store.list("acme").unwrap().is_empty());
    }

    // ──────────────────────────────────────────────────────────────
    // `secret set` (value + egress binding) and `ls`
    // ──────────────────────────────────────────────────────────────

    fn set(
        store: &dyn SecretStore,
        bindings: &dyn BindingStore,
        audit: &AuditLog,
        name: &str,
        hosts: &[&str],
        auth_type: AuthType,
        value: &str,
    ) -> Result<()> {
        cmd_set(
            store,
            bindings,
            audit,
            SetArgs {
                tenant: "local".into(),
                name: name.into(),
                hosts: hosts.iter().map(|h| h.to_string()).collect(),
                auth_type,
                value: Some(value.into()),
                value_file: None,
            },
        )
    }

    #[test]
    fn cmd_set_stores_value_and_binding_without_leaking_value() {
        let tmp_store = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(tmp_store.path());
        let (bind_dir, bindings) = temp_bindings();
        let (_audit_dir, audit) = temp_audit();

        set(
            &store,
            &bindings,
            &audit,
            "openai",
            &["api.openai.com"],
            AuthType::Bearer,
            "sk-live-zzz",
        )
        .unwrap();

        // Value landed in the value store.
        assert_eq!(store.list("local").unwrap(), vec!["openai"]);
        // Binding landed with type + hosts.
        let b = bindings.get("local", "openai").unwrap().unwrap();
        assert_eq!(b.auth_type, AuthType::Bearer);
        assert_eq!(b.allowed_hosts, vec!["api.openai.com"]);
        // The binding sidecar carries metadata only — never the value.
        let sidecar =
            std::fs::read_to_string(bind_dir.path().join("local").join("openai.json")).unwrap();
        assert!(
            !sidecar.contains("sk-live-zzz"),
            "binding sidecar must not contain the secret value: {sidecar}"
        );
    }

    #[test]
    fn ls_line_shows_type_and_hosts_for_a_bound_secret() {
        let b = SecretBindingMeta {
            auth_type: AuthType::Bearer,
            allowed_hosts: vec!["api.openai.com".into(), "*.openai.com".into()],
            sigv4: None,
        };
        let line = ls_line("openai", Some(&b));
        assert!(line.starts_with("openai"));
        assert!(line.contains("type=bearer"), "got: {line}");
        assert!(
            line.contains("hosts=api.openai.com,*.openai.com"),
            "got: {line}"
        );
    }

    #[test]
    fn ls_line_for_a_value_only_secret_is_name_only() {
        assert_eq!(ls_line("legacy", None), "legacy");
    }

    #[test]
    fn cmd_rm_removes_binding_too() {
        let tmp_store = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(tmp_store.path());
        let (_bind_dir, bindings) = temp_bindings();
        let (_audit_dir, audit) = temp_audit();
        set(
            &store,
            &bindings,
            &audit,
            "openai",
            &["api.openai.com"],
            AuthType::Bearer,
            "sk-live-zzz",
        )
        .unwrap();
        cmd_rm(&store, &bindings, &audit, "local".into(), "openai".into()).unwrap();
        assert!(bindings.get("local", "openai").unwrap().is_none());
    }

    #[test]
    fn cmd_get_checks_presence_without_returning_secret() {
        let tmp_store = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(tmp_store.path());
        let (_audit_dir, audit) = temp_audit();
        cmd_put(
            &store,
            &audit,
            "acme".into(),
            "api_token".into(),
            Some("secret-xyz".into()),
            None,
        )
        .unwrap();
        cmd_get(&store, &audit, "acme".into(), "api_token".into()).unwrap();
        let log = read_audit(&audit);
        assert!(log.contains("\"action\":\"get\""), "got: {log}");
        assert!(
            !log.contains("secret-xyz"),
            "audit log must not contain the secret value: {log}"
        );
    }

    #[test]
    fn cmd_put_with_unsafe_tenant_id_records_audit_failure() {
        // `mvmctl secret put --tenant ../etc` must be rejected by
        // validate_shell_id before the secret hits disk, AND the
        // audit log must capture the rejection.
        let tmp_store = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(tmp_store.path());
        let (_audit_dir, audit) = temp_audit();
        let err = cmd_put(
            &store,
            &audit,
            "../etc".into(),
            "k".into(),
            Some("v".into()),
            None,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("Invalid tenant_id")
                || err.to_string().contains("alphanumeric")
        );
        let log = read_audit(&audit);
        assert!(log.contains("\"outcome\":\"err\""));
        assert!(log.contains("\"tenant\":\"../etc\""));
    }

    // ──────────────────────────────────────────────────────────────
    // Recorder dual-emit
    //
    // When a Recorder is wired, AuditLog::record additionally emits
    // a chain-signed `secret.<verb>` entry through the unified
    // EventCategory::Secret stream. Existing JSONL contract is
    // unchanged.
    // ──────────────────────────────────────────────────────────────

    use mvm_hostd::supervisor::CapturingAuditSigner;

    fn temp_audit_with_recorder() -> (
        tempfile::TempDir,
        AuditLog,
        std::sync::Arc<CapturingAuditSigner>,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let jsonl_path = tmp.path().join("secrets.jsonl");
        let signer = std::sync::Arc::new(CapturingAuditSigner::new());
        let recorder = Recorder::new(signer.clone(), TenantId("local".to_string()));
        (
            tmp,
            AuditLog::with_path_and_recorder(jsonl_path, recorder),
            signer,
        )
    }

    #[test]
    fn record_with_recorder_dual_emits_to_jsonl_and_chain() {
        // Both sinks fire on a single record() call: the original
        // JSONL stream keeps its shape, and the Recorder's
        // chain-signed envelope carries the secret.<verb> event.
        let (_dir, audit, signer) = temp_audit_with_recorder();
        let res: Result<()> = Ok(());
        audit.record("put", "acme", "api_token", &res).unwrap();

        // JSONL stream — preserved verbatim.
        let log = read_audit(&audit);
        assert!(log.contains("\"action\":\"put\""), "got: {log}");
        assert!(log.contains("\"tenant\":\"acme\""));
        assert!(log.contains("\"secret_visibility\":\"write_only\""));
        assert!(log.contains("\"storage_security\":\"encrypted_at_rest\""));

        // Recorder stream — entry carries the
        // canonical `secret.put` event name and per-action tenant
        // in labels (the entry's `tenant` field is the recorder's
        // default).
        let entries = signer.entries();
        assert_eq!(entries.len(), 1, "expected one Recorder entry");
        assert_eq!(entries[0].event, "secret.put");
        assert_eq!(entries[0].labels.get("tenant"), Some(&"acme".to_string()));
        assert_eq!(
            entries[0].labels.get("name"),
            Some(&"api_token".to_string())
        );
        assert_eq!(entries[0].labels.get("outcome"), Some(&"ok".to_string()));
        assert_eq!(
            entries[0].labels.get("secret_visibility"),
            Some(&"write_only".to_string())
        );
        assert_eq!(
            entries[0].labels.get("storage_security"),
            Some(&"encrypted_at_rest".to_string())
        );
        // category label is injected by the Recorder substrate.
        assert_eq!(
            entries[0].labels.get("category"),
            Some(&"secret".to_string())
        );
        // No value leaks into the chain entry — same posture as
        // the JSONL stream.
        assert!(!entries[0].labels.values().any(|v| v.contains("plaintext")));
    }

    #[test]
    fn record_with_recorder_carries_error_label_on_failure() {
        let (_dir, audit, signer) = temp_audit_with_recorder();
        let res: Result<()> = Err(anyhow::anyhow!("boom"));
        audit.record("get", "acme", "tok", &res).unwrap();

        let entries = signer.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event, "secret.get");
        assert_eq!(entries[0].labels.get("outcome"), Some(&"err".to_string()));
        assert_eq!(entries[0].labels.get("error"), Some(&"boom".to_string()));
        assert_eq!(
            entries[0].labels.get("secret_visibility"),
            Some(&"write_only".to_string())
        );
        assert_eq!(
            entries[0].labels.get("storage_security"),
            Some(&"encrypted_at_rest".to_string())
        );
    }

    #[test]
    fn record_without_recorder_only_writes_jsonl() {
        // Default `temp_audit()` path leaves recorder=None. The
        // chain stream must NOT be touched.
        let (_dir, audit) = temp_audit();
        let res: Result<()> = Ok(());
        audit.record("put", "acme", "k", &res).unwrap();
        // Sanity: the JSONL still has the entry.
        assert!(read_audit(&audit).contains("\"action\":\"put\""));
        // No way to inspect a chain we never wired — the absence is
        // the contract. The signer field on AuditLog is None.
        assert!(audit.recorder.is_none());
    }

    #[test]
    fn record_with_recorder_emits_all_four_verbs() {
        let (_dir, audit, signer) = temp_audit_with_recorder();
        let ok: Result<()> = Ok(());
        audit.record("put", "acme", "k", &ok).unwrap();
        audit.record("get", "acme", "k", &ok).unwrap();
        audit.record("list", "acme", "*", &ok).unwrap();
        audit.record("delete", "acme", "k", &ok).unwrap();

        let events: Vec<String> = signer.entries().iter().map(|e| e.event.clone()).collect();
        assert_eq!(
            events,
            vec!["secret.put", "secret.get", "secret.list", "secret.delete"]
        );
    }
}
