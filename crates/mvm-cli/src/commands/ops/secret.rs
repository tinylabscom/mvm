//! `mvmctl secret put/set/get/ls/rm` CLI surface.
//!
//! Thin flag layer over the canonical write-only secret lifecycle service
//! ([`mvm_client::secret::SecretService`]) — the same orchestration local UI
//! surfaces consume. Values never appear in logs, error chains, or process
//! listings — `put`/`set` accept the value via an interactive hidden prompt,
//! stdin, flag, or file; `get` verifies that a secret exists but never
//! prints the stored value; the service has no reveal path at all.
//!
//! `set` is `put` plus an egress binding: it records the auth-type and
//! destination allow-list for a secret whose value the host egress proxy
//! substitutes toward bound destinations only (never the guest). `ls`
//! surfaces that binding (type + hosts) but never the value. `rm` refuses
//! while a persistent machine still references the secret.
//!
//! ## Audit
//!
//! The service emits one JSON line per action to
//! `~/.mvm/audit/secrets.jsonl` (`create`/`replace`/`bind`/`unbind`/
//! `remove`/`remove_refused`/`get`/`list`) carrying
//! `(timestamp, action, tenant, name, outcome, pid, secret_visibility,
//! storage_security, error?)`. Values are never logged. When the chain
//! recorder is available, the same posture labels ride the chain-signed
//! `secret.*` event.
//!
//! ## Backend choice
//!
//! [`SecretService::local`] goes through the default store selection:
//! - Auto store when the OS keystore is reachable: writes prefer
//!   `KeyringSecretStore`, while reads/lists/deletes keep file-backed
//!   secrets visible.
//! - `FileSecretStore` everywhere else (CI Linux, headless hosts).
//!
//! Tests inject temp-dir stores via [`SecretService::builder`] and
//! [`run_with_service`].

use std::io::{IsTerminal, Read};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand, ValueEnum};
use mvm_client::secret::{PutOutcome, SecretBindingMeta, SecretService, SecretValueInput};
use mvm_contract::ir::{AuthType, Sigv4Params};
use mvm_contract::service_catalog;

use mvm_core::user_config::MvmConfig;

use super::Cli;

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
        /// Named provider from the built-in catalog (`mvmctl secret
        /// providers`). Supplies the destination hosts and auth type, so
        /// neither is hand-typed. Mutually exclusive with `--host`/`--type`.
        #[arg(long, conflicts_with_all = ["hosts", "auth_type"])]
        provider: Option<String>,
        /// Destination the credential may reach. Repeatable; at least one
        /// required unless `--provider` supplies them. `*.` subdomain
        /// wildcards supported.
        #[arg(long = "host", required_unless_present = "provider")]
        hosts: Vec<String>,
        /// How the credential authenticates outbound requests. Required
        /// unless `--provider` supplies it.
        #[arg(long = "type", value_enum, required_unless_present = "provider")]
        auth_type: Option<AuthTypeArg>,
        /// AWS access-key id (e.g. `AKIA…`). Required with `--type sigv4`,
        /// rejected otherwise. Public (it pairs with the secret-access-key
        /// value, which is the stored secret) — not the signing key.
        #[arg(long = "aws-access-key-id")]
        aws_access_key_id: Option<String>,
        /// AWS credential-scope region (e.g. `us-east-1`). Required with
        /// `--type sigv4`, rejected otherwise.
        #[arg(long)]
        region: Option<String>,
        /// AWS credential-scope service (e.g. `s3`, `execute-api`). Required
        /// with `--type sigv4`, rejected otherwise. With `--provider` the
        /// service comes from the catalog entry, so passing it is rejected.
        #[arg(long, conflicts_with = "provider")]
        service: Option<String>,
        /// Inline value. Pass `-` to read from stdin (preferred when
        /// scripting; avoids shell-history exposure).
        #[arg(long, conflicts_with = "value_file")]
        value: Option<String>,
        /// Read value from a file on disk.
        #[arg(long)]
        value_file: Option<PathBuf>,
    },

    /// List the built-in service providers `--provider` accepts. Static
    /// data compiled into this binary — no store access, no network.
    Providers {
        /// Case-insensitive substring filter over name, description and tags.
        #[arg(long)]
        search: Option<String>,
    },

    /// List secret names stored for a tenant. Bound secrets (defined via
    /// `set`) also show their auth-type and destination allow-list;
    /// never the value.
    Ls {
        #[arg(long, default_value = "local")]
        tenant: String,
    },

    /// Remove a tenant secret. Refused while a persistent machine still
    /// references it.
    Rm {
        name: String,
        #[arg(long, default_value = "local")]
        tenant: String,
    },
}

/// Clap mirror of [`mvm_contract::ir::AuthType`] — kept local so the CLI owns
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
    let service = SecretService::local()?;
    run_with_service(&service, args)
}

/// Same dispatch as [`run`] but takes an injected service. Test seam for a
/// `SecretService` built over temp-dir stores.
pub(in crate::commands) fn run_with_service(service: &SecretService, args: Args) -> Result<()> {
    match args.action {
        SecretAction::Put {
            name,
            tenant,
            value,
            value_file,
        } => cmd_put(service, tenant, name, value, value_file),
        SecretAction::Set {
            name,
            tenant,
            provider,
            hosts,
            auth_type,
            aws_access_key_id,
            region,
            service: aws_service,
            value,
            value_file,
        } => cmd_set(
            service,
            SetArgs {
                tenant,
                name,
                provider,
                hosts,
                auth_type: auth_type.map(Into::into),
                aws_access_key_id,
                region,
                service: aws_service,
                value,
                value_file,
            },
        ),
        SecretAction::Get { name, tenant } => cmd_get(service, tenant, name),
        SecretAction::Providers { search } => cmd_providers(search.as_deref()),
        SecretAction::Ls { tenant } => cmd_ls(service, tenant),
        SecretAction::Rm { name, tenant } => cmd_rm(service, tenant, name),
    }
}

// ============================================================================
// Subcommand handlers
// ============================================================================

fn cmd_put(
    service: &SecretService,
    tenant: String,
    name: String,
    value: Option<String>,
    value_file: Option<PathBuf>,
) -> Result<()> {
    let raw = resolve_value(value, value_file, &name)?;
    let outcome = service.put(&tenant, &name, SecretValueInput::new(raw))?;
    match outcome {
        PutOutcome::Created => eprintln!("Stored secret '{name}' for tenant '{tenant}'."),
        PutOutcome::Replaced => eprintln!("Replaced secret '{name}' for tenant '{tenant}'."),
    }
    Ok(())
}

/// The `secret set` inputs, bundled to keep [`cmd_set`] under the
/// argument-count lint (never suppressed — see CLAUDE.md).
struct SetArgs {
    tenant: String,
    name: String,
    provider: Option<String>,
    hosts: Vec<String>,
    auth_type: Option<AuthType>,
    aws_access_key_id: Option<String>,
    region: Option<String>,
    service: Option<String>,
    value: Option<String>,
    value_file: Option<PathBuf>,
}

fn cmd_set(service: &SecretService, set: SetArgs) -> Result<()> {
    let SetArgs {
        tenant,
        name,
        provider,
        hosts,
        auth_type,
        aws_access_key_id,
        region,
        service: aws_service,
        value,
        value_file,
    } = set;
    // Resolve the destination + auth shape BEFORE touching the store, so a
    // rejected provider or a bad SigV4 scope leaves nothing behind.
    let resolved = resolve_binding_shape(BindingShapeInput {
        provider,
        hosts,
        auth_type,
        aws_access_key_id,
        region,
        aws_service,
    })?;
    let raw = resolve_value(value, value_file, &name)?;
    service.put(&tenant, &name, SecretValueInput::new(raw))?;
    // Binding after value: the service refuses to bind a secret with no
    // stored value, so a failed value write never leaves a dangling binding.
    service.bind(
        &tenant,
        &name,
        SecretBindingMeta {
            auth_type: resolved.auth_type,
            allowed_hosts: resolved.allowed_hosts,
            sigv4: resolved.sigv4,
            provider: resolved.provider,
        },
    )?;
    eprintln!("Defined secret '{name}' for tenant '{tenant}'.");
    Ok(())
}

/// The destination-and-auth inputs to [`resolve_binding_shape`].
struct BindingShapeInput {
    provider: Option<String>,
    hosts: Vec<String>,
    auth_type: Option<AuthType>,
    aws_access_key_id: Option<String>,
    region: Option<String>,
    aws_service: Option<String>,
}

/// What a binding will be recorded with, after a provider (if any) is expanded.
///
/// `Debug` is safe here: every field is operator-declared destination policy.
/// The secret value is resolved separately and never reaches this struct — the
/// SigV4 access-key id it can carry is public and pairs with the stored
/// secret-access-key, which stays in the value store.
#[derive(Debug)]
struct ResolvedBindingShape {
    allowed_hosts: Vec<String>,
    auth_type: AuthType,
    sigv4: Option<Sigv4Params>,
    provider: Option<String>,
}

/// Expand `--provider` into literal hosts and an auth type, or take the
/// explicit `--host`/`--type` form.
///
/// The expansion happens here, once, and the *literal* hosts are what get
/// stored: the catalog is never consulted again for this binding. That is what
/// keeps a later catalog edit from silently widening a binding that already
/// exists, and keeps the egress path free of catalog lookups. The provider name
/// travels alongside for display and audit and is not an input to any decision.
///
/// An unrecognised provider is refused. It must not fall through to the
/// explicit form or to a default: a typo'd `--provider` that quietly became
/// "no restriction" is exactly the failure this whole feature exists to remove.
fn resolve_binding_shape(input: BindingShapeInput) -> Result<ResolvedBindingShape> {
    let BindingShapeInput {
        provider,
        hosts,
        auth_type,
        aws_access_key_id,
        region,
        aws_service,
    } = input;

    let Some(provider_name) = provider else {
        // Explicit form. clap guarantees both are present without --provider,
        // but the type is still Option, so name the invariant rather than
        // unwrapping it.
        let auth_type = auth_type.context("--type is required when --provider is not given")?;
        let sigv4 = resolve_sigv4_params(auth_type, aws_access_key_id, region, aws_service)?;
        return Ok(ResolvedBindingShape {
            allowed_hosts: hosts,
            auth_type,
            sigv4,
            provider: None,
        });
    };

    let catalog = service_catalog::builtin();
    let entry = catalog.find(&provider_name).with_context(|| {
        let known = catalog
            .all()
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "unknown provider {provider_name:?}; known providers: {known}. \
             Use --host/--type for a destination the catalog does not carry."
        )
    })?;

    // The entry supplies the service; the operator still supplies the
    // account-scoped halves, which are theirs and not the provider's.
    let sigv4 = resolve_sigv4_params(
        entry.auth,
        aws_access_key_id,
        region,
        entry.sigv4_service.clone(),
    )?;

    Ok(ResolvedBindingShape {
        allowed_hosts: entry.hosts.clone(),
        auth_type: entry.auth,
        sigv4,
        provider: Some(entry.name.clone()),
    })
}

/// `mvmctl secret providers` — the catalog, with no store access.
fn cmd_providers(search: Option<&str>) -> Result<()> {
    let catalog = service_catalog::builtin();
    let rows: Vec<_> = match search {
        Some(q) => catalog.search(q),
        None => catalog.all().iter().collect(),
    };
    if rows.is_empty() {
        eprintln!("No providers match. Use --host/--type for an uncatalogued destination.");
        return Ok(());
    }
    for p in rows {
        let mut line = format!(
            "{}\ttype={}\thosts={}",
            p.name,
            auth_type_label(p.auth),
            p.hosts.join(",")
        );
        if let Some(svc) = &p.sigv4_service {
            line.push_str(&format!("\tservice={svc}"));
        }
        line.push_str(&format!("\t{}", p.description));
        println!("{line}");
    }
    Ok(())
}

/// Validate + assemble the SigV4 scope params against the auth-type. Pure so it
/// is unit-testable without a store. `Sigv4` demands all three (`access_key_id`,
/// `region`, `service`); any other auth-type rejects all three (a passed param
/// would otherwise be silently ignored, masking an operator mistake). The secret
/// value (the secret-access-key) is resolved separately and never lands here.
fn resolve_sigv4_params(
    auth_type: AuthType,
    access_key_id: Option<String>,
    region: Option<String>,
    service: Option<String>,
) -> Result<Option<Sigv4Params>> {
    match auth_type {
        AuthType::Sigv4 => {
            let access_key_id = access_key_id
                .filter(|s| !s.is_empty())
                .context("--type sigv4 requires --aws-access-key-id")?;
            let region = region
                .filter(|s| !s.is_empty())
                .context("--type sigv4 requires --region")?;
            let service = service
                .filter(|s| !s.is_empty())
                .context("--type sigv4 requires --service")?;
            Ok(Some(Sigv4Params {
                access_key_id,
                region,
                service,
            }))
        }
        AuthType::Hmac | AuthType::Bearer | AuthType::Basic => {
            if access_key_id.is_some() || region.is_some() || service.is_some() {
                anyhow::bail!(
                    "--aws-access-key-id/--region/--service are only valid with --type sigv4"
                );
            }
            Ok(None)
        }
    }
}

fn cmd_get(service: &SecretService, tenant: String, name: String) -> Result<()> {
    // Presence check only — the service has no reveal path, so the value is
    // never decrypted, let alone printed.
    match service.metadata(&tenant, &name)? {
        Some(_) => {
            println!("Secret '{name}' is set for tenant '{tenant}'.");
            Ok(())
        }
        None => anyhow::bail!("secret '{name}' is not set for tenant '{tenant}'"),
    }
}

fn cmd_ls(service: &SecretService, tenant: String) -> Result<()> {
    let rows = service.list(&tenant)?;
    if rows.is_empty() {
        eprintln!("No secrets stored for tenant '{tenant}'.");
        return Ok(());
    }
    for row in &rows {
        // Name + (for bound secrets) auth-type and destination
        // allow-list. Never the value, and never anything value-derived:
        // the binding is operator-declared metadata.
        println!("{}", ls_line(&row.name, row.binding.as_ref()));
    }
    Ok(())
}

/// Render one `secret ls` row. Pure so it is unit-testable without
/// capturing stdout — and structurally incapable of leaking the value,
/// which is never an input.
fn ls_line(name: &str, binding: Option<&SecretBindingMeta>) -> String {
    match binding {
        Some(b) => {
            let mut line = format!(
                "{name}\ttype={}\thosts={}",
                auth_type_label(b.auth_type),
                b.allowed_hosts.join(",")
            );
            // SigV4 scope is non-secret operator metadata. access_key_id is
            // identifying but public (it pairs with the secret-access-key, which
            // is never shown); region/service name the credential scope.
            if let Some(s) = &b.sigv4 {
                line.push_str(&format!(
                    "\taccess_key_id={}\tregion={}\tservice={}",
                    s.access_key_id, s.region, s.service
                ));
            }
            // Which catalog entry authored this, when one did. The hosts above
            // remain the enforced set — this names their provenance.
            if let Some(p) = &b.provider {
                line.push_str(&format!("\tprovider={p}"));
            }
            line
        }
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

fn cmd_rm(service: &SecretService, tenant: String, name: String) -> Result<()> {
    // The service refuses while a persistent machine references the secret
    // (fail closed; no force path) and drops the binding alongside the value
    // so a re-`put` of the same name can't inherit a stale allow-list.
    service.remove(&tenant, &name)?;
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
        crate::ui::prompt_secret(&format!("Secret value for '{secret_name}'"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_client::secret::{MachineSecretRef, SecretAudit};
    use mvm_core::crypto::secret_store::FileSecretStore;
    use mvm_hostd::keyholder::FileBindingStore;
    use std::sync::Arc;
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
        let bindings_dir = tmp.path().join("bindings");
        let machines_root = tmp.path().join("machines");
        let audit_path = tmp.path().join("secrets.jsonl");
        let service = SecretService::builder()
            .store(Arc::new(FileSecretStore::with_dir(
                tmp.path().join("secrets"),
            )))
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

    fn set(
        f: &Fixture,
        name: &str,
        hosts: &[&str],
        auth_type: AuthType,
        value: &str,
    ) -> Result<()> {
        cmd_set(
            &f.service,
            SetArgs {
                tenant: "local".into(),
                name: name.into(),
                provider: None,
                hosts: hosts.iter().map(|h| h.to_string()).collect(),
                auth_type: Some(auth_type),
                aws_access_key_id: None,
                region: None,
                service: None,
                value: Some(value.into()),
                value_file: None,
            },
        )
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
    // Subcommand handlers over the service
    //
    // `cmd_get` is intentionally a presence check only: it verifies
    // the entry exists but never exposes the raw value (the service
    // has no reveal path to call).
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn cmd_put_then_ls_shows_name() {
        let f = fixture();
        cmd_put(
            &f.service,
            "acme".into(),
            "api_token".into(),
            Some("secret-xyz".into()),
            None,
        )
        .unwrap();
        let rows = f.service.list("acme").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "api_token");
    }

    #[test]
    fn cmd_rm_after_put_clears_name() {
        let f = fixture();
        cmd_put(
            &f.service,
            "acme".into(),
            "k".into(),
            Some("v".into()),
            None,
        )
        .unwrap();
        cmd_rm(&f.service, "acme".into(), "k".into()).unwrap();
        assert!(f.service.list("acme").unwrap().is_empty());
    }

    #[test]
    fn cmd_set_stores_value_and_binding_without_leaking_value() {
        let f = fixture();
        set(
            &f,
            "openai",
            &["api.openai.com"],
            AuthType::Bearer,
            "sk-live-zzz",
        )
        .unwrap();

        // Value + binding both landed.
        let rows = f.service.list("local").unwrap();
        assert_eq!(rows.len(), 1);
        let binding = rows[0].binding.as_ref().expect("binding recorded");
        assert_eq!(binding.auth_type, AuthType::Bearer);
        assert_eq!(binding.allowed_hosts, vec!["api.openai.com"]);
        // The binding sidecar carries metadata only — never the value.
        let sidecar =
            std::fs::read_to_string(f.bindings_dir.join("local").join("openai.json")).unwrap();
        assert!(
            !sidecar.contains("sk-live-zzz"),
            "binding sidecar must not contain the secret value: {sidecar}"
        );
        // Neither does the audit stream.
        assert!(!audit_text(&f).contains("sk-live-zzz"));
    }

    // ── Named service bindings (--provider) ──────────────────────────

    /// A provider expands to exactly its catalog entry's hosts and auth type,
    /// so the operator never types the destination.
    #[test]
    fn provider_resolves_to_its_catalog_hosts_and_auth_type() {
        let entry = service_catalog::builtin()
            .find("openai")
            .expect("openai is a shipped provider")
            .clone();
        let r = resolve_binding_shape(BindingShapeInput {
            provider: Some("openai".into()),
            hosts: vec![],
            auth_type: None,
            aws_access_key_id: None,
            region: None,
            aws_service: None,
        })
        .unwrap();
        assert_eq!(r.allowed_hosts, entry.hosts);
        assert_eq!(r.auth_type, entry.auth);
        assert_eq!(r.provider.as_deref(), Some("openai"));
    }

    /// An unrecognised name refuses. It must not fall through to the explicit
    /// form, and must not become an empty (or permissive) host set.
    #[test]
    fn unknown_provider_refuses_rather_than_falling_through() {
        let err = resolve_binding_shape(BindingShapeInput {
            provider: Some("not-a-provider".into()),
            hosts: vec![],
            auth_type: None,
            aws_access_key_id: None,
            region: None,
            aws_service: None,
        })
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown provider"), "got: {msg}");
        // The refusal names the alternatives rather than stranding the operator.
        assert!(msg.contains("openai"), "lists known providers: {msg}");
        assert!(msg.contains("--host"), "names the escape hatch: {msg}");
    }

    /// The two authoring forms are mutually exclusive at the clap layer, so a
    /// command carrying both is rejected before any resolution runs.
    #[test]
    fn provider_and_explicit_host_are_mutually_exclusive() {
        use clap::Parser;
        #[derive(Parser)]
        struct Probe {
            #[command(subcommand)]
            action: SecretAction,
        }
        let both = Probe::try_parse_from([
            "probe",
            "set",
            "k",
            "--provider",
            "openai",
            "--host",
            "evil.example",
        ]);
        assert!(both.is_err(), "--provider with --host must be refused");

        let with_type = Probe::try_parse_from([
            "probe",
            "set",
            "k",
            "--provider",
            "openai",
            "--type",
            "bearer",
        ]);
        assert!(with_type.is_err(), "--provider with --type must be refused");

        // And neither form present is also a refusal — there is no default.
        let neither = Probe::try_parse_from(["probe", "set", "k"]);
        assert!(neither.is_err(), "one of the two forms is required");

        // Each form alone parses.
        assert!(Probe::try_parse_from(["probe", "set", "k", "--provider", "openai"]).is_ok());
        assert!(
            Probe::try_parse_from([
                "probe",
                "set",
                "k",
                "--host",
                "h.example",
                "--type",
                "bearer"
            ])
            .is_ok()
        );
    }

    /// The stored binding carries literal hosts, not the provider name. This is
    /// what makes a later catalog edit unable to widen a binding that already
    /// exists — enforcement reads `allowed_hosts`, which was fixed at set time.
    #[test]
    fn binding_records_resolved_hosts_not_the_provider_name() {
        let f = fixture();
        cmd_set(
            &f.service,
            SetArgs {
                tenant: "local".into(),
                name: "openai".into(),
                provider: Some("openai".into()),
                hosts: vec![],
                auth_type: None,
                aws_access_key_id: None,
                region: None,
                service: None,
                value: Some("sk-live-zzz".into()),
                value_file: None,
            },
        )
        .unwrap();
        let meta = f
            .service
            .metadata("local", "openai")
            .unwrap()
            .and_then(|m| m.binding)
            .expect("set records a binding");
        let entry = service_catalog::builtin().find("openai").unwrap().clone();
        assert_eq!(
            meta.allowed_hosts, entry.hosts,
            "the enforced set is literal hosts"
        );
        assert!(
            !meta.allowed_hosts.iter().any(|h| h == "openai"),
            "the provider name is not a destination"
        );
        assert_eq!(meta.provider.as_deref(), Some("openai"));
    }

    /// A SigV4 provider supplies the scope service; the account-scoped halves
    /// stay the operator's, and their absence is still refused.
    #[test]
    fn a_sigv4_provider_supplies_the_scope_service_but_not_the_account() {
        let ok = resolve_binding_shape(BindingShapeInput {
            provider: Some("aws-s3".into()),
            hosts: vec![],
            auth_type: None,
            aws_access_key_id: Some("AKIAIOSFODNN7EXAMPLE".into()),
            region: Some("us-east-1".into()),
            aws_service: None,
        })
        .unwrap();
        let sigv4 = ok.sigv4.expect("sigv4 provider yields scope params");
        assert_eq!(sigv4.service, "s3", "service comes from the catalog");
        assert_eq!(sigv4.region, "us-east-1", "region comes from the operator");

        let missing_region = resolve_binding_shape(BindingShapeInput {
            provider: Some("aws-s3".into()),
            hosts: vec![],
            auth_type: None,
            aws_access_key_id: Some("AKIAIOSFODNN7EXAMPLE".into()),
            region: None,
            aws_service: None,
        });
        assert!(missing_region.is_err(), "region is not inferable");
    }

    /// The shipped catalog must be internally consistent: a malformed entry
    /// would produce a binding nobody authored deliberately.
    #[test]
    fn catalog_entry_rejects_mismatched_auth_scope() {
        service_catalog::builtin()
            .validate()
            .expect("shipped catalog validates");
        // And the check has teeth: a sigv4 entry with no scope service fails.
        let bad = mvm_contract::service_catalog::ServiceProvider {
            name: "x".into(),
            description: "d".into(),
            hosts: vec!["h.example".into()],
            auth: AuthType::Sigv4,
            sigv4_service: None,
            tags: vec![],
        };
        assert!(bad.validate().is_err());
    }

    /// `providers` reads only compiled-in data — no store, no network.
    #[test]
    fn cmd_providers_lists_the_catalog_and_filters() {
        cmd_providers(None).unwrap();
        cmd_providers(Some("llm")).unwrap();
        cmd_providers(Some("zzz-no-match")).unwrap();
    }

    /// `ls` names the provider a binding came from, without changing what is
    /// enforced.
    #[test]
    fn ls_line_shows_the_provider_when_one_authored_the_binding() {
        let b = SecretBindingMeta {
            auth_type: AuthType::Bearer,
            allowed_hosts: vec!["api.openai.com".into()],
            sigv4: None,
            provider: Some("openai".into()),
        };
        let line = ls_line("openai", Some(&b));
        assert!(line.contains("provider=openai"), "got: {line}");
        assert!(line.contains("hosts=api.openai.com"), "got: {line}");
    }

    #[test]
    fn cmd_set_sigv4_stores_params_in_binding_not_value_in_sidecar() {
        let f = fixture();
        cmd_set(
            &f.service,
            SetArgs {
                tenant: "local".into(),
                name: "aws".into(),
                provider: None,
                hosts: vec!["s3.us-east-1.amazonaws.com".into()],
                auth_type: Some(AuthType::Sigv4),
                aws_access_key_id: Some("AKIAIOSFODNN7EXAMPLE".into()),
                region: Some("us-east-1".into()),
                service: Some("s3".into()),
                // The secret-access-key is the stored value.
                value: Some("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into()),
                value_file: None,
            },
        )
        .unwrap();

        let rows = f.service.list("local").unwrap();
        let binding = rows[0].binding.as_ref().expect("binding recorded");
        assert_eq!(binding.auth_type, AuthType::Sigv4);
        let params = binding.sigv4.as_ref().expect("sigv4 params stored");
        assert_eq!(params.access_key_id, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(params.region, "us-east-1");
        assert_eq!(params.service, "s3");
        // The secret-access-key (the signing key) never lands in the sidecar.
        let sidecar =
            std::fs::read_to_string(f.bindings_dir.join("local").join("aws.json")).unwrap();
        assert!(
            !sidecar.contains("wJalrXUtnFEMI"),
            "binding sidecar must not carry the secret-access-key: {sidecar}"
        );
    }

    #[test]
    fn resolve_sigv4_params_requires_all_three_for_sigv4() {
        // Missing any of the three is an error.
        assert!(
            resolve_sigv4_params(AuthType::Sigv4, Some("AKIA".into()), Some("r".into()), None)
                .is_err()
        );
        assert!(
            resolve_sigv4_params(AuthType::Sigv4, Some("AKIA".into()), None, Some("s".into()))
                .is_err()
        );
        assert!(
            resolve_sigv4_params(AuthType::Sigv4, None, Some("r".into()), Some("s".into()))
                .is_err()
        );
        // All three present → params.
        let p = resolve_sigv4_params(
            AuthType::Sigv4,
            Some("AKIA".into()),
            Some("us-east-1".into()),
            Some("s3".into()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(p.access_key_id, "AKIA");
        assert_eq!(p.region, "us-east-1");
        assert_eq!(p.service, "s3");
    }

    #[test]
    fn resolve_sigv4_params_rejects_params_for_non_sigv4_types() {
        // Passing a sigv4 param to a bearer secret is an operator error, not
        // a silent no-op.
        for t in [AuthType::Bearer, AuthType::Basic, AuthType::Hmac] {
            assert!(
                resolve_sigv4_params(t, Some("AKIA".into()), None, None).is_err(),
                "{t:?} must reject --aws-access-key-id"
            );
            // No params → None, fine.
            assert_eq!(resolve_sigv4_params(t, None, None, None).unwrap(), None);
        }
    }

    #[test]
    fn ls_line_shows_sigv4_scope_for_a_sigv4_secret() {
        let b = SecretBindingMeta {
            auth_type: AuthType::Sigv4,
            allowed_hosts: vec!["s3.us-east-1.amazonaws.com".into()],
            sigv4: Some(Sigv4Params {
                access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
                region: "us-east-1".into(),
                service: "s3".into(),
            }),
            provider: None,
        };
        let line = ls_line("aws", Some(&b));
        assert!(line.contains("type=sigv4"), "got: {line}");
        assert!(
            line.contains("access_key_id=AKIAIOSFODNN7EXAMPLE"),
            "got: {line}"
        );
        assert!(line.contains("region=us-east-1"), "got: {line}");
        assert!(line.contains("service=s3"), "got: {line}");
    }

    #[test]
    fn ls_line_shows_type_and_hosts_for_a_bound_secret() {
        let b = SecretBindingMeta {
            auth_type: AuthType::Bearer,
            allowed_hosts: vec!["api.openai.com".into(), "*.openai.com".into()],
            sigv4: None,
            provider: None,
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
        let f = fixture();
        set(
            &f,
            "openai",
            &["api.openai.com"],
            AuthType::Bearer,
            "sk-live-zzz",
        )
        .unwrap();
        cmd_rm(&f.service, "local".into(), "openai".into()).unwrap();
        assert!(f.service.metadata("local", "openai").unwrap().is_none());
    }

    #[test]
    fn cmd_rm_refused_while_a_machine_references_the_secret() {
        let f = fixture();
        cmd_put(
            &f.service,
            "local".into(),
            "openai".into(),
            Some("sk-live-zzz".into()),
            None,
        )
        .unwrap();
        // A persistent machine (spec on disk) declares a reference.
        let machine_dir = f.machines_root.join("web");
        std::fs::create_dir_all(&machine_dir).unwrap();
        std::fs::write(machine_dir.join("machine.json"), b"{}").unwrap();
        f.service
            .record_machine_references(
                "web",
                &[MachineSecretRef {
                    tenant: "local".into(),
                    name: "openai".into(),
                    placeholder_var: Some("OPENAI_API_KEY".into()),
                    destinations: vec!["api.openai.com".into()],
                }],
            )
            .unwrap();

        let err = cmd_rm(&f.service, "local".into(), "openai".into()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("web"), "refusal names the machine: {msg}");
        assert!(!msg.contains("sk-live-zzz"), "refusal must not leak: {msg}");
        // Value survives; refusal is audited.
        assert_eq!(f.service.list("local").unwrap().len(), 1);
        assert!(audit_text(&f).contains("\"action\":\"remove_refused\""));
    }

    #[test]
    fn cmd_get_checks_presence_without_returning_secret() {
        let f = fixture();
        cmd_put(
            &f.service,
            "acme".into(),
            "api_token".into(),
            Some("secret-xyz".into()),
            None,
        )
        .unwrap();
        cmd_get(&f.service, "acme".into(), "api_token".into()).unwrap();
        let log = audit_text(&f);
        assert!(log.contains("\"action\":\"get\""), "got: {log}");
        assert!(
            !log.contains("secret-xyz"),
            "audit log must not contain the secret value: {log}"
        );
    }

    #[test]
    fn cmd_get_missing_secret_is_an_error() {
        let f = fixture();
        let err = cmd_get(&f.service, "acme".into(), "absent".into()).unwrap_err();
        assert!(err.to_string().contains("not set"), "got: {err}");
    }

    #[test]
    fn cmd_put_with_unsafe_tenant_id_records_audit_failure() {
        // `mvmctl secret put --tenant ../etc` must be rejected by
        // validate_shell_id before the secret hits disk, AND the
        // audit log must capture the rejection.
        let f = fixture();
        let err = cmd_put(
            &f.service,
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
        let log = audit_text(&f);
        assert!(log.contains("\"outcome\":\"err\""));
        assert!(log.contains("\"tenant\":\"../etc\""));
    }
}
