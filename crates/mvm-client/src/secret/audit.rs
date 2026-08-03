//! Non-sensitive audit emission for secret lifecycle operations.
//!
//! Every service operation emits one JSON line to
//! `~/.mvm/audit/secrets.jsonl` carrying
//! `(timestamp, action, tenant, name, outcome, pid, secret_visibility,
//! storage_security, error?)`. Values are never logged — the entry shape has
//! no field that could carry secret material.
//!
//! Dual-emit: when a chain [`Recorder`] is wired (via
//! [`SecretAudit::with_recorder_best_effort`]), every recorded action also
//! lands as a chain-signed `secret.<action>` entry in the unified audit
//! stream, signed by the host keypair. The JSONL stream stays authoritative
//! for operators tailing the file; the Recorder is purely additive.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::Utc;
use mvm_core::plan::TenantId;
use mvm_hostd::supervisor::{EventCategory, FileAuditSigner, Recorder};

const AUDIT_FILENAME: &str = "secrets.jsonl";
const SECRET_VISIBILITY_AUDIT_VALUE: &str = "write_only";
const STORAGE_SECURITY_AUDIT_VALUE: &str = "encrypted_at_rest";

/// Append-only audit sink for secret lifecycle actions.
///
/// Falls back to a no-op sink when no home root resolves (CI sandboxes,
/// daemons without a home dir) rather than failing the operation — secret
/// CRUD keeps working even when the audit destination is unreachable.
pub struct SecretAudit {
    path: Option<PathBuf>,
    recorder: Option<Recorder>,
}

impl SecretAudit {
    /// Resolve `~/.mvm/audit/secrets.jsonl` (honors `MVM_HOME`). No-op sink
    /// when no home root resolves.
    pub fn default_local() -> Result<Self> {
        if mvm_core::config::mvm_home_strict().is_err() {
            return Ok(Self::disabled());
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

    /// A sink that records nothing. Used when no home root resolves.
    pub fn disabled() -> Self {
        Self {
            path: None,
            recorder: None,
        }
    }

    /// Injection seam: write JSONL to an explicit path, no recorder.
    pub fn with_path(path: PathBuf) -> Self {
        Self {
            path: Some(path),
            recorder: None,
        }
    }

    /// Injection seam: explicit path plus a pre-built chain [`Recorder`].
    pub fn with_path_and_recorder(path: PathBuf, recorder: Recorder) -> Self {
        Self {
            path: Some(path),
            recorder: Some(recorder),
        }
    }

    /// Best-effort: attach a Recorder backed by the host signer's
    /// chain-signed audit stream. Failures (no home dir, host signer
    /// unavailable, loose perms) leave the recorder unset and log a
    /// `tracing::warn` — the operation continues; the extra chain-signed
    /// entry just doesn't land.
    pub fn with_recorder_best_effort(mut self) -> Self {
        match build_secret_recorder() {
            Ok(rec) => self.recorder = Some(rec),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "secret audit recorder not wired; falling back to JSONL-only audit"
                );
            }
        }
        self
    }

    /// The JSONL destination, if any. Test/diagnostic accessor.
    pub fn jsonl_path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Whether a chain recorder is attached.
    pub fn has_recorder(&self) -> bool {
        self.recorder.is_some()
    }

    /// Record one action outcome. Only the error's `Display` text is
    /// captured — never any payload — so the entry is structurally incapable
    /// of carrying secret material.
    pub fn record<T, E>(
        &self,
        action: &str,
        tenant: &str,
        name: &str,
        outcome: &std::result::Result<T, E>,
    ) -> Result<()>
    where
        E: std::fmt::Display,
    {
        match outcome {
            Ok(_) => self.record_outcome(action, tenant, name, "ok", None),
            Err(e) => self.record_outcome(action, tenant, name, "err", Some(&e.to_string())),
        }
    }

    /// Record with an explicit outcome label. The `ok`/`err` pair covers most
    /// actions; probe-shaped reads additionally use `miss` so an absent
    /// secret is distinguishable from a present one — and from a storage
    /// failure — in the audit stream.
    pub fn record_outcome(
        &self,
        action: &str,
        tenant: &str,
        name: &str,
        outcome_str: &str,
        error: Option<&str>,
    ) -> Result<()> {
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
        // Chain-recorder failures are surfaced as warnings, not propagated —
        // operator secret CRUD must not fail because the chain-signed stream
        // is unreachable.
        if let Some(ref rec) = self.recorder {
            emit_through_recorder(rec, action, tenant, name, outcome_str, error);
        }
        Ok(())
    }
}

/// Build a Recorder backed by `FileAuditSigner` rooted at the default audit
/// dir. The host signing key is loaded (or initialized) from the default
/// keys dir; the recorder's default tenant for the unbound entry's required
/// `tenant` field is `"local"` — the per-action tenant rides in the labels.
fn build_secret_recorder() -> Result<Recorder> {
    let signer = mvm_hostd::audit::host_keypair::load_or_init()
        .context("loading host signer for secret recorder")?;
    let audit_dir = mvm_hostd::audit::emitter::default_audit_dir()?;
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
    use mvm_hostd::supervisor::CapturingAuditSigner;

    fn temp_audit() -> (tempfile::TempDir, SecretAudit) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("secrets.jsonl");
        (tmp, SecretAudit::with_path(path))
    }

    fn read_audit(audit: &SecretAudit) -> String {
        let path = audit.jsonl_path().expect("audit has path");
        std::fs::read_to_string(path).unwrap_or_default()
    }

    fn temp_audit_with_recorder() -> (tempfile::TempDir, SecretAudit, Arc<CapturingAuditSigner>) {
        let tmp = tempfile::tempdir().unwrap();
        let jsonl_path = tmp.path().join("secrets.jsonl");
        let signer = Arc::new(CapturingAuditSigner::new());
        let recorder = Recorder::new(signer.clone(), TenantId("local".to_string()));
        (
            tmp,
            SecretAudit::with_path_and_recorder(jsonl_path, recorder),
            signer,
        )
    }

    #[test]
    fn records_action_with_tenant_name_and_posture_labels() {
        let (_dir, audit) = temp_audit();
        let res: Result<()> = Ok(());
        audit.record("create", "acme", "api_token", &res).unwrap();
        let log = read_audit(&audit);
        assert!(log.contains("\"action\":\"create\""), "got: {log}");
        assert!(log.contains("\"tenant\":\"acme\""));
        assert!(log.contains("\"name\":\"api_token\""));
        assert!(log.contains("\"outcome\":\"ok\""));
        assert!(log.contains("\"pid\":"));
        assert!(log.contains("\"secret_visibility\":\"write_only\""));
        assert!(log.contains("\"storage_security\":\"encrypted_at_rest\""));
    }

    #[test]
    fn entry_shape_has_no_value_field_even_on_failure() {
        let (_dir, audit) = temp_audit();
        let res: Result<()> = Err(anyhow::anyhow!("boom"));
        audit.record("create", "acme", "tok", &res).unwrap();
        let log = read_audit(&audit);
        assert!(!log.contains("\"value\""));
        assert!(!log.contains("\"plaintext\""));
        assert!(log.contains("\"outcome\":\"err\""));
        assert!(log.contains("\"error\":\"boom\""));
    }

    #[test]
    fn disabled_sink_records_nothing_and_succeeds() {
        let audit = SecretAudit::disabled();
        let res: Result<()> = Ok(());
        audit.record("create", "acme", "k", &res).unwrap();
        assert!(audit.jsonl_path().is_none());
        assert!(!audit.has_recorder());
    }

    #[test]
    fn recorder_dual_emits_chain_entry_with_labels() {
        let (_dir, audit, signer) = temp_audit_with_recorder();
        let res: Result<()> = Ok(());
        audit.record("replace", "acme", "api_token", &res).unwrap();

        // JSONL stream keeps its shape.
        let log = read_audit(&audit);
        assert!(log.contains("\"action\":\"replace\""), "got: {log}");

        // Chain entry carries the canonical event name + labels.
        let entries = signer.entries();
        assert_eq!(entries.len(), 1, "expected one Recorder entry");
        assert_eq!(entries[0].event, "secret.replace");
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
        assert_eq!(
            entries[0].labels.get("category"),
            Some(&"secret".to_string())
        );
    }

    #[test]
    fn recorder_carries_error_label_on_failure() {
        let (_dir, audit, signer) = temp_audit_with_recorder();
        let res: Result<()> = Err(anyhow::anyhow!("boom"));
        audit.record("bind", "acme", "tok", &res).unwrap();

        let entries = signer.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event, "secret.bind");
        assert_eq!(entries[0].labels.get("outcome"), Some(&"err".to_string()));
        assert_eq!(entries[0].labels.get("error"), Some(&"boom".to_string()));
    }

    #[test]
    fn recorder_emits_every_lifecycle_action() {
        let (_dir, audit, signer) = temp_audit_with_recorder();
        let ok: Result<()> = Ok(());
        for action in ["create", "replace", "bind", "unbind", "remove"] {
            audit.record(action, "acme", "k", &ok).unwrap();
        }
        let refusal: Result<()> = Err(anyhow::anyhow!("referenced"));
        audit
            .record("remove_refused", "acme", "k", &refusal)
            .unwrap();

        let events: Vec<String> = signer.entries().iter().map(|e| e.event.clone()).collect();
        assert_eq!(
            events,
            vec![
                "secret.create",
                "secret.replace",
                "secret.bind",
                "secret.unbind",
                "secret.remove",
                "secret.remove_refused",
            ]
        );
    }
}
