//! Plan 60 Phase 4 — `cmd.*` audit envelope around the CLI dispatch.
//!
//! Wraps `commands::run()`'s top-level match so every `mvmctl <verb>`
//! invocation produces two chain-signed entries:
//!
//! - `cmd.<verb>.invoked` — fired before the command runs.
//! - `cmd.<verb>.completed` / `cmd.<verb>.failed` — fired after.
//!
//! These complement (don't replace) the per-command `LocalAuditKind`
//! emissions and the plan 64 `plan.*` chain. Read-only commands
//! (`ls`, `logs`, `audit tail`) didn't previously emit anything; with
//! this wrap, every invocation has at least one audit footprint.
//!
//! ## Best-effort posture
//!
//! Recorder construction is best-effort. On any failure (`$HOME`
//! unset, host signer not initialized, loose perms on the secret
//! half), the wrap logs a `tracing::warn` and the command runs
//! without cmd-level audit. Audit emits themselves are also
//! best-effort — a chain-signer failure does NOT fail the command,
//! same posture as `mvm_cli::commands::vm::audit_chain::AuditEmitter`
//! and the secret command's plan 60 Phase 4 wiring.
//!
//! ## Why a separate module
//!
//! `commands::Commands::verb_name` lives here so the verb-name table
//! and the recorder build sit side-by-side. A future slice can add
//! per-verb labels (success exit codes, duration) without touching
//! `mod.rs`'s dispatch.

use std::sync::Arc;

use mvm_plan::TenantId;
use mvm_supervisor::{EventCategory, FileAuditSigner, Recorder};

use super::Commands;
use super::vm::audit_chain::default_audit_dir;
use super::vm::host_signer;

/// Best-effort Recorder for `cmd.*` envelopes. Returns `None` (with
/// a `tracing::warn`) when any setup step fails — the CLI runs
/// without cmd-level audit in that case.
///
/// Also used by `commands::ops::mcp::build_tool_registry` to wire
/// the same chain-signed audit stream into the host-mediated
/// `ToolRegistry`. The Recorder is category-agnostic (callers pass
/// `EventCategory::Cmd` for both `cmd.<verb>` and
/// `cmd.tool.<verb>` events) so one builder serves both consumers.
pub(crate) fn build_cmd_recorder() -> Option<Recorder> {
    let signer = match host_signer::load_or_init() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "plan 60 Phase 4 cmd recorder not wired (host signer); \
                 commands run without cmd-level audit"
            );
            return None;
        }
    };
    let audit_dir = match default_audit_dir() {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "plan 60 Phase 4 cmd recorder not wired (audit dir)");
            return None;
        }
    };
    let file_signer = match FileAuditSigner::open(signer.signing, &audit_dir) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "plan 60 Phase 4 cmd recorder not wired (FileAuditSigner)");
            return None;
        }
    };
    Some(Recorder::new(
        Arc::new(file_signer),
        TenantId("local".to_string()),
    ))
}

/// Emit `cmd.<verb>.invoked` before the dispatch arm runs. Returns
/// quietly on any error (audit is best-effort).
pub(super) fn emit_cmd_invoked(recorder: Option<&Recorder>, verb: &'static str) {
    let Some(rec) = recorder else { return };
    let event = format!("cmd.{verb}.invoked");
    let extras = vec![
        ("verb".to_string(), verb.to_string()),
        ("pid".to_string(), std::process::id().to_string()),
    ];
    emit_unbound(rec, event, extras);
}

/// Emit `cmd.<verb>.completed` or `cmd.<verb>.failed` after the
/// dispatch arm returns. The error message is captured in the
/// `error` label on failure; success carries no extras.
pub(super) fn emit_cmd_outcome<T, E>(
    recorder: Option<&Recorder>,
    verb: &'static str,
    outcome: &Result<T, E>,
) where
    E: std::fmt::Display,
{
    let Some(rec) = recorder else { return };
    let (phase, extras) = match outcome {
        Ok(_) => ("completed", vec![("verb".to_string(), verb.to_string())]),
        Err(e) => (
            "failed",
            vec![
                ("verb".to_string(), verb.to_string()),
                ("error".to_string(), e.to_string()),
            ],
        ),
    };
    let event = format!("cmd.{verb}.{phase}");
    emit_unbound(rec, event, extras);
}

fn emit_unbound(recorder: &Recorder, event: String, extras: Vec<(String, String)>) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::warn!(error = %e, "building tokio runtime for cmd audit emit");
            return;
        }
    };
    if let Err(e) = rt.block_on(recorder.record_unbound(EventCategory::Cmd, event, extras)) {
        tracing::warn!(error = %e, "Recorder emit failed for cmd event");
    }
}

impl Commands {
    /// Canonical clap-subcommand name for this variant. Used as the
    /// `<verb>` slot in `cmd.<verb>.*` audit events. The values
    /// MUST match the names emitted by `clap::Command::get_name()`
    /// (the `audit_total_coverage.rs` test pins this via the
    /// AUDIT_POSTURE table; bumping a name here without a matching
    /// table update will trip that test).
    pub(super) fn verb_name(&self) -> &'static str {
        match self {
            Commands::Bootstrap(_) => "bootstrap",
            Commands::Dev(_) => "dev",
            Commands::Cleanup(_) => "cleanup",
            Commands::Logs(_) => "logs",
            Commands::Forward(_) => "forward",
            Commands::Ls(_) => "ls",
            Commands::Update(_) => "update",
            Commands::Doctor(_) => "doctor",
            Commands::Manifest(_) => "manifest",
            Commands::Storage(_) => "storage",
            Commands::Build(_) => "build",
            Commands::Compile(_) => "compile",
            Commands::Deploy(_) => "deploy",
            Commands::Up(_) => "up",
            Commands::Down(_) => "down",
            Commands::ShellInit(_) => "shell-init",
            Commands::Metrics(_) => "metrics",
            Commands::Config(_) => "config",
            Commands::Uninstall(_) => "uninstall",
            Commands::Audit(_) => "audit",
            Commands::Validate(_) => "validate",
            Commands::Diff(_) => "diff",
            Commands::Network(_) => "network",
            Commands::Catalog(_) => "catalog",
            Commands::Console(_) => "console",
            Commands::Cache(_) => "cache",
            Commands::Init(_) => "init",
            Commands::Exec(_) => "exec",
            Commands::Invoke(_) => "invoke",
            Commands::Session(_) => "session",
            Commands::Mcp(_) => "mcp",
            Commands::SetTtl(_) => "set-ttl",
            Commands::Fs(_) => "fs",
            Commands::Proc(_) => "proc",
            Commands::Pause(_) => "pause",
            Commands::Resume(_) => "resume",
            Commands::Snapshot(_) => "snapshot",
            Commands::Volume(_) => "volume",
            Commands::Secret(_) => "secret",
            Commands::Attest(_) => "attest",
            Commands::Policy(_) => "policy",
            Commands::Bundle(_) => "bundle",
            Commands::Trust(_) => "trust",
            Commands::Tenant(_) => "tenant",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_supervisor::CapturingAuditSigner;

    fn recorder_with_capturing_signer() -> (Recorder, Arc<CapturingAuditSigner>) {
        let signer = Arc::new(CapturingAuditSigner::new());
        let rec = Recorder::new(signer.clone(), TenantId("local".to_string()));
        (rec, signer)
    }

    #[test]
    fn emit_cmd_invoked_writes_canonical_event_name() {
        let (rec, signer) = recorder_with_capturing_signer();
        emit_cmd_invoked(Some(&rec), "up");
        let entries = signer.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event, "cmd.up.invoked");
        assert_eq!(entries[0].labels.get("verb"), Some(&"up".to_string()));
        // pid label present and parses to a u32-ish.
        assert!(entries[0].labels.contains_key("pid"));
    }

    #[test]
    fn emit_cmd_outcome_completed_on_ok() {
        let (rec, signer) = recorder_with_capturing_signer();
        let r: Result<(), anyhow::Error> = Ok(());
        emit_cmd_outcome(Some(&rec), "doctor", &r);
        let entries = signer.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event, "cmd.doctor.completed");
        assert_eq!(entries[0].labels.get("verb"), Some(&"doctor".to_string()));
        // No error label on success.
        assert!(!entries[0].labels.contains_key("error"));
    }

    #[test]
    fn emit_cmd_outcome_failed_captures_error_message() {
        let (rec, signer) = recorder_with_capturing_signer();
        let r: Result<(), anyhow::Error> = Err(anyhow::anyhow!("policy refused"));
        emit_cmd_outcome(Some(&rec), "up", &r);
        let entries = signer.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event, "cmd.up.failed");
        assert_eq!(
            entries[0].labels.get("error"),
            Some(&"policy refused".to_string())
        );
    }

    #[test]
    fn emit_helpers_are_noop_when_recorder_is_none() {
        // No panic, no side effects. The contract is "best-effort"
        // — when the recorder isn't wired, the call is silent.
        emit_cmd_invoked(None, "up");
        let r: Result<(), anyhow::Error> = Ok(());
        emit_cmd_outcome(None, "up", &r);
    }

    #[test]
    fn cmd_outcome_event_uses_verb_name_with_dash_for_set_ttl() {
        // set-ttl is the only verb with a clap rename. The verb name
        // table must reflect the clap name, not the enum variant.
        // (Renaming a verb without updating this table would trip the
        // audit_total_coverage test, so this is a belt-and-suspenders
        // pin.)
        let (rec, signer) = recorder_with_capturing_signer();
        emit_cmd_invoked(Some(&rec), "set-ttl");
        assert_eq!(signer.entries()[0].event, "cmd.set-ttl.invoked");
    }
}
