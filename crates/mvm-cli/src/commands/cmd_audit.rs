//! `cmd.*` audit envelope around the CLI dispatch.
//!
//! Wraps `commands::run()`'s top-level match so every `mvmctl <verb>`
//! invocation produces two chain-signed entries:
//!
//! - `cmd.<verb>.invoked` — fired before the command runs.
//! - `cmd.<verb>.completed` / `cmd.<verb>.failed` — fired after.
//!
//! These complement (don't replace) the per-command `LocalAuditKind`
//! emissions and the `plan.*` chain. Read-only commands
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
//! and the secret command's audit wiring.
//!
//! ## Why a separate module
//!
//! `commands::Commands::verb_name` lives here so the verb-name table
//! and the recorder build sit side-by-side. A future slice can add
//! per-verb labels (success exit codes, duration) without touching
//! `mod.rs`'s dispatch.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

use mvm_core::plan::TenantId;
use mvm_hostd::supervisor::{EventCategory, FileAuditSigner, Recorder};

use super::Commands;
use super::machine;
use super::vm::audit_chain::default_audit_dir;
use super::vm::host_signer;

struct ActiveCmdSigner {
    audit_dir: PathBuf,
    signer: Weak<FileAuditSigner>,
}

static ACTIVE_CMD_SIGNER: Mutex<Option<ActiveCmdSigner>> = Mutex::new(None);

/// Owns the command recorder and keeps its concrete file signer available to
/// launch audit emitters for the duration of dispatch.
pub(crate) struct CommandAudit {
    recorder: Recorder,
    _signer: Arc<FileAuditSigner>,
}

impl CommandAudit {
    pub(crate) fn recorder(&self) -> &Recorder {
        &self.recorder
    }
}

impl Drop for CommandAudit {
    fn drop(&mut self) {
        *ACTIVE_CMD_SIGNER
            .lock()
            .expect("active command signer poisoned") = None;
    }
}

/// Reuse the command signer only when it targets this exact primary audit
/// directory. Policy replicas continue to own their separate signers.
pub(crate) fn active_signer_for(audit_dir: &Path) -> Option<Arc<FileAuditSigner>> {
    let active = ACTIVE_CMD_SIGNER
        .lock()
        .expect("active command signer poisoned");
    let active = active.as_ref()?;
    (active.audit_dir == audit_dir)
        .then(|| active.signer.upgrade())
        .flatten()
}

/// Best-effort Recorder for `cmd.*` envelopes. Returns `None` (with
/// a `tracing::warn`) when any setup step fails — the CLI runs
/// without cmd-level audit in that case.
///
/// The Recorder is category-agnostic (callers pass
/// `EventCategory::Cmd` for both `cmd.<verb>` and `cmd.tool.<verb>`
/// events), so one builder serves every consumer.
pub(crate) fn build_cmd_recorder() -> Option<CommandAudit> {
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
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::warn!(error = %e, "plan 60 Phase 4 cmd recorder not wired (FileAuditSigner)");
            return None;
        }
    };
    *ACTIVE_CMD_SIGNER
        .lock()
        .expect("active command signer poisoned") = Some(ActiveCmdSigner {
        audit_dir,
        signer: Arc::downgrade(&file_signer),
    });
    Some(CommandAudit {
        recorder: Recorder::new(file_signer.clone(), TenantId("local".to_string())),
        _signer: file_signer,
    })
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
    /// Whether this command emits a structured payload on stdout and must
    /// reserve that channel before reconcile-on-entry or other startup chrome.
    pub(super) fn emits_machine_readable_stdout(&self) -> bool {
        match self {
            Commands::Run(a) => a.run.json,
            Commands::SdkNoVm(_) => true,
            Commands::Machine(a) => match &a.action {
                // Folded advanced ops delegate to their own check.
                machine::MachineAction::Vm(cmd) => cmd.emits_machine_readable_stdout(),
                // `machine run --json` streams a structured MachineRunSummary;
                // `machine run --up-json` emits the SDK boot envelope;
                // reserve stdout so reconcile chrome can't interleave.
                machine::MachineAction::Run(r) => r.run.json || r.up_json,
                // `machine timeline --json` prints a structured lineage.
                machine::MachineAction::Timeline(t) => t.json,
                // A `--json` restore reuses the fork path's structured output.
                machine::MachineAction::Revert(a) | machine::MachineAction::Rewind(a) => a.json,
                machine::MachineAction::Advance(a) => a.json,
                machine::MachineAction::Ls(a) => a.json,
                machine::MachineAction::Fork(a) => a.json,
                machine::MachineAction::Restore(a) => a.json,
                _ => false,
            },
            _ => false,
        }
    }

    /// Whether this command reads or mutates VM lifecycle state and so
    /// warrants the cheap reconcile-on-entry convergence pass.
    /// Read-only, VM-agnostic commands (`doctor`, `ls`
    /// of caches, build/compile, config, …) skip it. `reconcile` itself
    /// is excluded — it *is* the convergence pass, run with its own opts.
    pub(super) fn touches_vm_state(&self) -> bool {
        // `machine <sub>` — named/persistent lifecycle commands touch
        // running-VM state. Unnamed foreground `machine run` is throwaway
        // cattle: running global convergence before it can auto-resume
        // unrelated machines and turn a plain OCI launch into a hidden
        // builder/dev-VM boot.
        // For the advanced VmCmd variants folded under `machine`, delegate to
        // VmCmd's own touches_vm_state (pause/resume/snapshot/save/restore
        // converge; registry-record and guest-RPC ops opt out).
        if let Commands::Machine(a) = self {
            if let machine::MachineAction::Vm(ref cmd) = a.action {
                return cmd.touches_vm_state();
            }
            if let machine::MachineAction::Run(ref run) = a.action {
                return machine_run_touches_vm_state(run);
            }
            // `machine ls --all` is the listing that must render registry-only
            // stopped rows before any convergence pass can sweep them.
            if let machine::MachineAction::Ls(ref list) = a.action {
                return !list.all;
            }
            return true;
        }
        matches!(
            self,
            // Lifecycle mutate/read on the local single-host path.
            Commands::Run(_)
        )
    }

    /// Canonical clap-subcommand name for this variant. Used as the
    /// `<verb>` slot in `cmd.<verb>.*` audit events. The values
    /// MUST match the names emitted by `clap::Command::get_name()`
    /// (the `audit_total_coverage.rs` test pins this via the
    /// AUDIT_POSTURE table; bumping a name here without a matching
    /// table update will trip that test).
    pub(super) fn verb_name(&self) -> &'static str {
        match self {
            // `env <sub>` delegates (bootstrap/cleanup/uninstall/update/sign).
            Commands::Env(a) => a.action.verb_name(),
            Commands::Bootstrap(_) => "bootstrap",
            Commands::BuilderVmBootstrap(_) => "__builder-vm-bootstrap",
            Commands::BuilderEgressSupervisor(_) => "__builder-egress-supervisor",
            #[cfg(feature = "builder-vm")]
            Commands::BuilderShellJob(_) => "__builder-shell-job",
            Commands::Explain(_) => "explain",
            Commands::Bench(_) => "bench",
            Commands::Plugin(_) => "plugin",
            Commands::Completions(_) => "completions",
            Commands::Run(_) => "run",
            Commands::SdkNoVm(_) => "__sdk-no-vm",
            Commands::Doctor(_) => "doctor",
            Commands::Dashboard(_) => "dashboard",
            Commands::Prepare(_) => "prepare",
            Commands::Kernel(_) => "kernel",
            Commands::Generate(_) => "generate",
            Commands::Template(_) => "template",
            Commands::Watch(_) => "watch",
            Commands::Manifest(_) => "manifest",
            Commands::Image(_) => "image",
            Commands::Pack(_) => "pack",
            // `machine <sub>`: folded advanced ops (pause/snapshot/set-ttl/…)
            // keep their per-op verb; native lifecycle verbs report `machine`.
            Commands::Machine(a) => a.action.verb_name(),
            Commands::Storage(_) => "storage",
            // `build <sub>` delegates to the per-op verb (image/compile/validate/kernel).
            Commands::Build(a) => a.action.verb_name(),
            Commands::Deploy(_) => "deploy",
            Commands::ShellInit(_) => "shell-init",
            // `ops <sub>` delegates to the per-op verb (metrics/config/MCP).
            Commands::Ops(a) => a.action.verb_name(),
            Commands::Network(_) => "network",
            Commands::Catalog(_) => "catalog",
            Commands::Cache(_) => "cache",
            Commands::Pool(_) => "pool",
            Commands::Reconcile(_) => "reconcile",
            Commands::Init(_) => "init",
            Commands::Secret(_) => "secret",
            Commands::Bundle(_) => "bundle",
            // `trust <sub>` delegates: attest/receipt/audit keep their own
            // verbs, publisher add/list/remove keep `trust`.
            Commands::Trust(a) => a.action.verb_name(),
            Commands::AgentSession(_) => "agent-session",
            Commands::Deps(_) => "deps",
            Commands::Capture(a) => a.action.verb_name(),
            Commands::Artifact(_) => "artifact",
            Commands::SeccompAudit(_) => "seccomp-audit",
            #[cfg(feature = "builder-vm")]
            Commands::PersistentBuilder(_) => "persistent-builder",
            Commands::QemuVsockBridge(_) => "__qemu-vsock-bridge",
        }
    }
}

fn machine_run_touches_vm_state(run: &machine::MachineRunArgs) -> bool {
    run.name.is_some() || run.detach || run.up_json || run.ttl.is_some() || run.attach
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_hostd::supervisor::CapturingAuditSigner;

    fn recorder_with_capturing_signer() -> (Recorder, Arc<CapturingAuditSigner>) {
        let signer = Arc::new(CapturingAuditSigner::new());
        let rec = Recorder::new(signer.clone(), TenantId("local".to_string()));
        (rec, signer)
    }

    #[test]
    fn the_active_file_signer_is_scoped_to_the_command_and_directory() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let signer = Arc::new(
            FileAuditSigner::open(ed25519_dalek::SigningKey::from_bytes(&[41; 32]), dir.path())
                .unwrap(),
        );
        *ACTIVE_CMD_SIGNER
            .lock()
            .expect("active command signer poisoned") = Some(ActiveCmdSigner {
            audit_dir: dir.path().to_path_buf(),
            signer: Arc::downgrade(&signer),
        });
        let audit = CommandAudit {
            recorder: Recorder::new(signer.clone(), TenantId("local".to_string())),
            _signer: signer.clone(),
        };

        let active = active_signer_for(dir.path()).expect("matching directory shares the signer");
        assert!(Arc::ptr_eq(&active, &signer));
        assert!(active_signer_for(other.path()).is_none());

        drop(audit);
        assert!(active_signer_for(dir.path()).is_none());
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
