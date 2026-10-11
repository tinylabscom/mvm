//! Best-effort, chain-signed command envelopes and scoped signer ownership.

use std::sync::Arc;

use mvm_core::plan::TenantId;
use mvm_hostd::audit::active_signer::{ActiveSignerGuard, register_active_signer};
use mvm_hostd::audit::emitter::default_audit_dir;
use mvm_hostd::audit::host_keypair;
use mvm_hostd::supervisor::{EventCategory, FileAuditSigner, Recorder};

/// An opaque command recorder; the underlying signer and keys stay private.
pub struct CommandRecorder {
    inner: Recorder,
}

/// Keeps the command's file signer available to admitted operations until the
/// frontend finishes dispatch. It cannot be serialized or detached from scope.
pub struct CommandAudit {
    recorder: CommandRecorder,
    _signer: Arc<FileAuditSigner>,
    _registration: ActiveSignerGuard,
}

impl CommandAudit {
    pub fn recorder(&self) -> &CommandRecorder {
        &self.recorder
    }
}

/// Open the configured host command audit scope. Setup remains best-effort:
/// report failures through tracing and let the frontend continue without this
/// envelope. Domain admission and mutation audit requirements are unchanged.
pub fn build_cmd_recorder() -> Option<CommandAudit> {
    let signer = match host_keypair::load_or_init() {
        Ok(signer) => signer,
        Err(error) => {
            tracing::warn!(
                error = %error,
                "plan 60 Phase 4 cmd recorder not wired (host signer); \
                 commands run without cmd-level audit"
            );
            return None;
        }
    };
    let audit_dir = match default_audit_dir() {
        Ok(dir) => dir,
        Err(error) => {
            tracing::warn!(error = %error, "plan 60 Phase 4 cmd recorder not wired (audit dir)");
            return None;
        }
    };
    let signer = match FileAuditSigner::open(signer.signing, &audit_dir) {
        Ok(signer) => Arc::new(signer),
        Err(error) => {
            tracing::warn!(error = %error, "plan 60 Phase 4 cmd recorder not wired (FileAuditSigner)");
            return None;
        }
    };
    let registration = register_active_signer(&audit_dir, &signer);
    Some(CommandAudit {
        recorder: CommandRecorder {
            inner: Recorder::new(signer.clone(), TenantId("local".to_string())),
        },
        _signer: signer,
        _registration: registration,
    })
}

/// Record the frontend's stable verb name before dispatch.
pub fn emit_cmd_invoked(recorder: Option<&CommandRecorder>, verb: &'static str) {
    let Some(recorder) = recorder else { return };
    emit(
        recorder,
        format!("cmd.{verb}.invoked"),
        vec![
            ("verb".to_string(), verb.to_string()),
            ("pid".to_string(), std::process::id().to_string()),
        ],
    );
}

/// Record completion or the existing display error after dispatch.
pub fn emit_cmd_outcome<T, E>(
    recorder: Option<&CommandRecorder>,
    verb: &'static str,
    outcome: &Result<T, E>,
) where
    E: std::fmt::Display,
{
    let Some(recorder) = recorder else { return };
    let (phase, extras) = match outcome {
        Ok(_) => ("completed", vec![("verb".to_string(), verb.to_string())]),
        Err(error) => (
            "failed",
            vec![
                ("verb".to_string(), verb.to_string()),
                ("error".to_string(), error.to_string()),
            ],
        ),
    };
    emit(recorder, format!("cmd.{verb}.{phase}"), extras);
}

fn emit(recorder: &CommandRecorder, event: String, extras: Vec<(String, String)>) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(error) => {
            tracing::warn!(error = %error, "building tokio runtime for cmd audit emit");
            return;
        }
    };
    if let Err(error) = rt.block_on(recorder.inner.record_unbound(
        EventCategory::Cmd,
        event,
        extras,
    )) {
        tracing::warn!(error = %error, "Recorder emit failed for cmd event");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_hostd::supervisor::CapturingAuditSigner;

    fn capturing() -> (CommandRecorder, Arc<CapturingAuditSigner>) {
        let signer = Arc::new(CapturingAuditSigner::new());
        let recorder = CommandRecorder {
            inner: Recorder::new(signer.clone(), TenantId("local".to_string())),
        };
        (recorder, signer)
    }

    #[test]
    fn active_signer_is_scoped_to_command_and_directory() {
        use mvm_hostd::audit::active_signer::active_signer_for;

        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let signer = Arc::new(
            FileAuditSigner::open(ed25519_dalek::SigningKey::from_bytes(&[41; 32]), dir.path())
                .unwrap(),
        );
        let audit = CommandAudit {
            recorder: CommandRecorder {
                inner: Recorder::new(signer.clone(), TenantId("local".to_string())),
            },
            _signer: signer.clone(),
            _registration: register_active_signer(dir.path(), &signer),
        };
        let active = active_signer_for(dir.path()).unwrap();
        assert!(Arc::ptr_eq(&active, &signer));
        assert!(active_signer_for(other.path()).is_none());
        drop(audit);
        assert!(active_signer_for(dir.path()).is_none());
    }

    #[test]
    fn invoked_preserves_canonical_event_verb_and_pid() {
        let (recorder, signer) = capturing();
        for verb in ["up", "set-ttl"] {
            emit_cmd_invoked(Some(&recorder), verb);
        }
        let entries = signer.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].event, "cmd.up.invoked");
        assert_eq!(entries[0].labels.get("verb"), Some(&"up".to_string()));
        assert!(entries[0].labels["pid"].parse::<u32>().is_ok());
        assert_eq!(entries[1].event, "cmd.set-ttl.invoked");
    }

    #[test]
    fn success_has_no_error_label_and_failure_preserves_its_meaning() {
        let (recorder, signer) = capturing();
        emit_cmd_outcome(Some(&recorder), "doctor", &Ok::<_, anyhow::Error>(()));
        emit_cmd_outcome(
            Some(&recorder),
            "up",
            &Err::<(), _>(anyhow::anyhow!("policy refused")),
        );
        let entries = signer.entries();
        assert_eq!(entries[0].event, "cmd.doctor.completed");
        assert_eq!(entries[0].labels.get("verb"), Some(&"doctor".to_string()));
        assert!(!entries[0].labels.contains_key("error"));
        assert_eq!(entries[1].event, "cmd.up.failed");
        assert_eq!(entries[1].labels["error"], "policy refused");
    }

    #[test]
    fn an_absent_recorder_is_a_noop() {
        emit_cmd_invoked(None, "up");
        emit_cmd_outcome(None, "up", &Ok::<_, anyhow::Error>(()));
    }

    #[test]
    fn an_unusable_key_directory_refuses_setup_without_overwriting_it() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let keys = mvm_core::config::mvm_keys_dir();
        std::fs::create_dir_all(keys.parent().unwrap()).unwrap();
        std::fs::write(&keys, "not a directory").unwrap();
        assert!(build_cmd_recorder().is_none());
        assert_eq!(std::fs::read_to_string(keys).unwrap(), "not a directory");
    }
}
