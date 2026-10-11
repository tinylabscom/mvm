//! One-shot prompt replay: verified preparation, admitted fork, then dispatch.

use super::{ReplayService, SessionReplayReport, SessionReplayRequest, SessionReplaySummary};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Run a recorded session on a fresh checkpoint fork, or inspect it without effects.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct SessionReplayRunRequest {
    pub selection: SessionReplayRequest,
    pub dry_run: bool,
    pub timeout_secs: u64,
    pub tenant: String,
}

/// Dry runs have a verified summary but no execution report.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SessionReplayRunReport {
    pub summary: SessionReplaySummary,
    pub execution: Option<SessionReplayReport>,
}

impl ReplayService {
    /// Verify the complete session timeline before creating or contacting a VM.
    ///
    /// A mid-dispatch failure leaves the fork running at its last answered
    /// prompt, matching ordinary replay recovery. Fork hygiene failures stop it
    /// before any prompt may be sent.
    pub fn run_session(
        &self,
        request: &SessionReplayRunRequest,
        observer: &mut dyn crate::entrypoint::CallObserver,
    ) -> Result<SessionReplayRunReport> {
        let prepared = self.prepare_session(&request.selection)?;
        let summary = prepared.summary().clone();
        let execution = if request.dry_run {
            None
        } else {
            self.checkpoints
                .fork(
                    &crate::checkpoint::ForkRequest {
                        id: summary.checkpoint.clone(),
                        new_id: Some(summary.restored_name.clone()),
                        boot: true,
                        hypervisor: String::new(),
                        cpus: None,
                        memory: None,
                        declared_secrets: Vec::new(),
                        allow_secret_drop: false,
                        // Prompt replay preserves the parent's prompt grant; unlike
                        // exec-journal replay it must not request unrestricted exec.
                        intent: crate::checkpoint::ForkIntent::Ordinary,
                        tenant: request.tenant.clone(),
                    },
                    observer,
                )
                .with_context(|| {
                    format!(
                        "restoring checkpoint {:?} for replay",
                        summary.checkpoint.as_str()
                    )
                })?;
            Some(prepared.dispatch(request.timeout_secs, observer)?)
        };
        Ok(SessionReplayRunReport { summary, execution })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_session_refuses_before_fork_or_dispatch() {
        let root = tempfile::tempdir().unwrap();
        let service = ReplayService {
            checkpoints: crate::checkpoint::Checkpoints::at(root.path()),
        };
        let request = SessionReplayRunRequest {
            selection: SessionReplayRequest {
                session_id: "Not A Session".into(),
                from: None,
                as_name: None,
            },
            dry_run: false,
            timeout_secs: 1,
            tenant: "default".into(),
        };
        assert!(
            service
                .run_session(&request, &mut crate::entrypoint::CapturedOutput::default())
                .is_err()
        );
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn dry_run_report_contains_metadata_but_no_execution() {
        let report = SessionReplayRunReport {
            summary: SessionReplaySummary {
                checkpoint: mvm_core::checkpoint::CheckpointId::new("base"),
                session_id: "session".into(),
                generation: 1,
                checkpoint_cursor: 0,
                restored_name: "fork".into(),
                inputs: Vec::new(),
            },
            execution: None,
        };
        let json = serde_json::to_value(&report).unwrap();
        assert!(json["execution"].is_null());
        assert_eq!(json["summary"]["checkpoint"], "base");
        let decoded: SessionReplayRunReport = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.summary, report.summary);
        assert!(decoded.execution.is_none());
    }
}
