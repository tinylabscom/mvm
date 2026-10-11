//! Local machine-replay preparation.
//!
//! A replay command may orchestrate execution and rendering, but checkpoint
//! lookup and collision checks belong to the client layer that owns local
//! machine state.

use anyhow::{Context, Result, bail};
use mvm_core::checkpoint::{CheckpointId, CheckpointMeta};

use crate::checkpoint::Checkpoints;

pub mod input_journal;
mod session_run;
pub use session_run::{SessionReplayRunReport, SessionReplayRunRequest};

/// Select a signed session timeline without exposing its encrypted input store.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct SessionReplayRequest {
    pub session_id: String,
    pub from: Option<String>,
    pub as_name: Option<String>,
}

/// Public metadata for one encrypted input. Never contains prompt bytes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SessionReplayInput {
    pub journal_cursor: u64,
    pub artifact_digest: String,
}

/// A validated replay selection suitable for dry-run output and host APIs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SessionReplaySummary {
    pub checkpoint: CheckpointId,
    pub session_id: String,
    pub generation: u64,
    pub checkpoint_cursor: u64,
    pub restored_name: String,
    pub inputs: Vec<SessionReplayInput>,
}

/// Replay outcome without runtime implementation types.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SessionReplayReport {
    pub applied: usize,
    pub duplicates: usize,
    pub last_cursor: u64,
    pub nonzero_exits: Vec<(u64, i32)>,
}

/// An opaque, validated session replay. Neither serializable nor debug-printable.
///
/// Input references and decryption state stay client-owned. Dispatch rechecks
/// encrypted artifacts and the destination's admitted prompt grant.
pub struct PreparedSessionReplay {
    plan: mvm_runtime::agent_session::replay::ReplayPlan,
    inputs: mvm_runtime::agent_session::replay_input::ReplayInputStore,
    summary: SessionReplaySummary,
}

impl PreparedSessionReplay {
    pub(crate) fn new(
        plan: mvm_runtime::agent_session::replay::ReplayPlan,
        inputs: mvm_runtime::agent_session::replay_input::ReplayInputStore,
        restored_name: String,
    ) -> Self {
        let summary = SessionReplaySummary {
            checkpoint: plan.checkpoint.clone(),
            session_id: plan.session_id.as_str().to_owned(),
            generation: plan.generation,
            checkpoint_cursor: plan.checkpoint_cursor,
            restored_name,
            inputs: plan
                .inputs
                .iter()
                .map(|input| SessionReplayInput {
                    journal_cursor: input.binding.journal_cursor,
                    artifact_digest: input.artifact_digest.clone(),
                })
                .collect(),
        };
        Self {
            plan,
            inputs,
            summary,
        }
    }

    pub fn summary(&self) -> &SessionReplaySummary {
        &self.summary
    }

    /// Deliver only to the target selected during preparation.
    pub fn dispatch(
        &self,
        timeout_secs: u64,
        observer: &mut dyn crate::entrypoint::CallObserver,
    ) -> Result<SessionReplayReport> {
        let replayed = crate::agent_prompt::replay::replay_onto(
            &self.summary.restored_name,
            &self.plan,
            &self.inputs,
            timeout_secs,
            observer,
        )?;
        Ok(SessionReplayReport {
            applied: replayed.report.applied,
            duplicates: replayed.report.duplicates,
            last_cursor: replayed.report.last_cursor,
            nonzero_exits: replayed.nonzero_exits,
        })
    }
}

/// The source state and collision-free target selected for a replay.
#[derive(Debug)]
pub struct ReplaySource {
    pub checkpoint: CheckpointMeta,
    pub restored_name: String,
}

/// Prepare local replay operations against the checkpoint catalog.
pub struct ReplayService {
    checkpoints: Checkpoints,
}

impl ReplayService {
    pub fn open() -> Self {
        Self {
            checkpoints: Checkpoints::open(),
        }
    }

    pub fn with_checkpoints(checkpoints: Checkpoints) -> Self {
        Self { checkpoints }
    }

    /// Verify the signed session timeline and every selected encrypted input.
    pub fn prepare_session(&self, request: &SessionReplayRequest) -> Result<PreparedSessionReplay> {
        self.checkpoints.prepare_session_replay(request)
    }

    /// Load the replay source and choose a target that does not overwrite a
    /// running or persisted machine.
    pub fn prepare(&self, from: &CheckpointId, as_name: Option<&str>) -> Result<ReplaySource> {
        let checkpoint = self.checkpoints.read(from)?;
        let restored_name = replay_target_name(from, as_name)?;
        Ok(ReplaySource {
            checkpoint,
            restored_name,
        })
    }
}

impl Default for ReplayService {
    fn default() -> Self {
        Self::open()
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Choose a collision-free local target for checkpoint or prompt replay.
pub fn replay_target_name(from: &CheckpointId, as_name: Option<&str>) -> Result<String> {
    match as_name {
        Some(name) => {
            mvm_core::naming::validate_vm_name(name)
                .with_context(|| format!("Invalid VM name: {name:?}"))?;
            if mvm_runtime::checkpoint::vm_is_running(name) {
                bail!("a VM named {name:?} is already running; stop it or pick another --as name");
            }
            if mvm_runtime::machine::persist::load_machine_spec(name).is_ok() {
                bail!("a machine named {name:?} already exists; pick another --as name");
            }
            Ok(name.to_string())
        }
        None => Ok(format!("replay-{}-{}", from.as_str(), now_unix())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_targets_are_validated_by_the_service() {
        let error = replay_target_name(&CheckpointId::new("ckpt-a"), Some("bad name!"))
            .expect_err("invalid target");
        assert!(error.to_string().contains("Invalid VM name"), "{error:#}");
    }

    #[test]
    fn generated_target_carries_the_checkpoint_and_timestamp() {
        let name = replay_target_name(&CheckpointId::new("ckpt-a"), None).expect("target");
        assert!(name.starts_with("replay-ckpt-a-"), "{name}");
        assert!(name.len() > "replay-ckpt-a-".len());
    }
}
