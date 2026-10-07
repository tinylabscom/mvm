//! Local machine-replay preparation.
//!
//! A replay command may orchestrate execution and rendering, but checkpoint
//! lookup and collision checks belong to the client layer that owns local
//! machine state.

use anyhow::{Context, Result, bail};
use mvm_core::checkpoint::{CheckpointId, CheckpointMeta};

use crate::checkpoint::Checkpoints;

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
