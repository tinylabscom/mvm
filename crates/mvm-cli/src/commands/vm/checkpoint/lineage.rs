use anyhow::Result;
use serde::Serialize;

use super::validated_checkpoint_id;
use crate::ui;

#[derive(Serialize)]
struct CheckpointVerifyJson<'a> {
    schema_version: u8,
    action: &'static str,
    id: &'a str,
    verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Render the verification result and preserve a nonzero status on failure.
pub(super) fn verify(id: &str, json: bool) -> Result<()> {
    let checkpoint = validated_checkpoint_id(id)?;
    let result = mvm_client::checkpoint::Checkpoints::open().verify(&checkpoint);
    if json {
        crate::json_out::emit_json(&CheckpointVerifyJson {
            schema_version: 1,
            action: "verify",
            id: checkpoint.as_str(),
            verified: result.is_ok(),
            error: result.as_ref().err().map(|error| format!("{error:#}")),
        })?;
    }
    result.map_err(|error| {
        error.context(format!(
            "checkpoint {} lineage verification failed",
            checkpoint.as_str()
        ))
    })?;
    if !json {
        ui::success(&format!(
            "checkpoint {} lineage verifies against the signed audit chain",
            checkpoint.as_str()
        ));
    }
    Ok(())
}
