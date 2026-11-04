use anyhow::Result;
use serde::Serialize;

use mvm_client::checkpoint::Checkpoints;

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
/// `mvmctl vm checkpoint verify <id>`: chain-anchored lineage verification.
/// Exits nonzero on any failure so it is scriptable.
pub(super) fn verify(id: &str, json: bool) -> Result<()> {
    let checkpoint = validated_checkpoint_id(id)?;

    match Checkpoints::open().verify_lineage(&checkpoint) {
        Ok(()) => {
            if json {
                crate::json_out::emit_json(&CheckpointVerifyJson {
                    schema_version: 1,
                    action: "verify",
                    id: checkpoint.as_str(),
                    verified: true,
                    error: None,
                })?;
            } else {
                ui::success(&format!(
                    "checkpoint {} lineage verifies against the signed audit chain",
                    checkpoint.as_str()
                ));
            }
            Ok(())
        }
        Err(e) => {
            if json {
                crate::json_out::emit_json(&CheckpointVerifyJson {
                    schema_version: 1,
                    action: "verify",
                    id: checkpoint.as_str(),
                    verified: false,
                    error: Some(format!("{e:#}")),
                })?;
            }
            Err(e.context(format!(
                "checkpoint {} lineage verification failed",
                checkpoint.as_str()
            )))
        }
    }
}
