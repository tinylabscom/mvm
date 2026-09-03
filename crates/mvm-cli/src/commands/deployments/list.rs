//! `mvmctl deployments ls`.

use anyhow::Result;
use serde::Serialize;

use mvm_core::config::deployments_dir;
use mvm_sdk::deploy::list_deployments;

use crate::ui;

/// One row of `deployments ls` — the fields a user needs to recognize
/// a deployment and trace it to exact bytes, flattened for JSON.
#[derive(Debug, Serialize)]
struct DeploymentRow {
    workload_id: String,
    ir_hash: String,
    image_blake3: String,
    image_sha256: String,
    boot_sha256: String,
    kernel_sha256: Option<String>,
    sbom_sha256: Option<String>,
}

pub(in crate::commands) fn run(workload: Option<String>, json: bool) -> Result<()> {
    let (entries, skips) = list_deployments(&deployments_dir())?;
    let rows: Vec<DeploymentRow> = entries
        .iter()
        .filter(|entry| {
            workload
                .as_deref()
                .is_none_or(|wanted| entry.record.workload_id == wanted)
        })
        .map(|entry| DeploymentRow {
            workload_id: entry.record.workload_id.clone(),
            ir_hash: entry.ir_hash.clone(),
            image_blake3: entry.record.image.blake3.clone(),
            image_sha256: entry.record.image.sha256.clone(),
            boot_sha256: entry.record.boot_artifact.sha256.clone(),
            kernel_sha256: entry
                .record
                .environment
                .as_ref()
                .map(|pin| pin.kernel_sha256.clone()),
            sbom_sha256: entry
                .record
                .dependency_volume
                .as_ref()
                .map(|volume| volume.sbom_sha256.clone()),
        })
        .collect();

    for skip in &skips {
        ui::warn(&format!("skipping {}: {}", skip.dir, skip.reason));
    }

    if json {
        crate::json_out::emit_json(&rows)?;
        return Ok(());
    }

    if rows.is_empty() {
        ui::info("No deployments recorded. `mvmctl deploy` records one per deployment.");
        return Ok(());
    }

    for row in &rows {
        println!(
            "{:<24}  {:<12}  blake3:{}  boot:{}",
            row.workload_id,
            row.ir_hash.get(..12).unwrap_or(&row.ir_hash),
            row.image_blake3.get(..12).unwrap_or(&row.image_blake3),
            row.boot_sha256.get(..12).unwrap_or(&row.boot_sha256),
        );
    }
    ui::info("Exact digests: re-run with --json.");
    Ok(())
}
