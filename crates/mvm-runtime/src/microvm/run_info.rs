//! Per-VM `run-info.json` persistence (write/read/migrate) and orphaned-state
//! scanning/cleanup.

use anyhow::Result;
use tracing::instrument;

use crate::base::config::{MICROVM_DIR, RunInfo};
use crate::base::shell::{run_in_vm, run_in_vm_stdout};
use crate::base::ui;

use super::abs_vms_dir;
use super::flake_run::FlakeRunConfig;

/// Persist run info for a named VM.
#[instrument(skip_all, fields(name = %config.name))]
pub fn write_vm_run_info(config: &FlakeRunConfig, abs_dir: &str) -> Result<()> {
    let info = RunInfo {
        schema_version: 1,
        mode: "flake".to_string(),
        name: Some(config.name.clone()),
        revision: Some(config.revision_hash.clone()),
        flake_ref: Some(config.flake_ref.clone()),
        guest_ip: Some(config.slot.guest_ip.clone()),
        profile: config.profile.clone(),
        guest_user: String::new(),
        cpus: config.cpus,
        memory: config.memory,
        ports: config.ports.clone(),
    };

    // Also store slot_index for allocation tracking
    let mut json_value = serde_json::to_value(&info)?;
    if let Some(obj) = json_value.as_object_mut() {
        obj.insert(
            "slot_index".to_string(),
            serde_json::Value::Number(config.slot.index.into()),
        );
    }

    let json = serde_json::to_string(&json_value)?;
    run_in_vm(&format!(
        "echo '{}' > {dir}/run-info.json",
        json,
        dir = abs_dir,
    ))?;
    Ok(())
}

/// Read run info for a named VM.
#[instrument(skip_all, fields(name))]
pub fn read_vm_run_info(name: &str) -> Result<RunInfo> {
    let abs_vms = abs_vms_dir();
    let abs_dir = format!("{}/{}", abs_vms.trim(), name);
    read_vm_run_info_from(&abs_dir)
        .ok_or_else(|| anyhow::anyhow!("No run-info found for VM '{}'. Is it running?", name))
}

/// Current schema version for `RunInfo` files.
const RUN_INFO_SCHEMA_VERSION: u32 = 1;

/// Registered migrations for `RunInfo` (indexed by the version they produce).
/// Currently empty — framework is wired but no field changes have occurred yet.
const RUN_INFO_MIGRATIONS: &[mvm_core::migration::MigrateFn] = &[];

/// Read run info from a specific VM directory, applying schema migrations if needed.
pub(super) fn read_vm_run_info_from(abs_dir: &str) -> Option<RunInfo> {
    let json = run_in_vm_stdout(&format!(
        "cat {dir}/run-info.json 2>/dev/null || echo 'null'",
        dir = abs_dir,
    ))
    .ok()?;
    let raw: serde_json::Value = serde_json::from_str(&json).ok()?;
    let from = mvm_core::migration::schema_version_of(&raw);
    let migrated =
        mvm_core::migration::migrate(raw, from, RUN_INFO_SCHEMA_VERSION, RUN_INFO_MIGRATIONS)
            .map_err(|e| tracing::warn!("run-info migration failed: {e}"))
            .ok()?;
    serde_json::from_value(migrated).ok()
}

/// Read the slot_index from a VM's run-info.json.
pub(super) fn read_slot_index(abs_dir: &str) -> Option<u8> {
    let json = run_in_vm_stdout(&format!(
        "cat {dir}/run-info.json 2>/dev/null || echo 'null'",
        dir = abs_dir,
    ))
    .ok()?;
    let value: serde_json::Value = serde_json::from_str(&json).ok()?;
    value.get("slot_index")?.as_u64().map(|v| v as u8)
}

/// Check whether a PID is alive on the current OS.
///
/// On Linux: checks for `/proc/<pid>` existence (no signal needed).
/// On macOS: runs `kill -0 <pid>` via the shell.
pub fn is_pid_alive(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new(&format!("/proc/{}", pid)).exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

/// Scan the vms root on the Linux host for orphaned entries — run-info.json files
/// whose stored Firecracker PID is no longer alive.
///
/// Returns a list of VM names with orphaned state files.
pub fn find_orphaned_vms() -> Result<Vec<String>> {
    // List all run-info.json files and check each PID in a single shell script.
    let output = run_in_vm_stdout(&format!(
        r#"for dir in {vms_dir}/*/; do
            name=$(basename "$dir")
            rif="${{dir}}run-info.json"
            if [ ! -f "$rif" ]; then continue; fi
            pid=$(cat "$rif" 2>/dev/null | grep -o '"fc_pid":[0-9]*' | grep -o '[0-9]*$' | head -1)
            if [ -z "$pid" ]; then continue; fi
            if ! kill -0 "$pid" 2>/dev/null; then
                echo "$name"
            fi
        done 2>/dev/null || true"#,
        vms_dir = abs_vms_dir(),
    ))?;

    Ok(output
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect())
}

/// Remove orphaned `run-info.json` entries from the vms root.
///
/// In dry-run mode: lists orphaned entries without deleting.
/// In normal mode: removes the orphaned files and logs each removal.
pub fn cleanup_orphaned_vms(dry_run: bool) -> Result<()> {
    let orphans = find_orphaned_vms()?;

    if orphans.is_empty() {
        ui::success("No orphaned VM state files found.");
        return Ok(());
    }

    if dry_run {
        ui::info(&format!(
            "Would remove {} orphaned VM state file(s):",
            orphans.len()
        ));
        for name in &orphans {
            println!("  {}", name);
        }
        return Ok(());
    }

    for name in &orphans {
        let result = run_in_vm(&format!(
            "rm -f {vms_dir}/{name}/run-info.json",
            vms_dir = abs_vms_dir(),
            name = name,
        ));
        match result {
            Ok(_) => {
                ui::success(&format!("Removed orphaned state for VM '{}'", name));
                tracing::info!(vm = %name, "removed orphaned run-info.json");
            }
            Err(e) => {
                tracing::warn!(vm = %name, "failed to remove orphaned run-info.json: {e}");
            }
        }
    }

    Ok(())
}

/// Read persisted run info (returns None if file doesn't exist), with migration.
pub fn read_run_info() -> Option<RunInfo> {
    let json = run_in_vm_stdout(&format!(
        "cat {dir}/.mvm-run-info 2>/dev/null || echo 'null'",
        dir = MICROVM_DIR,
    ))
    .ok()?;
    let raw: serde_json::Value = serde_json::from_str(&json).ok()?;
    let from = mvm_core::migration::schema_version_of(&raw);
    let migrated =
        mvm_core::migration::migrate(raw, from, RUN_INFO_SCHEMA_VERSION, RUN_INFO_MIGRATIONS)
            .map_err(|e| tracing::warn!("run-info migration failed: {e}"))
            .ok()?;
    serde_json::from_value(migrated).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // is_pid_alive
    #[test]
    fn test_is_pid_alive_current_process() {
        // The current process is definitely alive.
        let my_pid = std::process::id();
        assert!(is_pid_alive(my_pid), "current process must be alive");
    }

    #[test]
    fn test_is_pid_alive_impossible_pid() {
        // PID 999999999 exceeds the maximum Linux PID (4194304) and will never exist.
        assert!(
            !is_pid_alive(999_999_999),
            "impossible PID must not be alive"
        );
    }
}
