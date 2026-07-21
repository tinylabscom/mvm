//! VM observability: logs, layered diagnostics, the running-VM listing, and
//! slot allocation/reservation bookkeeping.

use anyhow::{Context, Result};
use tracing::{instrument, warn};

use crate::base::config::{RunInfo, VmSlot};
use crate::base::shell::{run_in_vm, run_in_vm_stdout, run_in_vm_visible, shell_quote};
use crate::base::ui;
use crate::firecracker;

use super::{abs_vms_dir, firecracker_vsock_uds_path, require_linux_env};

/// Show logs from a named VM.
///
/// By default shows the guest serial console (`console.log`).
/// With `hypervisor=true`, shows Firecracker hypervisor logs (`firecracker.log`).
pub fn logs(name: &str, follow: bool, lines: u32, hypervisor: bool) -> Result<()> {
    require_linux_env()?;

    let abs_vms = abs_vms_dir();
    let filename = if hypervisor {
        "firecracker.log"
    } else {
        "console.log"
    };
    let log_file = format!("{}/{}/{}", abs_vms, name, filename);

    // Check the log file exists; fall back to firecracker.log for VMs started before
    // the console.log split.
    let exists = run_in_vm_stdout(&format!("[ -f {} ] && echo yes || echo no", log_file))?;
    if exists.trim() != "yes" {
        if !hypervisor {
            // Try legacy location (pre-split VMs wrote everything to firecracker.log)
            let fallback = format!("{}/{}/firecracker.log", abs_vms, name);
            let fb_exists =
                run_in_vm_stdout(&format!("[ -f {} ] && echo yes || echo no", fallback))?;
            if fb_exists.trim() == "yes" {
                ui::warn(
                    "console.log not found; showing firecracker.log (VM started before log split)",
                );
                return show_log_file(&fallback, follow, lines);
            }
        }
        anyhow::bail!("No logs found for VM '{}' (is the name correct?)", name);
    }

    show_log_file(&log_file, follow, lines)
}

fn show_log_file(log_file: &str, follow: bool, lines: u32) -> Result<()> {
    if follow {
        run_in_vm_visible(&format!("tail -f {}", log_file))?;
    } else {
        let output = run_in_vm_stdout(&format!("tail -n {} {}", lines, log_file))?;
        print!("{}", output);
    }
    Ok(())
}

// ============================================================================
// VM diagnostics
// ============================================================================

/// Result of layered VM diagnostics. Each field represents one diagnostic
/// check that works independently of vsock connectivity.
#[derive(Debug, serde::Serialize)]
pub struct DiagnoseResult {
    pub fc_alive: bool,
    pub fc_pid: Option<u32>,
    pub fc_api_responsive: bool,
    pub fc_machine_config: Option<serde_json::Value>,
    pub vsock_exists: bool,
    pub console_warnings: Vec<String>,
    pub fc_log_errors: Vec<String>,
    pub agent_reachable: bool,
    pub agent_error: Option<String>,
    pub worker_status: Option<String>,
    pub last_busy_at: Option<String>,
    pub probe_results: Vec<mvm_agentd::probes::ProbeResult>,
    pub integration_results: Vec<mvm_agentd::integrations::IntegrationStateReport>,
    pub suggestions: Vec<String>,
}

/// Known-bad patterns in console log output.
const CONSOLE_WARNING_PATTERNS: &[&str] = &[
    "Kernel panic",
    "Out of memory",
    "Killed process",
    "BUG:",
    "Call Trace:",
    "oom-kill:",
    "invoked oom-killer",
];

/// Run layered diagnostics on a named VM.
///
/// Checks each layer independently so that useful information is returned
/// even when vsock is broken (e.g. guest agent crashed, OOM, kernel panic).
#[instrument(skip_all, fields(name))]
pub fn diagnose_vm(name: &str) -> Result<DiagnoseResult> {
    require_linux_env()?;

    let abs_vms = abs_vms_dir();
    let abs_dir = format!("{}/{}", abs_vms, name);

    // Check VM directory exists
    let dir_exists = run_in_vm_stdout(&format!("[ -d '{}' ] && echo yes || echo no", abs_dir))?;
    if dir_exists.trim() != "yes" {
        anyhow::bail!(
            "VM directory not found: {}. The VM '{}' may not exist.",
            abs_dir,
            name
        );
    }

    let mut result = DiagnoseResult {
        fc_alive: false,
        fc_pid: None,
        fc_api_responsive: false,
        fc_machine_config: None,
        vsock_exists: false,
        console_warnings: Vec::new(),
        fc_log_errors: Vec::new(),
        agent_reachable: false,
        agent_error: None,
        worker_status: None,
        last_busy_at: None,
        probe_results: Vec::new(),
        integration_results: Vec::new(),
        suggestions: Vec::new(),
    };

    // Layer 1: FC process alive?
    let pid_check = run_in_vm_stdout(&format!(
        r#"if [ -f '{dir}/fc.pid' ]; then
            pid=$(cat '{dir}/fc.pid')
            if [ -f "/proc/$pid/comm" ] && [ "$(cat /proc/$pid/comm)" = "firecracker" ]; then
                echo "alive:$pid"
            else
                echo "dead:$pid"
            fi
        else
            echo "nopid"
        fi"#,
        dir = abs_dir,
    ))?;
    let pid_check = pid_check.trim();
    if let Some(pid_str) = pid_check.strip_prefix("alive:") {
        result.fc_alive = true;
        result.fc_pid = pid_str
            .parse()
            .map_err(|e| warn!("failed to parse firecracker PID '{}': {}", pid_str, e))
            .ok();
    } else if let Some(pid_str) = pid_check.strip_prefix("dead:") {
        result.fc_pid = pid_str
            .parse()
            .map_err(|e| warn!("failed to parse firecracker PID '{}': {}", pid_str, e))
            .ok();
        result.suggestions.push(format!(
            "Firecracker process (pid {}) is dead. Run: mvmctl stop {}",
            pid_str, name,
        ));
    } else {
        result
            .suggestions
            .push(format!("No fc.pid file found. Run: mvmctl stop {}", name));
    }

    // Layer 2: FC API responsive?
    if result.fc_alive {
        let api_output = run_in_vm_stdout(&format!(
            "sudo curl -sf --unix-socket '{dir}/fc.socket' 'http://localhost/machine-config' 2>/dev/null || echo FAIL",
            dir = abs_dir,
        ))?;
        let api_output = api_output.trim();
        if api_output != "FAIL" {
            result.fc_api_responsive = true;
            result.fc_machine_config = serde_json::from_str(api_output)
                .map_err(|e| warn!("failed to parse FC machine config: {}", e))
                .ok();
        }
    }

    // Layer 3: Vsock socket exists?
    let vsock_path = firecracker_vsock_uds_path(&abs_dir);
    let sock_check = run_in_vm_stdout(&format!(
        "[ -S '{vsock}' ] && echo yes || echo no",
        vsock = vsock_path,
    ))?;
    result.vsock_exists = sock_check.trim() == "yes";
    if !result.vsock_exists && result.fc_alive {
        result.suggestions.push(
            "Vsock socket missing despite FC running — vsock device may not be configured.".into(),
        );
    }

    // Layer 4: Console log warnings
    let console_tail = run_in_vm_stdout(&format!(
        "tail -n 200 '{dir}/console.log' 2>/dev/null || true",
        dir = abs_dir,
    ))?;
    for line in console_tail.lines() {
        for pattern in CONSOLE_WARNING_PATTERNS {
            if line.contains(pattern) {
                result.console_warnings.push(line.trim().to_string());
                break;
            }
        }
    }
    if !result.console_warnings.is_empty() {
        result.suggestions.push(format!(
            "Console log contains warnings. Run: mvmctl logs {} -n 200",
            name,
        ));
    }

    // Layer 5: FC log errors
    let fc_log_tail = run_in_vm_stdout(&format!(
        "tail -n 100 '{dir}/firecracker.log' 2>/dev/null || true",
        dir = abs_dir,
    ))?;
    for line in fc_log_tail.lines() {
        if line.contains("ERROR") {
            result.fc_log_errors.push(line.trim().to_string());
        }
    }

    // Layer 6: Guest agent reachable? (short timeout)
    if result.vsock_exists {
        match mvm_agentd::vsock::ping_at(&vsock_path) {
            Ok(true) => {
                result.agent_reachable = true;
            }
            Ok(false) => {
                result.agent_error = Some("Ping returned false".into());
                result
                    .suggestions
                    .push("Guest agent not responding to ping.".into());
            }
            Err(e) => {
                result.agent_error = Some(e.to_string());
                if !result.fc_alive {
                    result
                        .suggestions
                        .push("Firecracker process is dead — guest agent cannot respond.".into());
                } else {
                    result.suggestions.push(
                        "Guest agent unreachable. Check if mvm-guest-agent service is running inside the guest.".into(),
                    );
                }
            }
        }
    }

    // Layer 7: If agent reachable, get detailed status
    if result.agent_reachable {
        if let Ok(mvm_agentd::vsock::GuestResponse::WorkerStatus {
            status,
            last_busy_at,
        }) = mvm_agentd::vsock::query_worker_status_at(&vsock_path)
        {
            result.worker_status = Some(status);
            result.last_busy_at = last_busy_at;
        }
        result.integration_results =
            mvm_agentd::vsock::query_integration_status_at(&vsock_path).unwrap_or_default();
        result.probe_results =
            mvm_agentd::vsock::query_probe_status_at(&vsock_path).unwrap_or_default();

        // Check for failing health checks
        let failing: Vec<&str> = result
            .integration_results
            .iter()
            .filter(|ig| !ig.health.as_ref().is_some_and(|h| h.healthy))
            .map(|ig| ig.name.as_str())
            .chain(
                result
                    .probe_results
                    .iter()
                    .filter(|p| !p.healthy)
                    .map(|p| p.name.as_str()),
            )
            .collect();
        if !failing.is_empty() {
            result.suggestions.push(format!(
                "Failing health checks: {}. Run: mvmctl vm inspect {}",
                failing.join(", "),
                name,
            ));
        }
    }

    Ok(result)
}

/// List all running VMs by scanning `<mvm_home>/vms/*/run-info.json`.
#[instrument(skip_all)]
pub fn list_vms() -> Result<Vec<RunInfo>> {
    let output = run_in_vm_stdout(&format!(
        "for f in {dir}/*/run-info.json; do [ -f \"$f\" ] && cat \"$f\"; done 2>/dev/null || true",
        dir = abs_vms_dir(),
    ))?;

    let mut vms = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(info) = serde_json::from_str::<RunInfo>(line) {
            // Verify the VM is actually running
            if let Some(ref name) = info.name {
                let abs_vms = abs_vms_dir();
                let pid_file = format!("{}/{}/fc.pid", abs_vms, name);
                if firecracker::is_vm_running(&pid_file).unwrap_or(false) {
                    vms.push(info);
                }
            }
        }
    }

    Ok(vms)
}

/// Allocate the next free slot index by scanning existing VMs.
pub fn allocate_slot(name: &str) -> Result<VmSlot> {
    let q_name = shell_quote(name);
    let q_json_name = shell_quote(&serde_json::to_string(name)?);
    let output = run_in_vm_stdout(&format!(
        r#"
        set -e
        mkdir -p {dir}
        (
          flock -x 9
          used="$(
            for f in {dir}/*/run-info.json; do
              [ -f "$f" ] || continue
              sed -n 's/.*"slot_index":\([0-9][0-9]*\).*/\1/p' "$f"
            done 2>/dev/null || true
          )"
          for i in $(seq 0 252); do
            if ! printf '%s\n' "$used" | grep -qx "$i"; then
              vm_dir={dir}/{name}
              mkdir -p "$vm_dir"
              printf '{{"schema_version":1,"mode":"starting","name":%s,"slot_index":%s,"slot_reserved":true}}\n' {json_name} "$i" > "$vm_dir/run-info.json"
              echo "$i"
              exit 0
            fi
          done
          exit 2
        ) 9>{dir}/.slot.lock
        "#,
        dir = abs_vms_dir(),
        name = q_name,
        json_name = q_json_name,
    ))?;

    let index = output
        .lines()
        .rev()
        .find_map(|line| line.trim().parse::<u8>().ok())
        .ok_or_else(|| anyhow::anyhow!("No free VM slots available (max 253 VMs)"))?;
    Ok(VmSlot::new(name, index))
}

/// Recreate a slot from a previously reserved VM directory.
pub fn read_reserved_slot(name: &str) -> Result<VmSlot> {
    let q_name = shell_quote(name);
    let output = run_in_vm_stdout(&format!("cat {}/{}/run-info.json", abs_vms_dir(), q_name))?;
    let value: serde_json::Value =
        serde_json::from_str(output.trim()).with_context(|| format!("parse slot for {name}"))?;
    let index = value
        .get("slot_index")
        .and_then(serde_json::Value::as_u64)
        .and_then(|n| u8::try_from(n).ok())
        .ok_or_else(|| anyhow::anyhow!("reserved slot for '{name}' has no valid slot_index"))?;
    Ok(VmSlot::new(name, index))
}

pub(super) fn release_slot_reservation(slot: &VmSlot) -> Result<()> {
    let q_name = shell_quote(&slot.name);
    run_in_vm(&format!(
        r#"
        run_info={dir}/{name}/run-info.json
        if [ -f {run_info} ] && grep -q '"slot_reserved":true' {run_info}; then
          rm -f {run_info}
        fi
        "#,
        dir = abs_vms_dir(),
        name = q_name,
        run_info = "$run_info",
    ))
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_warning_patterns_detect_kernel_panic() {
        let lines = "Booting Linux\nKernel panic - not syncing: VFS\ndone";
        let mut warnings = Vec::new();
        for line in lines.lines() {
            for pattern in CONSOLE_WARNING_PATTERNS {
                if line.contains(pattern) {
                    warnings.push(line.to_string());
                    break;
                }
            }
        }
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Kernel panic"));
    }

    #[test]
    fn console_warning_patterns_detect_oom() {
        let lines = "init done\nOut of memory: Killed process 123\nnormal line";
        let mut warnings = Vec::new();
        for line in lines.lines() {
            for pattern in CONSOLE_WARNING_PATTERNS {
                if line.contains(pattern) {
                    warnings.push(line.to_string());
                    break;
                }
            }
        }
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Out of memory"));
    }

    #[test]
    fn console_warning_patterns_skip_clean_log() {
        let lines = "Booting Linux\nStarting services\nAll services ready";
        let mut warnings = Vec::new();
        for line in lines.lines() {
            for pattern in CONSOLE_WARNING_PATTERNS {
                if line.contains(pattern) {
                    warnings.push(line.to_string());
                    break;
                }
            }
        }
        assert!(warnings.is_empty());
    }

    #[test]
    fn diagnose_result_serializes_to_json() {
        let result = DiagnoseResult {
            fc_alive: true,
            fc_pid: Some(12345),
            fc_api_responsive: true,
            fc_machine_config: Some(serde_json::json!({"vcpu_count": 2})),
            vsock_exists: true,
            console_warnings: vec![],
            fc_log_errors: vec![],
            agent_reachable: true,
            agent_error: None,
            worker_status: Some("idle".into()),
            last_busy_at: None,
            probe_results: vec![],
            integration_results: vec![],
            suggestions: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"fc_alive\":true"));
        assert!(json.contains("\"fc_pid\":12345"));
    }
}
