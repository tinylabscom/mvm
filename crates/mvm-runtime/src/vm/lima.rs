use anyhow::{Context, Result};

use crate::config::VM_NAME;
use crate::shell::{run_host, run_host_visible};
use crate::ui;

#[derive(Debug, PartialEq)]
pub enum LimaStatus {
    Running,
    Stopped,
    NotFound,
}

// ---------------------------------------------------------------------------
// Parameterized functions (accept vm_name)
// ---------------------------------------------------------------------------

/// Get the current status of a named Lima VM.
pub fn get_vm_status(vm_name: &str) -> Result<LimaStatus> {
    // On native KVM hosts, Lima isn't required—skip external call to limactl.
    if mvm_core::platform::current().has_kvm() {
        return Ok(LimaStatus::NotFound);
    }

    let output = run_host("limactl", &["list", "--format", "{{.Status}}", vm_name])?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if !output.status.success() || stdout.is_empty() {
        return Ok(LimaStatus::NotFound);
    }

    match stdout.as_str() {
        "Running" => Ok(LimaStatus::Running),
        "Stopped" => Ok(LimaStatus::Stopped),
        _ => Ok(LimaStatus::NotFound),
    }
}

/// Create and start a new named Lima VM from the given yaml config.
pub fn create_vm(vm_name: &str, lima_yaml: &std::path::Path) -> Result<()> {
    let yaml_str = lima_yaml.to_str().context("Invalid lima.yaml path")?;
    run_host_visible("limactl", &["start", "--name", vm_name, yaml_str])
}

/// Start an existing stopped named Lima VM.
pub fn start_vm(vm_name: &str) -> Result<()> {
    run_host_visible("limactl", &["start", vm_name])
}

/// Ensure a named Lima VM is running. Creates, starts, or does nothing as needed.
pub fn ensure_vm_running(vm_name: &str, lima_yaml: &std::path::Path) -> Result<()> {
    match get_vm_status(vm_name)? {
        LimaStatus::Running => {
            ui::info(&format!("Lima VM '{}' is running.", vm_name));
            Ok(())
        }
        LimaStatus::Stopped => {
            ui::info(&format!("Starting Lima VM '{}'...", vm_name));
            start_vm(vm_name)
        }
        LimaStatus::NotFound => {
            ui::info(&format!("Creating Lima VM '{}'...", vm_name));
            create_vm(vm_name, lima_yaml)
        }
    }
}

/// Stop a named Lima VM.
pub fn stop_vm(vm_name: &str) -> Result<()> {
    run_host_visible("limactl", &["stop", vm_name])
}

/// Delete a named Lima VM forcefully.
pub fn destroy_vm(vm_name: &str) -> Result<()> {
    run_host_visible("limactl", &["delete", "--force", vm_name])
}

// ---------------------------------------------------------------------------
// Default VM_NAME wrappers (used by setup, start, stop, ssh, etc.)
// ---------------------------------------------------------------------------

/// Get the current status of the default Lima VM.
pub fn get_status() -> Result<LimaStatus> {
    get_vm_status(VM_NAME)
}

/// Create and start the default Lima VM from the given yaml config.
pub fn create(lima_yaml: &std::path::Path) -> Result<()> {
    create_vm(VM_NAME, lima_yaml)
}

/// Start the default Lima VM.
pub fn start() -> Result<()> {
    start_vm(VM_NAME)
}

/// Ensure the default Lima VM is running.
pub fn ensure_running(lima_yaml: &std::path::Path) -> Result<()> {
    ensure_vm_running(VM_NAME, lima_yaml)
}

/// Require that the default Lima VM is currently running.
pub fn require_running() -> Result<()> {
    match get_vm_status(VM_NAME)? {
        LimaStatus::Running => Ok(()),
        LimaStatus::Stopped => {
            anyhow::bail!(
                "Lima VM '{}' is stopped. Run 'mvmctl dev up' or 'mvmctl setup'.",
                VM_NAME
            )
        }
        LimaStatus::NotFound => {
            anyhow::bail!(
                "Lima VM '{}' does not exist. Run 'mvmctl setup' first.",
                VM_NAME
            )
        }
    }
}

/// Stop the default Lima VM.
pub fn stop() -> Result<()> {
    stop_vm(VM_NAME)
}

/// Delete the default Lima VM forcefully.
pub fn destroy() -> Result<()> {
    destroy_vm(VM_NAME)
}
