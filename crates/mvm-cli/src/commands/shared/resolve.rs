//! Environment-aware resolution helpers (running VMs, flake refs, network policy).

use anyhow::{Context, Result};

use crate::bootstrap;

use mvm_runtime::config;
use mvm_runtime::shell;
use mvm_runtime::vm::{firecracker, lima};

/// Resolve a VM name to its absolute directory path inside the Lima VM
/// and verify it is running.
pub fn resolve_running_vm(name: &str) -> Result<String> {
    if bootstrap::is_lima_required() {
        lima::require_running()?;
    }

    let abs_vms = shell::run_in_vm_stdout(&format!("echo {}", config::VMS_DIR))?;
    let abs_dir = format!("{}/{}", abs_vms, name);
    let pid_file = format!("{}/fc.pid", abs_dir);

    if !firecracker::is_vm_running(&pid_file)? {
        anyhow::bail!(
            "VM '{}' is not running. Use 'mvmctl status' to list running VMs.",
            name
        );
    }

    Ok(abs_dir)
}

/// Resolve a flake reference: relative/absolute paths are canonicalized,
/// remote refs (containing `:`) pass through unchanged.
pub fn resolve_flake_ref(flake_ref: &str) -> Result<String> {
    if flake_ref.contains(':') {
        // Remote ref like "github:user/repo" — pass through
        return Ok(flake_ref.to_string());
    }

    // Local path — canonicalize to absolute
    let path = std::path::Path::new(flake_ref);
    let canonical = path
        .canonicalize()
        .with_context(|| format!("Flake path '{}' does not exist", flake_ref))?;

    Ok(canonical.to_string_lossy().to_string())
}

/// Resolve CLI network flags into a `NetworkPolicy`.
/// `--network-preset` and `--network-allow` are mutually exclusive.
pub fn resolve_network_policy(
    preset: Option<&str>,
    allow: &[String],
) -> Result<mvm_core::network_policy::NetworkPolicy> {
    use mvm_core::network_policy::{HostPort, NetworkPolicy, NetworkPreset};

    match (preset, allow.is_empty()) {
        (Some(_), false) => {
            anyhow::bail!("--network-preset and --network-allow are mutually exclusive")
        }
        (Some(name), true) => {
            let p: NetworkPreset = name.parse()?;
            Ok(NetworkPolicy::preset(p))
        }
        (None, false) => {
            let rules: Vec<HostPort> = allow
                .iter()
                .map(|s| s.parse())
                .collect::<Result<Vec<_>>>()?;
            Ok(NetworkPolicy::allow_list(rules))
        }
        (None, true) => Ok(NetworkPolicy::default()),
    }
}
