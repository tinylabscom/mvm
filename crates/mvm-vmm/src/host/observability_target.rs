//! Per-VM observability target metadata for host-side eBPF probes.
//!
//! This module defines a small, serializable contract that lets host-side
//! telemetry collectors (eBPF, procfs pollers, etc.) attach to the right
//! host processes for a given VM without knowing backend-specific file
//! layouts. It is persisted as part of `mode.json` by
//! `crate::host::runtime_meta`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Identifies a process that an observability probe may attach to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessTarget {
    /// Logical role, e.g. "vmm", "substitution", "broker",
    /// "audit-signer", "qemu-vsock-bridge".
    pub role: String,

    /// Executable base name, e.g. "firecracker" or "mvm-network-endpoint".
    pub process_name: String,

    /// Path to the PID file written by the spawner.
    pub pid_file: PathBuf,

    /// Resolved PID, if available at write time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
}

/// VMM-specific observability target fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmmTarget {
    pub process_name: String,
    pub pid_file: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Whether the VMM process is expected to run as root (Firecracker).
    #[serde(default)]
    pub runs_as_root: bool,
}

/// Vsock layout for the VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VsockTarget {
    /// Guest CID, if fixed or allocated per-VM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_cid: Option<u32>,

    /// Directory containing per-port vsock socket files.
    pub socket_dir: PathBuf,
}

/// Network-related observability target fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkTarget {
    /// Path to the substitution endpoint's Unix domain socket.
    pub substitution_socket: PathBuf,
}

/// Backend-agnostic observability metadata for a running VM.
///
/// Populated at VM start and updated as VMM/helper PIDs become available.
/// Host-side collectors read this record to attach probes without
/// hard-coding backend file layouts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmObservabilityTarget {
    /// Backend kind string, e.g. "firecracker", "libkrun", "hvf", "qemu".
    pub backend_kind: String,

    /// VM state directory (`~/.mvm/vms/<name>`).
    pub state_dir: PathBuf,

    /// Socket directory (may be a short `/tmp` path on macOS).
    pub socket_dir: PathBuf,

    /// Tenant that admitted the workload, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// Plan ID of the admitted workload, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<String>,

    /// VMM process target.
    pub vmm: VmmTarget,

    /// Helper processes (substitution endpoint, broker, etc.).
    pub helpers: Vec<ProcessTarget>,

    /// Vsock socket layout.
    pub vsock: VsockTarget,

    /// Network observability fields.
    pub network: NetworkTarget,

    /// Reserved for future cgroup-scoped probes. Today cgroups are not
    /// assigned per-VM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cgroup_path: Option<PathBuf>,
}

impl VmObservabilityTarget {
    /// Return the substitution-endpoint helper target, if recorded.
    pub fn substitution_target(&self) -> Option<&ProcessTarget> {
        self.helpers.iter().find(|h| h.role == "substitution")
    }
}

/// Read a PID from a PID file, returning `None` if the file is missing or
/// unreadable. This is best-effort: observability must not fail VM start.
///
/// The pid is the file's first field: an endpoint's pid file also records
/// when the process started, after the pid.
pub fn read_pid_file(path: &std::path::Path) -> Option<u32> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_pid_file_returns_none_for_missing_file() {
        let path = std::path::Path::new("/nonexistent/path/pid");
        assert_eq!(read_pid_file(path), None);
    }

    #[test]
    fn read_pid_file_reads_the_pid_of_a_file_that_also_records_a_start_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("substitution.pid");
        std::fs::write(&path, "4242 1791788104").unwrap();
        assert_eq!(read_pid_file(&path), Some(4242));
        std::fs::write(&path, "4242\n").unwrap();
        assert_eq!(read_pid_file(&path), Some(4242));
    }
}
