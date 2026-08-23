//! Per-VM observability target metadata for host-side eBPF probes.
//!
//! This module defines a small, serializable contract that lets host-side
//! telemetry collectors (eBPF, procfs pollers, etc.) attach to the right
//! host processes for a given VM without knowing backend-specific file
//! layouts. It is persisted as part of `mode.json` by
//! `crate::host::runtime_meta`.

use std::path::PathBuf;

use mvm_core::vm_backend::BackendKind;
use serde::{Deserialize, Serialize};

use crate::host::network_endpoint_spawn;

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
    /// Return an iterator over all process targets (VMM + helpers).
    pub fn all_processes(&self) -> impl Iterator<Item = ProcessTarget> + '_ {
        let vmm = ProcessTarget {
            role: "vmm".to_string(),
            process_name: self.vmm.process_name.clone(),
            pid_file: self.vmm.pid_file.clone(),
            pid: self.vmm.pid,
        };
        std::iter::once(vmm).chain(self.helpers.iter().cloned())
    }

    /// Return the substitution-endpoint helper target, if recorded.
    pub fn substitution_target(&self) -> Option<&ProcessTarget> {
        self.helpers.iter().find(|h| h.role == "substitution")
    }
}

/// Read a PID from a PID file, returning `None` if the file is missing or
/// unreadable. This is best-effort: observability must not fail VM start.
pub fn read_pid_file(path: &std::path::Path) -> Option<u32> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Build an observability target from VM start configuration.
///
/// This is best-effort: PID files may not exist yet when this is called
/// (the VMM has not booted, helpers may not be spawned). Callers should
/// update PIDs later via `VmObservabilityTarget` mutation and
/// `runtime_meta::update_observability_target`.
pub fn build_from_start_config(
    kind: BackendKind,
    start_config: &mvm_core::vm_backend::VmStartConfig,
) -> VmObservabilityTarget {
    let name = &start_config.name;
    let state_dir = mvm_core::config::vm_state_dir(name);
    let socket_dir = mvm_core::config::vm_socket_dir_at(&state_dir);

    let (vmm_process_name, vmm_pid_file, runs_as_root) = match kind {
        BackendKind::Firecracker => ("firecracker", state_dir.join("fc.pid"), true),
        BackendKind::Libkrun => (
            "mvm-libkrun-supervisor",
            mvm_core::config::vm_libkrun_pid(name),
            false,
        ),
        BackendKind::Hvf | BackendKind::AppleContainer => {
            ("mvm-hvf-supervisor", state_dir.join("hvf.pid"), false)
        }
        BackendKind::Qemu => ("qemu-system-", state_dir.join("qemu.pid"), false),
        BackendKind::Mock | BackendKind::Wasm | BackendKind::WebLinux => {
            ("", state_dir.join("noop.pid"), false)
        }
    };

    let substitution_socket = mvm_core::config::vm_network_endpoint_socket(name);

    let plan_id = start_config
        .plan_json
        .as_deref()
        .and_then(|json| mvm_core::plan::plan_from_admitted_json(json).ok())
        .map(|plan| plan.plan_id.0);

    let helpers = vec![ProcessTarget {
        role: "substitution".to_string(),
        process_name: "mvm-network-endpoint".to_string(),
        pid_file: state_dir.join(network_endpoint_spawn::SUBST_PID_FILE),
        pid: None,
    }];

    VmObservabilityTarget {
        backend_kind: format!("{kind:?}").to_lowercase(),
        state_dir: state_dir.clone(),
        socket_dir: socket_dir.clone(),
        tenant_id: start_config.tenant_id.clone(),
        plan_id,
        vmm: VmmTarget {
            process_name: vmm_process_name.to_string(),
            pid_file: vmm_pid_file,
            pid: None,
            runs_as_root,
        },
        helpers,
        vsock: VsockTarget {
            guest_cid: None,
            socket_dir,
        },
        network: NetworkTarget {
            substitution_socket,
        },
        cgroup_path: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::vm_backend::BackendKind;

    fn minimal_start_config(name: &str) -> mvm_core::vm_backend::VmStartConfig {
        mvm_core::vm_backend::VmStartConfig {
            name: name.to_string(),
            template_id: None,
            rootfs_path: "/tmp/rootfs.ext4".to_string(),
            virtiofs_root: None,
            kernel_path: None,
            initrd_path: None,
            verity_path: None,
            roothash: None,
            runtime_overlay_path: None,
            runtime_overlay_verity_path: None,
            runtime_overlay_roothash: None,
            runtime_overlay_version: None,
            runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy::RootfsOnly,
            revision_hash: "abc".to_string(),
            flake_ref: "test".to_string(),
            profile: None,
            cpus: 1,
            cpu_grant: None,
            memory_mib: 256,
            mem_initial_mib: None,
            ports: Vec::new(),
            volumes: Vec::new(),
            extensions: Vec::new(),
            extension_plan_id: None,
            service_proxies: Vec::new(),
            config_files: Vec::new(),
            secret_files: Vec::new(),
            runner_dir: None,
            tenant_id: Some("tenant-1".to_string()),
            plan_json: None,
            bundle_json: None,
            warm_pool_size: 0,
            network_policy: mvm_core::policy::network_policy::NetworkPolicy::deny_all(),
            dev_console: false,
        }
    }

    #[test]
    fn build_target_for_libkrun_includes_substitution_and_vmm() {
        let config = minimal_start_config("obs-test-1");
        let target = build_from_start_config(BackendKind::Libkrun, &config);

        assert_eq!(target.backend_kind, "libkrun");
        assert_eq!(target.vmm.process_name, "mvm-libkrun-supervisor");
        assert!(target.helpers.iter().any(|h| h.role == "substitution"));
    }

    #[test]
    fn build_target_for_firecracker_marks_root() {
        let config = minimal_start_config("obs-test-2");
        let target = build_from_start_config(BackendKind::Firecracker, &config);

        assert_eq!(target.backend_kind, "firecracker");
        assert!(target.vmm.runs_as_root);
    }

    #[test]
    fn read_pid_file_returns_none_for_missing_file() {
        let path = std::path::Path::new("/nonexistent/path/pid");
        assert_eq!(read_pid_file(path), None);
    }
}
