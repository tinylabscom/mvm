use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for a VM managed by a backend.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VmId(pub String);

impl fmt::Display for VmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for VmId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for VmId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Runtime status of a VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmStatus {
    /// VM exists but is not running.
    Stopped,
    /// VM is booting / initializing.
    Starting,
    /// VM is running and accepting work.
    Running,
    /// VM vCPUs are paused (Firecracker warm state).
    Paused,
    /// VM is in an error state.
    Failed { reason: String },
}

/// Capabilities that a backend may or may not support.
///
/// Used by consumers to check what operations are available before
/// attempting them. For example, WASM backends won't support snapshots.
#[derive(Debug, Clone, Default)]
pub struct VmCapabilities {
    /// Can pause/resume vCPUs (Firecracker: yes, WASM: no).
    pub pause_resume: bool,
    /// Can create/restore memory snapshots (Firecracker: yes, Docker: checkpoints, WASM: no).
    pub snapshots: bool,
    /// Supports vsock guest communication (Firecracker: yes, others: typically no).
    pub vsock: bool,
    /// Supports TAP-based networking (Firecracker/Docker: yes, WASM: no).
    pub tap_networking: bool,
}

/// Summary info for a managed VM, returned by [`VmBackend::list`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmInfo {
    /// Backend-assigned VM identifier.
    pub id: VmId,
    /// Human-readable name.
    pub name: String,
    /// Current status.
    pub status: VmStatus,
    /// Guest IP address, if networking is configured.
    pub guest_ip: Option<String>,
    /// Number of vCPUs.
    pub cpus: u32,
    /// Memory in MiB.
    pub memory_mib: u32,
}

/// Backend-agnostic VM lifecycle trait.
///
/// Defines the minimal interface for starting, stopping, inspecting, and
/// listing VMs. Each backend provides its own configuration type via the
/// associated [`Config`](VmBackend::Config) type.
///
/// This trait lives in `mvm-core` so it has no runtime dependencies.
/// Implementations live in `mvm-runtime` (Firecracker) or future crates
/// (Docker, WASM).
///
/// # Examples
///
/// ```ignore
/// use mvm_core::vm_backend::{VmBackend, VmId};
///
/// fn run_vm(backend: &impl VmBackend<Config = MyConfig>, config: &MyConfig) -> anyhow::Result<()> {
///     let id = backend.start(config)?;
///     println!("Started VM: {}", id);
///     backend.stop(&id)?;
///     Ok(())
/// }
/// ```
pub trait VmBackend: Send + Sync {
    /// Backend-specific VM configuration (kernel paths, image name, module path, etc.).
    type Config: Send + Sync;

    /// Human-readable backend name (e.g., "firecracker", "docker", "wasm").
    fn name(&self) -> &str;

    /// Capabilities supported by this backend.
    fn capabilities(&self) -> VmCapabilities;

    /// Start a new VM from the given configuration.
    ///
    /// Returns the [`VmId`] assigned to the running VM.
    fn start(&self, config: &Self::Config) -> Result<VmId>;

    /// Stop a running VM.
    fn stop(&self, id: &VmId) -> Result<()>;

    /// Stop all VMs managed by this backend.
    fn stop_all(&self) -> Result<()>;

    /// Query the status of a specific VM.
    fn status(&self, id: &VmId) -> Result<VmStatus>;

    /// List all VMs managed by this backend.
    fn list(&self) -> Result<Vec<VmInfo>>;

    /// Retrieve log output from a VM.
    ///
    /// `lines` controls how many recent lines to return.
    /// `hypervisor` selects hypervisor logs vs guest console logs.
    fn logs(&self, id: &VmId, lines: u32, hypervisor: bool) -> Result<String>;

    /// Check whether the backend runtime is installed and available.
    fn is_available(&self) -> Result<bool>;

    /// Install or download the backend runtime (if supported).
    fn install(&self) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_id_display() {
        let id = VmId("my-vm".to_string());
        assert_eq!(format!("{id}"), "my-vm");
    }

    #[test]
    fn test_vm_id_from_str() {
        let id: VmId = "test".into();
        assert_eq!(id.0, "test");
    }

    #[test]
    fn test_vm_id_from_string() {
        let id: VmId = String::from("test").into();
        assert_eq!(id.0, "test");
    }

    #[test]
    fn test_vm_id_serde_roundtrip() {
        let id = VmId("vm-001".to_string());
        let json = serde_json::to_string(&id).unwrap();
        let parsed: VmId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn test_vm_status_serde_roundtrip() {
        let statuses = vec![
            VmStatus::Stopped,
            VmStatus::Starting,
            VmStatus::Running,
            VmStatus::Paused,
            VmStatus::Failed {
                reason: "oom".to_string(),
            },
        ];
        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: VmStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, status);
        }
    }

    #[test]
    fn test_vm_capabilities_default() {
        let caps = VmCapabilities::default();
        assert!(!caps.pause_resume);
        assert!(!caps.snapshots);
        assert!(!caps.vsock);
        assert!(!caps.tap_networking);
    }

    #[test]
    fn test_vm_info_serde_roundtrip() {
        let info = VmInfo {
            id: VmId("vm-1".to_string()),
            name: "worker-1".to_string(),
            status: VmStatus::Running,
            guest_ip: Some("172.16.0.2".to_string()),
            cpus: 2,
            memory_mib: 512,
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: VmInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, info.id);
        assert_eq!(parsed.name, "worker-1");
        assert_eq!(parsed.cpus, 2);
        assert_eq!(parsed.memory_mib, 512);
        assert_eq!(parsed.guest_ip.as_deref(), Some("172.16.0.2"));
    }
}
