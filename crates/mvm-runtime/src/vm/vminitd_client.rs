//! vminitd gRPC client for Apple Container guest communication.
//!
//! Apple Containers run vminitd as PID 1, which provides a gRPC API over
//! vsock port 1024. This module provides a typed Rust interface for the
//! subset of the SandboxContext API needed by mvm:
//!
//! - **CreateProcess** + **StartProcess**: launch the mvm guest agent
//! - **WaitProcess**: wait for a process to exit
//! - **WriteFile**: inject config/secret files into the guest
//! - **Kill**: send signals to processes
//!
//! # Architecture
//!
//! ```text
//! Host (Rust)                    Guest (vminitd, PID 1)
//! ┌──────────────┐              ┌─────────────────────┐
//! │ VminitdClient │──vsock:1024──│ SandboxContext gRPC  │
//! │  .launch()    │              │  CreateProcess()     │
//! │  .write_file()│              │  WriteFile()         │
//! │  .kill()      │              │  Kill()              │
//! └──────────────┘              └─────────────────────┘
//! ```
//!
//! # Protocol
//!
//! The protobuf definition is at `proto/sandbox_context.proto` (from
//! Apple's containerization repo). The gRPC transport uses vsock,
//! not TCP — the client connects to CID of the container VM on port 1024.
//!
//! # Status
//!
//! This module defines the typed interface. The actual gRPC-over-vsock
//! transport will be implemented when the Apple Container backend
//! can fully boot a VM (requires vmnet entitlement).

use anyhow::Result;

/// Port that vminitd listens on inside the Apple Container VM.
pub const VMINITD_VSOCK_PORT: u32 = 1024;

/// Port that the mvm guest agent listens on (same as Firecracker).
pub const GUEST_AGENT_VSOCK_PORT: u32 = 52;

/// Configuration for launching a process inside an Apple Container via vminitd.
#[derive(Debug, Clone)]
pub struct ProcessConfig {
    /// Process ID (vminitd-scoped, not a PID).
    pub id: String,
    /// Path to the executable inside the guest.
    pub path: String,
    /// Command-line arguments.
    pub args: Vec<String>,
    /// Environment variables (KEY=VALUE).
    pub env: Vec<String>,
    /// Working directory.
    pub cwd: String,
}

/// Client for communicating with vminitd inside an Apple Container.
///
/// vminitd is PID 1 in every Apple Container VM and provides a gRPC
/// API over vsock port 1024. This client wraps the subset of the
/// SandboxContext API that mvm needs.
pub struct VminitdClient {
    /// Container ID (used for process scoping).
    container_id: String,
}

impl VminitdClient {
    /// Create a new client for a specific container.
    pub fn new(container_id: &str) -> Self {
        Self {
            container_id: container_id.to_string(),
        }
    }

    /// Launch the mvm guest agent inside the container.
    ///
    /// Uses CreateProcess + StartProcess to start the guest agent binary,
    /// which then listens on vsock port 52 for health checks and
    /// integration probes (same protocol as Firecracker).
    pub fn launch_guest_agent(&self) -> Result<()> {
        let _config = ProcessConfig {
            id: format!("{}-guest-agent", self.container_id),
            path: "/usr/local/bin/mvm-guest-agent".to_string(),
            args: vec![],
            env: vec![format!("MVM_VSOCK_PORT={}", GUEST_AGENT_VSOCK_PORT)],
            cwd: "/".to_string(),
        };

        // TODO: Connect to vminitd via vsock:1024 and call:
        //   1. CreateProcess(id, configuration: ProcessConfig)
        //   2. StartProcess(id)
        // The gRPC-over-vsock transport needs the container to be
        // running first (requires vmnet entitlement for networking).
        anyhow::bail!(
            "vminitd gRPC client not yet connected — \
             requires running Apple Container with vmnet entitlement"
        )
    }

    /// Write a file into the guest filesystem via vminitd.
    ///
    /// Used to inject config files and secrets before starting the
    /// guest agent or application.
    pub fn write_file(&self, path: &str, data: &[u8], mode: u32) -> Result<()> {
        let _ = (path, data, mode, &self.container_id);
        anyhow::bail!(
            "vminitd WriteFile not yet connected — \
             requires running Apple Container"
        )
    }

    /// Send a signal to a process by PID.
    pub fn kill(&self, pid: i32, signal: i32) -> Result<()> {
        let _ = (pid, signal, &self.container_id);
        anyhow::bail!(
            "vminitd Kill not yet connected — \
             requires running Apple Container"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vminitd_client_creation() {
        let client = VminitdClient::new("test-container");
        assert_eq!(client.container_id, "test-container");
    }

    #[test]
    fn test_process_config() {
        let config = ProcessConfig {
            id: "agent-1".to_string(),
            path: "/usr/local/bin/mvm-guest-agent".to_string(),
            args: vec!["--port".to_string(), "52".to_string()],
            env: vec!["MVM_VSOCK_PORT=52".to_string()],
            cwd: "/".to_string(),
        };
        assert_eq!(config.id, "agent-1");
        assert_eq!(config.args.len(), 2);
    }

    #[test]
    fn test_vsock_port_constants() {
        assert_eq!(VMINITD_VSOCK_PORT, 1024);
        assert_eq!(GUEST_AGENT_VSOCK_PORT, 52);
    }
}
