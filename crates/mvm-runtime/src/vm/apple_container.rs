//! Apple Container backend for macOS 26+.
//!
//! Uses Apple's Containerization framework to run Linux containers in
//! lightweight VMs with sub-second startup. Each container gets its own
//! VM with dedicated networking (vmnet) and vsock for guest communication.
//!
//! The actual Containerization framework calls are behind a Swift FFI bridge
//! (`mvm-apple-container` crate). This module provides the `VmBackend`
//! implementation that translates `VmStartConfig` into container operations.
//!
//! # Platform Requirements
//!
//! - macOS 26+ on Apple Silicon
//! - Containerization framework available via Xcode 26+
//!
//! # Architecture
//!
//! ```text
//! AppleContainerBackend (this module)
//!   └── swift-bridge FFI (future: mvm-apple-container crate)
//!         └── Containerization.framework
//!               ├── ContainerManager (lifecycle)
//!               ├── LinuxContainer (per-VM)
//!               └── vminitd (PID 1, gRPC over vsock:1024)
//! ```

use anyhow::Result;
use mvm_core::vm_backend::{
    GuestChannelInfo, VmBackend, VmCapabilities, VmId, VmInfo, VmNetworkInfo, VmStartConfig,
    VmStatus,
};

use crate::ui;

/// Apple Container backend using macOS Containerization framework.
///
/// Currently a stub implementation — the Swift FFI bridge will be
/// connected when macOS 26 is available. All lifecycle methods return
/// appropriate errors until the bridge is wired up.
pub struct AppleContainerBackend;

impl AppleContainerBackend {
    /// Check whether the Apple Containerization framework is available
    /// at runtime (macOS 26+ on Apple Silicon).
    ///
    /// Uses the Swift FFI bridge when available, falls back to platform
    /// detection otherwise.
    pub fn is_platform_available() -> bool {
        // Try the Swift bridge first (most accurate — checks actual framework)
        if mvm_apple_container::is_available() {
            return true;
        }
        // Fall back to platform detection (works without Swift bridge)
        mvm_core::platform::current().has_apple_containers()
    }
}

impl VmBackend for AppleContainerBackend {
    fn name(&self) -> &str {
        "apple-container"
    }

    fn capabilities(&self) -> VmCapabilities {
        VmCapabilities {
            pause_resume: false,
            snapshots: false,
            vsock: true,
            tap_networking: false,
        }
    }

    fn start(&self, config: &VmStartConfig) -> Result<VmId> {
        if !Self::is_platform_available() {
            anyhow::bail!(
                "Apple Containers require macOS 26+ on Apple Silicon.\n\
                 Use '--hypervisor firecracker' or run on a supported platform."
            );
        }

        let kernel_path = config.kernel_path.as_deref().unwrap_or_default();
        if kernel_path.is_empty() {
            anyhow::bail!(
                "Apple Container backend requires a kernel path.\n\
                 Build with 'mvmctl build --flake .' first."
            );
        }

        ui::info(&format!(
            "Starting Apple Container '{}' (cpus={}, mem={}MiB)...",
            config.name, config.cpus, config.memory_mib
        ));

        mvm_apple_container::start(
            &config.name,
            kernel_path,
            &config.rootfs_path,
            config.cpus,
            config.memory_mib as u64,
        )
        .map_err(|e| anyhow::anyhow!("Apple Container start failed: {e}"))?;

        ui::success(&format!("Apple Container '{}' started.", config.name));
        Ok(VmId(config.name.clone()))
    }

    fn stop(&self, id: &VmId) -> Result<()> {
        mvm_apple_container::stop(&id.0)
            .map_err(|e| anyhow::anyhow!("Apple Container stop failed: {e}"))
    }

    fn stop_all(&self) -> Result<()> {
        let ids = mvm_apple_container::list_ids();
        for id in &ids {
            if let Err(e) = mvm_apple_container::stop(id) {
                tracing::warn!("Failed to stop container '{id}': {e}");
            }
        }
        Ok(())
    }

    fn status(&self, id: &VmId) -> Result<VmStatus> {
        let ids = mvm_apple_container::list_ids();
        if ids.contains(&id.0) {
            Ok(VmStatus::Running)
        } else {
            Ok(VmStatus::Stopped)
        }
    }

    fn list(&self) -> Result<Vec<VmInfo>> {
        let ids = mvm_apple_container::list_ids();
        Ok(ids
            .into_iter()
            .map(|id| VmInfo {
                id: VmId(id.clone()),
                name: id,
                status: VmStatus::Running,
                guest_ip: None,
                cpus: 0,
                memory_mib: 0,
                profile: None,
                revision: None,
                flake_ref: None,
            })
            .collect())
    }

    fn logs(&self, id: &VmId, _lines: u32, _hypervisor: bool) -> Result<String> {
        anyhow::bail!("Apple Container logs not yet implemented for VM '{}'", id.0)
    }

    fn is_available(&self) -> Result<bool> {
        Ok(Self::is_platform_available())
    }

    fn install(&self) -> Result<()> {
        ui::info(
            "Apple Containers are built into macOS 26+. No separate installation needed.\n\
             Ensure you are running macOS 26 or later on Apple Silicon.",
        );
        Ok(())
    }

    fn network_info(&self, id: &VmId) -> Result<VmNetworkInfo> {
        // Apple Containers use vmnet with 192.168.64.0/24 subnet.
        // The actual IP is assigned dynamically by vmnet.
        anyhow::bail!(
            "Apple Container network info not yet available for VM '{}'",
            id.0
        )
    }

    fn guest_channel_info(&self, _id: &VmId) -> Result<GuestChannelInfo> {
        // Apple VZ backend uses vsock directly (VZVirtioSocketDevice).
        // The guest agent listens on port 52, same as Firecracker.
        Ok(GuestChannelInfo::Vsock {
            cid: 3, // standard guest CID
            port: mvm_apple_container::GUEST_AGENT_PORT,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apple_container_backend_name() {
        let backend = AppleContainerBackend;
        assert_eq!(backend.name(), "apple-container");
    }

    #[test]
    fn test_apple_container_capabilities() {
        let backend = AppleContainerBackend;
        let caps = backend.capabilities();
        assert!(!caps.pause_resume);
        assert!(!caps.snapshots);
        assert!(caps.vsock);
        assert!(!caps.tap_networking);
    }

    #[test]
    fn test_apple_container_list_returns_empty() {
        let backend = AppleContainerBackend;
        let vms = backend.list().unwrap();
        assert!(vms.is_empty());
    }

    #[test]
    fn test_apple_container_stop_all_succeeds() {
        let backend = AppleContainerBackend;
        assert!(backend.stop_all().is_ok());
    }

    #[test]
    fn test_apple_container_status_returns_stopped() {
        let backend = AppleContainerBackend;
        let status = backend.status(&VmId("test".into())).unwrap();
        assert_eq!(status, VmStatus::Stopped);
    }
}
