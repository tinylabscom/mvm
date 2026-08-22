//! Browser-hosted WebLinux backend — native stub.
//!
//! The real `WebLinuxBackend` runs a Nix-built Linux kernel under
//! QEMU-Wasm inside a browser Worker. On a native host
//! (Linux/macOS CLI builds) there is no browser sandbox, no Worker, and
//! no Emscripten-compiled QEMU-Wasm engine, so this module provides a
//! constructible, side-effect-free stub that fails closed the moment a
//! lifecycle operation is invoked.
//!
//! The stub is intentionally selectable via `--hypervisor web-linux` /
//! `MVM_BACKEND=web-linux` so the catalog and CLI help surfaces can list
//! it, but `AnyBackend::auto_select` never returns it and the native
//! `as_workload_backend()` gate refuses to admit an untrusted workload
//! through it. A future browser build of `mvm-runtime` will replace this
//! stub with a real `WebLinuxBackend` that boots a kernel over a
//! MessagePort/Worker channel.

use anyhow::Result;
use mvm_contract::protocol::vm_backend::{
    AttestationTier, BackendCapabilityDimensions, BackendSecurityProfile, ClaimStatus,
    CpuExecution, GuestEnvironment, IsolationBoundary, LayerCoverage, LifecycleScope,
    SnapshotCapability,
};
use mvm_core::vm_backend::{
    BackendKind, ResourceControls, StartMode, VmBackend, VmCapabilities, VmExitStatus, VmId,
    VmInfo, VmStartConfig, VmStatus,
};
use thiserror::Error;

/// Typed, fail-closed errors for the native WebLinux stub.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WebLinuxBackendError {
    /// The WebLinux backend was selected on a native host. It only runs in a
    /// browser WebAssembly environment.
    #[error(
        "web-linux is a browser-only backend — it runs in a WebAssembly browser environment; \
         on native hosts select a real microVM backend (firecracker, libkrun, hvf, qemu)"
    )]
    NativeUnavailable,
}

/// Native stub for the browser-hosted WebLinux backend.
///
/// Construction is pure: no I/O, no engine init. Every lifecycle method
/// returns [`WebLinuxBackendError::NativeUnavailable`] so the backend can be
/// registered in the catalog without making native builds depend on
/// browser/QEMU-Wasm/Emscripten artifacts.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WebLinuxBackend;

impl WebLinuxBackend {
    /// Construct the stub.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    fn unavailable<T>(&self) -> Result<T> {
        Err(WebLinuxBackendError::NativeUnavailable.into())
    }
}

impl VmBackend for WebLinuxBackend {
    fn name(&self) -> &str {
        "web-linux"
    }

    fn kind(&self) -> BackendKind {
        BackendKind::WebLinux
    }

    fn capabilities(&self) -> VmCapabilities {
        VmCapabilities {
            // The real browser backend boots a Linux kernel; the native stub
            // cannot, so every operation that would exercise these fails
            // closed. The capability matrix still advertises the browser
            // identity honestly: no host routable NIC, no snapshots, no
            // standby pool, no host-enforced resource controls.
            no_routable_guest_nic: true,
            snapshot_capability: SnapshotCapability::Unsupported,
            standby_pool: false,
            resource_controls: ResourceControls::for_backend(BackendKind::WebLinux),
            capability_dimensions: BackendCapabilityDimensions {
                guest_environment: GuestEnvironment::Linux,
                cpu_execution: CpuExecution::SoftwareEmulated,
                isolation_boundary: IsolationBoundary::BrowserSandbox,
                lifecycle_scope: LifecycleScope::Document,
                attestation_tier: AttestationTier::None,
            },
            ..VmCapabilities::default()
        }
    }

    fn start_with_mode(&self, _config: &VmStartConfig, _mode: StartMode) -> Result<VmId> {
        self.unavailable()
    }

    fn wait(&self, _id: &VmId) -> Result<VmExitStatus> {
        self.unavailable()
    }

    fn stop(&self, _id: &VmId) -> Result<()> {
        self.unavailable()
    }

    fn stop_all(&self) -> Result<()> {
        self.unavailable()
    }

    fn pause(&self, _id: &VmId) -> Result<()> {
        self.unavailable()
    }

    fn resume(&self, _id: &VmId) -> Result<()> {
        self.unavailable()
    }

    fn status(&self, _id: &VmId) -> Result<VmStatus> {
        self.unavailable()
    }

    fn list(&self) -> Result<Vec<VmInfo>> {
        self.unavailable()
    }

    fn logs(&self, _id: &VmId, _lines: u32, _hypervisor: bool) -> Result<String> {
        self.unavailable()
    }

    fn is_available(&self) -> Result<bool> {
        // The native stub is never available; a browser build would probe the
        // Worker/QEMU-Wasm engine instead.
        Ok(false)
    }

    fn install(&self) -> Result<()> {
        self.unavailable()
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        BackendSecurityProfile {
            claims: [ClaimStatus::DoesNotHold; 7],
            layer_coverage: LayerCoverage::default(),
            tier: "Tier3-fallback",
            notes: &[
                "Browser-hosted WebLinux backend (QEMU-Wasm + Nix-built Linux kernel).",
                "Runs only inside a WebAssembly browser environment; the native stub \
                 is selectable for catalog/help parity but cannot boot a VM.",
                "Claim-free software-emulation tier; opt-in only; never auto-selected.",
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::vm_backend::VmBackend;

    #[test]
    fn kind_is_weblinux() {
        let backend = WebLinuxBackend::new();
        assert_eq!(backend.kind(), BackendKind::WebLinux);
        assert_eq!(backend.name(), "web-linux");
    }

    #[test]
    fn capabilities_declare_linux_browser_identity() {
        let caps = WebLinuxBackend::new().capabilities();
        assert!(caps.no_routable_guest_nic);
        assert!(!caps.standby_pool);
        assert_eq!(
            caps.capability_dimensions.guest_environment,
            GuestEnvironment::Linux
        );
        assert_eq!(
            caps.capability_dimensions.cpu_execution,
            CpuExecution::SoftwareEmulated
        );
        assert_eq!(
            caps.capability_dimensions.isolation_boundary,
            IsolationBoundary::BrowserSandbox
        );
        assert_eq!(
            caps.capability_dimensions.lifecycle_scope,
            LifecycleScope::Document
        );
        assert_eq!(
            caps.capability_dimensions.attestation_tier,
            AttestationTier::None
        );
    }

    #[test]
    fn start_fails_closed_on_native_host() {
        let backend = WebLinuxBackend::new();
        let err = backend
            .start(&VmStartConfig::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("browser-only"), "unexpected error: {err}");
    }

    #[test]
    fn is_available_is_false_on_native_host() {
        assert!(!WebLinuxBackend::new().is_available().unwrap());
    }
}
