use anyhow::Result;
use mvm_core::vm_backend::{VmBackend, VmCapabilities, VmId, VmInfo, VmStatus};

use super::{firecracker, microvm, microvm_nix};
use crate::config::VMS_DIR;
use crate::shell::run_in_vm_stdout;

pub use microvm_nix::{MicrovmNixBackend, MicrovmNixConfig};

/// Firecracker VM configuration for the [`VmBackend`] trait.
///
/// Wraps [`FlakeRunConfig`](microvm::FlakeRunConfig) which contains all
/// data needed for starting a Firecracker VM from Nix-built artifacts.
pub struct FirecrackerConfig {
    pub run_config: microvm::FlakeRunConfig,
}

/// Firecracker backend implementation.
///
/// Wraps the existing free functions in [`microvm`] and [`firecracker`]
/// behind the [`VmBackend`] trait. This is a thin adapter — all real
/// work is delegated to the existing implementation.
pub struct FirecrackerBackend;

impl VmBackend for FirecrackerBackend {
    type Config = FirecrackerConfig;

    fn name(&self) -> &str {
        "firecracker"
    }

    fn capabilities(&self) -> VmCapabilities {
        VmCapabilities {
            pause_resume: true,
            snapshots: true,
            vsock: true,
            tap_networking: true,
        }
    }

    fn start(&self, config: &Self::Config) -> Result<VmId> {
        microvm::run_from_build(&config.run_config)?;
        Ok(VmId(config.run_config.name.clone()))
    }

    fn stop(&self, id: &VmId) -> Result<()> {
        microvm::stop_vm(&id.0)
    }

    fn stop_all(&self) -> Result<()> {
        microvm::stop_all_vms()
    }

    fn status(&self, id: &VmId) -> Result<VmStatus> {
        let vms = microvm::list_vms()?;
        match vms.iter().find(|info| info.name.as_deref() == Some(&*id.0)) {
            Some(_) => Ok(VmStatus::Running),
            None => Ok(VmStatus::Stopped),
        }
    }

    fn list(&self) -> Result<Vec<VmInfo>> {
        let vms = microvm::list_vms()?;
        Ok(vms
            .into_iter()
            .filter_map(|info| {
                let name = info.name.clone()?;
                Some(VmInfo {
                    id: VmId(name.clone()),
                    name,
                    status: VmStatus::Running,
                    guest_ip: info.guest_ip,
                    cpus: info.cpus,
                    memory_mib: info.memory,
                    profile: info.profile,
                    revision: info.revision,
                    flake_ref: info.flake_ref,
                })
            })
            .collect())
    }

    fn logs(&self, id: &VmId, lines: u32, hypervisor: bool) -> Result<String> {
        let abs_vms = run_in_vm_stdout(&format!("echo {}", VMS_DIR))?;
        let abs_vms = abs_vms.trim();
        let filename = if hypervisor {
            "firecracker.log"
        } else {
            "console.log"
        };
        let log_file = format!("{}/{}/{}", abs_vms, id.0, filename);
        run_in_vm_stdout(&format!(
            "tail -n {} {} 2>/dev/null || true",
            lines, log_file
        ))
    }

    fn is_available(&self) -> Result<bool> {
        firecracker::is_installed()
    }

    fn install(&self) -> Result<()> {
        firecracker::install()
    }
}

/// Backend-agnostic dispatch enum.
///
/// Wraps concrete backends so CLI commands don't need to know which
/// backend is active. Each variant delegates to its inner implementation.
pub enum AnyBackend {
    Firecracker(FirecrackerBackend),
    MicrovmNix(MicrovmNixBackend),
}

impl AnyBackend {
    /// Create the default backend (Firecracker).
    pub fn default_backend() -> Self {
        Self::Firecracker(FirecrackerBackend)
    }

    /// Select backend based on whether the build output includes a
    /// microvm.nix runner script.
    pub fn from_build_output(has_runner: bool) -> Self {
        if has_runner {
            Self::MicrovmNix(MicrovmNixBackend)
        } else {
            Self::Firecracker(FirecrackerBackend)
        }
    }

    /// Select backend by hypervisor name.
    ///
    /// Currently supported: `"firecracker"` (default), `"qemu"` (via
    /// microvm.nix runner). Unknown names fall back to Firecracker.
    pub fn from_hypervisor(name: &str) -> Self {
        match name {
            "qemu" => Self::MicrovmNix(MicrovmNixBackend),
            _ => Self::Firecracker(FirecrackerBackend),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Firecracker(b) => b.name(),
            Self::MicrovmNix(b) => b.name(),
        }
    }

    pub fn capabilities(&self) -> VmCapabilities {
        match self {
            Self::Firecracker(b) => b.capabilities(),
            Self::MicrovmNix(b) => b.capabilities(),
        }
    }

    /// Start a VM using the Firecracker backend (manual API calls).
    pub fn start_firecracker(&self, config: &FirecrackerConfig) -> Result<VmId> {
        match self {
            Self::Firecracker(b) => b.start(config),
            Self::MicrovmNix(_) => {
                anyhow::bail!("Cannot start Firecracker config with microvm.nix backend")
            }
        }
    }

    /// Start a VM using the microvm.nix runner backend.
    pub fn start_microvm_nix(&self, config: &MicrovmNixConfig) -> Result<VmId> {
        match self {
            Self::MicrovmNix(b) => b.start(config),
            Self::Firecracker(_) => {
                anyhow::bail!("Cannot start microvm.nix config with Firecracker backend")
            }
        }
    }

    pub fn stop(&self, id: &VmId) -> Result<()> {
        match self {
            Self::Firecracker(b) => b.stop(id),
            Self::MicrovmNix(b) => b.stop(id),
        }
    }

    pub fn stop_all(&self) -> Result<()> {
        match self {
            Self::Firecracker(b) => b.stop_all(),
            Self::MicrovmNix(b) => b.stop_all(),
        }
    }

    pub fn status(&self, id: &VmId) -> Result<VmStatus> {
        match self {
            Self::Firecracker(b) => b.status(id),
            Self::MicrovmNix(b) => b.status(id),
        }
    }

    pub fn list(&self) -> Result<Vec<VmInfo>> {
        match self {
            Self::Firecracker(b) => b.list(),
            Self::MicrovmNix(b) => b.list(),
        }
    }

    pub fn logs(&self, id: &VmId, lines: u32, hypervisor: bool) -> Result<String> {
        match self {
            Self::Firecracker(b) => b.logs(id, lines, hypervisor),
            Self::MicrovmNix(b) => b.logs(id, lines, hypervisor),
        }
    }

    pub fn is_available(&self) -> Result<bool> {
        match self {
            Self::Firecracker(b) => b.is_available(),
            Self::MicrovmNix(b) => b.is_available(),
        }
    }

    pub fn install(&self) -> Result<()> {
        match self {
            Self::Firecracker(b) => b.install(),
            Self::MicrovmNix(b) => b.install(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firecracker_backend_name() {
        let backend = FirecrackerBackend;
        assert_eq!(backend.name(), "firecracker");
    }

    #[test]
    fn test_firecracker_capabilities() {
        let backend = FirecrackerBackend;
        let caps = backend.capabilities();
        assert!(caps.pause_resume);
        assert!(caps.snapshots);
        assert!(caps.vsock);
        assert!(caps.tap_networking);
    }

    #[test]
    fn test_microvm_nix_backend_name() {
        let backend = MicrovmNixBackend;
        assert_eq!(backend.name(), "microvm-nix");
    }

    #[test]
    fn test_microvm_nix_capabilities() {
        let backend = MicrovmNixBackend;
        let caps = backend.capabilities();
        assert!(!caps.pause_resume);
        assert!(!caps.snapshots);
        assert!(caps.vsock);
        assert!(caps.tap_networking);
    }

    #[test]
    fn test_any_backend_default_is_firecracker() {
        let backend = AnyBackend::default_backend();
        assert_eq!(backend.name(), "firecracker");
    }

    #[test]
    fn test_any_backend_from_build_output_no_runner() {
        let backend = AnyBackend::from_build_output(false);
        assert_eq!(backend.name(), "firecracker");
    }

    #[test]
    fn test_any_backend_from_build_output_with_runner() {
        let backend = AnyBackend::from_build_output(true);
        assert_eq!(backend.name(), "microvm-nix");
    }

    #[test]
    fn test_any_backend_from_hypervisor_firecracker() {
        let backend = AnyBackend::from_hypervisor("firecracker");
        assert_eq!(backend.name(), "firecracker");
    }

    #[test]
    fn test_any_backend_from_hypervisor_qemu() {
        let backend = AnyBackend::from_hypervisor("qemu");
        assert_eq!(backend.name(), "microvm-nix");
    }

    #[test]
    fn test_any_backend_from_hypervisor_unknown_defaults() {
        let backend = AnyBackend::from_hypervisor("unknown");
        assert_eq!(backend.name(), "firecracker");
    }

    #[test]
    fn test_any_backend_capabilities() {
        let backend = AnyBackend::default_backend();
        let caps = backend.capabilities();
        assert!(caps.vsock);
        assert!(caps.tap_networking);
    }
}
