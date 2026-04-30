use anyhow::Result;
use mvm_core::vm_backend::{VmBackend, VmCapabilities, VmId, VmInfo, VmStartConfig, VmStatus};

use super::apple_container::AppleContainerBackend;
use super::docker::DockerBackend;
use super::{firecracker, microvm, microvm_nix};
use crate::config::{PortMapping, VMS_DIR};
use crate::shell::run_in_vm_stdout;
use crate::vm::image::RuntimeVolume;
use crate::vm::microvm::{DriveFile, FlakeRunConfig};

pub use microvm_nix::{MicrovmNixBackend, MicrovmNixConfig};

/// Firecracker VM configuration for the [`VmBackend`] trait.
///
/// Wraps [`FlakeRunConfig`](microvm::FlakeRunConfig) which contains all
/// data needed for starting a Firecracker VM from Nix-built artifacts.
pub struct FirecrackerConfig {
    pub run_config: microvm::FlakeRunConfig,
}

impl FirecrackerConfig {
    /// Convert a backend-agnostic `VmStartConfig` into a Firecracker-specific
    /// `FlakeRunConfig`, allocating a network slot automatically.
    pub fn from_start_config(config: &VmStartConfig) -> Result<Self> {
        let slot = microvm::allocate_slot(&config.name)?;
        let run_config = FlakeRunConfig {
            name: config.name.clone(),
            slot,
            vmlinux_path: config.kernel_path.clone().unwrap_or_default(),
            initrd_path: config.initrd_path.clone(),
            rootfs_path: config.rootfs_path.clone(),
            verity_path: config.verity_path.clone(),
            roothash: config.roothash.clone(),
            revision_hash: config.revision_hash.clone(),
            flake_ref: config.flake_ref.clone(),
            profile: config.profile.clone(),
            cpus: config.cpus,
            memory: config.memory_mib,
            volumes: config
                .volumes
                .iter()
                .map(|v| RuntimeVolume {
                    host: v.host.clone(),
                    guest: v.guest.clone(),
                    size: v.size.clone(),
                    read_only: v.read_only,
                })
                .collect(),
            config_files: config
                .config_files
                .iter()
                .map(|f| DriveFile {
                    name: f.name.clone(),
                    content: f.content.clone(),
                    mode: f.mode,
                })
                .collect(),
            secret_files: config
                .secret_files
                .iter()
                .map(|f| DriveFile {
                    name: f.name.clone(),
                    content: f.content.clone(),
                    mode: f.mode,
                })
                .collect(),
            ports: config
                .ports
                .iter()
                .map(|p| PortMapping {
                    host: p.host,
                    guest: p.guest,
                })
                .collect(),
            network_policy: mvm_core::network_policy::NetworkPolicy::default(),
        };
        Ok(Self { run_config })
    }
}

/// Firecracker backend implementation.
///
/// Wraps the existing free functions in [`microvm`] and [`firecracker`]
/// behind the [`VmBackend`] trait. This is a thin adapter — all real
/// work is delegated to the existing implementation.
pub struct FirecrackerBackend;

impl VmBackend for FirecrackerBackend {
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

    fn start(&self, config: &VmStartConfig) -> Result<VmId> {
        let fc_config = FirecrackerConfig::from_start_config(config)?;
        microvm::run_from_build(&fc_config.run_config)?;
        Ok(VmId(fc_config.run_config.name.clone()))
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
                    ports: Vec::new(),
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
    AppleContainer(AppleContainerBackend),
    Docker(DockerBackend),
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
    /// Supported: `"firecracker"` (default), `"qemu"` (via microvm.nix),
    /// `"apple-container"` (macOS 26+). Unknown names fall back to Firecracker.
    pub fn from_hypervisor(name: &str) -> Self {
        match name {
            "apple-container" => Self::AppleContainer(AppleContainerBackend),
            "docker" => Self::Docker(DockerBackend),
            "qemu" => Self::MicrovmNix(MicrovmNixBackend),
            _ => Self::Firecracker(FirecrackerBackend),
        }
    }

    /// Select the best backend for the current platform.
    ///
    /// Priority:
    /// 1. Firecracker (if /dev/kvm available — fastest, production-grade)
    /// 2. Apple Container (macOS 26+ — sub-second dev startup)
    /// 3. Firecracker via Lima (macOS fallback)
    pub fn auto_select() -> Self {
        let plat = mvm_core::platform::current();

        // 1. KVM available → Firecracker directly (fastest — dev & production)
        if plat.has_kvm() {
            return Self::Firecracker(FirecrackerBackend);
        }

        // 2. macOS 26+ → Apple Virtualization.framework (sub-second dev)
        if plat.has_apple_containers() {
            return Self::AppleContainer(AppleContainerBackend);
        }

        // 3. Docker available → universal fallback (works on all platforms)
        if plat.has_docker() {
            return Self::Docker(DockerBackend);
        }

        // 4. Firecracker via Lima (legacy macOS fallback)
        Self::Firecracker(FirecrackerBackend)
    }

    /// Dispatch helper — returns a `&dyn VmBackend` for the inner backend.
    fn inner(&self) -> &dyn VmBackend {
        match self {
            Self::Firecracker(b) => b,
            Self::MicrovmNix(b) => b,
            Self::AppleContainer(b) => b,
            Self::Docker(b) => b,
        }
    }

    pub fn name(&self) -> &str {
        self.inner().name()
    }

    pub fn capabilities(&self) -> VmCapabilities {
        self.inner().capabilities()
    }

    /// Start a VM using the backend-agnostic config.
    ///
    /// Each backend converts `VmStartConfig` into its own internal
    /// configuration (e.g., Firecracker allocates a VmSlot and builds
    /// a `FlakeRunConfig`; Apple Container creates a LinuxContainer).
    pub fn start(&self, config: &VmStartConfig) -> Result<VmId> {
        self.inner().start(config)
    }

    /// Start a VM using a pre-built `FirecrackerConfig`.
    ///
    /// This is a convenience method for callers that already have a
    /// `FlakeRunConfig` (e.g., template snapshot restore). Prefer
    /// [`start`](Self::start) for new VMs.
    pub fn start_firecracker(&self, config: &FirecrackerConfig) -> Result<VmId> {
        match self {
            Self::Firecracker(_) => {
                microvm::run_from_build(&config.run_config)?;
                Ok(VmId(config.run_config.name.clone()))
            }
            _ => {
                anyhow::bail!(
                    "Cannot start Firecracker config with {} backend",
                    self.name()
                )
            }
        }
    }

    pub fn stop(&self, id: &VmId) -> Result<()> {
        self.inner().stop(id)
    }

    pub fn stop_all(&self) -> Result<()> {
        self.inner().stop_all()
    }

    pub fn status(&self, id: &VmId) -> Result<VmStatus> {
        self.inner().status(id)
    }

    pub fn list(&self) -> Result<Vec<VmInfo>> {
        self.inner().list()
    }

    pub fn logs(&self, id: &VmId, lines: u32, hypervisor: bool) -> Result<String> {
        self.inner().logs(id, lines, hypervisor)
    }

    pub fn is_available(&self) -> Result<bool> {
        self.inner().is_available()
    }

    pub fn install(&self) -> Result<()> {
        self.inner().install()
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

    #[test]
    fn test_any_backend_from_hypervisor_apple_container() {
        let backend = AnyBackend::from_hypervisor("apple-container");
        assert_eq!(backend.name(), "apple-container");
    }

    #[test]
    fn test_apple_container_via_any_backend_capabilities() {
        let backend = AnyBackend::from_hypervisor("apple-container");
        let caps = backend.capabilities();
        assert!(caps.vsock);
        assert!(!caps.snapshots);
        assert!(!caps.tap_networking);
        assert!(!caps.pause_resume);
    }

    #[test]
    fn test_apple_container_via_any_backend_list_empty() {
        // Isolate HOME so the persisted ~/.mvm/vms registry doesn't bleed
        // into this assertion when the developer's real dev VM is running.
        let temp = std::path::PathBuf::from(format!(
            "/tmp/mvmac-anybe-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&temp).expect("create temp HOME");
        let saved = std::env::var("HOME").ok();
        // SAFETY: list() is the only HOME consumer in this test; no other
        // threads in this test process race with it.
        unsafe { std::env::set_var("HOME", &temp) };

        let backend = AnyBackend::from_hypervisor("apple-container");
        let vms = backend.list().unwrap();
        assert!(vms.is_empty());

        unsafe {
            match saved {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn test_any_backend_from_hypervisor_docker() {
        let backend = AnyBackend::from_hypervisor("docker");
        assert_eq!(backend.name(), "docker");
    }

    #[test]
    fn test_docker_via_any_backend_capabilities() {
        let backend = AnyBackend::from_hypervisor("docker");
        let caps = backend.capabilities();
        assert!(caps.pause_resume);
        assert!(!caps.snapshots);
        assert!(!caps.vsock);
        assert!(!caps.tap_networking);
    }

    #[test]
    fn test_auto_select_returns_valid_backend() {
        let backend = AnyBackend::auto_select();
        let name = backend.name();
        assert!(
            name == "firecracker" || name == "apple-container" || name == "docker",
            "auto_select returned unexpected backend: {name}"
        );
    }
}
