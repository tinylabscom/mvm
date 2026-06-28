//! The `Machine` product abstraction.
//!
//! One library type the CLI, mvmd, and the SDKs all build a workload from,
//! independent of which backend runs it. A `MachineBuilder` validates the
//! requested shape into a `Machine`; the machine derives the
//! `RequiredCapabilities` the run needs and fails closed against a backend
//! that cannot serve them, rather than silently degrading onto a weaker one.
//!
//! Boot / exec / shell wiring lands on top of this seam in later work; this
//! module is the construction + capability-gate backbone.

use mvm_backend::AnyBackend;
use mvm_backend::selection::SelectionError;
use mvm_core::vm_backend::{RequiredCapabilities, VmCapabilities};

/// How a machine reaches the network. Closed by default: a machine gets no
/// guest NIC, and reaches nothing until networking is explicitly requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkMode {
    /// No guest NIC, no broker — the workload cannot reach the network.
    #[default]
    None,
    /// No guest NIC; egress and ingress are mediated by host brokers over
    /// vsock. Endpoint access is still gated by policy.
    HostVsockProxy,
}

const DEFAULT_CPUS: u32 = 1;
const DEFAULT_MEMORY_MIB: u64 = 512;

/// A machine could not be built or matched to a backend.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MachineError {
    #[error("a machine requires an image (set .image(...))")]
    MissingImage,
}

/// A backend cannot serve a machine because it lacks required capabilities.
/// Carries the named shortfall so the caller gets a recovery action instead
/// of a silent degrade onto a weaker backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityError {
    pub missing: Vec<&'static str>,
}

impl std::fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "backend lacks required capabilities: {}",
            self.missing.join(", ")
        )
    }
}

impl std::error::Error for CapabilityError {}

/// Builder for a [`Machine`]. The single construction path the CLI, mvmd, and
/// the SDKs share.
#[derive(Debug, Clone, Default)]
pub struct MachineBuilder {
    image: Option<String>,
    cpus: Option<u32>,
    memory_mib: Option<u64>,
    network: NetworkMode,
    pty: bool,
}

impl MachineBuilder {
    /// The image to boot (OCI reference, Nix flake/template output, etc.).
    pub fn image(mut self, image: impl Into<String>) -> Self {
        self.image = Some(image.into());
        self
    }

    pub fn cpus(mut self, cpus: u32) -> Self {
        self.cpus = Some(cpus);
        self
    }

    pub fn memory_mib(mut self, mib: u64) -> Self {
        self.memory_mib = Some(mib);
        self
    }

    /// Networking mode. Defaults to [`NetworkMode::None`] (no guest NIC, no
    /// reachable network).
    pub fn network(mut self, mode: NetworkMode) -> Self {
        self.network = mode;
        self
    }

    /// Request an interactive PTY (shell attach). Requires a backend that can
    /// carry a PTY exec session.
    pub fn pty(mut self, pty: bool) -> Self {
        self.pty = pty;
        self
    }

    /// Validate the requested shape into a [`Machine`].
    pub fn build(self) -> Result<Machine, MachineError> {
        let image = self.image.ok_or(MachineError::MissingImage)?;
        Ok(Machine {
            spec: MachineSpec {
                image,
                cpus: self.cpus.unwrap_or(DEFAULT_CPUS),
                memory_mib: self.memory_mib.unwrap_or(DEFAULT_MEMORY_MIB),
                network: self.network,
                pty: self.pty,
            },
        })
    }
}

/// A validated machine specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineSpec {
    pub image: String,
    pub cpus: u32,
    pub memory_mib: u64,
    pub network: NetworkMode,
    pub pty: bool,
}

/// A workload machine. Construct via [`Machine::builder`]. Boot / exec / shell
/// are layered on this handle in later work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Machine {
    spec: MachineSpec,
}

impl Machine {
    /// Start building a machine.
    pub fn builder() -> MachineBuilder {
        MachineBuilder::default()
    }

    /// The validated specification.
    pub fn spec(&self) -> &MachineSpec {
        &self.spec
    }

    /// The capabilities a backend must advertise to run this machine.
    pub fn required_capabilities(&self) -> RequiredCapabilities {
        let mut req = RequiredCapabilities {
            // All guest communication is over vsock.
            vsock: true,
            ..Default::default()
        };
        if self.spec.pty {
            req.pty_exec = true;
        }
        match self.spec.network {
            NetworkMode::None => {}
            NetworkMode::HostVsockProxy => {
                req.host_vsock_proxy = true;
                req.no_guest_nic = true;
            }
        }
        req
    }

    /// Fail closed if `caps` cannot serve this machine — returns the named
    /// capability shortfall rather than degrading onto a weaker backend.
    pub fn check_backend(&self, caps: &VmCapabilities) -> Result<(), CapabilityError> {
        let missing = caps.shortfall(&self.required_capabilities());
        if missing.is_empty() {
            Ok(())
        } else {
            Err(CapabilityError { missing })
        }
    }

    /// Choose the most-preferred backend whose capabilities can serve this
    /// machine, failing closed with the per-candidate shortfall if none can.
    /// This is selection only — it does not boot anything.
    pub fn select_backend(&self) -> Result<AnyBackend, SelectionError> {
        AnyBackend::select_capable(&self.required_capabilities())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_requires_an_image() {
        let err = Machine::builder().build().unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("image"),
            "error should name the missing image: {err}"
        );
    }

    #[test]
    fn defaults_are_closed_and_sensible() {
        let machine = Machine::builder().image("alpine").build().unwrap();
        let spec = machine.spec();
        assert_eq!(spec.network, NetworkMode::None, "default is no network");
        assert!(!spec.pty);
        assert_eq!(spec.cpus, DEFAULT_CPUS);
        assert_eq!(spec.memory_mib, DEFAULT_MEMORY_MIB);
    }

    #[test]
    fn required_capabilities_always_include_vsock() {
        let machine = Machine::builder().image("alpine").build().unwrap();
        assert!(machine.required_capabilities().vsock);
    }

    #[test]
    fn pty_machine_requires_pty_exec() {
        let machine = Machine::builder()
            .image("alpine")
            .pty(true)
            .build()
            .unwrap();
        assert!(machine.required_capabilities().pty_exec);
    }

    #[test]
    fn host_vsock_proxy_requires_broker_capabilities() {
        let machine = Machine::builder()
            .image("alpine")
            .network(NetworkMode::HostVsockProxy)
            .build()
            .unwrap();
        let req = machine.required_capabilities();
        assert!(req.host_vsock_proxy);
        assert!(req.no_guest_nic);
    }

    #[test]
    fn check_backend_fails_closed_with_named_shortfall() {
        // A pty machine needs vsock + pty_exec; a backend advertising neither
        // is rejected, and the error names both.
        let machine = Machine::builder()
            .image("alpine")
            .pty(true)
            .build()
            .unwrap();
        let err = machine
            .check_backend(&VmCapabilities::default())
            .unwrap_err();
        assert!(err.missing.contains(&"vsock"));
        assert!(err.missing.contains(&"pty_exec"));
    }

    #[test]
    fn check_backend_ok_for_capable_backend() {
        let machine = Machine::builder()
            .image("alpine")
            .pty(true)
            .build()
            .unwrap();
        let caps = VmCapabilities {
            vsock: true,
            pty_exec: true,
            ..VmCapabilities::default()
        };
        assert!(machine.check_backend(&caps).is_ok());
    }

    #[test]
    fn select_backend_picks_a_capable_backend_for_a_basic_machine() {
        let machine = Machine::builder().image("alpine").build().unwrap();
        let backend = machine.select_backend().unwrap();
        assert!(backend.capabilities().vsock);
    }

    #[test]
    fn select_backend_fails_closed_for_host_vsock_proxy_until_brokers_exist() {
        // No backend advertises the broker capabilities yet, so a brokered-net
        // machine is rejected rather than degraded onto a guest-NIC path.
        let machine = Machine::builder()
            .image("alpine")
            .network(NetworkMode::HostVsockProxy)
            .build()
            .unwrap();
        match machine.select_backend() {
            Ok(_) => panic!("host-vsock-proxy has no capable backend yet; must fail closed"),
            Err(err) => assert!(
                err.shortfalls
                    .iter()
                    .all(|(_, m)| m.contains(&"host_vsock_proxy"))
            ),
        }
    }
}
