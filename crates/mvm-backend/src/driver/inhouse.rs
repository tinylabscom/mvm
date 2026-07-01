//! `InHouseDriver` — the `VmmDriver` for the first-party VMM (HVF on macOS, KVM
//! on Linux via the shared `vmm` device model). Identity and capabilities
//! delegate to the proven `HvfBackend`; the boot path lands with the egress
//! gate-relocation increment, so `boot` fails closed until then.

use anyhow::Result;
use mvm_core::vm_backend::{SnapshotCapability, VmBackend, VmCapabilities};

use crate::driver::{RunningVm, VmmDriver, VmmSpec};
use crate::hvf_backend::HvfBackend;

/// The first-party VMM driver: pure VMM mechanics, no policy and no admission.
/// It boots what a `VmmSpec` describes and relays the guest's egress port to the
/// host-side bridge; the claim-10 gate and substitution live in that bridge, not
/// here.
pub struct InHouseDriver {
    backend: HvfBackend,
}

impl InHouseDriver {
    pub fn new() -> Self {
        Self {
            backend: HvfBackend,
        }
    }
}

impl Default for InHouseDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl VmmDriver for InHouseDriver {
    fn name(&self) -> &str {
        self.backend.name()
    }

    fn is_available(&self) -> Result<bool> {
        self.backend.is_available()
    }

    fn capabilities(&self) -> VmCapabilities {
        self.backend.capabilities()
    }

    fn snapshot_capability(&self) -> SnapshotCapability {
        self.backend.snapshot_capability()
    }

    fn boot(&self, _spec: &VmmSpec) -> Result<Box<dyn RunningVm>> {
        // The boot path maps the VmmSpec to a policy-free supervisor config,
        // spawns the per-VM supervisor, and relays the guest's egress port to the
        // host-side bridge (claim-10 gate + substitution). That relocation — the
        // gate moving out of the supervisor into the bridge — is the next
        // increment; until it is wired and live-verified, boot fails closed
        // rather than launch a path whose egress enforcement has moved but is not
        // yet proven.
        anyhow::bail!(
            "in-house VmmDriver boot is not yet wired: the egress gate relocation \
             (the supervisor becomes a relay to the host bridge) is pending live verification"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{ConsoleCapture, KernelImage, VmmSpec};

    fn minimal_spec() -> VmmSpec {
        VmmSpec {
            name: "w".into(),
            kernel: KernelImage::Bundled,
            cmdline: String::new(),
            vcpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            blocks: vec![],
            vsock: vec![],
            console: ConsoleCapture {
                log_path: "/tmp/console.log".into(),
            },
        }
    }

    #[test]
    fn identity_and_capabilities_delegate_to_the_hvf_backend() {
        let d = InHouseDriver::new();
        assert_eq!(d.name(), "hvf");
        assert!(d.capabilities().vsock);
        assert_eq!(d.snapshot_capability(), SnapshotCapability::Unsupported);
    }

    #[test]
    fn boot_fails_closed_until_the_gate_relocation_is_wired() {
        let result = InHouseDriver::new().boot(&minimal_spec());
        assert!(
            result.is_err(),
            "boot must fail closed before the gate relocation is wired"
        );
        let err = result.err().unwrap().to_string();
        assert!(err.contains("not yet wired"), "unexpected error: {err}");
    }
}
