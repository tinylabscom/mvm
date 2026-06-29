//! `HvfBackend` — `VmBackend` skeleton for the raw-HVF macOS path.
//!
//! Reports identity, capabilities, and availability (probed against
//! `Hypervisor.framework` itself), and exposes the lifecycle verbs as
//! not-yet-implemented. The guest-RAM-mapping + boot primitive that the
//! lifecycle will build on is proven in [`super::boot_smoke`]; wiring it into
//! `start`/`stop`/`status` (device model, vsock, console, snapshot) is the next
//! slice. Not yet registered in `AnyBackend` or backend selection.

use anyhow::Result;
use mvm_core::vm_backend::{VmBackend, VmCapabilities, VmId, VmInfo, VmStartConfig, VmStatus};

use crate::base::ui;

/// Raw HVF (`Hypervisor.framework`) backend. macOS / Apple-silicon only.
pub struct HvfBackend;

impl HvfBackend {
    fn not_implemented(verb: &str) -> anyhow::Error {
        anyhow::anyhow!("hvf backend {verb} is not yet implemented (Plan 214 Phase 11)")
    }
}

impl VmBackend for HvfBackend {
    fn name(&self) -> &str {
        "hvf"
    }

    fn capabilities(&self) -> VmCapabilities {
        // Skeleton: the boot primitive is proven but no VM lifecycle exists yet,
        // so every lifecycle-keyed capability reports honestly as unsupported.
        // These flip on as start/snapshot/vsock land on the primitive.
        VmCapabilities {
            pause_resume: false,
            snapshots: false,
            vsock: false,
            tap_networking: false,
            balloon: false,
            fs_quick_checkpoint: false,
        }
    }

    fn start(&self, _config: &VmStartConfig) -> Result<VmId> {
        Err(Self::not_implemented("start"))
    }

    fn stop(&self, _id: &VmId) -> Result<()> {
        Err(Self::not_implemented("stop"))
    }

    fn stop_all(&self) -> Result<()> {
        // No VMs are ever created yet, so there is nothing to stop.
        Ok(())
    }

    fn pause(&self, _id: &VmId) -> Result<()> {
        Err(Self::not_implemented("pause"))
    }

    fn resume(&self, _id: &VmId) -> Result<()> {
        Err(Self::not_implemented("resume"))
    }

    fn status(&self, _id: &VmId) -> Result<VmStatus> {
        Ok(VmStatus::Stopped)
    }

    fn list(&self) -> Result<Vec<VmInfo>> {
        Ok(Vec::new())
    }

    fn logs(&self, _id: &VmId, _lines: u32, _hypervisor: bool) -> Result<String> {
        Err(Self::not_implemented("logs"))
    }

    fn is_available(&self) -> Result<bool> {
        // True only when the platform supports HVF and this binary holds the
        // hypervisor entitlement — probed by creating + destroying a bare VM.
        Ok(super::probe_available())
    }

    fn install(&self) -> Result<()> {
        ui::info("Hypervisor.framework is built into macOS; no host install needed.");
        if !super::probe_available() {
            ui::info(
                "HVF probe failed — ensure the binary is codesigned with \
                 com.apple.security.hypervisor.",
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_as_hvf() {
        assert_eq!(HvfBackend.name(), "hvf");
    }

    #[test]
    fn skeleton_advertises_no_lifecycle_capabilities() {
        let c = HvfBackend.capabilities();
        assert!(!c.pause_resume);
        assert!(!c.snapshots);
        assert!(!c.vsock);
        assert!(!c.tap_networking);
        assert!(!c.balloon);
        assert!(!c.fs_quick_checkpoint);
    }

    #[test]
    fn lifecycle_verbs_fail_clearly_until_implemented() {
        let id = VmId("x".into());
        for e in [
            HvfBackend.start(&VmStartConfig::default()).err(),
            HvfBackend.stop(&id).err(),
            HvfBackend.pause(&id).err(),
            HvfBackend.resume(&id).err(),
            HvfBackend.logs(&id, 0, false).err(),
        ] {
            assert!(
                e.unwrap().to_string().contains("not yet implemented"),
                "lifecycle stub should say so"
            );
        }
    }

    #[test]
    fn no_vms_so_list_is_empty_and_stop_all_succeeds() {
        assert!(HvfBackend.list().unwrap().is_empty());
        assert!(HvfBackend.stop_all().is_ok());
        assert_eq!(
            HvfBackend.status(&VmId("x".into())).unwrap(),
            VmStatus::Stopped
        );
    }

    #[test]
    fn is_available_returns_a_verdict_without_panicking() {
        // Value depends on the entitlement (false under un-codesigned `cargo
        // test`); we only assert the probe runs cleanly.
        let _ = HvfBackend.is_available().unwrap();
    }
}
