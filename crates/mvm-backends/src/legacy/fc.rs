//! The legacy `VmBackend` shell for Firecracker.
//!
//! A thin adapter over the free functions in [`crate::fc`]; every call
//! delegates. Kept alongside the other legacy shells until `AnyBackend`
//! consumers finish migrating to the `VmmDriver` seam.

use anyhow::{Result, bail};

use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, ClaimStatus, LayerCoverage, SnapshotCapability, VmBackend,
    VmCapabilities, VmId, VmInfo, VmStartConfig, VmStatus,
};

use crate::fc;
use mvm_vmm::host::shell::run_in_vm_stdout;

/// Firecracker backend implementation.
///
/// Wraps the existing free functions in [`crate::fc`] and [`crate::fc`]
/// behind the [`VmBackend`] trait. This is a thin adapter — all real
/// work is delegated to the existing implementation.
pub struct FirecrackerBackend;

impl VmBackend for FirecrackerBackend {
    fn name(&self) -> &str {
        "firecracker"
    }

    fn kind(&self) -> BackendKind {
        BackendKind::Firecracker
    }

    fn capabilities(&self) -> VmCapabilities {
        // Firecracker ships a virtio-balloon device with PATCH-able
        // target via `/balloon`; the start path attaches it whenever
        // `VmStartConfig::mem_initial_mib` is `Some`. Capability is
        // advertised unconditionally so the host-side controller can
        // discover support before deciding to plumb a workload.
        VmCapabilities {
            pause_resume: true,
            snapshots: false,
            snapshot_capability: SnapshotCapability::Unsupported,
            standby_pool: false,
            vsock: true,
            tap_networking: false,
            no_routable_guest_nic: true,
            host_vsock_proxy: true,
            balloon: true,
            fs_quick_checkpoint: false,
            ..VmCapabilities::default()
        }
    }

    /// Not a start path. Booting a Firecracker workload goes through the
    /// `VmmDriver` seam — `FcDriver` under `WorkloadRunner` — which is what
    /// applies plan admission, the egress gate and the audit chain. This
    /// shell exists for the descriptive half of `VmBackend` (name, kind,
    /// availability, security profile, guest channel), and `AnyBackend`
    /// routes every real start to the runner, so nothing reaches here.
    ///
    /// Refusing loudly rather than silently succeeding: if a future caller
    /// does land on this, it must be routed to the runner, not quietly given
    /// a VM that skipped admission.
    fn start(&self, _config: &VmStartConfig) -> Result<VmId> {
        bail!(
            "the Firecracker VmBackend shell cannot start a workload; \
             route the start through the runner-backed backend so plan \
             admission and the egress gate apply"
        )
    }

    fn stop(&self, id: &VmId) -> Result<()> {
        fc::stop_vm(&id.0)
    }

    fn stop_all(&self) -> Result<()> {
        fc::stop_all_vms()
    }

    fn pause(&self, id: &VmId) -> Result<()> {
        fc::pause_vm(&id.0)
    }

    fn resume(&self, id: &VmId) -> Result<()> {
        fc::resume_vm(&id.0)
    }

    fn balloon_set_target(&self, id: &VmId, target_inflate_mib: u32) -> Result<()> {
        fc::balloon_set_target(&id.0, target_inflate_mib)
    }

    fn balloon_state(&self, id: &VmId) -> Result<mvm_core::vm_backend::BalloonState> {
        let inflated = fc::balloon_state(&id.0)?;
        // FC reports the inflation amount via /balloon; the cap is
        // tracked host-side in the VM's runtime metadata (RunInfo).
        // List the VM to recover its declared cap.
        let vms = fc::list_vms()?;
        let info = vms
            .into_iter()
            .find(|i| i.name.as_deref() == Some(&*id.0))
            .ok_or_else(|| anyhow::anyhow!("balloon_state: VM '{}' not found in list", id.0))?;
        let max_mib = info.memory;
        Ok(mvm_core::vm_backend::BalloonState {
            max_mib,
            inflated_mib: inflated,
            host_committed_mib: max_mib.saturating_sub(inflated),
        })
    }

    fn status(&self, id: &VmId) -> Result<VmStatus> {
        let vms = fc::list_vms()?;
        match vms.iter().find(|info| info.name.as_deref() == Some(&*id.0)) {
            Some(_) => Ok(VmStatus::Running),
            None => Ok(VmStatus::Stopped),
        }
    }

    fn list(&self) -> Result<Vec<VmInfo>> {
        let vms = fc::list_vms()?;
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
        let abs_vms = fc::abs_vms_dir();
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
        fc::host::is_installed()
    }

    fn install(&self) -> Result<()> {
        fc::host::install()
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        // Tier 1: full security posture. All seven CI-enforced claims
        // hold. Hardware isolation via KVM; verified boot via
        // dm-verity.
        BackendSecurityProfile {
            claims: [ClaimStatus::Holds; 7],
            layer_coverage: LayerCoverage::all_layers(),
            tier: "Tier 1",
            notes: &[
                "Full ADR-002 — all seven CI-enforced claims hold.",
                "Hardware isolation via KVM. Verified boot via dm-verity (W3).",
            ],
        }
    }
}
