//! Apple Containerization-framework backend — registered, honest skeleton.
//!
//! `AppleContainerBackend` is the selectable front door for running mvm
//! workloads inside Apple's Containerization-framework VMs: lightweight,
//! hardware-isolated Linux VMs whose kernel boot and guest PID 1 (`vminitd`,
//! serving gRPC on vsock port 1024) are owned by Apple's Swift-only
//! framework. Because the framework owns the boot path, the mvm initramfs
//! does not apply verbatim here — activation will ride `vminitd`'s existing
//! gRPC API instead, while the guest agent binary, the mount logic, the
//! uid-901 privilege drop, the `NotActivated` RPC gate, and the operational
//! RPC surface stay shared verbatim with every other backend.
//!
//! This is the skeleton stage of that backend: it is registered in the
//! catalog and selectable via `--hypervisor apple-container`, but no
//! Containerization-framework integration exists yet, so **every operation
//! that would touch a real VM fails closed** with a typed
//! [`AppleContainerError`] naming the milestone that provides it — mirroring
//! how [`crate::wasm_backend::WasmBackend`] surfaces "not available" at
//! first use rather than at construction. Construction itself does no I/O
//! and touches no framework state, so the catalog/dispatch machinery every
//! other backend goes through stays uniform.
//!
//! Honest reporting, not silent degradation: `capabilities()` advertises no
//! snapshot, no standby pool, and no warm start; `security_profile()`
//! reports every numbered claim as `DoesNotHold` until the boot path lands
//! and can actually enforce them; and the backend is opt-in only —
//! `AnyBackend::auto_select` never returns this kind. The trivially-true
//! answers (`stop`, `stop_all`, `list`, `status`) are honest because
//! `start` cannot succeed yet: nothing can be running.

use anyhow::Result;
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, ClaimStatus, LayerCoverage, SnapshotCapability, StartMode,
    VmBackend, VmCapabilities, VmExitStatus, VmId, VmInfo, VmStartConfig, VmStatus,
};
use thiserror::Error;

/// Typed, fail-closed errors for requests this backend cannot satisfy yet.
/// Every error names the operation that was refused and the milestone that
/// provides it, rather than silently falling back to another backend or
/// panicking — see the module docs.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AppleContainerError {
    /// The operation is part of the backend's design but has no
    /// implementation yet; `milestone` names the work that provides it.
    #[error("apple-container backend cannot {operation} yet — {milestone}")]
    NotImplemented {
        operation: &'static str,
        milestone: &'static str,
    },
}

/// Apple Containerization-framework backend skeleton. See the module docs
/// for the fail-closed contract and the opt-in/honest-reporting rules.
#[derive(Debug, Default, Clone)]
pub struct AppleContainerBackend;

impl AppleContainerBackend {
    /// Construct the backend skeleton. Side-effect free — no
    /// Containerization-framework symbol is touched and no VM state is read.
    pub fn new() -> Self {
        Self
    }
}

impl VmBackend for AppleContainerBackend {
    fn name(&self) -> &str {
        "apple-container"
    }

    fn kind(&self) -> BackendKind {
        BackendKind::AppleContainer
    }

    fn capabilities(&self) -> VmCapabilities {
        VmCapabilities {
            // Framework VMs will route egress through the same host-mediated
            // vsock endpoint seam every other backend uses — no routable
            // guest NIC. Until the boot path lands this is vacuously true:
            // the skeleton boots nothing, so nothing can reach a network.
            no_routable_guest_nic: true,
            snapshot_capability: SnapshotCapability::Unsupported,
            standby_pool: false,
            ..VmCapabilities::default()
        }
    }

    fn start_with_mode(&self, _config: &VmStartConfig, _mode: StartMode) -> Result<VmId> {
        Err(AppleContainerError::NotImplemented {
            operation: "start a container VM",
            milestone: "the Containerization Swift shim (stage 2)",
        }
        .into())
    }

    fn wait(&self, _id: &VmId) -> Result<VmExitStatus> {
        Err(AppleContainerError::NotImplemented {
            operation: "wait on a container VM",
            milestone: "the vminitd gRPC transport (stage 3)",
        }
        .into())
    }

    fn pause(&self, _id: &VmId) -> Result<()> {
        Err(AppleContainerError::NotImplemented {
            operation: "pause a container VM",
            milestone: "the Containerization Swift shim (stage 2)",
        }
        .into())
    }

    fn resume(&self, _id: &VmId) -> Result<()> {
        Err(AppleContainerError::NotImplemented {
            operation: "resume a container VM",
            milestone: "the Containerization Swift shim (stage 2)",
        }
        .into())
    }

    fn stop(&self, _id: &VmId) -> Result<()> {
        // Honest trivial answer: `start` cannot succeed yet, so no container
        // VM this backend owns can be running.
        Ok(())
    }

    fn stop_all(&self) -> Result<()> {
        Ok(())
    }

    fn status(&self, _id: &VmId) -> Result<VmStatus> {
        // No boot path exists, so every VM is trivially stopped.
        Ok(VmStatus::Stopped)
    }

    fn list(&self) -> Result<Vec<VmInfo>> {
        Ok(Vec::new())
    }

    fn logs(&self, _id: &VmId, _lines: u32, _hypervisor: bool) -> Result<String> {
        Err(AppleContainerError::NotImplemented {
            operation: "read container VM logs",
            milestone: "the vminitd gRPC transport (stage 3)",
        }
        .into())
    }

    fn is_available(&self) -> Result<bool> {
        // No boot path exists on any host yet; reporting `true` would let a
        // probe conclude a workload could start here.
        Ok(false)
    }

    fn install(&self) -> Result<()> {
        Err(AppleContainerError::NotImplemented {
            operation: "install the Apple Containerization runtime",
            milestone: "the Containerization Swift shim (stage 2)",
        }
        .into())
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        // Every numbered claim reports `DoesNotHold` until the boot path
        // lands and can actually enforce them — the skeleton booted nothing,
        // so nothing here may be claimed. Apple's framework VMs are
        // hardware-isolated lightweight Linux VMs, which is the Tier 2
        // shape this backend is being built toward; the tier string says so
        // honestly rather than rounding the posture up.
        BackendSecurityProfile {
            claims: [ClaimStatus::DoesNotHold; 7],
            layer_coverage: LayerCoverage::default(),
            tier: "Tier 2 (Apple Containerization framework; skeleton — no boot path yet)",
            notes: &[
                "Apple Containerization-framework VMs are hardware-isolated lightweight \
                 Linux VMs; the framework owns the kernel boot and `vminitd` as guest PID 1.",
                "Activation will ride vminitd's gRPC API (vsock port 1024) instead of an \
                 mvm initramfs; the guest agent, mount logic, uid-901 drop, and RPC gate \
                 stay shared with every other backend.",
                "Skeleton: every claim reports DoesNotHold until the boot path lands — \
                 nothing here may carry an untrusted workload yet.",
                "Opt-in only; never selected by auto-detect.",
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::AnyBackend;

    fn cfg(name: &str) -> VmStartConfig {
        VmStartConfig {
            name: name.to_string(),
            ..Default::default()
        }
    }

    /// Extract the typed error from the `anyhow` wrapper the trait returns,
    /// so tests assert the exact variant, not a substring.
    fn not_implemented(err: &anyhow::Error) -> &AppleContainerError {
        err.downcast_ref::<AppleContainerError>()
            .expect("apple-container failures must be the typed error")
    }

    #[test]
    fn kind_and_name_are_apple_container() {
        let b = AppleContainerBackend::new();
        assert_eq!(b.name(), "apple-container");
        assert_eq!(b.kind(), BackendKind::AppleContainer);
    }

    #[test]
    fn selector_and_alias_resolve_through_any_backend() {
        for sel in ["apple-container", "container"] {
            let backend = AnyBackend::from_hypervisor(sel);
            assert!(
                matches!(backend, AnyBackend::AppleContainer(_)),
                "selector {sel} must resolve to the apple-container backend"
            );
            assert_eq!(backend.name(), "apple-container");
            assert_eq!(backend.kind(), BackendKind::AppleContainer);
        }
    }

    #[test]
    fn auto_select_never_returns_apple_container() {
        // Opt-in only, same discipline as the wasm tier: `auto_select`'s
        // ladder constructs Firecracker/Hvf/Libkrun and nothing else, so this
        // holds on every platform the ladder can resolve to.
        assert_ne!(
            AnyBackend::auto_select().kind(),
            BackendKind::AppleContainer,
            "auto_select must never fall through to the apple-container skeleton"
        );
    }

    #[test]
    fn capabilities_are_honest_about_lacking_a_boot_path() {
        let caps = AppleContainerBackend::new().capabilities();
        assert!(!caps.pause_resume);
        assert!(!caps.snapshots);
        assert_eq!(caps.snapshot_capability, SnapshotCapability::Unsupported);
        assert!(!caps.standby_pool);
        assert!(!caps.vsock);
        assert!(!caps.tap_networking);
        assert!(!caps.balloon);
        assert!(!caps.fs_quick_checkpoint);
        assert!(!caps.host_vsock_proxy);
        assert!(!caps.pty_exec);
        assert!(!caps.production_ssh);
        assert!(caps.no_routable_guest_nic);
    }

    #[test]
    fn security_profile_carries_zero_numbered_claims() {
        let profile = AppleContainerBackend::new().security_profile();
        assert!(
            profile
                .claims
                .iter()
                .all(|c| matches!(c, ClaimStatus::DoesNotHold)),
            "the skeleton must not claim any numbered security guarantee"
        );
        assert_eq!(profile.dropped_claims(), vec![1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(profile.layer_coverage, LayerCoverage::default());
        assert!(
            profile.tier.starts_with("Tier 2"),
            "the tier string must agree with the catalog's Tier 2 classification: {}",
            profile.tier
        );
    }

    #[test]
    fn snapshot_capability_defaults_to_unsupported() {
        assert_eq!(
            AppleContainerBackend::new().snapshot_capability(),
            SnapshotCapability::Unsupported
        );
    }

    #[test]
    fn warm_start_fails_closed() {
        use mvm_core::vm_backend::{SnapshotCapability, WarmStartError};
        let b = AppleContainerBackend::new();
        match b.warm_start(&VmStartConfig::default(), SnapshotCapability::DiskOnly) {
            Err(WarmStartError::Unsupported { .. }) => {}
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn standby_pool_fails_closed() {
        assert!(!AppleContainerBackend::new().supports_standby_pool());
    }

    #[test]
    fn start_fails_closed_with_typed_error_naming_the_milestone() {
        let b = AppleContainerBackend::new();
        let err = b.start(&cfg("x")).unwrap_err();
        assert_eq!(
            not_implemented(&err),
            &AppleContainerError::NotImplemented {
                operation: "start a container VM",
                milestone: "the Containerization Swift shim (stage 2)",
            }
        );
        assert!(
            err.to_string().contains("cannot start a container VM yet"),
            "the display names the refused operation and the milestone: {err}"
        );
    }

    #[test]
    fn pause_resume_wait_logs_fail_closed_with_typed_errors() {
        let b = AppleContainerBackend::new();
        let id = VmId("x".to_string());
        for err in [
            b.pause(&id).unwrap_err(),
            b.resume(&id).unwrap_err(),
            b.wait(&id).unwrap_err(),
            b.logs(&id, 10, false).unwrap_err(),
        ] {
            assert!(
                matches!(
                    not_implemented(&err),
                    AppleContainerError::NotImplemented { .. }
                ),
                "expected a typed NotImplemented, got: {err}"
            );
        }
    }

    #[test]
    fn trivially_true_operations_are_honest() {
        // `start` cannot succeed, so nothing can be running: stop, status,
        // and list answer trivially instead of inventing state.
        let b = AppleContainerBackend::new();
        let id = VmId("x".to_string());
        assert!(b.stop(&id).is_ok());
        assert!(b.stop_all().is_ok());
        assert_eq!(b.status(&id).unwrap(), VmStatus::Stopped);
        assert!(b.list().unwrap().is_empty());
    }

    #[test]
    fn availability_is_honest_and_install_fails_closed() {
        let b = AppleContainerBackend::new();
        assert!(!b.is_available().unwrap(), "no boot path exists yet");
        assert!(matches!(
            not_implemented(&b.install().unwrap_err()),
            AppleContainerError::NotImplemented { .. }
        ));
    }

    #[test]
    fn network_info_and_guest_channel_info_fail_closed_by_default() {
        let b = AppleContainerBackend::new();
        let id = VmId("x".to_string());
        assert!(b.network_info(&id).is_err());
        assert!(b.guest_channel_info(&id).is_err());
    }

    #[test]
    fn balloon_ops_fail_closed_by_default() {
        let b = AppleContainerBackend::new();
        let id = VmId("x".to_string());
        assert!(b.balloon_set_target(&id, 64).is_err());
        assert!(b.balloon_state(&id).is_err());
    }
}
