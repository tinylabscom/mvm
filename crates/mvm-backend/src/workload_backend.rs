//! `WorkloadBackend`: the type-level permission to carry an untrusted
//! workload. Only backends that go through the full enforcement funnel
//! implement it; the admitted launch path accepts `&dyn WorkloadBackend`
//! only, so a non-workload backend cannot reach it.
use crate::backend::{AnyBackend, FirecrackerBackend};
use crate::libkrun::LibkrunBackend;
use crate::mock::MockBackend;
use crate::vz::VzBackend;
use anyhow::{Result, anyhow};
use mvm_core::vm_backend::VmBackend;

/// Declares how a workload backend carries the egress secret-substitution
/// channel. The shared launch funnel interprets this to spawn the per-VM
/// substitution endpoint; the backend only declares the mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressSubstitutionTransport {
    /// Linux Firecracker: the guest's :80/:443 is steered to a host TCP
    /// terminator via an nft PREROUTING REDIRECT; the funnel computes the
    /// per-slot terminator address and installs the redirect post-boot.
    NftTerminator,
    /// macOS (libkrun / vz): the guest dials the substitution port over
    /// vsock, bridged to a host unix socket; the endpoint listens on that
    /// `Uds`. No transparent :80/:443 terminator yet (that is gated on the
    /// rvproxy gateway — a separate follow-up).
    VsockUdsChannel,
    /// This backend does not run egress substitution (the mock test double).
    None,
}

/// Type-level permission to carry an untrusted workload.
pub trait WorkloadBackend: VmBackend {
    /// How this backend carries the egress substitution channel. No default:
    /// a new workload backend must declare it (cannot silently omit it).
    fn egress_substitution_transport(&self) -> EgressSubstitutionTransport;
}

impl WorkloadBackend for FirecrackerBackend {
    fn egress_substitution_transport(&self) -> EgressSubstitutionTransport {
        EgressSubstitutionTransport::NftTerminator
    }
}
impl WorkloadBackend for LibkrunBackend {
    fn egress_substitution_transport(&self) -> EgressSubstitutionTransport {
        EgressSubstitutionTransport::VsockUdsChannel
    }
}
impl WorkloadBackend for VzBackend {
    fn egress_substitution_transport(&self) -> EgressSubstitutionTransport {
        EgressSubstitutionTransport::VsockUdsChannel
    }
}
// `MockBackend` is the hermetic lifecycle test double — it carries no real
// workload, so it stands in for a workload backend on the admitted path in
// tests. `QemuBackend` (a real dev/test VMM) is deliberately NOT a
// `WorkloadBackend`: it is the meaningful Tier-2 carve-out.
impl WorkloadBackend for MockBackend {
    fn egress_substitution_transport(&self) -> EgressSubstitutionTransport {
        EgressSubstitutionTransport::None
    }
}

/// The single boundary the admitted launch path goes through. Returns the
/// backend as `&dyn WorkloadBackend`, or a typed refusal for backends not
/// permitted to carry an untrusted workload (the dev/test backends). The
/// bar is permission, not tier — libkrun and vz are Tier-2 yet workload-capable.
pub fn require_workload_backend(backend: &AnyBackend) -> Result<&dyn WorkloadBackend> {
    backend.as_workload_backend().ok_or_else(|| {
        anyhow!(
            "backend `{}` is not a workload backend — it cannot carry an \
             untrusted workload",
            backend.name()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time proof the workload backends implement the marker (incl. the
    // mock test double; qemu is intentionally absent).
    fn assert_is_workload_backend<T: WorkloadBackend>() {}

    #[test]
    fn workload_backends_implement_marker() {
        assert_is_workload_backend::<FirecrackerBackend>();
        assert_is_workload_backend::<LibkrunBackend>();
        assert_is_workload_backend::<VzBackend>();
        assert_is_workload_backend::<MockBackend>();
    }

    #[test]
    fn firecracker_declares_nft_terminator() {
        assert_eq!(
            FirecrackerBackend.egress_substitution_transport(),
            EgressSubstitutionTransport::NftTerminator
        );
    }

    #[test]
    fn libkrun_declares_vsock_uds_channel() {
        assert_eq!(
            LibkrunBackend.egress_substitution_transport(),
            EgressSubstitutionTransport::VsockUdsChannel
        );
    }

    #[test]
    fn vz_declares_vsock_uds_channel() {
        assert_eq!(
            VzBackend.egress_substitution_transport(),
            EgressSubstitutionTransport::VsockUdsChannel
        );
    }

    #[test]
    fn mock_declares_none() {
        assert_eq!(
            MockBackend::new().egress_substitution_transport(),
            EgressSubstitutionTransport::None
        );
    }

    #[test]
    fn require_workload_backend_accepts_firecracker() {
        let backend = AnyBackend::from_hypervisor("firecracker");
        let workload = match require_workload_backend(&backend) {
            Ok(w) => w,
            Err(e) => panic!("firecracker is a workload backend: {e}"),
        };
        assert_eq!(workload.name(), "firecracker");
    }

    #[test]
    fn require_workload_backend_refuses_qemu() {
        let backend = AnyBackend::from_hypervisor("qemu");
        // `&dyn WorkloadBackend` isn't `Debug`, so match rather than `expect_err`.
        let err = match require_workload_backend(&backend) {
            Ok(_) => panic!("qemu is a Tier-2 dev/test backend, not a workload backend"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("not a workload backend"),
            "refusal must explain the bar, got: {err}"
        );
    }
}
