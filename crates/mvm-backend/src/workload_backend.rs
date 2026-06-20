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

impl EgressSubstitutionTransport {
    /// Whether this transport can carry proxy-aware substitution requests.
    pub fn supports_proxy_aware_substitution(self) -> bool {
        !matches!(self, Self::None)
    }

    /// Whether this transport can transparently intercept ordinary guest
    /// `:80`/`:443` egress and deliver it to the host terminator.
    pub fn supports_transparent_terminator(self) -> bool {
        matches!(self, Self::NftTerminator)
    }
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

/// Require the backend's substitution transport to include the transparent
/// `:80`/`:443` terminator leg. Proxy-aware substitution alone is not enough
/// for deleting the in-line gateway splice because non-proxy-aware workloads
/// would otherwise lose SDK-free egress substitution.
pub fn require_transparent_egress_terminator(backend: &dyn WorkloadBackend) -> Result<()> {
    if backend
        .egress_substitution_transport()
        .supports_transparent_terminator()
    {
        return Ok(());
    }
    anyhow::bail!(
        "backend `{}` does not provide a transparent :80/:443 egress terminator",
        backend.name()
    )
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
        let transport = FirecrackerBackend.egress_substitution_transport();
        assert_eq!(transport, EgressSubstitutionTransport::NftTerminator);
        assert!(transport.supports_proxy_aware_substitution());
        assert!(transport.supports_transparent_terminator());
    }

    #[test]
    fn libkrun_declares_vsock_uds_channel() {
        let transport = LibkrunBackend.egress_substitution_transport();
        assert_eq!(transport, EgressSubstitutionTransport::VsockUdsChannel);
        assert!(transport.supports_proxy_aware_substitution());
        assert!(!transport.supports_transparent_terminator());
    }

    #[test]
    fn vz_declares_vsock_uds_channel() {
        let transport = VzBackend.egress_substitution_transport();
        assert_eq!(transport, EgressSubstitutionTransport::VsockUdsChannel);
        assert!(transport.supports_proxy_aware_substitution());
        assert!(!transport.supports_transparent_terminator());
    }

    #[test]
    fn mock_declares_none() {
        let transport = MockBackend::new().egress_substitution_transport();
        assert_eq!(transport, EgressSubstitutionTransport::None);
        assert!(!transport.supports_proxy_aware_substitution());
        assert!(!transport.supports_transparent_terminator());
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

    #[test]
    fn transparent_egress_terminator_requirement_accepts_firecracker() {
        require_transparent_egress_terminator(&FirecrackerBackend)
            .expect("firecracker declares the nft terminator leg");
    }

    #[test]
    fn transparent_egress_terminator_requirement_refuses_proxy_only_backends() {
        let mock = MockBackend::new();
        for backend in [
            &LibkrunBackend as &dyn WorkloadBackend,
            &VzBackend as &dyn WorkloadBackend,
            &mock as &dyn WorkloadBackend,
        ] {
            let err = match require_transparent_egress_terminator(backend) {
                Ok(()) => panic!("{} should not satisfy the terminator gate", backend.name()),
                Err(e) => e,
            };
            assert!(
                err.to_string().contains("transparent :80/:443"),
                "refusal must name the missing terminator leg, got: {err}"
            );
        }
    }
}
