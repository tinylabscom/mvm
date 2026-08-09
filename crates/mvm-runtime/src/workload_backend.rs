//! `WorkloadBackend`: the type-level permission to carry an untrusted
//! workload. Only backends that go through the full enforcement funnel
//! implement it; the admitted launch path accepts `&dyn WorkloadBackend`
//! only, so a non-workload backend cannot reach it.
use crate::backend::AnyBackend;
#[cfg(feature = "test-support")]
use crate::mock::MockBackend;
use anyhow::{Result, anyhow};
use mvm_backends::legacy::hvf::HvfBackend;
use mvm_core::vm_backend::VmBackend;

/// Declares how a workload backend carries the egress secret-substitution
/// channel. The shared launch funnel interprets this to spawn the per-VM
/// substitution endpoint; the backend only declares the mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressSubstitutionTransport {
    /// macOS native path: the guest still has a proxy-aware vsock/UDS
    /// channel, and ordinary `:80/:443` TCP is intercepted by the native gateway
    /// and forwarded to the same host terminator.
    RvproxyTransparentTerminator,
    /// Proxy-aware channel only: the guest dials the substitution port over
    /// vsock, bridged to a host unix socket; no transparent `:80/:443` leg.
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
        matches!(self, Self::RvproxyTransparentTerminator)
    }
}

/// Type-level permission to carry an untrusted workload.
pub trait WorkloadBackend: VmBackend {
    /// How this backend carries the egress substitution channel. No default:
    /// a new workload backend must declare it (cannot silently omit it).
    fn egress_substitution_transport(&self) -> EgressSubstitutionTransport;
}

impl WorkloadBackend for HvfBackend {
    fn egress_substitution_transport(&self) -> EgressSubstitutionTransport {
        // Proxy-aware substitution over the vsock gateway: the guest dials the
        // egress port, and the VMM relays bytes to the per-VM endpoint that owns
        // claim-10 enforcement and claims 12/13. No transparent :80/:443
        // terminator.
        EgressSubstitutionTransport::VsockUdsChannel
    }
}
// `MockBackend` is the hermetic lifecycle test double — it carries no real
// workload, so it stands in for a workload backend on the admitted path in
// tests. `QemuBackend` (a real dev/test VMM) is deliberately NOT a
// `WorkloadBackend`: it is the meaningful Tier-2 carve-out.
#[cfg(feature = "test-support")]
impl WorkloadBackend for MockBackend {
    fn egress_substitution_transport(&self) -> EgressSubstitutionTransport {
        EgressSubstitutionTransport::None
    }
}

/// The single boundary the admitted launch path goes through. Returns the
/// backend as `&dyn WorkloadBackend`, or a typed refusal for backends not
/// permitted to carry an untrusted workload (the dev/test backends). The
/// bar is permission, not tier — libkrun is Tier-2 yet workload-capable.
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
        assert_is_workload_backend::<HvfBackend>();
        let firecracker = crate::backend::fc_runner();
        let _: &dyn WorkloadBackend = &firecracker;
        #[cfg(feature = "test-support")]
        assert_is_workload_backend::<MockBackend>();
        // libkrun is now a workload backend via the runner's blanket impl, not a
        // standalone one; the refuses-bucket test below coerces a live
        // `libkrun_runner()` to `&dyn WorkloadBackend`, which is that proof.
    }

    #[test]
    fn hvf_declares_vsock_uds_channel() {
        let transport = HvfBackend.egress_substitution_transport();
        assert_eq!(transport, EgressSubstitutionTransport::VsockUdsChannel);
        assert!(transport.supports_proxy_aware_substitution());
        assert!(!transport.supports_transparent_terminator());
    }

    #[test]
    fn libkrun_runner_declares_vsock_uds_channel() {
        // Post-flip libkrun carries egress over the runner's vsock UDS channel
        // (proxy-aware substitution, no transparent :80/:443 terminator) — the
        // same posture as HVF, reached through the blanket runner impl.
        let transport = crate::backend::libkrun_runner().egress_substitution_transport();
        assert_eq!(transport, EgressSubstitutionTransport::VsockUdsChannel);
        assert!(transport.supports_proxy_aware_substitution());
        assert!(!transport.supports_transparent_terminator());
    }

    #[test]
    #[cfg(feature = "test-support")]
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
}
