//! `WorkloadBackend`: the type-level permission to carry an untrusted
//! workload. Only backends that go through the full enforcement funnel
//! implement it; the admitted launch path accepts `&dyn WorkloadBackend`
//! only, so a non-workload backend cannot reach it.
use crate::backend::{AnyBackend, FirecrackerBackend};
use crate::hvf_backend::HvfBackend;
use crate::libkrun::LibkrunBackend;
use crate::mock::MockBackend;
use anyhow::{Result, anyhow};
use mvm_core::network_policy::NetworkPolicy;
use mvm_core::vm_backend::{RequiredCapabilities, VmBackend};

/// Declares how a workload backend carries the egress secret-substitution
/// channel. The shared launch funnel interprets this to spawn the per-VM
/// substitution endpoint; the backend only declares the mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressSubstitutionTransport {
    /// The guest's only workload egress path is the host-vsock proxy gate on
    /// `EGRESS_PORT`: raw SOCKS5 (`mvm-egress-client`) for secret-free traffic,
    /// or WireRequest substitution for secret-bearing traffic. No guest NIC and
    /// no transparent `:80/:443` interception leg.
    VsockHostProxy,
    /// This backend does not run egress substitution (the mock test double).
    None,
}

impl EgressSubstitutionTransport {
    /// Whether this transport can carry proxy-aware substitution requests.
    pub fn supports_proxy_aware_substitution(self) -> bool {
        !matches!(self, Self::None)
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
        EgressSubstitutionTransport::VsockHostProxy
    }
}

impl WorkloadBackend for LibkrunBackend {
    fn egress_substitution_transport(&self) -> EgressSubstitutionTransport {
        EgressSubstitutionTransport::VsockHostProxy
    }
}

impl WorkloadBackend for HvfBackend {
    fn egress_substitution_transport(&self) -> EgressSubstitutionTransport {
        EgressSubstitutionTransport::VsockHostProxy
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
/// permitted to carry an untrusted workload (the dev/test backends).
pub fn require_workload_backend(backend: &AnyBackend) -> Result<&dyn WorkloadBackend> {
    backend.as_workload_backend().ok_or_else(|| {
        anyhow!(
            "backend `{}` is not a workload backend — it cannot carry an \
             untrusted workload",
            backend.name()
        )
    })
}

fn legacy_workload_egress_note(_backend: &AnyBackend) -> Option<&'static str> {
    None
}

/// Require the fail-closed workload-egress contract for any boot that carries
/// network policy: vsock transport, no guest NIC, and a host/vsock proxy gate.
/// Policy selects admission only — it never enables legacy guest networking.
pub fn require_vsock_only_workload_egress<'a>(
    backend: &'a AnyBackend,
    policy: &NetworkPolicy,
    surface: &str,
) -> Result<&'a dyn WorkloadBackend> {
    let workload = require_workload_backend(backend)?;
    let required = RequiredCapabilities::vsock_only_workload_egress();
    let missing = workload.capabilities().shortfall(&required);
    if missing.is_empty() {
        return Ok(workload);
    }

    let legacy_note = legacy_workload_egress_note(backend)
        .map(|note| format!(" {note}"))
        .unwrap_or_default();
    anyhow::bail!(
        "refusing {surface} on backend `{}`: workload network policy `{}` requires \
         backend capabilities [vsock, no_guest_nic, host_vsock_proxy], but `{}` lacks \
         [{}]. `--net` and `--allow-host` select policy only; they never enable a \
         guest NIC, TAP, gvproxy, passt, or any backend-specific L2/L3 workload \
         dataplane.{}",
        backend.name(),
        policy.posture_label(),
        backend.name(),
        missing.join(", "),
        legacy_note,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_is_workload_backend<T: WorkloadBackend>() {}

    #[test]
    fn workload_backends_implement_marker() {
        assert_is_workload_backend::<FirecrackerBackend>();
        assert_is_workload_backend::<LibkrunBackend>();
        assert_is_workload_backend::<HvfBackend>();
        assert_is_workload_backend::<MockBackend>();
    }

    #[test]
    fn hvf_declares_vsock_host_proxy() {
        let transport = HvfBackend.egress_substitution_transport();
        assert_eq!(transport, EgressSubstitutionTransport::VsockHostProxy);
        assert!(transport.supports_proxy_aware_substitution());
    }

    #[test]
    fn firecracker_declares_vsock_host_proxy() {
        let transport = FirecrackerBackend.egress_substitution_transport();
        assert_eq!(transport, EgressSubstitutionTransport::VsockHostProxy);
        assert!(transport.supports_proxy_aware_substitution());
    }

    #[test]
    fn libkrun_declares_vsock_host_proxy() {
        let transport = LibkrunBackend.egress_substitution_transport();
        assert_eq!(transport, EgressSubstitutionTransport::VsockHostProxy);
        assert!(transport.supports_proxy_aware_substitution());
    }

    #[test]
    fn mock_declares_none() {
        let transport = MockBackend::new().egress_substitution_transport();
        assert_eq!(transport, EgressSubstitutionTransport::None);
        assert!(!transport.supports_proxy_aware_substitution());
    }

    #[test]
    fn require_workload_backend_accepts_firecracker() {
        let backend = AnyBackend::from_hypervisor("firecracker");
        let workload = match require_workload_backend(&backend) {
            Ok(workload) => workload,
            Err(err) => panic!("firecracker is a workload backend: {err}"),
        };
        assert_eq!(workload.name(), "firecracker");
    }

    #[test]
    fn require_workload_backend_refuses_qemu() {
        let backend = AnyBackend::from_hypervisor("qemu");
        let err = match require_workload_backend(&backend) {
            Ok(_) => panic!("qemu is a Tier-2 dev/test backend, not a workload backend"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("not a workload backend"),
            "refusal must explain the bar, got: {err}"
        );
    }

    #[test]
    fn vsock_only_workload_egress_accepts_hvf() {
        let backend = AnyBackend::from_hypervisor("hvf");
        let workload =
            require_vsock_only_workload_egress(&backend, &NetworkPolicy::deny_all(), "machine run")
                .expect("hvf satisfies the vsock-only workload-egress contract");
        assert_eq!(workload.name(), "hvf");
    }

    #[test]
    fn vsock_only_workload_egress_accepts_firecracker() {
        let backend = AnyBackend::from_hypervisor("firecracker");
        let workload =
            require_vsock_only_workload_egress(&backend, &NetworkPolicy::deny_all(), "machine run")
                .expect("firecracker satisfies the vsock-only workload-egress contract");
        assert_eq!(workload.name(), "firecracker");
    }

    #[test]
    fn vsock_only_workload_egress_accepts_libkrun() {
        let backend = AnyBackend::from_hypervisor("libkrun");
        let workload = require_vsock_only_workload_egress(
            &backend,
            &NetworkPolicy::allow_list(vec![mvm_core::network_policy::HostPort::new(
                "api.example.com",
                443,
            )]),
            "transient workload run",
        )
        .expect("libkrun satisfies the vsock-only workload-egress contract");
        assert_eq!(workload.name(), "libkrun");
    }
}
