//! `WorkloadBackend`: the type-level permission to carry an untrusted
//! workload. Only backends that go through the full enforcement funnel
//! implement it; the admitted launch path accepts `&dyn WorkloadBackend`
//! only, so a non-workload backend cannot reach it.
use crate::backend::{AnyBackend, FirecrackerBackend};
use crate::libkrun::LibkrunBackend;
use crate::vz::VzBackend;
use anyhow::{Result, anyhow};
use mvm_core::vm_backend::VmBackend;

/// Type-level permission to carry an untrusted workload.
pub trait WorkloadBackend: VmBackend {}

impl WorkloadBackend for FirecrackerBackend {}
impl WorkloadBackend for LibkrunBackend {}
impl WorkloadBackend for VzBackend {}

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

    // Compile-time proof the three workload backends implement the marker.
    fn assert_is_workload_backend<T: WorkloadBackend>() {}

    #[test]
    fn workload_backends_implement_marker() {
        assert_is_workload_backend::<FirecrackerBackend>();
        assert_is_workload_backend::<LibkrunBackend>();
        assert_is_workload_backend::<VzBackend>();
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
