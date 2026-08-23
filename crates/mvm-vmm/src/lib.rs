//! Backend-agnostic VMM device model and hypervisor seam.
//!
//! Guest memory access, the device tree (FDT), arm64 kernel-image loading,
//! virtio-mmio devices, and the portable hypervisor trait seam live here.
//! Concrete backends (HVF, KVM, etc.) depend on this crate and implement the
//! [`hv::HypervisorVm`] / [`hv::HypervisorVcpu`] traits, then drive the
//! shared device model through [`run::run`].
//!
//! The driver seam ([`driver::VmmDriver`](driver::VmmDriver), [`VmmSpec`])
//! and the backend-agnostic vsock transport also live here so that
//! `mvm-backends` can implement backends without depending on the workload
//! orchestration in `mvm-runtime`.

pub mod checkpoint;
pub mod dax;
pub mod driver;
pub mod host;
pub mod hvf_handoff;
pub mod post_restore;
pub mod qemu_arch;
pub mod quota;
pub mod snapshot;
pub mod vmm;
pub mod vsock_egress_bridge;
pub mod vsock_transport;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
