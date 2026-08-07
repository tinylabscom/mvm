//! Backend-agnostic VMM device model and hypervisor seam.
//!
//! Guest memory access, the device tree (FDT), arm64 kernel-image loading,
//! virtio-mmio devices, and the portable hypervisor trait seam live here.
//! Concrete backends (HVF, KVM, etc.) depend on this crate and implement the
//! [`hv::HypervisorVm`] / [`hv::HypervisorVcpu`] traits, then drive the
//! shared device model through [`run::run`].

pub mod dax;
pub mod vmm;
pub mod vsock_egress_bridge;

#[cfg(test)]
pub(crate) mod test_support;
