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

//!
//! Everything that touches a Unix socket, a file descriptor or guest memory is
//! built on Unix hosts only; elsewhere the crate is its portable modules.

#![deny(unreachable_pub)]
#[cfg(unix)]
pub mod agent_debug;
#[cfg(unix)]
pub mod checkpoint;
#[cfg(unix)]
pub mod driver;
#[cfg(unix)]
pub mod host;
pub mod hvf_handoff;
#[cfg(unix)]
pub mod post_restore;
pub mod qemu_arch;
#[cfg(unix)]
pub mod quota;
#[cfg(unix)]
pub mod runtime_artifacts;
#[cfg(unix)]
pub mod snapshot;
#[cfg(unix)]
pub mod vmm;
#[cfg(unix)]
pub mod vsock_egress_bridge;
#[cfg(unix)]
pub mod vsock_transport;

#[cfg(all(unix, any(test, feature = "test-support")))]
pub mod test_support;
