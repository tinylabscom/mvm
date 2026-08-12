//! HVF (`Hypervisor.framework`) backend for macOS / Apple Silicon.
//!
//! The raw substrate modules remain here; the `VmBackend` and `VmmDriver`
//! implementations have moved to `mvm-backends` and are re-exported below for
//! backward compatibility.

mod boot_smoke;
mod console_smoke;
mod guest_ram;
mod hv_impl;
mod kernel_boot;
pub mod snapshot;
mod sys;
mod vcpu;

pub use mvm_backends::driver::hvf::HvfDriver;
pub use mvm_backends::legacy::hvf::HvfBackend;
pub use mvm_backends::legacy::hvf_bootargs::{
    default_bootargs, default_virtiofs_bootargs, workload_bootargs,
};
pub use mvm_vmm::vmm::virtio::DiskImage;

pub use boot_smoke::{BootProof, HvfError, MAGIC, boot_smoke, probe_available};
pub use console_smoke::{ConsoleProof, console_smoke};
pub use hv_impl::{HvfHandle, HvfVcpu, HvfVm};
pub use kernel_boot::{
    HostChannels, KernelBootResult, KernelBootUntilParams, KernelShutdownTiming, boot_kernel,
    boot_kernel_until,
};

/// Compatibility alias for examples/tests that still reach `backends::hvf::driver::HvfDriver`.
pub mod driver {
    pub use super::HvfDriver;
}
