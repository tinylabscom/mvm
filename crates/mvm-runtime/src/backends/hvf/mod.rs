//! HVF (`Hypervisor.framework`) backend for macOS / Apple Silicon.
//!
//! This module contains the full HVF path:
//! - the raw Hypervisor.framework substrate ([`sys`], [`hv_impl`], [`vcpu`]);
//! - kernel boot and guest RAM setup ([`kernel_boot`], [`guest_ram`]);
//! - smoke proofs ([`boot_smoke`], [`console_smoke`]);
//! - the [`VmBackend`] orchestration implementation ([`backend`]);
//! - boot argument helpers ([`bootargs`]);
//! - the [`VmmDriver`] implementation ([`driver`]).
//!
//! Apple-silicon macOS only; every entry point needs the
//! `com.apple.security.hypervisor` entitlement (already applied by
//! [`crate::codesign`]).

mod boot_smoke;
mod console_smoke;
mod dax_mapper;
mod guest_ram;
mod hv_impl;
mod kernel_boot;
mod sys;
mod vcpu;

pub mod backend;
pub mod bootargs;
pub mod driver;

pub use crate::vmm::virtio::DiskImage;
pub use backend::HvfBackend;
pub use boot_smoke::{BootProof, HvfError, MAGIC, boot_smoke, probe_available};
pub use bootargs::workload_bootargs;
pub use console_smoke::{ConsoleProof, console_smoke};
pub use driver::HvfDriver;
pub use hv_impl::{HvfHandle, HvfVcpu, HvfVm};
pub use kernel_boot::{
    HostChannels, KernelBootResult, KernelBootUntilParams, boot_kernel, boot_kernel_until,
};
