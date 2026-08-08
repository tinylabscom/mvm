//! Legacy [`mvm_core::vm_backend::VmBackend`] implementations for the
//! concrete VMMs. These are the raw backend shells that predate the
//! `VmmDriver` seam; production orchestration goes through the driver seam
//! in [`crate::driver`], but the legacy shells remain for direct callers and
//! benchmarks.

pub mod libkrun;
pub mod qemu;

pub mod fc;
pub mod hvf;
pub mod hvf_bootargs;
