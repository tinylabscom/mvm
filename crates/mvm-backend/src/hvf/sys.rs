//! Minimal `Hypervisor.framework` (arm64) FFI — only the symbols the boot
//! smoke needs. A full raw-HVF backend would generate these with bindgen or
//! `objc2`; this hand-written surface is the spike's proof-of-primitive.
//!
//! Linked against the system `Hypervisor` framework. Every call needs the
//! `com.apple.security.hypervisor` entitlement on the launching binary (the
//! same entitlement `mvm_backend::codesign` already applies), otherwise
//! `hv_vm_create` returns a denied error.

#![allow(non_camel_case_types)]
// The FFI surface intentionally declares the full set of symbols/constants the
// backend will use; not all are exercised by the boot smoke yet.
#![allow(dead_code)]

use core::ffi::c_void;

/// `hv_return_t` is `int`; `HV_SUCCESS` is 0, errors are nonzero codes.
pub type hv_return_t = i32;
pub const HV_SUCCESS: hv_return_t = 0;

/// Guest physical address.
pub type hv_ipa_t = u64;
/// vCPU handle.
pub type hv_vcpu_t = u64;
/// Opaque config object pointers (`hv_vm_config_t` / `hv_vcpu_config_t`); NULL
/// selects the defaults.
pub type hv_config_t = *mut c_void;

/// `hv_memory_flags_t` bits.
pub type hv_memory_flags_t = u64;
pub const HV_MEMORY_READ: hv_memory_flags_t = 1 << 0;
pub const HV_MEMORY_WRITE: hv_memory_flags_t = 1 << 1;
pub const HV_MEMORY_EXEC: hv_memory_flags_t = 1 << 2;

/// `hv_reg_t` indices (subset). X0..X30 = 0..30, then PC/FPCR/FPSR/CPSR.
pub type hv_reg_t = u32;
pub const HV_REG_X0: hv_reg_t = 0;
pub const HV_REG_X1: hv_reg_t = 1;
pub const HV_REG_PC: hv_reg_t = 31;
pub const HV_REG_CPSR: hv_reg_t = 34;

/// `hv_exit_reason_t`.
pub type hv_exit_reason_t = u32;
pub const HV_EXIT_REASON_CANCELED: hv_exit_reason_t = 0;
pub const HV_EXIT_REASON_EXCEPTION: hv_exit_reason_t = 1;
pub const HV_EXIT_REASON_VTIMER_ACTIVATED: hv_exit_reason_t = 2;
pub const HV_EXIT_REASON_UNKNOWN: hv_exit_reason_t = 3;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct hv_vcpu_exit_exception_t {
    pub syndrome: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct hv_vcpu_exit_t {
    pub reason: hv_exit_reason_t,
    pub exception: hv_vcpu_exit_exception_t,
}

#[link(name = "Hypervisor", kind = "framework")]
unsafe extern "C" {
    pub fn hv_vm_create(config: hv_config_t) -> hv_return_t;
    pub fn hv_vm_destroy() -> hv_return_t;
    pub fn hv_vm_map(
        addr: *mut c_void,
        ipa: hv_ipa_t,
        size: usize,
        flags: hv_memory_flags_t,
    ) -> hv_return_t;
    pub fn hv_vm_unmap(ipa: hv_ipa_t, size: usize) -> hv_return_t;

    pub fn hv_vcpu_create(
        vcpu: *mut hv_vcpu_t,
        exit: *mut *mut hv_vcpu_exit_t,
        config: hv_config_t,
    ) -> hv_return_t;
    pub fn hv_vcpu_destroy(vcpu: hv_vcpu_t) -> hv_return_t;
    pub fn hv_vcpu_run(vcpu: hv_vcpu_t) -> hv_return_t;
    pub fn hv_vcpu_set_reg(vcpu: hv_vcpu_t, reg: hv_reg_t, value: u64) -> hv_return_t;
    pub fn hv_vcpu_get_reg(vcpu: hv_vcpu_t, reg: hv_reg_t, value: *mut u64) -> hv_return_t;
}
