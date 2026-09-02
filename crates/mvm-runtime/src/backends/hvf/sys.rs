//! Minimal `Hypervisor.framework` (arm64) FFI — only the symbols the boot
//! smoke needs. A full raw-HVF backend would generate these with bindgen or
//! `objc2`; this hand-written surface is the spike's proof-of-primitive.
//!
//! Linked against the system `Hypervisor` framework. Every call needs the
//! `com.apple.security.hypervisor` entitlement on the launching binary (the
//! same entitlement `crate::codesign` already applies), otherwise
//! `hv_vm_create` returns a denied error.

#![allow(non_camel_case_types)]
// The FFI surface intentionally declares the full set of symbols/constants the
// backend will use; not all are exercised by the boot smoke yet.
#![allow(dead_code)]

use core::ffi::c_void;

/// `hv_return_t` is `int`; `HV_SUCCESS` is 0, errors are nonzero codes.
pub type hv_return_t = i32;
pub const HV_SUCCESS: hv_return_t = 0;
/// Stub error returned by the HVF FFI on non-Apple targets. Hypervisor.framework
/// is unavailable there; the HVF backend is never selected, but the symbols must
/// still link.
pub const HV_ERROR_UNSUPPORTED: hv_return_t = i32::MAX;

/// Guest physical address.
pub type hv_ipa_t = u64;
/// vCPU handle.
pub type hv_vcpu_t = u64;
/// Opaque config object pointers (`hv_vm_config_t` / `hv_vcpu_config_t`); NULL
/// selects the defaults.
pub type hv_config_t = *mut c_void;
/// Opaque GIC state object returned by Hypervisor.framework.
pub type hv_gic_state_t = *mut c_void;
/// GIC ICC system-register selector.
pub type hv_gic_icc_reg_t = u16;

/// `hv_memory_flags_t` bits.
pub type hv_memory_flags_t = u64;
pub const HV_MEMORY_READ: hv_memory_flags_t = 1 << 0;
pub const HV_MEMORY_WRITE: hv_memory_flags_t = 1 << 1;
pub const HV_MEMORY_EXEC: hv_memory_flags_t = 1 << 2;

/// `hv_reg_t` indices (subset). X0..X30 = 0..30, then PC/FPCR/FPSR/CPSR.
pub type hv_reg_t = u32;
pub const HV_REG_X0: hv_reg_t = 0;
pub const HV_REG_X1: hv_reg_t = 1;
pub const HV_REG_X2: hv_reg_t = 2;
pub const HV_REG_X3: hv_reg_t = 3;
/// Highest general-purpose register index; X0..X30 are contiguous from 0, so a
/// GP register index `n` maps directly to `HV_REG_X0 + n`.
pub const HV_REG_X30: hv_reg_t = 30;
pub const HV_REG_PC: hv_reg_t = 31;
pub const HV_REG_FPCR: hv_reg_t = 32;
pub const HV_REG_FPSR: hv_reg_t = 33;
pub const HV_REG_CPSR: hv_reg_t = 34;

/// ARM SIMD/FP register selector.
pub type hv_simd_fp_reg_t = u32;

// The framework's setter takes its 128-bit vector by value in q0. Stable Rust
// cannot express that SIMD C ABI, so this leaf shim accepts a byte pointer,
// loads q0, and tail-calls the framework entry point.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
core::arch::global_asm!(
    ".globl _mvm_hv_vcpu_set_simd_fp_reg",
    "_mvm_hv_vcpu_set_simd_fp_reg:",
    "ldr q0, [x2]",
    "b _hv_vcpu_set_simd_fp_reg",
);

/// `hv_sys_reg_t` — encoded AArch64 system register id (op0/op1/crn/crm/op2).
pub type hv_sys_reg_t = u32;
/// `MPIDR_EL1` — must hold the vCPU's affinity so the GIC redistributor matches.
pub const HV_SYS_REG_MPIDR_EL1: hv_sys_reg_t = 0xc005;
pub const HV_SYS_REG_SCTLR_EL1: hv_sys_reg_t = 0xc080;
pub const HV_SYS_REG_TTBR0_EL1: hv_sys_reg_t = 0xc100;
pub const HV_SYS_REG_TTBR1_EL1: hv_sys_reg_t = 0xc101;
pub const HV_SYS_REG_TCR_EL1: hv_sys_reg_t = 0xc102;
pub const HV_SYS_REG_SPSR_EL1: hv_sys_reg_t = 0xc200;
pub const HV_SYS_REG_ELR_EL1: hv_sys_reg_t = 0xc201;
pub const HV_SYS_REG_ESR_EL1: hv_sys_reg_t = 0xc290;
pub const HV_SYS_REG_FAR_EL1: hv_sys_reg_t = 0xc300;
pub const HV_SYS_REG_MAIR_EL1: hv_sys_reg_t = 0xc510;
pub const HV_SYS_REG_VBAR_EL1: hv_sys_reg_t = 0xc600;
pub const HV_SYS_REG_CNTKCTL_EL1: hv_sys_reg_t = 0xc708;
pub const HV_SYS_REG_CNTV_CTL_EL0: hv_sys_reg_t = 0xdf19;
pub const HV_SYS_REG_CNTV_CVAL_EL0: hv_sys_reg_t = 0xdf1a;
pub const HV_SYS_REG_SP_EL1: hv_sys_reg_t = 0xe208;
pub const HV_SYS_REG_ACTLR_EL1: hv_sys_reg_t = 0xc081;
pub const HV_SYS_REG_CPACR_EL1: hv_sys_reg_t = 0xc082;
pub const HV_SYS_REG_APIAKEYLO_EL1: hv_sys_reg_t = 0xc108;
pub const HV_SYS_REG_APIAKEYHI_EL1: hv_sys_reg_t = 0xc109;
pub const HV_SYS_REG_APIBKEYLO_EL1: hv_sys_reg_t = 0xc10a;
pub const HV_SYS_REG_APIBKEYHI_EL1: hv_sys_reg_t = 0xc10b;
pub const HV_SYS_REG_APDAKEYLO_EL1: hv_sys_reg_t = 0xc110;
pub const HV_SYS_REG_APDAKEYHI_EL1: hv_sys_reg_t = 0xc111;
pub const HV_SYS_REG_APDBKEYLO_EL1: hv_sys_reg_t = 0xc112;
pub const HV_SYS_REG_APDBKEYHI_EL1: hv_sys_reg_t = 0xc113;
pub const HV_SYS_REG_APGAKEYLO_EL1: hv_sys_reg_t = 0xc118;
pub const HV_SYS_REG_APGAKEYHI_EL1: hv_sys_reg_t = 0xc119;
pub const HV_SYS_REG_SP_EL0: hv_sys_reg_t = 0xc208;
pub const HV_SYS_REG_CONTEXTIDR_EL1: hv_sys_reg_t = 0xc681;
pub const HV_SYS_REG_TPIDR_EL1: hv_sys_reg_t = 0xc684;
pub const HV_SYS_REG_TPIDR_EL0: hv_sys_reg_t = 0xde82;
pub const HV_SYS_REG_TPIDRRO_EL0: hv_sys_reg_t = 0xde83;

/// Exception class (ESR `EC`, bits 31:26) values the run loop dispatches on.
pub const EC_HVC_AARCH64: u32 = 0x16;
pub const EC_DATA_ABORT_LOWER_EL: u32 = 0x24;

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

// Layout contract with Hypervisor.framework. The framework writes these
// structs; we only read them. A size, alignment, or field-offset mismatch
// therefore misreads the exit reason and the fault addresses rather than
// failing loudly, and the exit reason is what drives the whole vCPU loop.
//
// Values are the framework's, not this file's — derived from
// <Hypervisor/Hypervisor.h> on arm64 with:
//
//   clang -framework Hypervisor -x c - <<'EOF'
//   #include <Hypervisor/Hypervisor.h>
//   #include <stddef.h>
//   #include <stdio.h>
//   int main(void){ printf("%zu %zu %zu\n", sizeof(hv_vcpu_exit_t),
//       _Alignof(hv_vcpu_exit_t), offsetof(hv_vcpu_exit_t, exception)); }
//   EOF
//
// Re-derive against the SDK header before changing any number below.
const _: () = {
    use core::mem::{align_of, offset_of, size_of};

    assert!(size_of::<hv_vcpu_exit_exception_t>() == 24);
    assert!(align_of::<hv_vcpu_exit_exception_t>() == 8);
    assert!(offset_of!(hv_vcpu_exit_exception_t, syndrome) == 0);
    assert!(offset_of!(hv_vcpu_exit_exception_t, virtual_address) == 8);
    assert!(offset_of!(hv_vcpu_exit_exception_t, physical_address) == 16);

    assert!(size_of::<hv_vcpu_exit_t>() == 32);
    assert!(align_of::<hv_vcpu_exit_t>() == 8);
    assert!(offset_of!(hv_vcpu_exit_t, reason) == 0);
    // 4 bytes of tail padding after the u32 reason: the framework aligns
    // the nested exception to 8. Asserting this offset is the point of the
    // block — a reason widened to u64 would still size to 32 and silently
    // shift every field the fault handler reads.
    assert!(offset_of!(hv_vcpu_exit_t, exception) == 8);
};

#[cfg(target_os = "macos")]
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
    pub fn hv_vcpu_get_simd_fp_reg(
        vcpu: hv_vcpu_t,
        reg: hv_simd_fp_reg_t,
        value: *mut [u8; 16],
    ) -> hv_return_t;
    pub fn mvm_hv_vcpu_set_simd_fp_reg(
        vcpu: hv_vcpu_t,
        reg: hv_simd_fp_reg_t,
        value: *const [u8; 16],
    ) -> hv_return_t;
    pub fn hv_vcpu_set_sys_reg(vcpu: hv_vcpu_t, reg: hv_sys_reg_t, value: u64) -> hv_return_t;
    pub fn hv_vcpu_get_sys_reg(vcpu: hv_vcpu_t, reg: hv_sys_reg_t, value: *mut u64) -> hv_return_t;
    /// Force the listed vCPUs out of `hv_vcpu_run` (they exit with
    /// `HV_EXIT_REASON_CANCELED`). Safe to call from another thread — used as a
    /// run watchdog.
    pub fn hv_vcpus_exit(vcpus: *const hv_vcpu_t, vcpu_count: u32) -> hv_return_t;

    // In-kernel GICv3 (macOS 15+). Created after `hv_vm_create` and before
    // `hv_vcpu_create`; base addresses must match the device tree.
    pub fn hv_gic_config_create() -> hv_gic_config_t;
    pub fn hv_gic_config_set_distributor_base(
        config: hv_gic_config_t,
        base: hv_ipa_t,
    ) -> hv_return_t;
    pub fn hv_gic_config_set_redistributor_base(
        config: hv_gic_config_t,
        base: hv_ipa_t,
    ) -> hv_return_t;
    pub fn hv_gic_create(config: hv_gic_config_t) -> hv_return_t;
    /// Raise/lower a Shared Peripheral Interrupt line (absolute INTID). Used to
    /// signal virtio device completions to the guest.
    pub fn hv_gic_set_spi(intid: u32, level: bool) -> hv_return_t;
    pub fn hv_gic_get_distributor_size(size: *mut usize) -> hv_return_t;
    pub fn hv_gic_get_distributor_base_alignment(alignment: *mut usize) -> hv_return_t;
    pub fn hv_gic_get_redistributor_size(size: *mut usize) -> hv_return_t;
    /// The guest-physical base of one vCPU's redistributor frame. HVF assigns
    /// these itself as vCPUs are created; this is the only way to learn where a
    /// given vCPU's landed, and hence whether it matches the device tree the
    /// guest is reading.
    pub fn hv_gic_get_redistributor_base(
        vcpu: hv_vcpu_t,
        redistributor_base: *mut hv_ipa_t,
    ) -> hv_return_t;
    pub fn hv_gic_get_redistributor_base_alignment(alignment: *mut usize) -> hv_return_t;
    pub fn hv_gic_get_spi_interrupt_range(
        spi_intid_base: *mut u32,
        spi_intid_count: *mut u32,
    ) -> hv_return_t;
    pub fn hv_gic_state_create() -> hv_gic_state_t;
    pub fn hv_gic_state_get_size(state: hv_gic_state_t, size: *mut usize) -> hv_return_t;
    pub fn hv_gic_state_get_data(state: hv_gic_state_t, data: *mut c_void) -> hv_return_t;
    pub fn hv_gic_set_state(data: *const c_void, size: usize) -> hv_return_t;
    pub fn hv_gic_get_icc_reg(
        vcpu: hv_vcpu_t,
        reg: hv_gic_icc_reg_t,
        value: *mut u64,
    ) -> hv_return_t;
    pub fn hv_gic_set_icc_reg(vcpu: hv_vcpu_t, reg: hv_gic_icc_reg_t, value: u64) -> hv_return_t;
    pub fn os_release(object: *mut c_void);
}

#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_vm_create(_config: hv_config_t) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
pub unsafe fn hv_vm_destroy() -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_vm_map(
    _addr: *mut c_void,
    _ipa: hv_ipa_t,
    _size: usize,
    _flags: hv_memory_flags_t,
) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_vm_unmap(_ipa: hv_ipa_t, _size: usize) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_vcpu_create(
    _vcpu: *mut hv_vcpu_t,
    _exit: *mut *mut hv_vcpu_exit_t,
    _config: hv_config_t,
) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
pub unsafe fn hv_vcpu_destroy(_vcpu: hv_vcpu_t) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
pub unsafe fn hv_vcpu_run(_vcpu: hv_vcpu_t) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_vcpu_set_reg(_vcpu: hv_vcpu_t, _reg: hv_reg_t, _value: u64) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_vcpu_get_reg(_vcpu: hv_vcpu_t, _reg: hv_reg_t, _value: *mut u64) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_vcpu_get_simd_fp_reg(
    _vcpu: hv_vcpu_t,
    _reg: hv_simd_fp_reg_t,
    _value: *mut [u8; 16],
) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn mvm_hv_vcpu_set_simd_fp_reg(
    _vcpu: hv_vcpu_t,
    _reg: hv_simd_fp_reg_t,
    _value: *const [u8; 16],
) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_vcpu_set_sys_reg(
    _vcpu: hv_vcpu_t,
    _reg: hv_sys_reg_t,
    _value: u64,
) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_vcpu_get_sys_reg(
    _vcpu: hv_vcpu_t,
    _reg: hv_sys_reg_t,
    _value: *mut u64,
) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_vcpus_exit(_vcpus: *const hv_vcpu_t, _vcpu_count: u32) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
pub unsafe fn hv_gic_config_create() -> hv_gic_config_t {
    std::ptr::null_mut()
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_gic_config_set_distributor_base(
    _config: hv_gic_config_t,
    _base: hv_ipa_t,
) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_gic_config_set_redistributor_base(
    _config: hv_gic_config_t,
    _base: hv_ipa_t,
) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_gic_create(_config: hv_gic_config_t) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
pub unsafe fn hv_gic_set_spi(_intid: u32, _level: bool) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_gic_get_distributor_size(_size: *mut usize) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_gic_get_distributor_base_alignment(_alignment: *mut usize) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_gic_get_redistributor_size(_size: *mut usize) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_gic_get_redistributor_base(
    _vcpu: hv_vcpu_t,
    _redistributor_base: *mut hv_ipa_t,
) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_gic_get_redistributor_base_alignment(_alignment: *mut usize) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_gic_get_spi_interrupt_range(
    _spi_intid_base: *mut u32,
    _spi_intid_count: *mut u32,
) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
pub unsafe fn hv_gic_state_create() -> hv_gic_state_t {
    std::ptr::null_mut()
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_gic_state_get_size(_state: hv_gic_state_t, _size: *mut usize) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_gic_state_get_data(_state: hv_gic_state_t, _data: *mut c_void) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_gic_set_state(_data: *const c_void, _size: usize) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_gic_get_icc_reg(
    _vcpu: hv_vcpu_t,
    _reg: hv_gic_icc_reg_t,
    _value: *mut u64,
) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn hv_gic_set_icc_reg(
    _vcpu: hv_vcpu_t,
    _reg: hv_gic_icc_reg_t,
    _value: u64,
) -> hv_return_t {
    HV_ERROR_UNSUPPORTED
}
#[cfg(not(target_os = "macos"))]
pub unsafe fn os_release(_object: *mut c_void) {}

/// Opaque `hv_gic_config_t`.
pub type hv_gic_config_t = *mut c_void;
