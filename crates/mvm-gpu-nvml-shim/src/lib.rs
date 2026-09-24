//! Drop-in `libnvidia-ml.so.1` replacement for an mvm guest.
//!
//! Frameworks decide whether a GPU exists by asking NVML, so without this
//! shim a remoted GPU is invisible to exactly the tools that want it. The
//! answers come from the same host endpoint the driver shims speak to.
//!
//! The NVML device handle the guest receives is the device ordinal as a
//! u64 — opaque to the workload, meaningful only here.

use std::cell::Cell;

use mvm_contract::protocol::gpu::GpuResponse;
use mvm_gpu_shim_core::{call, guard, wire, write_cstr};

use libc::{c_char, c_int, c_uint, c_void};

/// `nvmlReturn_t`.
type NvmlReturn = c_int;

/// NVML's documented name-buffer size.
const NVML_DEVICE_NAME_BUFFER_SIZE: usize = 64;
/// NVML's documented system-driver-version buffer size.
const NVML_SYSTEM_DRIVER_VERSION_BUFFER_SIZE: usize = 80;

const SUCCESS: NvmlReturn = wire::SUCCESS;

thread_local! {
    static INITIALIZED: Cell<bool> = const { Cell::new(false) };
}

fn initialized() -> bool {
    INITIALIZED.with(Cell::get)
}

/// `nvmlMemory_t`.
#[repr(C)]
pub struct NvmlMemory {
    pub total: u64,
    pub free: u64,
    pub used: u64,
}

// Layout pinned against the nvml.h definition (fixed-width fields, so the
// contract is total): three u64s at offsets 0/8/16, size 24, align 8.
const _: () = {
    use core::mem::{align_of, offset_of, size_of};

    assert!(size_of::<NvmlMemory>() == 24);
    assert!(align_of::<NvmlMemory>() == 8);
    assert!(offset_of!(NvmlMemory, total) == 0);
    assert!(offset_of!(NvmlMemory, free) == 8);
    assert!(offset_of!(NvmlMemory, used) == 16);
};

/// `nvmlUtilization_t`.
#[repr(C)]
pub struct NvmlUtilization {
    pub gpu: c_uint,
    pub memory: c_uint,
}

// Layout pinned against the nvml.h definition: two u32s at offsets 0/4,
// size 8, align 4.
const _: () = {
    use core::mem::{align_of, offset_of, size_of};

    assert!(size_of::<NvmlUtilization>() == 8);
    assert!(align_of::<NvmlUtilization>() == 4);
    assert!(offset_of!(NvmlUtilization, gpu) == 0);
    assert!(offset_of!(NvmlUtilization, memory) == 4);
};

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nvmlInit_v2() -> NvmlReturn {
    guard(
        move || {
            // Liveness round trip: the endpoint answers the device count
            // or an error that explains what is wrong.
            let code = match call(&mvm_contract::protocol::gpu::GpuRequest::NvmlDeviceGetCount) {
                GpuResponse::NvmlDeviceCount { .. } => SUCCESS,
                GpuResponse::Err(e) => e.code as NvmlReturn,
                _ => wire::NVML_ERROR_UNKNOWN as NvmlReturn,
            };
            if code == SUCCESS {
                INITIALIZED.with(|i| i.set(true));
            }
            code
        },
        wire::NVML_ERROR_UNKNOWN as NvmlReturn,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nvmlShutdown() -> NvmlReturn {
    guard(
        move || {
            INITIALIZED.with(|i| i.set(false));
            SUCCESS
        },
        wire::NVML_ERROR_UNKNOWN as NvmlReturn,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nvmlErrorString(code: NvmlReturn) -> *const c_char {
    guard(
        move || {
            use std::ffi::CStr;
            let text: &'static CStr = match code {
                SUCCESS => c"Success",
                e if e == wire::NVML_ERROR_UNINITIALIZED => c"Uninitialized",
                e if e == wire::NVML_ERROR_INVALID_ARGUMENT => c"Invalid Argument",
                e if e == wire::NVML_ERROR_NOT_SUPPORTED => c"Not Supported",
                e if e == wire::NVML_ERROR_NOT_FOUND => c"Not Found",
                e if e == wire::NVML_ERROR_INSUFFICIENT_SIZE => c"Insufficient Size",
                _ => c"Unknown Error",
            };
            text.as_ptr()
        },
        c"Unknown Error".as_ptr(),
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nvmlSystemGetDriverVersion(
    version: *mut c_char,
    length: c_uint,
) -> NvmlReturn {
    guard(
        move || {
            if !initialized() {
                return wire::NVML_ERROR_UNINITIALIZED as NvmlReturn;
            }
            if version.is_null() || length == 0 {
                return wire::NVML_ERROR_INVALID_ARGUMENT as NvmlReturn;
            }
            if (length as usize) < NVML_SYSTEM_DRIVER_VERSION_BUFFER_SIZE {
                return wire::NVML_ERROR_INSUFFICIENT_SIZE as NvmlReturn;
            }
            match call(&mvm_contract::protocol::gpu::GpuRequest::NvmlSystemGetDriverVersion) {
                GpuResponse::NvmlDriverVersion { version: v } => {
                    if unsafe { write_cstr(version, length as usize, &v) } {
                        SUCCESS
                    } else {
                        wire::NVML_ERROR_INSUFFICIENT_SIZE as NvmlReturn
                    }
                }
                GpuResponse::Err(e) => e.code as NvmlReturn,
                _ => wire::NVML_ERROR_UNKNOWN as NvmlReturn,
            }
        },
        wire::NVML_ERROR_UNKNOWN as NvmlReturn,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nvmlDeviceGetCount_v2(count: *mut c_uint) -> NvmlReturn {
    guard(
        move || {
            if !initialized() {
                return wire::NVML_ERROR_UNINITIALIZED as NvmlReturn;
            }
            if count.is_null() {
                return wire::NVML_ERROR_INVALID_ARGUMENT as NvmlReturn;
            }
            match call(&mvm_contract::protocol::gpu::GpuRequest::NvmlDeviceGetCount) {
                GpuResponse::NvmlDeviceCount { count: n } => {
                    // SAFETY: null-checked above.
                    unsafe { *count = n };
                    SUCCESS
                }
                GpuResponse::Err(e) => e.code as NvmlReturn,
                _ => wire::NVML_ERROR_UNKNOWN as NvmlReturn,
            }
        },
        wire::NVML_ERROR_UNKNOWN as NvmlReturn,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nvmlDeviceGetHandleByIndex_v2(
    index: c_uint,
    device: *mut *mut c_void,
) -> NvmlReturn {
    guard(
        move || {
            if !initialized() {
                return wire::NVML_ERROR_UNINITIALIZED as NvmlReturn;
            }
            if device.is_null() {
                return wire::NVML_ERROR_INVALID_ARGUMENT as NvmlReturn;
            }
            // The handle encodes the ordinal (offset so it is never null);
            // the endpoint validates it on each query. SAFETY: null-checked
            // above.
            unsafe { *device = ordinal_to_handle(index) };
            SUCCESS
        },
        wire::NVML_ERROR_UNKNOWN as NvmlReturn,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nvmlDeviceGetName(
    device: *mut c_void,
    name: *mut c_char,
    length: c_uint,
) -> NvmlReturn {
    guard(
        move || {
            if !initialized() {
                return wire::NVML_ERROR_UNINITIALIZED as NvmlReturn;
            }
            if name.is_null() || device.is_null() {
                return wire::NVML_ERROR_INVALID_ARGUMENT as NvmlReturn;
            }
            if (length as usize) < NVML_DEVICE_NAME_BUFFER_SIZE {
                return wire::NVML_ERROR_INSUFFICIENT_SIZE as NvmlReturn;
            }
            match call(
                &mvm_contract::protocol::gpu::GpuRequest::NvmlDeviceGetName {
                    ordinal: handle_to_ordinal(device),
                },
            ) {
                GpuResponse::DeviceName { name: n } => {
                    if unsafe { write_cstr(name, length as usize, &n) } {
                        SUCCESS
                    } else {
                        wire::NVML_ERROR_INSUFFICIENT_SIZE as NvmlReturn
                    }
                }
                GpuResponse::Err(e) => e.code as NvmlReturn,
                _ => wire::NVML_ERROR_UNKNOWN as NvmlReturn,
            }
        },
        wire::NVML_ERROR_UNKNOWN as NvmlReturn,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nvmlDeviceGetMemoryInfo(
    device: *mut c_void,
    memory: *mut NvmlMemory,
) -> NvmlReturn {
    guard(
        move || {
            if !initialized() {
                return wire::NVML_ERROR_UNINITIALIZED as NvmlReturn;
            }
            if memory.is_null() || device.is_null() {
                return wire::NVML_ERROR_INVALID_ARGUMENT as NvmlReturn;
            }
            match call(
                &mvm_contract::protocol::gpu::GpuRequest::NvmlDeviceGetMemoryInfo {
                    ordinal: handle_to_ordinal(device),
                },
            ) {
                GpuResponse::NvmlMemoryInfo { total, free, used } => {
                    // SAFETY: `memory` is a valid out-struct (null-checked).
                    unsafe {
                        (*memory).total = total;
                        (*memory).free = free;
                        (*memory).used = used;
                    }
                    SUCCESS
                }
                GpuResponse::Err(e) => e.code as NvmlReturn,
                _ => wire::NVML_ERROR_UNKNOWN as NvmlReturn,
            }
        },
        wire::NVML_ERROR_UNKNOWN as NvmlReturn,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nvmlDeviceGetUtilizationRates(
    device: *mut c_void,
    rates: *mut NvmlUtilization,
) -> NvmlReturn {
    guard(
        move || {
            if !initialized() {
                return wire::NVML_ERROR_UNINITIALIZED as NvmlReturn;
            }
            if rates.is_null() || device.is_null() {
                return wire::NVML_ERROR_INVALID_ARGUMENT as NvmlReturn;
            }
            match call(
                &mvm_contract::protocol::gpu::GpuRequest::NvmlDeviceGetUtilizationRates {
                    ordinal: handle_to_ordinal(device),
                },
            ) {
                GpuResponse::NvmlUtilization { gpu, memory } => {
                    // SAFETY: `rates` is a valid out-struct (null-checked).
                    unsafe {
                        (*rates).gpu = gpu;
                        (*rates).memory = memory;
                    }
                    SUCCESS
                }
                GpuResponse::Err(e) => e.code as NvmlReturn,
                _ => wire::NVML_ERROR_UNKNOWN as NvmlReturn,
            }
        },
        wire::NVML_ERROR_UNKNOWN as NvmlReturn,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nvmlDeviceGetCudaComputeCapability(
    device: *mut c_void,
    major: *mut c_int,
    minor: *mut c_int,
) -> NvmlReturn {
    guard(
        move || {
            if !initialized() {
                return wire::NVML_ERROR_UNINITIALIZED as NvmlReturn;
            }
            if major.is_null() || minor.is_null() || device.is_null() {
                return wire::NVML_ERROR_INVALID_ARGUMENT as NvmlReturn;
            }
            match call(
                &mvm_contract::protocol::gpu::GpuRequest::NvmlDeviceGetCudaComputeCapability {
                    ordinal: handle_to_ordinal(device),
                },
            ) {
                GpuResponse::NvmlComputeCapability {
                    major: maj,
                    minor: min,
                } => {
                    // SAFETY: both out-pointers are null-checked.
                    unsafe {
                        *major = maj;
                        *minor = min;
                    }
                    SUCCESS
                }
                GpuResponse::Err(e) => e.code as NvmlReturn,
                _ => wire::NVML_ERROR_UNKNOWN as NvmlReturn,
            }
        },
        wire::NVML_ERROR_UNKNOWN as NvmlReturn,
    )
}

// ---------------------------------------------------------------------------
// Device-handle encoding
//
// The guest-visible handle must never be null: real NVML hands out opaque
// non-null pointers, and callers (correctly) treat a null device as an
// error. The ordinal is therefore encoded with a +1 offset so ordinal 0
// still yields a live-looking handle; every query decodes with the inverse.
// ---------------------------------------------------------------------------

/// Encode a device ordinal as the guest-visible handle (never null).
fn ordinal_to_handle(ordinal: u32) -> *mut c_void {
    (u64::from(ordinal) + 1) as *mut c_void
}

/// Decode a guest handle back to its ordinal. A null handle is not a
/// valid device — callers already reject it, but keep the mapping total.
fn handle_to_ordinal(handle: *mut c_void) -> u32 {
    (handle as u64).saturating_sub(1) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinal_zero_still_yields_a_non_null_handle() {
        // The BDD witness caught this: with the raw ordinal as the handle,
        // device 0 minted a null handle and every subsequent NVML query
        // rejected it as an invalid argument.
        let handle = ordinal_to_handle(0);
        assert!(!handle.is_null());
        assert_eq!(handle_to_ordinal(handle), 0);
    }

    #[test]
    fn handle_round_trips_for_arbitrary_ordinals() {
        for ordinal in [0, 1, 2, 7, u32::MAX - 1] {
            let handle = ordinal_to_handle(ordinal);
            assert!(!handle.is_null(), "ordinal {ordinal} minted a null handle");
            assert_eq!(handle_to_ordinal(handle), ordinal);
        }
    }
}
