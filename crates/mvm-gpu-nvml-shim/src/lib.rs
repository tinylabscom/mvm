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

/// `nvmlUtilization_t`.
#[repr(C)]
pub struct NvmlUtilization {
    pub gpu: c_uint,
    pub memory: c_uint,
}

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
            // The handle is the ordinal; the endpoint validates it on each
            // query. SAFETY: null-checked above.
            unsafe { *device = u64::from(index) as *mut c_void };
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
                    ordinal: device as u64 as u32,
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
                    ordinal: device as u64 as u32,
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
                    ordinal: device as u64 as u32,
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
                    ordinal: device as u64 as u32,
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
