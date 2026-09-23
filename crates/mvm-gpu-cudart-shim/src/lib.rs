//! Drop-in `libcudart.so` replacement for an mvm guest.
//!
//! The CUDA Runtime API is lowered onto the same wire the driver shim
//! speaks: allocations, copies, and synchrony map one-to-one onto driver
//! operations server-side, so the wire carries one vocabulary. Runtime
//! device pointers are the endpoint's opaque device pointers verbatim.
//!
//! v1 coverage is documented in `specs/plans/2026-09-20-gpu-over-vsock.md`.

use std::cell::Cell;

use mvm_contract::protocol::gpu::GpuResponse;
use mvm_gpu_shim_core::{call, guard, wire};

use libc::{c_char, c_int, c_uint, c_void};

/// `cudaError_t`.
type CudaError = c_int;
/// Memcpy kind, per `cudaMemcpyKind`.
const MEMCPY_HOST_TO_HOST: c_int = 0;
const MEMCPY_HOST_TO_DEVICE: c_int = 1;
const MEMCPY_DEVICE_TO_HOST: c_int = 2;
const MEMCPY_DEVICE_TO_DEVICE: c_int = 3;

const SUCCESS: CudaError = wire::SUCCESS;

thread_local! {
    /// This thread's last sticky runtime error.
    static LAST_ERROR: Cell<CudaError> = const { Cell::new(SUCCESS) };
    /// The device this thread has selected; v1 supports device 0 only.
    static CURRENT_DEVICE: Cell<c_int> = const { Cell::new(0) };
}

fn set_last_error(code: CudaError) {
    if code != SUCCESS {
        LAST_ERROR.with(|e| e.set(code));
    }
}

fn last_error() -> CudaError {
    LAST_ERROR.with(|e| e.replace(SUCCESS))
}

fn current_device() -> c_int {
    CURRENT_DEVICE.with(Cell::get)
}

fn unit(response: GpuResponse) -> CudaError {
    match response {
        GpuResponse::Ok => SUCCESS,
        GpuResponse::Err(e) => e.code as CudaError,
        _ => wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    }
}

fn queued(response: GpuResponse) -> CudaError {
    match response {
        GpuResponse::AsyncQueued { .. } => SUCCESS,
        GpuResponse::Err(e) => e.code as CudaError,
        _ => wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    }
}

/// The context the endpoint has implicitly per device: created lazily on
/// first use and reused for the process lifetime. Device 0 only in v1.
fn ensure_context() -> Result<u64, CudaError> {
    thread_local! {
        static CTX: Cell<u64> = const { Cell::new(0) };
    }
    let existing = CTX.with(Cell::get);
    if existing != 0 {
        return Ok(existing);
    }
    match call(&mvm_contract::protocol::gpu::GpuRequest::ContextCreate { ordinal: 0 }) {
        GpuResponse::ContextCreated { context } => {
            CTX.with(|c| c.set(context));
            Ok(context)
        }
        GpuResponse::Err(e) => Err(e.code as CudaError),
        _ => Err(wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError),
    }
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaGetDeviceCount(count: *mut c_int) -> CudaError {
    guard(
        move || {
            if count.is_null() {
                return wire::CUDA_ERROR_RUNTIME_INVALID_VALUE as CudaError;
            }
            match call(&mvm_contract::protocol::gpu::GpuRequest::DeviceGetCount) {
                GpuResponse::DeviceCount { count: n } => {
                    // SAFETY: null-checked above.
                    unsafe { *count = n as c_int };
                    SUCCESS
                }
                GpuResponse::Err(e) => e.code as CudaError,
                _ => wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
            }
        },
        wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaSetDevice(device: c_int) -> CudaError {
    guard(
        move || {
            if device != 0 {
                set_last_error(wire::CUDA_ERROR_RUNTIME_INVALID_VALUE as CudaError);
                return wire::CUDA_ERROR_RUNTIME_INVALID_VALUE as CudaError;
            }
            CURRENT_DEVICE.with(|d| d.set(device));
            SUCCESS
        },
        wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaGetDevice(device: *mut c_int) -> CudaError {
    guard(
        move || {
            if device.is_null() {
                return wire::CUDA_ERROR_RUNTIME_INVALID_VALUE as CudaError;
            }
            // SAFETY: null-checked above.
            unsafe { *device = current_device() };
            SUCCESS
        },
        wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaSetDeviceFlags(flags: c_uint) -> CudaError {
    guard(
        move || {
            // Any flags the workload passes are accepted and ignored: the
            // endpoint owns scheduling. A zero flag is the common case.
            let _ = flags;
            SUCCESS
        },
        wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaMalloc(devptr: *mut *mut c_void, bytes: usize) -> CudaError {
    guard(
        move || {
            if devptr.is_null() {
                return wire::CUDA_ERROR_RUNTIME_INVALID_VALUE as CudaError;
            }
            let result = (|| -> Result<CudaError, CudaError> {
                let ctx = ensure_context()?;
                match call(&mvm_contract::protocol::gpu::GpuRequest::MemAlloc {
                    context: ctx,
                    bytes: bytes as u64,
                }) {
                    GpuResponse::DevicePointer { ptr } => {
                        // SAFETY: null-checked above.
                        unsafe { *devptr = ptr as *mut c_void };
                        Ok(SUCCESS)
                    }
                    GpuResponse::Err(e) => {
                        set_last_error(e.code as CudaError);
                        Ok(e.code as CudaError)
                    }
                    _ => Ok(wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError),
                }
            })();
            result.unwrap_or_else(|e| {
                set_last_error(e);
                e
            })
        },
        wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaFree(devptr: *mut c_void) -> CudaError {
    guard(
        move || {
            let code = (|| -> CudaError {
                let Ok(ctx) = ensure_context() else {
                    return wire::CUDA_ERROR_RUNTIME_INITIALIZATION as CudaError;
                };
                unit(call(&mvm_contract::protocol::gpu::GpuRequest::MemFree {
                    context: ctx,
                    ptr: devptr as u64,
                }))
            })();
            set_last_error(code);
            code
        },
        wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaMemcpy(
    dst: *mut c_void,
    src: *const c_void,
    count: usize,
    kind: c_int,
) -> CudaError {
    guard(
        move || {
            let result = (|| -> CudaError {
                match kind {
                    MEMCPY_HOST_TO_HOST => {
                        if (dst.is_null() || src.is_null()) && count > 0 {
                            return wire::CUDA_ERROR_RUNTIME_INVALID_VALUE as CudaError;
                        }
                        // SAFETY: the workload named both regions for a
                        // host-to-host copy of `count` bytes.
                        unsafe {
                            std::ptr::copy_nonoverlapping(src.cast::<u8>(), dst.cast::<u8>(), count)
                        };
                        SUCCESS
                    }
                    MEMCPY_HOST_TO_DEVICE => {
                        if (src.is_null() || dst.is_null()) && count > 0 {
                            return wire::CUDA_ERROR_RUNTIME_INVALID_VALUE as CudaError;
                        }
                        let Ok(ctx) = ensure_context() else {
                            return wire::CUDA_ERROR_RUNTIME_INITIALIZATION as CudaError;
                        };
                        // SAFETY: `src` is readable for `count` bytes (the
                        // workload supplied it as the copy source).
                        let data = unsafe { std::slice::from_raw_parts(src.cast::<u8>(), count) };
                        unit(call(&mvm_contract::protocol::gpu::GpuRequest::MemcpyHtoD {
                            context: ctx,
                            dst: dst as u64,
                            data: data.to_vec(),
                        }))
                    }
                    MEMCPY_DEVICE_TO_HOST => {
                        if (src.is_null() || dst.is_null()) && count > 0 {
                            return wire::CUDA_ERROR_RUNTIME_INVALID_VALUE as CudaError;
                        }
                        let Ok(ctx) = ensure_context() else {
                            return wire::CUDA_ERROR_RUNTIME_INITIALIZATION as CudaError;
                        };
                        match call(&mvm_contract::protocol::gpu::GpuRequest::MemcpyDtoH {
                            context: ctx,
                            src: src as u64,
                            len: count as u64,
                        }) {
                            GpuResponse::Data { bytes } => {
                                // SAFETY: the workload named `dst` as the
                                // destination of exactly this transfer.
                                unsafe {
                                    std::ptr::copy_nonoverlapping(
                                        bytes.as_ptr(),
                                        dst.cast::<u8>(),
                                        bytes.len(),
                                    )
                                };
                                SUCCESS
                            }
                            other => unit(other),
                        }
                    }
                    MEMCPY_DEVICE_TO_DEVICE => {
                        if (src.is_null() || dst.is_null()) && count > 0 {
                            return wire::CUDA_ERROR_RUNTIME_INVALID_VALUE as CudaError;
                        }
                        let Ok(ctx) = ensure_context() else {
                            return wire::CUDA_ERROR_RUNTIME_INITIALIZATION as CudaError;
                        };
                        // Read-then-write through the endpoint: two RPCs,
                        // one transaction shape the wire already knows.
                        match call(&mvm_contract::protocol::gpu::GpuRequest::MemcpyDtoH {
                            context: ctx,
                            src: src as u64,
                            len: count as u64,
                        }) {
                            GpuResponse::Data { bytes } => {
                                unit(call(&mvm_contract::protocol::gpu::GpuRequest::MemcpyHtoD {
                                    context: ctx,
                                    dst: dst as u64,
                                    data: bytes,
                                }))
                            }
                            other => unit(other),
                        }
                    }
                    _ => wire::CUDA_ERROR_RUNTIME_INVALID_MEMCPY_DIRECTION as CudaError,
                }
            })();
            set_last_error(result);
            result
        },
        wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the CUDA Runtime API contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaMemcpyAsync(
    dst: *mut c_void,
    src: *const c_void,
    count: usize,
    kind: c_int,
    stream: *mut c_void,
) -> CudaError {
    guard(
        move || {
            let result = (|| -> CudaError {
                if (dst.is_null() || src.is_null()) && count > 0 {
                    return wire::CUDA_ERROR_RUNTIME_INVALID_VALUE as CudaError;
                }
                if kind == MEMCPY_HOST_TO_HOST {
                    // SAFETY: the workload supplied both host regions.
                    unsafe {
                        std::ptr::copy_nonoverlapping(src.cast::<u8>(), dst.cast::<u8>(), count)
                    };
                    return SUCCESS;
                }
                let Ok(context) = ensure_context() else {
                    return wire::CUDA_ERROR_RUNTIME_INITIALIZATION as CudaError;
                };
                let stream = stream as u64;
                match kind {
                    MEMCPY_HOST_TO_DEVICE => {
                        // SAFETY: `src` is readable for `count` bytes.
                        let data = unsafe { std::slice::from_raw_parts(src.cast::<u8>(), count) };
                        queued(call(
                            &mvm_contract::protocol::gpu::GpuRequest::MemcpyHtoDAsync {
                                context,
                                dst: dst as u64,
                                data: data.to_vec(),
                                stream,
                            },
                        ))
                    }
                    MEMCPY_DEVICE_TO_HOST => {
                        match call(&mvm_contract::protocol::gpu::GpuRequest::MemcpyDtoHAsync {
                            context,
                            src: src as u64,
                            len: count as u64,
                            stream,
                        }) {
                            GpuResponse::DataQueued { bytes, .. } => {
                                // SAFETY: the workload supplied the destination.
                                unsafe {
                                    std::ptr::copy_nonoverlapping(
                                        bytes.as_ptr(),
                                        dst.cast::<u8>(),
                                        bytes.len(),
                                    )
                                };
                                SUCCESS
                            }
                            GpuResponse::Err(e) => e.code as CudaError,
                            _ => wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
                        }
                    }
                    MEMCPY_DEVICE_TO_DEVICE => {
                        match call(&mvm_contract::protocol::gpu::GpuRequest::MemcpyDtoHAsync {
                            context,
                            src: src as u64,
                            len: count as u64,
                            stream,
                        }) {
                            GpuResponse::DataQueued { bytes, .. } => queued(call(
                                &mvm_contract::protocol::gpu::GpuRequest::MemcpyHtoDAsync {
                                    context,
                                    dst: dst as u64,
                                    data: bytes,
                                    stream,
                                },
                            )),
                            GpuResponse::Err(e) => e.code as CudaError,
                            _ => wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
                        }
                    }
                    _ => wire::CUDA_ERROR_RUNTIME_INVALID_MEMCPY_DIRECTION as CudaError,
                }
            })();
            set_last_error(result);
            result
        },
        wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaMemset(ptr: *mut c_void, value: c_int, count: usize) -> CudaError {
    guard(
        move || {
            let result = (|| -> CudaError {
                let Ok(ctx) = ensure_context() else {
                    return wire::CUDA_ERROR_RUNTIME_INITIALIZATION as CudaError;
                };
                unit(call(&mvm_contract::protocol::gpu::GpuRequest::MemsetD8 {
                    context: ctx,
                    dst: ptr as u64,
                    value: value as u8,
                    len: count as u64,
                }))
            })();
            set_last_error(result);
            result
        },
        wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaDeviceSynchronize() -> CudaError {
    guard(
        move || {
            let result = (|| -> CudaError {
                let Ok(ctx) = ensure_context() else {
                    return wire::CUDA_ERROR_RUNTIME_INITIALIZATION as CudaError;
                };
                unit(call(
                    &mvm_contract::protocol::gpu::GpuRequest::Synchronize { context: ctx },
                ))
            })();
            set_last_error(result);
            result
        },
        wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    )
}

/// # Safety
/// `stream` must name writable storage for one runtime stream handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaStreamCreate(stream: *mut *mut c_void) -> CudaError {
    unsafe { cudaStreamCreateWithFlags(stream, 0) }
}

/// # Safety
/// `stream` must name writable storage for one runtime stream handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaStreamCreateWithFlags(
    stream: *mut *mut c_void,
    flags: c_uint,
) -> CudaError {
    guard(
        move || {
            if stream.is_null() {
                return wire::CUDA_ERROR_RUNTIME_INVALID_VALUE as CudaError;
            }
            let Ok(context) = ensure_context() else {
                return wire::CUDA_ERROR_RUNTIME_INITIALIZATION as CudaError;
            };
            match call(&mvm_contract::protocol::gpu::GpuRequest::StreamCreate { context, flags }) {
                GpuResponse::StreamCreated { stream: handle } => {
                    // SAFETY: null-checked above.
                    unsafe { *stream = handle as *mut c_void };
                    SUCCESS
                }
                GpuResponse::Err(e) => e.code as CudaError,
                _ => wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
            }
        },
        wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    )
}

/// # Safety
/// `stream` must be null or a handle returned by `cudaStreamCreate`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaStreamDestroy(stream: *mut c_void) -> CudaError {
    guard(
        move || {
            let Ok(context) = ensure_context() else {
                return wire::CUDA_ERROR_RUNTIME_INITIALIZATION as CudaError;
            };
            unit(call(
                &mvm_contract::protocol::gpu::GpuRequest::StreamDestroy {
                    context,
                    stream: stream as u64,
                },
            ))
        },
        wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    )
}

/// # Safety
/// `stream` must be null or a handle returned by `cudaStreamCreate`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaStreamSynchronize(stream: *mut c_void) -> CudaError {
    guard(
        move || {
            let Ok(context) = ensure_context() else {
                return wire::CUDA_ERROR_RUNTIME_INITIALIZATION as CudaError;
            };
            unit(call(
                &mvm_contract::protocol::gpu::GpuRequest::StreamSynchronize {
                    context,
                    stream: stream as u64,
                },
            ))
        },
        wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    )
}

/// # Safety
/// Both handles must have been created by this runtime context.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaStreamWaitEvent(
    stream: *mut c_void,
    event: *mut c_void,
    flags: c_uint,
) -> CudaError {
    guard(
        move || {
            if flags != 0 {
                return wire::CUDA_ERROR_RUNTIME_INVALID_VALUE as CudaError;
            }
            let Ok(context) = ensure_context() else {
                return wire::CUDA_ERROR_RUNTIME_INITIALIZATION as CudaError;
            };
            queued(call(
                &mvm_contract::protocol::gpu::GpuRequest::StreamWaitEvent {
                    context,
                    stream: stream as u64,
                    event: event as u64,
                },
            ))
        },
        wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    )
}

/// # Safety
/// `event` must name writable storage for one runtime event handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaEventCreate(event: *mut *mut c_void) -> CudaError {
    unsafe { cudaEventCreateWithFlags(event, 0) }
}

/// # Safety
/// `event` must name writable storage for one runtime event handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaEventCreateWithFlags(
    event: *mut *mut c_void,
    flags: c_uint,
) -> CudaError {
    guard(
        move || {
            if event.is_null() {
                return wire::CUDA_ERROR_RUNTIME_INVALID_VALUE as CudaError;
            }
            let Ok(context) = ensure_context() else {
                return wire::CUDA_ERROR_RUNTIME_INITIALIZATION as CudaError;
            };
            match call(&mvm_contract::protocol::gpu::GpuRequest::EventCreate { context, flags }) {
                GpuResponse::EventCreated { event: handle } => {
                    // SAFETY: null-checked above.
                    unsafe { *event = handle as *mut c_void };
                    SUCCESS
                }
                GpuResponse::Err(e) => e.code as CudaError,
                _ => wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
            }
        },
        wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    )
}

/// # Safety
/// `event` must be a handle returned by `cudaEventCreate`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaEventDestroy(event: *mut c_void) -> CudaError {
    guard(
        move || {
            let Ok(context) = ensure_context() else {
                return wire::CUDA_ERROR_RUNTIME_INITIALIZATION as CudaError;
            };
            unit(call(
                &mvm_contract::protocol::gpu::GpuRequest::EventDestroy {
                    context,
                    event: event as u64,
                },
            ))
        },
        wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    )
}

/// # Safety
/// Both handles must belong to this runtime context; null stream is default.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaEventRecord(event: *mut c_void, stream: *mut c_void) -> CudaError {
    guard(
        move || {
            let Ok(context) = ensure_context() else {
                return wire::CUDA_ERROR_RUNTIME_INITIALIZATION as CudaError;
            };
            queued(call(
                &mvm_contract::protocol::gpu::GpuRequest::EventRecord {
                    context,
                    event: event as u64,
                    stream: stream as u64,
                },
            ))
        },
        wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    )
}

/// # Safety
/// `event` must be a handle returned by `cudaEventCreate`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaEventQuery(event: *mut c_void) -> CudaError {
    guard(
        move || {
            let Ok(context) = ensure_context() else {
                return wire::CUDA_ERROR_RUNTIME_INITIALIZATION as CudaError;
            };
            match call(&mvm_contract::protocol::gpu::GpuRequest::EventQuery {
                context,
                event: event as u64,
            }) {
                GpuResponse::EventStatus { complete: true } => SUCCESS,
                GpuResponse::EventStatus { complete: false } => {
                    wire::CUDA_ERROR_RUNTIME_NOT_READY as CudaError
                }
                GpuResponse::Err(e) => e.code as CudaError,
                _ => wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
            }
        },
        wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    )
}

/// # Safety
/// `event` must be a handle returned by `cudaEventCreate`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaEventSynchronize(event: *mut c_void) -> CudaError {
    guard(
        move || {
            let Ok(context) = ensure_context() else {
                return wire::CUDA_ERROR_RUNTIME_INITIALIZATION as CudaError;
            };
            unit(call(
                &mvm_contract::protocol::gpu::GpuRequest::EventSynchronize {
                    context,
                    event: event as u64,
                },
            ))
        },
        wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaGetLastError() -> CudaError {
    guard(last_error, wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError)
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaPeekAtLastError() -> CudaError {
    guard(
        move || LAST_ERROR.with(Cell::get),
        wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaGetErrorString(error: CudaError) -> *const c_char {
    // Infallible by contract (returns a static pointer); guard anyway.
    guard(
        move || {
            use std::ffi::CStr;
            let text: &'static CStr = match error {
                SUCCESS => c"no error",
                e if e == wire::CUDA_ERROR_RUNTIME_INVALID_VALUE => c"invalid argument",
                e if e == wire::CUDA_ERROR_RUNTIME_MEMORY_ALLOCATION => c"out of memory",
                e if e == wire::CUDA_ERROR_RUNTIME_INITIALIZATION => c"initialization error",
                e if e == wire::CUDA_ERROR_RUNTIME_NO_DEVICE => {
                    c"no CUDA-capable device is available"
                }
                e if e == wire::CUDA_ERROR_RUNTIME_NOT_READY => c"operation not ready",
                e if e == wire::CUDA_ERROR_RUNTIME_NOT_SUPPORTED => c"operation not supported",
                _ => c"unknown error",
            };
            text.as_ptr()
        },
        c"unknown error".as_ptr(),
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaRuntimeGetVersion(version: *mut c_int) -> CudaError {
    guard(
        move || {
            if version.is_null() {
                return wire::CUDA_ERROR_RUNTIME_INVALID_VALUE as CudaError;
            }
            // The wire protocol version the shim speaks, in CUDA's
            // version encoding (major * 1000 + minor * 10).
            // SAFETY: null-checked above.
            unsafe { *version = 12_040 };
            SUCCESS
        },
        wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cudaDriverGetVersion(version: *mut c_int) -> CudaError {
    guard(
        move || {
            if version.is_null() {
                return wire::CUDA_ERROR_RUNTIME_INVALID_VALUE as CudaError;
            }
            match call(&mvm_contract::protocol::gpu::GpuRequest::DriverGetVersion) {
                GpuResponse::DriverVersion { version: v } => {
                    // SAFETY: null-checked above.
                    unsafe { *version = v };
                    SUCCESS
                }
                GpuResponse::Err(e) => e.code as CudaError,
                _ => wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
            }
        },
        wire::CUDA_ERROR_RUNTIME_UNKNOWN as CudaError,
    )
}
