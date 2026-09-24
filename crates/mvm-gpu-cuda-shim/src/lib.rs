//! Drop-in `libcuda.so.1` replacement for an mvm guest.
//!
//! Every exported symbol implements the CUDA Driver API by forwarding over
//! vsock to the host GPU endpoint (`mvm-gpu-shim-core::call`). The workload
//! links `libcuda.so.1` exactly as it would the real library; nothing in
//! the guest carries a driver or a device node.
//!
//! v1 ABI coverage and the deliberate limits (no PTX-param launches)
//! are documented in `specs/plans/2026-09-20-gpu-over-vsock.md`.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::Mutex;

use mvm_contract::protocol::gpu::GpuResponse;
use mvm_gpu_shim_core::{call, guard, wire, write_cstr};

use libc::{c_char, c_int, c_uchar, c_uint, c_ulonglong, c_void};

/// `CUresult` — the shim returns the host endpoint's numeric code verbatim.
type CuResult = c_int;
/// Opaque context/module/function handles, as the guest sees them: the
/// same u64 the endpoint minted, cast through a pointer.
type Handle = *mut c_void;

const SUCCESS: CuResult = wire::SUCCESS as CuResult;

// ---------------------------------------------------------------------------
// Per-process shim state
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct FunctionMeta {
    module: u64,
    #[expect(dead_code, reason = "kept for diagnostics and future param reflection")]
    name: String,
    /// Parameter sizes recovered from the PTX image at lookup time; `None`
    /// when the image carries no parseable metadata (launches then refuse
    /// rather than guess).
    param_sizes: Option<Vec<usize>>,
}

thread_local! {
    /// The context this thread last created or set current — the shadow of
    /// the endpoint's own current-context tracking, so
    /// `cuCtxGetCurrent`/`cuCtxSetCurrent` resolve locally.
    static CURRENT_CTX: Cell<u64> = const { Cell::new(0) };
}

/// Module images by module handle, for PTX param-size recovery.
fn modules() -> &'static Mutex<HashMap<u64, Vec<u8>>> {
    static MODULES: std::sync::OnceLock<Mutex<HashMap<u64, Vec<u8>>>> = std::sync::OnceLock::new();
    MODULES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Function metadata by function handle.
fn functions() -> &'static Mutex<HashMap<u64, FunctionMeta>> {
    static FUNCTIONS: std::sync::OnceLock<Mutex<HashMap<u64, FunctionMeta>>> =
        std::sync::OnceLock::new();
    FUNCTIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn set_current_ctx(handle: u64) {
    CURRENT_CTX.with(|c| c.set(handle));
}

fn current_ctx() -> u64 {
    CURRENT_CTX.with(Cell::get)
}

/// Unpack a response that carries only success-or-error.
fn unit(response: GpuResponse) -> CuResult {
    match response {
        GpuResponse::Ok => SUCCESS,
        GpuResponse::Err(e) => e.code as CuResult,
        _other => wire::CUDA_ERROR_UNKNOWN as CuResult,
    }
}

fn queued(response: GpuResponse) -> CuResult {
    match response {
        GpuResponse::AsyncQueued { .. } => SUCCESS,
        GpuResponse::Err(e) => e.code as CuResult,
        _ => unexpected(),
    }
}

/// The generic error result for an unexpected response shape.
fn unexpected() -> CuResult {
    wire::CUDA_ERROR_UNKNOWN as CuResult
}

/// Read `len` bytes of guest memory into a owned blob.
///
/// # Safety
/// `ptr` must be readable for `len` bytes — the caller only passes pointers
/// the workload itself supplied to the API call.
unsafe fn read_guest_bytes(ptr: *const c_void, len: usize) -> Option<Vec<u8>> {
    if len == 0 {
        return Some(Vec::new());
    }
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the contract above; the slice is immediately copied out.
    let slice = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) };
    Some(slice.to_vec())
}

/// Determine a module image's byte length from a guest pointer: ELF images
/// bound themselves via the section-header table; anything else is treated
/// as NUL-terminated PTX text.
///
/// # Safety
/// `ptr` must be readable — the workload supplied it to `cuModuleLoadData`.
unsafe fn image_len(ptr: *const c_void) -> Option<usize> {
    if ptr.is_null() {
        return None;
    }
    const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
    // SAFETY: 16 bytes is inside every ELF header and every plausible text
    // pointer target here — but a hostile value can still fault, which is
    // the workload faulting on its own pointer, not a shim defect.
    let head = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), 16) };
    if head[..4] == ELF_MAGIC && head[4] == 2 {
        // ELF64: e_shoff u64 @ 0x28, e_shentsize u16 @ 0x3a, e_shnum u16 @ 0x3c.
        // SAFETY: same pointer contract.
        const ELF64_HEADER_LEN: usize = 0x40;
        let header = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), ELF64_HEADER_LEN) };
        if header.len() < 0x3e {
            return None;
        }
        let shoff = u64::from_le_bytes(header[0x28..0x30].try_into().ok()?) as usize;
        let shentsize = u16::from_le_bytes(header[0x3a..0x3c].try_into().ok()?) as usize;
        let shnum = u16::from_le_bytes(header[0x3c..0x3e].try_into().ok()?) as usize;
        shoff.checked_add(shentsize.checked_mul(shnum)?)
    } else {
        // SAFETY: NUL-terminated text per the CUDA contract.
        let text = unsafe { std::ffi::CStr::from_ptr(ptr.cast::<c_char>()) };
        Some(text.to_bytes().len())
    }
}

// ---------------------------------------------------------------------------
// Exported Driver API
// ---------------------------------------------------------------------------

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuInit(flags: c_uint) -> CuResult {
    guard(
        move || {
            if flags != 0 {
                return wire::CUDA_ERROR_INVALID_VALUE as CuResult;
            }
            // A liveness round trip: the endpoint answers DeviceGetCount or
            // an error that tells the workload what is wrong.
            match call(&mvm_contract::protocol::gpu::GpuRequest::DeviceGetCount) {
                GpuResponse::DeviceCount { .. } => SUCCESS,
                GpuResponse::Err(e) => e.code as CuResult,
                _ => unexpected(),
            }
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuDriverGetVersion(version: *mut c_int) -> CuResult {
    guard(
        move || {
            if version.is_null() {
                return wire::CUDA_ERROR_INVALID_VALUE as CuResult;
            }
            match call(&mvm_contract::protocol::gpu::GpuRequest::DriverGetVersion) {
                GpuResponse::DriverVersion { version: v } => {
                    // SAFETY: null-checked above.
                    unsafe { *version = v };
                    SUCCESS
                }
                GpuResponse::Err(e) => e.code as CuResult,
                _ => unexpected(),
            }
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuDeviceGetCount(count: *mut c_int) -> CuResult {
    guard(
        move || {
            if count.is_null() {
                return wire::CUDA_ERROR_INVALID_VALUE as CuResult;
            }
            match call(&mvm_contract::protocol::gpu::GpuRequest::DeviceGetCount) {
                GpuResponse::DeviceCount { count: n } => {
                    // SAFETY: null-checked above.
                    unsafe { *count = n as c_int };
                    SUCCESS
                }
                GpuResponse::Err(e) => e.code as CuResult,
                _ => unexpected(),
            }
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuDeviceGet(device: *mut c_int, ordinal: c_int) -> CuResult {
    guard(
        move || {
            if device.is_null() || ordinal < 0 {
                return wire::CUDA_ERROR_INVALID_VALUE as CuResult;
            }
            // The endpoint validates the ordinal against its device count.
            match call(&mvm_contract::protocol::gpu::GpuRequest::DeviceGetCount) {
                GpuResponse::DeviceCount { count } => {
                    if ordinal as u32 >= count {
                        return wire::CUDA_ERROR_INVALID_DEVICE as CuResult;
                    }
                    // SAFETY: null-checked above.
                    unsafe { *device = ordinal };
                    SUCCESS
                }
                GpuResponse::Err(e) => e.code as CuResult,
                _ => unexpected(),
            }
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuDeviceGetName(
    name: *mut c_char,
    len: c_int,
    ordinal: c_int,
) -> CuResult {
    guard(
        move || {
            if name.is_null() || len <= 0 || ordinal < 0 {
                return wire::CUDA_ERROR_INVALID_VALUE as CuResult;
            }
            match call(&mvm_contract::protocol::gpu::GpuRequest::DeviceGetName {
                ordinal: ordinal as u32,
            }) {
                GpuResponse::DeviceName { name: n } => {
                    if unsafe { write_cstr(name, len as usize, &n) } {
                        SUCCESS
                    } else {
                        wire::CUDA_ERROR_INVALID_VALUE as CuResult
                    }
                }
                GpuResponse::Err(e) => e.code as CuResult,
                _ => unexpected(),
            }
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuDeviceTotalMem(bytes: *mut usize, ordinal: c_int) -> CuResult {
    guard(
        move || {
            if bytes.is_null() || ordinal < 0 {
                return wire::CUDA_ERROR_INVALID_VALUE as CuResult;
            }
            match call(&mvm_contract::protocol::gpu::GpuRequest::DeviceTotalMem {
                ordinal: ordinal as u32,
            }) {
                GpuResponse::DeviceTotalMem { bytes: n } => {
                    // SAFETY: null-checked above.
                    unsafe { *bytes = n as usize };
                    SUCCESS
                }
                GpuResponse::Err(e) => e.code as CuResult,
                _ => unexpected(),
            }
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuCtxCreate(pctx: *mut Handle, flags: c_uint, ordinal: c_int) -> CuResult {
    guard(
        move || {
            if pctx.is_null() {
                return wire::CUDA_ERROR_INVALID_VALUE as CuResult;
            }
            if flags != 0 {
                return wire::CUDA_ERROR_NOT_SUPPORTED as CuResult;
            }
            match call(&mvm_contract::protocol::gpu::GpuRequest::ContextCreate {
                ordinal: ordinal as u32,
            }) {
                GpuResponse::ContextCreated { context } => {
                    set_current_ctx(context);
                    // SAFETY: null-checked above.
                    unsafe { *pctx = context as Handle };
                    SUCCESS
                }
                GpuResponse::Err(e) => e.code as CuResult,
                _ => unexpected(),
            }
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuCtxDestroy(ctx: Handle) -> CuResult {
    guard(
        move || {
            if ctx.is_null() {
                return wire::CUDA_ERROR_INVALID_CONTEXT as CuResult;
            }
            let result = unit(call(
                &mvm_contract::protocol::gpu::GpuRequest::ContextDestroy {
                    context: ctx as u64,
                },
            ));
            if result == SUCCESS && current_ctx() == ctx as u64 {
                set_current_ctx(0);
            }
            result
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuCtxSetCurrent(ctx: Handle) -> CuResult {
    guard(
        move || {
            // The endpoint re-validates the handle on every call; here we
            // only track which context this thread believes is current.
            // Null clears it, per the CUDA contract.
            set_current_ctx(ctx as u64);
            SUCCESS
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuCtxGetCurrent(pctx: *mut Handle) -> CuResult {
    guard(
        move || {
            if pctx.is_null() {
                return wire::CUDA_ERROR_INVALID_VALUE as CuResult;
            }
            // SAFETY: null-checked above.
            unsafe { *pctx = current_ctx() as Handle };
            SUCCESS
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuMemAlloc(devptr: *mut u64, bytes: usize) -> CuResult {
    guard(
        move || {
            if devptr.is_null() {
                return wire::CUDA_ERROR_INVALID_VALUE as CuResult;
            }
            let ctx = current_ctx();
            if ctx == 0 {
                return wire::CUDA_ERROR_INVALID_CONTEXT as CuResult;
            }
            match call(&mvm_contract::protocol::gpu::GpuRequest::MemAlloc {
                context: ctx,
                bytes: bytes as u64,
            }) {
                GpuResponse::DevicePointer { ptr } => {
                    // SAFETY: null-checked above.
                    unsafe { *devptr = ptr };
                    SUCCESS
                }
                GpuResponse::Err(e) => e.code as CuResult,
                _ => unexpected(),
            }
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuMemFree(devptr: u64) -> CuResult {
    guard(
        move || {
            let ctx = current_ctx();
            if ctx == 0 {
                return wire::CUDA_ERROR_INVALID_CONTEXT as CuResult;
            }
            unit(call(&mvm_contract::protocol::gpu::GpuRequest::MemFree {
                context: ctx,
                ptr: devptr,
            }))
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuMemcpyHtoD(dst: u64, src: *const c_void, bytes: usize) -> CuResult {
    guard(
        move || {
            let ctx = current_ctx();
            if ctx == 0 {
                return wire::CUDA_ERROR_INVALID_CONTEXT as CuResult;
            }
            let Some(data) = (unsafe { read_guest_bytes(src, bytes) }) else {
                return wire::CUDA_ERROR_INVALID_VALUE as CuResult;
            };
            unit(call(&mvm_contract::protocol::gpu::GpuRequest::MemcpyHtoD {
                context: ctx,
                dst,
                data,
            }))
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuMemcpyDtoH(dst: *mut c_void, src: u64, bytes: usize) -> CuResult {
    guard(
        move || {
            if dst.is_null() && bytes > 0 {
                return wire::CUDA_ERROR_INVALID_VALUE as CuResult;
            }
            let ctx = current_ctx();
            if ctx == 0 {
                return wire::CUDA_ERROR_INVALID_CONTEXT as CuResult;
            }
            match call(&mvm_contract::protocol::gpu::GpuRequest::MemcpyDtoH {
                context: ctx,
                src,
                len: bytes as u64,
            }) {
                GpuResponse::Data { bytes: data } => {
                    // SAFETY: the workload supplied `dst` for exactly this
                    // transfer; its length matches what we asked for.
                    unsafe {
                        std::ptr::copy_nonoverlapping(data.as_ptr(), dst.cast::<u8>(), data.len())
                    };
                    SUCCESS
                }
                GpuResponse::Err(e) => e.code as CuResult,
                _ => unexpected(),
            }
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the CUDA Driver API contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuMemcpyHtoDAsync(
    dst: u64,
    src: *const c_void,
    bytes: usize,
    stream: Handle,
) -> CuResult {
    guard(
        move || {
            let ctx = current_ctx();
            if ctx == 0 {
                return wire::CUDA_ERROR_INVALID_CONTEXT as CuResult;
            }
            let Some(data) = (unsafe { read_guest_bytes(src, bytes) }) else {
                return wire::CUDA_ERROR_INVALID_VALUE as CuResult;
            };
            queued(call(
                &mvm_contract::protocol::gpu::GpuRequest::MemcpyHtoDAsync {
                    context: ctx,
                    dst,
                    data,
                    stream: stream as u64,
                },
            ))
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the CUDA Driver API contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuMemcpyDtoHAsync(
    dst: *mut c_void,
    src: u64,
    bytes: usize,
    stream: Handle,
) -> CuResult {
    guard(
        move || {
            if dst.is_null() && bytes > 0 {
                return wire::CUDA_ERROR_INVALID_VALUE as CuResult;
            }
            let ctx = current_ctx();
            if ctx == 0 {
                return wire::CUDA_ERROR_INVALID_CONTEXT as CuResult;
            }
            match call(&mvm_contract::protocol::gpu::GpuRequest::MemcpyDtoHAsync {
                context: ctx,
                src,
                len: bytes as u64,
                stream: stream as u64,
            }) {
                GpuResponse::DataQueued { bytes, .. } => {
                    // SAFETY: the caller supplied a destination for this transfer.
                    unsafe {
                        std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst.cast::<u8>(), bytes.len())
                    };
                    SUCCESS
                }
                GpuResponse::Err(e) => e.code as CuResult,
                _ => unexpected(),
            }
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

/// # Safety
/// Same contract as [`cuMemcpyHtoDAsync`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuMemcpyHtoDAsync_v2(
    dst: u64,
    src: *const c_void,
    bytes: usize,
    stream: Handle,
) -> CuResult {
    unsafe { cuMemcpyHtoDAsync(dst, src, bytes, stream) }
}

/// # Safety
/// Same contract as [`cuMemcpyDtoHAsync`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuMemcpyDtoHAsync_v2(
    dst: *mut c_void,
    src: u64,
    bytes: usize,
    stream: Handle,
) -> CuResult {
    unsafe { cuMemcpyDtoHAsync(dst, src, bytes, stream) }
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuMemsetD8(dst: u64, value: c_uchar, bytes: usize) -> CuResult {
    guard(
        move || {
            let ctx = current_ctx();
            if ctx == 0 {
                return wire::CUDA_ERROR_INVALID_CONTEXT as CuResult;
            }
            unit(call(&mvm_contract::protocol::gpu::GpuRequest::MemsetD8 {
                context: ctx,
                dst,
                value,
                len: bytes as u64,
            }))
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuModuleLoadData(module: *mut Handle, image: *const c_void) -> CuResult {
    guard(
        move || {
            if module.is_null() {
                return wire::CUDA_ERROR_INVALID_VALUE as CuResult;
            }
            let Some(len) = (unsafe { image_len(image) }) else {
                return wire::CUDA_ERROR_INVALID_IMAGE as CuResult;
            };
            let Some(image_bytes) = (unsafe { read_guest_bytes(image, len) }) else {
                return wire::CUDA_ERROR_INVALID_IMAGE as CuResult;
            };
            let ctx = current_ctx();
            if ctx == 0 {
                return wire::CUDA_ERROR_INVALID_CONTEXT as CuResult;
            }
            match call(&mvm_contract::protocol::gpu::GpuRequest::ModuleLoad {
                context: ctx,
                image: image_bytes.clone(),
            }) {
                GpuResponse::ModuleLoaded { module: handle } => {
                    if let Ok(mut modules) = modules().lock() {
                        modules.insert(handle, image_bytes);
                    }
                    // SAFETY: null-checked above.
                    unsafe { *module = handle as Handle };
                    SUCCESS
                }
                GpuResponse::Err(e) => e.code as CuResult,
                _ => unexpected(),
            }
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuModuleUnload(module: Handle) -> CuResult {
    guard(
        move || {
            let ctx = current_ctx();
            if ctx == 0 {
                return wire::CUDA_ERROR_INVALID_CONTEXT as CuResult;
            }
            let result = unit(call(
                &mvm_contract::protocol::gpu::GpuRequest::ModuleUnload {
                    context: ctx,
                    module: module as u64,
                },
            ));
            if result == SUCCESS {
                if let Ok(mut modules) = modules().lock() {
                    modules.remove(&(module as u64));
                }
                if let Ok(mut functions) = functions().lock() {
                    functions.retain(|_, meta| meta.module != module as u64);
                }
            }
            result
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuModuleGetFunction(
    function: *mut Handle,
    module: Handle,
    name: *const c_char,
) -> CuResult {
    guard(
        move || {
            if function.is_null() || name.is_null() {
                return wire::CUDA_ERROR_INVALID_VALUE as CuResult;
            }
            // SAFETY: the workload supplied `name` as a C string.
            let name_str = unsafe { std::ffi::CStr::from_ptr(name) };
            let Ok(name_owned) = name_str.to_str().map(str::to_string) else {
                return wire::CUDA_ERROR_INVALID_VALUE as CuResult;
            };
            let ctx = current_ctx();
            if ctx == 0 {
                return wire::CUDA_ERROR_INVALID_CONTEXT as CuResult;
            }
            match call(
                &mvm_contract::protocol::gpu::GpuRequest::ModuleGetFunction {
                    context: ctx,
                    module: module as u64,
                    name: name_owned.clone(),
                },
            ) {
                GpuResponse::Function { handle } => {
                    let image = modules()
                        .lock()
                        .ok()
                        .and_then(|modules| modules.get(&(module as u64)).cloned());
                    let param_sizes = image.as_deref().and_then(|bytes| {
                        mvm_gpu_shim_core::ptx_entry_param_sizes(bytes, &name_owned)
                    });
                    if let Ok(mut functions) = functions().lock() {
                        functions.insert(
                            handle,
                            FunctionMeta {
                                module: module as u64,
                                name: name_owned,
                                param_sizes,
                            },
                        );
                    }
                    // SAFETY: null-checked above.
                    unsafe { *function = handle as Handle };
                    SUCCESS
                }
                GpuResponse::Err(e) => e.code as CuResult,
                _ => unexpected(),
            }
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

/// The body of `cuLaunchKernel`, carried as one value so the exported
/// function stays a thin ABI adapter.
struct LaunchArgs {
    function: Handle,
    grid: [c_uint; 3],
    block: [c_uint; 3],
    shared_mem_bytes: c_uint,
    stream: *mut c_void,
    kernel_params: *const *mut c_void,
    extra: *const *mut c_void,
}

fn launch_kernel(args: LaunchArgs) -> CuResult {
    let LaunchArgs {
        function,
        grid,
        block,
        shared_mem_bytes,
        stream,
        kernel_params,
        extra,
    } = args;
    {
        if !extra.is_null() {
            return wire::CUDA_ERROR_NOT_SUPPORTED as CuResult;
        }
        let ctx = current_ctx();
        if ctx == 0 {
            return wire::CUDA_ERROR_INVALID_CONTEXT as CuResult;
        }
        let meta = functions()
            .lock()
            .ok()
            .and_then(|functions| functions.get(&(function as u64)).cloned());
        let Some(meta) = meta else {
            return wire::CUDA_ERROR_INVALID_HANDLE as CuResult;
        };
        let Some(sizes) = meta.param_sizes else {
            // No param metadata (non-PTX image): refuse rather than
            // guess how many bytes each parameter is.
            return wire::CUDA_ERROR_NOT_SUPPORTED as CuResult;
        };
        if sizes.is_empty() && kernel_params.is_null() {
            // Valid: a no-parameter kernel launched with no array.
        } else if kernel_params.is_null() {
            return wire::CUDA_ERROR_INVALID_VALUE as CuResult;
        }
        let mut params: Vec<Vec<u8>> = Vec::with_capacity(sizes.len());
        for (i, size) in sizes.iter().enumerate() {
            // SAFETY: the workload supplied `kernel_params` as an array
            // of at least `sizes.len()` pointers; entry i names a
            // readable `size`-byte argument.
            let arg_ptr = unsafe { *kernel_params.add(i) };
            let Some(blob) = (unsafe { read_guest_bytes(arg_ptr, *size) }) else {
                return wire::CUDA_ERROR_INVALID_VALUE as CuResult;
            };
            params.push(blob);
        }
        unit(call(
            &mvm_contract::protocol::gpu::GpuRequest::LaunchKernel {
                context: ctx,
                function: function as u64,
                grid,
                block,
                shared_mem_bytes,
                stream: (!stream.is_null()).then_some(stream as u64),
                params,
            },
        ))
    }
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuLaunchKernel(
    function: Handle,
    grid_x: c_uint,
    grid_y: c_uint,
    grid_z: c_uint,
    block_x: c_uint,
    block_y: c_uint,
    block_z: c_uint,
    shared_mem_bytes: c_uint,
    stream: *mut c_void,
    kernel_params: *const *mut c_void,
    extra: *const *mut c_void,
) -> CuResult {
    // The 11-argument shape is the CUDA driver ABI itself: a workload's
    // binary calls exactly this signature, so it cannot be restructured
    // into fewer parameters. The work rides `LaunchArgs` instead.
    let args = LaunchArgs {
        function,
        grid: [grid_x, grid_y, grid_z],
        block: [block_x, block_y, block_z],
        shared_mem_bytes,
        stream,
        kernel_params,
        extra,
    };
    guard(
        move || launch_kernel(args),
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuCtxSynchronize() -> CuResult {
    guard(
        move || {
            let ctx = current_ctx();
            if ctx == 0 {
                return wire::CUDA_ERROR_INVALID_CONTEXT as CuResult;
            }
            unit(call(
                &mvm_contract::protocol::gpu::GpuRequest::Synchronize { context: ctx },
            ))
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

///
/// # Safety
/// `stream` must name writable storage for one CUDA stream handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuStreamCreate(stream: *mut Handle, flags: c_uint) -> CuResult {
    guard(
        move || {
            if stream.is_null() {
                return wire::CUDA_ERROR_INVALID_VALUE as CuResult;
            }
            let ctx = current_ctx();
            if ctx == 0 {
                return wire::CUDA_ERROR_INVALID_CONTEXT as CuResult;
            }
            match call(&mvm_contract::protocol::gpu::GpuRequest::StreamCreate {
                context: ctx,
                flags,
            }) {
                GpuResponse::StreamCreated { stream: handle } => {
                    // SAFETY: null-checked above.
                    unsafe { *stream = handle as Handle };
                    SUCCESS
                }
                GpuResponse::Err(e) => e.code as CuResult,
                _ => unexpected(),
            }
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

/// # Safety
/// `stream` must be a handle returned by `cuStreamCreate`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuStreamDestroy_v2(stream: Handle) -> CuResult {
    guard(
        move || {
            let ctx = current_ctx();
            if ctx == 0 {
                return wire::CUDA_ERROR_INVALID_CONTEXT as CuResult;
            }
            unit(call(
                &mvm_contract::protocol::gpu::GpuRequest::StreamDestroy {
                    context: ctx,
                    stream: stream as u64,
                },
            ))
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

/// # Safety
/// Same contract as [`cuStreamDestroy_v2`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuStreamDestroy(stream: Handle) -> CuResult {
    unsafe { cuStreamDestroy_v2(stream) }
}

/// # Safety
/// `stream` must be null or a handle returned by `cuStreamCreate`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuStreamSynchronize(stream: Handle) -> CuResult {
    guard(
        move || {
            let ctx = current_ctx();
            if ctx == 0 {
                return wire::CUDA_ERROR_INVALID_CONTEXT as CuResult;
            }
            unit(call(
                &mvm_contract::protocol::gpu::GpuRequest::StreamSynchronize {
                    context: ctx,
                    stream: stream as u64,
                },
            ))
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

/// # Safety
/// Both handles must have been returned by this shim for the current context.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuStreamWaitEvent(
    stream: Handle,
    event: Handle,
    flags: c_uint,
) -> CuResult {
    guard(
        move || {
            if flags != 0 {
                return wire::CUDA_ERROR_INVALID_VALUE as CuResult;
            }
            let ctx = current_ctx();
            if ctx == 0 {
                return wire::CUDA_ERROR_INVALID_CONTEXT as CuResult;
            }
            queued(call(
                &mvm_contract::protocol::gpu::GpuRequest::StreamWaitEvent {
                    context: ctx,
                    stream: stream as u64,
                    event: event as u64,
                },
            ))
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

/// # Safety
/// `event` must name writable storage for one CUDA event handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuEventCreate(event: *mut Handle, flags: c_uint) -> CuResult {
    guard(
        move || {
            if event.is_null() {
                return wire::CUDA_ERROR_INVALID_VALUE as CuResult;
            }
            let ctx = current_ctx();
            if ctx == 0 {
                return wire::CUDA_ERROR_INVALID_CONTEXT as CuResult;
            }
            match call(&mvm_contract::protocol::gpu::GpuRequest::EventCreate {
                context: ctx,
                flags,
            }) {
                GpuResponse::EventCreated { event: handle } => {
                    // SAFETY: null-checked above.
                    unsafe { *event = handle as Handle };
                    SUCCESS
                }
                GpuResponse::Err(e) => e.code as CuResult,
                _ => unexpected(),
            }
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

/// # Safety
/// `event` must be a handle returned by `cuEventCreate`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuEventDestroy_v2(event: Handle) -> CuResult {
    guard(
        move || {
            let ctx = current_ctx();
            if ctx == 0 {
                return wire::CUDA_ERROR_INVALID_CONTEXT as CuResult;
            }
            unit(call(
                &mvm_contract::protocol::gpu::GpuRequest::EventDestroy {
                    context: ctx,
                    event: event as u64,
                },
            ))
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

/// # Safety
/// Same contract as [`cuEventDestroy_v2`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuEventDestroy(event: Handle) -> CuResult {
    unsafe { cuEventDestroy_v2(event) }
}

/// # Safety
/// `event` and `stream` must belong to the current context; null stream is default.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuEventRecord(event: Handle, stream: Handle) -> CuResult {
    guard(
        move || {
            let ctx = current_ctx();
            if ctx == 0 {
                return wire::CUDA_ERROR_INVALID_CONTEXT as CuResult;
            }
            queued(call(
                &mvm_contract::protocol::gpu::GpuRequest::EventRecord {
                    context: ctx,
                    event: event as u64,
                    stream: stream as u64,
                },
            ))
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

/// # Safety
/// `event` must be a handle returned by `cuEventCreate`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuEventQuery(event: Handle) -> CuResult {
    guard(
        move || {
            let ctx = current_ctx();
            if ctx == 0 {
                return wire::CUDA_ERROR_INVALID_CONTEXT as CuResult;
            }
            match call(&mvm_contract::protocol::gpu::GpuRequest::EventQuery {
                context: ctx,
                event: event as u64,
            }) {
                GpuResponse::EventStatus { complete: true } => SUCCESS,
                GpuResponse::EventStatus { complete: false } => {
                    wire::CUDA_ERROR_NOT_READY as CuResult
                }
                GpuResponse::Err(e) => e.code as CuResult,
                _ => unexpected(),
            }
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

/// # Safety
/// `event` must be a handle returned by `cuEventCreate`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuEventSynchronize(event: Handle) -> CuResult {
    guard(
        move || {
            let ctx = current_ctx();
            if ctx == 0 {
                return wire::CUDA_ERROR_INVALID_CONTEXT as CuResult;
            }
            unit(call(
                &mvm_contract::protocol::gpu::GpuRequest::EventSynchronize {
                    context: ctx,
                    event: event as u64,
                },
            ))
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

///
/// # Safety
/// Pointer arguments must satisfy the API contract for this call — valid,
/// correctly sized out-buffers — and are named by the workload itself,
/// exactly as they would be against the real library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuGetErrorString(code: CuResult, message: *mut *const c_char) -> CuResult {
    guard(
        move || {
            if message.is_null() {
                return wire::CUDA_ERROR_INVALID_VALUE as CuResult;
            }
            let text: &'static str = match code {
                wire::SUCCESS => "no error",
                wire::CUDA_ERROR_INVALID_VALUE => "invalid argument",
                wire::CUDA_ERROR_OUT_OF_MEMORY => "out of memory",
                wire::CUDA_ERROR_NOT_INITIALIZED => "driver not initialized",
                wire::CUDA_ERROR_NO_DEVICE => "no CUDA-capable device available",
                wire::CUDA_ERROR_INVALID_DEVICE => "invalid device ordinal",
                wire::CUDA_ERROR_INVALID_CONTEXT => "invalid context",
                wire::CUDA_ERROR_INVALID_IMAGE => "invalid module image",
                wire::CUDA_ERROR_INVALID_HANDLE => "invalid handle",
                wire::CUDA_ERROR_NOT_FOUND => "named symbol not found",
                wire::CUDA_ERROR_NOT_READY => "operation not ready",
                wire::CUDA_ERROR_NOT_SUPPORTED => "operation not supported",
                _ => "unknown error",
            };
            // SAFETY: `message` is a valid out-pointer for one pointer; the
            // text is a 'static string that outlives every call.
            unsafe { *message = text.as_ptr().cast::<c_char>() };

            SUCCESS
        },
        wire::CUDA_ERROR_UNKNOWN as CuResult,
    )
}

// ---------------------------------------------------------------------------
// cuGetProcAddress resolution
//
// CUDA 12 cudart, torch, and vLLM resolve driver entry points through
// `cuGetProcAddress` rather than linking the versioned aliases directly. The
// resolver answers every symbol this shim implements — under both its base
// name and the versioned alias the real driver serves (e.g. `cuMemAlloc`
// answers as `cuMemAlloc_v2`) — and refuses everything else with
// `CUDA_ERROR_NOT_FOUND`, which is how the real driver reports a symbol it
// does not carry. Per-thread-default-stream (`*_ptsz`) variants are out of
// v1 scope: the flags argument is accepted and ignored, and stream-flagged
// lookups receive the base entry point.
// ---------------------------------------------------------------------------

/// `(name, address)` pairs for every implemented entry point, base names and
/// versioned aliases alike. Kept in one table so the test can assert the
/// resolver and the exported symbol set agree.
/// `(name, address)` pairs for every implemented entry point, base names and
/// versioned aliases alike. Kept in one table so the test can assert the
/// resolver and the exported symbol set agree. Built lazily: casting a
/// function address to an integer is not allowed in const eval, and the
/// table only needs to exist once per process.
fn resolver_table() -> &'static [(&'static str, usize)] {
    static TABLE: std::sync::OnceLock<Vec<(&'static str, usize)>> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        vec![
            ("cuInit", cuInit as *const () as usize),
            (
                "cuDriverGetVersion",
                cuDriverGetVersion as *const () as usize,
            ),
            ("cuDeviceGetCount", cuDeviceGetCount as *const () as usize),
            ("cuDeviceGet", cuDeviceGet as *const () as usize),
            ("cuDeviceGetName", cuDeviceGetName as *const () as usize),
            ("cuDeviceTotalMem", cuDeviceTotalMem as *const () as usize),
            (
                "cuDeviceTotalMem_v2",
                cuDeviceTotalMem as *const () as usize,
            ),
            ("cuCtxCreate", cuCtxCreate as *const () as usize),
            ("cuCtxCreate_v2", cuCtxCreate as *const () as usize),
            ("cuCtxDestroy", cuCtxDestroy as *const () as usize),
            ("cuCtxDestroy_v2", cuCtxDestroy as *const () as usize),
            ("cuCtxSetCurrent", cuCtxSetCurrent as *const () as usize),
            ("cuCtxGetCurrent", cuCtxGetCurrent as *const () as usize),
            ("cuMemAlloc", cuMemAlloc as *const () as usize),
            ("cuMemAlloc_v2", cuMemAlloc as *const () as usize),
            ("cuMemFree", cuMemFree as *const () as usize),
            ("cuMemFree_v2", cuMemFree as *const () as usize),
            ("cuMemcpyHtoD", cuMemcpyHtoD as *const () as usize),
            ("cuMemcpyHtoD_v2", cuMemcpyHtoD as *const () as usize),
            ("cuMemcpyDtoH", cuMemcpyDtoH as *const () as usize),
            ("cuMemcpyDtoH_v2", cuMemcpyDtoH as *const () as usize),
            ("cuMemcpyHtoDAsync", cuMemcpyHtoDAsync as *const () as usize),
            (
                "cuMemcpyHtoDAsync_v2",
                cuMemcpyHtoDAsync as *const () as usize,
            ),
            ("cuMemcpyDtoHAsync", cuMemcpyDtoHAsync as *const () as usize),
            (
                "cuMemcpyDtoHAsync_v2",
                cuMemcpyDtoHAsync as *const () as usize,
            ),
            ("cuMemsetD8", cuMemsetD8 as *const () as usize),
            ("cuMemsetD8_v2", cuMemsetD8 as *const () as usize),
            ("cuModuleLoadData", cuModuleLoadData as *const () as usize),
            ("cuModuleUnload", cuModuleUnload as *const () as usize),
            (
                "cuModuleGetFunction",
                cuModuleGetFunction as *const () as usize,
            ),
            ("cuLaunchKernel", cuLaunchKernel as *const () as usize),
            ("cuCtxSynchronize", cuCtxSynchronize as *const () as usize),
            ("cuGetErrorString", cuGetErrorString as *const () as usize),
            ("cuStreamCreate", cuStreamCreate as *const () as usize),
            ("cuStreamDestroy", cuStreamDestroy as *const () as usize),
            (
                "cuStreamDestroy_v2",
                cuStreamDestroy_v2 as *const () as usize,
            ),
            (
                "cuStreamSynchronize",
                cuStreamSynchronize as *const () as usize,
            ),
            ("cuStreamWaitEvent", cuStreamWaitEvent as *const () as usize),
            ("cuEventCreate", cuEventCreate as *const () as usize),
            ("cuEventDestroy", cuEventDestroy as *const () as usize),
            ("cuEventDestroy_v2", cuEventDestroy_v2 as *const () as usize),
            ("cuEventQuery", cuEventQuery as *const () as usize),
            ("cuEventRecord", cuEventRecord as *const () as usize),
            (
                "cuEventSynchronize",
                cuEventSynchronize as *const () as usize,
            ),
            ("cuGetProcAddress", cuGetProcAddress as *const () as usize),
            (
                "cuGetProcAddress_v2",
                cuGetProcAddress as *const () as usize,
            ),
        ]
    })
}

/// `cuGetProcAddress` — CUDA 12's driver entry-point resolver.
///
/// Answers implemented symbols (base names and versioned aliases) with their
/// function pointer; refuses everything else with `CUDA_ERROR_NOT_FOUND` and
/// a null out-pointer, matching the real driver's contract. The version and
/// flags arguments are accepted and ignored: v1 serves one implementation
/// per name and has no per-thread-default-stream variants.
///
/// No `guard`: this performs no RPC, and the lookup cannot panic (a `CStr`
/// view of arbitrary bytes is infallible).
///
/// # Safety
/// `symbol` must name a NUL-terminated string; `func_ptr` must name writable
/// storage for one pointer, exactly as the CUDA Driver API contract says.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuGetProcAddress(
    symbol: *const c_char,
    func_ptr: *mut *mut c_void,
    _cuda_version: c_uint,
    _flags: c_ulonglong,
) -> CuResult {
    if symbol.is_null() || func_ptr.is_null() {
        return wire::CUDA_ERROR_INVALID_VALUE as CuResult;
    }
    // SAFETY: `func_ptr` names writable storage per the caller contract.
    unsafe { *func_ptr = std::ptr::null_mut() };
    let name = unsafe { std::ffi::CStr::from_ptr(symbol) }.to_bytes();
    for &(table_name, addr) in resolver_table() {
        if table_name.as_bytes() == name {
            // The table stores `usize` so it can live in a `static` (raw
            // pointers are not `Sync`); every address comes from a live
            // function and is never null.
            unsafe { *func_ptr = addr as *mut c_void };
            return SUCCESS;
        }
    }
    wire::CUDA_ERROR_NOT_FOUND as CuResult
}

/// `cuGetProcAddress_v2` — the CUDA 12.1+ alias; identical semantics.
///
/// # Safety
/// Same contract as [`cuGetProcAddress`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cuGetProcAddress_v2(
    symbol: *const c_char,
    func_ptr: *mut *mut c_void,
    cuda_version: c_uint,
    flags: c_ulonglong,
) -> CuResult {
    unsafe { cuGetProcAddress(symbol, func_ptr, cuda_version, flags) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn resolve(name: &str) -> (CuResult, *mut c_void) {
        let symbol = CString::new(name).expect("test symbol has no NUL");
        let mut out: *mut c_void = std::ptr::null_mut();
        let rc = unsafe { cuGetProcAddress(symbol.as_ptr(), &mut out, 12000, 0) };
        (rc, out)
    }

    #[test]
    fn every_implemented_symbol_resolves_to_a_live_entry_point() {
        assert_eq!(resolver_table().len(), 46);
        for &(name, _) in resolver_table() {
            let (rc, out) = resolve(name);
            assert_eq!(rc, wire::SUCCESS as CuResult, "{name} refused");
            assert!(!out.is_null(), "{name} resolved to null");
        }
    }

    #[test]
    fn versioned_aliases_answer_the_base_entry_point() {
        for (base, alias) in [
            ("cuDeviceTotalMem", "cuDeviceTotalMem_v2"),
            ("cuCtxCreate", "cuCtxCreate_v2"),
            ("cuCtxDestroy", "cuCtxDestroy_v2"),
            ("cuMemAlloc", "cuMemAlloc_v2"),
            ("cuMemFree", "cuMemFree_v2"),
            ("cuMemcpyHtoD", "cuMemcpyHtoD_v2"),
            ("cuMemcpyDtoH", "cuMemcpyDtoH_v2"),
            ("cuMemsetD8", "cuMemsetD8_v2"),
            ("cuGetProcAddress", "cuGetProcAddress_v2"),
        ] {
            let (_, base_ptr) = resolve(base);
            let (rc, alias_ptr) = resolve(alias);
            assert_eq!(rc, wire::SUCCESS as CuResult, "{alias} refused");
            assert_eq!(base_ptr, alias_ptr, "{alias} != {base}");
        }
    }

    #[test]
    fn unimplemented_symbols_refuse_with_not_found_and_null() {
        for name in [
            "cuGraphicsResourceGetMappedPointer",
            "cuOccupancyMaxActiveBlocksPerMultiprocessor",
            "cuLaunchKernelEx",
            "not_a_symbol",
            "",
        ] {
            let (rc, out) = resolve(name);
            assert_eq!(
                rc,
                wire::CUDA_ERROR_NOT_FOUND as CuResult,
                "{name}: expected NOT_FOUND"
            );
            assert!(out.is_null(), "{name}: out-pointer not cleared");
        }
    }

    #[test]
    fn null_arguments_are_invalid_value() {
        let symbol = CString::new("cuInit").expect("test symbol has no NUL");
        let mut out: *mut c_void = std::ptr::null_mut();
        let rc = unsafe { cuGetProcAddress(std::ptr::null(), &mut out, 12000, 0) };
        assert_eq!(rc, wire::CUDA_ERROR_INVALID_VALUE as CuResult);
        let rc = unsafe { cuGetProcAddress(symbol.as_ptr(), std::ptr::null_mut(), 12000, 0) };
        assert_eq!(rc, wire::CUDA_ERROR_INVALID_VALUE as CuResult);
    }

    #[test]
    fn table_names_are_unique() {
        let mut names: Vec<&str> = resolver_table().iter().map(|&(name, _)| name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), resolver_table().len(), "duplicate table names");
    }

    #[test]
    fn the_v2_alias_entry_point_resolves_like_the_base() {
        let symbol = CString::new("cuMemAlloc_v2").expect("test symbol has no NUL");
        let mut out: *mut c_void = std::ptr::null_mut();
        let rc = unsafe { cuGetProcAddress_v2(symbol.as_ptr(), &mut out, 13000, 2) };
        assert_eq!(rc, wire::SUCCESS as CuResult);
        let (_, base_ptr) = resolve("cuMemAlloc");
        assert_eq!(out, base_ptr);
    }
}
