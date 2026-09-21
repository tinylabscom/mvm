//! The real driver, dynamically loaded on the host.
//!
//! The guest never links a driver and never sees a device node; this
//! backend is the one place the real `libcuda.so.1` / `libnvidia-ml.so.1`
//! enter the picture, and they stay on the host. Everything is resolved at
//! runtime with `dlopen`/`dlsym` rather than link time, so this crate
//! builds and tests on machines with no GPU and no NVIDIA toolchain, and a
//! GPU-less host gets a clean "no driver" answer from [`probe`] instead of
//! a build or load failure.
//!
//! Handle discipline: contexts, modules, and functions are real host
//! pointers minted by the driver, exposed to the guest as opaque `u64`s.
//! They leave this process only as numbers, so the guest can pass them
//! back but can never dereference them.

use std::collections::HashMap;
use std::ffi::{CString, c_char, c_int, c_uchar, c_uint, c_void};

use mvm_contract::protocol::gpu::GpuError;

use crate::{GpuBackend, LaunchConfig, wire};

/// The driver library probed first, in the order a CUDA install provides.
const LIBCUDA_CANDIDATES: [&str; 2] = ["libcuda.so.1", "libcuda.so"];
const LIBNVML_CANDIDATES: [&str; 2] = ["libnvidia-ml.so.1", "libnvidia-ml.so"];

/// Context handles minted into the high half of the u64 space, so a guest
/// handle can never alias a real small host pointer by accident.
const CTX_BASE: u64 = 0x0000_00c0_0000_0000;

// ---------------------------------------------------------------------------
// Dynamic loading
// ---------------------------------------------------------------------------

/// One dynamically loaded library and the symbols taken from it.
struct Dynlib {
    handle: *mut c_void,
}

// The handle is a dlopen reference: owned, not aliased, and only ever used
// from this thread behind `&mut` backend methods.
unsafe impl Send for Dynlib {}

impl Dynlib {
    fn open(candidates: &[&str]) -> Result<Self, GpuError> {
        for path in candidates {
            let c_path = CString::new(*path).expect("library path has no NUL");
            // SAFETY: `c_path` is a valid NUL-terminated string; dlopen
            // returns either NULL (checked) or an owned handle freed by
            // dlclose in `Drop`.
            let handle =
                unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
            if !handle.is_null() {
                return Ok(Self { handle });
            }
        }
        Err(GpuError::new(
            wire::CUDA_ERROR_NOT_FOUND,
            format!("none of {} could be dlopen'd", candidates.join(", ")),
        ))
    }

    /// Resolve one symbol. `T` is always a function-pointer type at the
    /// call site; the transmute is the standard dlsym pattern.
    fn sym<T: Copy>(&self, name: &str) -> Result<T, GpuError> {
        let c_name = CString::new(name).expect("symbol name has no NUL");
        // SAFETY: `self.handle` is a live dlopen handle, `c_name` is
        // NUL-terminated. dlsym returns NULL (checked) or a pointer valid
        // for the library's lifetime, which `self` outlives at every call.
        let ptr = unsafe { libc::dlsym(self.handle, c_name.as_ptr()) };
        if ptr.is_null() {
            return Err(GpuError::new(
                wire::CUDA_ERROR_NOT_FOUND,
                format!("symbol {name} not found in the driver library"),
            ));
        }
        // SAFETY: the caller names `T` as the symbol's function-pointer
        // type; a wrong `T` is a compile-time call-site error in practice,
        // and every use below pairs one symbol with one fixed type.
        Ok(unsafe { std::mem::transmute_copy(&ptr) })
    }
}

impl Drop for Dynlib {
    fn drop(&mut self) {
        // SAFETY: `self.handle` was returned by a successful dlopen and is
        // released exactly once, here.
        unsafe { libc::dlclose(self.handle) };
    }
}

// ---------------------------------------------------------------------------
// Driver FFI surface (the v1 subset; ABI-stable C types only)
// ---------------------------------------------------------------------------

type ResultCode = c_int;
type Device = c_int;
type DevicePtr = u64;
type ContextPtr = *mut c_void;
type ModulePtr = *mut c_void;
type FunctionPtr = *mut c_void;

type FnInit = unsafe extern "C" fn(c_uint) -> ResultCode;
type FnDriverGetVersion = unsafe extern "C" fn(*mut c_int) -> ResultCode;
type FnDeviceGetCount = unsafe extern "C" fn(*mut c_int) -> ResultCode;
type FnDeviceGet = unsafe extern "C" fn(*mut Device, c_int) -> ResultCode;
type FnDeviceGetName = unsafe extern "C" fn(*mut c_char, c_int, Device) -> ResultCode;
type FnDeviceTotalMem = unsafe extern "C" fn(*mut usize, Device) -> ResultCode;
type FnCtxCreate = unsafe extern "C" fn(*mut ContextPtr, c_uint, Device) -> ResultCode;
type FnCtxDestroy = unsafe extern "C" fn(ContextPtr) -> ResultCode;
type FnCtxSetCurrent = unsafe extern "C" fn(ContextPtr) -> ResultCode;
type FnMemAlloc = unsafe extern "C" fn(*mut DevicePtr, usize) -> ResultCode;
type FnMemFree = unsafe extern "C" fn(DevicePtr) -> ResultCode;
type FnMemcpyHtoD = unsafe extern "C" fn(DevicePtr, *const c_void, usize) -> ResultCode;
type FnMemcpyDtoH = unsafe extern "C" fn(*mut c_void, DevicePtr, usize) -> ResultCode;
type FnMemsetD8 = unsafe extern "C" fn(DevicePtr, c_uchar, usize) -> ResultCode;
type FnModuleLoadData = unsafe extern "C" fn(*mut ModulePtr, *const c_void) -> ResultCode;
type FnModuleUnload = unsafe extern "C" fn(ModulePtr) -> ResultCode;
type FnModuleGetFunction =
    unsafe extern "C" fn(*mut FunctionPtr, ModulePtr, *const c_char) -> ResultCode;
type FnLaunchKernel = unsafe extern "C" fn(
    FunctionPtr,
    c_uint,
    c_uint,
    c_uint,
    c_uint,
    c_uint,
    c_uint,
    c_uint,
    *mut c_void,
    *const *mut c_void,
    *mut *mut c_void,
) -> ResultCode;
type FnCtxSynchronize = unsafe extern "C" fn() -> ResultCode;
type FnGetErrorString = unsafe extern "C" fn(ResultCode) -> *const c_char;

struct CudaSymbols {
    _lib: Dynlib,
    init: FnInit,
    driver_get_version: FnDriverGetVersion,
    device_get_count: FnDeviceGetCount,
    device_get: FnDeviceGet,
    device_get_name: FnDeviceGetName,
    device_total_mem: FnDeviceTotalMem,
    ctx_create: FnCtxCreate,
    ctx_destroy: FnCtxDestroy,
    ctx_set_current: FnCtxSetCurrent,
    mem_alloc: FnMemAlloc,
    mem_free: FnMemFree,
    memcpy_htod: FnMemcpyHtoD,
    memcpy_dtoh: FnMemcpyDtoH,
    memset_d8: FnMemsetD8,
    module_load_data: FnModuleLoadData,
    module_unload: FnModuleUnload,
    module_get_function: FnModuleGetFunction,
    launch_kernel: FnLaunchKernel,
    ctx_synchronize: FnCtxSynchronize,
    get_error_string: FnGetErrorString,
}

impl CudaSymbols {
    fn load() -> Result<Self, GpuError> {
        let lib = Dynlib::open(&LIBCUDA_CANDIDATES)?;
        Ok(Self {
            init: lib.sym("cuInit")?,
            driver_get_version: lib.sym("cuDriverGetVersion")?,
            device_get_count: lib.sym("cuDeviceGetCount")?,
            device_get: lib.sym("cuDeviceGet")?,
            device_get_name: lib.sym("cuDeviceGetName")?,
            device_total_mem: lib.sym("cuDeviceTotalMem")?,
            ctx_create: lib.sym("cuCtxCreate")?,
            ctx_destroy: lib.sym("cuCtxDestroy")?,
            ctx_set_current: lib.sym("cuCtxSetCurrent")?,
            mem_alloc: lib.sym("cuMemAlloc")?,
            mem_free: lib.sym("cuMemFree")?,
            memcpy_htod: lib.sym("cuMemcpyHtoD")?,
            memcpy_dtoh: lib.sym("cuMemcpyDtoH")?,
            memset_d8: lib.sym("cuMemsetD8")?,
            module_load_data: lib.sym("cuModuleLoadData")?,
            module_unload: lib.sym("cuModuleUnload")?,
            module_get_function: lib.sym("cuModuleGetFunction")?,
            launch_kernel: lib.sym("cuLaunchKernel")?,
            ctx_synchronize: lib.sym("cuCtxSynchronize")?,
            get_error_string: lib.sym("cuGetErrorString")?,
            _lib: lib,
        })
    }

    fn describe(&self, code: ResultCode) -> String {
        // SAFETY: `get_error_string` is the driver's own formatter; it
        // returns either NULL or a static NUL-terminated string.
        let ptr = unsafe { (self.get_error_string)(code) };
        if ptr.is_null() {
            return format!("driver error {code}");
        }
        // SAFETY: the driver returned a valid NUL-terminated C string.
        let text = unsafe { std::ffi::CStr::from_ptr(ptr) };
        text.to_string_lossy().into_owned()
    }

    fn check(&self, code: ResultCode, what: &str) -> Result<(), GpuError> {
        if code == wire::SUCCESS {
            Ok(())
        } else {
            Err(GpuError::new(
                code,
                format!("{what}: {}", self.describe(code)),
            ))
        }
    }
}

// NVML ABI surface (v1 subset).
type NvmlDevice = *mut c_void;

#[repr(C)]
struct NvmlMemory {
    total: u64,
    free: u64,
    used: u64,
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

#[repr(C)]
struct NvmlUtilization {
    gpu: c_uint,
    memory: c_uint,
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

type FnNvmlInit = unsafe extern "C" fn() -> ResultCode;
type FnNvmlShutdown = unsafe extern "C" fn() -> ResultCode;
type FnNvmlSystemGetDriverVersion = unsafe extern "C" fn(*mut c_char, c_uint) -> ResultCode;
type FnNvmlDeviceGetCount = unsafe extern "C" fn(*mut c_uint) -> ResultCode;
type FnNvmlDeviceGetHandleByIndex = unsafe extern "C" fn(c_uint, *mut NvmlDevice) -> ResultCode;
type FnNvmlDeviceGetName = unsafe extern "C" fn(*mut c_char, c_uint, NvmlDevice) -> ResultCode;
type FnNvmlDeviceGetMemoryInfo = unsafe extern "C" fn(NvmlDevice, *mut NvmlMemory) -> ResultCode;
type FnNvmlDeviceGetUtilizationRates =
    unsafe extern "C" fn(NvmlDevice, *mut NvmlUtilization) -> ResultCode;
type FnNvmlDeviceGetCudaComputeCapability =
    unsafe extern "C" fn(*mut c_int, *mut c_int, NvmlDevice) -> ResultCode;

struct NvmlSymbols {
    _lib: Dynlib,
    init: FnNvmlInit,
    _shutdown: FnNvmlShutdown,
    system_get_driver_version: FnNvmlSystemGetDriverVersion,
    device_get_count: FnNvmlDeviceGetCount,
    device_get_handle_by_index: FnNvmlDeviceGetHandleByIndex,
    device_get_name: FnNvmlDeviceGetName,
    device_get_memory_info: FnNvmlDeviceGetMemoryInfo,
    device_get_utilization_rates: FnNvmlDeviceGetUtilizationRates,
    device_get_cuda_compute_capability: FnNvmlDeviceGetCudaComputeCapability,
}

impl NvmlSymbols {
    fn load() -> Result<Self, GpuError> {
        let lib = Dynlib::open(&LIBNVML_CANDIDATES)?;
        Ok(Self {
            init: lib.sym("nvmlInit_v2")?,
            _shutdown: lib.sym("nvmlShutdown")?,
            system_get_driver_version: lib.sym("nvmlSystemGetDriverVersion")?,
            device_get_count: lib.sym("nvmlDeviceGetCount_v2")?,
            device_get_handle_by_index: lib.sym("nvmlDeviceGetHandleByIndex_v2")?,
            device_get_name: lib.sym("nvmlDeviceGetName")?,
            device_get_memory_info: lib.sym("nvmlDeviceGetMemoryInfo")?,
            device_get_utilization_rates: lib.sym("nvmlDeviceGetUtilizationRates")?,
            device_get_cuda_compute_capability: lib.sym("nvmlDeviceGetCudaComputeCapability")?,
            _lib: lib,
        })
    }
}

// ---------------------------------------------------------------------------
// The backend
// ---------------------------------------------------------------------------

/// A backend bound to the host's real driver. Construct via [`probe`].
pub struct NativeCudaBackend {
    cuda: CudaSymbols,
    nvml: Option<NvmlSymbols>,
    /// Context handle → real CUcontext. Each connection owns its contexts;
    /// nothing is shared between guests.
    contexts: HashMap<u64, ContextPtr>,
    next_ctx: u64,
    current: Option<u64>,
}

// The backend holds raw CUcontext/CUmodule/CUfunction pointers minted by
// the driver. It is only ever used behind a `Mutex` owned by one connection
// thread (see `server::serve_connection`), so handing it across threads
// cannot create aliasing driver state.
unsafe impl Send for NativeCudaBackend {}

/// Load the driver and initialize it. `None` when no usable driver is
/// present — `--backend auto` treats that as "fall back to the stub".
pub fn probe() -> Option<NativeCudaBackend> {
    let cuda = CudaSymbols::load().ok()?;
    // SAFETY: no CUDA state exists yet; cuInit(0) is the defined first call.
    let code = unsafe { (cuda.init)(0) };
    if code != wire::SUCCESS {
        return None;
    }
    let nvml = NvmlSymbols::load().ok().and_then(|nvml| {
        // SAFETY: NVML is uninitialized; nvmlInit_v2 is the defined first call.
        let code = unsafe { (nvml.init)() };
        (code == wire::SUCCESS).then_some(nvml)
    });
    Some(NativeCudaBackend {
        cuda,
        nvml,
        contexts: HashMap::new(),
        next_ctx: 0,
        current: None,
    })
}

impl NativeCudaBackend {
    /// Validate `handle`, make its context current on this thread (the
    /// driver API is context-stateful per thread), and return the pointer.
    fn use_context(&mut self, handle: u64) -> Result<ContextPtr, GpuError> {
        let ptr = self.contexts.get(&handle).copied().ok_or_else(|| {
            GpuError::new(
                wire::CUDA_ERROR_INVALID_HANDLE,
                format!("unknown context handle 0x{handle:x}"),
            )
        })?;
        if self.current != Some(handle) {
            // SAFETY: `ptr` is a live CUcontext this backend created and
            // has not destroyed.
            let code = unsafe { (self.cuda.ctx_set_current)(ptr) };
            self.cuda.check(code, "cuCtxSetCurrent")?;
            self.current = Some(handle);
        }
        Ok(ptr)
    }

    fn device(&self, ordinal: u32) -> Result<Device, GpuError> {
        let mut device: Device = 0;
        let ordinal_c = c_int::try_from(ordinal).map_err(|_| {
            GpuError::new(
                wire::CUDA_ERROR_INVALID_DEVICE,
                format!("device ordinal {ordinal} does not fit the driver ABI"),
            )
        })?;
        // SAFETY: `device` is a valid out-pointer for the call's duration.
        let code = unsafe { (self.cuda.device_get)(&mut device, ordinal_c) };
        self.cuda.check(code, "cuDeviceGet")?;
        Ok(device)
    }

    fn nvml_device(&self, ordinal: u32) -> Result<NvmlDevice, GpuError> {
        let nvml = self.nvml.as_ref().ok_or_else(|| {
            GpuError::new(
                wire::NVML_ERROR_UNINITIALIZED,
                "NVML is not available in this endpoint",
            )
        })?;
        let mut count: c_uint = 0;
        // SAFETY: `count` is a valid out-pointer.
        let code = unsafe { (nvml.device_get_count)(&mut count) };
        if code != wire::SUCCESS {
            return Err(GpuError::new(
                code,
                format!("nvmlDeviceGetCount_v2 failed with code {code}"),
            ));
        }
        if ordinal >= count {
            return Err(GpuError::new(
                wire::NVML_ERROR_INVALID_ARGUMENT,
                format!("device ordinal {ordinal} of {count}"),
            ));
        }
        let mut handle: NvmlDevice = std::ptr::null_mut();
        // SAFETY: `handle` is a valid out-pointer; ordinal < count was checked.
        let code = unsafe { (nvml.device_get_handle_by_index)(ordinal, &mut handle) };
        if code != wire::SUCCESS {
            return Err(GpuError::new(
                code,
                format!("nvmlDeviceGetHandleByIndex_v2({ordinal}) failed with code {code}"),
            ));
        }
        Ok(handle)
    }
}

impl GpuBackend for NativeCudaBackend {
    fn driver_version(&mut self) -> Result<i32, GpuError> {
        let mut version: c_int = 0;
        // SAFETY: `version` is a valid out-pointer.
        let code = unsafe { (self.cuda.driver_get_version)(&mut version) };
        self.cuda.check(code, "cuDriverGetVersion")?;
        Ok(version)
    }

    fn device_count(&mut self) -> Result<u32, GpuError> {
        let mut count: c_int = 0;
        // SAFETY: `count` is a valid out-pointer.
        let code = unsafe { (self.cuda.device_get_count)(&mut count) };
        self.cuda.check(code, "cuDeviceGetCount")?;
        u32::try_from(count)
            .map_err(|_| GpuError::new(wire::CUDA_ERROR_UNKNOWN, "negative device count"))
    }

    fn device_name(&mut self, ordinal: u32) -> Result<String, GpuError> {
        let device = self.device(ordinal)?;
        let mut buf = [0_i8; 256];
        // SAFETY: `buf` is 256 bytes, its size is passed explicitly, and
        // `device` came from cuDeviceGet above.
        let code =
            unsafe { (self.cuda.device_get_name)(buf.as_mut_ptr(), buf.len() as c_int, device) };
        self.cuda.check(code, "cuDeviceGetName")?;
        Ok(std::ffi::CStr::from_bytes_until_nul(bytemuck_i8(&buf))
            .map_err(|_| GpuError::new(wire::CUDA_ERROR_UNKNOWN, "device name not NUL-terminated"))?
            .to_string_lossy()
            .into_owned())
    }

    fn device_total_mem(&mut self, ordinal: u32) -> Result<u64, GpuError> {
        let device = self.device(ordinal)?;
        let mut bytes: usize = 0;
        // SAFETY: `bytes` is a valid out-pointer.
        let code = unsafe { (self.cuda.device_total_mem)(&mut bytes, device) };
        self.cuda.check(code, "cuDeviceTotalMem")?;
        Ok(bytes as u64)
    }

    fn context_create(&mut self, ordinal: u32) -> Result<u64, GpuError> {
        let device = self.device(ordinal)?;
        let mut ptr: ContextPtr = std::ptr::null_mut();
        // SAFETY: `ptr` is a valid out-pointer; flags 0 requests the
        // sched-spin-free default.
        let code = unsafe { (self.cuda.ctx_create)(&mut ptr, 0, device) };
        self.cuda.check(code, "cuCtxCreate")?;
        let handle = CTX_BASE + self.next_ctx * 0x1000;
        self.next_ctx += 1;
        self.contexts.insert(handle, ptr);
        self.current = Some(handle);
        Ok(handle)
    }

    fn context_destroy(&mut self, handle: u64) -> Result<(), GpuError> {
        let ptr = self.contexts.get(&handle).copied().ok_or_else(|| {
            GpuError::new(
                wire::CUDA_ERROR_INVALID_HANDLE,
                format!("unknown context handle 0x{handle:x}"),
            )
        })?;
        // SAFETY: `ptr` is a live CUcontext this backend created; after a
        // successful destroy the map entry is removed before any reuse.
        let code = unsafe { (self.cuda.ctx_destroy)(ptr) };
        self.cuda.check(code, "cuCtxDestroy")?;
        self.contexts.remove(&handle);
        if self.current == Some(handle) {
            self.current = None;
        }
        Ok(())
    }

    fn synchronize(&mut self, handle: u64) -> Result<(), GpuError> {
        self.use_context(handle)?;
        // SAFETY: a valid context is current on this thread.
        let code = unsafe { (self.cuda.ctx_synchronize)() };
        self.cuda.check(code, "cuCtxSynchronize")
    }

    fn mem_alloc(&mut self, context: u64, bytes: u64) -> Result<u64, GpuError> {
        self.use_context(context)?;
        let mut ptr: DevicePtr = 0;
        let bytes = usize::try_from(bytes).map_err(|_| {
            GpuError::new(
                wire::CUDA_ERROR_OUT_OF_MEMORY,
                "allocation size overflows this host",
            )
        })?;
        // SAFETY: `ptr` is a valid out-pointer; a context is current.
        let code = unsafe { (self.cuda.mem_alloc)(&mut ptr, bytes) };
        self.cuda.check(code, "cuMemAlloc")?;
        Ok(ptr)
    }

    fn mem_free(&mut self, context: u64, ptr: u64) -> Result<(), GpuError> {
        self.use_context(context)?;
        // SAFETY: `ptr` was minted by cuMemAlloc on this context (or is an
        // invalid value, which cuMemFree reports as an error, not UB, per
        // the CUDA contract).
        let code = unsafe { (self.cuda.mem_free)(ptr) };
        self.cuda.check(code, "cuMemFree")
    }

    fn memcpy_htod(&mut self, context: u64, dst: u64, data: &[u8]) -> Result<(), GpuError> {
        self.use_context(context)?;
        // SAFETY: `data` is a readable slice; `dst` names device memory on
        // the current context (invalid values are reported by the driver).
        let code =
            unsafe { (self.cuda.memcpy_htod)(dst, data.as_ptr().cast::<c_void>(), data.len()) };
        self.cuda.check(code, "cuMemcpyHtoD")
    }

    fn memcpy_dtoh(&mut self, context: u64, src: u64, len: u64) -> Result<Vec<u8>, GpuError> {
        self.use_context(context)?;
        let len = usize::try_from(len)
            .map_err(|_| GpuError::new(wire::CUDA_ERROR_INVALID_VALUE, "copy length overflows"))?;
        let mut out = vec![0_u8; len];
        // SAFETY: `out` is writable for `len` bytes; `src` names device
        // memory on the current context.
        let code = unsafe { (self.cuda.memcpy_dtoh)(out.as_mut_ptr().cast::<c_void>(), src, len) };
        self.cuda.check(code, "cuMemcpyDtoH")?;
        Ok(out)
    }

    fn memset_d8(&mut self, context: u64, dst: u64, value: u8, len: u64) -> Result<(), GpuError> {
        self.use_context(context)?;
        let len = usize::try_from(len).map_err(|_| {
            GpuError::new(wire::CUDA_ERROR_INVALID_VALUE, "memset length overflows")
        })?;
        // SAFETY: `dst` names device memory on the current context.
        let code = unsafe { (self.cuda.memset_d8)(dst, value, len) };
        self.cuda.check(code, "cuMemsetD8")
    }

    fn module_load(&mut self, context: u64, image: &[u8]) -> Result<u64, GpuError> {
        self.use_context(context)?;
        let mut module: ModulePtr = std::ptr::null_mut();
        // SAFETY: `image` is readable (an empty image is refused before the
        // wire even reaches here by the same check the driver makes);
        // `module` is a valid out-pointer.
        let code =
            unsafe { (self.cuda.module_load_data)(&mut module, image.as_ptr().cast::<c_void>()) };
        self.cuda.check(code, "cuModuleLoadData")?;
        Ok(module as u64)
    }

    fn module_unload(&mut self, context: u64, module: u64) -> Result<(), GpuError> {
        self.use_context(context)?;
        // SAFETY: `module` names a loaded module on the current context;
        // the driver reports invalid values.
        let code = unsafe { (self.cuda.module_unload)(module as ModulePtr) };
        self.cuda.check(code, "cuModuleUnload")
    }

    fn module_get_function(
        &mut self,
        context: u64,
        module: u64,
        name: &str,
    ) -> Result<u64, GpuError> {
        self.use_context(context)?;
        let c_name = CString::new(name)
            .map_err(|_| GpuError::new(wire::CUDA_ERROR_INVALID_VALUE, "function name has NUL"))?;
        let mut function: FunctionPtr = std::ptr::null_mut();
        // SAFETY: `c_name` is NUL-terminated, `function` is a valid
        // out-pointer, `module` names a loaded module.
        let code = unsafe {
            (self.cuda.module_get_function)(&mut function, module as ModulePtr, c_name.as_ptr())
        };
        self.cuda.check(code, "cuModuleGetFunction")?;
        Ok(function as u64)
    }

    fn launch_kernel(
        &mut self,
        context: u64,
        function: u64,
        config: &LaunchConfig,
    ) -> Result<(), GpuError> {
        self.use_context(context)?;
        // The kernelParams ABI wants pointers to each argument's bytes;
        // the wire already delivered each blob by value, so take addresses
        // of the received buffers for the duration of the call.
        let params: Vec<*mut c_void> = config
            .params
            .iter()
            .map(|blob| blob.as_ptr().cast::<c_void>().cast_mut())
            .collect();
        let [gx, gy, gz] = config.grid;
        let [bx, by, bz] = config.block;
        // SAFETY: a context is current; `function` names a function from a
        // module loaded on it; each params entry points at a live buffer;
        // the stream is the legacy default stream (NULL); `extra` is NULL.
        let code = unsafe {
            (self.cuda.launch_kernel)(
                function as FunctionPtr,
                gx,
                gy,
                gz,
                bx,
                by,
                bz,
                config.shared_mem_bytes,
                std::ptr::null_mut(),
                params.as_ptr(),
                std::ptr::null_mut(),
            )
        };
        self.cuda.check(code, "cuLaunchKernel")
    }

    fn nvml_device_count(&mut self) -> Result<u32, GpuError> {
        let nvml = self.nvml.as_ref().ok_or_else(|| {
            GpuError::new(
                wire::NVML_ERROR_UNINITIALIZED,
                "NVML is not available in this endpoint",
            )
        })?;
        let mut count: c_uint = 0;
        // SAFETY: `count` is a valid out-pointer.
        let code = unsafe { (nvml.device_get_count)(&mut count) };
        if code != wire::SUCCESS {
            return Err(GpuError::new(
                code,
                format!("nvmlDeviceGetCount_v2 failed with code {code}"),
            ));
        }
        Ok(count)
    }

    fn nvml_driver_version(&mut self) -> Result<String, GpuError> {
        let nvml = self.nvml.as_ref().ok_or_else(|| {
            GpuError::new(
                wire::NVML_ERROR_UNINITIALIZED,
                "NVML is not available in this endpoint",
            )
        })?;
        let mut buf = vec![0_i8; 80];
        // SAFETY: `buf` is 80 bytes and its length is passed explicitly.
        let code =
            unsafe { (nvml.system_get_driver_version)(buf.as_mut_ptr(), buf.len() as c_uint) };
        if code != wire::SUCCESS {
            return Err(GpuError::new(
                code,
                format!("nvmlSystemGetDriverVersion failed with code {code}"),
            ));
        }
        Ok(std::ffi::CStr::from_bytes_until_nul(bytemuck_i8(&buf))
            .map_err(|_| {
                GpuError::new(
                    wire::NVML_ERROR_UNKNOWN,
                    "driver version not NUL-terminated",
                )
            })?
            .to_string_lossy()
            .into_owned())
    }

    fn nvml_device_name(&mut self, ordinal: u32) -> Result<String, GpuError> {
        let nvml = self.nvml.as_ref().ok_or_else(|| {
            GpuError::new(
                wire::NVML_ERROR_UNINITIALIZED,
                "NVML is not available in this endpoint",
            )
        })?;
        let device = self.nvml_device(ordinal)?;
        let mut buf = vec![0_i8; 64];
        // SAFETY: `buf` is 64 bytes and its length is passed; `device` is
        // a handle NVML minted.
        let code = unsafe { (nvml.device_get_name)(buf.as_mut_ptr(), buf.len() as c_uint, device) };
        if code != wire::SUCCESS {
            return Err(GpuError::new(
                code,
                format!("nvmlDeviceGetName({ordinal}) failed with code {code}"),
            ));
        }
        Ok(std::ffi::CStr::from_bytes_until_nul(bytemuck_i8(&buf))
            .map_err(|_| GpuError::new(wire::NVML_ERROR_UNKNOWN, "device name not NUL-terminated"))?
            .to_string_lossy()
            .into_owned())
    }

    fn nvml_memory_info(&mut self, ordinal: u32) -> Result<(u64, u64, u64), GpuError> {
        let nvml = self.nvml.as_ref().ok_or_else(|| {
            GpuError::new(
                wire::NVML_ERROR_UNINITIALIZED,
                "NVML is not available in this endpoint",
            )
        })?;
        let device = self.nvml_device(ordinal)?;
        let mut info = NvmlMemory {
            total: 0,
            free: 0,
            used: 0,
        };
        // SAFETY: `info` is a valid out-struct; `device` is NVML's handle.
        let code = unsafe { (nvml.device_get_memory_info)(device, &mut info) };
        if code != wire::SUCCESS {
            return Err(GpuError::new(
                code,
                format!("nvmlDeviceGetMemoryInfo({ordinal}) failed with code {code}"),
            ));
        }
        Ok((info.total, info.free, info.used))
    }

    fn nvml_utilization(&mut self, ordinal: u32) -> Result<(u32, u32), GpuError> {
        let nvml = self.nvml.as_ref().ok_or_else(|| {
            GpuError::new(
                wire::NVML_ERROR_UNINITIALIZED,
                "NVML is not available in this endpoint",
            )
        })?;
        let device = self.nvml_device(ordinal)?;
        let mut rates = NvmlUtilization { gpu: 0, memory: 0 };
        // SAFETY: `rates` is a valid out-struct; `device` is NVML's handle.
        let code = unsafe { (nvml.device_get_utilization_rates)(device, &mut rates) };
        if code != wire::SUCCESS {
            return Err(GpuError::new(
                code,
                format!("nvmlDeviceGetUtilizationRates({ordinal}) failed with code {code}"),
            ));
        }
        Ok((rates.gpu, rates.memory))
    }

    fn nvml_compute_capability(&mut self, ordinal: u32) -> Result<(i32, i32), GpuError> {
        let nvml = self.nvml.as_ref().ok_or_else(|| {
            GpuError::new(
                wire::NVML_ERROR_UNINITIALIZED,
                "NVML is not available in this endpoint",
            )
        })?;
        let device = self.nvml_device(ordinal)?;
        let (mut major, mut minor) = (0_i32, 0_i32);
        // SAFETY: both are valid out-pointers; `device` is NVML's handle.
        let code =
            unsafe { (nvml.device_get_cuda_compute_capability)(&mut major, &mut minor, device) };
        if code != wire::SUCCESS {
            return Err(GpuError::new(
                code,
                format!("nvmlDeviceGetCudaComputeCapability({ordinal}) failed with code {code}"),
            ));
        }
        Ok((major, minor))
    }
}

/// View an i8 buffer as bytes for NUL-scanning. `i8` and `u8` have the
/// same layout and the buffer originates from a `*mut c_char` fill, so the
/// reinterpretation is total.
fn bytemuck_i8(buf: &[i8]) -> &[u8] {
    // SAFETY: i8 and u8 are layout-compatible; the slice bounds are unchanged.
    unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), buf.len()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_absent_driver_is_none_not_a_crash() {
        // Every CI runner and developer laptop exercises this arm: no
        // libcuda present, and the answer must be the fallback signal,
        // never a panic or a build gate.
        if native_driver_expected() {
            assert!(probe().is_some(), "a driver-present host must probe");
        } else {
            assert!(probe().is_none(), "a driver-less host must fall back");
        }
    }

    /// Whether this machine is expected to have a usable driver. Deliberately
    /// environment-based rather than a cfg: the same binary answers both ways.
    fn native_driver_expected() -> bool {
        std::env::var("MVM_GPU_TEST_EXPECT_NATIVE").is_ok()
    }
}
