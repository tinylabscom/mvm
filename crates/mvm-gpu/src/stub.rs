//! A deterministic fake GPU, backed by host memory.
//!
//! The stub exists for two reasons. It makes the whole remoting transport —
//! guest shim, vsock/UDS/TCP framing, dispatch — testable on a machine with
//! no GPU at all, which is every CI runner and every developer laptop. And
//! it makes `--backend auto` honest: a GPU-less host still answers the
//! guest's CUDA calls with well-formed results instead of a connection
//! failure inside the workload.
//!
//! What it deliberately does **not** do is execute kernels. A launch is
//! validated (function known, parameters in range) and recorded, then
//! reported as success. That is enough for transport, dispatch, and
//! framework-detection testing; it is not a compute backend, and the device
//! name says so out loud.

use std::collections::HashMap;

use crate::{GpuBackend, LaunchConfig, wire};
use mvm_contract::protocol::gpu::GpuError;

/// One allocation's bytes. Device memory is a plain host buffer the stub
/// copies into and out of — the same lifecycle the real backend's
/// `cuMemAlloc`/`cuMemcpy*` give it.
struct Allocation {
    bytes: Vec<u8>,
}

/// One loaded module. The stub never parses the image; it records the byte
/// length so a load of garbage is still a load of *something* deterministically.
struct Module {
    _image_len: usize,
    /// Function name → handle. Handles are per-module indices in the high
    /// half of the handle space.
    functions: HashMap<String, u64>,
    next_function: u64,
}

/// One primary context's state.
struct Context {
    _ordinal: u32,
    allocations: HashMap<u64, Allocation>,
    next_ptr: u64,
    modules: HashMap<u64, Module>,
    next_module: u64,
    launches: Vec<LaunchRecord>,
}

/// What one launch asked for, kept for test inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchRecord {
    pub function: u64,
    pub config: LaunchConfig,
}

/// The stub device identity. Fixed on purpose: anything a test or a
/// framework-detection probe reads here must be stable across runs and
/// machines, or "deterministic test backend" is a lie.
pub const STUB_DEVICE_NAME: &str = "mvm deterministic GPU stub";
pub const STUB_DRIVER_VERSION: i32 = 12_040;
pub const STUB_DRIVER_VERSION_STRING: &str = "555.0.0-mvm-stub";
pub const STUB_TOTAL_MEM_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const STUB_COMPUTE_CAPABILITY: (i32, i32) = (7, 5);
/// Fake device pointers start here, page-aligned and far from any real
/// userspace address a workload might dereference by mistake.
const PTR_BASE: u64 = 0x0000_7f00_0000_0000;
/// Context handles start here.
const CTX_BASE: u64 = 0x0000_00c0_0000_0000;
/// Module handles start here.
const MODULE_BASE: u64 = 0x0000_00d0_0000_0000;
/// Per-module function handles start here and step by one.
const FUNCTION_BASE: u64 = 0x0000_00f0_0000_0000;

/// The deterministic stub backend. One instance serves one connection.
#[derive(Default)]
pub struct StubBackend {
    contexts: HashMap<u64, Context>,
    next_ctx: u64,
    current: Option<u64>,
}

impl StubBackend {
    /// A fresh stub with no state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// All launches recorded so far, across contexts — the test surface for
    /// "did the launch actually arrive intact".
    #[must_use]
    pub fn launches(&self) -> Vec<LaunchRecord> {
        self.contexts
            .values()
            .flat_map(|ctx| ctx.launches.iter().cloned())
            .collect()
    }

    fn context(&self, handle: u64) -> Result<&Context, GpuError> {
        self.contexts.get(&handle).ok_or_else(|| {
            GpuError::new(
                wire::CUDA_ERROR_INVALID_HANDLE,
                format!("unknown context handle 0x{handle:x}"),
            )
        })
    }

    fn context_mut(&mut self, handle: u64) -> Result<&mut Context, GpuError> {
        self.contexts.get_mut(&handle).ok_or_else(|| {
            GpuError::new(
                wire::CUDA_ERROR_INVALID_HANDLE,
                format!("unknown context handle 0x{handle:x}"),
            )
        })
    }

    fn require_ordinal(ordinal: u32) -> Result<(), GpuError> {
        if ordinal == 0 {
            Ok(())
        } else {
            Err(GpuError::new(
                wire::CUDA_ERROR_INVALID_DEVICE,
                format!("the stub exposes exactly one device, ordinal 0, not {ordinal}"),
            ))
        }
    }
}

impl GpuBackend for StubBackend {
    fn driver_version(&mut self) -> Result<i32, GpuError> {
        Ok(STUB_DRIVER_VERSION)
    }

    fn device_count(&mut self) -> Result<u32, GpuError> {
        Ok(1)
    }

    fn device_name(&mut self, ordinal: u32) -> Result<String, GpuError> {
        Self::require_ordinal(ordinal)?;
        Ok(STUB_DEVICE_NAME.to_string())
    }

    fn device_total_mem(&mut self, ordinal: u32) -> Result<u64, GpuError> {
        Self::require_ordinal(ordinal)?;
        Ok(STUB_TOTAL_MEM_BYTES)
    }

    fn context_create(&mut self, ordinal: u32) -> Result<u64, GpuError> {
        Self::require_ordinal(ordinal)?;
        let handle = CTX_BASE + self.next_ctx * 0x1000;
        self.next_ctx += 1;
        self.contexts.insert(
            handle,
            Context {
                _ordinal: ordinal,
                allocations: HashMap::new(),
                next_ptr: 0,
                modules: HashMap::new(),
                next_module: 0,
                launches: Vec::new(),
            },
        );
        self.current = Some(handle);
        Ok(handle)
    }

    fn context_destroy(&mut self, handle: u64) -> Result<(), GpuError> {
        self.contexts
            .remove(&handle)
            .ok_or_else(|| {
                GpuError::new(
                    wire::CUDA_ERROR_INVALID_HANDLE,
                    format!("unknown context handle 0x{handle:x}"),
                )
            })
            .map(|_| {
                if self.current == Some(handle) {
                    self.current = None;
                }
            })
    }

    fn synchronize(&mut self, handle: u64) -> Result<(), GpuError> {
        // Nothing is ever in flight: a stub launch completes when recorded.
        self.context(handle).map(|_| ())
    }

    fn mem_alloc(&mut self, context: u64, bytes: u64) -> Result<u64, GpuError> {
        let ctx = self.context_mut(context)?;
        let bytes_usize = usize::try_from(bytes).map_err(|_| {
            GpuError::new(
                wire::CUDA_ERROR_OUT_OF_MEMORY,
                format!("allocation of {bytes} bytes does not fit this host"),
            )
        })?;
        // The honest failure a real driver gives for an impossible size:
        // refuse before touching the host allocator.
        if bytes_usize > STUB_TOTAL_MEM_BYTES as usize {
            return Err(GpuError::new(
                wire::CUDA_ERROR_OUT_OF_MEMORY,
                format!("allocation of {bytes} bytes exceeds the stub's device memory"),
            ));
        }
        let ptr = PTR_BASE + ctx.next_ptr * 0x1000;
        ctx.next_ptr += 1 + (bytes / 0x1000);
        ctx.allocations.insert(
            ptr,
            Allocation {
                bytes: vec![0_u8; bytes_usize],
            },
        );
        Ok(ptr)
    }

    fn mem_free(&mut self, context: u64, ptr: u64) -> Result<(), GpuError> {
        self.context_mut(context)?
            .allocations
            .remove(&ptr)
            .ok_or_else(|| {
                GpuError::new(
                    wire::CUDA_ERROR_INVALID_HANDLE,
                    format!("unknown device pointer 0x{ptr:x}"),
                )
            })
            .map(|_| ())
    }

    fn memcpy_htod(&mut self, context: u64, dst: u64, data: &[u8]) -> Result<(), GpuError> {
        let ctx = self.context_mut(context)?;
        let alloc = ctx.allocations.get_mut(&dst).ok_or_else(|| {
            GpuError::new(
                wire::CUDA_ERROR_INVALID_HANDLE,
                format!("unknown device pointer 0x{dst:x}"),
            )
        })?;
        let end = data.len();
        if end > alloc.bytes.len() {
            return Err(GpuError::new(
                wire::CUDA_ERROR_INVALID_VALUE,
                format!(
                    "HtoD copy of {} bytes into an allocation of {} bytes",
                    data.len(),
                    alloc.bytes.len()
                ),
            ));
        }
        alloc.bytes[..end].copy_from_slice(data);
        Ok(())
    }

    fn memcpy_dtoh(&mut self, context: u64, src: u64, len: u64) -> Result<Vec<u8>, GpuError> {
        let ctx = self.context(context)?;
        let alloc = ctx.allocations.get(&src).ok_or_else(|| {
            GpuError::new(
                wire::CUDA_ERROR_INVALID_HANDLE,
                format!("unknown device pointer 0x{src:x}"),
            )
        })?;
        let len = usize::try_from(len).map_err(|_| {
            GpuError::new(
                wire::CUDA_ERROR_INVALID_VALUE,
                "copy length overflows this host",
            )
        })?;
        if len > alloc.bytes.len() {
            return Err(GpuError::new(
                wire::CUDA_ERROR_INVALID_VALUE,
                format!(
                    "DtoH copy of {len} bytes from an allocation of {} bytes",
                    alloc.bytes.len()
                ),
            ));
        }
        Ok(alloc.bytes[..len].to_vec())
    }

    fn memset_d8(&mut self, context: u64, dst: u64, value: u8, len: u64) -> Result<(), GpuError> {
        let ctx = self.context_mut(context)?;
        let alloc = ctx.allocations.get_mut(&dst).ok_or_else(|| {
            GpuError::new(
                wire::CUDA_ERROR_INVALID_HANDLE,
                format!("unknown device pointer 0x{dst:x}"),
            )
        })?;
        let len = usize::try_from(len).map_err(|_| {
            GpuError::new(
                wire::CUDA_ERROR_INVALID_VALUE,
                "memset length overflows this host",
            )
        })?;
        if len > alloc.bytes.len() {
            return Err(GpuError::new(
                wire::CUDA_ERROR_INVALID_VALUE,
                format!(
                    "memset of {len} bytes on an allocation of {} bytes",
                    alloc.bytes.len()
                ),
            ));
        }
        alloc.bytes[..len].fill(value);
        Ok(())
    }

    fn module_load(&mut self, context: u64, image: &[u8]) -> Result<u64, GpuError> {
        if image.is_empty() {
            return Err(GpuError::new(
                wire::CUDA_ERROR_INVALID_IMAGE,
                "module image is empty",
            ));
        }
        let ctx = self.context_mut(context)?;
        let handle = MODULE_BASE + ctx.next_module * 0x1000;
        ctx.next_module += 1;
        ctx.modules.insert(
            handle,
            Module {
                _image_len: image.len(),
                functions: HashMap::new(),
                next_function: 0,
            },
        );
        Ok(handle)
    }

    fn module_unload(&mut self, context: u64, module: u64) -> Result<(), GpuError> {
        self.context_mut(context)?
            .modules
            .remove(&module)
            .ok_or_else(|| {
                GpuError::new(
                    wire::CUDA_ERROR_INVALID_HANDLE,
                    format!("unknown module handle 0x{module:x}"),
                )
            })
            .map(|_| ())
    }

    fn module_get_function(
        &mut self,
        context: u64,
        module: u64,
        name: &str,
    ) -> Result<u64, GpuError> {
        if name.is_empty() {
            return Err(GpuError::new(
                wire::CUDA_ERROR_INVALID_VALUE,
                "function name is empty",
            ));
        }
        let ctx = self.context_mut(context)?;
        let module = ctx.modules.get_mut(&module).ok_or_else(|| {
            GpuError::new(
                wire::CUDA_ERROR_INVALID_HANDLE,
                format!("unknown module handle 0x{module:x}"),
            )
        })?;
        if let Some(&handle) = module.functions.get(name) {
            return Ok(handle);
        }
        let handle = FUNCTION_BASE + module.next_function;
        module.next_function += 1;
        module.functions.insert(name.to_string(), handle);
        Ok(handle)
    }

    fn launch_kernel(
        &mut self,
        context: u64,
        function: u64,
        config: &LaunchConfig,
    ) -> Result<(), GpuError> {
        // The function handle must belong to some loaded module in this
        // context — a forged handle is refused, not laundered into a launch.
        let ctx = self.context_mut(context)?;
        let known = ctx
            .modules
            .values()
            .any(|module| module.functions.values().any(|&h| h == function));
        if !known {
            return Err(GpuError::new(
                wire::CUDA_ERROR_INVALID_HANDLE,
                format!("unknown function handle 0x{function:x}"),
            ));
        }
        ctx.launches.push(LaunchRecord {
            function,
            config: config.clone(),
        });
        Ok(())
    }

    fn nvml_device_count(&mut self) -> Result<u32, GpuError> {
        Ok(1)
    }

    fn nvml_driver_version(&mut self) -> Result<String, GpuError> {
        Ok(STUB_DRIVER_VERSION_STRING.to_string())
    }

    fn nvml_device_name(&mut self, ordinal: u32) -> Result<String, GpuError> {
        Self::require_ordinal(ordinal)?;
        Ok(format!("{STUB_DEVICE_NAME} (NVML)"))
    }

    fn nvml_memory_info(&mut self, ordinal: u32) -> Result<(u64, u64, u64), GpuError> {
        Self::require_ordinal(ordinal)?;
        let used: u64 = self
            .contexts
            .values()
            .flat_map(|ctx| ctx.allocations.values().map(|a| a.bytes.len() as u64))
            .sum();
        Ok((STUB_TOTAL_MEM_BYTES, STUB_TOTAL_MEM_BYTES - used, used))
    }

    fn nvml_utilization(&mut self, ordinal: u32) -> Result<(u32, u32), GpuError> {
        Self::require_ordinal(ordinal)?;
        // Nothing is ever in flight.
        Ok((0, 0))
    }

    fn nvml_compute_capability(&mut self, ordinal: u32) -> Result<(i32, i32), GpuError> {
        Self::require_ordinal(ordinal)?;
        Ok(STUB_COMPUTE_CAPABILITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stub_reports_one_fixed_device() {
        let mut gpu = StubBackend::new();
        assert_eq!(gpu.device_count(), Ok(1));
        assert_eq!(gpu.device_name(0), Ok(STUB_DEVICE_NAME.to_string()));
        assert_eq!(gpu.device_total_mem(0), Ok(STUB_TOTAL_MEM_BYTES));
        let err = gpu.device_name(1).expect_err("only ordinal 0 exists");
        assert_eq!(err.code, wire::CUDA_ERROR_INVALID_DEVICE);
    }

    #[test]
    fn alloc_copy_memset_and_free_round_trip_through_host_memory() {
        let mut gpu = StubBackend::new();
        let ctx = gpu.context_create(0).expect("context");
        let ptr = gpu.mem_alloc(ctx, 16).expect("alloc");
        assert!(ptr >= PTR_BASE);

        gpu.memcpy_htod(ctx, ptr, &[1, 2, 3, 4]).expect("htod");
        assert_eq!(
            gpu.memcpy_dtoh(ctx, ptr, 4).expect("dtoh"),
            vec![1, 2, 3, 4]
        );
        gpu.memset_d8(ctx, ptr, 0xaa, 2).expect("memset");
        assert_eq!(
            gpu.memcpy_dtoh(ctx, ptr, 4).expect("dtoh"),
            vec![0xaa, 0xaa, 3, 4]
        );

        gpu.mem_free(ctx, ptr).expect("free");
        let err = gpu.memcpy_dtoh(ctx, ptr, 1).expect_err("freed pointer");
        assert_eq!(err.code, wire::CUDA_ERROR_INVALID_HANDLE);
    }

    #[test]
    fn copies_past_the_allocation_are_refused() {
        let mut gpu = StubBackend::new();
        let ctx = gpu.context_create(0).expect("context");
        let ptr = gpu.mem_alloc(ctx, 4).expect("alloc");
        let err = gpu
            .memcpy_htod(ctx, ptr, &[0_u8; 8])
            .expect_err("oversize copy");
        assert_eq!(err.code, wire::CUDA_ERROR_INVALID_VALUE);
    }

    #[test]
    fn an_impossible_allocation_size_is_refused_before_touching_the_allocator() {
        let mut gpu = StubBackend::new();
        let ctx = gpu.context_create(0).expect("context");
        let err = gpu
            .mem_alloc(ctx, STUB_TOTAL_MEM_BYTES + 1)
            .expect_err("allocation past device memory");
        assert_eq!(err.code, wire::CUDA_ERROR_OUT_OF_MEMORY);
    }

    #[test]
    fn module_function_launch_flow_records_the_launch() {
        let mut gpu = StubBackend::new();
        let ctx = gpu.context_create(0).expect("context");
        let module = gpu.module_load(ctx, b"fake-ptx").expect("load");
        let function = gpu
            .module_get_function(ctx, module, "vector_add")
            .expect("function");
        let config = LaunchConfig {
            grid: [1, 1, 1],
            block: [32, 1, 1],
            shared_mem_bytes: 0,
            params: vec![vec![0; 8], vec![0; 8], vec![0; 8]],
        };
        gpu.launch_kernel(ctx, function, &config).expect("launch");
        assert_eq!(
            gpu.launches(),
            vec![LaunchRecord {
                function,
                config: config.clone()
            }]
        );

        let err = gpu
            .launch_kernel(ctx, 0xdead_beef, &config)
            .expect_err("forged function handle");
        assert_eq!(err.code, wire::CUDA_ERROR_INVALID_HANDLE);
    }

    #[test]
    fn nvml_reports_memory_used_by_live_allocations() {
        let mut gpu = StubBackend::new();
        assert_eq!(gpu.nvml_device_count(), Ok(1));
        let (total, free, used) = gpu.nvml_memory_info(0).expect("memory info");
        assert_eq!(total, STUB_TOTAL_MEM_BYTES);
        assert_eq!(used, 0);

        let ctx = gpu.context_create(0).expect("context");
        let _ptr = gpu.mem_alloc(ctx, 1024).expect("alloc");
        let (_, free_after, used_after) = gpu.nvml_memory_info(0).expect("memory info");
        assert_eq!(used_after, 1024);
        assert_eq!(free_after, free - 1024);
    }
}
