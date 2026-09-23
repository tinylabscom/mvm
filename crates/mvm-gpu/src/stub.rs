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
    streams: HashMap<u64, StreamState>,
    next_stream: u64,
    events: HashMap<u64, EventState>,
    next_event: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct StreamState {
    submitted: u64,
    completed: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct EventState {
    recorded: bool,
    stream: u64,
    target: u64,
    forced_complete: bool,
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
pub const STUB_DEVICE_COUNT: u32 = 2;
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
/// Stream and event handles occupy disjoint ranges.
const STREAM_BASE: u64 = 0x0000_0050_0000_0000;
const EVENT_BASE: u64 = 0x0000_00e0_0000_0000;

/// The deterministic stub backend. One instance serves one connection.
#[derive(Default)]
pub struct StubBackend {
    contexts: HashMap<u64, Context>,
    next_ctx: u64,
    current: Option<u64>,
    device_ordinal: Option<u32>,
}

impl StubBackend {
    /// A fresh stub with no state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict this backend to one host ordinal, exposed to the guest as
    /// ordinal zero.
    #[must_use]
    pub fn with_device_ordinal(mut self, ordinal: u32) -> Self {
        self.device_ordinal = Some(ordinal);
        self
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
        if ordinal < STUB_DEVICE_COUNT {
            Ok(())
        } else {
            Err(GpuError::new(
                wire::CUDA_ERROR_INVALID_DEVICE,
                format!(
                    "the stub exposes {STUB_DEVICE_COUNT} devices; ordinal {ordinal} is out of range"
                ),
            ))
        }
    }

    fn stream(context: &Context, handle: u64) -> Result<&StreamState, GpuError> {
        context.streams.get(&handle).ok_or_else(|| {
            GpuError::new(
                wire::CUDA_ERROR_INVALID_HANDLE,
                format!("unknown stream handle 0x{handle:x}"),
            )
        })
    }

    fn stream_mut(context: &mut Context, handle: u64) -> Result<&mut StreamState, GpuError> {
        context.streams.get_mut(&handle).ok_or_else(|| {
            GpuError::new(
                wire::CUDA_ERROR_INVALID_HANDLE,
                format!("unknown stream handle 0x{handle:x}"),
            )
        })
    }

    fn queue(context: &mut Context, stream: u64) -> Result<u64, GpuError> {
        let is_default = stream == 0;
        let state = Self::stream_mut(context, stream)?;
        state.submitted = state.submitted.checked_add(1).ok_or_else(|| {
            GpuError::new(
                wire::CUDA_ERROR_UNKNOWN,
                "stream completion counter overflow",
            )
        })?;
        if is_default {
            state.completed = state.submitted;
        }
        Ok(state.submitted)
    }
}

impl GpuBackend for StubBackend {
    fn device_ordinal(&self) -> Option<u32> {
        self.device_ordinal
    }

    fn driver_version(&mut self) -> Result<i32, GpuError> {
        Ok(STUB_DRIVER_VERSION)
    }

    fn device_count(&mut self) -> Result<u32, GpuError> {
        Ok(STUB_DEVICE_COUNT)
    }

    fn device_name(&mut self, ordinal: u32) -> Result<String, GpuError> {
        Self::require_ordinal(ordinal)?;
        Ok(if ordinal == 0 {
            STUB_DEVICE_NAME.to_string()
        } else {
            format!("{STUB_DEVICE_NAME} {ordinal}")
        })
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
                streams: HashMap::from([(0, StreamState::default())]),
                next_stream: 0,
                events: HashMap::new(),
                next_event: 0,
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
        let context = self.context_mut(handle)?;
        for stream in context.streams.values_mut() {
            stream.completed = stream.submitted;
        }
        Ok(())
    }

    fn stream_create(&mut self, context: u64, flags: u32) -> Result<u64, GpuError> {
        if flags & !1 != 0 {
            return Err(GpuError::new(
                wire::CUDA_ERROR_INVALID_VALUE,
                format!("unsupported stream flags 0x{flags:x}"),
            ));
        }
        let context = self.context_mut(context)?;
        let offset = context.next_stream.checked_mul(0x1000).ok_or_else(|| {
            GpuError::new(wire::CUDA_ERROR_UNKNOWN, "stream handle counter overflow")
        })?;
        let handle = STREAM_BASE.checked_add(offset).ok_or_else(|| {
            GpuError::new(wire::CUDA_ERROR_UNKNOWN, "stream handle counter overflow")
        })?;
        context.next_stream = context.next_stream.checked_add(1).ok_or_else(|| {
            GpuError::new(wire::CUDA_ERROR_UNKNOWN, "stream handle counter overflow")
        })?;
        context.streams.insert(handle, StreamState::default());
        Ok(handle)
    }

    fn stream_destroy(&mut self, context: u64, stream: u64) -> Result<(), GpuError> {
        if stream == 0 {
            return Err(GpuError::new(
                wire::CUDA_ERROR_INVALID_HANDLE,
                "the default stream cannot be destroyed",
            ));
        }
        let context = self.context_mut(context)?;
        context.streams.remove(&stream).ok_or_else(|| {
            GpuError::new(
                wire::CUDA_ERROR_INVALID_HANDLE,
                format!("unknown stream handle 0x{stream:x}"),
            )
        })?;
        for event in context
            .events
            .values_mut()
            .filter(|event| event.stream == stream)
        {
            event.forced_complete = true;
        }
        Ok(())
    }

    fn stream_synchronize(&mut self, context: u64, stream: u64) -> Result<(), GpuError> {
        let stream = Self::stream_mut(self.context_mut(context)?, stream)?;
        stream.completed = stream.submitted;
        Ok(())
    }

    fn stream_wait_event(
        &mut self,
        context: u64,
        stream: u64,
        event: u64,
    ) -> Result<u64, GpuError> {
        self.event_synchronize(context, event)?;
        Self::queue(self.context_mut(context)?, stream)
    }

    fn event_create(&mut self, context: u64, flags: u32) -> Result<u64, GpuError> {
        if flags & !7 != 0 {
            return Err(GpuError::new(
                wire::CUDA_ERROR_INVALID_VALUE,
                format!("unsupported event flags 0x{flags:x}"),
            ));
        }
        let context = self.context_mut(context)?;
        let offset = context.next_event.checked_mul(0x1000).ok_or_else(|| {
            GpuError::new(wire::CUDA_ERROR_UNKNOWN, "event handle counter overflow")
        })?;
        let handle = EVENT_BASE.checked_add(offset).ok_or_else(|| {
            GpuError::new(wire::CUDA_ERROR_UNKNOWN, "event handle counter overflow")
        })?;
        context.next_event = context.next_event.checked_add(1).ok_or_else(|| {
            GpuError::new(wire::CUDA_ERROR_UNKNOWN, "event handle counter overflow")
        })?;
        context.events.insert(handle, EventState::default());
        Ok(handle)
    }

    fn event_destroy(&mut self, context: u64, event: u64) -> Result<(), GpuError> {
        self.context_mut(context)?
            .events
            .remove(&event)
            .ok_or_else(|| {
                GpuError::new(
                    wire::CUDA_ERROR_INVALID_HANDLE,
                    format!("unknown event handle 0x{event:x}"),
                )
            })
            .map(|_| ())
    }

    fn event_record(&mut self, context: u64, event: u64, stream: u64) -> Result<u64, GpuError> {
        let context = self.context_mut(context)?;
        let target = Self::queue(context, stream)?;
        let state = context.events.get_mut(&event).ok_or_else(|| {
            GpuError::new(
                wire::CUDA_ERROR_INVALID_HANDLE,
                format!("unknown event handle 0x{event:x}"),
            )
        })?;
        *state = EventState {
            recorded: true,
            stream,
            target,
            forced_complete: false,
        };
        Ok(target)
    }

    fn event_query(&mut self, context: u64, event: u64) -> Result<bool, GpuError> {
        let context = self.context(context)?;
        let state = *context.events.get(&event).ok_or_else(|| {
            GpuError::new(
                wire::CUDA_ERROR_INVALID_HANDLE,
                format!("unknown event handle 0x{event:x}"),
            )
        })?;
        if !state.recorded || state.forced_complete {
            return Ok(true);
        }
        Ok(Self::stream(context, state.stream)?.completed >= state.target)
    }

    fn event_synchronize(&mut self, context: u64, event: u64) -> Result<(), GpuError> {
        let context = self.context_mut(context)?;
        let state = *context.events.get(&event).ok_or_else(|| {
            GpuError::new(
                wire::CUDA_ERROR_INVALID_HANDLE,
                format!("unknown event handle 0x{event:x}"),
            )
        })?;
        if state.recorded && !state.forced_complete {
            let stream = Self::stream_mut(context, state.stream)?;
            stream.completed = stream.completed.max(state.target);
        }
        Ok(())
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

    fn memcpy_htod_async(
        &mut self,
        context: u64,
        dst: u64,
        data: &[u8],
        stream: u64,
    ) -> Result<u64, GpuError> {
        Self::stream(self.context(context)?, stream)?;
        self.memcpy_htod(context, dst, data)?;
        Self::queue(self.context_mut(context)?, stream)
    }

    fn memcpy_dtoh_async(
        &mut self,
        context: u64,
        src: u64,
        len: u64,
        stream: u64,
    ) -> Result<(Vec<u8>, u64), GpuError> {
        Self::stream(self.context(context)?, stream)?;
        let bytes = self.memcpy_dtoh(context, src, len)?;
        let completion = Self::queue(self.context_mut(context)?, stream)?;
        Ok((bytes, completion))
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
        Self::queue(ctx, config.stream.unwrap_or(0))?;
        ctx.launches.push(LaunchRecord {
            function,
            config: config.clone(),
        });
        Ok(())
    }

    fn nvml_device_count(&mut self) -> Result<u32, GpuError> {
        Ok(STUB_DEVICE_COUNT)
    }

    fn nvml_driver_version(&mut self) -> Result<String, GpuError> {
        Ok(STUB_DRIVER_VERSION_STRING.to_string())
    }

    fn nvml_device_name(&mut self, ordinal: u32) -> Result<String, GpuError> {
        Self::require_ordinal(ordinal)?;
        Ok(format!("{STUB_DEVICE_NAME} {ordinal} (NVML)"))
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
    fn the_stub_reports_distinct_deterministic_devices() {
        let mut gpu = StubBackend::new();
        assert_eq!(gpu.device_count(), Ok(2));
        assert_eq!(gpu.device_name(0), Ok(STUB_DEVICE_NAME.to_string()));
        assert_eq!(gpu.device_name(1), Ok(format!("{STUB_DEVICE_NAME} 1")));
        assert_eq!(gpu.device_total_mem(0), Ok(STUB_TOTAL_MEM_BYTES));
        let first = gpu.context_create(0).expect("device zero context");
        let second = gpu.context_create(1).expect("device one context");
        assert_eq!(gpu.contexts[&first]._ordinal, 0);
        assert_eq!(gpu.contexts[&second]._ordinal, 1);
        let err = gpu.device_name(2).expect_err("only ordinals 0 and 1 exist");
        assert_eq!(err.code, wire::CUDA_ERROR_INVALID_DEVICE);
    }

    #[test]
    fn a_device_pin_exposes_one_guest_ordinal_mapped_to_the_host_selection() {
        let mut gpu = StubBackend::new().with_device_ordinal(1);
        assert_eq!(
            crate::handle_request(&mut gpu, &crate::GpuRequest::DeviceGetCount),
            crate::GpuResponse::DeviceCount { count: 1 }
        );
        assert_eq!(
            crate::handle_request(&mut gpu, &crate::GpuRequest::DeviceGetName { ordinal: 0 }),
            crate::GpuResponse::DeviceName {
                name: format!("{STUB_DEVICE_NAME} 1")
            }
        );
        let crate::GpuResponse::ContextCreated { context } =
            crate::handle_request(&mut gpu, &crate::GpuRequest::ContextCreate { ordinal: 0 })
        else {
            panic!("guest ordinal zero must create a context on the selected host device");
        };
        assert_eq!(gpu.contexts[&context]._ordinal, 1);
        let crate::GpuResponse::Err(error) =
            crate::handle_request(&mut gpu, &crate::GpuRequest::DeviceGetName { ordinal: 1 })
        else {
            panic!("guest ordinal 1 must be hidden by the pin");
        };
        assert_eq!(error.code, wire::CUDA_ERROR_INVALID_DEVICE);
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
    fn async_copy_event_query_and_wait_have_deterministic_completion() {
        let mut gpu = StubBackend::new();
        let ctx = gpu.context_create(0).expect("context");
        let stream = gpu.stream_create(ctx, 1).expect("stream");
        let event = gpu.event_create(ctx, 2).expect("event");
        let ptr = gpu.mem_alloc(ctx, 4).expect("allocation");

        assert_eq!(
            gpu.memcpy_htod_async(ctx, ptr, &[1, 2, 3, 4], stream),
            Ok(1)
        );
        assert_eq!(gpu.event_record(ctx, event, stream), Ok(2));
        assert_eq!(gpu.event_query(ctx, event), Ok(false));

        gpu.event_synchronize(ctx, event).expect("event wait");
        assert_eq!(gpu.event_query(ctx, event), Ok(true));
        assert_eq!(
            gpu.memcpy_dtoh_async(ctx, ptr, 4, stream),
            Ok((vec![1, 2, 3, 4], 3))
        );
        assert_eq!(gpu.event_record(ctx, event, stream), Ok(4));
        assert_eq!(gpu.event_query(ctx, event), Ok(false));
        gpu.stream_synchronize(ctx, stream).expect("stream wait");
        assert_eq!(gpu.event_query(ctx, event), Ok(true));
    }

    #[test]
    fn forged_streams_and_events_are_refused_without_queueing_work() {
        let mut gpu = StubBackend::new();
        let ctx = gpu.context_create(0).expect("context");
        let ptr = gpu.mem_alloc(ctx, 1).expect("allocation");
        let err = gpu
            .memcpy_htod_async(ctx, ptr, &[9], 0xdead_beef)
            .expect_err("forged stream");
        assert_eq!(err.code, wire::CUDA_ERROR_INVALID_HANDLE);
        assert_eq!(gpu.memcpy_dtoh(ctx, ptr, 1), Ok(vec![0]));

        let err = gpu.event_query(ctx, 0xdead_beef).expect_err("forged event");
        assert_eq!(err.code, wire::CUDA_ERROR_INVALID_HANDLE);
    }

    #[test]
    fn destroying_a_stream_completes_its_recorded_events() {
        let mut gpu = StubBackend::new();
        let ctx = gpu.context_create(0).expect("context");
        let stream = gpu.stream_create(ctx, 0).expect("stream");
        let event = gpu.event_create(ctx, 0).expect("event");
        let ptr = gpu.mem_alloc(ctx, 1).expect("allocation");
        gpu.memcpy_htod_async(ctx, ptr, &[7], stream)
            .expect("async copy");
        gpu.event_record(ctx, event, stream).expect("record");
        assert_eq!(gpu.event_query(ctx, event), Ok(false));
        gpu.stream_destroy(ctx, stream).expect("destroy");
        assert_eq!(gpu.event_query(ctx, event), Ok(true));
        let err = gpu
            .memcpy_htod_async(ctx, ptr, &[8], stream)
            .expect_err("destroyed stream is stale");
        assert_eq!(err.code, wire::CUDA_ERROR_INVALID_HANDLE);
    }

    #[test]
    fn a_stream_wait_orders_the_waiting_stream_after_the_source_event() {
        let mut gpu = StubBackend::new();
        let ctx = gpu.context_create(0).expect("context");
        let source = gpu.stream_create(ctx, 0).expect("source stream");
        let waiting = gpu.stream_create(ctx, 0).expect("waiting stream");
        let source_event = gpu.event_create(ctx, 0).expect("source event");
        let waiting_event = gpu.event_create(ctx, 0).expect("waiting event");
        let ptr = gpu.mem_alloc(ctx, 1).expect("allocation");

        gpu.memcpy_htod_async(ctx, ptr, &[1], source)
            .expect("source work");
        gpu.event_record(ctx, source_event, source)
            .expect("source record");
        assert_eq!(gpu.event_query(ctx, source_event), Ok(false));
        assert_eq!(gpu.stream_wait_event(ctx, waiting, source_event), Ok(1));
        assert_eq!(gpu.event_query(ctx, source_event), Ok(true));
        gpu.event_record(ctx, waiting_event, waiting)
            .expect("waiting record");
        assert_eq!(gpu.event_query(ctx, waiting_event), Ok(false));
        gpu.stream_synchronize(ctx, waiting).expect("waiting sync");
        assert_eq!(gpu.event_query(ctx, waiting_event), Ok(true));
    }

    #[test]
    fn default_stream_async_calls_remain_synchronously_complete() {
        let mut gpu = StubBackend::new();
        let ctx = gpu.context_create(0).expect("context");
        let event = gpu.event_create(ctx, 0).expect("event");
        let ptr = gpu.mem_alloc(ctx, 1).expect("allocation");
        assert_eq!(gpu.memcpy_htod_async(ctx, ptr, &[8], 0), Ok(1));
        assert_eq!(gpu.event_record(ctx, event, 0), Ok(2));
        assert_eq!(gpu.event_query(ctx, event), Ok(true));
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
            stream: None,
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
        assert_eq!(gpu.nvml_device_count(), Ok(2));
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
