//! Host-side GPU endpoint: the process that owns the GPU and answers the
//! guest's shim RPCs.
//!
//! A guest with `--gpu` carries no driver and no device nodes; its
//! `libcuda.so.1` / `libcudart.so` / `libnvidia-ml.so.1` are mvm shims that
//! forward every call over vsock ([`mvm_contract::protocol::gpu`]) to this
//! endpoint. The endpoint runs each call against a [`GpuBackend`]:
//!
//! - [`NativeCudaBackend`](native::NativeCudaBackend) — dynamically loads the
//!   real `libcuda.so.1` / `libnvidia-ml.so.1` from the host. The driver
//!   stays entirely on the host; only its answers cross the vsock.
//! - [`StubBackend`](stub::StubBackend) — a deterministic fake device backed
//!   by host memory. It exists so the whole transport is testable on a
//!   machine with no GPU, and so a `--gpu` guest on a GPU-less host fails
//!   loudly at the endpoint, never silently inside the workload.
//!
//! Everything the guest can reference — contexts, device pointers, modules,
//! functions — is an opaque `u64` handle minted here. A forged handle is a
//! lookup miss, never a host address.

pub mod native;
pub mod server;
pub mod stub;

pub use mvm_contract::protocol::gpu as wire;
pub use mvm_contract::protocol::gpu::{GpuError, GpuRequest, GpuResponse};

/// The launch shape of [`GpuBackend::launch_kernel`]: grid, block, shared
/// memory, and the parameter blobs. Carried as one value so a launch
/// cannot transpose same-typed arguments and the trait method does not grow
/// a positional argument list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LaunchConfig {
    pub grid: [u32; 3],
    pub block: [u32; 3],
    pub shared_mem_bytes: u32,
    /// `None` selects CUDA's legacy default stream.
    pub stream: Option<u64>,
    pub params: Vec<Vec<u8>>,
}

impl LaunchConfig {
    /// Validate against the wire contract's caps. Run before trusting a
    /// guest-supplied launch.
    pub fn validate(&self) -> Result<(), GpuError> {
        if self.params.len() > wire::MAX_KERNEL_PARAMS {
            return Err(GpuError::new(
                wire::CUDA_ERROR_INVALID_VALUE,
                format!(
                    "{} kernel parameters exceed the {}-parameter wire cap",
                    self.params.len(),
                    wire::MAX_KERNEL_PARAMS
                ),
            ));
        }
        for (i, blob) in self.params.iter().enumerate() {
            let len = blob.len() as u64;
            if len > wire::MAX_PARAM_LEN {
                return Err(GpuError::new(
                    wire::CUDA_ERROR_INVALID_VALUE,
                    format!(
                        "kernel parameter {i} is {len} bytes, past the {}-byte wire cap \
                         (pass large data through device memory, not parameters)",
                        wire::MAX_PARAM_LEN
                    ),
                ));
            }
        }
        Ok(())
    }
}

/// Run one request against `backend`. Pure dispatch: no I/O, so every arm
/// is unit-testable without a socket.
pub fn handle_request(backend: &mut dyn GpuBackend, request: &GpuRequest) -> GpuResponse {
    match request {
        GpuRequest::DriverGetVersion => backend
            .driver_version()
            .map(|version| GpuResponse::DriverVersion { version })
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::DeviceGetCount => visible_device_count(backend, false)
            .map(|count| GpuResponse::DeviceCount { count })
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::DeviceGetName { ordinal } => visible_ordinal(backend, *ordinal, false)
            .and_then(|ordinal| backend.device_name(ordinal))
            .map(|name| GpuResponse::DeviceName { name })
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::DeviceTotalMem { ordinal } => visible_ordinal(backend, *ordinal, false)
            .and_then(|ordinal| backend.device_total_mem(ordinal))
            .map(|bytes| GpuResponse::DeviceTotalMem { bytes })
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::ContextCreate { ordinal } => visible_ordinal(backend, *ordinal, false)
            .and_then(|ordinal| backend.context_create(ordinal))
            .map(|context| GpuResponse::ContextCreated { context })
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::ContextDestroy { context } => backend
            .context_destroy(*context)
            .map(|()| GpuResponse::Ok)
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::Synchronize { context } => backend
            .synchronize(*context)
            .map(|()| GpuResponse::Ok)
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::StreamCreate { context, flags } => backend
            .stream_create(*context, *flags)
            .map(|stream| GpuResponse::StreamCreated { stream })
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::StreamDestroy { context, stream } => backend
            .stream_destroy(*context, *stream)
            .map(|()| GpuResponse::Ok)
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::StreamSynchronize { context, stream } => backend
            .stream_synchronize(*context, *stream)
            .map(|()| GpuResponse::Ok)
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::StreamWaitEvent {
            context,
            stream,
            event,
        } => backend
            .stream_wait_event(*context, *stream, *event)
            .map(|completion| GpuResponse::AsyncQueued { completion })
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::EventCreate { context, flags } => backend
            .event_create(*context, *flags)
            .map(|event| GpuResponse::EventCreated { event })
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::EventDestroy { context, event } => backend
            .event_destroy(*context, *event)
            .map(|()| GpuResponse::Ok)
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::EventRecord {
            context,
            event,
            stream,
        } => backend
            .event_record(*context, *event, *stream)
            .map(|completion| GpuResponse::AsyncQueued { completion })
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::EventQuery { context, event } => backend
            .event_query(*context, *event)
            .map(|complete| GpuResponse::EventStatus { complete })
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::EventSynchronize { context, event } => backend
            .event_synchronize(*context, *event)
            .map(|()| GpuResponse::Ok)
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::MemAlloc { context, bytes } => backend
            .mem_alloc(*context, *bytes)
            .map(|ptr| GpuResponse::DevicePointer { ptr })
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::MemFree { context, ptr } => backend
            .mem_free(*context, *ptr)
            .map(|()| GpuResponse::Ok)
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::MemcpyHtoD { context, dst, data } => backend
            .memcpy_htod(*context, *dst, data)
            .map(|()| GpuResponse::Ok)
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::MemcpyDtoH { context, src, len } => backend
            .memcpy_dtoh(*context, *src, *len)
            .map(|bytes| GpuResponse::Data { bytes })
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::MemcpyHtoDAsync {
            context,
            dst,
            data,
            stream,
        } => backend
            .memcpy_htod_async(*context, *dst, data, *stream)
            .map(|completion| GpuResponse::AsyncQueued { completion })
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::MemcpyDtoHAsync {
            context,
            src,
            len,
            stream,
        } => backend
            .memcpy_dtoh_async(*context, *src, *len, *stream)
            .map(|(bytes, completion)| GpuResponse::DataQueued { bytes, completion })
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::MemsetD8 {
            context,
            dst,
            value,
            len,
        } => backend
            .memset_d8(*context, *dst, *value, *len)
            .map(|()| GpuResponse::Ok)
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::ModuleLoad { context, image } => backend
            .module_load(*context, image)
            .map(|module| GpuResponse::ModuleLoaded { module })
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::ModuleUnload { context, module } => backend
            .module_unload(*context, *module)
            .map(|()| GpuResponse::Ok)
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::ModuleGetFunction {
            context,
            module,
            name,
        } => backend
            .module_get_function(*context, *module, name)
            .map(|handle| GpuResponse::Function { handle })
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::LaunchKernel {
            context,
            function,
            grid,
            block,
            shared_mem_bytes,
            stream,
            params,
        } => {
            let config = LaunchConfig {
                grid: *grid,
                block: *block,
                shared_mem_bytes: *shared_mem_bytes,
                stream: *stream,
                params: params.clone(),
            };
            if let Err(e) = config.validate() {
                return GpuResponse::Err(e);
            }
            backend
                .launch_kernel(*context, *function, &config)
                .map(|()| GpuResponse::Ok)
                .unwrap_or_else(GpuResponse::Err)
        }
        GpuRequest::NvmlDeviceGetCount => visible_device_count(backend, true)
            .map(|count| GpuResponse::NvmlDeviceCount { count })
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::NvmlSystemGetDriverVersion => backend
            .nvml_driver_version()
            .map(|version| GpuResponse::NvmlDriverVersion { version })
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::NvmlDeviceGetName { ordinal } => visible_ordinal(backend, *ordinal, true)
            .and_then(|ordinal| backend.nvml_device_name(ordinal))
            .map(|name| GpuResponse::DeviceName { name })
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::NvmlDeviceGetMemoryInfo { ordinal } => visible_ordinal(backend, *ordinal, true)
            .and_then(|ordinal| backend.nvml_memory_info(ordinal))
            .map(|(total, free, used)| GpuResponse::NvmlMemoryInfo { total, free, used })
            .unwrap_or_else(GpuResponse::Err),
        GpuRequest::NvmlDeviceGetUtilizationRates { ordinal } => {
            visible_ordinal(backend, *ordinal, true)
                .and_then(|ordinal| backend.nvml_utilization(ordinal))
                .map(|(gpu, memory)| GpuResponse::NvmlUtilization { gpu, memory })
                .unwrap_or_else(GpuResponse::Err)
        }
        GpuRequest::NvmlDeviceGetCudaComputeCapability { ordinal } => {
            visible_ordinal(backend, *ordinal, true)
                .and_then(|ordinal| backend.nvml_compute_capability(ordinal))
                .map(|(major, minor)| GpuResponse::NvmlComputeCapability { major, minor })
                .unwrap_or_else(GpuResponse::Err)
        }
    }
}

fn invalid_device(nvml: bool, message: impl Into<String>) -> GpuError {
    GpuError::new(
        if nvml {
            wire::NVML_ERROR_INVALID_ARGUMENT
        } else {
            wire::CUDA_ERROR_INVALID_DEVICE
        },
        message,
    )
}

fn visible_ordinal(
    backend: &dyn GpuBackend,
    guest_ordinal: u32,
    nvml: bool,
) -> Result<u32, GpuError> {
    match backend.device_ordinal() {
        None => Ok(guest_ordinal),
        Some(host_ordinal) if guest_ordinal == 0 => Ok(host_ordinal),
        Some(host_ordinal) => Err(invalid_device(
            nvml,
            format!(
                "this VM is pinned to host GPU {host_ordinal}; only guest ordinal 0 is visible, not {guest_ordinal}"
            ),
        )),
    }
}

fn visible_device_count(backend: &mut dyn GpuBackend, nvml: bool) -> Result<u32, GpuError> {
    let count = if nvml {
        backend.nvml_device_count()?
    } else {
        backend.device_count()?
    };
    match backend.device_ordinal() {
        None => Ok(count),
        Some(host_ordinal) if host_ordinal < count => Ok(1),
        Some(host_ordinal) => Err(invalid_device(
            nvml,
            format!("host GPU ordinal {host_ordinal} is outside the detected device count {count}"),
        )),
    }
}

/// One GPU and its driver, behind the operations the wire protocol needs.
///
/// Implementations own their handle tables; a handle is only ever meaningful
/// to the backend instance that minted it, on the connection that asked.
pub trait GpuBackend: Send {
    /// Host device exposed as guest ordinal zero, or `None` to expose every
    /// backend device with its native ordinal.
    fn device_ordinal(&self) -> Option<u32> {
        None
    }

    fn driver_version(&mut self) -> Result<i32, GpuError>;
    fn device_count(&mut self) -> Result<u32, GpuError>;
    fn device_name(&mut self, ordinal: u32) -> Result<String, GpuError>;
    fn device_total_mem(&mut self, ordinal: u32) -> Result<u64, GpuError>;

    fn context_create(&mut self, ordinal: u32) -> Result<u64, GpuError>;
    fn context_destroy(&mut self, context: u64) -> Result<(), GpuError>;
    fn synchronize(&mut self, context: u64) -> Result<(), GpuError>;
    fn stream_create(&mut self, context: u64, flags: u32) -> Result<u64, GpuError>;
    fn stream_destroy(&mut self, context: u64, stream: u64) -> Result<(), GpuError>;
    fn stream_synchronize(&mut self, context: u64, stream: u64) -> Result<(), GpuError>;
    fn stream_wait_event(&mut self, context: u64, stream: u64, event: u64)
    -> Result<u64, GpuError>;
    fn event_create(&mut self, context: u64, flags: u32) -> Result<u64, GpuError>;
    fn event_destroy(&mut self, context: u64, event: u64) -> Result<(), GpuError>;
    fn event_record(&mut self, context: u64, event: u64, stream: u64) -> Result<u64, GpuError>;
    fn event_query(&mut self, context: u64, event: u64) -> Result<bool, GpuError>;
    fn event_synchronize(&mut self, context: u64, event: u64) -> Result<(), GpuError>;

    fn mem_alloc(&mut self, context: u64, bytes: u64) -> Result<u64, GpuError>;
    fn mem_free(&mut self, context: u64, ptr: u64) -> Result<(), GpuError>;
    fn memcpy_htod(&mut self, context: u64, dst: u64, data: &[u8]) -> Result<(), GpuError>;
    fn memcpy_dtoh(&mut self, context: u64, src: u64, len: u64) -> Result<Vec<u8>, GpuError>;
    fn memcpy_htod_async(
        &mut self,
        context: u64,
        dst: u64,
        data: &[u8],
        stream: u64,
    ) -> Result<u64, GpuError>;
    fn memcpy_dtoh_async(
        &mut self,
        context: u64,
        src: u64,
        len: u64,
        stream: u64,
    ) -> Result<(Vec<u8>, u64), GpuError>;
    fn memset_d8(&mut self, context: u64, dst: u64, value: u8, len: u64) -> Result<(), GpuError>;

    fn module_load(&mut self, context: u64, image: &[u8]) -> Result<u64, GpuError>;
    fn module_unload(&mut self, context: u64, module: u64) -> Result<(), GpuError>;
    fn module_get_function(
        &mut self,
        context: u64,
        module: u64,
        name: &str,
    ) -> Result<u64, GpuError>;
    fn launch_kernel(
        &mut self,
        context: u64,
        function: u64,
        config: &LaunchConfig,
    ) -> Result<(), GpuError>;

    fn nvml_device_count(&mut self) -> Result<u32, GpuError>;
    fn nvml_driver_version(&mut self) -> Result<String, GpuError>;
    fn nvml_device_name(&mut self, ordinal: u32) -> Result<String, GpuError>;
    fn nvml_memory_info(&mut self, ordinal: u32) -> Result<(u64, u64, u64), GpuError>;
    fn nvml_utilization(&mut self, ordinal: u32) -> Result<(u32, u32), GpuError>;
    fn nvml_compute_capability(&mut self, ordinal: u32) -> Result<(i32, i32), GpuError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A backend that answers every call with one fixed error, so dispatch
    /// itself is what the test observes.
    struct FixedErrBackend {
        code: i32,
        calls: std::cell::RefCell<Vec<&'static str>>,
    }

    impl FixedErrBackend {
        fn record(&self, name: &'static str) -> Result<i32, GpuError> {
            self.calls.borrow_mut().push(name);
            Err(GpuError::new(self.code, "fixed"))
        }
    }

    impl GpuBackend for FixedErrBackend {
        fn driver_version(&mut self) -> Result<i32, GpuError> {
            self.record("driver_version")
        }
        fn device_count(&mut self) -> Result<u32, GpuError> {
            self.record("device_count").map(|_| 0)
        }
        fn device_name(&mut self, _: u32) -> Result<String, GpuError> {
            self.record("device_name").map(|_| String::new())
        }
        fn device_total_mem(&mut self, _: u32) -> Result<u64, GpuError> {
            self.record("device_total_mem").map(|_| 0)
        }
        fn context_create(&mut self, _: u32) -> Result<u64, GpuError> {
            self.record("context_create").map(|_| 0)
        }
        fn context_destroy(&mut self, _: u64) -> Result<(), GpuError> {
            self.record("context_destroy").map(|_| ())
        }
        fn synchronize(&mut self, _: u64) -> Result<(), GpuError> {
            self.record("synchronize").map(|_| ())
        }
        fn stream_create(&mut self, _: u64, _: u32) -> Result<u64, GpuError> {
            self.record("stream_create").map(|_| 0)
        }
        fn stream_destroy(&mut self, _: u64, _: u64) -> Result<(), GpuError> {
            self.record("stream_destroy").map(|_| ())
        }
        fn stream_synchronize(&mut self, _: u64, _: u64) -> Result<(), GpuError> {
            self.record("stream_synchronize").map(|_| ())
        }
        fn stream_wait_event(&mut self, _: u64, _: u64, _: u64) -> Result<u64, GpuError> {
            self.record("stream_wait_event").map(|_| 0)
        }
        fn event_create(&mut self, _: u64, _: u32) -> Result<u64, GpuError> {
            self.record("event_create").map(|_| 0)
        }
        fn event_destroy(&mut self, _: u64, _: u64) -> Result<(), GpuError> {
            self.record("event_destroy").map(|_| ())
        }
        fn event_record(&mut self, _: u64, _: u64, _: u64) -> Result<u64, GpuError> {
            self.record("event_record").map(|_| 0)
        }
        fn event_query(&mut self, _: u64, _: u64) -> Result<bool, GpuError> {
            self.record("event_query").map(|_| false)
        }
        fn event_synchronize(&mut self, _: u64, _: u64) -> Result<(), GpuError> {
            self.record("event_synchronize").map(|_| ())
        }
        fn mem_alloc(&mut self, _: u64, _: u64) -> Result<u64, GpuError> {
            self.record("mem_alloc").map(|_| 0)
        }
        fn mem_free(&mut self, _: u64, _: u64) -> Result<(), GpuError> {
            self.record("mem_free").map(|_| ())
        }
        fn memcpy_htod(&mut self, _: u64, _: u64, _: &[u8]) -> Result<(), GpuError> {
            self.record("memcpy_htod").map(|_| ())
        }
        fn memcpy_dtoh(&mut self, _: u64, _: u64, _: u64) -> Result<Vec<u8>, GpuError> {
            self.record("memcpy_dtoh").map(|_| Vec::new())
        }
        fn memcpy_htod_async(&mut self, _: u64, _: u64, _: &[u8], _: u64) -> Result<u64, GpuError> {
            self.record("memcpy_htod_async").map(|_| 0)
        }
        fn memcpy_dtoh_async(
            &mut self,
            _: u64,
            _: u64,
            _: u64,
            _: u64,
        ) -> Result<(Vec<u8>, u64), GpuError> {
            self.record("memcpy_dtoh_async").map(|_| (Vec::new(), 0))
        }
        fn memset_d8(&mut self, _: u64, _: u64, _: u8, _: u64) -> Result<(), GpuError> {
            self.record("memset_d8").map(|_| ())
        }
        fn module_load(&mut self, _: u64, _: &[u8]) -> Result<u64, GpuError> {
            self.record("module_load").map(|_| 0)
        }
        fn module_unload(&mut self, _: u64, _: u64) -> Result<(), GpuError> {
            self.record("module_unload").map(|_| ())
        }
        fn module_get_function(&mut self, _: u64, _: u64, _: &str) -> Result<u64, GpuError> {
            self.record("module_get_function").map(|_| 0)
        }
        fn launch_kernel(&mut self, _: u64, _: u64, _: &LaunchConfig) -> Result<(), GpuError> {
            self.record("launch_kernel").map(|_| ())
        }
        fn nvml_device_count(&mut self) -> Result<u32, GpuError> {
            self.record("nvml_device_count").map(|_| 0)
        }
        fn nvml_driver_version(&mut self) -> Result<String, GpuError> {
            self.record("nvml_driver_version").map(|_| String::new())
        }
        fn nvml_device_name(&mut self, _: u32) -> Result<String, GpuError> {
            self.record("nvml_device_name").map(|_| String::new())
        }
        fn nvml_memory_info(&mut self, _: u32) -> Result<(u64, u64, u64), GpuError> {
            self.record("nvml_memory_info").map(|_| (0, 0, 0))
        }
        fn nvml_utilization(&mut self, _: u32) -> Result<(u32, u32), GpuError> {
            self.record("nvml_utilization").map(|_| (0, 0))
        }
        fn nvml_compute_capability(&mut self, _: u32) -> Result<(i32, i32), GpuError> {
            self.record("nvml_compute_capability").map(|_| (0, 0))
        }
    }

    #[test]
    fn dispatch_reaches_the_matching_backend_method() {
        let mut backend = FixedErrBackend {
            code: wire::CUDA_ERROR_UNKNOWN,
            calls: std::cell::RefCell::new(Vec::new()),
        };
        let cases: Vec<(GpuRequest, &'static str)> = vec![
            (GpuRequest::DriverGetVersion, "driver_version"),
            (GpuRequest::DeviceGetCount, "device_count"),
            (GpuRequest::DeviceGetName { ordinal: 0 }, "device_name"),
            (
                GpuRequest::DeviceTotalMem { ordinal: 0 },
                "device_total_mem",
            ),
            (GpuRequest::ContextCreate { ordinal: 0 }, "context_create"),
            (GpuRequest::ContextDestroy { context: 1 }, "context_destroy"),
            (GpuRequest::Synchronize { context: 1 }, "synchronize"),
            (
                GpuRequest::StreamCreate {
                    context: 1,
                    flags: 0,
                },
                "stream_create",
            ),
            (
                GpuRequest::StreamDestroy {
                    context: 1,
                    stream: 2,
                },
                "stream_destroy",
            ),
            (
                GpuRequest::StreamSynchronize {
                    context: 1,
                    stream: 2,
                },
                "stream_synchronize",
            ),
            (
                GpuRequest::StreamWaitEvent {
                    context: 1,
                    stream: 2,
                    event: 3,
                },
                "stream_wait_event",
            ),
            (
                GpuRequest::EventCreate {
                    context: 1,
                    flags: 0,
                },
                "event_create",
            ),
            (
                GpuRequest::EventDestroy {
                    context: 1,
                    event: 3,
                },
                "event_destroy",
            ),
            (
                GpuRequest::EventRecord {
                    context: 1,
                    event: 3,
                    stream: 2,
                },
                "event_record",
            ),
            (
                GpuRequest::EventQuery {
                    context: 1,
                    event: 3,
                },
                "event_query",
            ),
            (
                GpuRequest::EventSynchronize {
                    context: 1,
                    event: 3,
                },
                "event_synchronize",
            ),
            (
                GpuRequest::MemAlloc {
                    context: 1,
                    bytes: 8,
                },
                "mem_alloc",
            ),
            (GpuRequest::MemFree { context: 1, ptr: 2 }, "mem_free"),
            (
                GpuRequest::MemcpyHtoD {
                    context: 1,
                    dst: 2,
                    data: vec![1],
                },
                "memcpy_htod",
            ),
            (
                GpuRequest::MemcpyDtoH {
                    context: 1,
                    src: 2,
                    len: 3,
                },
                "memcpy_dtoh",
            ),
            (
                GpuRequest::MemcpyHtoDAsync {
                    context: 1,
                    dst: 2,
                    data: vec![1],
                    stream: 3,
                },
                "memcpy_htod_async",
            ),
            (
                GpuRequest::MemcpyDtoHAsync {
                    context: 1,
                    src: 2,
                    len: 3,
                    stream: 4,
                },
                "memcpy_dtoh_async",
            ),
            (
                GpuRequest::MemsetD8 {
                    context: 1,
                    dst: 2,
                    value: 0,
                    len: 3,
                },
                "memset_d8",
            ),
            (
                GpuRequest::ModuleLoad {
                    context: 1,
                    image: vec![2],
                },
                "module_load",
            ),
            (
                GpuRequest::ModuleUnload {
                    context: 1,
                    module: 2,
                },
                "module_unload",
            ),
            (
                GpuRequest::ModuleGetFunction {
                    context: 1,
                    module: 2,
                    name: "f".into(),
                },
                "module_get_function",
            ),
            (GpuRequest::NvmlDeviceGetCount, "nvml_device_count"),
            (
                GpuRequest::NvmlSystemGetDriverVersion,
                "nvml_driver_version",
            ),
            (
                GpuRequest::NvmlDeviceGetName { ordinal: 0 },
                "nvml_device_name",
            ),
            (
                GpuRequest::NvmlDeviceGetMemoryInfo { ordinal: 0 },
                "nvml_memory_info",
            ),
            (
                GpuRequest::NvmlDeviceGetUtilizationRates { ordinal: 0 },
                "nvml_utilization",
            ),
            (
                GpuRequest::NvmlDeviceGetCudaComputeCapability { ordinal: 0 },
                "nvml_compute_capability",
            ),
        ];
        for (request, expected) in cases {
            let response = handle_request(&mut backend, &request);
            assert!(
                matches!(response, GpuResponse::Err(ref e) if e.code == wire::CUDA_ERROR_UNKNOWN),
                "{request:?} must surface the backend error"
            );
            assert_eq!(backend.calls.borrow().last().copied(), Some(expected));
        }
    }

    #[test]
    fn a_launch_past_the_param_cap_is_refused_without_touching_the_backend() {
        let mut backend = FixedErrBackend {
            code: wire::CUDA_ERROR_UNKNOWN,
            calls: std::cell::RefCell::new(Vec::new()),
        };
        let params = vec![vec![0_u8; 4]; wire::MAX_KERNEL_PARAMS + 1];
        let response = handle_request(
            &mut backend,
            &GpuRequest::LaunchKernel {
                context: 1,
                function: 2,
                grid: [1, 1, 1],
                block: [1, 1, 1],
                shared_mem_bytes: 0,
                stream: None,
                params,
            },
        );
        let GpuResponse::Err(e) = response else {
            panic!("an over-cap launch must be refused: {response:?}");
        };
        assert_eq!(e.code, wire::CUDA_ERROR_INVALID_VALUE);
        assert!(
            backend.calls.borrow().is_empty(),
            "the backend must never see an over-cap launch"
        );
    }

    #[test]
    fn launch_config_validation_bounds_each_param_blob() {
        let mut config = LaunchConfig {
            params: vec![vec![0_u8; 8]],
            ..LaunchConfig::default()
        };
        assert!(config.validate().is_ok());
        config
            .params
            .push(vec![0_u8; (wire::MAX_PARAM_LEN + 1) as usize]);
        assert!(config.validate().is_err());
    }
}
