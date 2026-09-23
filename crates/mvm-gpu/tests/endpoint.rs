//! End-to-end: the real `mvm-gpu-endpoint` process serving the same framed
//! RPC path the in-guest shims use, with the stub backend standing in for a
//! GPU and a unix socket standing in for vsock.

use std::process::{Child, Command};
use std::time::Duration;

use mvm_contract::protocol::gpu::{GpuRequest, GpuResponse};

/// Point the shim transport at this test's socket. Unsafe for the same
/// reason `std::env::set_var` is: process-global mutation. Both tests in
/// this binary set the value before any `call`, and each spawns its own
/// endpoint, so the sequencing is the entire contract.
fn set_transport(socket: &std::path::Path) {
    // SAFETY: the whole test binary is the caller; both tests set the
    // value before any RPC and use per-test sockets, so no other thread
    // reads or writes this variable concurrently.
    unsafe {
        std::env::set_var(
            mvm_gpu_shim_core::TRANSPORT_ENV,
            format!("unix:{}", socket.display()),
        );
    }
}

struct EndpointProcess {
    child: Child,
    socket: std::path::PathBuf,
}

impl EndpointProcess {
    fn start(socket: &std::path::Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_mvm-gpu-endpoint"))
            .arg("--listen")
            .arg(format!("unix:{}", socket.display()))
            .arg("--backend")
            .arg("stub")
            .spawn()
            .expect("spawn mvm-gpu-endpoint");
        // Wait until the socket actually accepts a connection: the file
        // appearing proves bind() ran, not that listen() has, and a dial in
        // that window is ECONNREFUSED.
        for _ in 0..500 {
            if socket.exists() && std::os::unix::net::UnixStream::connect(socket).is_ok() {
                return Self {
                    child,
                    socket: socket.to_path_buf(),
                };
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // Reap before failing so the panic never leaves the child behind.
        let _ = child.kill();
        let _ = child.wait();
        panic!("endpoint never bound {}", socket.display());
    }
}

impl Drop for EndpointProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// One test owns the whole flow: `MVM_GPU_RPC` is process-global state, so
/// the transport cannot be shared with another test's env var.
fn the_stub_endpoint_serves_the_full_device_memory_and_launch_flow() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("gpu.sock");
    let _endpoint = EndpointProcess::start(&socket);
    set_transport(&socket);

    // Device enumeration answers the NVML-style detection path.
    let response = mvm_gpu_shim_core::call(&GpuRequest::NvmlDeviceGetCount);
    assert_eq!(response, GpuResponse::NvmlDeviceCount { count: 1 });
    let response = mvm_gpu_shim_core::call(&GpuRequest::NvmlDeviceGetName { ordinal: 0 });
    let GpuResponse::DeviceName { name } = response else {
        panic!("device name: {response:?}");
    };
    assert!(name.contains("stub"), "the stub names itself: {name}");

    // Driver flow: context → alloc → HtoD → DtoH → memset → free.
    let GpuResponse::ContextCreated { context } =
        mvm_gpu_shim_core::call(&GpuRequest::ContextCreate { ordinal: 0 })
    else {
        panic!("context create");
    };
    let GpuResponse::DevicePointer { ptr } =
        mvm_gpu_shim_core::call(&GpuRequest::MemAlloc { context, bytes: 16 })
    else {
        panic!("mem alloc");
    };
    assert_eq!(
        mvm_gpu_shim_core::call(&GpuRequest::MemcpyHtoD {
            context,
            dst: ptr,
            data: vec![9, 8, 7, 6],
        }),
        GpuResponse::Ok
    );
    assert_eq!(
        mvm_gpu_shim_core::call(&GpuRequest::MemcpyDtoH {
            context,
            src: ptr,
            len: 4,
        }),
        GpuResponse::Data {
            bytes: vec![9, 8, 7, 6]
        }
    );
    assert_eq!(
        mvm_gpu_shim_core::call(&GpuRequest::MemsetD8 {
            context,
            dst: ptr,
            value: 0x5a,
            len: 2,
        }),
        GpuResponse::Ok
    );
    assert_eq!(
        mvm_gpu_shim_core::call(&GpuRequest::MemcpyDtoH {
            context,
            src: ptr,
            len: 4,
        }),
        GpuResponse::Data {
            bytes: vec![0x5a, 0x5a, 7, 6]
        }
    );
    let GpuResponse::StreamCreated { stream } =
        mvm_gpu_shim_core::call(&GpuRequest::StreamCreate { context, flags: 1 })
    else {
        panic!("stream create");
    };
    let GpuResponse::EventCreated { event } =
        mvm_gpu_shim_core::call(&GpuRequest::EventCreate { context, flags: 2 })
    else {
        panic!("event create");
    };
    assert_eq!(
        mvm_gpu_shim_core::call(&GpuRequest::MemcpyHtoDAsync {
            context,
            dst: ptr,
            data: vec![4, 3, 2, 1],
            stream,
        }),
        GpuResponse::AsyncQueued { completion: 1 }
    );
    assert_eq!(
        mvm_gpu_shim_core::call(&GpuRequest::EventRecord {
            context,
            event,
            stream,
        }),
        GpuResponse::AsyncQueued { completion: 2 }
    );
    assert_eq!(
        mvm_gpu_shim_core::call(&GpuRequest::EventQuery { context, event }),
        GpuResponse::EventStatus { complete: false }
    );
    assert_eq!(
        mvm_gpu_shim_core::call(&GpuRequest::EventSynchronize { context, event }),
        GpuResponse::Ok
    );
    assert_eq!(
        mvm_gpu_shim_core::call(&GpuRequest::EventQuery { context, event }),
        GpuResponse::EventStatus { complete: true }
    );
    assert_eq!(
        mvm_gpu_shim_core::call(&GpuRequest::MemcpyDtoHAsync {
            context,
            src: ptr,
            len: 4,
            stream,
        }),
        GpuResponse::DataQueued {
            bytes: vec![4, 3, 2, 1],
            completion: 3,
        }
    );
    assert_eq!(
        mvm_gpu_shim_core::call(&GpuRequest::StreamSynchronize { context, stream }),
        GpuResponse::Ok
    );
    assert_eq!(
        mvm_gpu_shim_core::call(&GpuRequest::EventDestroy { context, event }),
        GpuResponse::Ok
    );
    assert_eq!(
        mvm_gpu_shim_core::call(&GpuRequest::StreamDestroy { context, stream }),
        GpuResponse::Ok
    );
    assert_eq!(
        mvm_gpu_shim_core::call(&GpuRequest::MemFree { context, ptr }),
        GpuResponse::Ok
    );

    // Module → function → launch, with a forged handle refused.
    let GpuResponse::ModuleLoaded { module } = mvm_gpu_shim_core::call(&GpuRequest::ModuleLoad {
        context,
        image: b".version 8.3\n.entry k(.param .u64 p)\n{\n}\n".to_vec(),
    }) else {
        panic!("module load");
    };
    let GpuResponse::Function { handle } =
        mvm_gpu_shim_core::call(&GpuRequest::ModuleGetFunction {
            context,
            module,
            name: "k".into(),
        })
    else {
        panic!("module get function");
    };
    assert_eq!(
        mvm_gpu_shim_core::call(&GpuRequest::LaunchKernel {
            context,
            function: handle,
            grid: [1, 1, 1],
            block: [1, 1, 1],
            shared_mem_bytes: 0,
            stream: None,
            params: vec![vec![0; 8]],
        }),
        GpuResponse::Ok
    );
    let GpuResponse::Err(e) = mvm_gpu_shim_core::call(&GpuRequest::LaunchKernel {
        context,
        function: 0xdead_beef,
        grid: [1, 1, 1],
        block: [1, 1, 1],
        shared_mem_bytes: 0,
        stream: None,
        params: vec![],
    }) else {
        panic!("a forged function handle must be refused");
    };
    assert_eq!(e.code, mvm_gpu_shim_core::wire::CUDA_ERROR_INVALID_HANDLE);

    // Dropping the connection state and reconnecting recovers: a forked
    // guest's first call on a fresh transport works against the same
    // endpoint.
    assert_eq!(
        mvm_gpu_shim_core::call(&GpuRequest::DeviceGetCount),
        GpuResponse::DeviceCount { count: 1 }
    );
}

/// Runs inside the full-flow test: the transport is process-global, so the
/// cap check cannot own a second endpoint in parallel.
fn over_cap_launch_is_refused_before_it_reaches_the_backend() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("gpu-cap.sock");
    let _endpoint = EndpointProcess::start(&socket);
    set_transport(&socket);
    let GpuResponse::ContextCreated { context } =
        mvm_gpu_shim_core::call(&GpuRequest::ContextCreate { ordinal: 0 })
    else {
        panic!("context create");
    };
    let params = vec![vec![0_u8; 4]; mvm_gpu_shim_core::wire::MAX_KERNEL_PARAMS + 1];
    let response = mvm_gpu_shim_core::call(&GpuRequest::LaunchKernel {
        context,
        function: 1,
        grid: [1, 1, 1],
        block: [1, 1, 1],
        shared_mem_bytes: 0,
        stream: None,
        params,
    });
    let GpuResponse::Err(e) = response else {
        panic!("over-cap launch must be refused: {response:?}");
    };
    assert_eq!(e.code, mvm_gpu_shim_core::wire::CUDA_ERROR_INVALID_VALUE);
}

#[test]
fn the_cap_refusal_runs_after_the_full_flow() {
    // Sequenced, not parallel: `MVM_GPU_RPC` and the cached transport are
    // process-global, and each of these tests needs a different endpoint.
    the_stub_endpoint_serves_the_full_device_memory_and_launch_flow();
    over_cap_launch_is_refused_before_it_reaches_the_backend();
}
