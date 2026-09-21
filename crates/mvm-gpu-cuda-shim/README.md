# mvm-gpu-cuda-shim

`mvm-gpu-cuda-shim` builds the guest's drop-in `libcuda.so.1` replacement.
It implements a focused CUDA Driver API surface without loading a guest driver.

## How it works

Exported C ABI functions validate their pointer and scalar arguments.
They translate supported operations into `mvm-contract` GPU requests.
`mvm-gpu-shim-core` sends those requests to the host endpoint over vsock.
CUDA result codes and output buffers are returned to the calling workload.

Contexts, allocations, modules, and functions are represented by opaque handles.
The handles are meaningful only to the endpoint that created them.
Module images and launch parameters are copied into bounded protocol messages.
The shim parses PTX metadata to determine kernel parameter sizes safely.

## Scope

The shim covers the driver calls needed by the supported mvm GPU workloads.
Unsupported operations return CUDA errors instead of falling through to a host path.
Panics are contained at the FFI boundary and converted to an unknown-error code.

## Building and testing

Build with `cargo build -p mvm-gpu-cuda-shim`.
Run `cargo test -p mvm-gpu-cuda-shim` for its ABI behavior tests.
Run `cargo clippy -p mvm-gpu-cuda-shim --all-targets -- -D warnings` before merging.
