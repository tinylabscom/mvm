# mvm-gpu-cudart-shim

`mvm-gpu-cudart-shim` builds a drop-in `libcudart.so` for mvm guests.
It exposes a focused CUDA Runtime API while the real driver remains on the host.

## How it works

Runtime calls are lowered onto the same GPU protocol used by the driver shim.
The shared shim core carries each request to the per-machine host endpoint.
Device selection and sticky runtime errors remain local to the calling thread.
The first operation that needs a context creates one lazily for device zero.

Allocations return opaque endpoint handles presented as CUDA device pointers.
Copies move bounded byte buffers through the protocol in the requested direction.
Synchronization and memory operations retain CUDA-compatible result codes.
Invalid pointers, devices, or copy kinds are rejected at the FFI boundary.
The runtime exports stream and event lifecycle calls plus `cudaMemcpyAsync`;
event queries distinguish ready from `cudaErrorNotReady`, and a null stream
keeps synchronous default-stream behavior.

## Scope

The initial surface targets the runtime calls used by supported workloads.
Unsupported behavior returns a CUDA runtime error rather than using host devices.
Rust panics are caught and translated to the runtime's unknown-error result.

## Building and testing

Build with `cargo build -p mvm-gpu-cudart-shim`.
Run `cargo test -p mvm-gpu-cudart-shim` for its ABI behavior tests.
Run `cargo clippy -p mvm-gpu-cudart-shim --all-targets -- -D warnings` before merging.
