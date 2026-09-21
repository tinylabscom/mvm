# mvm-gpu-nvml-shim

`mvm-gpu-nvml-shim` builds the guest's drop-in `libnvidia-ml.so.1` replacement.
It lets GPU-aware tools discover a remoted device without guest driver access.

## How it works

The exported NVML ABI validates initialization state and caller buffers.
Supported queries become GPU protocol requests through `mvm-gpu-shim-core`.
The per-machine host endpoint obtains answers from the selected GPU backend.
Results are written back using the sizes and layouts defined by NVML.

Device handles encode an ordinal but remain opaque to the workload.
The shim reports device count, name, memory information, utilization,
compute capability, and the host driver version.
Fixed-size ABI structures have compile-time size, alignment, and offset checks.
Bounded CString writes always preserve NUL termination.

## Failure behavior

Calls made before initialization return the NVML uninitialized result.
Small or null output buffers return documented NVML errors.
FFI panics are contained and converted to an unknown-error result.

## Building and testing

Build with `cargo build -p mvm-gpu-nvml-shim`.
Run `cargo test -p mvm-gpu-nvml-shim` for its ABI behavior tests.
Run `cargo clippy -p mvm-gpu-nvml-shim --all-targets -- -D warnings` before merging.
