# mvm-gpu

`mvm-gpu` is the host-side endpoint for GPU-enabled mvm guests.
The guest does not receive host GPU device nodes or driver libraries.
Instead, its CUDA and NVML shims send framed requests to this endpoint.

## Architecture

Each GPU-enabled machine gets one endpoint process.
The endpoint accepts the GPU wire protocol from `mvm-contract`.
It validates requests and dispatches them through the `GpuBackend` trait.
Opaque integer handles keep host pointers out of the guest protocol.

`NativeCudaBackend` loads the host CUDA and NVML libraries dynamically.
`StubBackend` provides deterministic behavior without GPU hardware.
The stub keeps transport and lifecycle tests portable and repeatable.
It tracks a submitted and completed sequence position for every stream.
Events snapshot one position, remain not-ready until that position completes,
and make stream/event waits deterministic. The legacy default stream remains
synchronously complete.

## Transport

Production guests reach the endpoint over the machine's vsock channel.
Tests use a Unix socket while exercising the same framed protocol.
Messages are length-limited before allocation or dispatch.

## Testing

Run `cargo test -p mvm-gpu` for dispatch, backend, and endpoint tests.
Run `cargo clippy -p mvm-gpu --all-targets -- -D warnings` for lint checks.
Native-driver tests require compatible host libraries and hardware.
