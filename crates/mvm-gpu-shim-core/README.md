# mvm-gpu-shim-core

`mvm-gpu-shim-core` contains the shared client runtime used by the guest GPU
shim libraries. It is not itself a replacement driver library.

## Responsibilities

The crate selects and opens the transport to the host GPU endpoint.
Linux guests use vsock by default, with the host at CID 2.
Tests can select Unix or TCP transport through `MVM_GPU_RPC`.
Requests and responses use the bounded GPU frames from `mvm-contract`.

One process-wide connection is established lazily and reused.
A failed call drops the connection and performs one bounded reconnect.
FFI entry points use `guard` so Rust panics become API error codes.
Bounded PTX, cubin ELF, and basic fatbin parsing recovers kernel parameter
sizes for launch requests. Binary offsets, lengths, parameter ordinals, and
input size are validated before they control allocation or pointer reads.
CString helpers perform bounded writes with explicit NUL termination.

## Security properties

The guest receives only opaque handles, never host addresses.
Response lengths are checked before allocating or reading frame bodies.
Invalid transport specifications fail closed with a GPU error.
Malformed, compressed, truncated, over-cap, or unsupported-endian CUDA module
metadata fails closed; the CUDA shim never guesses a launch layout.

## Testing

Run `cargo test -p mvm-gpu-shim-core` for transport and helper coverage.
Run `cargo clippy -p mvm-gpu-shim-core --all-targets -- -D warnings` for lint checks.
