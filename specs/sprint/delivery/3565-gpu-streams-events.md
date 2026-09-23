# #3565 — GPU streams, events, and asynchronous copies

## What shipped

- The GPU wire has typed requests and responses for stream creation,
  destruction, synchronization and event waits; event creation, destruction,
  record, query and synchronization; and asynchronous host/device copies.
  Every queued operation returns a completion position that increases within
  its stream, while event queries return readiness without translating a normal
  not-ready state into a transport error.
- `GpuBackend` carries the same surface. The native CUDA backend dynamically
  resolves the corresponding driver entry points, validates opaque stream and
  event handles against their owning context, and refuses forged, stale or
  cross-context handles before calling the driver.
- The deterministic stub keeps a submitted and completed position per stream.
  An event snapshots its stream's submitted position, reports not-ready until
  that fence completes, and advances only through a stream, event, context, or
  explicit stream-wait operation. Stream destruction completes already-recorded
  event fences and invalidates the stream handle. The null/default stream keeps
  the prior synchronous behavior.
- The driver shim exports stream/event calls, versioned async-copy aliases and
  stream-backed kernel launch. The runtime shim exports `cudaStream*`,
  `cudaEvent*`, and `cudaMemcpyAsync`, including the runtime-specific
  `cudaErrorNotReady` value.

## Ordering and buffer lifetime

The protocol copies guest buffers into bounded RPC frames. A native host-side
asynchronous copy therefore synchronizes the named CUDA stream before releasing
the frame-owned host buffer (and before returning DtoH bytes). This preserves
memory safety and CUDA stream order across the process boundary. The endpoint
still assigns completion positions, and event/stream operations remain the
portable ordering surface. The stub deliberately delays the completion
position of named-stream work until a wait so ordering tests are deterministic;
the legacy default stream completes immediately.

## Tests

Protocol tests cover serde/frame round trips for every new request family,
response handle/readiness/completion shapes, and decoding an older launch frame
without the optional stream field. Backend tests cover positive async copy and
event flows, cross-stream waiting, default-stream compatibility, forged and
stale handles, stream destruction, and event readiness transitions. The real
endpoint integration test exercises the same flow through framed Unix-socket
RPC. Focused contract and GPU tests, the complete workspace unit/integration
suite, workspace check, all-target Clippy, feature/Linux-gated checks, and all
74 repository structure gates pass. The workspace run reached a transient
`rustdoc` crate lookup failure only after every test binary passed; the isolated
`mvm-build` doctest retry passed cleanly.
