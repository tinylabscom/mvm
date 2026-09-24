# MLX backend for the GPU-over-vsock plane — design note

Backing: shipped-source
Validation: check-sprint-append

**Epic:** [#3560](https://github.com/tinylabscom/mvm/issues/3560) —
GPU support for microVMs. This note designs the named follow-up from
`specs/plans/2026-09-20-gpu-over-vsock.md`: the MLX backend for Apple
Silicon hosts, the second backend family behind the same endpoint and
transport (ADR-053). **Nothing here is scheduled work** — it is the
design to build from when the trigger conditions at the bottom fire, so
the decisions survive the gap.

## Why a family, not a backend impl

The shipped wire protocol is CUDA-shaped on purpose: the guest shims
present the CUDA C ABI because that is what existing workloads link
against. MLX semantics differ on every axis that shape touches, so an
`MlxBackend` cannot be a third variant behind `GpuBackend`:

| CUDA plane concept | MLX reality |
|---|---|
| `MemcpyHtoD` / `MemcpyDtoH` | Meaningless — unified memory; a copy is a metadata operation (new handle, same storage) or a no-op alias |
| `ModuleLoad` + `LaunchKernel` (PTX/cubin) | MLX executes lazily-evaluated op graphs compiled per-device; there is no guest-supplied binary to load, and no cubin param metadata to read |
| Contexts, streams, events | No user-visible context; `eval` is the synchronization point; streams exist but have different ordering semantics |
| NVML surface | No counterpart; device enumeration is the entire surface |
| Device pointers | `mlx::Array` handles over host-shared storage |

The consequence: real MLX value requires a **parallel op family** on the
same transport, plus a guest `libmlx.so` shim for the mlx C API — not a
CUDA-ABI emulation that could only ever answer enumeration and memset.

## What stays the same

- **Transport and framing.** AF_VSOCK port 5256, 4-byte length-prefixed
  JSON frames, `deny_unknown_fields` round-trip discipline. The
  per-request `op=` log line and the BDD witness pattern (`s35_gpu_e2e`)
  carry over unchanged.
- **Endpoint lifecycle.** One `mvm-gpu-endpoint` per VM, spawned when the
  launch arms the plane, reaped with the VM, verified through the
  host-helper contract probe before spawn. On macOS HVF hosts the
  endpoint already runs on the host, so the MLX backend links mlx
  host-side — no cross-compilation problem.
- **Capability admission.** `gpu = true` stays the single flag; the
  backend family is host-side selection, never guest-visible.
- **The no-GPU contract.** ADR-053 pins that a GPU is never required
  anywhere. The MLX family carries the same property: CI and GPU-less
  hosts answer through a deterministic stub, and `--backend mlx` on a
  host without mlx refuses with a named error rather than silently
  falling back.

## The MLX op family (sketch)

A sibling enum, not an extension of `GpuRequest` — the frames are
distinguished by a family discriminator in the handshake, so the CUDA
family keeps its wire-frozen shape:

- `DeviceCount` / `DeviceInfo` — enumeration (mirrors the stub's
  deterministic identity; the name carries "mlx" so logs and witnesses
  read correctly).
- `ArrayAlloc { shape, dtype }` → handle — the host mints the opaque
  handle; storage lives in a per-endpoint table over mlx unified memory.
- `ArrayFree` / `ArrayShape` / `ArrayDtype`.
- `Eval { program }` — the op-graph execution request. The guest frames
  a small expression tree (unary/binary ops, matmul, a fixed set of
  fused ops) rather than shipping kernels; the host compiles and evals.
  `Eval` doubles as the synchronization point.
- `Copy { src, dst }` — under unified memory this is a handle alias in
  the table plus an optional lazy materialization; the wire keeps the op
  so the guest ABI looks normal, but the host may answer it without
  touching bytes.
- `RandomSeeded { ... }` — deterministic-stub parity: the stub family
  answers every op with fixed seeds and fixed values so the entire
  plane runs and is tested GPU-free.

What is deliberately absent: any guest-supplied code, any PTX-shaped
anything, NVML-shaped anything, and stream/event ordering semantics.
The v1 family is tensor-ops-and-eval, sized for inference workloads
(llama-class models through the mlx C API), not for hand-written kernel
launches.

## Guest ABI

A `libmlx.so`-named cdylib shim exporting the stable subset of the mlx C
API an inference workload actually calls: device queries, array
create/free, the ops the family implements, and `eval`. The shim is a
second cdylib family beside the CUDA shims (same `shim-core` transport
client); the runtime overlay composes it the same way, and the same
loader-path activation rules apply.

The mlx C API is pre-1.0 and moving. The guest ABI pins only the subset
above, and the host-side backend builds against the pinned mlx release —
version skew between host mlx and the guest ABI is contained because the
guest never speaks to mlx directly.

## Fork-safety — better than CUDA, worth stating

The decisive property ADR-053 claims for remoting over passthrough is
fork-safety, and MLX improves it: array handles are host-side table
entries, so a forked guest child opens its own connection to the same
endpoint and the handles it inherited resolve identically. There is no
graph-reconnect problem because there are no device-side graphs to
reconnect — `Eval` is stateless per request. This should be a named
witness in the family's BDD scenarios, since it is the property a
passthrough Apple GPU could never give.

## Security lens

- **Same trust shape.** The only guest-controlled bytes the host parses
  are framed JSON on the dedicated port — identical to the CUDA family
  and the broker; no new parse-surface class.
- **Admission.** `Eval` is host CPU/GPU work under a tenant's grants;
  the CPU grant and wall-clock grant already meter it, but memory
  pressure deserves an explicit note: unified-memory arrays consume the
  host's shared pool, so the endpoint needs a per-VM array-bytes budget
  the CUDA family does not (device memory there is bounded by the
  physical GPU).
- **Determinism.** The stub family must be byte-deterministic
  (fixed seeds, fixed values) so witnesses never flake.

## Test plan sketch

- Wire round-trips + unknown-field refusal for the new family (mirrors
  the `mvm-contract` GPU tests).
- Stub backend invariants: array table bookkeeping, eval determinism,
  alias semantics for `Copy`.
- Endpoint integration over a unix socket (`MVM_GPU_RPC=unix:`),
  mirroring `crates/mvm-gpu/tests/endpoint.rs`.
- BDD: an `s35`-adjacent suite with an mlx probe — positive (eval
  answers with deterministic values, host log shows the ops) and the
  fork witness (parent allocates, child evals after fork).
- No GPU anywhere; the native mlx backend additionally gets a smoke lane
  on an Apple Silicon host, but CI never requires one.

## Explicit non-goals (v1)

- CUDA-kernel execution on MLX (impossible, not merely out of scope).
- Training-loop ergonomics (optimizer state lives at the framework
  layer; the wire carries arrays and evals).
- Multi-device peer semantics beyond enumeration and ordinal pinning
  (the existing `--gpu-device` pin carries over).
- Paravirtual display (unchanged from the parent plan).

## Trigger conditions

Build this when **two of three** hold:

1. **Native validation done** — #3561 has exercised the CUDA `native`
   backend against real hardware, confirming the endpoint lifecycle
   assumptions a second family inherits.
2. **A real workload asks** — someone runs an mlx inference workload in
   a guest and the stub is the blocker, not the demo.
3. **The mlx C API settles** — the subset above is stable across two mlx
   releases, so the guest ABI pin stops being churn.

Until then the plane as shipped is the deliverable: on Linux hosts the
CUDA family runs native or stub; on macOS hosts it runs stub today and
this note is the map from stub to real.
