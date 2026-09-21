# ADR-053: GPU compute inside microVMs by API remoting over vsock

## Status

Accepted, 2026-09-20. Amends ADR-029 (GPU posture) decision 1; the rest of
ADR-029 — paravirtual display (option A) posture, no virtio-gpu device, the
venus/virgl parser obligation, and compute *passthrough* remaining out of
scope — stands unchanged.

## Context

ADR-029 ruled "mvm ships no GPU support today" against two asks it
distinguished: paravirtual display (A) and compute passthrough (B). It did
not consider a third shape, which the recent GPU-over-vsock work by an
adjacent sandbox project demonstrates end to end: **API remoting**. The
guest carries no driver and no device nodes — three drop-in shim libraries
(`libcuda.so.1`, `libcudart.so`, `libnvidia-ml.so.1`) forward every CUDA
call over the guest's existing vsock to a host process that owns the real
GPU and runs the call there.

This shape answers every objection ADR-029 raised:

- **No VFIO, no dedicated device, no IOMMU surface** — the GPU stays on the
  host. Decision 4's "no" to compute passthrough is untouched.
- **No new guest-supplied parser on the host.** The host endpoint parses
  only length-capped JSON frames on a dedicated vsock port — the same trust
  shape as the broker and FlowMux channels, not a new venus/virgl-class
  command-stream parser. Decision 3's fuzzing obligation for option (A) does
  not transfer.
- **VM isolation preserved.** Unlike container device injection, the
  workload stays behind a real VM boundary; the GPU is shared host-side.
- **Fork-safe.** A passed-through GPU cannot be cloned, so passthrough
  never composes with mvm's fork; a forked child simply opens its own
  connection to the same host endpoint. This is the property that makes the
  plane worth having for agent workloads.
- **Every VMM tier serves it.** The GPU never enters the guest, so the
  channel is a vsock port plus a per-VM host process — Firecracker's
  multiplexed vsock, libkrun's and HVF's per-port UDS, QEMU's real
  AF_VSOCK all terminate it without a device model change.

The costs, stated honestly: every CUDA call is an RPC (a host-local memory
copy over vsock, not a network hop — fine for large-kernel/large-transfer
workloads, costly for many tiny latency-sensitive calls); the CUDA ABI
surface is large and v1 covers a deliberate subset; and it is NVIDIA-only
on the host.

## Decision

1. **GPU compute is supported by API remoting over vsock.** One flag
   (`mvmctl run --gpu`, `machine create/start --gpu`, `gpu = true` in a
   manifest) turns on the whole plane: guest shim libraries on the loader
   path, the dedicated GPU vsock channel (port 5256,
   `mvm_contract::protocol::gpu::GPU_RPC_PORT`), and a per-VM
   `mvm-gpu-endpoint` host process spawned by the workload runner and
   reaped with the VM.
2. **The endpoint owns the backend selection.** It loads the real
   `libcuda.so.1` / `libnvidia-ml.so.1` by `dlopen` when present
   (`--backend auto`, the default) and falls back to a deterministic stub
   device otherwise, so the entire transport is testable on a GPU-less host
   and a `--gpu` guest on such a host fails loudly at the endpoint, never
   silently inside the workload.
   **No GPU is required to run mvm, at any point on any tier:** nothing in
   the build links a GPU vendor library (the driver is `dlopen`'d at
   runtime, never a link-time or cargo dependency); launches that do not
   pass `--gpu` carry no GPU channel, no endpoint process, and no shim
   libraries; and a `--gpu` launch on a GPU-less host still boots and
   answers — the stub device reports itself as a stub by name, and
   `--backend native` refuses outright when no driver library exists. CI
   and every development host exercise the whole plane GPU-free today.
3. **Guest handles are opaque `u64`s minted by the endpoint.** Contexts,
   device pointers, modules, and functions leave the host only as numbers;
   a forged handle is a lookup miss, never a host address.
4. **Admission stays honest.** `gpu` is a declared capability: every
   microVM backend advertises it, the wasm/browser/mock tiers refuse it
   through the existing negotiation with a named alternative, and a launch
   that asks for it on a refusing backend fails before anything boots.
5. **Off by default, non-default in docs.** No launch carries the GPU
   channel unless it asked; `check-machine-doc-guards` wording rules still
   apply to beginner-facing docs.
6. **v1 scope is a named subset, not a silent gap:** Driver API
   (init/enumeration/contexts/memory/modules/launch/sync), Runtime API
   (device/malloc/memcpy/memset/sync), and NVML device queries. The host
   ABI is NVIDIA-only in v1; **MLX is the named roadmap direction for
   Apple Silicon hosts** — a second backend family behind the same
   endpoint/transport, not a fork of it. Named follow-ups:
   `cuGetProcAddress` resolution, CUDA graphs and warm device-memory
   handoff across fork, streams/events, cubin param metadata, multi-GPU,
   the MLX backend, and — separately, under ADR-029's option (A) rules —
   any paravirtual display question.

## Consequences

A `--gpu` guest can run unmodified CUDA programs that fit the v1 subset
with no driver, no device nodes, and no passthrough, on any microVM tier,
including forked children of a warm parent. The CUDA ABI subset is a
surface we must maintain as frameworks evolve; the wire protocol is
versioned (`mvm_contract::protocol::gpu`) to carry that growth.

The paravirtual-display question and compute passthrough are deliberately
untouched: this ADR amends the "no GPU support today" ruling only for the
remoted-compute shape.
