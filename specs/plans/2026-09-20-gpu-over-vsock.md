# GPU compute inside microVMs by API remoting over vsock

Backing: shipped-source
Validation: check-sprint-append

**Epic:** [#3560](https://github.com/tinylabscom/mvm/issues/3560) — GPU
support for microVMs. Follow-ups: [#3561](https://github.com/tinylabscom/mvm/issues/3561)
hardware validation, [#3562](https://github.com/tinylabscom/mvm/issues/3562)
CUDA graphs + fork-reconnect, [#3563](https://github.com/tinylabscom/mvm/issues/3563)
`cuGetProcAddress`, [#3564](https://github.com/tinylabscom/mvm/issues/3564)
cubin param metadata, [#3565](https://github.com/tinylabscom/mvm/issues/3565)
streams/events, [#3566](https://github.com/tinylabscom/mvm/issues/3566)
multi-GPU, [#3567](https://github.com/tinylabscom/mvm/issues/3567) BDD
coverage. Overlay composition: tinylabscom/mvm-images#10.

## Outcome

A workload in an mvm microVM can run CUDA code with **no GPU driver, no
device nodes, and no passthrough device in the guest**. The guest carries
three drop-in shim libraries — `libcuda.so.1`, `libcudart.so`,
`libnvidia-ml.so.1` — that implement the CUDA C ABI by forwarding every
call over the guest's existing vsock egress channel to a host-side
endpoint that owns the real GPU. One flag — `mvmctl machine run --gpu` /
`gpu = true` in the machine spec — turns the whole plane on. The optional
`--gpu-device N` / `gpu_device = N` selector pins a VM to host ordinal `N`
and presents that device as guest ordinal zero.

The approach is **API remoting**, in the lineage of rCUDA and the recent
"GPU over vsock" work by an adjacent sandbox project: the GPU and its
driver never enter the guest. Against the four ways to give an isolated
workload a GPU, remoting is the only one that composes with mvm's
existing guarantees:

| Approach | Guest driver | Shares GPU | VM boundary | Fork-safe |
|---|---|---|---|---|
| PCIe passthrough (VFIO) | full stack | no | yes | no |
| Mediated vGPU / MIG | vGPU driver | yes | yes | no |
| Container device injection | host mounts | yes | **no** | n/a |
| **API remoting over vsock** | **none — shims only** | **yes, via host daemon** | **yes** | **yes** |

Fork-safety is the decisive property for mvm: a passed-through GPU
belongs to one VM and cannot be cloned, while a forked child simply
opens its own RPC connection to the same host endpoint. This sidesteps
every objection ADR-029 raised: no VFIO, no venus/virgl guest-supplied
parser surface on the host (the only guest-controlled bytes the host
parses are the already-framed RPC messages on a dedicated vsock port,
the same trust shape as the broker and FlowMux channels), and the
sealed-prod claim set is unchanged because the GPU plane is off unless
the launch asks for it.

## How it works

```
guest workload                 host
--------------                 ----
torch / CUDA binary
   └─ dlopen libcuda.so.1  →   mvm-gpu-cuda-shim (cdylib)
        └─ AF_VSOCK :5256  →   (VMM per-port relay)
                                └─ mvm-gpu-endpoint (per-VM process)
                                     └─ GpuBackend
                                          ├─ NativeCudaBackend: dlopen libcuda.so.1
                                          └─ StubBackend: deterministic fake device
```

- **Transport selection** (guest side, `MVM_GPU_RPC`): unset → vsock,
  host CID 2, port 5256; `tcp:HOST:PORT`; `unix:/path`. The same env
  override makes the whole stack testable on a machine with no GPU and
  no VM.
- **Backend selection** (host side, `--backend auto|native|stub`):
  `auto` probes for `libcuda.so.1` and falls back to the stub, so the
  transport is exercisable end to end on any host.
- **No GPU is ever required.** Nothing links a vendor library at build
  time; launches without `--gpu` are bit-for-bit the launches mvm always
  had; a `--gpu` launch on a GPU-less host boots and answers through the
  stub (or refuses with `--backend native`). The entire plane runs and is
  tested GPU-free — CI included.
- **NVML shim** answers the device-detection queries frameworks like
  vLLM issue, backed by the remoted driver — without it a remoted GPU
  is invisible to the frameworks that want it.
- Device pointers, contexts, modules, and functions are opaque `u64`
  handles minted by the host endpoint; the guest never sees a host
  address.

## v1 scope (this plan)

The CUDA ABI surface is large and moving; v1 covers a deliberately
small subset, enough for unmodified Driver-API and Runtime-API programs
that allocate, copy, load a module, and launch kernels:

- Driver API: `cuInit`, `cuDriverGetVersion`, `cuDeviceGetCount`,
  `cuDeviceGet`, `cuDeviceGetName`, `cuDeviceTotalMem`,
  `cuCtxCreate/Destroy/SetCurrent/GetCurrent`, `cuMemAlloc`, `cuMemFree`,
  `cuMemcpyHtoD`, `cuMemcpyDtoH`, `cuMemsetD8`, `cuModuleLoadData`,
  `cuModuleUnload`, `cuModuleGetFunction`, `cuLaunchKernel`,
  `cuCtxSynchronize`, `cuGetErrorString`.
- Runtime API: `cudaGetDeviceCount`, `cudaSetDevice`, `cudaGetDevice`,
  `cudaMalloc`, `cudaFree`, `cudaMemcpy` (H2D/D2H/D2D/H2H), `cudaMemset`,
  `cudaDeviceSynchronize`, `cudaGetLastError`, `cudaPeekAtLastError`,
  `cudaGetErrorString`, `cudaSetDeviceFlags`, `cudaRuntimeGetVersion`,
  `cudaDriverGetVersion`.
- NVML: `nvmlInit_v2`, `nvmlShutdown`, `nvmlErrorString`,
  `nvmlSystemGetDriverVersion`, `nvmlDeviceGetCount_v2`,
  `nvmlDeviceGetHandleByIndex_v2`, `nvmlDeviceGetName`,
  `nvmlDeviceGetMemoryInfo`, `nvmlDeviceGetUtilizationRates`,
  `nvmlDeviceGetCudaComputeCapability`.

`cuGetProcAddress`-based resolution (CUDA 12 cudart's full symbol
path) moved from this list into the work items below (W13). Still out of
v1 (named follow-ups, not silent gaps): CUDA graphs and contexted
fork-reconnect (warm device memory handoff), peer-device access, the MLX
backend for Apple Silicon hosts (second backend family behind the same
endpoint and transport), and the paravirtual-display question (ADR-029's
option A) which this plan does not touch.

## Work items

- [x] W1 — Wire protocol: `mvm-contract::protocol::gpu` — `GPU_RPC_PORT`
      = 5256, versioned `GpuRequest`/`GpuResponse` enums, `GpuError`
      carrying numeric CUDA/NVML codes. Round-trip + cap tests.
- [x] W2 — Host endpoint: new `crates/mvm-gpu` — `GpuBackend` trait,
      `StubBackend` (deterministic fake device, host-memory buffers),
      `NativeCudaBackend` (runtime `dlopen("libcuda.so.1")`; Linux),
      framed JSON server, `mvm-gpu-endpoint` bin with
      `--listen unix|tcp|vsock` and `--backend auto|native|stub`.
- [x] W3 — Guest shims: `crates/mvm-gpu-shim-core` (transport dial,
      framed RPC client, panic containment) + three cdylibs
      (`mvm-gpu-cuda-shim`, `mvm-gpu-cudart-shim`, `mvm-gpu-nvml-shim`)
      exporting the v1 ABI with correct sonames.
- [x] W4 — Capability admission: `gpu` on `VmCapabilities` /
      `RequiredCapabilities`, negotiation alternative, per-backend
      advertisement (VMM tiers yes; wasm/weblinux/mock no).
- [x] W5 — Config surface: `VmStartConfig.gpu`, CLI `--gpu`
      (`RunArgs`, shared with `machine run`), persisted
      `MachineSpec.gpu` (+ `machine_config_matches`/`_diff`), mvm.toml
      manifest field.
- [x] W6 — Channel declaration: `GuestService::Gpu` (port from the
      contract constant), `WorkloadSockets.gpu`,
      `workload_vsock_ports`, `standing_sockets` resolution.
- [x] W7 — Backend wiring: HVF supervisor config field + vsock relay
      handler + handoff mask bit; libkrun port allowlist; Firecracker
      guest-dial bridge.
- [x] W8 — Host endpoint spawn in the workload runner when
      `config.gpu`, reaped with the VM; per-VM socket path helper in
      `mvm-core::config`.
- [x] W9 — Nix: shim cdylib package recipes (`nix/packages/mvm-gpu-shims.nix`,
      glibc + musl-static variants exposed from the flake). Composing them
      into the runtime overlay image is mvm-images work, tracked at
      tinylabscom/mvm-images#10 — the image train owns composition; mvm
      owns the recipes.
- [x] W10 — Docs: ADR-053 (compute-over-vsock, amends ADR-029 decision
      1's "no GPU support today"), plan checkboxes, SPRINT.md,
      REFACTOR-STATUS.md, doc-guard-compliant wording.
- [x] W13 — `cuGetProcAddress` in the cuda shim (#3563, merged as #3652):
      resolver answers all implemented v1 symbols under their base names
      and the versioned aliases the real driver serves; refuses the rest
      with `CUDA_ERROR_NOT_FOUND`. Unit + dynamic-export tests.
- [x] W14 — BDD end-to-end witness (#3567, merged as #3653): live-lane
      scenarios boot a real `--gpu` VM on a GPU-less runner (stub
      backend), run a guest probe that dlopens the shims and issues a
      CUDA driver + NVML call chain, and assert guest answers plus
      per-request `op=` lines in the host `gpu-endpoint.log`; the
      negative scenario boots without `--gpu` and asserts the guest dial
      is refused and no endpoint exists. Flushed out: the endpoint's
      missing host-helper contract-probe answer and the NVML shim's
      null handle for device ordinal 0.
- [x] W11 — Streams and events (#3565): typed stream/event/async-copy wire
      operations; endpoint completion positions; deterministic stub ordering;
      native CUDA bindings; driver/runtime shim exports; compatibility,
      refusal, ordering, endpoint and workspace validation.
- [x] W12 — Multi-GPU ordinals (#3566): real backend enumeration; distinct
      ordinal-to-host-device mapping; runtime per-device contexts; optional
      manifest/CLI pinning that exposes only guest ordinal zero; invalid host
      and guest ordinal refusal; deterministic two-device endpoint coverage.

## Test plan

- Protocol round-trips and unknown-field refusal (`mvm-contract`).
- Stub backend behavior: alloc/free/copy/memset invariants, launch
  bookkeeping, deterministic device identity.
- Daemon ↔ shim integration over a unix socket (`MVM_GPU_RPC=unix:`):
  a test client drives the exported C ABI through the shim into the
  daemon and back.
- Negotiation: VMM tiers serve `gpu`, wasm/weblinux/mock refuse with a
  named alternative.
- spec_map/standing-sockets: the Gpu channel appears only when the
  launch requests it, as `GuestDials`, on the contract port.
- `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`,
  `just check-gated` (shared-type shape changed).
