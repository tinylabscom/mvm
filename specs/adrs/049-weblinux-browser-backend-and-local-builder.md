# ADR-049 — `WebLinux` is a first-class browser-hosted Linux backend and local builder

Backing: preview
Validation: none

**Status: Accepted**  
**Date: 2026-08-15**  
**Supersedes:** ADR-024 only where it rejects emulating Linux in WebAssembly and
where it limits browser execution to a throwaway/direct-WASI demo. ADR-024
continues to govern the direct-WASI tier and its claim-free security posture.  
**Amends:** ADR-006 only where it forbids an `mvm` deployment verb. `mvm` may
contain one open-source `mvmd` deployment client, but it still does not become a
tenant scheduler, provider registry, or fleet control plane.  
**Complements:** ADR-007 (`VmBackend`), ADR-014 (signed/audited execution
plans), ADR-024 (WASI/browser claim boundary), ADR-037 (`mvmd` is the only
production launch authority), and ADR-042 (one flow-aware workload networking
path).  
**Implementation plan:** `specs/plans/338-weblinux-browser-backend-builder-workbench-and-mvmd-deploy.md`

## Context

`mvm` already treats the execution substrate as a backend concern. Firecracker,
HVF, libkrun, QEMU, Apple Container, and direct WASI can all satisfy different
parts of the same workload lifecycle while reporting different capabilities and
security profiles.

The existing `WasmBackend` is not a Linux backend. It instantiates a
user-supplied WASI module and intentionally has no guest kernel, block devices,
virtio devices, vsock, verified boot, or normal Linux process environment. The
existing browser demo follows that same direct-WASI model.

A different browser target is now required:

- boot a real Nix-built Linux kernel under a browser-hosted system emulator;
- materialize and run broad classes of Linux/OCI workloads without recompiling
  them to WASI;
- expose a local development environment, terminal, files, tasks, language
  services, tests, and application previews;
- launch a clean browser-local builder VM that produces the same portable
  `mvm` artifacts as other builder backends;
- run the resulting artifact locally under the browser backend;
- optionally submit that already-built artifact to proprietary `mvmd` through
  an open-source `mvm` deployment client.

QEMU-Wasm, container2wasm, and `vscode-container-wasm` establish useful prior
art for the machine substrate and browser IDE shape. They do not define the
`mvm` architecture, security claims, artifact contract, builder contract, or
deployment boundary.

The product boundary is also explicit:

- **`mvm` is open-source and complete for local development, local builds, local
  runs, artifact creation, inspection, export, and deployment-client UX.**
- **`mvmd` is the proprietary managed deployment destination.** It owns tenant
  identity, production admission, placement, reconciliation, public ingress,
  managed secrets, scaling, billing, fleet observability, and durable
  operation.

The browser is therefore one universal `mvm` workbench and one local host
surface. It is not merely a thin client for `mvmd`.

## Decision

### 1. Add a distinct `WebLinux` backend identity

`WebLinux` is a first-class backend kind, separate from direct WASI:

```rust
pub enum BackendKind {
    // existing variants ...
    Wasi,
    WebLinux,
}
```

The existing selector `wasm` may remain a compatibility alias for direct WASI,
but code and documentation should converge on the precise names:

```text
WasiBackend             host Wasmtime + direct WASI workload
BrowserWasiBackend      browser runtime + direct WASI workload
WebLinuxBackend         QEMU-Wasm + real Linux guest
```

`WebLinux` participates in typed capability negotiation and backend
conformance. It is never identified by string matching outside the catalog or
generated descriptor surfaces.

A browser-only constructor need not be forced into a native `AnyBackend`
implementation that cannot execute it. Pure backend metadata and wire contracts
must be shareable; host-specific and browser-specific constructors remain in
their respective adapters.

### 2. `WebLinuxBackend` is a complete local development and run backend

The open-source browser backend supports the same user-level lifecycle classes
as the native development backends:

- create or resume a development guest;
- attach an interactive terminal;
- edit a workspace shared with the guest;
- execute commands and tasks;
- run tests and language services;
- expose local application previews;
- stop, restart, inspect, and collect logs;
- boot a clean artifact for local validation.

It is not restricted to a curated demo shell.

The first supported platform is desktop Chromium with a `linux/amd64` guest.
Additional browsers, mobile devices, and guest architectures are compatibility
work, not assumptions baked into the core contract.

### 3. Add `WebLinuxBuilderVm` as a real builder backend

The browser also gets a builder implementation:

```rust
pub enum BuilderBackendChoice {
    // existing variants ...
    WebLinux,
}
```

`WebLinuxBuilderVm` consumes the same logical `BuilderJob` contract as the
other builder implementations and emits the same logical artifact contract. Its
storage handles are browser-native internally, but portable build inputs and
outputs are content-addressed and serializable.

A browser-local build is not a toy build. It can produce a valid signed,
content-addressed artifact suitable for:

- local `WebLinuxBackend` execution;
- export and inspection;
- native `mvm` execution on a compatible backend;
- upload and deployment through `mvmd`.

A deployment policy may require a trusted publisher, a reproducibility check,
or a trusted rebuild, but build location alone does not make an artifact
invalid.

### 4. Keep development, build, and runtime guests distinct

The mutable development guest is not the deployable product.

The browser workbench uses three logical modes:

```text
development guest
    mutable workspace, toolchains, language servers, debugger, caches

builder guest
    immutable source checkpoint, controlled inputs, persistent build cache,
    clean output, build receipt

runtime guest
    built workload artifact, runtime-only configuration, local validation
```

The first implementation may run these modes sequentially because multiple
QEMU-Wasm instances can exceed practical browser memory. The contract does not
require them to be concurrent.

### 5. Separate workload identity from runtime-pack identity

Portable execution is anchored in the workload, not in a QEMU process or VM
memory image.

The artifact model evolves toward three independently meaningful objects:

```text
WorkloadArtifact
    application filesystem or OCI-derived root
    entrypoint, arguments, user, environment declaration, working directory
    source/build provenance, SBOM, expected ports, application digest

RuntimePack
    kernel, initramfs, runtime overlay, guest agent
    machine/device ABI, transport profile, backend compatibility
    runtime-pack digest and publisher signature

ExecutionPlan
    binds workload + runtime selection + policy + grants + secret references
```

A browser-local run can bind a workload to a `web-linux-x86_64` runtime pack.
An `mvmd` production deployment can bind the same workload digest to a
Firecracker, HVF, libkrun, or QEMU runtime pack selected by production
admission.

Live migration from browser QEMU-Wasm to a hardware backend is not part of this
decision. Seamlessness means unchanged workload identity and lineage, not
identical hypervisor state.

### 6. Directly boot the workload root for the first OCI tier

For the first supported OCI path, `mvm` materializes the OCI image into the
same bootable Linux-root shape used by the existing workload pipeline and boots
it directly under the `mvm` kernel/initramfs.

The browser guest does not run Docker, containerd, or a nested Docker daemon.
Running `runc` inside the guest is not required for the initial architecture:
the microVM is already the workload isolation unit.

OCI compatibility is defined by an explicit matrix. Unsupported runtime
features such as privileged host devices, Docker socket mounts, host network
mode, host kernel modules, nested KVM, GPUs, or arbitrary host bind mounts fail
with typed errors rather than being ignored.

### 7. Extract a portable asynchronous backend protocol

The existing native traits are synchronous, `Send + Sync`, and path-oriented.
Browser execution uses Workers, promises, OPFS objects, message ports, and
content references.

The shared layer therefore owns portable request/response DTOs and state
machines, while adapters own execution details:

```text
portable backend/build protocol in mvm-contract
    |
    +-- native adapter -> VmBackend / BuilderVm
    +-- browser Worker service -> WebLinuxBackend / WebLinuxBuilderVm
    +-- MvmClient gateway adapter -> mvmd deployment/status client
```

Portable contracts carry artifact identities and digests, not host
`PathBuf`s. Native paths, OPFS handles, HTTP range sources, and node-local CAS
paths are resolver details below the portable boundary.

This is not a second backend model. It is the transport-neutral form of the
same lifecycle and builder contracts.

### 8. The browser workbench is native to open-source `mvm`

The repository may ship a Code-OSS/VS Code Web-compatible workbench, subject to
license and trademark review. The initial implementation keeps the editor UI
outside the VM and connects it to the guest through `mvm` protocols.

The staged workbench is:

1. OPFS-backed source workspace;
2. guest-backed integrated terminal;
3. tasks, logs, tests, problems, and local preview;
4. selected guest language servers and debugger adapters;
5. an optional guest-side Node workspace-extension host after memory and
   performance measurements support it.

The Microsoft proprietary extension marketplace is not assumed. An open
extension source and explicit extension trust/placement model are required.

### 9. Browser storage is durable local state, not an invisible in-memory disk

OPFS is used for:

- content-addressed immutable artifacts;
- the development workspace;
- persistent Nix/build caches;
- per-workspace writable disks;
- clean builder outputs;
- disk-only checkpoints.

Boot-critical immutable content is verified on read. Writable disks use
single-writer leases, flush semantics, bounded caches, quota preflight, and
unclean-shutdown recovery.

The user must be able to export source and artifacts. OPFS is useful local
persistence but not the only copy of valuable source code.

### 10. Browser networking follows ADR-042's one policy path

`WebLinux` does not reintroduce a raw-packet policy bypass.

The guest reaches the same logical `NetworkFlow` service through a
browser-capable transport, expected to be virtio-serial mapped to typed
`MessagePort`s rather than AF_VSOCK. The canonical policy, destination binding,
secret-substitution decision, limits, and audit shape remain shared.

Browser-hosted transports may have different capabilities:

```text
Off
    no network grant and no external connection path

Fetch/typed HTTP
    browser-originated HTTP(S), subject to browser constraints

Relay
    opaque TCP/UDP or preview traffic through the open relay protocol
    a self-hosted mvm relay or managed mvmd implementation may serve it
```

A weaker browser transport reports the gap. It never claims raw-socket or
destination evidence that it cannot provide.

Production secrets do not enter browser JavaScript, OPFS, or the local guest.
Local development secrets are an explicit weaker mode and are never packaged
into the workload artifact.

### 11. Browser lifecycle is document/workbench-bound

A browser cannot honestly promise that a VM survives tab closure, browser
discard, or device shutdown.

The capability model distinguishes lifecycle scope. A WebLinux VM may be
detached from an individual UI command while remaining bound to the browser
workbench/session; it is not a durable detached deployment.

Disk checkpoints and recoverable restart are supported independently from
durable process lifetime.

### 12. `mvmd` is a deployment target, not a backend

No `BackendKind::Mvmd` is added.

`mvm` may expose an open-source deployment client and user experience:

```text
build locally
run locally
Deploy on mvmd
```

The client submits:

- an immutable workload artifact or missing CAS objects;
- a signed deployment intent;
- policy and grants;
- references to managed production secrets;
- desired ingress/scale/region intent where the public contract permits it.

The client does not choose a production host or hypervisor. `mvmd` owns
production admission, placement, backend selection, reconciliation, and launch.

This amends ADR-006 narrowly: `mvmctl deploy` is allowed as a client operation,
but `mvm` still has no provider registry, fleet scheduler, tenant reconciler, or
cloud control-plane implementation.

ADR-037 remains unchanged: only an authenticated `mvmd`-initiated launch is a
production launch. Browser and other local executions are development-tier,
even when they run a production-shaped artifact.

### 13. Security and claim posture remain explicit

`WebLinux` is a claim-free browser-sandbox backend:

```text
guest environment      Linux
CPU execution          software emulation
outer isolation        browser sandbox/process isolation
hardware VM boundary   none
remote attestation     none
production authority   none
```

It may verify signed plans, runtime packs, artifact digests, dm-verity data,
and local audit chains. Those facts do not become hardware attestation.

The trusted browser origin, QEMU-Wasm engine, JavaScript/Wasm glue, OPFS block
service, editor extensions, and browser-network bridge are in the local trusted
computing base.

The workbench, execution runtime, and untrusted application preview use
separate origins and capabilities. Guest output and preview content are hostile
input.

### 14. Native performance goals remain unchanged

The native backend cold/warm-start goals are not weakened.

`WebLinux` has a separate measured performance class because it performs
software emulation inside a browser. No browser latency target is declared
until the feasibility slice records engine compile time, kernel-entry time,
PID-1 time, workload-ready time, peak memory, disk throughput, and cached
restart behavior.

A browser implementation may not introduce dependencies or regressions into
default native builds when the WebLinux feature is not selected.

## Consequences

### Positive

- `mvm` gains a complete browser-local development, build, and run workflow
  without requiring an `mvmd` account.
- The same open project model can target WebLinux, HVF, libkrun, Firecracker,
  QEMU, and direct WASI.
- Browser-built artifacts can move into the existing native and managed
  deployment lifecycle without deploying a mutable development machine.
- `mvmd` has a clean paid value proposition: managed production deployment and
  operation rather than gated local capability.
- Content-addressed portable contracts improve remote execution, cache
  deduplication, and cluster artifact movement beyond the browser use case.

### Costs

- `mvm` takes on a pinned QEMU/Emscripten toolchain, browser runtime, storage
  service, workbench, and compatibility matrix.
- QEMU-Wasm and browser APIs are less mature and more resource-intensive than
  native hardware virtualization.
- The portable contract extraction touches current path-oriented VM and builder
  boundaries.
- A complete IDE experience requires careful extension-host placement,
  filesystem semantics, preview isolation, and memory admission.
- The open deployment client creates a long-lived compatibility contract with
  proprietary `mvmd`.

## Alternatives considered

### Keep the browser direct-WASI only

Rejected as the only browser path. Direct WASI remains valuable for small,
portable workloads, but it cannot run ordinary Linux toolchains and OCI
userspaces with the expected development experience.

### Make the browser only a thin client for remote `mvmd`

Rejected. It would reproduce a remote Codespaces architecture and make the
open-source workbench incomplete without the proprietary service.

### Run the full editor server inside the guest first

Deferred. It maximizes extension compatibility but adds a heavy server,
Node extension host, HTTP/WebSocket ingress bridge, and substantial memory
before the basic backend and builder are stable.

### Treat `mvmd` as another backend

Rejected. A backend executes one machine; `mvmd` is the authenticated
production control plane that admits, places, reconciles, and operates
deployments.

### Deploy the mutable development VM

Rejected. Development state contains toolchains, credentials, editor state,
and drift. Deployment consumes a clean artifact from an immutable source
checkpoint.

### Run Docker or nested container infrastructure in the browser guest

Rejected for the first architecture. It adds another daemon and isolation layer
where the microVM already supplies the workload boundary.

### Live-migrate QEMU-Wasm state to Firecracker/HVF/libkrun

Rejected from scope. Runtime-pack and machine-state compatibility would couple
unrelated backends and make the browser engine part of the production ABI.

## Migration and compatibility

- The current direct-WASI implementation remains functional.
- Browser-facing names and docs converge from ambiguous `BrowserWasmBackend`
  wording toward `BrowserWasiBackend`.
- `BackendKind::WebLinux` is added without making it an auto-selected fallback
  for native hosts.
- `BuilderBackendChoice::WebLinux` is explicit; it is selected by the browser
  workbench and is not silently chosen by native builder auto-detection.
- Existing `.mvmpkg` readers remain supported while the workload/runtime-pack
  split is introduced through a versioned schema.
- ADR-024 should be updated in the implementation change to remove its stale
  “nothing has landed” text and reference this ADR for browser Linux.
- ADR-006 should link to this ADR and distinguish `deploy` from provider/fleet
  orchestration.
