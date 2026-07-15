# ADR-024: A WASM/browser backend, if built, claims no isolation

## Status

Proposed — no implementation exists. `BackendKind` (`mvm-backend::catalog`)
enumerates exactly `Firecracker`, `Libkrun`, `Qemu`, `Mock`, `Hvf`; no
`wasmtime` dependency appears anywhere in the workspace; `mvm-guest`'s
runner has no WASM variant. This document records a boundary decision for
if and when that changes, not a shipped backend.

## Context

mvm's real backends provide hardware-isolated microVMs: Firecracker on
Linux `/dev/kvm`, libkrun and HVF on macOS, QEMU as a Linux dev/test
substrate. There is a recurring desire for a backend that runs in a
browser or a WASI-like sandbox — for demos, docs playgrounds, and
deterministic repros where installing and booting a real microVM is the
wrong ask. Browsers and WASM runtimes expose none of the primitives the
security model depends on: no KVM, no Hypervisor.framework, no TAP, no
virtio, no vsock, no privileged mounts. A backend built on that substrate
cannot honestly claim microVM isolation.

## Decision

**If a WASM/browser-compatible backend is ever built, it is bound by
three constraints, decided now so they cannot be relitigated case by case
later:**

1. **It is opt-in only and never auto-selected.** Backend auto-detection
   (the platform ladder documented in the `VmBackend` ADR) never resolves
   to it; a caller must name it explicitly.
2. **It reports its capabilities honestly, never a degraded approximation
   of a real backend.** It implements the same `VmBackend` trait every
   other backend does, with a capability matrix that says plainly what it
   lacks — no hardware virtualization, no real Linux kernel, no TAP
   networking, no virtio, no vsock. A request for any of those fails
   closed with a typed error naming the supported alternative; it never
   silently drops a requirement and proceeds.
3. **It carries none of the numbered security claims, and this ADR does
   not request claim-table promotion for it.** The security posture's
   threat model and per-backend tier matrix cover backends that provide a
   hardware isolation boundary; a WASM/browser tier is a portability and
   demo tier, not an isolation tier, and must never be documented or
   marketed as one.

**If the backend is ever used to execute a workload as more than a
demo/preview — i.e. if it becomes a production execution path rather than
a throwaway sandbox — the untrusted-bytes-executing engine (wasmtime or
equivalent) runs as a guest binary inside a real microVM, never as a host
process dependency.** This mirrors the existing rule for every other
interpreted-language workload (Python, Node): the host never links the
thing that parses and executes attacker-influenced input; that surface
lives behind the microVM boundary, confined the same way any other guest
service is.

## Alternatives considered

- **Emulate a Linux kernel in WASM to approximate a real microVM.**
  Rejected: enormous scope, still not hardware isolation, and dishonest
  framing regardless of effort spent.
- **Silently degrade** — accept a kernel image or TAP request and ignore
  it rather than fail. Rejected: violates the standing rule that a
  backend never silently drops a security-relevant requirement.

## Consequences

- Until built, mvm has exactly one portability story: run a real microVM,
  on whichever of the five current backends the host supports. There is
  no fallback tier for hosts with none of them.
- A future implementation is scoped by this ADR before a line of code
  lands: opt-in, honestly-capable, claim-free, and — if it ever executes
  real workloads — engine-in-guest rather than engine-in-host.
- Any design for the promotion path from a browser/demo session to a
  claims-bearing production microVM is unwritten. It is not decided here,
  and no existing subsystem in the tree currently serves that purpose.
