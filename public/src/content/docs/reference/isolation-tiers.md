---
title: Isolation tiers
description: How mvm's full-OS microVM isolation compares to the no-OS / no-kernel function-sandbox tier on workload compatibility, security posture, and startup latency.
---

Untrusted-code isolation today splits into two tiers. This page describes both
on their own terms, states which one mvm is, and gives the honest tradeoff so
you can pick the right one for a given workload.

## High-level summary

mvm is the choice when the workload needs **real Linux**: an unmodified OCI
image, arbitrary native dependencies, multiple processes, a filesystem, or
ordinary Linux syscalls. Each run gets a full guest kernel and microVM boundary,
with signed admission, default-deny networking, private writable state, and
explicit host mounts.

A no-OS function tier is the choice when the workload already fits a restricted
ABI and the absolute lowest cold-start latency matters more than general Linux
compatibility. It avoids booting an operating system, but that speed comes with
a narrower execution model.

The practical rule is simple: **choose mvm for compatibility and isolation;
choose the no-OS tier for constrained pure functions at extreme scale; compose
both when an application has both shapes of work.** Warm mvm starts reduce the
latency difference without giving up the full Linux environment.

## The two tiers

**Full-OS microVM** — what mvm runs. A real Linux kernel plus userspace,
hardware-virtualized inside a microVM (Firecracker/KVM on Linux, or the
equivalent Hypervisor.framework/libkrun path on macOS). The guest boots an
actual kernel, has a process tree and a filesystem, and can run anything that
runs on Linux.

**No-OS / no-kernel tier** — a bare function loaded directly into a hypervisor
partition or a language-level sandbox, with no OS layer between the function
and the virtualization boundary. No kernel boots, there is no process tree,
and no general Linux syscall surface is presented. This tier is referred to
here by category, not by product name.

Neither is a worse version of the other. They sit at different points on the
compatibility/security/latency curve, aimed at different workload shapes.

## Workload compatibility

This is mvm's core advantage. Because a full-OS microVM boots a real kernel:

- mvm runs any unmodified OCI image or Linux workload — arbitrary binaries,
  arbitrary language runtimes, arbitrary process trees, unmodified.
- There is no compile-target restriction. Ship whatever already builds and
  runs on Linux.
- Stateful and multi-process workloads (databases, long-running services,
  anything that shells out to another binary) work the same as on any Linux
  host.

The no-OS tier requires compiling the workload down to its restricted ABI —
often Wasm — before it can run at all. That is a hard compatibility ceiling,
not a workaroundable limitation: it excludes most existing software, arbitrary
native dependencies, multi-process workloads, and anything that expects a real
filesystem or Linux syscalls, because there is no OS underneath to provide
them.

## Security posture

mvm backs a set of machine-checked security claims — CI-enforced, so a
regression fails the build rather than shipping silently. They group into a
few categories:

- No host-filesystem access from the guest beyond what is explicitly shared.
- No privilege escalation inside the guest — a compromised workload cannot
  become root.
- Verified boot — a tampered root filesystem fails to boot rather than
  running.
- Signed, audited execution plans — every workload launch is admitted from a
  signed, chain-audited plan rather than started ad hoc.
- Default-deny egress — network access requires positive admission by policy;
  nothing reaches the network by default.
- Secrets never enter the guest — credential substitution happens host-side; <!-- allow(doc-claim:secret-non-leakage): summarizes an existing shipped host-side property -->
  raw secret bytes never cross into guest memory.
- No interactive access to a sealed production guest — no shell, no `do_exec`,
  no PTY. The one host-to-guest byte path is a plan-granted, default-deny
  channel to a fixed entrypoint's stdin, which cannot select a program or spawn
  anything; see [Workload input](/guides/workload-input/).

These categories describe what a full OS lets you reason about: a process
model, a filesystem boundary, a network stack you can filter, an audit trail
tied to a real kernel-level execution context. The no-OS tier mostly doesn't
have these categories to reason about, because there is no OS: no filesystem
to scope access to, no privilege model to escalate out of, no kernel boot to
verify. That absence is fine for a pure, stateless function call. It is a gap
for anything that needs a filesystem, a process boundary, or an audited
network egress path.

## Latency tradeoff (honest)

The no-OS tier wins raw cold start — sub-millisecond, because there is no
kernel to boot. That is real, and mvm does not claim otherwise for a naive
cold boot: booting a full Linux kernel from scratch costs hundreds of
milliseconds to a few seconds, depending on kernel size and backend.

mvm closes the gap with warm snapshot-restore instead of a cold boot: resuming
a paused, already-booted microVM from a memory snapshot restores a full-OS
guest in tens of milliseconds, measured on Firecracker/KVM — far below a cold
boot, and close enough that latency stops being the deciding factor. You keep
the full-OS compatibility and the whole security-claim chain above; you are
just not paying the cold-boot cost on every start.

|                      | Cold boot                       | Warm snapshot-restore                  | No-OS tier cold start       |
| -------------------- | ------------------------------- | -------------------------------------- | --------------------------- |
| Compatibility        | Any Linux workload              | Any Linux workload                     | Restricted ABI (often Wasm) |
| Security-claim chain | Full                            | Full, re-verified on restore           | Narrower by construction    |
| Typical latency      | Hundreds of ms to a few seconds | Tens of milliseconds (Firecracker/KVM) | Sub-millisecond             |

## Wasm and browser tiers

Two backends sit outside the hypervisor boundary. They are distinct, and neither is
`BrowserWasi` — there is no backend by that name and no `--hypervisor browser-wasm`
selector.

- **`wasm`** (`--hypervisor wasm`) is the host tier: the workload runs as a module in a
  host `wasmtime` engine. No guest kernel, no guest network.
- **`web-linux`** (`--hypervisor web-linux`) is the browser tier: it boots a real
  Nix-built Linux kernel under QEMU-Wasm inside the browser's own WebAssembly engine. On
  a native host the backend is a stub that fails closed with a typed "browser-only"
  error.

Both are **claim-free**: there is no hardware isolation, so neither can assert the
numbered security claims.

| Feature         | `wasm` (host wasmtime)      | `web-linux` (browser)                        |
| --------------- | --------------------------- | -------------------------------------------- |
| Isolation       | Wasm engine sandbox only    | Browser sandbox/process isolation only       |
| Guest kernel    | None (Wasm module)          | Nix-built Linux kernel under QEMU-Wasm       |
| vsock           | None                        | None                                         |
| Verified boot   | None                        | None                                         |
| Snapshots       | None                        | None                                         |
| Network         | No guest network            | No native NIC                                |
| Secure claims   | None (claim-free tier)      | None (claim-free tier)                       |

These tiers exist for demos, playgrounds, and browser-local development. Neither can be
auto-selected, and neither is used for production workloads.

## When to pick which

- **Full-OS microVM (mvm)** — real, stateful, or arbitrary workloads:
  unmodified containers, services with native dependencies, anything that
  needs a filesystem, more than one process, or Linux syscalls you don't want
  to re-architect around.
- **No-OS tier** — ephemeral, pure-function calls at extreme scale, where the
  workload already fits (or can be compiled to fit) a restricted ABI and the
  cold-start floor matters more than compatibility or the full security-claim
  surface.
- **They compose.** Fronting a full-OS microVM backend with a no-OS function
  tier is a reasonable architecture: use the fast tier for the pure-function
  hot path and hand off to a full-OS microVM whenever a request needs real
  Linux semantics.

## Related pages

- [The Matryoshka model](/security/matryoshka/) — mvm's isolation layers and
  per-backend claim tiers in detail.
- [Platform support](/reference/platform-support/) — host, backend, and
  support-status matrix.
- [Limits & resources](/reference/limits/) — sizing and backend limits.
