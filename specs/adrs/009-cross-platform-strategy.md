# ADR-009: Cross-platform strategy — Linux and macOS native, Windows via the studio app

## Status

Accepted.

## Context

mvm runs directly on the two host classes that expose a real hypervisor
primitive its backends can drive: Linux (`/dev/kvm`) and macOS
(Hypervisor.framework). Windows exposes no equivalent primitive any
`VmBackend` implementation targets, and CI cannot assert live-microVM
behavior on a Windows runner the way it can on Linux and macOS.

mvm's non-CLI consumers already reach the runtime through one stable,
backend-agnostic trait (`mvm-client`'s `MvmClient`) regardless of whether
the target is in-process or remote. That seam is exactly what a
Windows-native GUI needs: it never has to run a `VmBackend` itself.

## Decision

Linux and macOS are the two native execution hosts. Every `VmBackend`
implementation (Firecracker, libkrun, HVF, QEMU) runs only on these two;
none targets Windows.

Windows is not a native execution host and never gets a `VmBackend`
implementation. The supported Windows path is the **studio** desktop app
(a Tauri shell): it links `mvm-client` and, by default, talks to a remote
fleet or sidecar over `GatewayBackend` — no local hypervisor requirement
on Windows at all. An in-process `LocalBackend` build (`--features local`)
is available for a Windows host with a working libkrun path, but it is
not the default and is not asserted by CI.

CI mirrors this split exactly:

- `ci.yml` (every push) and `ci-full.yml` (the full platform matrix) build
  and test Linux and macOS.
- `windows.yml` runs a **non-blocking, informational** Windows lane —
  `cargo check --workspace` (`continue-on-error: true`) plus a build and
  test of `mvm-core` alone, the one crate required to compile everywhere
  (no shell-out, no vsock, no platform-specific VMM binding) — triggered
  only at release tags or by manual dispatch, never gating a push or a
  merge.

No code path assumes a Windows-native hypervisor. Crates that shell out,
open a vsock socket, or link a platform VMM (`mvm-backend`, `mvm-build`,
`mvm-guest`, `mvm-hostd`, `mvm-vm-host`) are not asserted to build on
Windows and are outside the informational lane's scope.

## Consequences

No Windows-specific VMM code, no Windows-specific integration-test
surface, and no long-tail Windows bug queue competing with Linux/macOS
engineering time. The studio app is the one place Windows-specific UX
work happens, and it already exercises the same `MvmClient` trait every
other consumer uses — Windows support work and runtime-library work stay
decoupled.

A Windows user who wants a bare terminal `mvmctl` workflow with a local
backend gets an unverified, best-effort path, not a first-class one.

The Windows CI lane exists purely to catch a `mvm-core`-level compile
break early; it asserts nothing about VM lifecycle behavior and is not a
required check.
