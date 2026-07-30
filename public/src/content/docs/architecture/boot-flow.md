---
title: Boot flow
description: How a microVM boots the universal initramfs, receives its environment over vsock, and starts the workload.
---

This page describes the current boot and execution path for workload microVMs.
It replaces the older per-rootfs init schemes (`mvm-verity-init`, `mvm-oci-init`,
busybox `/init`) with a single **universal initramfs** and a fail-closed
activation step over vsock.

## The universal initramfs

The initramfs is built by `nix/images/initramfs/flake.nix`. It is a small,
deterministic cpio that contains exactly one file:

- `/init` — the static `mvm-guest-agent` binary.

It deliberately contains **no `/dev` nodes** (the build sandbox cannot create
device nodes). The guest creates them at boot by mounting `devtmpfs`.

The artifact is content-addressed and cached at
`<MVM_HOME>/cache/initramfs/<version>/<arch>/` alongside `initramfs.hash`,
`initramfs.size`, and `VERSION`. On a cache miss the CLI seeds from the shared
default cache, builds it via `nix build` on Linux (through the builder-VM
boundary, never a host nix binary), or downloads a published release artifact
on macOS. Attaching the initramfs is non-fatal: a cold cache falls back to the
legacy boot path rather than failing the run.

## Boot inputs and device layout

When the initramfs is attached, the backend boots:

- the workload kernel (`kernel_path`),
- the universal initramfs (`initrd_path`),
- the workload rootfs and its dm-verity sidecar,
- the runtime overlay and its dm-verity sidecar,
- any virtio-fs or virtio-blk volumes.

The block layout is fixed by the workload runner (verity sidecars are
attached only for verity-sealed boots):

| Guest device | Content |
| --- | --- |
| `/dev/vda` | rootfs data |
| `/dev/vdb` | rootfs dm-verity hash tree (verity boots only) |
| `/dev/vdc` | runtime overlay data |
| `/dev/vdd` | runtime overlay dm-verity hash tree |

A block-less virtiofs-root dev boot attaches no disks at all; the root comes
from a virtio-fs tag instead.

The kernel cmdline **does not carry roothash tokens**. The legacy
`mvm.roothash=`, `mvm.data=`, `mvm.hash=`, and `mvm.runtime_*=` tokens are gone;
the cmdline carries only the VMM console base plus
`mvm.runtime_source_policy=…` (and, when applicable, egress, verb-grant, and
user-volume tokens). The 2048-byte cmdline overflow guard still applies.

## Guest PID 1: early setup, then a fail-closed gate

`mvm-guest-agent` runs as `/init` (PID 1). Its startup sequence is:

1. Mount `/proc` and `/sys` with `MS_NOSUID | MS_NOEXEC | MS_NODEV`.
2. Mount `devtmpfs` on `/dev` with `MS_NOSUID` (providing `/dev/console`,
   `/dev/null`, and friends).
3. Install a SIGCHLD handler so orphaned descendants are reaped immediately.
4. Enter the normal vsock accept loop in the `Awaiting` activation state.

While in PID-1 initramfs mode, the dispatcher enforces a hard gate:

- **Only `ActivateEnvironment` is accepted.**
- Every other operational verb is refused with `NotActivated`.
- If activation fails, the agent stays in `Failed` and reports the reason on
  subsequent requests.

The guest exposes no operational RPC surface until the host activates it.

## Host-side activation over vsock

After the VMM boots, the workload runner builds an `ActivateEnvironment`
message from the admitted launch config and sends it over the guest-agent
vsock port — for every boot that attached the universal initramfs, verified
or not. The message carries:

- **Rootfs config** — one of three shapes: a dm-verity block root (`/dev/vda`
  + `/dev/vdb` + roothash, from the launch config or the `rootfs.roothash`
  sidecar), an unverified plain-block root (`/dev/vda` only), or a virtio-fs
  root tag (`mvmroot`).
- **Runtime overlay config** — `/dev/vdc`, `/dev/vdd`, and its roothash, when
  the boot carries an overlay. A rootfs-only boot sends no overlay.
- **Volumes** — `DirShare` volumes translated to virtio-fs tags (`uvol0`,
  `uvol1`, …) with guest mountpoints and read-only flags. `Disk` volumes are
  already attached as block devices, so they are not part of the message.
- **Optional verb-grant envelope** — read from
  `<MVM_HOME>/vms/<name>/verb-grant.json` when present.

The host requires an `ActivateEnvironmentAck`. Any error or unexpected response
fails the boot closed. A legacy per-rootfs verity initramfs (used when the
universal artifact is not cached yet) keeps its own PID 1 and is never sent
this verb.

## Guest applies activation and pivots into the workload

On receiving `ActivateEnvironment`, the guest:

1. Mounts the root: the `root` dm-verity target from `/dev/vda` + `/dev/vdb`
   for a sealed boot, the plain block device read-only for an unverified boot,
   or the virtio-fs tag for a block-less dev boot — staged at `/mnt/root`.
2. Mounts the runtime overlay read-only at `/mvm/runtime` inside the new root,
   when one was sent.
3. Mounts any virtio-fs volumes.
4. Pivots the root filesystem to the mounted root.
5. Drops privilege to the fixed workload UID/GID `901`.
6. Flips the boot state to `Activated` and begins serving operational RPCs.

If a verb-grant envelope was included, the activation message must authenticate
against the host-signer trust anchor before the agent accepts operational RPCs.

## Execution after activation

Once activated, the guest is a normal workload VM:

- The runtime overlay at `/mvm/runtime` provides the guest binaries.
- The workload entrypoint runs under UID 901 inside the verified rootfs.
- Exit status, readiness, and entrypoint events stream back to the host over
  vsock.
- Egress still goes through the per-VM substitution endpoint (the sole egress
  gate, spawned before boot).

## Warm-pool / standby note

Factory standby parents boot the same device model and cmdline shape as
workloads, minus workload authority (no plan, no volumes, no broker, deny-all
egress). They are captured before activation, so the warm-claim path with the
universal initramfs is not armed yet; it is part of the HVF / warm-claim
convergence work.

## Future tiers and backends

The universal initramfs assumes a Linux guest kernel with virtio-blk /
virtio-fs devices and a vsock channel. Tiers that don't provide those get the
model in adapted form — or honestly not at all:

- **Wasm** (`WasmBackend`, ADR-024) — no Linux kernel and no initramfs: the
  workload is a WASI module under host `wasmtime`, so `ActivateEnvironment`
  does not apply. If this tier ever goes beyond demo/preview, the analogous
  step is a capability handshake over the wasm import channel (the same seam
  as today's host-mediated `mvm:egress` import): admission binds policy, the
  module receives exactly the host functions the plan admits, and any
  kernel/verified-boot/vsock request fails closed. Per ADR-024 it stays
  opt-in, claim-free, and — if it ever executes real workloads — the engine
  runs in-guest, never as a host process dependency.
- **Docker / shared-kernel containers** — there is no container fallback and
  none is planned: a shared-kernel container is not a microVM (see
  [Matryoshka model](/security/matryoshka/)). Its init is not
  `mvm-guest-agent` and its mounts are host-kernel namespaces, not dm-verity
  block devices, so this boot contract cannot apply without becoming a
  microVM. A container tier, if one is ever admitted, would be dev-tier only,
  refused by prod admission, and would carry its own explicitly weaker boot
  contract rather than sharing this one.
- **Apple Container** — Apple's `container` framework boots lightweight Linux
  VMs with its own init and networking/vsock stack. There is no backend
  variant for it today. Future support means a driver that boots the same
  kernel + universal initramfs (or runs `mvm-guest-agent` as the guest init)
  and bridges the activation channel to the framework's vsock transport.
- **WHP (Windows Hypervisor Platform)** — a future Windows-host backend. The
  guest side is unchanged: the same kernel + universal initramfs boot and the
  same `ActivateEnvironment`. The work is entirely host-side — a WHP
  `VmmDriver`, virtio-blk/virtio-fs device model, and a vsock transport over
  Hyper-V sockets (`AF_HYPERV`) in place of `AF_VSOCK`. dm-verity runs in the
  guest, so verified boot is host-agnostic and a WHP backend could target the
  same Tier 2 posture as HVF/libkrun once its egress gate lands. Until then,
  WSL2 with nested `/dev/kvm` is the supported Windows-adjacent path.

## Security properties

- **Fail-closed guest** — no operational RPCs before a successful
  `ActivateEnvironment`, on every boot that attaches the universal initramfs.
- **No roothash on the kernel cmdline** — verity parameters travel over the
  authenticated vsock channel instead of being visible in `/proc/cmdline`.
- **Verified root where sealed** — a verity boot only pivots into a rootfs
  that passed dm-verity; unverified dev-tier boots are mounted plainly and
  are exactly as trustworthy as the legacy path they replace.
- **Least privilege after activation** — the agent drops to UID 901 before
  running any workload code.
