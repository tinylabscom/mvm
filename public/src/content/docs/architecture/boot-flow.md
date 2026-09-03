---
title: Boot flow
description: How a microVM boots the universal initramfs, receives its environment over vsock, and starts the workload.
---

This page describes the current boot and execution path for workload microVMs.
It replaces the older per-rootfs init schemes (`mvm-verity-init`, `mvm-oci-init`,
busybox `/init`) with a single **universal initramfs** and a fail-closed
activation step over vsock. Every runner backend boots this contract —
Firecracker, libkrun, HVF, and QEMU (dev/test tier) all attach the universal
initramfs and deliver `ActivateEnvironment` over vsock. QEMU's `vhost-vsock`
speaks real `AF_VSOCK`, so its channels ride a per-VM `AF_VSOCK`↔UNIX bridge
into the same per-port UNIX-socket convention the other backends expose
natively.

## The universal initramfs

The initramfs is a deterministic **cargo artifact**: the pinned agent
source is cross-compiled once (`cargo zigbuild` → musl, content-keyed
cache) and packed as an epoch-zero, stably-ordered cpio — no Nix on the
boot path. It is a small,
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
- any virtio-blk volumes.

The block layout is fixed by the workload runner (verity sidecars are
attached only for verity-sealed boots):

| Guest device | Content                                        |
| ------------ | ---------------------------------------------- |
| `/dev/vda`   | rootfs data                                    |
| `/dev/vdb`   | rootfs dm-verity hash tree (verity boots only) |
| `/dev/vdc`   | runtime overlay data                           |
| `/dev/vdd`   | runtime overlay dm-verity hash tree            |

Every workload boots from a block root. The virtio-fs root was the one boot
mode that could not be dm-verity sealed, and across this project's recorded
launch history it was taken zero times; it has been removed, and the root
strategy is now unconditionally block-backed ext4.

**On the universal-initramfs verity path the kernel cmdline carries no roothash
tokens**: the rootfs and runtime-overlay roothashes and device paths arrive over
vsock in `ActivateEnvironment` after boot, so the cmdline carries only the
VMM console base plus, when applicable, egress, verb-grant, and user-volume
tokens.

That scoping matters, because the legacy tokens are not gone from the tree. The
per-backend verity cmdline builders still emit `mvm.roothash=`, `mvm.data=`,
`mvm.hash=`, and the `mvm.runtime_roothash=` / `mvm.runtime_data=` /
`mvm.runtime_hash=` trio — the shared `build_verity_cmdline_args` for the QEMU
driver, and an inline equivalent in the libkrun driver. A non-verity boot that
carries a runtime overlay as a plain read-only block device still emits
`mvm.runtime_data=`, naming the device the overlay actually landed on. The
2048-byte cmdline overflow guard still applies.

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

- **Rootfs config** — one of two shapes: a dm-verity block root (`/dev/vda`
  - `/dev/vdb` + roothash, from the launch config or the `rootfs.roothash`
    sidecar), or an unverified plain-block root (`/dev/vda` only).
- **Runtime overlay config** — `/dev/vdc`, `/dev/vdd`, and its roothash, when
  the boot carries an overlay. A rootfs-only boot sends no overlay.
- **Volumes** — the guest mountpoint, read-only flag and ext4 volume label for
  each granted directory. A granted directory is materialized into an ext4
  image on the host and attached as virtio-blk, so the guest mounts it by
  label rather than by a virtio-fs tag. `Disk` volumes are attached as block
  devices directly and are not part of the message.
- **Optional verb-grant envelope** — read from
  `<MVM_HOME>/vms/<name>/verb-grant.json` when present.

The host requires an `ActivateEnvironmentAck`. Any error or unexpected response
fails the boot closed. A legacy per-rootfs verity initramfs (used when the
universal artifact is not cached yet) keeps its own PID 1 and is never sent
this verb.

## Guest applies activation and pivots into the workload

On receiving `ActivateEnvironment`, the guest:

1. Mounts the root: the `root` dm-verity target from `/dev/vda` + `/dev/vdb`
   for a sealed boot, or the plain block device read-only for an unverified
   boot — staged at `/mnt/root`.
2. Mounts the runtime overlay read-only at `/mvm/runtime` inside the new root,
   when one was sent.
3. Mounts any volumes, each by its ext4 volume label.
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

The universal initramfs assumes a Linux guest kernel with virtio-blk devices
and a vsock channel. Tiers that don't provide those get the model in adapted
form — or honestly not at all:

- **Wasm** (`WasmBackend`, ADR-024) — no Linux kernel and no initramfs: the
  workload is a WASI module under host `wasmtime`, so `ActivateEnvironment`
  does not apply verbatim. Its implemented analog is the **capability
  handshake**: every run receives the same environment description adapted
  to WASI — the runtime-overlay guest binaries and each directory-share
  volume as preopened directories (read-only honored) at the same guest
  paths the other backends mount them, and policy/grant delivery as an
  `activation.json` (overlay path, volume mountpoints, policy posture
  label, grant presence) preopened read-only at `/run/mvm` with
  `MVM_ACTIVATION_FILE` in the module's env. The WASI capability model is
  the gate: the module receives exactly the preopens, env, and host imports
  the plan admits and nothing else; there is no in-guest signature
  verification because the WASI host is the trust boundary. Kernel,
  verified-boot, block-volume, and console requests still fail closed. Per
  ADR-024 it stays opt-in, claim-free, and — if it ever executes real
  workloads — the engine runs in-guest, never as a host process dependency.
- **Docker / shared-kernel containers** — removed by Plan 329. The
  ADR-034 dev tier has been deleted; mvm is microVM-only and a host with no
  usable hypervisor fails closed. The Apple Container backend remains
  available as an explicit opt-in on Apple Silicon, but it is a
  hardware-virtualized path (HVF with a container kernel), not a
  shared-kernel container.
- **Apple Container** — Apple's prebuilt container kernel (a fetched binary
  artifact, no toolchain) boots on mvm's own HVF supervisor behind
  `--hypervisor apple-container` (opt-in only, never auto-selected). The
  backend resolves the kernel from the local cache, sets it as the launch's
  kernel image, and delegates the entire boot to the HVF workload runner:
  the same universal initramfs, the same agent-as-PID-1, and the same
  `ActivateEnvironment` flow as every other backend — only the kernel
  differs. There is no Swift and no Virtualization.framework anywhere in
  the design (the earlier vminitd line was dropped: it is Swift with no
  prebuilt artifact). The kernel's provenance is the artifact cache rather
  than an mvm build — recorded honestly in the backend's security profile,
  see `specs/plans/271-apple-container-backend.md`.
- **WHP (Windows Hypervisor Platform)** — a future Windows-host backend. The
  guest side is unchanged: the same kernel + universal initramfs boot and the
  same `ActivateEnvironment`. The work is entirely host-side — a WHP
  `VmmDriver`, a virtio-blk device model, and a vsock transport over
  Hyper-V sockets (`AF_HYPERV`) in place of `AF_VSOCK`. dm-verity runs in the
  guest, so verified boot is host-agnostic and a WHP backend could target the
  same Tier 2 posture as HVF/libkrun once its egress gate lands. Until then,
  WSL2 with nested `/dev/kvm` is the supported Windows-adjacent path.
- **WebLinux (browser tier)** — boots a real Nix-built Linux kernel under
  QEMU-Wasm inside a browser Worker, so the guest side is a Linux boot rather
  than a bare module load. What is missing is the layer below: there is no
  hypervisor and no hardware isolation boundary, only the browser's sandbox, so
  the tier is claim-free and never auto-selected. It is reachable through
  `--hypervisor web-linux`; on a native host the backend is a fail-closed stub
  that refuses every lifecycle call.
- **Wasm (host `wasmtime` tier)** — a separate claim-free tier that runs a
  user-supplied WASI Preview 1 module directly, with no Linux kernel, no
  initramfs, and no vsock. Its `mvm:egress` host import relays each request over
  a Unix socket to the host-side substitution endpoint, so egress is gated at
  the same place the microVM tiers gate it. Opt-in only.

## Security properties

- **Fail-closed guest** — no operational RPCs before a successful
  `ActivateEnvironment`, on every boot that attaches the universal initramfs.
- **No roothash on the kernel cmdline, on the universal-initramfs verity path**
  — there, verity parameters travel over the authenticated vsock channel instead
  of being visible in `/proc/cmdline`. The per-backend verity cmdline builders
  still emit them on the paths described above.
- **Verified root where sealed** — a verity boot only pivots into a rootfs
  that passed dm-verity; unverified dev-tier boots are mounted plainly and
  are exactly as trustworthy as the legacy path they replace.
- **Least privilege after activation** — the agent drops to UID 901 before
  running any workload code.
