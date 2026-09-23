---
title: Machine limitations
description: Explicit limits for the mvmctl machine workflow.
---

This page keeps the `mvmctl machine` happy path honest. If a capability is not
listed as supported here, treat it as backend-specific, experimental, or future
work rather than a default guarantee.

## Host Nix

Image-backed machine runs do not need host Nix. The normal path is a signed
`mvmctl` binary plus `mvmctl machine run --image ...`.

Workflows that build Linux images, evaluate flakes, or use source-checkout Nix
recipes still use mvm's builder boundary. On macOS that means the project
builder VM owns Linux/Nix work; on Linux the command may use the native Linux
path or the builder boundary depending on the workflow.

## Network Protocol Scope

Machine networking is default-deny. `--net` enables dev-tier egress, and
`--allow-host HOST[:PORT]` narrows the allowed destinations.

Current common-path policy is host/port-oriented TCP egress. Do not assume ICMP,
raw sockets, multicast, arbitrary L2 behavior, inbound services, or transparent
`:80`/`:443` interception are available on every backend. When a guide depends
on a backend-specific network behavior, it must name that backend.

## Volume Shapes

Volumes are explicit host shares. They default to read-only unless a workflow
spells out writable access.

Do not treat arbitrary host paths, device nodes, nested mounts, special files,
or symlink traversal as portable volume features. Production inputs should be
declared host-side and promoted into builds or artifacts explicitly; mutable dev
state inside a persistent machine is not automatically a production input.

## Guest fsync On macOS Volumes

On the HVF backend, a guest fsync on a writable disk volume puts the data in
the host's storage, but not past the drive's write cache. The drive cache is
emptied once, when the VM stops cleanly; a VM process that is force-killed
skips that step. A guest fsync therefore survives a crash of the guest or of
the VM process, but a host power loss or kernel panic before the drive cache is
emptied can lose writes the guest believed durable.

That trade is deliberate. Emptying the drive cache on macOS costs milliseconds
per call, and a guest that syncs after every small write ran about twice as
slow when every guest fsync paid it. The apple-container backend runs on the
same VMM and behaves the same way; other backends are unaffected.

HVF full-VM checkpoints refuse a VM with any writable disk, because a snapshot
does not carry disk contents. Use a volume for durable files, and stop the VM
to make its last writes durable.

## No SSH, On Any Tier

There is no SSH capability of any kind in a machine, on any profile —
including dev/permissive. Private key files, `~/.ssh`, known-hosts files, SSH
servers, SSH clients, SSH config, and host ssh-agent forwarding are never
copied, mounted, or bridged into a guest. TCP/22 is blocked on the default
machine path. The console PTY-over-vsock transport (`machine exec -it`,
`machine shell`) is the only interactive path into a dev-tier machine.

## macOS Signing And Entitlements

Apple Silicon macOS uses the supported macOS virtualization path. Some behavior
depends on host OS version, Hypervisor.framework availability, and the
local signed binary/entitlement posture.

If a command fails only on macOS, include `mvmctl doctor`, the macOS version,
CPU architecture, and backend in the report. Do not assume Intel macOS is a
supported runtime target.

## GPU Status

GPU passthrough or virtual GPU acceleration is not part of the default
`mvmctl machine` surface. A non-default, opt-in compute remoting
capability forwards the guest's CUDA/NVML calls to a host accelerator over
vsock when a launch explicitly asks for it; this is a different path from
passthrough, which remains unsupported. Do not depend on GPU access from a
machine that did not explicitly opt in: without the opt-in, an
accelerator is not available to the guest.

On this path, which is not part of the default machine surface, `--gpu` exposes
the backend's available device ordinals. `--gpu-device N` is likewise not part of the default
machine surface and pins the VM to host ordinal `N`. A pinned VM sees exactly
one guest device at ordinal `0`; the endpoint maps it to the selected host
device and refuses any other guest ordinal. An unavailable host ordinal is a
startup error rather than a fallback to another device.

## Host And Guest Architecture Support

Supported host/runtime combinations are listed in
[Platform support](/reference/platform-support/). The common supported hosts are
Linux with KVM and Apple Silicon macOS.

Guest image architecture must match the backend's supported guest target. A
portable artifact or OCI image that verifies on one architecture is not
automatically runnable on another; `machine check-artifact` refuses host-arch
mismatches.

## Portable Artifact Preview

`machine check-artifact` verifies artifact signature, hash, format, and host
architecture before deriving admission posture. That is not the same as a
complete `machine pack` / `machine run <artifact>` product workflow.

Until the pack/run workflow lands, keep transfer, cleanup, and lower-level
artifact operations in advanced docs and do not present `.mvm` artifacts as
self-executing bypass blobs.
