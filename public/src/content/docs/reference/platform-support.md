---
title: Platform support
description: Current host, architecture, backend, and support-status matrix for mvm.
---

`mvm` supports local microVM workflows on native Linux with KVM and on Apple
Silicon macOS. Windows is tracked as future host work. Linux hosts without `/dev/kvm` can run the dev/test QEMU/TCG backend (`--hypervisor qemu`); there is no container fallback.

Use this page to decide where to run `mvmctl`, where Linux image builds happen,
and which backend limitations apply.

## Support matrix

| Host | Architecture | Runtime backend | Status | Notes |
| --- | --- | --- | --- | --- |
| Linux with `/dev/kvm` | x86_64, aarch64 | Firecracker | Supported | Strongest local target; direct KVM microVM path. |
| macOS Apple Silicon | aarch64 | Apple Virtualization / libkrun-backed paths | Supported | Local development and runtime path for M-series Macs. |
| Linux without `/dev/kvm` | x86_64, aarch64 | QEMU (TCG) | Dev/test | Software-emulated microVM (`--hypervisor qemu`); Tier 2 dev/test — slower, not for production. |
| Windows native | x86_64, aarch64 | None | Future | Tracked in [mvm#428](https://github.com/tinylabscom/mvm/issues/428). |
| WSL2 with nested KVM | x86_64, aarch64 | Experimental Linux path | Future/experimental | May expose `/dev/kvm`; not a supported host path today. |
| Intel macOS | x86_64 | None | Unsupported | Use Linux KVM or Apple Silicon macOS. |

## Build boundary by host

The guest image is a Linux artifact even when the host is macOS. `mvmctl build`
is still a host command, but Linux-specific work belongs to the builder
boundary.

| Host | Where Nix/Linux image work happens | User command |
| --- | --- | --- |
| Linux with KVM | Native Linux path or project builder boundary, depending on command. | `mvmctl build` |
| macOS Apple Silicon | Project builder VM. | `mvmctl build` |
| Windows/WSL2 future path | Future Linux backend/builder design. | Not supported today. |

You do not need host-side Nix for normal `mvmctl build` usage. The builder path
owns Linux evaluation, image assembly, and artifact extraction.

## Runtime boundary by host

Build time and runtime are separate. After an image is built:

- Linux with KVM boots through Firecracker.
- Apple Silicon macOS uses the supported macOS runtime backend path.
- Linux without `/dev/kvm` runs QEMU/TCG — a software-emulated microVM for dev/test (Tier 2), not a production isolation target.
- Windows native does not have a supported runtime backend today.

When reporting runtime behavior, include host OS, CPU architecture, selected
backend, `mvmctl doctor` output, and whether `/dev/kvm` was available.

## Target system strings

Nix target strings describe the Linux guest artifact, not the host operating
system:

| Host | Common guest target |
| --- | --- |
| Apple Silicon macOS | `aarch64-linux` |
| ARM Linux | `aarch64-linux` |
| Intel/AMD Linux | `x86_64-linux` |

The OS segment is `linux` because the workload runs inside a Linux guest.

## Security status

| Backend path | Security posture |
| --- | --- |
| Firecracker on Linux/KVM | Preferred local microVM isolation target. |
| Apple Virtualization / libkrun-backed macOS path | Supported local microVM path with backend-specific feature differences. |
| QEMU (TCG, no `/dev/kvm`) | Tier 2 dev/test microVM; do not use for untrusted code or security-sensitive workloads. |
| WSL2 nested KVM | Research/future path until tested and documented as supported. |

Security-sensitive examples should name the backend when behavior differs.

## Related pages

- [Install on Linux](/install/linux/)
- [Install on macOS](/install/macos/)
- [Install on Windows](/install/windows/)
- [Builder VM](/guides/builder-vm/)
- [Matryoshka model](/security/matryoshka/)
