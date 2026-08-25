---
title: Platform support
description: Current host, architecture, backend, and support-status matrix for mvm.
---

`mvm` supports local microVM workflows on native Linux with KVM, on Apple
Silicon macOS, and on **WSL2 with nested KVM** for the libkrun-backed workload
path. Native Windows is still future host work. Linux hosts without `/dev/kvm`
can run the dev/test QEMU/TCG backend (`--hypervisor qemu`); there is no
container fallback.

Use this page to decide where to run `mvmctl`, where Linux image builds happen,
and which backend limitations apply.

## Support matrix

| Host                      | Architecture    | Runtime backend            | Status                  | Notes                                                                                                                                                                                                                      |
| ------------------------- | --------------- | -------------------------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Linux with `/dev/kvm`     | x86_64, aarch64 | Firecracker                | Supported               | Strongest local target; direct KVM microVM path.                                                                                                                                                                           |
| macOS Apple Silicon       | aarch64         | HVF / libkrun-backed paths | Supported               | Local development and runtime path for M-series Macs. OCI `--allow-host` runs use the HVF no-guest-NIC host-vsock-proxy path when `mvm-hvf-supervisor` is available; otherwise the CLI fails closed before pull/boot work. |
| Linux without `/dev/kvm`  | x86_64, aarch64 | QEMU (TCG)                 | Dev/test                | Software-emulated microVM (`--hypervisor qemu`); Tier 2 dev/test — slower, not for production.                                                                                                                             |
| Browser (Chromium/Chrome) | Any             | BrowserWasi                | Dev/test                | Browser-tier WASI backend (no hypervisor); runs inside browser's own WebAssembly engine; claim-free tier for demos and browser-local development.                                                                          |
| Windows native            | x86_64, aarch64 | None                       | Future                  | Use WSL2 for the supported Windows-adjacent workload path; native Windows runtime support is still tracked in [mvm#428](https://github.com/tinylabscom/mvm/issues/428).                                                    |
| WSL2 with nested KVM      | x86_64, aarch64 | libkrun                    | Supported workload path | Requires `/dev/kvm`, libkrun installed in the distro, and both the repo and `MVM_HOME` on the WSL ext4 filesystem rather than `/mnt/<drive>/...`.                                                                          |
| Intel macOS               | x86_64          | None                       | Unsupported             | Use Linux KVM or Apple Silicon macOS.                                                                                                                                                                                      |

## Build boundary by host

The guest image is a Linux artifact even when the host is macOS. `mvmctl machine build`
is still a host command, but Linux-specific work belongs to the builder
boundary.

| Host                 | Where Nix/Linux image work happens                                                                  | User command                                             |
| -------------------- | --------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| Linux with KVM       | Native Linux path or project builder boundary, depending on command.                                | `mvmctl machine build`                                           |
| macOS Apple Silicon  | Project builder VM.                                                                                 | `mvmctl machine build`                                           |
| WSL2 with nested KVM | Supported workload runtime path inside the distro; builder/dev flows stay separate from this slice. | `mvmctl machine run`, `mvmctl run`, other workload verbs |
| Windows native       | Future Linux backend/builder design.                                                                | Not supported today.                                     |

You do not need host-side Nix for normal `mvmctl machine build` usage. The builder path
owns Linux evaluation, image assembly, and artifact extraction.

## Runtime boundary by host

Build time and runtime are separate. After an image is built:

- Browser browsers boot through the BrowserWasi backend, running the guest workload as a WASI module inside the browser's own WebAssembly engine.
- Linux with KVM boots through Firecracker.
- Apple Silicon macOS uses the supported macOS runtime backend path. OCI `--image --allow-host ...` uses the HVF host-vsock proxy path with no guest NIC when the helper is available, and is refused early when it is not.
- Linux without `/dev/kvm` runs QEMU/TCG — a software-emulated microVM for dev/test (Tier 2), not a production isolation target.
- WSL2 with nested KVM uses the libkrun workload backend inside the distro.
- Windows native does not have a supported runtime backend today.

The browser-tier backend is **claim-free**: it cannot assert any of the numbered security claims because there is no hardware isolation boundary. It runs inside the browser's own WebAssembly engine and has no guest kernel, no hypervisor, no vsock, and no verified boot. It is for demos, playgrounds, and browser-local development only, and it is never auto-selected.

When reporting runtime behavior, include host OS, CPU architecture, selected
backend, `mvmctl doctor` output, and whether `/dev/kvm` was available.

## Recovery capability boundary

Recovery is not interchangeable across backends. `mvmctl doctor` is the
authoritative live matrix; its `snapshot_tier` and `standby_pool` values come
from the selected backend's `VmCapabilities`.

| Recovery path                  | Meaning                                                                                  | Current limitation                                                                                            |
| ------------------------------ | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| Live-memory snapshot/restore   | Resume captured guest RAM and device state.                                              | Not advertised by the selectable production runners.                                                          |
| Save/restore machine state     | Restore a serialized VMM machine state without claiming live-memory fidelity.            | No selectable backend currently advertises it.                                                                |
| Disk-only CoW warm start       | Rebuild from a copy-on-write disk/overlay artifact; no RAM is restored.                  | The raw libkrun substrate has this primitive, but no selectable workload runner advertises it yet.            |
| Prelaunched supervisor standby | Pay supervisor/setup latency before a workload is claimed; this is not snapshot restore. | The raw libkrun substrate has a standby primitive, but no selectable workload runner advertises the pool yet. |
| Cold boot                      | Boot immutable kernel, initrd, image, and policy artifacts from scratch.                 | The portable fallback, with no saved machine state.                                                           |

Unsupported recovery requests fail closed. They must not silently change from
live-memory restore to disk-only warm start or cold boot; use the actionable
error to select a supported tier or request a cold boot explicitly.

## Target system strings

Nix target strings describe the Linux guest artifact, not the host operating
system:

| Host                | Common guest target |
| ------------------- | ------------------- |
| Apple Silicon macOS | `aarch64-linux`     |
| ARM Linux           | `aarch64-linux`     |
| Intel/AMD Linux     | `x86_64-linux`      |

The OS segment is `linux` because the workload runs inside a Linux guest.

## Security status

| Backend path                    | Security posture                                                                                                                                                    |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Firecracker on Linux/KVM        | Preferred local microVM isolation target.                                                                                                                           |
| HVF / libkrun-backed macOS path | Supported local microVM path with backend-specific feature differences. OCI `--allow-host` on `--image` is the HVF host-vsock-proxy path, not guest-NIC networking. |
| QEMU (TCG, no `/dev/kvm`)       | Tier 2 dev/test microVM; do not use for untrusted code or security-sensitive workloads.                                                                             |
| WSL2 nested KVM + libkrun       | Supported Tier 2 workload path inside the WSL2 distro. Firecracker is intentionally not part of this Windows slice.                                                 |

Security-sensitive examples should name the backend when behavior differs.

## Related pages

- [Install on Linux](/install/linux/)
- [Install on macOS](/install/macos/)
- [Install on Windows](/install/windows/)
- [Builder VM](/guides/builder-vm/)
- [Matryoshka model](/security/matryoshka/)
