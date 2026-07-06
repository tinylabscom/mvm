---
title: "WSL2 notes for mvm"
description: "Experimental WSL2 notes for mvm. WSL2 nested KVM is future backend work, not a supported local host today."
---

This page captures WSL2 research notes for future Windows support. WSL2 is **not** a supported local microVM host today. Native Windows host support is tracked in [mvm#428](https://github.com/tinylabscom/mvm/issues/428).

## Why WSL2 for mvm

WSL2 is a real Linux kernel running under Hyper-V, but mvm does not yet treat it as a supported backend. A future WSL2 path would require nested KVM to be present and tested in CI. From inside a capable WSL2 distro:

- **`/dev/kvm` may be available** on some Windows 11/WSL2 combinations. When it is missing, mvm cannot run the Linux KVM path.
- **Filesystem is real Linux ext4**. APFS-style copy-on-write isn't here yet (Sprint 47 Plan D ships APFS CoW for macOS Vz; WSL2's ext4 will fall back to byte-copy in `mvm-runtime::vm::cow::reflink_or_copy`), but everything functionally works.
- **Networking is bridged** through Hyper-V's vmswitch. Port forwarding from Windows host to a WSL2 distro is automatic for `127.0.0.1` binds; mvm guests behind the WSL2 distro need an additional hop, covered below.

The cost is one nested VM hop: workload runs inside a microVM, inside WSL2, inside Hyper-V on the Windows host. We do not currently publish performance or support guarantees for that stack.

## Setup

The [install quickstart](/install/windows) covers `wsl --install` + `cargo install`. Two follow-up steps that matter for mvm specifically:

### Confirm nested KVM works

```bash
ls -l /dev/kvm
```

Should show a character device. If `/dev/kvm` is missing, WSL2 didn't pick up nested virt. Two fixes:

1. **Update Windows + WSL** to current versions:
   ```powershell
   wsl --update
   ```
2. **Confirm BIOS settings**: VT-x / AMD-V enabled, Hyper-V allowed.

If `mvmctl doctor` still reports KVM unavailable, see the [No /dev/kvm available](/guides/troubleshooting#no-devkvm-available-cloud-vms-without-nested-virt) entry.

### Allocate WSL2 resources

WSL2 starts with a default of 50% of host RAM and all CPUs. mvm guests run inside this budget. For a comfortable dev machine:

`%USERPROFILE%\.wslconfig`:
```ini
[wsl2]
memory=12GB
processors=8
```

Then restart WSL: `wsl --shutdown` and reopen the Ubuntu shell.

## Port forwarding (Windows host ↔ mvm guest)

mvm guests inside WSL2 run on the `172.16.0.0/24` TAP bridge, which is invisible from the Windows host by default. To expose a guest service to a Windows-side browser:

1. **Forward the guest port to the WSL2 distro's loopback** with mvm's standard mechanism:
   ```bash
   mvmctl run --port-forward 8080:80 --flake .
   ```
   This binds `127.0.0.1:8080` inside the WSL2 distro to the guest's port 80.

2. **WSL2's automatic localhost forwarding** ([documented by Microsoft](https://learn.microsoft.com/en-us/windows/wsl/networking#accessing-network-applications)) makes `localhost:8080` on Windows reach the WSL2 distro's loopback. Open `http://localhost:8080` in a Windows browser and you're hitting the mvm guest.

If localhost forwarding isn't working (some corporate VPN clients break it), fall back to the WSL2 distro's IP:

```bash
hostname -I  # inside WSL2 — gives the distro's IP on the Hyper-V vmswitch
```

Then `http://<that-ip>:8080` from Windows.

## File sharing

`/mnt/c/` (and similar) inside WSL2 maps to Windows drives. **Don't put your Nix store on `/mnt/c/`** — the cross-fs perf is brutal and Nix's case-sensitivity assumptions don't hold on NTFS. Keep mvm work inside the WSL2 ext4 filesystem (e.g. `~/work/...`).

If you need to read source from a Windows directory, do it explicitly with `cp` rather than running `cargo build` against a `/mnt/c/` path.

## Future Backend Work

Two Windows paths remain plausible future work:

- WSL2 experimental backend, gated on nested KVM and `/dev/kvm`.
- Hyper-V managed Linux builder/backend VM, with its own lifecycle and trust model.

Neither path is part of the supported local platform matrix today.

Tracking issue: [Future work: Windows host support via Windows Hypervisor Platform](https://github.com/tinylabscom/mvm/issues/428).

## See also

- [Install on Windows](/install/windows)
- [Matryoshka model](/security/matryoshka) — what each isolation tier promises
- [Windows troubleshooting](/guides/windows-troubleshooting)
- [WSL2 documentation](https://learn.microsoft.com/en-us/windows/wsl/)
