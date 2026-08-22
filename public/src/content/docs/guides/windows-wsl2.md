---
title: "WSL2 notes for mvm"
description: "WSL2 workload-host notes for mvm. WSL2 with nested KVM is supported for the libkrun-backed workload path."
---

This page documents the supported Windows-adjacent runtime path: run `mvm`
inside a **WSL2 distro** that exposes nested `/dev/kvm`, install libkrun in the
distro, and keep both the repo and runtime state on the WSL ext4 filesystem.
Native Windows host support is still tracked separately in
[mvm#428](https://github.com/tinylabscom/mvm/issues/428).

## Why WSL2 for mvm

WSL2 is a real Linux kernel running under Hyper-V. In this slice, mvm treats it
as a supported **libkrun-backed workload host** when the distro exposes
`/dev/kvm`. From inside a capable WSL2 distro:

- **`/dev/kvm` must be available**. When it is missing, the supported WSL2 workload path is unavailable.
- **Filesystem is real Linux ext4**. APFS-style copy-on-write isn't here yet (Sprint 47 Plan D ships APFS CoW for macOS; WSL2's ext4 will fall back to byte-copy in `mvm-runtime::vm::cow::reflink_or_copy`), but everything functionally works.
- **Networking is bridged** through Hyper-V's vmswitch. Port forwarding from Windows host to a WSL2 distro is automatic for `127.0.0.1` binds; mvm guests behind the WSL2 distro need an additional hop, covered below.

The cost is one nested VM hop: workload runs inside a microVM, inside WSL2,
inside Hyper-V on the Windows host. This is a supported **workload runtime**
shape, not a promise that native Windows or WSL2 builder/dev flows are
feature-complete.

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

### Keep the repo and state on ext4

The supported path is:

- repo/worktree under the WSL distro filesystem, for example `~/work/...`
- runtime state under the default `~/.mvm` or another ext4-backed `MVM_HOME`

Do **not** run the workload path from `/mnt/c/...` or point `MVM_HOME` at a
DrvFs mount. `mvmctl doctor` refuses that shape because it is too flaky.

### Allocate WSL2 resources

WSL2 starts with a default of 50% of host RAM and all CPUs. mvm guests run inside this budget. For a comfortable dev machine:

`%USERPROFILE%\.wslconfig`:
```ini
[wsl2]
memory=12GB
processors=8
```

Then restart WSL: `wsl --shutdown` and reopen the Ubuntu shell.

## Declared ingress (Windows host ↔ mvm guest)

mvm guests have no workload NIC. To expose a guest service to a Windows-side
browser, declare its FlowMux ingress mapping before boot:

1. **Boot a named machine that serves on port 8080**:
   ```bash
   mvmctl machine run --name my-vm --manifest . --port 8080:8080
   ```
2. **WSL2's automatic localhost forwarding** ([documented by Microsoft](https://learn.microsoft.com/en-us/windows/wsl/networking#accessing-network-applications)) makes `localhost:8080` on Windows reach the WSL2 distro's loopback. Open `http://localhost:8080` in a Windows browser and you're hitting the admitted FlowMux listener.

If localhost forwarding isn't working (some corporate VPN clients break it), fall back to the WSL2 distro's IP:

```bash
hostname -I  # inside WSL2 — gives the distro's IP on the Hyper-V vmswitch
```

Then `http://<that-ip>:8080` from Windows.

## File sharing

`/mnt/c/` (and similar) inside WSL2 maps to Windows drives. **Don't run mvm
from `/mnt/c/`** — the cross-fs perf is brutal and the runtime/socket path
shape is not part of the supported WSL2 workload surface. Keep mvm work inside
the WSL2 ext4 filesystem (e.g. `~/work/...`).

If you need to read source from a Windows directory, do it explicitly with `cp` rather than running `cargo build` against a `/mnt/c/` path.

## Live smoke

For an opt-in proof on a real WSL2 host, run:

```bash
sh scripts/run-wsl2-libkrun-smoke.sh
```

Use a **real Windows host running WSL2** for this proof, for example:

- Windows 11 with WSL2 and nested `/dev/kvm` exposed inside the distro;
- Windows Server with WSL2 enabled and the same nested-KVM shape.

Do **not** treat the following as equivalent proof for this guide:

- macOS integration layers such as OrbStack;
- plain Linux VMs that are not actually WSL2;
- Hetzner Cloud or other hosted VMs that do not expose the required nested-virt shape.

The wrapper checks that you are inside WSL2, confirms `/dev/kvm` exists, and
refuses DrvFs-backed repo/state paths. It then:

- runs the gated libkrun backend lifecycle smoke;
- scaffolds and builds a temporary HTTP preset manifest;
- proves transient `run --json --receipt`;
- boots a persistent libkrun-backed machine and waits for guest-agent reachability;
- verifies `machine exec`, `--allow-host` egress, declared FlowMux ingress, and clean stop.

## Future Backend Work

Two Windows paths remain plausible future work:

- native Windows backend/builder work, distinct from this WSL2 slice;
- Hyper-V managed Linux builder/backend VM, with its own lifecycle and trust model.

Neither path is part of the supported local platform matrix today.

Tracking issue: [Future work: Windows host support via Windows Hypervisor Platform](https://github.com/tinylabscom/mvm/issues/428).

## See also

- [Install on Windows](/install/windows)
- [Matryoshka model](/security/matryoshka) — what each isolation tier promises
- [Windows troubleshooting](/guides/windows-troubleshooting)
- [WSL2 documentation](https://learn.microsoft.com/en-us/windows/wsl/)
