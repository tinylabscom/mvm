---
title: "Install mvm on Windows"
description: "Neither native Windows nor WSL2 is a supported local microVM host. Use native Linux with /dev/kvm or an Apple Silicon Mac."
---

mvm does **not** currently support native Windows as a local microVM host, and
**WSL2 is not a supported workload path either**. The supported local hosts are:

- macOS Apple Silicon.
- Native Linux with `/dev/kvm`.

mvm detects WSL2 as its own platform and refuses the libkrun workload backend
there unconditionally — `Platform::Wsl2` never resolves to libkrun regardless of
whether the distro exposes nested `/dev/kvm`. `mvmctl doctor` reports it plainly:
*"WSL2 — a workload runtime needs nested /dev/kvm; without it only `qemu`
(dev/test only, no claim-10) runs."* The `qemu` backend is dev/test only and does
**not** enforce claim-10 egress, so it is not a workload runtime. Native Windows
support remains future work, tracked in
[mvm#428](https://github.com/tinylabscom/mvm/issues/428).

For the full host/backend matrix, see [Platform support](/reference/platform-support/).

## Current Windows Guidance

Use one of these paths today:

- Run mvm on a Linux host with `/dev/kvm`.
- Run mvm on an Apple Silicon Mac.

## What about WSL2?

WSL2 is not a supported workload path, even with nested KVM exposed. You can
install `mvmctl` inside a WSL2 distro and run non-workload commands, but the
platform probe refuses libkrun there and auto-select never reaches a workload
backend, so a `machine run` has nothing to boot on. `mvmctl doctor` will tell you
so:

```bash
mvmctl doctor
```

See the [WSL2 notes](/guides/windows-wsl2) for details and caveats.

## What about native Windows microVMs?

There isn't a maintained native-Windows microVM stack we support today. Hyper-V is the likely future Windows direction, but as a **managed Linux builder/backend VM**, not as part of the libkrun path.

That future backend needs its own lifecycle, filesystem, networking, and trust model. Until it lands, native Windows remains unsupported.

Tracking issue: [Future work: Windows host support via Windows Hypervisor Platform](https://github.com/tinylabscom/mvm/issues/428).

## Troubleshooting

- **`/dev/kvm` missing inside WSL2** — expected; WSL2 is unsupported for workloads either way.
- **`mvmctl doctor` reports "no KVM available"** — use a supported Linux KVM host or Apple Silicon Mac.

See [Windows troubleshooting](/guides/windows-troubleshooting) for the full Windows-specific FAQ.
