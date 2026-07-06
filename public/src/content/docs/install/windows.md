---
title: "Install mvm on Windows"
description: "Windows is not a supported local microVM host today. WSL2 nested KVM and Hyper-V managed Linux builders are future backend work."
---

mvm does **not** currently support native Windows as a local microVM host. The supported local hosts are:

- macOS Apple Silicon.
- Native Linux with `/dev/kvm`.

WSL2 with nested KVM is a future/experimental backend candidate, not a support promise. A managed Linux builder VM on Hyper-V is also future work, tracked in [mvm#428](https://github.com/tinylabscom/mvm/issues/428).

For the full host/backend matrix, see [Platform support](/reference/platform-support/).

## Current Windows Guidance

Use one of these paths today:

- Run mvm on a Linux host with `/dev/kvm`.
- Run mvm on an Apple Silicon Mac.

## Experimental: WSL2 With Nested KVM

Some WSL2 installations expose `/dev/kvm` through nested virtualization. If present, pieces of the Linux path may work, but this is not a supported backend yet. Before treating it as usable, verify inside the WSL2 distro:

```bash
test -c /dev/kvm && test -w /dev/kvm
mvmctl doctor
```

If either check fails, use a supported host. See the [WSL2 notes](/guides/windows-wsl2) for details and caveats.

### Optional: host-side Nix (in WSL2) for power users

Skip this unless you're contributing to mvm itself or want a shared `/nix/store` between your editor and mvm. Inside the WSL2 distro:

```bash
sh <(curl -L https://nixos.org/nix/install) --daemon
. /etc/profile.d/nix.sh
```

Installing host-side Nix is optional. The normal `mvmctl build` path still treats the CLI as the host control plane and the builder VM as the image build boundary. See [Builder VM](/guides/builder-vm/).

## What about native Windows microVMs?

There isn't a maintained native-Windows microVM stack we support today. Hyper-V is the likely future Windows direction, but as a **managed Linux builder/backend VM**, not as part of the libkrun path.

That future backend needs its own lifecycle, filesystem, networking, and trust model. Until it lands, native Windows remains unsupported.

Tracking issue: [Future work: Windows host support via Windows Hypervisor Platform](https://github.com/tinylabscom/mvm/issues/428).

## Troubleshooting

- **`/dev/kvm` missing inside WSL2** — this is expected on many hosts. WSL2 nested KVM is experimental for mvm.
- **`mvmctl doctor` reports "no KVM available"** — use a supported Linux KVM host or Apple Silicon Mac.

See [Windows troubleshooting](/guides/windows-troubleshooting) for the full Windows-specific FAQ.
