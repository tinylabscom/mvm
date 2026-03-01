# mvm Sprint 13: Boot Time Optimization

Previous sprints:
- [01-foundation.md](sprints/01-foundation.md) (complete)
- [02-production-readiness.md](sprints/02-production-readiness.md) (complete)
- [03-real-world-validation.md](sprints/03-real-world-validation.md) (complete)
- Sprint 4: Security Baseline 90% (complete)
- Sprint 5: Final Security Hardening (complete)
- [06-minimum-runtime.md](sprints/06-minimum-runtime.md) (complete)
- [07-role-profiles.md](sprints/07-role-profiles.md) (complete)
- [08-integration-lifecycle.md](sprints/08-integration-lifecycle.md) (complete)
- [09-openclaw-support.md](sprints/09-openclaw-support.md) (complete)
- [10-coordinator.md](sprints/10-coordinator.md) (complete)
- Sprint 11: Dev Environment (complete)
- [12-install-release-security.md](sprints/12-install-release-security.md) (complete)

---

## Motivation

NixOS microVMs currently take ~1m55s to boot (21s kernel + 1m33s userspace).
For a minimal Firecracker VM running an ephemeral workload, this is far too
slow — target is under 10s total. Fast boot is critical for scaling: pool
autoscaling, cold-start latency, and developer iteration speed all depend on
how quickly a microVM reaches its workload service.

## Baseline

| Metric            | Value                                |
| ----------------- | ------------------------------------ |
| Workspace crates  | 6 + root facade                      |
| Total tests       | 557                                  |
| Clippy warnings   | 0                                    |
| Boot time         | ~1m55s (21s kernel + 1m33s userspace) |
| Target boot time  | < 10s total                          |

---

## Phase 1: Fix Dependency Chain (highest impact, lowest risk)

**Status: COMPLETE**

**Expected savings: 20-40s userspace**

The primary userspace bottleneck is the `network-online.target` dependency.
Both `gateway.nix` and `worker.nix` declare `wants = [ "network-online.target" ]`,
which re-enables `systemd-networkd-wait-online.service` even though
`systemd.network.wait-online.enable = false` is set at the base guest level.
This causes systemd to poll eth0 for ~20-30s waiting for it to be "online".

### 1a. Remove `network-online.target` from OpenClaw roles

Replace `wants = [ "network-online.target" ]` with a direct dependency on
`systemd-networkd.service` in both `gateway.nix` and `worker.nix`:

```nix
# Before:
after = [ "network-online.target" "openclaw-init.service" ];
wants = [ "network-online.target" ];

# After:
after = [ "systemd-networkd.service" "openclaw-init.service" ];
wants = [ "systemd-networkd.service" ];
```

The static IP is configured by `mvm-network-config` (which runs before
`systemd-networkd`), so the interface is ready as soon as networkd starts.

**Files:** `nix/openclaw/roles/gateway.nix`, `nix/openclaw/roles/worker.nix`

### 1b. Fix optional data drive dependency in `common.nix`

Remove `mnt-data.mount` from the `openclaw-init` `after` clause. The data
drive is optional (`noauto`) and the init script already handles the
missing-drive case with `[ -b /dev/vdd ]`.

```nix
# Before:
after = [ "mnt-config.mount" "mnt-secrets.mount" "mnt-data.mount" ];

# After:
after = [ "mnt-config.mount" "mnt-secrets.mount" ];
```

**Files:** `nix/openclaw/roles/common.nix`

### Verification

- [ ] Rebuild image: `mvmctl template build openclaw`
- [ ] Boot VM and check: `mvmctl vm exec <name> -- systemd-analyze time`
- [ ] Verify networking works: `mvmctl vm ping <name>`
- [ ] Verify openclaw-gateway starts: `mvmctl vm exec <name> -- systemctl status openclaw-gateway`

---

## Phase 2: Mask Unnecessary systemd Services

**Status: COMPLETE**

**Expected savings: 5-10s userspace**

Add kernel command line parameters to mask services that are useless in
Firecracker. udevd scans for hardware — Firecracker has exactly 3 virtio
devices, so udev scanning is pure waste.

```nix
boot.kernelParams = [
  # ... existing params ...
  "systemd.mask=systemd-udevd.service"
  "systemd.mask=systemd-udevd-control.socket"
  "systemd.mask=systemd-udevd-kernel.socket"
  "systemd.mask=systemd-udev-trigger.service"
  "systemd.mask=systemd-udev-settle.service"
  "systemd.mask=systemd-random-seed.service"
  "systemd.mask=systemd-update-utmp.service"
  "random.trust_cpu=on"
  "systemd.show_status=false"
  "rd.systemd.show_status=false"
];
```

**Warning:** masking udevd means `/dev/disk/by-label/` won't exist. This is
fine — we mount by device path (`/dev/vda`, `/dev/vdb`, etc.). Masking
tmpfiles may conflict with `systemd.tmpfiles.rules` for `/mnt/data` — test
carefully before masking tmpfiles-setup.

**Files:** `nix/modules/mvm-guest.nix`

### Verification

- [ ] Rebuild and boot
- [ ] `systemd-analyze blame` shows udevd no longer in the list
- [ ] Drives still mount correctly (`/mnt/config`, `/mnt/secrets`)
- [ ] `/mnt/data` directory still exists (tmpfiles rule)

---

## Phase 3: Enable systemd Initrd

**Status: COMPLETE**

**Expected savings: 5-15s initrd/stage-1**

The default NixOS scripted initrd runs a sequential shell script. The
systemd-based initrd parallelizes device discovery and mounting.
microvm.nix uses this by default for Firecracker guests.

```nix
boot.initrd.systemd.enable = true;
boot.initrd.systemd.tpm2.enable = false;
```

**Files:** `nix/modules/mvm-guest.nix`

### Verification

- [ ] Rebuild and boot
- [ ] `systemd-analyze time` shows reduced initrd time
- [ ] Root filesystem mounts correctly
- [ ] Config/secrets drives mount correctly

---

## Phase 4: Custom Firecracker Kernel Config

**Status: COMPLETE**

**Expected savings: 10-20s kernel time**

The stock NixOS kernel probes hundreds of hardware subsystems (ACPI, USB,
SCSI, NUMA, sound, GPU) that don't exist in Firecracker. A custom kernel
config disabling these is the single biggest win for the 21s kernel time.

```nix
{ pkgs, lib, ... }:
{
  boot.kernelPatches = [{
    name = "firecracker-minimal";
    patch = null;
    structuredExtraConfig = with lib.kernel; {
      # Disable nonexistent hardware
      ACPI = no;
      NUMA = no;
      HIBERNATION = no;
      PM = no;
      CPU_FREQ = no;
      CPU_IDLE = no;
      USB_SUPPORT = no;
      SOUND = no;
      DRM = no;
      WIRELESS = no;
      BLUETOOTH = no;
      NFC = no;
      INPUT_MOUSE = no;
      INPUT_TOUCHSCREEN = no;
      HID = no;
      MEDIA_SUPPORT = no;
      HWMON = no;
      THERMAL = no;
      WATCHDOG = no;
      IOMMU_SUPPORT = no;
      PCCARD = no;

      # Disable unused filesystems
      XFS_FS = no;
      BTRFS_FS = no;
      NFS_FS = no;
      CIFS = no;

      # Disable unused network features
      BRIDGE = no;

      # Firecracker guest essentials
      KVM_GUEST = yes;
      PVH = yes;
      PARAVIRT = yes;
      HYPERVISOR_GUEST = yes;
      VIRTIO = yes;
      VIRTIO_PCI = yes;
      VIRTIO_BLK = yes;
      VIRTIO_NET = yes;
      VIRTIO_MMIO = yes;
      VIRTIO_CONSOLE = yes;
      VIRTIO_BALLOON = no;
      SERIAL_8250 = yes;
      SERIAL_8250_CONSOLE = yes;

      # Reduce kernel size
      DEBUG_INFO = no;
      KALLSYMS = no;
      KERNEL_LZ4 = yes;  # fastest decompression
    };
  }];
}
```

Additional kernel command line params:

```nix
boot.kernelParams = [
  # ... existing ...
  "noapic"            # no APIC in Firecracker
  "tsc=reliable"      # trust TSC from host CPU
  "i8042.noaux"       # skip keyboard controller probes
  "i8042.nomux"
  "i8042.nopnp"
  "i8042.nokbd"
];
```

**Note:** `pci=off` would save time but requires `VIRTIO_MMIO=y` built-in
and that Firecracker is NOT launched with `--enable-pci`. Need to verify
our Firecracker launch config first.

**Note:** This phase triggers a full kernel compilation in the Nix build,
which will take significantly longer than a normal image rebuild.

**Files:** `nix/modules/mvm-guest.nix`

### Verification

- [ ] Rebuild (expect longer build time due to kernel compile)
- [ ] `systemd-analyze time` shows reduced kernel time
- [ ] All virtio devices still work (block, net, console)
- [ ] Networking still works

---

## Phase 5: NixOS Activation Optimization

**Status: COMPLETE**

**Expected savings: 3-8s userspace**

```nix
# Replace slow Perl user-creation script with native systemd-sysusers
systemd.sysusers.enable = true;

# Volatile journal — no disk flush for ephemeral VMs
services.journald.storage = "volatile";
services.journald.extraConfig = ''
  ForwardToConsole=yes
  MaxLevelConsole=info
  RuntimeMaxUse=8M
'';

# Reduce console output overhead (serial is synchronous)
boot.consoleLogLevel = 0;
# Change loglevel from 4 to 0
```

**Files:** `nix/modules/mvm-guest.nix`

### Verification

- [ ] Rebuild and boot
- [ ] Users still created correctly (`id openclaw`)
- [ ] Journal forwarding to console still works (`mvmctl logs <name>`)
- [ ] `systemd-analyze blame` shows reduced activation time

---

## Phase 6: Rootfs & Closure Optimization (stretch)

**Status: COMPLETE**

**Expected savings: 2-5s**

Lower-priority optimizations for further iteration:

- [ ] Add `nobarrier` to ext4 root mount options (safe for ephemeral VMs)
- [ ] Remove `curl` and `jq` from `environment.systemPackages` (large closures);
      include in openclaw service `path` instead if needed
- [ ] Evaluate erofs/squashfs for read-only rootfs (microvm.nix uses erofs)
- [ ] Evaluate `system.etc.overlay.enable = true` with systemd initrd
      (replaces slow activation-script-based `/etc` population)

**Files:** `nix/modules/mvm-guest.nix`, `nix/openclaw/flake.nix`

---

## Non-goals (this sprint)

- Replacing systemd with a custom init binary (would get sub-1s but loses NixOS module system)
- Booting without initrd (currently broken in NixOS, requires patches)
- Kernel compilation from scratch (we patch the stock kernel, not replace it)
- Changes to the Lima VM or host-side tooling

## Success Criteria

- Total boot time under 10 seconds (kernel + userspace)
- `openclaw-gateway.service` or `openclaw-worker.service` starts within 15s of VM launch
- No regression in functionality (networking, mounts, guest agent all work)
- All existing tests pass, zero clippy warnings

## Expected Impact Summary

| Phase | Change | Est. Savings | Risk |
|-------|--------|-------------|------|
| 1a | Remove `network-online.target` | 20-30s | Low |
| 1b | Fix optional data drive dep | 5-10s | Low |
| 2 | Mask udevd, random-seed, utmp | 5-10s | Low |
| 3 | systemd initrd | 5-15s | Medium |
| 4 | Custom Firecracker kernel | 10-20s | Medium |
| 5 | sysusers, volatile journal, loglevel=0 | 3-8s | Low |
| 6 | Rootfs optimizations | 2-5s | Medium |

## Approach

1. Apply Phase 1 changes, rebuild, measure
2. Apply Phase 2 changes, rebuild, measure
3. Apply Phase 3 changes, rebuild, measure
4. If kernel time still >5s, apply Phase 4 (triggers full kernel rebuild)
5. Apply Phase 5 changes, rebuild, measure
6. Evaluate Phase 6 if still above target

## Verification

After each phase:
1. `mvmctl template build openclaw` — rebuild image
2. `mvmctl run --template openclaw --name boot-test` — boot VM
3. `mvmctl vm exec boot-test -- systemd-analyze time` — measure total boot
4. `mvmctl vm exec boot-test -- systemd-analyze blame` — per-unit breakdown
5. `mvmctl vm exec boot-test -- systemd-analyze critical-chain` — critical path
6. Verify functionality: networking, mounts, openclaw service, guest agent

## Backlog

Items deferred until the core mkGuest workflow is validated end-to-end:

- **Config-driven multi-variant builds**: Bring back `template.toml` support so
  `mvmctl template build --config template.toml` can build multiple variants
  (gateway, worker) in one command with per-variant resource defaults (vcpus,
  memory, data disk size). The old `mvm-profiles.toml` pointed at deleted NixOS
  modules -- the new version should map variant names to Nix flake package names
  (e.g., `gateway -> #tenant-gateway`, `worker -> #tenant-worker`).

- **`mvm-profiles.toml` redesign**: Currently the Rust build code
  (`mvm-build/src/build.rs`, `backend/host.rs`) reads `mvm-profiles.toml` to
  resolve `--profile`/`--role` flags to Nix module paths. With mkGuest, profiles
  map to flake package attributes instead of module files. Update the manifest
  format and Rust parser accordingly.

## References

- [microvm.nix optimization.nix](https://github.com/microvm-nix/microvm.nix/blob/main/nixos-modules/microvm/optimization.nix)
- [Firecracker CI kernel configs](https://github.com/firecracker-microvm/firecracker/tree/main/resources/guest_configs)
- [Minimizing Linux boot times](https://blog.davidv.dev/posts/minimizing-linux-boot-times/)
- [Kata containers boot fix](https://github.com/kata-containers/runtime/issues/1622)
- [firecracker-containerd #410](https://github.com/firecracker-microvm/firecracker-containerd/issues/410)
