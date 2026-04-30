# Sprint 13: Boot Time Optimization

## Problem

NixOS microVMs currently take ~1m55s to boot (21s kernel + 1m33s userspace).
For a minimal Firecracker VM this is far too slow — target is under 10s total.

## Observed Symptoms

```
[  115.716346] systemd[1]: Startup finished in 21.663s (kernel) + 1min 33.397s (userspace) = 1min 55.061s.
```

Key log lines suggesting investigation areas:

- `linger-users.service` runs for ~1.2s — likely harmless but unnecessary
- `systemd-networkd` warning about "potentially unpredictable interface name" (cosmetic)
- 21s kernel time suggests the kernel is too large or loading unneeded modules

## Root Cause Analysis

### Kernel time (21s)

The stock NixOS kernel is enormous and probes hundreds of hardware subsystems
(ACPI, USB, SCSI, NUMA, sound, GPU, etc.) that don't exist in Firecracker.
Each probe adds startup latency even when no hardware responds.

### Userspace time (1m33s)

The primary bottleneck is the **`network-online.target` dependency chain**.
Both `gateway.nix` and `worker.nix` declare `wants = [ "network-online.target" ]`,
which re-enables `systemd-networkd-wait-online.service` even though
`systemd.network.wait-online.enable = false` is set at the base guest level.
This causes systemd to poll eth0 for ~20-30s waiting for it to be "online".

Additional userspace overhead:
- **systemd-udevd**: scans for hardware devices (~1-6s). Firecracker has exactly
  3 virtio devices; udev scanning is pure waste.
- **Scripted initrd**: NixOS's default stage-1 runs a sequential shell script.
  A systemd-based initrd parallelizes unit activation.
- **NixOS activation scripts**: `/etc` population and user creation via Perl
  (`update-users-groups.pl`) add several seconds.
- **systemd-tmpfiles, random-seed, update-utmp**: all unnecessary in an
  ephemeral VM.
- **Mount polling for optional /dev/vdd**: `openclaw-init` waits for all three
  mount units including the optional data drive.

## Plan

### Phase 1: Fix dependency chain (highest impact, lowest risk)

**Expected savings: 20-40s userspace**

#### 1a. Remove `network-online.target` from OpenClaw roles

Replace `wants = [ "network-online.target" ]` with a direct dependency on
`systemd-networkd.service` in both `gateway.nix` and `worker.nix`:

```nix
after = [ "systemd-networkd.service" "openclaw-init.service" ];
wants = [ "systemd-networkd.service" ];
requires = [ "openclaw-init.service" ];
```

The static IP is configured by `mvm-network-config` (which runs before
`systemd-networkd`), so the interface is ready as soon as networkd starts.
No need to wait for the full "online" state.

#### 1b. Fix optional data drive dependency in `common.nix`

Remove `mnt-data.mount` from the `openclaw-init` `after` clause since the
data drive is optional (`noauto`). The init script already handles the
missing-drive case with `[ -b /dev/vdd ]`.

```nix
# Before:
after = [ "mnt-config.mount" "mnt-secrets.mount" "mnt-data.mount" ];
# After:
after = [ "mnt-config.mount" "mnt-secrets.mount" ];
```

### Phase 2: Mask unnecessary systemd services (medium impact, low risk)

**Expected savings: 5-10s userspace**

Add kernel command line parameters to mask services that are useless in
Firecracker:

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

**Warning**: masking udevd means `/dev/disk/by-label/` won't exist. This is
fine because we mount by device path (`/dev/vda`, `/dev/vdb`, etc.), not by
label. Masking tmpfiles may conflict with our `systemd.tmpfiles.rules` for
`/mnt/data` — test carefully.

### Phase 3: Enable systemd initrd (medium impact, medium risk)

**Expected savings: 5-15s initrd/stage-1**

```nix
boot.initrd.systemd.enable = true;
boot.initrd.systemd.tpm2.enable = false;
```

The systemd-based initrd parallelizes device discovery and mounting instead
of running them sequentially in a shell script. microvm.nix uses this by
default for Firecracker guests.

### Phase 4: Minimize kernel for Firecracker (high impact on kernel time)

**Expected savings: 10-20s kernel time**

Add `structuredExtraConfig` kernel patches to disable nonexistent hardware:

```nix
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
    IPV6 = no;         # if not needed

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
```

Additional kernel command line params:

```nix
boot.kernelParams = [
  # ... existing ...
  "pci=off"           # Firecracker uses MMIO, not PCI
  "nomodules"         # everything built-in, skip module loader
  "noapic"            # no APIC in Firecracker
  "tsc=reliable"      # trust TSC from host CPU
  "i8042.noaux"       # skip keyboard controller probes
  "i8042.nomux"
  "i8042.nopnp"
  "i8042.nokbd"
];
```

**Note**: `pci=off` requires `VIRTIO_MMIO=y` built into the kernel (not as
a module) and that Firecracker is NOT launched with `--enable-pci`. Default
Firecracker uses MMIO transport.

### Phase 5: NixOS activation optimization (medium impact, medium risk)

**Expected savings: 3-8s userspace**

```nix
# Replace slow Perl user-creation script with native systemd-sysusers
systemd.sysusers.enable = true;

# Volatile journal (no disk flush for ephemeral VMs)
services.journald.storage = "volatile";
services.journald.extraConfig = ''
  ForwardToConsole=yes
  MaxLevelConsole=info
  RuntimeMaxUse=8M
'';

# Reduce console output overhead (serial is synchronous)
boot.consoleLogLevel = 0;
boot.kernelParams = [ "loglevel=0" ];  # was: 4
```

### Phase 6: Rootfs optimization (low priority, higher complexity)

Consider for later iterations:
- `nobarrier` mount option for ext4 root (acceptable for ephemeral VMs)
- erofs or squashfs for read-only rootfs (microvm.nix uses erofs by default)
- Remove `curl`/`jq` from `environment.systemPackages` (large closures)
- `system.etc.overlay.enable = true` with `boot.initrd.systemd.enable = true`

## Profiling Commands

After each phase, rebuild the image and measure inside the VM:

```bash
# Boot time breakdown
mvmctl vm exec <name> -- systemd-analyze time
mvmctl vm exec <name> -- systemd-analyze blame
mvmctl vm exec <name> -- systemd-analyze critical-chain

# Visual timeline (copy out via serial or vsock)
mvmctl vm exec <name> -- systemd-analyze plot > /tmp/boot.svg
```

## Success Criteria

- Total boot time under 10 seconds (kernel + userspace)
- `openclaw-gateway.service` or `openclaw-worker.service` starts within 15s of VM launch
- No regression in functionality (networking, mounts, guest agent all work)

## Expected Impact Summary

| Phase | Change | Estimated Savings | Risk |
|-------|--------|-------------------|------|
| 1a | Remove `network-online.target` | 20-30s | Low |
| 1b | Fix optional data drive dep | 5-10s | Low |
| 2 | Mask udevd, random-seed, utmp | 5-10s | Low |
| 3 | systemd initrd | 5-15s | Medium |
| 4 | Custom Firecracker kernel | 10-20s | Medium |
| 5 | sysusers, volatile journal, loglevel=0 | 3-8s | Low |
| 6 | Rootfs optimizations | 2-5s | Medium |

Conservative estimate: 30-50s reduction (from ~115s to ~65-85s).
Optimistic estimate: 50-80s reduction (from ~115s to ~35-65s).

**To truly hit sub-10s** would require replacing NixOS's init system entirely
(custom init binary, no systemd) or booting without initrd. This is a larger
architectural change worth considering after phases 1-5 are validated.

## Approach

1. Apply Phase 1 changes, rebuild, measure
2. Apply Phase 2 changes, rebuild, measure
3. Apply Phase 3 changes, rebuild, measure
4. If kernel time still >5s, apply Phase 4 (triggers full kernel rebuild)
5. Apply Phase 5 changes, rebuild, measure
6. Evaluate whether sub-10s target requires Phase 6 or init replacement

## References

- [microvm.nix optimization.nix](https://github.com/microvm-nix/microvm.nix/blob/main/nixos-modules/microvm/optimization.nix) — how microvm.nix optimizes Firecracker boot
- [Firecracker CI kernel configs](https://github.com/firecracker-microvm/firecracker/tree/main/resources/guest_configs)
- [Minimizing Linux boot times](https://blog.davidv.dev/posts/minimizing-linux-boot-times/) — 5.94ms kernel-to-userspace with custom init
- [Kata containers boot fix](https://github.com/kata-containers/runtime/issues/1622) — masking udevd for fast boot
- [firecracker-containerd #410](https://github.com/firecracker-microvm/firecracker-containerd/issues/410) — random seed + entropy wait
- [NixOS: boot without initrd](https://discourse.nixos.org/t/how-to-boot-without-initrd/60082)
