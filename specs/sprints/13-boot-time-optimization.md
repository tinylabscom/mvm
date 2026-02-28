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

## Investigation Areas

### 1. Kernel boot (21s)

- **Kernel size**: NixOS default kernel is huge. Consider `boot.kernelPackages = pkgs.linuxPackages_minimal` or a custom kernel config with only virtio drivers.
- **Module loading**: Even with `includeDefaultModules = false`, the initrd may pull in extras. Check `lsinitrd` output.
- **initrd size**: NixOS scripted initrd may include udev, systemd components. Measure and minimize.

### 2. Userspace boot (1m33s)

- **systemd-analyze blame**: Run inside the VM to identify the slowest services.
  ```bash
  cr vm exec swift -- systemd-analyze blame
  cr vm exec swift -- systemd-analyze critical-chain
  ```
- **Unnecessary services**: Check for services that shouldn't be running in a headless microVM (e.g., `linger-users.service`, NixOS activation scripts, `nscd`, `systemd-resolved`).
- **Mount timeouts**: Even with `noauto` on `/dev/vdd`, systemd may still wait for other mount units or device units.
- **NixOS activation**: The NixOS activation scripts (switch-to-configuration, etc.) can be slow. Consider `system.switch.enable = false` (already set) and minimizing activation scripts.

### 3. Potential optimizations

- **systemd initrd** instead of scripted: Can be faster but requires careful config.
- **Disable NixOS activation scripts**: `system.activationScripts = {}` where safe.
- **Remove unnecessary services**: `services.nscd.enable = false`, `systemd.services.linger-users.enable = false`, etc.
- **Kernel cmdline**: Add `systemd.default_timeout_start_sec=5s` to reduce mount/device wait times.
- **Pre-built initrd**: Skip stage-1 entirely if possible (Firecracker can boot directly with rootfs).
- **Profile boot**: Use `systemd-analyze plot > boot.svg` inside the VM for a visual breakdown.

## Success Criteria

- Total boot time under 10 seconds (kernel + userspace)
- `openclaw-gateway.service` or `openclaw-worker.service` starts within 15s of VM launch
- No regression in functionality (networking, mounts, guest agent all work)

## Approach

1. Profile current boot with `systemd-analyze blame` and `critical-chain`
2. Identify top 5 slowest units
3. Disable or optimize each one
4. Measure again, iterate
5. Consider kernel minimization if kernel time dominates
