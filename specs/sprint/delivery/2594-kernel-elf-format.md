# 2594 — the kernel asset was a bzImage named vmlinux

## Two defects, stacked

The published `default-microvm` images carried two independent faults, and the
first hid the second:

1. `default-microvm-vmlinux-x86_64` was an x86 **bzImage**. Firecracker's
   x86_64 loader takes an uncompressed ELF and nothing else, so it failed with
   `Invalid Elf magic number` before any guest code ran.
2. The rootfs `/init` carried its `#!` at byte 1 (#2539), which panics the
   kernel with `ENOEXEC` once it is actually reached.

Investigating #2539 hit (1) first and could not reach (2) at all. That is worth
recording: a defect that stops the loader makes every defect behind it
invisible.

## Cause

`nix/images/kernel/base.nix` used `pkgs.linuxManualConfig`, which installs only
the compressed image — `bzImage` on x86_64, with no ELF anywhere in `$out`.
Measured on a real build:

```
$out contents: bzImage  System.map
```

Every consumer then copied that to a file named `vmlinux` — the name
Firecracker's loader is documented against — so the format was asserted by
filename and by nothing else. `nix/images/default-tenant/flake.nix:94` selected
it explicitly (`kernelFile = ... else "bzImage"`).

## Fix

- **`base.nix`** — `mkKernel` now runs the kernel tree's own
  `scripts/extract-vmlinux` in `postInstall` on x86_64 and asserts the result is
  ELF. The ELF is not lost, only compressed inside the bzImage.
- **`default-tenant/flake.nix`** — selects `vmlinux` on x86_64, `Image` on
  aarch64: what the loader takes, not what the build left lying around. Plus a
  build-time byte assertion so the format cannot silently drift again.
- **`assert-kernel-format.sh`** — the same check on the published artifact,
  wired into `verify-release` and into the staged-image step before upload,
  beside `assert-init-shebang.sh`.

`metricsFor` and `manifestFor` in `nix/images/kernel/flake.nix` still resolve
`bzImage`. That is deliberate and untouched: the first anchors the tiny-kernel
size claim, and the second governs the separate workload-kernel download
contract, which was not traced here.

## Evidence

Rebuilt the x86_64 workload kernel with the change:

```
$out contents: bzImage  System.map  vmlinux
vmlinux magic: 7f454c46          # ELF
```

The gate, against the real v0.17.0 assets:

```
ok: [v0.17.0 aarch64] arm64 Image (magic@56='ARMd')
::error::[v0.17.0 x86_64] not an ELF kernel (magic@0=0xffffffff...). It is a bzImage.
```

Then, booting the published v0.17.0 rootfs on KVM with the new ELF kernel and
the production cmdline (`root=/dev/vda rw init=/init console=ttyS0`):

```
[    0.266231] Run /init as init process
[    0.266816] Kernel panic - not syncing: Requested init /init failed (error -8).
```

and with **only** the leading space stripped from `/init`, nothing else changed:

```
[    0.263446] Run /init as init process
mvm-guest-netinit: ... __MVM_NETINIT_REPORT__ {...}
mvm-guest-agent: profile=Dev
mvm-guest-agent: control plane ready (1ms)
```

That is both defects isolated and confirmed on the real artifact: the kernel
fix makes the image loadable, and the shebang is the sole remaining blocker.
