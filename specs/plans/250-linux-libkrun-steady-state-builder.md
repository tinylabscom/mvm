# Plan 250 — Linux/KVM rootfs-backed steady-state libkrun builder

**Status: COMPLETE.** libkrun boots + builds end-to-end on Linux/KVM —
validated `exit 0` on the KVM box (real `nix build`, closure fetched over
vsock, artifacts produced). Root cause of the boot silence was a missing
kernel config, not an upstream libkrun defect. qemu stays the Linux
auto-default; libkrun is a working explicit opt-in.

## Goal

Lift the hard guard that disables the rootfs-backed **steady-state** libkrun
builder on Linux/KVM so it runs there instead of forcing qemu — matching macOS,
where the same path already works. Today `steady_state_rootfs_builder_unavailable_reason_for(LinuxNative)`
returns "the rootfs-backed libkrun builder is not supported on Linux/KVM yet;
use the qemu builder", and the check sat on the **shared** image loader, so it
also knocked out `--builder qemu` on any KVM host.

## Background

Three builder shapes: **Stage 0** (`BuilderVmImage::RootDir`, libkrun
`krun_set_root` + bundled kernel — *produces* `vmlinux` + `rootfs.ext4`; runs on
Linux, unguarded), **steady-state** (`BuilderVmImage::Rootfs` — boots the
external kernel + ext4 block root to *consume* the image and run the user's `nix
build`), and **qemu** (a second consumer of the same `Rootfs` image).

Root cause of the guard: libkrun's rootfs-mode boot (external kernel + ext4
block root) **does not reach userspace under Linux/KVM** — a minimal repro left
the guest console at zero bytes, while the identical image boots under libkrun
on macOS (HVF). KVM external-kernel page-alignment was one fix (see ADR-093); a
residual boot silence remains and may be a libkrun upstream limitation for
external-kernel + KVM boots.

## Phases

- [x] **P1 — Rescope the guard from platform to backend.** The guard lived in
  `load_builder_vm_image_from_cache`, which `ensure_builder_vm_image()` calls for
  *every* backend, so on a KVM host (`Platform::LinuxNative` ⇒ `/dev/kvm`
  present) it failed `--builder qemu` too — with a message telling you to use
  qemu. This PR moves the check onto the single libkrun steady-state chokepoint
  (`ensure_builder_vm_image_for_libkrun()`, routed from `run_build`,
  `run_shell_script`, the persistent VM start, and the libkrun backend
  constructor); qemu and hvf load the same cached image with no guard. The
  predicate is parameterised on `Platform` so it is unit-testable off the host it
  guards. Fixes a live regression on KVM hosts.

- [x] **P0 — Reproduce + root-cause the libkrun rootfs-mode boot silence on
  Linux/KVM.** **DONE — root cause was a missing kernel config, not an upstream
  libkrun defect.** The x86 builder kernel lacked `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES`;
  libkrun on x86 advertises its virtio-mmio devices only through
  `virtio_mmio.device=` kernel-cmdline params (no device tree like aarch64, no
  PCI like vz), so the guest ignored them, the root virtio-blk never bound, and
  boot stalled at "Waiting for root device /dev/vda". Wiring a real 16550 serial
  made the stall visible. The one-line, x86-gated kernel-config fix shipped in
  #1700 and boots to console + runs `nix build` under libkrun `rootfs_path` on KVM.

- [x] **P2 — Land the ext4 share/disk transport for `run_build` on
  libkrun-Linux.** **DONE.** The steady-state builder now probes and mounts all
  its virtio-blk disks (root / `/nix` / `/work`) once the guest sees the
  cmdline devices (P0); the merged Stage-0 ext4 delivery (#1685) carries `/work`,
  so there is no virtio-fs tag dependency on this path.

- [x] **P3 — Flip the guard off for libkrun on `LinuxNative`.** **DONE (#1711).**
  Removed the `LinuxNative` availability guard, the ensure-supported chokepoint,
  and the reason constant; `--builder libkrun` is now selectable on Linux. The
  read-only runtime overlay attaches and mounts in the builder guest. (The dev
  builder image is not dm-verity-sealed, so verity is out of scope here.)

- [x] **P4 — Live-validate on the KVM box.** **DONE.** `mvmctl machine build
  --flake examples/sleeper --builder libkrun` runs end-to-end on the KVM box
  with the guard lifted: steady-state builder boots, mounts root, runs a real
  `nix build` (closure fetched over vsock), the guest halts, the host defers to
  the on-disk result (halt-fix #1708), artifacts are produced, `exit 0`.

- [x] **P5 — Auto-default + docs decision.** **DONE — kept qemu-default with
  libkrun as an explicit opt-in** (no auto-default flip; libkrun has no Linux
  mileage yet). Refreshed the stale CLAUDE.md builder-selection + auto-fallback
  paragraphs to match the code (Linux → qemu; libkrun opt-in works).

## Risks / open questions

- The boot silence may be a libkrun **upstream** limitation for external-kernel +
  KVM boots — could force a libkrun patch or version pin, or keep steady-state on
  a root-dir shape.
- The macOS (HVF, tolerant) ↔ Linux (KVM, strict) asymmetry means fixes may need
  KVM-specific handling of the same artifact.
- dm-verity under libkrun-KVM in the builder guest is unproven.
- The auto-fallback libkrun→qemu on Linux was removed, so making libkrun-Linux
  work becomes the only auto path unless the user passes `--builder qemu`.
