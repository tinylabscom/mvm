# Plan 250 — Linux/KVM rootfs-backed steady-state libkrun builder

**Status: P1 complete; P0/P2–P5 open.**

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

- [ ] **P0 — Reproduce + root-cause the libkrun rootfs-mode boot silence on
  Linux/KVM.** On the Hetzner KVM box, rebuild the minimal-ext4 repro plus the
  real builder image and bisect what differs from macOS: kernel format
  (`Elf`/`Raw`), `console=hvc0` enumeration for external-kernel boots under KVM,
  the root virtio-blk node. Deliverable: a green boot-to-console and a green
  trivial `nix build` under libkrun `rootfs_path` on KVM, or a determination that
  the fix belongs upstream (patch / version pin). **Highest risk; gates P2–P4.**

- [ ] **P2 — Land the ext4 share/disk transport for `run_build` on
  libkrun-Linux.** Reuse the merged Stage-0 `pack_stage0_work_disk` ext4 delivery
  for the `run_build` input/output shares; resolve the `virtio-fs: tag not found`
  attach failure and reconcile per-backend disk-slot ceilings.

- [ ] **P3 — Flip the guard off for libkrun on `LinuxNative` + attach the verity
  runtime-overlay disk.** Remove `LinuxNative` from the predicate; confirm the
  read-only runtime-overlay disk + `required_overlay` policy attach and that
  dm-verity mounts under libkrun-KVM in the builder guest.

- [ ] **P4 — Live-validate on the KVM box + un-ignore the live builder tests.**
  Convert the `#[ignore]` live libkrun/qemu builder tests into a gated live lane;
  run `mvmctl build image --builder libkrun` end-to-end on the box; prove
  read-only `/mvm/runtime`, a real user `nix build`, and a clean audit.

- [ ] **P5 — Auto-default + docs decision.** Decide whether the LinuxNative
  builder auto-default flips back to libkrun-first or stays qemu-default with
  libkrun opt-in; refresh ADR-093's status, the builder-backend runbook table,
  and the stale CLAUDE.md libkrun→qemu fallback paragraph.

## Risks / open questions

- The boot silence may be a libkrun **upstream** limitation for external-kernel +
  KVM boots — could force a libkrun patch or version pin, or keep steady-state on
  a root-dir shape.
- The macOS (HVF, tolerant) ↔ Linux (KVM, strict) asymmetry means fixes may need
  KVM-specific handling of the same artifact.
- dm-verity under libkrun-KVM in the builder guest is unproven.
- The auto-fallback libkrun→qemu on Linux was removed, so making libkrun-Linux
  work becomes the only auto path unless the user passes `--builder qemu`.
