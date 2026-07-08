# HVF kernel image sharing

**Status:** Measured, ready for PR review
**Date:** 2026-07-07
**Issue:** #1527
**Backend:** HVF only

## Goal

Reduce idle HVF density cost by letting identical workload kernels share clean
host pages across guests. The HVF workload path is no-NIC and vsock-only; this
work does not touch networking, Vz, gvproxy, TAP, bridge, Firecracker, libkrun,
or guest IP behavior.

The target is the fixed kernel `Image` cost visible after demand-zero guest RAM:
the guest RAM allocation no longer resident-izes the full configured memory, but
the boot path still dirtied each VM's private RAM by copying the same kernel
bytes into every guest. That turns immutable kernel text and rodata into
non-shareable private pages.

## Design

The HVF supervisor now preserves the kernel file identity and passes the path to
the HVF boot code. The boot code reserves guest RAM with anonymous private
`mmap`, then maps the kernel file as `MAP_PRIVATE | MAP_FIXED` over the kernel
load subrange. The rest of guest RAM remains anonymous demand-zero memory.

This gives the desired split:

- Clean file-backed kernel pages can be shared by the host VM subsystem across
  guests that boot the same kernel file.
- Any kernel page the guest writes becomes a private COW page, preserving guest
  correctness without guest cooperation.
- The kernel BSS/effective-size tail remains anonymous zero memory rather than
  file-backed memory.

The byte-slice boot API remains for smoke tests and direct in-process callers.
Only the path-based HVF supervisor path takes the file-backed mapping.

## Safety constraints

- The mapping is HVF-only. Other backend memory paths are unchanged.
- The HVF backend remains `no_guest_nic=true` with `host_vsock_proxy=true`.
- The implementation must not add or restore Vz, gvproxy, TAP, bridge, guest
  NIC, guest IP, or Firecracker networking behavior.
- The kernel header's `image_size` is honored for placement checks, so the
  anonymous BSS tail cannot overlap the initramfs or DTB.
- The file mapping is `MAP_PRIVATE`, not shared-writable. Guest writes COW and
  never mutate the kernel artifact on disk.

## Measurement Procedure

Run this on macOS 26 Apple Silicon with the HVF backend selected. Use the same
kernel file for every guest, keep the workload/rootfs constant, and compare
before/after from adjacent commits.

1. Build the HVF supervisor and `mvmctl`.
2. Start one persistent idle VM and record its `phys_footprint`.
3. Start two or more concurrent idle VMs using the same kernel path and record
   aggregate `phys_footprint`.
4. Use `vmmap -summary <pid>` for each supervisor PID and record the private
   dirty, shared clean, and file-backed regions for the kernel image.
5. Repeat after stopping all VMs so there are no stale supervisors.

Expected result: the kernel image is no longer present as private anonymous
dirty memory in each supervisor. Total per-VM footprint still includes fixed
guest/device/process overhead; the kernel-specific proof is the `vmmap` kernel
path row showing a private COW file mapping instead of no file mapping at all.

Record one result row per measured commit with these fields: commit, kernel
bytes, VM count, aggregate `phys_footprint`, per-added-VM delta, kernel
file-mapping evidence, and notes. The pre-change row must be the anonymous-copy
baseline; the file-backed row must be the `MAP_PRIVATE` kernel-subrange build.

## Live Measurement

Measured on 2026-07-07 on macOS 26.5.1 / Apple Silicon. The measurement used the
cached builder kernel at `~/.cache/mvm/builder-vm/aarch64/vmlinux`
(17,135,624 bytes) and a temporary `/tmp` initramfs whose `/init` is the existing
static aarch64 `mvm-guest-agent` binary (1,431,552-byte cpio) so the guests stay
alive for stable sampling. Guests were diskless, NIC-free, TAP-free, bridge-free,
Vz-free, and gvproxy-free; the only virtual device beyond console was virtio-vsock
for the guest agent's listen socket. Sampling used `proc_pid_rusage`,
`ps`, and `vmmap` from the macOS host.

| Build | VM count | Aggregate `phys_footprint` | Per-added-VM delta | Kernel mapping evidence |
| --- | ---: | ---: | ---: | --- |
| Baseline `main` supervisor | 1 | 569.6 MiB | n/a | No `vmlinux` mapping in `vmmap`; writable regions resident ≈531.3 MiB |
| Baseline `main` supervisor | 2 | 1,139.2 MiB | 569.6 MiB | No `vmlinux` mapping in `vmmap`; each supervisor repeats the private RAM cost |
| File-backed feature supervisor | 1 | 40.9 MiB | n/a | `vmlinux` appears as `mapped file ... [16.3M ...] rw-/rwx SM=COW` |
| File-backed feature supervisor | 2 | 81.9 MiB | 41.0 MiB | Same private-COW `vmlinux` mapping; writable regions resident ≈4.0 MiB per supervisor |

Interpretation:

- The old path resident-ized almost the full 512 MiB guest RAM allocation per
  supervisor before boot, because it used allocator-backed zeroed memory and
  copied the kernel bytes into that private RAM.
- The new path reserves guest RAM as anonymous demand-zero memory and maps the
  kernel file over the kernel load window with `MAP_PRIVATE | MAP_FIXED`.
- The `vmmap` proof is kernel-specific: the feature build exposes the exact
  `vmlinux` path as a COW file mapping, while the baseline has no file mapping
  because the same bytes were copied into anonymous private memory.
- The remaining ≈41 MiB per running guest is fixed process/device/guest-dirtied
  overhead for this harness, not a repeated full-RAM or anonymous kernel copy.

## Current Implementation Status

The first code slice is implemented:

- HVF guest RAM allocation moved from allocator-backed zeroed memory to one
  contiguous anonymous private `mmap`, so fixed subrange replacement is safe and
  cleanup is one `munmap`.
- HVF kernel loading supports `KernelImageSource::File`, which maps the on-disk
  kernel over the guest kernel load subrange with private COW semantics.
- The supervisor no longer reads the kernel into a private byte vector before
  booting; it passes the configured kernel path to the boot code.
- Unit tests cover effective-size placement metadata, file-header loading, and
  private COW behavior without requiring HVF hardware.

The live measurement is complete. The temporary initramfs boot smoke reached
Linux userspace and the guest agent's vsock listen loop for both the baseline and
file-backed supervisors, including two concurrent HVF guests.
