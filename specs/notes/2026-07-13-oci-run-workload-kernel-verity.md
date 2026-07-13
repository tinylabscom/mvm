# OCI-run workload kernel vs dm-verity: boot panic + infra follow-ups

**Date:** 2026-07-13
**Status:** symptom fixed (PR #1684); follow-ups 1 + 4 landed (host-side verity
guard + kernel-provenance breadcrumb, #1689 + this change), 2 mitigated, 3 open.
**Live-repro:** `mvmctl machine run --image busybox --allow-host google.com` on
macOS 26 Apple Silicon (HVF workload backend), source-checkout mvmctl.

## Symptom

Every OCI `machine run --image` boot kernel-panicked the guest **before any
userspace**, so no workload ran and no egress was possible:

```
mvm-verity-init: starting
mvm-verity-init: rootfs data=/dev/vda hash=/dev/vdb roothash=a454492c…
mvm-verity-init: overlay data=/dev/vdc hash=/dev/vdd roothash=65f196bf…
mvm-verity-init: FATAL: open /dev/mapper/control: No such file or directory
Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000100
```

## Root cause

The OCI rootfs boots **verity-sealed**: `crates/mvm-guest/src/bin/mvm-verity-init.rs`
mounts devtmpfs at `/dev`, then opens `/dev/mapper/control` to build the dm-verity
target via raw ioctls. That control node is created by the kernel's device-mapper
subsystem only when `CONFIG_BLK_DEV_DM` is built **in**.

The kernel that booted did not have it. `machine run --image` resolves the kernel
through `ensure_workload_kernel` → `resolve_workload_kernel_bootstrap`
(`crates/mvm-cli/src/commands/env/dev_vz/default_microvm.rs`), which for **non-prod**
runs returned `WorkloadKernelBootstrap::ReusableBuilder` — the **builder** kernel at
`builder-vm/<arch>/vmlinux`. The builder kernel **force-drops** `BLK_DEV_DM` +
`DM_VERITY` (`nix/images/kernel/builder.nix`; it boots `root=/dev/vda ro` with no
roothash and never opens a dm device). The workload kernel builds both `=y`
(`nix/images/kernel/workload.nix`, asserted by `base.nix`'s olddefconfig guard;
`CONFIG_MODULES=n`, all-built-in).

So: **verity-sealed rootfs + non-dm-verity (builder) kernel → panic.** The
builder-kernel reuse was a dev-speed optimization that became invalid once
workloads verity-boot by default.

## Fix shipped (PR #1684)

Removed the builder-kernel reuse entirely: a verity-booting workload always
resolves the real workload kernel (`Cached` → `BuildLocal` on a source checkout →
`Download` on a release). Deleted `WorkloadKernelBootstrap::ReusableBuilder`, its
handler, and `find_reusable_builder_kernel`; the rewritten test
`workload_kernel_never_reuses_the_non_verity_builder_kernel` asserts the builder
kernel is never returned, in dev or prod.

**Live-verified:** the guest now builds the workload kernel and **boots past verity
to a reachable agent** on HVF.

## Deeper follow-ups (the actual infra to decide/fix)

The shipped fix removes the wrong-kernel reuse, but the episode exposes structural
gaps worth addressing:

1. **No host-side kernel↔rootfs agreement check.** — **DONE (#1689).** The mismatch
   surfaced only as a guest kernel panic on the serial console; the host had zero
   signal. `assert_workload_kernel_supports_verity` now runs in the `--image` launch
   path right after kernel resolution: it reads the resolved kernel and fails fast
   with a clear host-side message when the kernel carries no device-mapper/dm-verity
   symbol at all. The check (pure `kernel_carries_dm_verity`) is conservative — only
   a *readable, marker-free* kernel trips it, so a compressed/unrecognized kernel is
   never wrongly rejected. Invariant encoded: **a verity-sealed rootfs requires a
   dm-verity kernel.**

2. **The other reuse candidate may have the same latent bug.** — **mitigated (#1689),
   root question open.** `find_cached_workload_kernel` still adds `default-microvm/dev/vmlinux`
   as a **non-prod** candidate. The #1689 launch guard now catches a non-verity
   cached-dev kernel at boot with a clear error instead of a panic, so the identical
   failure mode no longer reaches the guest. Still open: confirm the dev
   default-microvm kernel actually carries dm-verity (so the guard never fires on a
   legitimate dev run), or exclude it for verity-sealed launches.

3. **Should non-prod OCI runs verity-seal at all?** — **open (design decision).** The
   builder-kernel reuse existed because non-prod dev runs were assumed to boot
   *unsealed* (a plain rootfs on the builder kernel — fast, no kernel build). Today
   they verity-seal, so the fix now forces a workload-kernel build (3–5 min cold) on
   the first non-prod run. Decide the intended dev-tier contract: keep verity on
   non-prod (correctness, current fix) or boot non-prod unsealed (restores the
   dev-speed path, but is a larger change to rootfs materialization + the boot path).
   Whichever is chosen, kernel resolution and rootfs sealing must agree — that
   agreement is the real invariant.

4. **`mvmctl` gives no breadcrumb for kernel provenance.** — **DONE.**
   `ensure_workload_kernel` now emits one `Workload kernel: <cached|built locally|
   downloaded|reused cached (local build failed)> at <path>` line per resolution, so
   which kernel variant a run resolved is observable without a source dig.
