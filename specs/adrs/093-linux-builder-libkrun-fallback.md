# ADR-093 — Linux builder: auto-fallback over libkrun, default unchanged

**Status:** Proposed
**Date:** 2026-06-22
**Relates to:** [ADR-002](002-microvm-security-posture.md) §"Per-backend tier
matrix", [Plan 98 — builder backend selection](../plans/98-vz-builder-vm.md),
[Plan 166 — QEMU dev builder backend](../plans/166-qemu-dev-builder-backend.md)

## Context

The builder VM — the Linux guest that runs `nix build` for `mvmctl build` /
`up` / `dev` / `machine run --image` — picks a host VMM. Plan-98 auto-detect:
macOS 26+ Apple Silicon → Vz; **everywhere else → libkrun**.

On a bare-metal Linux box (Intel i7-7700, kernel 6.1, 62 GiB RAM, libkrun
1.18.0) the libkrun builder **cannot create its VM**: libkrun's
`KVM_SET_USER_MEMORY_REGION` ioctl returns `EINVAL` (`rc -22`) for any guest
memory region spanning above ~4 GiB (the region above the PCI hole). Surfaced
via `MVM_KRUN_LOG=trace` as `Internal(Vm(SetUserMemoryRegion(Error(22))))`, and
confirmed by experiment: a 16 GiB and an 8 GiB builder VM both fail at memory
setup; a 2 GiB VM boots past it but is far too small for a `nix build` (which
peaks at 5–6 GiB). The builder fundamentally needs >4 GiB, so this is **not
tunable** — and it is a libkrun/kernel defect, not an mvm bug; mvm cannot make
that ioctl succeed.

The QEMU/microvm_nix builder (Plan 166) works on the same box — proven live: an
alpine microVM materialized via qemu and booted through Firecracker on
`/dev/kvm`.

Two tensions:

- The "Key Design Decisions" prose in `CLAUDE.md` says builds run "Firecracker
  on Linux KVM," but the dispatch (`resolve_stage0_backend` /
  `resolve_builder_backend`) only implements **libkrun / vz / qemu** —
  firecracker-as-*builder* is not wired. The real Linux default is libkrun.
- The qemu builder is documented "`mvm`-only dev/test, never `mvmd`" — so it is
  available to the *local* dev/build path but must not become the fleet
  builder.

Before this work, a Linux user on an affected host hit an opaque
`materialize OCI rootfs failed: rc -22` with no hint that `--builder qemu`
(which works) is the escape.

## Decision

1. **Keep the Plan-98 auto-detect default unchanged** — Linux still defaults to
   libkrun. We do **not** flip the Linux default to qemu.
2. **Add a transparent VMM-level auto-fallback.** When an *auto-detected* (not
   explicitly forced) builder fails to **create its VM** — a VMM-level failure,
   distinguished from a genuine build error by the new
   `BuilderVmError::SupervisorExited` variant — the dispatch retries the next
   backend. On Linux that order is libkrun → qemu; on macOS it preserves the
   pre-existing auto-Vz → libkrun behaviour. A genuine `nix build` failure
   surfaces unchanged with no retry, and an explicit `--builder` /
   `MVM_BUILDER_BACKEND` opts out entirely.

One pure policy drives every builder entry point — OCI materialize, the
`dev_build` flake path (`up --flake` / `build image` / `template build`),
Stage 0 bootstrap, and the dev-image / default-microvm CLI loops —
(`builder_attempt_order` + `run_with_builder_fallback{,_anyhow}` +
`resolve_stage0_backend_for_choice`), so the CLI loops and the `mvm-build`
build paths cannot drift. Implemented in PRs #1237 + #1239 and live-proven:
`machine run --image alpine` with no `--builder` falls back libkrun → qemu and
boots.

## Alternatives considered

### Flip the Linux default to qemu — rejected (for now)

- The evidence is a **single host**. The defect is tied to a specific
  libkrun/kernel/hardware combination and is not proven universal; libkrun may
  create its VM fine on many Linux boxes. Flipping the default would penalize
  every healthy Linux host — qemu/microvm_nix boots slower and adds a heavier
  dependency (`qemu-system-*`) where libkrun needs none.
- The fallback cost on an *affected* host is bounded: libkrun fails fast at VM
  creation (~seconds, no boot), then qemu runs. That is far cheaper than
  slowing the healthy majority.
- If future data shows libkrun-on-Linux is broadly broken rather than
  host-specific, revisit — flipping is then a one-line change to
  `auto_detect_default_for` / `builder_attempt_order`.

### Wire firecracker-as-builder now — deferred

`CLAUDE.md` names Firecracker as the intended Linux builder, but it is a fourth
`BuilderVm` implementation (its own `run_build` / `run_stage0` /
`run_shell_script`) — a separate, larger project. The qemu fallback unblocks
Linux users today; firecracker-as-builder remains the longer-term direction and
is tracked as a follow-up. Until it lands, the `CLAUDE.md` "Firecracker on Linux
KVM" builder line is corrected to describe the real default (libkrun + qemu
fallback).

## Consequences

- Linux `build` / `up` / `machine run --image` / `dev up` work out of the box
  even where libkrun cannot create its VM — no `--builder` knowledge required.
- A genuine build error still surfaces immediately (the fallback fires only on a
  VMM-level failure), and explicit `--builder` is honoured.
- The qemu builder is reached only by the **local** dev/build path, not mvmd's
  `pool_build` — staying inside its "`mvm`-only dev/test" boundary
  (ADR-002 §"Per-backend tier matrix").
- On an affected host every build pays a one-time ~5s libkrun-failure before
  qemu takes over. A per-host "libkrun builder unhealthy" cache to skip the
  doomed attempt is possible but out of scope.

## Follow-ups

- Determine whether the libkrun >4 GiB `KVM_SET_USER_MEMORY_REGION` EINVAL is
  universal-on-Linux or host-specific; feed the result back into this default
  decision.
- Implement firecracker-as-builder (the long-stated Linux intent) or keep the
  doc aligned with the libkrun + qemu-fallback reality.
- Optional: persist a per-host "libkrun-builder-unavailable" marker so affected
  hosts skip the failing libkrun attempt on subsequent builds.

## Update (2026-06-22): root cause corrected — unaligned kernel, fixed in mvm

The "`KVM_SET_USER_MEMORY_REGION` EINVAL for any region above ~4 GiB" diagnosis
above was **incomplete**. `strace -f` of the failing supervisor on the same box
showed the rejected ioctl is the **kernel** region, not a RAM region above the
PCI hole:

```
ioctl(KVM_SET_USER_MEMORY_REGION, {slot=1, guest_phys_addr=0x80000000,
      memory_size=8963072, ...}) = -1 EINVAL
```

`memory_size=8963072` is exactly the builder `vmlinux` file size, and
`8963072 % 4096 = 1024` — **not page-aligned**. Linux KVM requires
`KVM_SET_USER_MEMORY_REGION` sizes to be a multiple of the host page size; mvm
passed the kernel to libkrun (`krun_set_kernel`), which maps it verbatim, so an
unaligned `vmlinux` fails VM creation regardless of guest RAM. macOS HVF imposes
no such requirement — which is why the identical (also-unaligned) aarch64 builder
kernel boots under libkrun on macOS. So this **is** an mvm-addressable bug, not
purely a libkrun/kernel defect.

On the **"2 GiB boots past it" anomaly**: the rejected region is slot 1, the
*kernel*, whose size is the `vmlinux` file size — independent of how much guest
RAM is configured. So a smaller-RAM run must hit `EINVAL` at this *same* ioctl;
guest-RAM size cannot explain the difference. The earlier "2 GiB boots" reading
was never reproduced under `strace` and is **not** explained by this root cause —
most plausibly that run used a different, already-aligned kernel build (or never
reached slot 1 for an unrelated reason). We record it as an unexplained prior
observation rather than attribute a mechanism we can't substantiate; the
strace-confirmed alignment defect above is the real, reproduced cause.

**Fix:** `mvm_build::libkrun_builder::page_aligned_kernel` zero-pads the builder
kernel up to a page boundary (a cached `vmlinux.page-aligned` sibling) before
`krun_set_kernel`. Confirmed on the box: with the unaligned kernel on disk, the
code auto-creates the aligned sibling, every `KVM_SET_USER_MEMORY_REGION`
succeeds, and `KVM_RUN` runs the vCPUs (the EINVAL is gone).

This does **not** retire the qemu fallback: it still covers other VM-creation
failures, and at least one affected host shows a *separate* later issue (the
guest userspace does not reach `cmd.sh` under libkrun — empty console, no nix
output), tracked separately. The fallback stays; this fix removes the
unaligned-kernel EINVAL as one of its triggers.
