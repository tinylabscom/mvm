# HVF guest RAM demand-faulting — density design

**Status:** Phase 1 productionized + live-verified; Phase 2 baseline measured;
Phase 3 decisions recorded (below). Follow-on: kernel-image sharing + slimming.
**Owner:** Ari
**Goal:** Make 1000 concurrent HVF microVMs feasible on a single host by
paying host memory for a guest's *working set*, not its *allocation*.

## Problem

The HVF supervisor (`mvm-hvf-supervisor`) allocates guest RAM with
`std::alloc::alloc_zeroed` over the full `ram_size`
(`crates/mvm-backend/src/hvf/kernel_boot.rs`). The zeroing touches every
page, so the entire allocation becomes resident and dirty in the host
process regardless of what the guest actually uses.

Measured (debug build, this host, macOS 26 Apple Silicon, `--image alpine`):

| Guest `--memory` | Guest actually uses | Host supervisor RSS |
|---|---|---|
| 512 MB | 19 MB | 638 MB |
| 128 MB | 19 MB | 246 MB |

Host RSS tracks the allocation ~1:1 (`vmmap` shows the guest region fully
`DIRTY`/`RESIDENT`, `SWAPPED 0`). At this rate 1000 × 512 MB VMs need
~638 GB — infeasible. The process count inside the guest (~44, of which 41
are near-free kernel threads, ~19 MB total) is a non-issue; allocation-sized
host residency is the sole density blocker.

## Spike result (validated)

Replacing `alloc_zeroed` with an untouched `mmap(MAP_ANON | MAP_PRIVATE)`
region (demand-zero) and `munmap` on teardown, then re-measuring an idle
512 MB VM:

| Config (512 MB, idle) | Host RSS | Guest resident | Guest sees |
|---|---|---|---|
| Baseline `alloc_zeroed` | 638 MB | full 512 MB | 486 MB |
| `mmap` demand-zero | **144 MB** | **~21 MB** | 486 MB |

The guest boots and runs normally (functional check: `GUEST_OK`, `free`
unchanged, `MemTotal` still 486 MB). `hv_vm_map` faults host pages lazily on
guest access; only the boot working set (kernel + initramfs copies + ~19 MB
runtime) is resident. **~494 MB saved per idle 512 MB VM.**

`MAP_ANON` pages are kernel-zeroed on first fault, so the guest never sees
stale host memory — the security property `alloc_zeroed` provided is
preserved.

Of the remaining 144 MB, ~118 MB is debug-build VMM overhead (derived from
the 128 MB VM: 246 − 128). A release supervisor should drop per-VM idle
toward ~40–50 MB → **~40–50 GB for 1000 idle VMs**, which is the point where
the target is reachable.

## Goals

1. Guest RAM residency proportional to working set, not allocation.
2. No guest-visible behavior change; zero-init guarantee preserved.
3. A trustworthy release-build density number for capacity planning.
4. A decision, backed by real numbers, on whether the smaller levers
   (default sizing, kernel sharing, kernel slimming) are worth doing.

## Non-goals

- Multi-tenant guests, or changing the one-guest-one-workload model.
- Memory overcommit policy / swap tuning (see Risks).
- Touching the libkrun / Firecracker / Vz guest-memory paths. HVF only.

## Phase 1 — Productionize demand-faulting (the keystone)

Replace the raw `alloc_zeroed` + three hand-rolled `dealloc` paths in
`kernel_boot.rs` with a single-purpose owned type:

- `GuestRam` — owns an `mmap(MAP_ANON | MAP_PRIVATE)` region, page-aligned to
  the HVF page size, sized to `ram_size`. Exposes the base pointer + length
  for `hv_vm_map` and the kernel/initramfs/DTB copies.
- `Drop` calls `munmap`, collapsing the current three free paths (success
  cleanup + two error returns) into RAII. Removes the duplicated
  error-path `dealloc` calls.
- Demand-zero is documented as load-bearing (guest must not observe host
  memory); no explicit memset (that would re-touch every page and defeat the
  change).

Constraints:
- One small, testable type; no change to `hv_vm_map` flags, cmdline, boot
  protocol, or any guest-facing surface.
- Fits existing module style; no new dependency (`libc` is already a
  workspace dep of `mvm-backend`).

Tests:
- `GuestRam::new` returns a page-aligned, non-null region of the requested
  size; rejects a zero size.
- Repeated create/destroy does not leak (bounded RSS across N iterations).
- First-read-returns-zero on a fresh region (zero-init guarantee).
- Existing HVF boot/console smoke tests still pass unchanged.
- Live residency assertion where deterministic: idle VM host RSS is a small
  fraction of `--memory` (guarded/skipped where hardware-gated).

## Phase 2 — Release baseline + measurement

Mostly measurement, one real check:

1. Confirm the *shipped/packaged* supervisor is built `--release`. If the
   release/packaging path ships a debug supervisor, that is a real fix and
   becomes part of this phase; otherwise Phase 2 is measurement only.
2. Re-run the Phase 1 measurement matrix on a release supervisor across
   `--memory` ∈ {128 M, 512 M} idle and under a light workload. Record the
   per-VM idle floor and the marginal cost per VM.
3. Publish the numbers in this doc as the density baseline the reassessment
   in Phase 3 is judged against.

### Phase 2 results (measured 2026-07-07, this host, `--image alpine` idle)

**Release-build posture (step 1): correct.** The shipped supervisor is
release-built — the release pipeline builds every per-VM host binary with
`cargo build --release` and packages `mvm-hvf-supervisor` next to `mvmctl`
so the adjacent-to-exe resolver finds it on a downloaded install. Phase 2 is
therefore measurement only; no build-path fix is owed.

**Density baseline (steps 2–3).** Release `mvm-hvf-supervisor`, idle:

| Config (512 MB unless noted) | Host supervisor RSS | phys_footprint |
|---|---|---|
| Baseline `alloc_zeroed` (prior) | 638 MB | — (region fully resident) |
| demand-zero, debug | 144 MB | — |
| demand-zero, release, 128 MB | 136 MB | — |
| demand-zero, release, 512 MB | 144 MB | **139.9 MB** |

Reading the numbers:

- **Allocation is no longer resident.** 128 MB→512 MB (a 384 MB bump) moves
  RSS only 8 MB — a ~2% slope. `vmmap` on the idle 512 MB VM confirms it:
  writable regions total 702.9 MB but only **82.2 MB written / 101.1 MB
  resident** (86% of the guest region never faults in). The Phase 1 win holds
  in release.
- **The per-VM floor is real, not RSS inflation.** phys_footprint (139.9 MB)
  ≈ RSS (144 MB), so the floor is genuine private-dirty memory, not
  shared-framework pages double-counted across processes. Release does *not*
  shave it to the ~40–50 MB the design speculated.
- **What the floor is made of.** The ~82 MB written per idle VM is the guest
  *working set*, and its largest fixed component is the kernel `Image` — a
  ~20–40 MB arm64 kernel copied into each VM's *private* guest RAM at boot —
  plus the guest's own ~19 MB runtime, page tables, and supervisor heap. The
  512 MB allocation contributes almost nothing; the loaded kernel does.

**1000-VM projection (honest).** At ~140 MB private-dirty per idle VM, 1000
idle VMs land near **~140 GB**, not the earlier optimistic ~40–50 GB. Phase 1
took the allocation off the table; the remaining floor is dominated by
per-VM *kernel-image residency*, which is exactly what the Phase 3 levers
target. Capacity still scales with real working sets, not allocations.

## Phase 3 — Reassess the smaller levers against real numbers

The Phase 2 floor (~140 MB/VM, kernel-image-dominated) reorders the levers:
guest RAM is solved, so the next real memory is the per-VM private kernel copy.

- **Default `--memory` sizing — KEEP 512 MB (doc-only change).** The default
  is `512M` (`--memory`, machine CLI). Idle 128 MB and 512 MB now cost within
  8 MB of each other, so lowering the default frees almost nothing while
  raising OOM risk for real workloads that touch their RAM. Decision: keep
  `512M`; this doc records that idle allocation no longer costs its size. No
  config change.
- **Kernel sharing across VMs — GO, as its own follow-on (promoted).** This
  was expected to be minor; the numbers say otherwise. The kernel `Image` is
  `copy_nonoverlapping`'d into each VM's private demand-zero region, so every
  guest carries its own ~20–40 MB dirty copy — the single largest movable
  slice of the ~140 MB floor. A shared read-only mapping of the kernel image
  across guests would save on the order of tens of GB at 1000 VMs. It is a
  distinct, larger effort (guest RAM layout + `hv_vm_map` of a shared region
  + boot-protocol placement) and gets its own spec — not folded here — but it
  is now the priority density lever after Phase 1, not an afterthought.
- **Kernel slimming — FOLD into existing kernel work.** Every megabyte cut
  from the kernel `Image` is a megabyte off the per-VM private copy above, so
  slimming compounds directly with (and partially substitutes for) kernel
  sharing. Fold it into the in-repo kernel-slimming effort rather than run it
  standalone; track the per-VM `Image` size as the metric.

Net: Phase 1 shipped the big win (allocation → working set). The follow-on
density work is kernel-image sharing + slimming, quantified above; default
sizing needs no change.

## Risks / caveats

- **Density is working-set-bound, not free.** A VM that touches its RAM
  faults those pages in — correct and expected. 1000-VM capacity depends on
  the sum of real working sets plus headroom, not on allocations.
- **Faulted guest pages are dirty anonymous memory** — swap-eligible but not
  droppable; swapping guest RAM out from under a running VM is catastrophic.
  Overcommit past physical RAM is out of scope here; plan capacity against
  real working sets.
- **HVF-specific.** The lazy-fault behavior of `hv_vm_map` is what makes this
  work; the other backends are untouched and out of scope.

## Success criteria

- [x] Idle HVF VM host RSS is a small, bounded fraction of `--memory` (Phase 1),
  verified live on this host — 512 MB idle: 638 MB → 144 MB, allocation not resident.
- [x] Guest behavior, boot, and the zero-init guarantee are unchanged; existing
  HVF tests pass; new `GuestRam` tests pass — `GUEST_OK`, `MemTotal 497424 kB`,
  4/4 `guest_ram` tests, clippy clean.
- [x] A recorded release-build density baseline (Phase 2) — 128/512 MB idle,
  phys_footprint 139.9 MB, ~140 GB/1000-VM projection.
- [x] A written decision on each smaller lever (Phase 3) — keep default sizing;
  promote kernel-image sharing; fold in kernel slimming.
