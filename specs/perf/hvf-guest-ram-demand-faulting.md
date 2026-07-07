# HVF guest RAM demand-faulting — density design

**Status:** Design (spike-validated). Ready for implementation planning.
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

## Phase 3 — Reassess the smaller levers against real numbers

With Phase 1+2 landed, decide each with data rather than assumption:

- **Default `--memory` sizing (was #1).** Demand-faulting makes idle
  over-allocation nearly free, so lowering the default mainly risks OOM-ing
  real workloads. Expected outcome: keep a sane default, document that idle
  allocation no longer costs its size; a modest default tweak only if the
  release floor argues for it. Likely a doc + small config change, not a
  workstream.
- **Kernel sharing across VMs (was #4).** Kernel text is touched per VM, so
  at 1000 VMs a shared read-only mapping of the kernel image still saves
  real memory — but far less than Phase 1, and it is a distinct, larger
  effort. Expected outcome: spin out as its own plan/spec, not folded here.
- **Kernel slimming (was #5).** ~a few MB of Slab per guest; overlaps
  existing in-repo kernel-slimming work. Expected outcome: fold into that
  work or drop.

Phase 3 produces a written go/defer/drop decision for each, not necessarily
more code.

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

- Idle HVF VM host RSS is a small, bounded fraction of `--memory` (Phase 1),
  verified live on this host.
- Guest behavior, boot, and the zero-init guarantee are unchanged; existing
  HVF tests pass; new `GuestRam` tests pass.
- A recorded release-build density baseline (Phase 2).
- A written decision on each smaller lever (Phase 3).
