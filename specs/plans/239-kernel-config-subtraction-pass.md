# Plan 239 - Next kernel-config subtraction pass

**Status:** PROPOSED
**Created:** 2026-07-09
**Goal:** make the shared microVM kernel materially smaller by removing unused
kernel features from the generated config in a measured, boot-safe way.

## Why this plan exists

`mvm` already generates its guest kernels from an upstream `defconfig` plus a
scripted delta in `nix/images/kernel/base.nix`, then resolves the final config
with `make olddefconfig`. That gives the project one reproducible kernel recipe,
but it also means every default that survives the current `scripts/config`
subtractions still ships unless it is explicitly cut.

Plan 209 established the long-term slim-kernel direction and the config-budget
idea. This plan is the next concrete subtraction pass: audit the generated
config, remove whole dead subsystems where the workload and builder paths do not
need them, and record the measured result.

## Non-goals

- Do not change the rootfs model, dm-verity posture, or backend contract.
- Do not merge builder-only and workload-only kernel requirements back together.
- Do not introduce hand-edited committed `.config` files as the source of truth.
  The source of truth remains the generated recipe under `nix/images/kernel/`.
- Do not land speculative removals. Every cut needs a direct usage audit and a
  boot or runtime witness.

## Current state

- `nix/images/kernel/base.nix` runs `make defconfig`, applies
  `scripts/config --enable/--disable`, then runs `make olddefconfig`.
- `nix/images/kernel/builder.nix` adds the builder-only delta.
- `nix/images/kernel/workload.nix` adds the workload-only delta.
- Plan 209 already calls for a config-budget gate and audit-driven subtraction,
  but it does not spell out the next concrete candidate list or the exact proof
  sequence for the next reduction pass.

## Kernel-config generation contract

The generated final config is authoritative.

For each kernel variant, the recipe is:

1. unpack the pinned Linux source,
2. run `make defconfig`,
3. apply explicit `scripts/config` enables and disables,
4. run `make olddefconfig`,
5. use the resolved `.config` for the actual build.

Any subtraction in this plan must be judged against the resolved `.config`, not
only against the source enable/disable lists.

## Phase 0 - Make the resolved config easy to inspect

**Goal:** ensure every subtraction pass starts from the actual resolved config.

- [ ] Confirm there is a first-class way to build and inspect the resolved
      configfile for both builder and workload kernels.
- [ ] If needed, add or document dedicated outputs or commands so a reviewer can
      diff the resolved config before and after a subtraction pass.
- [ ] Record the current baseline for:
      `vmlinux` size,
      compressed kernel size,
      `=y` symbol count.

**Validation**

- `nix build ./nix/images/kernel#metrics`
- `cargo run -p xtask -- check-kernel-config-budget` if already wired

## Phase 1 - Workload-first candidate audit

**Goal:** cut obvious dead weight from the workload kernel before touching the
shared base.

Audit these candidates first, because they are common distro defaults but may be
unnecessary in a sealed workload guest:

- [ ] `BPF`
- [ ] `BPF_SYSCALL`
- [ ] `PERF_EVENTS`
- [ ] `PROFILING`
- [ ] `IKCONFIG`
- [ ] `IKCONFIG_PROC`
- [ ] `CHECKPOINT_RESTORE`
- [ ] `POSIX_MQUEUE`

For each candidate:

- [ ] Trace whether the workload boot path, guest agent, runtime helpers, or
      admitted workload behavior actually uses it.
- [ ] If workload-only dead, disable it in `workload.nix`; only move a cut into
      `base.nix` if the builder kernel also provably does not need it.
- [ ] Keep a short rationale next to the disable in the Nix file explaining the
      invariant, not any plan reference.

**Validation**

- workload-kernel build still succeeds
- workload boot smoke still succeeds
- any relevant guest-agent or runtime smoke still succeeds

## Phase 2 - Compression and initramfs surface audit

**Goal:** keep only the compression and initramfs support the project actually
ships.

- [ ] Audit the enabled kernel compression formats and keep only the ones the
      built artifacts use.
- [ ] Audit the `RD_*` decompressor symbols and keep only the formats the boot
      path actually accepts.
- [ ] Audit initramfs compression choices in the same way.
- [ ] Land cuts one class at a time so failures are attributable.

**Validation**

- kernel build still succeeds for both variants
- boot smoke still succeeds for the backends that consume the kernel artifact
- measured kernel-size deltas are recorded after each accepted cut

## Phase 3 - Workload size-mode experiment

**Goal:** test whether the workload kernel should optimize for size instead of
performance.

- [ ] Build the workload kernel with `CONFIG_CC_OPTIMIZE_FOR_SIZE`.
- [ ] Compare against the current workload kernel on:
      `vmlinux` bytes,
      compressed image bytes,
      boot success,
      any obvious runtime regressions.
- [ ] Keep the size-oriented mode only if the measured win is meaningful and the
      operational behavior remains acceptable.

**Validation**

- before/after kernel metrics
- workload boot smoke
- targeted runtime smoke using the workload kernel

## Phase 4 - Shared-base subtraction pass

**Goal:** after the workload-only cuts are exhausted, reduce the common kernel
surface safely.

- [ ] Re-read the resolved builder and workload configs after Phases 1 to 3.
- [ ] Enumerate surviving `=y` subsystems that are still unjustified in
      `base.nix`.
- [ ] For each candidate, prove neither the builder path nor the workload path
      needs it before moving the cut into `base.nix`.
- [ ] Prefer disabling whole dead subsystem menus over individual leaf drivers.
- [ ] Keep builder-specific needs in `builder.nix` and workload-specific needs in
      `workload.nix`; use `base.nix` only for truly shared removals.

**Validation**

- builder kernel still boots its dev/build path
- workload kernel still boots its runtime path
- kernel metrics improve or the candidate is reverted

## Phase 5 - Budget and regression gate refresh

**Goal:** make successful shrinkage sticky.

- [ ] Update the recorded kernel budget after accepted cuts.
- [ ] Ensure the config-budget gate reflects the new baseline instead of the old
      larger one.
- [ ] If the current metrics output is too weak to justify future reviews, expand
      it enough to capture the kernel-size shape that this plan changes.

**Validation**

- `cargo run -p xtask -- check-kernel-config-budget`
- any CI lane that already enforces the gate stays green

## Sequencing

1. Expose and record the resolved config baseline.
2. Audit workload-only candidates first.
3. Audit compression and initramfs support.
4. Run the workload size-optimization experiment.
5. Do a shared-base subtraction pass only after the earlier cuts are proven.
6. Refresh the budget gate.

## Completion criteria

- The resolved config for builder and workload kernels is easy to inspect and
  diff.
- At least one measured subtraction pass lands with a smaller kernel and green
  boot witnesses.
- The accepted cuts are recorded in the kernel recipe, not in an ad hoc local
  config file.
- The config-budget gate is updated so the smaller shape becomes the new floor.
