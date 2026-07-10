# Plan 238 - Streamed ext4 materialization and OCI/ext4 oracles

**Status:** COMPLETE
**Created:** 2026-07-09
**Goal:** remove dense in-memory ext4 image materialization from the in-process
OCI rootfs path while preserving byte-for-byte output confidence through
streamed writers and Linux-tool validation oracles.

**Progress (2026-07-09):** `mvm-ext4` now exposes a streamed sparse-range
emission API (`emit_image[_with_options]`) that returns the final image length,
`mvm-build`'s in-process OCI/rootfs materializers now seek/write directly to
the destination file instead of first building a dense `Vec<u8>`, and both
writer-level plus OCI-boundary dense-vs-streamed differential tests are green.
Linux-tool oracle tests (`e2fsck`, `debugfs`) are implemented under
Linux-gated coverage and were executed successfully on a Debian 6.1 host,
including the corruption-rejection witness.

## Why this plan exists

`mvm` already ships a block+ext4+dm-verity rootfs posture, and the current
in-process OCI materialization path works, but it still pays a memory tax by
building dense ext4 images in memory before writing them to disk. The low-level
ext4 writer surface is also strong enough to produce the right bytes without yet
having a dedicated streamed emission seam or a robust set of independent oracles
that prove the streamed path is equivalent to the dense path.

This plan captures the next narrow improvement step: keep the shipped artifact
model, add a sparse streamed block-emission API at the ext4 layer, switch the
OCI materialization path to write directly to the destination file, and harden
the seam with Linux-tool and dense-vs-streamed differential tests.

## Non-goals

- Do not change the shipped block+ext4+dm-verity artifact model.
- Do not pivot the runtime to a directory-backed or virtiofs root filesystem.
- Do not weaken determinism or verification just to save memory.
- Do not mix unrelated builder, runtime, or network refactors into this work.

## Current state

- `mvm-ext4` can already materialize the filesystem image in-process, but the
  current integration favors dense image assembly.
- `mvm-build` can produce rootfs artifacts from OCI input, but the in-process
  path still routes through dense ext4 image materialization before writing the
  result.
- Existing tests prove substantial ext4 behavior already, but the streamed
  writer seam and OCI integration need explicit equivalence witnesses.
- Linux filesystem tools can serve as independent validation oracles, but they
  are not yet wired in as a first-class proof layer for this path.

## Design constraints

1. The final ext4 bytes emitted by the streamed path must match the accepted
   dense path for the same logical input.
2. Sparse output is allowed during construction, but the finished artifact must
   remain compatible with the existing verity and boot expectations.
3. The streamed writer API must be narrow enough to test directly without
   forcing unrelated callers to understand ext4 internals.
4. Independent Linux-tool witnesses should validate filesystem correctness in
   addition to internal byte-for-byte differential tests.

## Phase 0 - Baseline the dense path and proof points

**Goal:** record exactly what the current path guarantees before replacing it.

- [x] Identify the current dense ext4 materialization entry points in
      `mvm-ext4` and the in-process OCI call path in `mvm-build`.
- [x] Record the current test coverage and any existing determinism guarantees
      that the streamed path must preserve.
- [x] Identify the artifact boundaries where independent Linux-tool validation
      can run reliably in CI or targeted local validation.

**Validation**

- Existing ext4/materialization tests still describe the baseline behavior.
- The dense path remains the comparison oracle until the streamed path proves
  equivalence.

## Phase 1 - Add a sparse streamed ext4 emission API

**Goal:** let callers write the ext4 image directly to an output sink instead of
forcing dense whole-image assembly first.

- [x] Add a streamed block-emission API to `mvm-ext4` that can write the final
      image to an output target incrementally.
- [x] Keep the API narrow and explicit about offsets, sparse ranges, and final
      image length so callers can reason about correctness.
- [x] Preserve the existing dense path long enough to use it as a direct
      differential oracle during rollout.
- [x] Add tests proving that dense and streamed emission produce byte-identical
      final filesystem images for the same logical input.

**Validation**

- `mvm-ext4` tests cover dense-vs-streamed byte identity.
- Error-path tests prove partial or malformed writes fail with `Err`, not panic.

## Phase 2 - Switch OCI rootfs materialization to direct streamed output

**Goal:** remove the dense in-memory image from the in-process OCI materialize
path.

- [x] Thread the new streamed ext4 emission API into the `mvm-build` OCI rootfs
      materialization path.
- [x] Write the ext4 output directly to the destination file instead of building
      a full dense image in memory first.
- [x] Keep the integration boundary small so the OCI layer still reasons in
      terms of filesystem contents, not ext4 internals.
- [x] Preserve any existing metadata, sizing, and verity-preparation invariants
      that the current artifact pipeline expects.

**Validation**

- `mvm-build` tests prove the streamed OCI materialization path succeeds for the
  same fixture inputs as the dense path.
- Boundary tests cover empty, small, and multi-file OCI filesystem inputs.

## Phase 3 - Add independent OCI/ext4 validation oracles

**Goal:** prove the streamed path with tools outside the Rust implementation.

- [x] Add Linux-tool validation oracles using `e2fsck` and `debugfs` against the
      emitted ext4 image.
- [x] Add differential tests that compare dense and streamed outputs at the OCI
      materialization boundary, not only at the raw writer boundary.
- [x] Verify directory structure, file presence, and expected metadata using the
      external tools in addition to raw byte comparison where appropriate.
- [x] Keep these oracle tests scoped to the ext4/OCI seam so failures are easy
      to attribute.

**Validation**

- Oracle-backed tests pass for known-good dense and streamed outputs.
- Corrupted or intentionally wrong artifacts are rejected by the Linux-tool
  witnesses.

## Phase 4 - Remove the dense-only fallback from the in-process path

**Goal:** make the streamed path the normal in-process materialization route
once equivalence is proven.

- [x] Remove or retire the dense-only in-process OCI materialization path where
      it is no longer needed.
- [x] Keep any helper logic that remains genuinely reusable; delete only the
      memory-heavy path that has been replaced.
- [x] Re-run the full ext4/OCI differential and oracle coverage after the
      fallback removal.

**Validation**

- No in-process OCI path still requires dense whole-image buffering.
- All ext4 writer, OCI differential, and Linux-tool oracle tests stay green.

## Sequencing

1. Baseline the current dense path and proof points.
2. Add streamed ext4 emission with byte-identity tests.
3. Thread streamed output into OCI rootfs materialization.
4. Add Linux-tool oracles and OCI-boundary differential tests.
5. Remove the dense-only in-process fallback once equivalence is proven.

## Completion criteria

- `mvm-ext4` exposes a streamed emission seam suitable for direct file output.
- The in-process OCI rootfs path no longer requires dense whole-image
  materialization in memory.
- Dense-vs-streamed differential tests prove byte identity at the writer and OCI
  boundaries.
- Independent Linux-tool oracles validate the emitted ext4 artifacts.
