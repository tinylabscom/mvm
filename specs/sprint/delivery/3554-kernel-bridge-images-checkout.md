# Kernel bridge: build kernels from the selected mvm-images checkout

The kernel-bridge commits were merged into `feat/kernel-variant-select` after
that branch had already squash-merged to main, so they never reached main. This
delivery re-lands them on main, reconciled with the sibling-checkout default
that landed separately in the meantime.

## What landed

- `mvmctl kernel build --source compile` resolves its flake through
  `resolve_current_source()`, the one image-source entry point every other
  image consumer uses. In order: a configured `MVM_IMAGES_DIR` (strict), the
  discovered sibling `../mvm-images`, then the in-repo `nix/images/builder-vm`
  flake. A checkout's `kernel/` flake is staged at `/work` with
  `MVM_STAGE0_FLAKE=path:/work#packages`, and variants map onto its
  `<name>-vmlinux` / `<name>-configfile` attrs. `--which rootless` exists
  only there.
- `--which workload-k8s` stays an in-repo kernel, because the image lane
  rejected in-guest network devices. A configured checkout refuses it, since
  the operator named that source. A discovered sibling falls back to the
  in-repo flake with a note, because a default must not turn a working build
  into a refusal.
- `ensure_workload_kernel` (the `machine run` resolve) honours
  `MVM_WORKLOAD_KERNEL_VARIANT` before either acquisition branch. With the
  sibling default, the local-checkout branch is now the usual contributor
  path, and it ignored the override entirely. The override only reads a
  verified cache entry. On a miss it warns and continues with the sealed
  kernel.
- Stage 0's kernel-config emit builds from the same flake base as the
  kernel, applies the vsock egress proxy env, streams stderr, and GC-roots
  the emitted config as `kernel-config`. The emit is extracted into
  `stage0-init/kernel_emit.rs` to keep `stage0-init.rs` under the
  production-line cap.
- `specs/notes/2026-09-23-fork-in-fresh-pid-ns-upstream-report.md` and the
  #3599 root-cause notes in the plan and sprint.

## What was dropped, and why

- The pair-install artifact-name fix: main already resolves pair entries
  through `CachedImageSet::contract_file`.
- The branch's own `MVM_IMAGES_DIR`-only selection: superseded by
  `resolve_current_source()`.
- The label threading through the cache branch's acquisition. On a
  `workload-k8s` miss with `MVM_KERNEL_SOURCE=download|auto`, it downloaded
  the published sealed kernel into the `workload-k8s` slot and recorded its
  digest. That produced a mislabelled entry that verified clean on every
  later boot. The override now never acquires.
- The throwaway kernel-bisect variants and their revert.

## Not changed

`--kernel-pin` and the kernel-less-template fallback in `mvmctl up` still
resolve the sealed `workload` label only.
