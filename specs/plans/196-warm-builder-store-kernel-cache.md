# Plan 196 — Warm builder /nix store + hash-keyed kernel prebuilt

**Goal:** stop cold builder-VM bring-up from recompiling the guest/workload
kernel and re-downloading the ~600 MiB base closure. This is where bring-up
time actually lives — not the egress gateway (ADR-082 §"Explicitly not a
performance decision").

## Root cause (confirmed)

The builder VM's persistent `/nix` store (`~/.cache/mvm/builder-vm/nix-store-<arch>.img`)
runs a post-build cap-triggered GC: when the store exceeds 24 GiB
(`DEFAULT_BUILDER_STORE_GC_GIB`), the build script runs
`nix-collect-garbage --delete-older-than 14d`
(`crates/mvm-build/src/builder_vm_runtime.rs` `render_flake_cmd_sh`, ~L485).

`--delete-older-than 14d` only bounds which *profile generations* are removed.
It does **not** spare a store path that has no GC root. After a build, the
kernel binary and the nixpkgs base closure are reachable only through the
build's transient `result` root; once the cap fires, the sweep treats them as
garbage. The *next* cold build then recompiles the kernel (3–10 min) and
re-pulls the base closure (~600 MiB). Builds stay warm only until the store
first crosses 24 GiB.

Nix-store *persistence itself already exists and works* (persistent ext4
virtio-blk image, lazy format, overlay mount, seeded DB, auto-GC) — the gap is
the GC discarding the warm kernel/base, plus the absence of any kernel cache
that survives a store wipe.

## WS-1 — Warm gcroot for the latest build closure (the surgical fix)

Pin the just-built closure as a **fixed-name** GC root so the cap-triggered GC
spares the kernel binary + runtime base it contains. A fixed name
(`/nix/var/nix/gcroots/mvm-warm-latest`, overwritten every build) keeps only the
*latest* closure warm, so the store stays bounded while an unchanged kernel
derivation becomes a store hit instead of a recompile.

- [x] In `render_flake_cmd_sh`, after `$NIX_OUT` is captured and written to
      `/job/store-path`, register `/nix/var/nix/gcroots/mvm-warm-latest` →
      `$NIX_OUT` (symlink under `gcroots/` is a valid root; `nix-store --add-root`
      idiom with an `ln -sfn` fallback for robustness). Best-effort, never fails
      the build.
- [x] Comment explains *why* (cap-GC sweeps unrooted-but-recent paths; fixed
      name keeps the store bounded). No spec/PR refs in the comment.
- [x] Extend `render_flake_cmd_sh_embeds_gc_tail_with_default_cap` (or a sibling
      test) to assert: the warm-gcroot line is rendered, roots `$NIX_OUT`, uses
      the fixed `mvm-warm-latest` name, and is emitted *before* the GC tail.
- [x] `cargo nextest run -p mvm-build` green; `cargo fmt --all`; clippy clean.

**Verification (live, on this macOS-26 Vz box) — PENDING:** build a dev-shell image twice
crossing the 24 GiB cap (or with `MVM_BUILDER_STORE_GC_GIB` lowered to force the
GC); confirm the kernel is a store hit on the second build (no
`CC`/`LD vmlinux` lines in `~/.cache/mvm/builder-vm/jobs/<id>/nix-stderr.log`).

## WS-2 — Hash-keyed kernel prebuilt outside the nix store — DESCOPED (redundant)

**Original idea:** a content-addressed kernel artifact at
`~/.cache/mvm/kernels/<config-hash>/<arch>/vmlinux` outside any nix store, so the
kernel survives a store wipe/GC and is shared across worktrees.

**Why descoped — it duplicates caching that already exists.** Tracing the loader:

- **Builder-VM kernel** is *already* a host-file prebuilt. `ensure_builder_vm_image`
  (`crates/mvm-build/src/libkrun_builder.rs:1231`) loads `vmlinux` directly from
  `~/.cache/mvm/builder-vm/<arch>/vmlinux` — compiled once in Stage 0, cached as a
  host file, shared across worktrees (one `~/.cache/mvm`), loaded at VM launch, never
  recompiled at runtime. That cache *is* WS-2 mechanism (i) for the builder kernel.
- **Workload kernel** (realized inside the builder VM for user image builds) is
  covered by WS-1: the warm gcroot keeps it from the cap-GC, so an unchanged
  derivation is a store hit.

A separate `~/.cache/mvm/kernels/` nar cache would re-implement these. Reuse-first /
YAGNI (CLAUDE.md) says don't.

**Residual gap (only build if measured):** a *fresh or `rm -rf`-wiped* builder store
rebuilds the workload kernel once and re-pulls the base closure. If that specific
cost is shown to bite (e.g. the degraded-store recovery path,
[[reference_degraded_builder_store_dev_up_loops]]), the minimal fix is seeding a
fresh store from the artifacts already on the host — not a new kernel-nar cache.
Defer until WS-1 is live-verified and a real gap is measured.

- [x] ~~Decide injection mechanism~~ → descoped; existing caches cover both kernels.

## Out of scope

- The egress gateway (ADR-082 owns that; explicitly not a perf lever).
- Nix-store persistence mechanics (already shipped).
- Changing the 24 GiB cap default (orthogonal; WS-1 fixes the symptom without it).
