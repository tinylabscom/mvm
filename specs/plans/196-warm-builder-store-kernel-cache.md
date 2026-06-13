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

## WS-2 — Hash-keyed kernel prebuilt outside the nix store (robust + cross-worktree)

Defense-in-depth: a content-addressed kernel artifact at
`~/.cache/mvm/kernels/<config-hash>/<arch>/vmlinux`, **outside** any nix store,
so the kernel survives a full store wipe/GC and is shared across worktrees and
machines. Key = `hash(base.nix .config + builder delta + arch + kernel-source-rev)`;
the builder-vm flake already exposes standalone `builder-kernel` /
`workload-kernel` / `kernel-configfile` outputs to derive it from.

**Open design fork (needs a call before building):** how the prebuilt kernel is
*injected* back into a build.
- (i) **Separate-file load** — keep loading `vmlinux` as a host file path
  (workload microVMs already do this) and source it from the prebuilt cache,
  bypassing the in-VM kernel derivation entirely. Cleanest, but only applies
  where the kernel is loaded separately (not the libkrun bundled-kernel path).
- (ii) **Store seed** — `nix-store --import` the prebuilt kernel closure into the
  in-VM store before the build so nix sees it as already-realised. Works
  everywhere but reintroduces a store dependency (and the closure must carry a
  valid signature or be imported with `--no-check-sigs`).

WS-1 makes the *steady-state* kernel recompile go away on its own; WS-2 is the
cross-worktree / post-wipe win. Sequence WS-2 after WS-1 lands and the fork is
decided.

- [ ] Decide injection mechanism (i) vs (ii).
- [ ] Derive + plumb the config-hash key (`nix/images/builder-vm/flake.nix`,
      `crates/mvm-backend/src/artifacts/artifact.rs` already carries a kernel hash).
- [ ] Copy-out after realise; lookup + inject before build
      (`crates/mvm-build/src/libkrun_builder.rs` `ensure_builder_vm_image` /
      `krun_context_for_image`).
- [ ] Cache-dir helper via `mvm-core::config` (never inline `$HOME`).
- [ ] Tests: key stability, hit/miss, injection roundtrip.

## Out of scope

- The egress gateway (ADR-082 owns that; explicitly not a perf lever).
- Nix-store persistence mechanics (already shipped).
- Changing the 24 GiB cap default (orthogonal; WS-1 fixes the symptom without it).
