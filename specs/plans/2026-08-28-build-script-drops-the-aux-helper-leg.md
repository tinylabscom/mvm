# Delete the per-VM aux-helper leg from `mvm-cli`'s build script

Backing: shipped-source
Validation: resolve_missing_helper_names_the_command_that_builds_it

**Status:** DELIVERED
**Date:** 2026-08-28
**Owner:** mvm

## Summary

`crates/mvm-cli/build.rs` had two legs. The first cross-compiles six binaries
for `aarch64-unknown-linux-musl` and `include_bytes!`s them into `mvmctl`; it
genuinely cannot be an ordinary cargo build, because it targets another triple
and needs zig's musl C toolchain for `ring`. The second compiled seven *host*
binaries — `mvm-network-endpoint`, `mvm-broker`, `mvm-hvf-supervisor`,
`mvm-libkrun-supervisor`, `mvm-host-agent`, `mvm-signer-helper`,
`mvm-audit-signer` — through seven sequential nested `cargo build` invocations
into a private target directory.

Every one of those seven is a plain `[[bin]]` of `mvm-hostd` that a workspace
`cargo build` already produces into `target/<profile>/`, and
`mvm_vmm::host::aux_bin::resolve` already searched there. The leg existed only
so that `cargo run -p mvm-cli` — which builds no sibling `[[bin]]`s — would
yield them. The price was a duplicate compile of `mvm-hostd`'s entire closure,
per worktree.

This deletes the leg. `just build` now depends on `just build-supervisors`, so
the documented contributor entry point still produces a complete dev setup.

## Measurements (2026-08-28, aarch64 macOS)

The build script was run directly, with cargo's environment reproduced, so its
cost is isolated from the crate compiles around it.

| Scenario | Before | After |
|---|---|---|
| Content-store hit | 1.69s | — |
| Key miss, nested helper binaries absent | **60.37s** | **0.13s** |
| Key miss, nested helper binaries present | 0.59s | 0.13s |
| Nested `cargo build` invocations on a miss | 7 | **0** |
| `cargo:rerun-if-changed` files emitted | 1013 | **648** |

Disk, same host:

| Path | Before | After |
|---|---|---|
| `…/mvm-cli-nested-target` (main checkout) | 13.6 GB | **649 MB** |
| `…/aux-helper-target` per worktree | 3.6–4.5 GB × many | **gone** |

The 60.37s figure is the one that matters: it is the whole of the leg, and it is
reached whenever the nested target directory does not already hold the binaries
— a fresh worktree, a pruned store, or a `just embed-refresh`.

The watch-set reduction is a second-order win. The key for the aux leg hashed
`mvm-hostd`'s closure, which reaches `mvm-runtime`; dropping it takes 365 files
out of both the hash and the `rerun-if-changed` set, so fewer edits re-run the
script at all.

## Why deleting beats the previous two fixes

`specs/plans/2026-08-17-embedded-binary-content-store.md` made reuse *sound* by
keying artifacts on their real dependency closure.
`specs/plans/2026-08-26-aux-helper-staleness-gate.md` then made the aux leg
*cheap* by reusing on a key miss and marking the binary so `aux_bin::resolve`
would refuse to spawn it.

Both were correct given the premise that the build script must produce these
binaries. The premise was wrong. Once cargo owns them:

- There is no key to miss, so no reuse decision and no 60s fallback.
- There is no `.mvm-stale` marker, no `MVM_ALLOW_STALE_AUX` escape hatch, and no
  spawn-time refusal — staleness is not representable, rather than detected.
  That is strictly stronger than the gate it replaces.
- The "two `mvm-network-endpoint` binaries from different commits under one
  target dir" symptom recorded in
  `specs/plans/2026-08-15-aux-helper-binary-freshness.md` §2 cannot recur:
  there is one binary, and cargo rebuilds it when its sources change.

## What changed

- [x] Delete `build_native_aux_helpers`, `run_cargo_native_build`,
      `libkrun_header_present`, `stale_marker_path`, `write_stale_marker` and
      `clear_stale_marker` from `crates/mvm-cli/build.rs` (196 lines).
- [x] Drop the `cargo:rustc-env=MVM_AUX_BIN_DIR` bake-in and the
      `aux_bin_dir_to_apply` bridge in `crates/mvm-cli/src/commands/mod.rs`.
      `MVM_AUX_BIN_DIR` survives as a pure runtime directory override.
- [x] Delete `refuse_if_stale`, `stale_marker_for`, `stale_reuse_allowed` and
      `Lookup::allow_stale` from `crates/mvm-vmm/src/host/aux_bin.rs`; the
      not-found error now names `cargo build --bins`.
- [x] Replace `crates/mvm-cli/build_aux_helpers.rs` with `build_support.rs`,
      holding only what the musl leg still needs (`extract_quoted_after`,
      `shared_nested_target_dir`). `PER_VM_HOST_BINARIES` stays — it is the
      registry `xtask check-per-vm-host-binaries-sync` checks against
      `release.yml`, and only the build-time *consumer* of its `scope` field is
      gone.
- [x] `just build-supervisors` builds `-p mvm-hostd --bins` and probes for
      `libkrun.h` before the `--features libkrun-sys` invocation, so it no
      longer fails on a host without libkrun. `just build` depends on it.
- [x] `just embed-refresh` clears only `host-vm-target`; `aux-helper-target` no
      longer exists.
- [x] `scripts/e2e-launch-modes.sh` reads the supervisor from
      `target/debug/`, and its `MVM_EMBED_NO_CACHE` note describes the musl leg
      rather than the deleted stale-marker mechanics.

## Resolved elsewhere

- Closes the open `MVM_LIBKRUN_HEADER` item in
  `specs/plans/2026-08-17-embedded-binary-content-store.md` §"Open work": the
  variable was read by `libkrun_header_present` with no
  `rerun-if-env-changed`, so changing it did not re-select the helper set. The
  probe is deleted, so the hazard is gone rather than papered over.
- Retires `specs/plans/2026-08-26-aux-helper-staleness-gate.md` in full.
- Moots §2 of `specs/plans/2026-08-15-aux-helper-binary-freshness.md` (the
  build script's watch-list holes). §1 (two divergent resolvers) and §3 (the
  non-sparse `pack_stage0_work_disk` write) are untouched and still stand.

## Deliberately not done

- **Gating the musl leg off for dev builds was planned and then dropped on the
  measurement.** With the aux leg gone the whole script costs 0.13s on an
  inner-loop miss, because the musl leg's dev path is a reuse-and-copy of six
  binaries totalling ~5 MB. Making it opt-in would save that 0.13s and, in
  exchange, hand contributors an `mvmctl` that cannot boot a builder VM until
  they run `just embed-refresh` — a worse default for a tool whose job is
  booting VMs. The leg's real cost (~163s) is only paid on a cold store, under
  `MVM_EMBED_NO_CACHE`, or under `--release`, all of which want the rebuild.
- `resolve_network_endpoint_path` in `crates/mvm-build/src/libkrun_builder.rs`
  is still a second resolver that reimplements `aux_bin::resolve`. It does not
  reference the deleted target dir, so it keeps working; collapsing the two
  remains §1 of the freshness plan.
- An earlier revision of this plan claimed the `~/.cache/mvm/embed` store was
  "17 GB against its 4 GiB `DEFAULT_MAX_BYTES`, i.e. `prune` is not holding."
  **That was wrong on both numbers and on the conclusion**, and it is recorded
  here rather than deleted because the way it was wrong is reusable. The 17 GB
  came from `du -sh`; the figure `prune` actually sums is the apparent size,
  6.11 GiB. And 4 GiB is the source default, not the effective ceiling — a
  probe in the real code path reported
  `keys=672 total=6562098608 max=68719476736 victims=0`, i.e. a 64 GiB cap set
  deliberately in this host's *global* `~/.cargo/config.toml` `[env]` table.
  Cargo's `[env]` injects into build scripts without appearing in `env`, so
  `env | grep MVM_EMBED` came back empty and read as "no override". `prune`
  works correctly and the store sits at ~10% of its configured cap.
