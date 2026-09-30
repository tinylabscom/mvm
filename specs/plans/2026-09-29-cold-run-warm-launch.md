# Cold-run builds are explicit; warm launches stay under the SLO

Issue: tinylabscom/mvm#3887 — `mvmctl machine run --image alpine -it -- ls /`
cold-builds ~85 minutes of toolchain before launching a trivial guest,
violating the sub-300ms warm-launch gate in
`specs/plans/297-sub-300ms-warm-launch-slo.md`.

## Root causes (established by inspection)

1. **Pair cache over-invalidation.** `LocalImageCacheKey` keys every role
   except `BuilderVm` on the whole mvm checkout (HEAD + full diff + untracked
   file contents), so any edit anywhere — `crates/mvm-cli`, docs, specs, an
   untracked scratch file — rekeys `default-tenant.default`,
   `runtime-overlay.default`, and `runtime-overlay.sdk-sidecar-image-musl`
   into a full in-builder-VM Nix rebuild (the 41-minute phase).
2. **No explicit cold path.** Each of the six build phases checks its cache
   independently, deep in the launch flow, and silently escalates into
   minute-scale builds. `machine run` has no `--build`/`--cold` flag and no
   upfront "this will build" gate.
3. **`mvmctl bootstrap` does not cover the launch path.** It never warms the
   host aux helpers (`mvm-hvf-supervisor`, `mvm-network-endpoint`, built
   lazily at spawn) or the pair-stamped SDK sidecar / runtime-overlay stamps
   the boot path checks, so even a "successful" bootstrap is followed by
   cold phases 2, 4, and 5.
4. **Worktree-isolated homes start cold.** `MVM_HOME=$PWD/.mvm-test` (dev-env)
   gives every worktree an empty `local-images` cache with no seeding from the
   default home (the runtime-overlay and initramfs caches already seed; this
   one does not).

## Change plan

- [x] **S1 — Narrow the pair key for the image roles.** Extend
      `consumed_inputs` in `crates/mvm-build/src/image_source/cache/mvm_inputs.rs`
      from `BuilderVm` to `DefaultTenant`, `RootlessTenant`, `RuntimeOverlay`,
      and `Initramfs`: digest the workspace-filter allow-list tree (reusing the
      `pipeline::build_cache` workspace walk, a tested superset of what
      `nix/lib/workspace-filter.nix` admits), keep the `image.nix` read-scan with
      its conservative whole-checkout fallback, and add shipped-tree tests
      mirroring the builder ones. `Kernel` stays whole-checkout.
- [x] **S2 — Explicit cold path for `machine run`.** New
      `mvm_core::cold_build` process-wide policy (`Allow` default; `Refuse` set
      by `machine run` unless `--build` or `MVM_COLD_BUILD=auto`). Choke points:
      `ensure_pair_built` (pre-lookup miss), `aux_bin` source build,
      `acquire_runtime_overlay` source arm, `resolve_or_build_local_initramfs`
      build arm. Refusal names the cold artifact and points at
      `mvmctl bootstrap` / `--build`. Downloads are never refused.
- [x] **S3 — `mvmctl bootstrap` prewarms what the launch path checks.** Add
      host aux-helper resolution and, under a selected image checkout, the
      pair-stamped SDK sidecar and runtime-overlay installs.
- [x] **S4 — Seed `local-images` for isolated homes.** Mirror the
      runtime-overlay/initramfs seeding: a worktree-isolated `MVM_HOME` inherits
      the default home's `local-images` entries (hardlink-first) before deciding
      to build.
- [x] **S5 — Timed e2e gate.** New `@live @perf_budget` scenario in
      `features/suites/s31_launch_e2e/launch_budget.feature`: after the cold pass,
      repeated warm `machine run --image alpine -- true` claims each stay under
      `WARM_START_MAX_MS` (300ms).
- [x] **Docs + tracking.** `--build` in
      `public/src/content/docs/reference/cli-commands.md`; BDD harness sets
      `MVM_COLD_BUILD=auto` for spawned mvmctl processes
      (`crates/mvm-conformance/tests/steps/cli.rs`, `launch_e2e.rs`). SPRINT.md
      and REFACTOR-STATUS.md are retired (archived 2026-09-29) and take no
      entries.

## Validation

- `cargo test --workspace` — green except two pre-existing host-flaky tests
  that fail identically on unmodified `main` on this host under parallel
  load: `image_lineage::record_flake_build_node_creates_and_audits_a_node`
  and the `builder_vm_runtime::image_lock` lock-timing family.
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `just check::gated` — clean (Linux cross-check + BDD feature targets).

## Non-goals

- Narrowing the `Kernel` role key (kernel builds are not on the `machine run`
  hot path).
- Changing the aux-bin freshness check from mtime to content hashing.
- Gating verbs other than `machine run` (`run`/`exec`/`up` keep today's
  automatic behavior; a follow-up can extend the policy).

## Test plan

- S1: fixture-tree unit tests (narrow digest resolves; unlisted read falls
  back; shipped flake-named paths ⊆ listed inputs).
- S2: per-choke-point tests (miss + Refuse → actionable error; Allow → builds;
  warm paths never consult the gate) plus `--build` parsing in `tests/cli.rs`.
- S3: bootstrap invokes the new prewarm steps (existing test seams).
- S4: isolated `MVM_HOME` seeds from the default home; no seed when absent.
- S5: new perf-budget scenario beside the existing one.
- Full workspace test + clippy + `just check::gated` before push.
