# Plan 198 — Host-side workload-flake build cache (skip the nix-eval round-trip on an unchanged flake)

## Status — IMPLEMENTED + box-validated (2026-06-15)

Shipped on `feat/vz-up-down-sub-second`: `crates/mvm-build/src/pipeline/build_cache.rs`
(fingerprint + record), the short-circuit in `dev_build`, and the `mkfs.ext4 -d`
drive change in `microvm.rs`. 13 unit tests; `cargo clippy` + nightly fmt clean.

Live result on the x86_64 Linux/KVM box (Firecracker v1.14.1, `examples/sleeper`):

| `up` | wall-clock | builder VM booted | cache hit |
|---|---|---|---|
| cold (no record) | 268 s | yes | no — records fingerprint |
| **warm** | **1.01 s** | **no — skipped** | **yes** |
| after a flake edit | 32 s | yes (rebuild) | no — correctly busted |

Warm `up` dropped ~30 s → **1.01 s** (builder VM + nix eval skipped entirely; the
remaining ~1 s is admit + 2 config/secrets drives + the ~70 ms firecracker boot).
The flake-edit bust validates soundness end-to-end; the workspace-source axis is
covered by `fingerprint_changes_when_workspace_source_changes`.

## Context

`mvmctl up --flake <dir>` couples two phases: **build** (produce kernel + rootfs
from the flake) and **boot** (admit the plan + start the microVM). The boot phase
is already fast — measured, not assumed. The build phase dominates `up` even when
the image is byte-for-byte unchanged from the previous run.

Measured on the x86_64 Linux/KVM box (Firecracker v1.14.1, `examples/sleeper`,
`--builder qemu --hypervisor firecracker`), warm `up` (image already built once):

| Phase | Duration |
|---|---|
| Step 1 — build leg (single-shot builder VM boot → `nix build` → **"Cache hit … discarding staged build"** → teardown) | **~29 s** |
| Step 2 — admit + bridge/TAP | ~0.2 s |
| config drive (`truncate` + `mkfs.ext4` + loop `mount`/write/`umount`) | ~0.64 s |
| secrets drive (same dance, empty `{}` for a no-secrets workload) | ~0.62 s |
| **firecracker boot → "MicroVM running"** | **~0.07 s** |

The microVM itself boots in ~70 ms. This matches Plan 139's earlier finding
("Build ≈ 126 s; VM start < 1 s; total ≈ 99 % build") — cold boot is dwarfed by
the build.

### Why a warm builder VM alone does not fix it

The expensive ~29 s is **`nix build` evaluating the whole derivation tree** inside
the builder VM — not the builder VM boot (~1.5 s of it). Even on a cache hit, nix
must evaluate to know the output path. So:

- The cache key is the **nix revision hash**, and `dev_build` only learns it by
  running nix and reading the store path (`dev_build.rs` Step 1→3:
  `nix build` → `nix build --print-out-paths` → `extract_revision_hash`).
- The host-side build-dir check (`check_cache`, Step 4) is correct but reached
  *after* the eval — so the cache hit costs a full builder-VM + nix-eval
  round-trip every time.
- On Linux/firecracker there is no persistent builder session
  (`linux_native.rs` `dev up` only preps the host), so every workload `up` boots a
  throwaway single-shot builder VM. A persistent builder (Plan 89) would shave the
  ~1.5 s boot but not the ~25 s eval.

This gap is untracked: Plan 139 deferred cold-boot work; Plan 76's "host-side warm
artifact cache" is the `up --artifact` (pre-built signed `.mvm`) path, not
`up --flake`; Plan 93 fingerprints the *builder VM image* inputs, not the
*workload flake* build.

## Goal

Make a warm `up --flake` (unchanged flake) skip the builder VM and nix entirely,
landing on the boot leg only — target **`up` ≤ ~1 s** on a cache hit, dropping
toward the ~70 ms boot floor as the secondary lever below lands.

## The fix — host-side input fingerprint → cached revision

Mirror Plan 93's `builder_vm_source_fingerprint` discipline, applied to the
workload flake build:

1. Before invoking the builder VM in `dev_build`, compute a **host-side input
   fingerprint** that captures every input the nix eval depends on:
   - the user flake directory contents (recursive, deterministic walk — same
     content-hash strategy Plan 93 uses);
   - `profile` + `BuildMode`;
   - `flake.lock` (pins nixpkgs + the `mvm` input);
   - the **in-repo `nix/` workspace** contents when a source checkout overrides
     `mvm` (`--override-input mvm path:/work/nix`) — this is what preserves the
     "a contributor editing the flake sees it on the very next `up`" invariant;
   - the `mvmctl` version (embedded host bins change per build).
2. Persist a cache record `~/.mvm/dev/build-cache/<fingerprint>.json → { revision_hash }`
   after every successful build (best-effort write, atomic temp+rename).
3. On `up`, compute the fingerprint, look up the record, and **only short-circuit
   when** the mapped `~/.mvm/dev/builds/<revision>/` still carries a complete
   artifact set (`vmlinux`/cached-builder-kernel fallback, `rootfs.ext4`, and any
   verity/runtime-overlay sidecars). Any miss → fall through to the normal builder
   VM path (which repopulates the record).

Return a `DevBuildResult { cached: true, … }` from the short-circuit identical to
the in-VM cache-hit arm, so the boot leg is unchanged.

### Correctness requirements (the footgun)

Plan 93 shipped a fingerprint bug where a missed input served a **stale image**.
Same risk class here — treat it as load-bearing:

- The fingerprint MUST cover every eval input. A missed input → a contributor's
  change is silently ignored on the next `up`. The `nix/` recursive walk + the
  `flake.lock` hash are the two that matter most; omitting either is the bug.
- **Impure builds**: when `impure_flag` is set the eval can read un-fingerprinted
  host state. The short-circuit MUST be disabled whenever the build would run
  impure, and gated behind an explicit escape (`MVM_NO_BUILD_CACHE=1`, never set
  in CI) for debugging.
- This is **not** a security hole: admission still re-verifies the rootfs SHA-256
  and binds it into the signed `ExecutionPlan` (claim 8), so a stale-but-consistent
  image boots the user's *own* prior image — a correctness footgun, not an escape.
  But it must still be correct.
- Honors the standing invariant: source-checkout builds never depend on published
  artifacts; this caches only locally-produced build dirs.

## Secondary lever — drive creation (~1.3 s)

`create_dev_config_drive` / `create_dev_secrets_drive` (`microvm.rs`) each do
`truncate` → `mkfs.ext4` → `sudo mount` (loop) → write → `umount`. Replace the
mount/write/umount dance with **populate-at-format** (`mkfs.ext4 -d <staging_dir>`,
e2fsprogs ≥ 1.43): stage the tiny files (config.json + role stub; empty
`secrets.json` + any secret files) in a host temp dir, then format directly from
it. Removes the loop-mount round-trip and the `sudo` from the hot path. Each drive
drops from ~0.6 s toward ~0.15 s.

## Tasks

- [x] Add `workload_build_fingerprint(user_flake, profile, mode, mvm_workspace)`
      in `mvm-build` (`build_cache.rs`) — deterministic walk hashing the whole
      filtered workspace tree (covers `nix/` + the buildRustPackage src +
      `flake.lock`). Unit-tested: determinism, user-flake change, workspace-source
      change, profile/mode distinction, excluded-dir invariance, and a drift guard
      binding `EXCLUDED_BASENAMES` ⊆ `workspace-filter.nix`.
- [x] Add the `~/.mvm/dev/build-cache/` record (read/write, atomic temp+rename)
      via `mvm_core::config` path helpers; path-traversal-guarded on read/write.
- [x] Wire the host-side short-circuit into `dev_build` *before* the builder VM
      dispatch, with the `rootfs.ext4` completeness re-check and the
      `MVM_NO_BUILD_CACHE` disable. Record-on-success. (Impure: the builder-VM dev
      build always runs `--impure`, but only to admit the three `path:` inputs the
      fingerprint already covers — so the cache is sound despite `--impure`, and a
      blanket impure-disable would make it never fire.)
- [x] Drive creation: `mkfs.ext4 -d` populate-at-format for config + secrets
      drives; labels + permissions preserved (firecracker runs as root, so file
      ownership matches the old `sudo tee` path).
- [x] Box validation (x86_64 KVM): cold `up` records the fingerprint; warm `up`
      short-circuits with **no builder VM in the log** at **1.01 s**; a flake edit
      busts the cache and the next `up` rebuilds (32 s). See Status table above.

## Non-goals

- Snapshot / live-memory warmstart (Plan 140 / Plan 175) — a different, faster
  tier; this plan only removes redundant *build* work.
- A persistent Linux builder VM (Plan 89) — orthogonal; helps the ~1.5 s boot, not
  the ~25 s eval.
- The `up --artifact` warm cache (Plan 76) — adjacent, different entry point.
- A host-side Nix store mirror (explicitly rejected in Plan 93 non-goals).
