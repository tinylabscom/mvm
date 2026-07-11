# Instant first-use via prepared, versioned packs + seeded builder closure

**Status:** design approved 2026-07-10
**Relation:** Plan 213 (attested fast-first-boot packs) — realizes WS-C (hardened
cache), WS-D (install/prepare UX), WS-F (fast builder path / seeded closure),
WS-J (benchmark). This note is the umbrella design; each sub-project below gets
its own spec → plan → implementation.

## Goal

Post-install, `mvmctl dev up` and `machine run` feel **instantaneous** — on par
with the sub-second dev-sandbox tools this project is measured against. The
installation phase pays the cost; the hot path pays nothing.

## Invariants

- **Builder-only closure.** The seeded Nix closure lives *only* in the builder
  VM's persistent Nix store. It is never included in, copied to, or reachable
  from a workload microVM rootfs — already enforced by
  `xtask check-guest-images-no-builder-tools`. Workload VMs boot a minimal
  materialized rootfs (the build *output*), never a build environment.
- **No hot-path cost after prepare.** After the prepare phase, first `dev up` /
  first common flake build performs zero network fetch, zero Nix substitution,
  and no builder cold-boot.
- **Never bypass verification.** Every cached pack version is signature- and
  hash-verified before it can become the active version. Rollback only ever
  activates an already-verified cached version.

## The four pieces

1. **Versioned pack cache + lifecycle facade + CLI.** The content-addressed pack
   cache keeps *multiple* versions side by side with an **active pointer**. A
   facade API over `mvm_core::pack_cache` exposes `download` / `update` /
   `rollback` / `list` / `prune`, surfaced through the `mvmctl::*` re-exports so
   the CLI, the SDK, and mvmd all drive the same operations. Covers every pack
   class (builder pack incl. the seeded closure, runtime pack, dev image). A new
   release is fetched + verified *alongside* the current version; promotion moves
   the pointer; rollback moves it back; nothing is destructively overwritten.

2. **Prepare phase + `install.sh`.** `mvmctl prepare` (and the `install.sh`
   hook, extending today's `mvmctl bootstrap` builder-image prefetch) does the
   slow work once: fetch + verify packs, import the seeded closure into the
   builder Nix store, warm the builder, and capture the warm snapshot. Opt-out
   knobs mirror the existing `MVM_SKIP_BUILDER_PREFETCH`.

3. **Seed-closure mechanism.** Content-agnostic: a NAR closure produced into the
   builder pack (`--closure` on `mvm-builder-pack-tool` + a release-pipeline step
   that exports it), carried by the pack's existing per-file hash + signature
   machinery (wiring the already-present but unused `PackOutputs.closure_hash`),
   and imported guest-side (`nix-store --import`) with a **content-keyed
   idempotency marker** so a changed closure re-imports rather than being skipped.
   Import is fail-open (an accelerator, never a hard dependency). The closure
   *contents* are policy/config — a generous common-toolchain +
   common-materialization set — never hardcoded in Rust.

4. **Benchmark harness.** A clean-box measurement proving post-prepare first
   `dev up` / common flake build hits the instant bar: zero network + zero Nix
   substitution on the hot path, boot within the warm-restore budget. The
   numeric target is tunable; the pass/fail gate is "no hot-path stall."

## Composition & build order

Piece 3 delivers value only on top of 1 + 2; piece 4 measures the whole. Build
order: **1 → 2 → 3, with 4 alongside.**

## Decomposition into sub-projects

- **SP1 — Versioned pack cache + lifecycle facade + CLI** *(this effort first)*.
  The foundation, and independently ships the `download` / `update` / `rollback`
  / `list` / `prune` surface. No seed closure yet — just multi-version cache +
  active pointer + verified promotion/rollback across pack classes, wired through
  the facade.
- **SP2 — Prepare phase + install.sh.** `mvmctl prepare`, install.sh hook, warm
  + snapshot capture. (Also cleans install.sh's dead `mvm-vz-supervisor` ref.)
- **SP3 — Seed-closure mechanism.** Producer `--closure` + release export + guest
  import + idempotency; closure-content policy decided with a size/measurement
  pass.
- **SP4 — Benchmark harness.** Instant-bar measurement, gating SP2/SP3.

## Open / deferred (decided per sub-project, not here)

- The exact seeded-closure **content set** and its **size budget** — decided in
  SP3 against SP4's measurement, not up front (avoids reintroducing the ~1 GB
  cost the builder rootfs deliberately excludes).
- The numeric **instant bar** — set in SP4.
- Warm-snapshot capture mechanics (SP2) build on the adjacent warm-start /
  hvf-snapshot work, not re-designed here.
