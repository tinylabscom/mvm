# Plan 211 — Sub-second `machine run`

**Status: IN PROGRESS** (Phase 1)

## Goal

`machine run --image <ref> -it` (and `-- <cmd>`) returns a ready guest in
**well under one second** on the warm path. Today the warm-cache run is ~2.6s,
dominated by a ~1.4s cold VM boot. Sub-second requires **not cold-booting** —
claiming a pre-booted standby from the warm pool — plus trimming the host-side
tail that the removed boot then exposes.

## Measured baseline (macOS Vz, warm cache, `machine run --image alpine -it`)

| Phase | Time | Reducible by |
|---|---|---|
| Host plan synth + Ed25519 sign | ~0.28s | parallelize with claim / warm signer |
| Rootfs reflink clone + attach | ~0.15s | already near-optimal |
| **Cold VM boot** (Vz create + kernel ~0.7s + agent bind) | **~1.4s** | **claim a warm standby → ~0** |
| Console attach | ~0.4s | replace the 200ms blind sleep with a readiness poll |

Target warm budget: **~300–500ms** to shell.

## What already exists (Plan 118, merged #1170)

- `try_warm_claim` + `replenish_after_launch` are wired into the `up`/`cmd_run`
  flow (`crates/mvm-cli/src/commands/vm/up.rs:2809/2858`). A claimed standby is
  pre-booted to agent-ready, so a claim skips the entire cold boot.
- Per-backend `spawn_standby` (`vz`/`libkrun`/`firecracker`).
- `StandbyCompat` keying = kernel + fixed resources + `image_sha256`.
- Vz residency default is `always_warm()` (`mvm_core::residency`), so the
  *policy* already wants a warm pool on the deployment tier.

## The two gaps

1. **Neither `machine run` runtime path claims today.** The transient `-- cmd`
   path (`run_secure`, `exec.rs`) and the interactive `-it` path
   (`run_interactive` → managed start) both cold-boot directly. The
   `try_warm_claim` glue exists only in the legacy `up`/`cmd_run` flow
   (`up.rs:2809`), which `machine run` does not route through. Phase 1 is
   therefore an *integration* (wire the existing claim helper into the run
   paths), not a flag flip.
2. **The Vz pool is per-image.** `image_sha256` must match exactly
   (`standby_pool.rs` — "Image sha must match exactly"). A standby is tied to the
   rootfs it was captured from. libkrun standbys are image-agnostic (rootfs
   threaded at claim), so on libkrun/Linux a generic pool already serves any
   image; **Vz needs either a per-image pool or an image-agnostic restore.**

## Phases

### Phase 1 — Warm-claim eligibility for transient + interactive `machine run`  ← this PR
- Replace the hardcoded `warm_pool_size: 0` on the transient/interactive
  start configs with a **mode-aware, policy-driven** value: claim-eligible for
  *transient* and *interactive-transient* (auto-named, throwaway), `0` for a
  user-named/`-d` persistent machine (those are long-lived, not pool cattle).
- Add the `try_warm_claim` attempt (mirroring `up.rs:2809`) to the
  interactive-transient start path so `-it` can claim.
- **Safe to land dark:** with an unpopulated pool, `try_warm_claim` returns
  `None` → cold boot, unchanged. Behavior only changes once Phase 2 fills the pool.
- TDD a pure `warm_pool_size_for(mode, explicit)` eligibility helper.

### Phase 2 — Populate + keep warm (Vz Option A: per-image)
- Lazy `replenish_after_launch` for the just-run image so the **2nd+ run of a
  given image is instant**. Residency default (`always_warm`) keeps 1–2 warm.
- First run of a *new* image still cold-boots (Option A limitation).

### Phase 3 — Cut the host tail (now the bottleneck)
- Plan synth+sign: sign in parallel with the claim; avoid per-run key reload.
- Console attach: replace the 200ms blind `sleep` (`console.rs:235`) with an
  agent-readiness poll (handle the data-port bind race via a readiness signal,
  not a blind wait).

### Phase 4 — Live-verify sub-second on Vz + regression gate
- Measure warm-path time-to-shell on this Mac; add a latency assertion so the
  warm path can't silently regress past the budget.

### Phase 5 — Image-agnostic Vz restore (Option B; own plan)
- Boot a Vz standby to agent-ready with no workload rootfs, snapshot, and on
  claim attach the image rootfs + pivot — the Lambda-SnapStart pattern, on the
  Plan 175/206 snapshot substrate. Makes **first run of any image instant** on
  Vz. Large; sequenced after A proves the budget.

## Critical path
Phases 1–4 with Vz Option A → sub-second for the **repeat-run** dev loop, the
common case. Option B (Phase 5) extends it to first-run-of-any-image on Vz.
libkrun/Linux reach sub-second for any image at Phase 1–4 (image-agnostic pool).
