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

**Phase 1a — eligibility decision core (DONE).** `MachineRunMode::warm_pool_size(explicit)`
returns the residency-policy size (`effective_warm_pool_size`) for *transient* and
*interactive-transient* (auto-named, throwaway), `0` for user-named/`-d` persistent
machines. Resolved + logged in `run_dispatch` so the dark-landed decision is
observable; unit-tested (`warm_pool_size_is_claim_eligible_only_for_throwaway_runs`).
Zero behavior change — nothing claims yet.

**Phase 1b — claim-call integration (design fixed; isolated commit next).**

*Investigation result — where to intercept.* Both run paths bottom out in shared
lower-layer lifecycle code: the transient path (`run_secure` → `crate::exec::run_captured`)
owns boot→run→teardown as one unit, and the interactive path (`run_interactive`
→ `persist_and_boot_machine` → `start_machine` → `up::start_persistent_oci_machine`)
delegates to the shared start. Hooking the shared lifecycle would touch every
caller. The only safe seam is the **mvm-cli orchestration layer, before the
shared start** — exactly the `up.rs:2809` pattern (`try_warm_claim` → on hit
rebind the vm-name to the standby-id and skip `backend.start`; on miss cold-boot;
then `replenish_after_launch`).

*The `-it` wrinkle.* The interactive path runs through the **managed (named-spec)**
machine lifecycle, and `console::run` attaches by the **spec name**. A warm claim
returns a *different* pre-booted VM under a **standby-id**. So `-it` cannot accept
a claim without reconciling the two — either (a) rebind the managed spec/registry
+ console-attach to the claimed standby-id, or (b) re-route interactive-transient
off the managed path onto a claim-aware transient flow. **Decision: split 1b.**

- **1b-i (transient `-- cmd`, tractable):** intercept in `run_secure` before
  `crate::exec::run_captured`: thread `MachineRunMode::warm_pool_size` in, attempt
  `try_warm_claim`; on hit, run the command against the claimed standby (reuse the
  attach-into-running path) instead of a cold `run_captured`; replenish after.
  Auto-named + throwaway, so it matches the `up.rs:2809` claim model directly.
- **1b-ii (interactive `-it`):** the managed-name ↔ standby-id reconciliation
  above. Larger; its own commit, with the console-attach + teardown + registry
  rebind covered by tests before it goes near the boot path.

**Safe to land dark** (both): empty pool → `try_warm_claim` → `None` → cold boot,
unchanged. Behavior only changes once Phase 2 fills the pool.

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
