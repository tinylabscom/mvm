# Plan 205 — Builder residency Step 2 (live-coupled mechanism) — Follow-up plan

**Status:** Proposed / not started (live-coupled; gated on a macOS-26 box).
**Depends on:** Step 1 (`specs/notes/plan-205-builder-residency-step1-execution.md`, merged) and Plan 204's `mvm-builderd`.

## Why this is a separate, deferred plan

Step 1 made `MVM_RESIDENCY` govern the **routing** decision (cold → ephemeral builder, warm/parked → persistent) and report builder residency in `doctor` — all pure, CI-tested, no live VM. Step 2 is the **lifecycle mechanism**: keeping a builder warm, parking it to a snapshot, reaping it on idle. Every piece here boots, snapshots, or tears down a real builder VM, so it can only be validated on a macOS-26 Apple Silicon box — the same live-gating as the Plan 118/159 standby-pool live lanes. It is tracked here so the residency story's remaining surface is explicit and grabbable, not lost.

## What Step 1 deliberately left as degrade-to-current

- `MVM_RESIDENCY=warm` does **not** auto-start a persistent builder; it only prefers/keeps one that is already active (via `persistent-builder start`). Warm's benefit today is conditional on an existing session.
- `MVM_RESIDENCY=parked` **degrades to warm** (keeps the persistent builder) — there is no builder snapshot-park yet.
- `MVM_RESIDENCY=cold` skips the persistent builder for *new* builds but does **not** tear down a builder that is already running.
- There is no builder **idle timeout** — a persistent builder stays up until explicit `dev down` / `persistent-builder stop`.

## Workstreams

### S2.1 — Builder VM snapshot-park (the `parked` mechanism)
- [ ] Wire vz saved-state (the Plan 159 snapshot path) into the persistent builder boot path so an idle persistent builder can be snapshotted to `~/.cache/mvm/builder-vm/vms/<vm>/state.vzsave` and restored on the next build instead of cold-booting.
- [ ] On `parked`: after a build (or on idle), snapshot + suspend; on the next build, detect the snapshot and restore (sub-second) rather than reusing a live VM or cold-booting.
- [ ] `parked` stops degrading-to-warm once this lands; `doctor`'s `builder residency` line reports `parked (snapshot present)` vs `parked (no snapshot)`.
- [ ] Live macOS-26 proof: a parked builder restores and serves a build via `mvm-builderd` without a cold boot.

### S2.2 — Idle-timeout keeper
- [ ] A mechanism that demotes a persistent builder after `ResidencyPolicy::idle_timeout()` of inactivity: `parked` → snapshot+suspend (S2.1), `cold` → teardown, `warm` → keep. Track last-activity on the persistent-builder session record.
- [ ] Decide the keeper shape (a check on the next `mvmctl` invocation vs. a lightweight background timer) — prefer the invocation-driven check first (no new daemon), escalate to a keeper only if needed. Pure decision function (`policy + idle_secs + now → Keep | Park | Teardown`) unit-tested; the live action gated.

### S2.3 — `dev up` / warm auto-start
- [ ] When the resolved policy is `warm` and no persistent builder is active, `dev up` (and optionally the first build) auto-starts a persistent builder so warm actually keeps one ready — the deferred auto-start noted in `persistent_builder.rs`.
- [ ] Respect explicit user lifecycle: `persistent-builder start`/`stop` always win; auto-start only fills the warm default.

### S2.4 — Active teardown on `cold`
- [ ] When the policy is `cold`, stop a running persistent builder (not just skip routing for new builds) — so `MVM_RESIDENCY=cold` truly means "no resident builder." Reuse the existing `persistent-builder stop` teardown.

## Acceptance

- `MVM_RESIDENCY=warm` keeps a builder ready and a second build reuses it with no boot (measured on a macOS-26 box).
- `MVM_RESIDENCY=parked` parks the idle builder to a snapshot and restores it sub-second on the next build.
- `MVM_RESIDENCY=cold` leaves no resident builder (existing ones are torn down) and each build is single-shot.
- `doctor` / `dev status` report the live builder residency state (warm / parked-snapshot / cold) and idle.
- No ADR-002 numbered claim regresses (the builder VM is dev-tier; snapshot/teardown changes lifecycle, not the trust boundary — same argument as ADR-090 §"Threat-model delta").

## Verification

- Pure decision functions (keeper demotion decision, snapshot-freshness) unit-tested in CI.
- Live macOS-26 lanes (gated, not required in PR CI): warm reuse, parked snapshot+restore, cold teardown.
- `cargo test --workspace`; `cargo clippy --workspace --all-targets -- -D warnings`.
