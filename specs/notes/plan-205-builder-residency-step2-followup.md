# Plan 205 — Builder residency Step 2 (live-coupled mechanism) — Follow-up plan

**Status:** Complete. Explicit Vz dev-builder snapshot park/restore is wired
and CI-tested; the libkrun persistent-builder path tracks activity and honors
invocation-driven cold/idle teardown; Vz `dev down` auto-parks a live builder
when residency keeps it resident; Vz `dev status`/`dev up` apply
invocation-driven idle/cold policy against the live dev builder; and the
macOS-26 live gate passed in `/tmp/mvm-plan205-live-proof9`.
**Depends on:** Step 1 (`specs/notes/plan-205-builder-residency-step1-execution.md`, merged) and Plan 204's `mvm-builderd`.

## Why this is a separate, deferred plan

Step 1 made `MVM_RESIDENCY` govern the **routing** decision (cold → ephemeral builder, warm/parked → persistent) and report builder residency in `doctor` — all pure, CI-tested, no live VM. Step 2 is the **lifecycle mechanism**: keeping a builder warm, parking it to a snapshot, reaping it on idle. Every piece here boots, snapshots, or tears down a real builder VM, so it can only be validated on a macOS-26 Apple Silicon box — the same live-gating as the Plan 118/159 standby-pool live lanes. It is tracked here so the residency story's remaining surface is explicit and grabbable, not lost.

## What Step 1 deliberately left as degrade-to-current

- `MVM_RESIDENCY=warm` keeps and reuses an existing resident builder. On the Vz
  dev-builder path, `dev up` starts the resident dev builder when none is active
  and reuses it on the next invocation without a builder boot.
- `MVM_RESIDENCY=parked` no longer lacks a Vz builder snapshot primitive:
  `mvmctl dev park` snapshots/stops the Vz dev builder and the next `dev up`
  restores an existing `state.vzsave`; policy automation and the live timing
  proof are complete for the Vz dev-builder path.
- `MVM_RESIDENCY=cold` skips the persistent builder for *new* builds and, on the
  next build invocation, actively tears down a live libkrun `persistent-builder`
  session before falling through to the single-shot builder.
- Vz dev-builder idle automation is invocation-driven: the explicit `dev park`
  path exists, `dev down` auto-parks a running non-reset Vz dev builder, and
  `dev status` parks a running warm builder after the policy idle timeout. The
  live macOS-26 restore/timing proof passed in
  `/tmp/mvm-plan205-live-proof9`.

## Workstreams

### S2.1 — Builder VM snapshot-park (the `parked` mechanism)
- [x] Wire vz saved-state (the Plan 159 snapshot path) into the persistent builder boot path so an idle persistent builder can be snapshotted to `~/.cache/mvm/builder-vm/vms/<vm>/state.vzsave` and restored on the next build instead of cold-booting. Implemented for the stable Vz dev-builder session (`mvm-persistent-builder-vz-dev`): `mvm-build::vz_builder` sends `SAVE <state.vzsave>` over the host-only control socket, verifies the `<snapshot>.machine-id` sidecar, stops the supervisor, reloads persisted `SupervisorConfig` in `Restore` mode, respawns gvproxy, and starts a fresh supervisor.
- [x] On `parked`: after a build (or on idle), snapshot + suspend; on the next build, detect the snapshot and restore (sub-second) rather than reusing a live VM or cold-booting. Explicit operator path exists (`mvmctl dev park`; next `mvmctl dev up` restores before cold-boot fallback), and invocation-driven idle demotion is implemented in S2.2.
- [x] `dev down` auto-parks the Vz dev builder when residency keeps a persistent builder, the VM is live, and the stop is not `--reset`; `dev up` resumes only when residency still allows a resident builder, and cold/reset/cache-clear paths discard stale snapshots rather than waking an unwanted builder.
- [x] `dev status` / `dev up` apply the invocation-driven Vz dev-builder keeper:
      activity timestamps are touched on start/restore/reuse/shell, warm parks
      after `ResidencyPolicy::idle_timeout()`, parked parks any live builder,
      and cold tears down a live builder before cold boot.
- [x] `parked` stops degrading-to-warm once this lands; `doctor`'s `builder residency` line reports `parked (snapshot present)` vs `parked (no snapshot)`. `mvmctl dev status` reports `parked` when a Vz dev-builder snapshot is present; `mvmctl doctor`'s `builder residency` check now scans the builder-VM `vms/` root for Vz `state.vzsave` snapshots.
- [x] Live macOS-26 proof: a parked builder restores without a cold boot. The
      closeout runner passed with warm reuse 130 ms, parked restore P50 643 ms,
      P95 1163 ms, zero command failures, final `dev status` state `parked`,
      and live OCI `run --image docker.io/library/alpine:3.20 -- /bin/true`
      exit 0.

### S2.2 — Idle-timeout keeper
- [x] A mechanism that demotes a persistent builder after `ResidencyPolicy::idle_timeout()` of inactivity: the libkrun `persistent-builder` session record carries `last_activity_unix_secs`, build dispatch touches it before/after use, and the next build invocation applies policy. Because that path has no memory snapshot primitive, `Park` degrades to teardown. The Vz dev-builder records its own activity timestamp and `dev status` applies the same policy, parking warm builders after the idle threshold and tearing down under cold policy.
- [x] Decide the keeper shape (a check on the next `mvmctl` invocation vs. a lightweight background timer) — shipped as invocation-driven first (no new daemon). Pure decision tests cover fresh warm keep, `cold` teardown, snapshot-unavailable idle teardown, old records without `last_activity_unix_secs`, Vz warm threshold behavior, and Vz activity timestamp round-trip.

### S2.3 — `dev up` / warm auto-start
- [x] When the resolved policy is `warm` and no persistent builder is active,
      `dev up` starts the Vz dev builder so warm keeps one ready; the first
      build path remains governed by the persistent-builder routing policy.
- [x] Respect explicit user lifecycle: `persistent-builder start`/`stop` and
      explicit `dev down --reset` / cold policy win; auto-start only fills the
      warm default.

### S2.4 — Active teardown on `cold`
- [x] When the policy is `cold`, stop a running persistent builder (not just skip routing for new builds) — the libkrun `persistent-builder` session is stopped best-effort on the next build invocation before single-shot fallback, and the Vz dev-builder is stopped on `dev status` or `dev up` entry before cold boot.

## Acceptance

- `MVM_RESIDENCY=warm` keeps a builder ready and a second invocation reuses it with no boot (measured on a macOS-26 box).
- `MVM_RESIDENCY=parked` parks the idle builder to a snapshot and restores it sub-second on the next invocation.
- `MVM_RESIDENCY=cold` leaves no resident builder (existing ones are torn down) and each build is single-shot.
- `doctor` / `dev status` report the live builder residency state (warm / parked-snapshot / cold). Idle age reporting remains polish.
- No ADR-002 numbered claim regresses (the builder VM is dev-tier; snapshot/teardown changes lifecycle, not the trust boundary — same argument as ADR-090 §"Threat-model delta").

## Verification

- Pure decision functions (keeper demotion decision, snapshot-freshness) unit-tested in CI.
- Live macOS-26 lanes (gated, not required in PR CI): warm reuse, parked
  snapshot+restore, cold teardown, and OCI `run --image`. The reproducible
  capture runner is `scripts/capture-plan-205-live-gates.sh`; proof
  `/tmp/mvm-plan205-live-proof9` passed with warm reuse 130 ms, restore P50
  643 ms, restore P95 1163 ms, and zero command failures.
- `cargo test --workspace`; `cargo clippy --workspace --all-targets -- -D warnings`.

## Implemented slice — explicit Vz dev-builder park/restore

- `mvm-build::vz_builder` exposes snapshot paths, `park_persistent_vz_builder`,
  and `restore_persistent_vz_builder_from_snapshot` for the persistent Vz builder
  state dir. The implementation uses the existing Rust Vz supervisor contract:
  newline-framed `SAVE`, absolute snapshot paths, `<snapshot>.machine-id`, and
  `StartupMode::Restore`.
- `mvmctl dev park` is a Vz-only lifecycle verb. It snapshots and stops the
  running dev builder; non-Vz backends fail explicitly because libkrun/Linux-KVM
  do not have this Vz saved-state path.
- `mvmctl dev up` detects an existing Vz dev-builder snapshot and attempts
  restore before falling back to cold boot; `dev status` reports `parked` when
  the snapshot exists.
- `mvmctl dev down` now parks the Vz dev builder automatically for non-reset
  resident stops. `--reset`, rebuild, cache-clear, cold residency, and failed
  restore paths remove stale snapshot markers so the next `dev up` cold-boots
  cleanly.
- `mvmctl dev status` now enforces the Vz dev-builder keeper before reporting
  state: warm builders idle past the policy threshold are parked, parked policy
  parks a live builder, and cold policy tears it down. `dev up` applies the cold
  policy at entry so a stale live builder cannot be reused under `cold`.
- `mvmctl doctor`'s `builder residency` line reports `parked (snapshot present)`
  vs `parked (no snapshot)` under the parked policy.
- CI coverage: `cargo test -p mvm-build --features builder-vm vz_builder::tests`,
  `cargo test -p mvm-cli --features builder-vm test_dev_park`,
  `cargo test -p mvm-cli --features builder-vm dev_park_json_reports`,
  `cargo nextest run -p mvm-cli --features builder-vm -E 'test(autopark_gating)'`,
  `cargo check -p mvm-build -p mvm-cli --features builder-vm`, and
  `cargo clippy -p mvm-build -p mvm-cli --features builder-vm --all-targets -- -D warnings`.
