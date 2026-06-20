# Plan 205 — Resident builder control plane + residency model (umbrella)

**Status:** Substantially complete
**Sprint:** 63 / product-DX + trust-boundary
**ADR:** [ADR-090](../adrs/090-resident-daemon-trust-gradient-and-residency.md)
**Builds on:** [ADR-002](../adrs/002-microvm-security-posture.md),
[ADR-084](../adrs/084-host-services-daemon-not-per-vm-spawn.md),
[ADR-088](../adrs/088-dev-vm-promotion-boundary.md),
[ADR-089](../adrs/089-builder-vm-resident-control-plane.md)
**Umbrella over:** Plan 118, Plan 152, Plan 159, Plan 196, Plan 202, Plan 204

## Goal

Make builder bring-up disappear from the steady state without moving any authority
into a guest. Concretely:

- the per-session builder boot (the top latency pain) is gone — the builder is already
  warm, or resumes from a snapshot in under a second;
- cold acquisition on a fresh machine is a one-time event whose second boot is a
  restore, with no release-pipeline dependency for source checkouts;
- the three long-lived daemons (host control, builder, workload agent) sit on an
  explicit, testable trust gradient (ADR-090);
- "always-resident" and "parked-and-resumed" are one residency policy, not two paths.

Target shape (the three-class model from ADR-090):

```text
host (TCB)            control daemon — keys, admission, audit, pool + lifecycle
   │ typed BuilderRequest over vsock (no keys cross this line)
builder VM (dev-tier) mvm-builderd — resident; owns Nix + store; allowlisted build/eval
   │ builds / host-side admission
workload microVM      guest agent — thin RPC runt; prod-stripped; zero authority
```

## Non-goals

- Do not move signing keys, plan admission, or the audit chain into the builder VM.
- Do not collapse the per-tenant host security daemons (Plan 202) into one global
  key-holding process.
- Do not let the workload guest agent grow orchestration authority or hold secrets.
- Do not reimplement the builder protocol — consume Plan 204's `BuilderRequest`.
- Do not snapshot/resume a workload's security posture; admission re-verifies host-side.
- Do not require host Nix for normal builds or runs (ADR-089 holds).
- Do not change the `mkGuest` user image API.

## How this sits over the existing plans

This plan is an umbrella. It owns the residency model and the trust-gradient invariant,
and it consumes the in-flight pieces rather than rebuilding them.

| Existing plan | What it already provides | What Plan 205 adds on top |
|---|---|---|
| Plan 118 — standby pool | warm-instance pool + reaper | residency *policy* (`min` + idle) and the warm↔parked transition |
| Plan 152 — Rust VZ supervisor | privileged per-VM supervisor (the worker that holds entitlements) | reuse as the residency worker; no new privileged process |
| Plan 159 — VZ snapshot/fork | Vz snapshot/restore + memory fork | wire snapshot into the pool's *parked* state for the builder VM |
| Plan 175 — FC live-memory | (proposed) Firecracker resume | the Firecracker leg of parked→warm resume |
| Plan 196 — warm store/kernel cache | persistent store + warm gcroot | keep the resident builder's Nix store + page cache hot across calls |
| Plan 202 — host services daemon | per-tenant keyless broker + key-holding signer | this *is* the host control daemon; Plan 205 keeps it host-side, per-tenant |
| Plan 204 — builder protocol | typed `BuilderRequest`/responses + one-shot `mvm-builderd` | make `mvm-builderd` *resident* across invocations |

Gaps this umbrella closes, which no single plan above owns: (i) a unified residency
knob instead of ad hoc warm/cold handling; (ii) a builder daemon that survives across
`mvmctl` invocations rather than one-shot; (iii) an explicit, lintable trust-gradient
invariant; (iv) a cold-acquisition snapshot-bake story; (v) a per-host residency
default.

## Execution update — 2026-06-20

Most structural work is landed. WS-A/B/D/F merged in #1090/#1094/#1099/#1103,
WS-E landed in #1102, Plan 204 delivered the resident `mvm-builderd` boot wiring
in #1091, the builder-tier trust-gradient gate landed in #1110, builder residency
Step 1/2 landed in #1114/#1121, and the benign `host_signer` trust-gate
false-positive was closed in #1123. The Plan 205 rollup remains unticked for
the live macOS-26 demotion/resume timing proof and the live-coupled OCI
`run --image` residency path; resident-daemon lifecycle and FC live-memory
details remain in their owning Plan 204/175 lanes.

Follow-up slice in progress: the persistent Vz dev builder now has an explicit
snapshot-park path (`mvmctl dev park`) and `dev up` restores an existing
`state.vzsave` before falling back to cold boot, and `mvmctl doctor` reports
parked snapshot presence in the builder-residency line. The primitive lives in
`mvm-build` and reuses the Plan 159 Vz `SAVE`/`Restore` supervisor contract:
host-only control socket, `<snapshot>.machine-id` sidecar, and persisted
`SupervisorConfig` replay. This is CI-tested without booting a VM; live macOS
timing proof remains the acceptance gate.

The invocation-driven keeper shape is also landed for the libkrun
`persistent-builder` session: the session record now carries
`last_activity_unix_secs`, dispatch touches it before/after use, and the next
build invocation applies the resolved residency policy. `MVM_RESIDENCY=cold`
actively tears down that live session before single-shot fallback, while
idle `Park` decisions degrade to teardown because the libkrun path has no
snapshot primitive. Vz dev-builder idle auto-park and the live timing proof
remain open.

## Design

### Trust gradient (ADR-090 §1)

Three daemon classes, authority decreasing host→builder→workload. The host control
plane stays thin and (under the fleet) per-tenant. The builder daemon is the only one
that may go resident for speed. The workload agent stays the prod-stripped runt. The
invariant — no daemon holds authority above its trust tier; keys/admission/audit never
cross the host→builder vsock line — is codified and tested (Workstream A).

### Residency slider (ADR-090 §2)

`min` warm builders + idle timeout select a point between always-resident (`min ≥ 1`)
and parked-and-resumed (`min = 0`, snapshot on disk, sub-second resume). One mechanism
over the Plan 118 pool. Per-host default, user-overridable. `mvmctl doctor` reports the
live residency state (warm / parked / cold) and the resolved default's source.

### Residency safety (ADR-090 §3)

Snapshot/resume applies only to the dev-tier builder VM. Claim-11 prod-dep volumes stay
safe via host-side content-addressed admit-time re-verification. The transport is the
typed allowlisted protocol, so residency shrinks rather than widens the attack surface.

## Workstreams

### A. Trust-gradient invariant

- [x] Write the three-class model and the authority/trust-tier invariant into the
      architecture docs and ADR-090 (#1103).
- [x] Add a structural test asserting the workload guest image carries no signing key,
      no admission authority, and (in prod) no `do_exec` / console symbol (#1090).
- [x] Add a structural test asserting the builder daemon links no host-signer key path
      and no admission entrypoint (#1110, with the false-positive narrowed in #1123).
- [x] Add a check that the host control daemon stays per-tenant (no global multi-tenant
      key holder), guarding the claim-12/13 moat (#1090).

### B. Residency policy over the standby pool

- [x] Add a residency policy type (`min` warm + idle timeout) over the Plan 118 pool
      (#1094).
- [x] Implement warm→parked demotion on idle and parked→warm promotion on demand
      (#1099; live timing proof remains below).
- [x] Resolve a per-host default (Apple-silicon dev → warm; CI → parked) with an
      explicit override env/flag (#1094).
- [x] Report live residency state and default source in `mvmctl doctor`; builder
      residency policy and persistent-session visibility landed in #1114.

### C. Resident builder daemon

- [x] Make `mvm-builderd` long-lived across `mvmctl` invocations (consume Plan 204's
      protocol; do not reimplement it) (#1091).
- [~] Add session reuse: a second command reuses the resident builder, store, and page
      cache (Plan 196) without re-boot. The resident daemon substrate is present,
      activity is persisted on the libkrun persistent-builder session, and
      cold/idle policy is enforced on the next build invocation; live no-boot
      proof remains part of the final latency gate.
- [~] Add readiness, version-skew, and crash-recovery handling for the resident daemon.
      Readiness/protocol handling lives in Plan 204; crash-recovery closeout remains
      in that lifecycle lane.

### D. Snapshot park/resume for the builder VM

- [x] Wire Plan 159 (Vz) snapshot into the pool's parked state; resume uses the existing
      saved-state path (#1099). Live under-budget timing proof remains open.
- [x] Wire explicit Vz dev-builder snapshot park/restore: `mvm-build::vz_builder`
      saves `~/.cache/mvm/builder-vm/vms/mvm-persistent-builder-vz-dev/state.vzsave`,
      persists/replays the supervisor config in `Restore` mode, `mvmctl dev park`
      snapshots + stops the VM, and the next `mvmctl dev up` restores before
      cold-boot fallback. Unit/CLI tests cover command framing, stale-snapshot
      replacement, restore config rewriting, parser, and JSON output.
- [~] Wire the Firecracker leg via Plan 175 when available; until then `min = 0` on FC
      falls back to fast boot, not a stub. FC/libkrun currently reap to cold.
- [x] Key builder snapshot freshness/invalidation to builder residency inputs (#1121).
      Correction from execution: workload-standby freshness is existing `StandbyCompat`
      (kernel+image sha), not Plan 195's builder-VM fingerprint.

### E. Cold acquisition (fresh machine)

- [x] Add `mvmctl bootstrap` prefetch so first acquisition can happen before the hot path
      (#1102). Snapshot-bake/live second-boot timing remains part of the live gate.
- [x] Keep the source-checkout path free of any mvm-release artifact dependency
      (ADR-046 / ADR-089) (#1102).
- [~] Add doctor visibility for builder residency. #1114 reports resolved builder
      residency policy and persistent-session presence; the Vz parked-snapshot
      slice adds `parked (snapshot present)` / `parked (no snapshot)` wording.
      Idle-age detail remains follow-up even though the hidden
      `persistent-builder` session now records activity timestamps.

### F. Docs and posture

- [x] Add a "what runs where" table (host control / builder daemon / workload agent)
      for users and contributors. — `reference/architecture.md` §"What runs where".
- [x] Document the residency default, the override, and the RAM-vs-latency tradeoff. —
      `reference/architecture.md` §"Residency".
- [x] Write the threat-model delta: residency changes the builder lifecycle, not the
      trust boundary; enumerate why each claim is unaffected. — ADR-090 §"Threat-model delta".

## Acceptance

Plan 205 is done when:

- a second `mvmctl` command in a session triggers no builder boot (warm) or a
  sub-second resume (parked) — held to the **latency budget** below, CI-gated,
  not asserted;
- the residency posture is a single policy with a per-host default and an override;
- the trust-gradient invariant has passing structural tests, and no signing key,
  admission authority, or audit writer exists below the host→builder vsock line;
- claim-11 volumes still fail closed on a resumed builder via host-side re-verification;
- `mvmctl doctor` reports residency state; docs explain host/builder/workload split.

## Latency budget (the "instant" bar)

"Feels instant" is an acceptance gate, not prose. The residency slider must hold
these budgets; a regression fails the build.

| Path | Budget (P50) | How it is gated |
|---|---|---|
| Warm (`min ≥ 1`), Nth command in a session | **no builder boot occurs**; the only added latency is the control round-trip (handshake + dispatch) to the resident `mvm-builderd`: **< 50 ms** | deterministic in the PR matrix — assert the warm path takes the resident-daemon branch (no boot) and measure the round-trip against a live local daemon (no VM) |
| Parked (`min = 0`), resume-on-demand | snapshot restore **< 100 ms** (ADR-090 §2) | backend-bearing live lane: Vz/macOS (Plan 159) and FC/KVM (Plan 175) |
| Cold acquisition, second-ever boot | a **restore**, not a cold boot — within the parked budget | first boot bakes a snapshot (WS-E); the second boot is measured ≤ the parked-resume budget |

Notes:

- GitHub Actions can enforce the *invariant* deterministically (warm reuses with
  no boot; the control-plane budget); the full **resume-ms** number needs a
  runner with the backend, so it rides the existing host-gated live-bench lanes
  (mirroring Plan 118 `bench microvm-launch` and the macOS live lanes), not the
  default PR matrix. Both are required checks for "done".
- A P95 ceiling of 2× the P50 budget guards tail latency.
- These are the *initial* bar — tighten as the warm/parked paths land; never
  loosen silently (log any cap, per the ADR-002 no-silent-caps discipline).
- The first-ever **image-download** cost is explicitly *out* of this budget: it
  is paid once at install/prefetch time (ADR-089 `mvmctl bootstrap` prefetch /
  the install script), never on the per-command hot path. The budget measures
  bring-up given the image is present.

## Verification

- [x] Structural tests for the trust-gradient invariant (Workstream A; #1090/#1110/#1123).
- [x] Residency policy unit tests: warm/parked transitions, idle demotion, default
      resolution, override (#1094/#1099/#1114).
- [~] Resident-daemon reuse test: second request reuses the live builder + hot store.
      Substrate is in place and the libkrun persistent-builder session now has
      CI-tested activity/keeper decisions; live no-boot proof remains open.
- [x] Builder snapshot freshness test: stale builder residency inputs refuse reuse (#1121).
- [~] Claim-11 admit-time re-verification holds on a resumed builder. The design remains
      host-side and content-addressed; resumed-builder live proof remains open.
- [~] Latency gate (the "instant" bar): the warm-path no-boot + control-plane
      `< 50 ms` assertion runs in the PR matrix; the parked-resume `< 100 ms` P50
      (P95 ≤ 2×) runs on the backend-bearing Vz/FC live lane; a regression past
      either budget fails the build. (See the Latency budget table.)
- [~] `cargo test --workspace` for all landed slices passed in their PRs; plan-wide
      final live-gated acceptance is still open.
- [~] `cargo clippy --workspace --all-targets -- -D warnings` for all landed slices
      passed in their PRs; plan-wide final live-gated acceptance is still open.

## Security Notes

This plan changes the builder *lifecycle*, not workload guest trust. The trust gradient
(ADR-090) is the load-bearing guarantee: keys, admission, and the audit chain stay
host-side in the TCB at every residency setting; the builder daemon is trusted to build
but never to sign or admit; the workload agent stays the prod-stripped runt. Residency
applies only to the dev-tier builder VM and re-verifies nothing about a workload's
posture, which admission re-checks host-side from content-addressed inputs regardless
of how the builder booted.
