# Plan 205 — Resident builder control plane + residency model (umbrella)

**Status:** Proposed
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

- [ ] Write the three-class model and the authority/trust-tier invariant into the
      architecture docs and ADR-090.
- [ ] Add a structural test asserting the workload guest image carries no signing key,
      no admission authority, and (in prod) no `do_exec` / console symbol.
- [ ] Add a structural test asserting the builder daemon links no host-signer key path
      and no admission entrypoint.
- [ ] Add a check that the host control daemon stays per-tenant (no global multi-tenant
      key holder), guarding the claim-12/13 moat.

### B. Residency policy over the standby pool

- [ ] Add a residency policy type (`min` warm + idle timeout) over the Plan 118 pool.
- [ ] Implement warm→parked demotion on idle and parked→warm promotion on demand.
- [ ] Resolve a per-host default (Apple-silicon dev → warm; CI → parked) with an
      explicit override env/flag.
- [ ] Report live residency state and default source in `mvmctl doctor`.

### C. Resident builder daemon

- [ ] Make `mvm-builderd` long-lived across `mvmctl` invocations (consume Plan 204's
      protocol; do not reimplement it).
- [ ] Add session reuse: a second command reuses the resident builder, store, and page
      cache (Plan 196) without re-boot.
- [ ] Add readiness, version-skew, and crash-recovery handling for the resident daemon.

### D. Snapshot park/resume for the builder VM

- [ ] Wire Plan 159 (Vz) snapshot into the pool's parked state; resume in under a second.
- [ ] Wire the Firecracker leg via Plan 175 when available; until then `min = 0` on FC
      falls back to fast boot, not a stub.
- [ ] Key snapshot freshness/invalidation to the builder fingerprint (Plan 195) so a
      stale parked builder is never resumed for changed inputs.

### E. Cold acquisition (fresh machine)

- [ ] Bake a snapshot on first successful builder boot so the second-ever boot is a
      restore, not a cold boot.
- [ ] Keep the source-checkout path free of any mvm-release artifact dependency
      (ADR-046 / ADR-089).
- [ ] Add a doctor line distinguishing "never built", "parked snapshot present", and
      "warm".

### F. Docs and posture

- [ ] Add a "what runs where" table (host control / builder daemon / workload agent)
      for users and contributors.
- [ ] Document the residency default, the override, and the RAM-vs-latency tradeoff.
- [ ] Write the threat-model delta: residency changes the builder lifecycle, not the
      trust boundary; enumerate why each claim is unaffected.

## Acceptance

Plan 205 is done when:

- a second `mvmctl` command in a session triggers no builder boot (warm) or a
  sub-second resume (parked) — measured, not asserted;
- the residency posture is a single policy with a per-host default and an override;
- the trust-gradient invariant has passing structural tests, and no signing key,
  admission authority, or audit writer exists below the host→builder vsock line;
- claim-11 volumes still fail closed on a resumed builder via host-side re-verification;
- `mvmctl doctor` reports residency state; docs explain host/builder/workload split.

## Verification

- [ ] Structural tests for the trust-gradient invariant (Workstream A).
- [ ] Residency policy unit tests: warm/parked transitions, idle demotion, default
      resolution, override.
- [ ] Resident-daemon reuse test: second request reuses the live builder + hot store.
- [ ] Snapshot freshness test: changed builder fingerprint refuses a stale resume.
- [ ] Claim-11 admit-time re-verification holds on a resumed builder.
- [ ] Measured latency: warm second command, and parked-resume first command.
- [ ] `cargo test --workspace`.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`.

## Security Notes

This plan changes the builder *lifecycle*, not workload guest trust. The trust gradient
(ADR-090) is the load-bearing guarantee: keys, admission, and the audit chain stay
host-side in the TCB at every residency setting; the builder daemon is trusted to build
but never to sign or admit; the workload agent stays the prod-stripped runt. Residency
applies only to the dev-tier builder VM and re-verifies nothing about a workload's
posture, which admission re-checks host-side from content-addressed inputs regardless
of how the builder booted.
