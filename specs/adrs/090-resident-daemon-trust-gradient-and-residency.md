# ADR-090 — Resident-daemon trust gradient and builder residency model

**Status:** Proposed
**Date:** 2026-06-19
**Relates to:** [ADR-002](002-microvm-security-posture.md),
[ADR-046](046-builder-vm-via-libkrun.md),
[ADR-057](057-symmetric-builder-vm.md),
[ADR-084](084-host-services-daemon-not-per-vm-spawn.md),
[ADR-088](088-dev-vm-promotion-boundary.md),
[ADR-089](089-builder-vm-resident-control-plane.md),
[Plan 118](../plans/118-supervisor-standby-pool-and-live-bench.md),
[Plan 152](../plans/152-rust-native-vz-and-init-lifecycle-parity.md),
[Plan 159](../plans/159-vz-inspired-macos-dx.md),
[Plan 196](../plans/196-warm-builder-store-kernel-cache.md),
[Plan 202](../plans/202-host-services-daemon.md),
[Plan 204](../plans/204-builder-vm-resident-control-plane.md), and
[Plan 205](../plans/205-resident-builder-control-plane.md)

## Context

The local product is meant to feel instant: a user types a command and a workload
runs. Today the worst latency is the per-session builder VM bring-up — the builder
boots (or rebuilds) at the start of a session before any useful work happens. Cold
acquisition on a fresh machine is the second worst. Both are felt every working day.

The instinct to fix this is "keep the builder VM running and let it be the daemon."
That instinct is correct in shape but dangerous if taken literally, because the word
*daemon* hides three very different processes with three very different trust levels:

- a host process that holds signing keys, admits signed `ExecutionPlan`s, and writes
  the chain-signed audit log;
- the builder VM process that owns Nix and produces artifacts;
- the in-guest agent that lives inside each workload microVM.

ADR-089 already decided that builder *execution* should move to a resident service
(`mvm-builderd`) behind a typed vsock protocol (Plan 204). Two questions it left open
are the source of the present design risk:

1. Should the builder VM be always-resident, or parked and resumed on demand? These
   were treated as competing strategies with opposite cost profiles.
2. What is the trust relationship among the three daemons, and what stops "make it
   instant" pressure from pushing authority (keys, admission) into the builder VM or
   fattening the workload agent — either of which would regress ADR-002?

ADR-002 is unambiguous that the host is the trusted computing base and the guest is
not. Any redesign that improves latency by relocating authority toward the guest is a
security regression, however fast it feels. This ADR fixes the trust relationship and
the residency model together so they cannot drift apart.

## Decision

Adopt a single coherent model with two parts: a **trust gradient over three daemon
classes**, and a **residency policy** that unifies "always-resident" and
"parked-and-resumed" as two settings of one mechanism rather than two code paths.

### 1. Three daemon classes on a trust gradient

There are exactly three long-lived process classes. Authority and resident weight
**decrease monotonically** as distance from the host increases:

| Layer | Daemon | Role | Authority | Trust tier |
|---|---|---|---|---|
| Host | control daemon | host-signer keys, plan admission, audit chain, pool + VM lifecycle | full | TCB (trusted) |
| Builder VM | builder daemon (`mvm-builderd`) | owns Nix + the builder store, runs allowlisted build/eval, resident | build-only | trusted-to-build, dev-tier |
| Workload microVM | guest agent | thin vsock RPC endpoint | none | untrusted |

The governing invariant:

> No daemon may hold authority that exceeds its trust tier, and a daemon farther from
> the host may never hold authority a closer one lacks. Signing keys, plan admission,
> and the audit chain never cross the host→builder vsock line.

Concretely:

- The host control daemon stays host-side and thin. For the local single-user case it
  is effectively one daemon; under the fleet it fans out **per tenant** (ADR-084 /
  Plan 202) so each tenant key sits behind its own process boundary. Collapsing tenants
  into one global key-holding daemon is forbidden — it would regress claims 12/13.
- The builder daemon is the resident service from ADR-089. It is the *only* daemon that
  may grow to host residency for performance, because building is its whole job and it
  is dev-tier (ADR-088).
- The workload guest agent stays the runt by construction: prod builds strip `do_exec`
  (claim 4) and the console (claim 15), both `dev-shell`-gated. It must never acquire
  orchestration authority or hold secrets. Fattening it is the primary smell this ADR
  exists to forbid.

### 2. Residency policy: one slider, not two strategies

Builder-VM residency is a policy over the existing standby pool (Plan 118), expressed
as `min` warm instances plus an idle timeout — not two implementations.

```text
 Parked (snapshot on disk)  ◀── idle-timeout ──  Warm (resident)
   │   resume <100ms ─────────────────────────────▶  │
 min=0: no idle RAM (resume-on-demand)     min≥1: no boot latency (always-resident)
```

- `min ≥ 1` keeps a builder warm: zero per-command boot latency.
- `min = 0` parks the builder as a snapshot (Plan 159 for Vz, Plan 175 for Firecracker)
  and resumes it on demand in well under a second.
- The idle timeout demotes warm→parked; the next command promotes parked→warm.
- Each host picks a default (for example, an Apple-silicon dev box defaults warm; CI
  defaults parked). The mechanism is identical either way.

This is the unification the user asked for: "support both" is one pool with a knob, the
same pattern proven by comparable single-library microVM tools (separate privileged
worker, snapshot cold-restore, pool with min/idle — matching Plan 152's supervisor
split and Plan 159's snapshot/fork).

### 3. Residency introduces no claim regression

- The builder VM is dev-tier (ADR-088), so snapshotting and resuming it requires no
  hardened kernel or verified boot and weakens no numbered claim.
- The security-sensitive case — claim-11 application-dependency volumes — stays safe
  because the sealed volume is content-addressed and **re-verified host-side at admit
  time** (`verify_sealed_volume`), independent of how the builder booted. A resumed
  builder cannot smuggle anything past host admission.
- The host→builder transport is the typed, allowlisted `BuilderRequest` protocol
  (Plan 204), not a shell. Making the builder resident therefore *shrinks* the attack
  surface relative to today's bind-mount-and-run-shell-jobs path.

## Security and trust boundary

This ADR does not weaken any existing boundary; it pins the relationships that keep
latency work from eroding them:

- Keys, admission, and audit remain host-side in the TCB at every residency setting.
- The builder daemon never receives signing keys or admission authority.
- The workload agent stays minimal and prod-stripped; the trust gradient is testable.
- Snapshot/resume applies only to the dev-tier builder VM, never to a workload's
  security posture, which is re-verified at admit time regardless of boot path.

## Consequences

Positive:

- The fast path (builds) and the trusted path (keys/admission/audit) are *different
  daemons*, so performance work and security stop trading against each other.
- "Always-on" vs "resume-on-demand" becomes a one-line policy, not a fork.
- The trust gradient becomes an explicit, lintable invariant rather than folklore.

Negative:

- A resident builder daemon has a wider uptime/crash-recovery surface than one-shot
  jobs (owned by Plan 204 / Plan 205).
- Snapshot freshness/invalidation must be tied to the builder fingerprint (Plan 195) so
  a stale parked builder is never resumed for changed inputs.
- The residency default per host is a support surface (RAM vs latency) that must be
  documented and overridable.

## Alternatives Considered

### Collapse the host control plane into the builder VM

Rejected. It is the literal reading of "let the daemon be the builder VM," but it moves
signing keys and admission into a Linux guest, directly inverting ADR-002. The builder
daemon may be resident; it may not be trusted with keys.

### One global host daemon holding every tenant's keys

Rejected. It looks like "a single host daemon," but it regresses the claim-12/13 moat
that ADR-084 / Plan 202 built. The model is one *logical* control plane with per-tenant
process isolation when multi-tenant; locally that already presents as a single daemon.

### Two separate modes for resident vs resume

Rejected. Divergent lifecycles drift and double the test surface. The standby-pool
`min`/idle knob expresses both with one mechanism.

### Keep the one-shot builder and only make boot faster

Rejected as the end state. It leaves the per-session boot (the top pain) in the hot
path. Residency removes the boot from the steady state instead of shortening it.

## Migration

Plan 205 owns execution and sits as the umbrella over Plans 118/152/159/196/202/204.
The sequence: codify the trust-gradient invariant and its structural test; add the
residency policy over the standby pool; make `mvm-builderd` resident across `mvmctl`
invocations (consuming Plan 204's protocol, not reimplementing it); wire snapshot
park/resume into the parked state; add the cold-acquisition snapshot-bake; document
"what runs where." No user command rename is required.

## Threat-model delta (residency landed)

The residency policy (Plan 205 WS-B) and parked-standby demotion (WS-D) are in the tree. This
section records why neither changes the trust boundary or weakens an ADR-002 claim:

- **Keys, admission, and audit stay host-side at every residency setting.** Residency only
  changes how warm the standby pool is kept and whether an idle standby is parked or reaped.
  The host control plane — signing keys, plan admission, the chain-signed audit log — is
  untouched. No claim 8 / 12 / 13 surface moves.
- **A parked standby is still admitted from content-addressed inputs.** A standby is a
  kernel + supervisor saved state carrying no workload; the workload is attached at claim time
  from the admitted, signed `ExecutionPlan` (claim 8) only after a compatibility check on
  `kernel_sha256` + image digest (`StandbyCompat`). A parked standby cannot be claimed for an
  incompatible image, and how long it sat parked changes nothing the admission path verifies.
- **Demotion is gated by the dev-tier saved-state shape (`is_saved_state()`, pid 0).** Parking
  applies only to a backend whose standby is already a captured saved state (the macOS managed
  backend); the live-process backend reaps to cold. No production workload's posture is
  snapshotted or resumed — the workload rootfs is dm-verity sealed (claim 3) and re-verified
  independent of the standby it was claimed from.
- **No new guest-reachable surface.** Residency is host-side pool bookkeeping (the reaper and
  the selection predicate). The guest wire is unchanged and the workload agent gains nothing.

Net: residency changes the builder/standby *lifecycle*, not the trust gradient. Claims 1–15
are unaffected, and `check-trust-gradient` continues to machine-check the gradient on every PR.
