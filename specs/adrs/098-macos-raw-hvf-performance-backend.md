# ADR-098 — Raw hypervisor as the macOS performance backend

**Status:** Proposed
**Date:** 2026-06-27
**Relates to:** [ADR-002](002-microvm-security-posture.md),
[ADR-073](073-warm-snapshot-prior-art-adoption-boundary.md),
[ADR-097](097-attested-downloadable-runtime-and-builder-packs.md),
[Plan 212](../plans/212-subsecond-machine-run.md),
[Plan 214](../plans/214-clean-replacement-architecture.md),
[Research note](../research/clean-replacement-architecture-review.md)

## Context

mvm runs Linux microVMs across several host VMM backends behind one `VmBackend`
trait. On macOS there are two paths today: a high-level system virtualization
framework (the "Vz" backend), which is the auto-selected default on the newest
Apple Silicon tier, and a third-party in-process VMM. The high-level framework is
excellent for stable VM orchestration and ships with the OS, but it deliberately
hides the machine internals: it does not expose guest-memory mapping, page-granular
control, or device-state capture, and its snapshot facility is a coarse, opaque
save/restore.

mvm's product promise now includes sub-second startup, with warm starts that feel
instant. The [research note](../research/clean-replacement-architecture-review.md)
establishes that the fastest *local* warm-restore mechanism is an eager
copy-on-write mapping of the snapshot RAM section: clean pages stay shared with the
snapshot file via the page cache, dirty pages become private only on write, and
there is no userspace fault round-trip. That mechanism requires the host to map a
file-backed region and present it to the guest as RAM, plus restore vCPU and device
state around it. The high-level macOS framework cannot do this. The raw
hypervisor interface (HVF) can.

The question this ADR answers:

> Should mvm use the raw hypervisor instead of the high-level virtualization
> framework for the macOS snapshot/warm-pool performance path?

This is a backend choice behind an existing abstraction, not a change to the
product, the CLI, the library contract, or the security model. The constraint is
that it must not become VMM lock-in: a new backend is one more implementation of
`VmBackend`, selected by capability, never a special case that leaks into callers.

## Decision

**The destination is HVF as the macOS backend; Vz is transitional.** The direction
is to move macOS off the high-level framework (Vz) and onto the raw hypervisor
(HVF). The chosen *path* there is staged (Option B as a transition into Option C):
add the raw-hypervisor (HVF) backend, make it the macOS backend for snapshot and
warm-pool work as soon as it is proven, and keep Vz only as a transitional
compatibility backend that is retired once HVF meets the acceptance criteria below.
Drive selection by backend capability and by the plan's required restore-latency
class. Stage the work behind benchmarks; the only reason Vz is not deleted on day
one is that we do not remove a working backend before its replacement is proven —
not because dual-backend is the intended end state.

### Options considered

- **Option A — keep only the high-level framework.** Lowest cost and lowest risk,
  but it caps macOS warm restore at the framework's coarse save/restore latency and
  forecloses eager-CoW and snapshot internals on macOS. Rejected: it cannot meet
  the sub-100 ms warm-restore target the product needs on macOS, and it is the
  backend we want to move away from.
- **Option B — add a raw-hypervisor backend for performance; keep the high-level
  framework for compatibility.** Higher cost (we own a device model and its
  fuzzing), but it unlocks guest-memory mapping, eager-CoW restore, and low-latency
  warm restore on macOS while preserving a stable fallback during the transition.
  **Chosen as the transition mechanism, not the end state** — Vz is kept only until
  HVF proves out.
- **Option C — HVF is the macOS backend; Vz is removed.** The intended end state.
  Reached by executing Option B and then sunsetting Vz once the acceptance criteria
  pass. Not done in one step only because removing a working backend before its
  replacement is proven would risk macOS users; the staged path reaches the same
  destination safely.

### Vz sunset criteria

Vz is removed from the macOS path once the HVF backend has, on the newest Apple
Silicon tier:

- passed the warm-run, shell-attach, and warm-restore acceptance gates in the
  [benchmark plan](../perf/sub-second-startup-benchmark-plan.md) (including eager-CoW
  restore p95 under target);
- booted the consolidated `mvm-init` over its vsock control channel and run both
  one-shot exec and interactive shell;
- carried the full security posture (no production SSH, no guest NIC by default,
  brokered egress/ingress, secret-free snapshot frames) with its device model under
  the same fuzzing discipline as the existing parsers;
- run a representative workload set with no Vz-only fallback required.

Until all four hold, Vz stays as the transitional fallback. After they hold, the Vz
backend, its supervisor, and its selection branch are deleted.

### What this ADR explicitly states

- The high-level macOS framework (Vz) is a useful stable backend for the
  transition, but it is not the end state: the macOS path moves to HVF, and Vz is
  retired once the sunset criteria pass.
- The high-level framework almost certainly cannot expose the guest-memory
  mapping, page-level control, and device-state capture that eager-CoW restore
  needs; its save/restore is coarse and opaque.
- The raw hypervisor is the likely correct substrate for low-latency warm restore
  and snapshot internals on macOS.
- Adopting the raw hypervisor does not violate "no VMM lock-in" because it is one
  backend behind the same `VmBackend` abstraction.
- The raw hypervisor is a larger implementation, fuzzing, device-model, and
  security commitment than wrapping a high-level framework, and the migration is
  staged and benchmark-driven.
- No existing CLI workflow changes because of this backend split. `mvm machine run
  --image <ref> -- /bin/sh` and interactive shell attach behave identically
  regardless of which macOS backend is selected.

## Backend selection rules

Selection is capability-aware and fail-closed, layered on the existing
platform-first auto-selection:

- Default macOS backend: the raw hypervisor (HVF) as soon as it is proven. Vz
  remains the auto-default only during the transition window, and only on hosts or
  for plans where HVF is not yet available; that window closes when the sunset
  criteria pass.
- Performance macOS backend: the raw hypervisor (HVF), always preferred.
- The scheduler (mvmd at the fleet level; the `Machine` library locally) chooses
  based on plan requirements, host capability, and the requested snapshot mode.
- If the requested snapshot mode requires eager CoW, prefer the raw hypervisor and
  do not silently fall back to the high-level framework unless the plan explicitly
  permits a fallback.
- If compatibility matters more than performance for a given plan, the high-level
  framework is allowed.
- If no raw-hypervisor backend exists yet on the host, fail clearly, or fall back
  only when the plan permits it.
- No macOS backend advertises a production-SSH capability; a plan that requires
  production SSH is rejected by either backend (consistent with the standing SSH
  ban).

The capability dimensions that gate this choice are added in
[Plan 214](../plans/214-clean-replacement-architecture.md) Phase 2:
`supports_guest_memory_mapping`, `supports_fixed_address_remap`,
`supports_device_state_snapshot`, `supports_vcpu_state_snapshot`,
`supports_eager_cow_restore`, alongside the existing pause/resume/snapshot/vsock
facts.

## Staged plan

1. Define the backend capability model (Plan 214 Phase 2) so this choice is
   expressed as capability, not as a special case in callers.
2. Keep Vz working as the transitional fallback (do not delete it yet).
3. Build a minimal raw-hypervisor spike: boot a Linux guest, no NIC, vsock control
   channel.
4. Prove guest-RAM mapping from a host file-backed region and fixed-address remap.
5. Prove the vsock/control channel and the consolidated `mvm-init` boot path on it.
6. Prove snapshot and eager-CoW restore of a minimal guest.
7. Compare restore latency (p50/p95/p99) and resident-memory profile against Vz,
   using the [benchmark plan](../perf/sub-second-startup-benchmark-plan.md).
8. Promote HVF to the macOS backend (default, not just performance) once it passes
   the gates.
9. Execute the Vz sunset once all four sunset criteria hold: delete the Vz backend,
   its supervisor, and its selection branch. If a criterion is not yet met, record
   which one and keep Vz only for that gap until it is closed.

## Consequences

**Positive.** Unlocks eager-CoW local restore and snapshot internals on macOS;
makes the sub-100 ms warm-restore target reachable on Apple Silicon; converges
macOS on a single owned backend (HVF), reducing the long-term surface to maintain;
stays within the no-lock-in principle because HVF is one `VmBackend` impl.

**Negative / costs.** mvm owns a macOS device model and its fuzzing surface; the
attack surface and maintenance grow during the transition; the spike must prove
feasibility before any promotion. Vz is a maintained second path only until the
sunset criteria pass, after which it is removed — the dual-backend cost is
transitional, not permanent.

**Security.** The raw-hypervisor backend inherits every standing requirement: no
production SSH, no guest NIC by default, no egress/ingress path that bypasses host
policy/audit, and snapshot frames that exclude secrets by construction
(see the [security/audit/trace/secret note](../notes/clean-replacement-security-audit-trace-secret-architecture.md)).
The device model is new untrusted-input surface and is fuzzed under the same
discipline as the existing vsock and supervisor-config parsers.
