# ADR-083 — Core security enforcement is a compile-time obligation on workload backends

**Status:** Accepted
**Amends:** [ADR-002](002-microvm-security-posture.md) (per-backend tier matrix — the workload / non-workload split becomes type-enforced rather than prose)
**Preserves:** all numbered claims; [ADR-082](082-rust-native-egress-gateway.md) and Plan 129 egress secret substitution (now a tracked compile-time obligation on macOS, not an optional follow-up)

## Context

`mvm` runs untrusted workloads across several backends behind the
`AnyBackend` enum. The cross-cutting security enforcement that backs the
claims — signed-plan admission, default-deny egress + flow audit, app-deps
seal, console lockdown, egress secret substitution — was applied in two
different ways:

- Some concerns run in a **shared funnel**: admission in the `up` launch
  path, the egress bridge in the per-backend supervisor, app-deps seal in
  the supervisor admission verifier. These apply to every workload backend
  uniformly.
- One concern, **egress secret substitution** (Plan 129), was hand-rolled
  as a free function (`spawn_substitution_endpoint`) called *inside*
  individual backends' `start()` methods — Firecracker and QEMU only.

Because nothing forced a backend to acknowledge that free function, libkrun
and vz silently never got it. The gap was invisible: a backend could be
fully wired for boot, admission, and egress *filtering* while missing an
entire security mechanism, and the type system was content. `BackendSecurityProfile`
(its `claims: [ClaimStatus; 7]` array) did not help — it is advisory, and
frozen at seven claims, so the substitution concern had no cell to be
missing from.

The lesson: a core security feature must not be expressible as *absent*
without a deliberate, visible decision. A declaration matrix that lets a
backend mark a core feature "unsupported" only *documents* the hole; it
does not prevent it.

## Decision

Introduce a marker trait and type-bar the admitted workload-launch path.

```rust
pub trait WorkloadBackend: VmBackend {}
```

- `FirecrackerBackend`, `LibkrunBackend`, `VzBackend` implement it. `qemu`
  (Tier-2 dev/test) and `mock` (test double) do **not**.
- `AnyBackend::as_workload_backend(&self) -> Option<&dyn WorkloadBackend>`
  converts via an **exhaustive match** — a new `AnyBackend` variant cannot
  compile without an explicit workload / non-workload decision.
- `require_workload_backend(&AnyBackend) -> Result<&dyn WorkloadBackend>`
  is the single boundary the admitted launch path runs; it refuses a
  non-workload backend before any VM starts.

The admitted launch arms in the `up` / `invoke` path call this guard before
dispatching, so a non-workload backend is refused, not launched.

This is the structural fix, not a capability matrix: a backend reaches the
untrusted-workload path only by being a `WorkloadBackend`, and the shared
funnel — not the backend — applies the cross-cutting enforcement. The lone
genuinely per-backend concern (the egress substitution *transport*, which
differs by backend mechanism) becomes a no-default `WorkloadBackend` method
in a follow-on phase, so it cannot be omitted either.

## Consequences

- **A new backend cannot reach the workload path silently.** It must either
  implement `WorkloadBackend` (and therefore the shared funnel applies) or
  be deliberately excluded — a visible, reviewable decision.
- **ADR-002's Tier-2 carve-out is now a type constraint.** QEMU's exclusion
  from claim-10 egress enforcement was previously prose ("dev/test only, not
  wired"); it is now enforced by types — `qemu` is not a `WorkloadBackend`,
  so it cannot be passed to the admitted launch path. `mock` likewise.
- **Egress secret substitution on macOS becomes a required build.** When the
  substitution transport becomes a no-default `WorkloadBackend` method,
  libkrun and vz will not compile without implementing it. This reclassifies
  the macOS substitution port from an optional fast-follow to a compliance
  requirement. (The transparent :80/:443 terminator half entangles with the
  rvproxy migration — ADR-082 / Plan 193 — and is resolved by a design
  spike before implementation.)
- **`BackendSecurityProfile` stays advisory.** It continues to drive
  `doctor` posture output; it is no longer mistaken for the enforcement
  mechanism.

## Alternatives considered

- **Capability matrix + witness gate** (a `BackendCapabilityMatrix` with a
  `Supported`/`DeliberatelyUnsupported` cell per concern, plus an xtask gate
  asserting each `Supported` cell has a witness). Rejected: for a *core*
  feature, a `DeliberatelyUnsupported` cell documents a hole rather than
  preventing it, which is the opposite of the goal. The compiler forbids the
  actual failure (a missing implementation) for free.
- **Every backend enforces (close the Tier-2 carve-out).** Put the core
  obligation on `VmBackend` so even `qemu` must enforce egress. Deferred: it
  reopens ADR-002's settled Tier-2 decision and forces enforcement onto a
  dev/test backend that carries no untrusted workload. Recorded as a future
  option.
- **Shared launch funnel with a per-backend transport seam only
  (no-op-proofing).** Lift all enforcement into one pipeline so a backend
  cannot even supply an inert implementation. Deferred: a larger launch-path
  refactor; adopt only if inert seams prove to be a real problem (a witness
  gate is the cheaper escalation).

Implementation is sequenced in Plan 197.
