# Plan 197 — `WorkloadBackend`: core security features as a compile-time obligation

**Date:** 2026-06-13
**Status:** design approved; implementation plan to follow
**Related:** ADR-002 (security posture / per-backend tier matrix), Plan 97
(vz closeout), Plan 129 (egress secret substitution), Plan 177 / ADR-076
(backend consolidation)

> **Priority update 2026-06-15:** Plan 200's machine UX must launch through this
> admitted workload-backend funnel. Do not add `machine run/start` paths that
> talk directly to a backend and skip `WorkloadBackend`, substitution transport,
> admission, audit, or policy visibility.

## Problem

Egress secret substitution (Plan 129) shipped on Firecracker and QEMU but
silently never reached the macOS workload backends (libkrun, vz). The
cause is structural, not an oversight: the cross-cutting enforcement was a
**free function** (`spawn_substitution_endpoint`) called ad-hoc inside
each backend's start path. Nothing forced a new backend — or an existing
one — to even acknowledge the concern. A backend could be fully wired for
boot, admission, and egress *filtering* while missing a whole security
mechanism, and the type system was content.

The existing `BackendSecurityProfile` (the `claims: [ClaimStatus; 7]`
array) is no defense: it is frozen at seven claims, so the concerns that
matter here (claim 10 egress, the substitution channel) have no cell to be
missing from, and it is advisory — it documents posture, it does not
enforce it.

## Goal

Make it **impossible for a workload-bearing backend to exist without the
core security features.** "Impossible" means *the compiler rejects it* —
not a lint, not a doc, not a runtime check. Adding a new backend, or
adding a new core security feature, must turn the tree red until every
workload backend implements it.

## Design

Grounding the design in the code changed its shape. **Five of the six core
concerns already run in a shared funnel**, not per-backend: signed-plan
admission (`up.rs`), the egress deny-by-default bridge + flow audit (the
supervisor every workload backend spawns), app-deps seal (supervisor
admission), and console lockdown (a separate command). Only **egress
secret substitution** is hand-rolled inside individual backends'
`start()` methods (`qemu.rs`, `microvm.rs`) — which is *exactly why it
silently never reached libkrun/vz.* Verified-boot cmdline is per-backend
but uniformly built by all.

So the fix is **not** to invent six per-backend trait methods — that would
drag shared funnel logic *into* per-backend code and invite the very drift
we are killing. It is two moves:

**Move 1 — type-bar the funnel.** Introduce a marker trait and retype the
admitted launch path:

```rust
/// Marker: a backend permitted to carry an untrusted workload. Only
/// backends that go through the full enforcement funnel implement it.
pub trait WorkloadBackend: VmBackend {
    /// The ONE genuinely per-backend seam: how this backend attaches the
    /// egress substitution / terminator transport. No default body → a new
    /// workload backend does not compile until it provides it; the shared
    /// funnel calls it uniformly. (Firecracker: nft TAP REDIRECT terminator;
    /// macOS: vsock-bridged Uds channel + gateway terminator — see Phase 2.)
    fn egress_substitution_transport(&self) -> EgressSubstitutionTransport;
}
```

This is the **end state**. Phase 1 ships `WorkloadBackend` as a bare marker
(no methods) — enough to type-bar the funnel with zero behavior change. The
`egress_substitution_transport` seam (and the `EgressSubstitutionTransport`
type) is added in **Phase 2**, together with its implementations, so the
no-default method never exists without a body.

- `FirecrackerBackend`, `LibkrunBackend`, `VzBackend` implement
  `WorkloadBackend`. `mock` also implements it (the ADR-045 hermetic test
  double — it carries no real workload). `qemu` (a real dev/test VMM) does
  **not** — it is the meaningful carve-out.
- The admitted workload-launch dispatch takes **`&dyn WorkloadBackend`**
  instead of `&dyn VmBackend`. `qemu` cannot be passed to it →
  ADR-002's Tier-2 carve-out becomes a *type constraint*, not prose.

**Move 2 — pull substitution into the funnel.** Lift
`spawn_substitution_endpoint` out of the per-backend `start()` methods and
into the shared launch funnel, applied uniformly to every
`WorkloadBackend` the same way admission and the bridge already are. The
funnel reads each backend's `egress_substitution_transport()` for the one
mechanism difference. After this, there is no per-backend copy to diverge.

Why this is the whole guarantee:

1. **No silent gaps.** A backend can only reach the workload path by being
   a `WorkloadBackend`, and the funnel — not the backend — applies every
   core enforcement. A backend cannot skip a funnel step; it does not own
   that code. The lone per-backend seam is a no-default method, so it
   cannot be omitted either.
2. **New features propagate by force.** A new core enforcement is added to
   the funnel once and applies to every workload backend at once; a new
   per-backend seam is a no-default method that breaks compilation until
   every workload backend fills it in.
3. **Tier separation is type-enforced.** `qemu` is not `WorkloadBackend`,
   so the type system bars it from the untrusted workload path. (`mock`
   implements it as the hermetic test double — ADR-045 — but never carries
   a real workload.)

## Deliberately NOT built (record so it is not re-added)

The first design iterations grew a `BackendCapabilityMatrix`,
`Support`/`TierEffect` enums, a per-backend `CoreWitnesses` manifest, and
an `xtask` witness gate. All of it was dropped. Reasons:

- A capability matrix with a `DeliberatelyUnsupported` cell is
  *documentation of a hole*, not prevention of one — the opposite of the
  goal for a core feature.
- The witness gate guards a *secondary* failure (a method implemented as a
  no-op), not the actual gap (a *missing* method). The compiler handles
  the actual gap for free.

If a no-op body ever becomes a real concern, the answer is not a witness
registry — see "Future options" below.

## The one honest limitation

The compiler forces the marker and the per-backend seam to *exist*; the
funnel guarantees the shared steps are *applied*. What neither forces is
that a seam's returned transport actually enforces — a backend could return
an inert transport. That is acceptable: it is **one visible, deliberate
line in that backend's file**, reviewable and covered by that backend's
tests, versus today's *invisible absence* scattered across start paths.
Catching an inert seam is a code-review and test concern, not an
architecture one. (If it ever becomes a real problem, the answer is the
witness gate — see "Future options" — not reintroducing the matrix.)

## Consequence for egress secret substitution (intentional)

Moving substitution into the funnel and making the per-backend transport a
no-default `WorkloadBackend` method **reclassifies the macOS substitution
port from optional to required**: once the seam method lands, vz and
libkrun will not compile without a real transport. This reverses the Plan
97 closeout's framing of substitution as an optional fast-follow. The
Sprint 55 "vz at parity with libkrun" verdict stays true (both lack it
today and both must gain it), but the gap becomes a *build failure*, which
is the point.

Sequencing keeps the tree green throughout:

- **Phase 1 — type-bar the funnel (executable now).** `WorkloadBackend`
  starts as a pure marker. `FirecrackerBackend`/`LibkrunBackend`/
  `VzBackend` implement it; `qemu`/`mock` do not. Retype the admitted
  launch dispatch to `&dyn WorkloadBackend`. This lands the structural
  keystone — every workload backend reaches the launch path only through
  the shared funnel, and the tier split is type-enforced — with no behavior
  change and no new mechanism. Low-risk, no design gaps.
- **Phase 2 — funnel-ize substitution + build it on macOS (design spike
  first).** Phase 2 opens with a design spike (see below) because the macOS
  terminator is not yet designed. Then: lift `spawn_substitution_endpoint`
  into the funnel, add the no-default `egress_substitution_transport()`
  seam, implement it for Firecracker (existing nft mechanism) and for
  libkrun/vz (the new macOS transport), all in one change so the no-default
  method never exists without an implementation.

**Phase 2 design spike — must resolve before any Phase 2 code:**
- The portable half (the vsock substitution *channel*) is tractable from
  existing parts: the endpoint already supports `EndpointTransport::Uds`,
  and the macOS supervisors already bridge guest vsock ports to host unix
  sockets — Phase 2 adds a bridge hop for `SUBSTITUTION_PORT` (5253).
- The transparent **:80/:443 terminator** half is undesigned and
  **entangles with the in-flight rvproxy gateway migration (ADR-082)**: on
  macOS there is no nft REDIRECT, so the terminator must live at the
  gateway layer — plausibly *in* the new Rust gateway (rvproxy) rather than
  bolted onto gvproxy, which is being replaced. The spike decides:
  terminator-in-rvproxy vs. a standalone macOS terminator, and how
  guest :80/:443 is steered to it. Its output is the executable Phase 2
  task list.

## Future options (deferred, recorded)

- **Every backend enforces (close the Tier-2 carve-out).** Collapse the
  funnel obligation onto `VmBackend` so even `qemu` must enforce egress.
  More absolute, but reopens ADR-002's settled Tier-2 decision and forces
  enforcement onto a dev/test backend carrying no untrusted workload.
  Not now.
- **Witness gate (no-op-proofing).** If an inert seam ever ships, add an
  `xtask` gate asserting each workload backend's transport is exercised by
  a real test — reusing the existing `check-claim-catalog` machinery.
  Cheaper and more targeted than a capability matrix. Adopt only if the
  problem is real.

## ADR touchpoint

ADR-002's per-backend tier matrix currently describes the workload /
non-workload split in prose. This design makes that split a type
constraint (`WorkloadBackend`). An ADR amendment (next free number) should
record that the Tier-2 carve-out for `qemu` is now type-enforced and that
core security features are a compile-time obligation on workload backends.

## Implementation outline (the companion plan expands this into TDD tasks)

**Phase 1 — type-bar the funnel (executable now): ✅ IMPLEMENTED** on
`feat/plan-197-workload-backend`; spec + quality reviewed; workspace build /
clippy / nightly-fmt green. Pending merge.

> **Refinement during implementation:** the original plan barred *both*
> `qemu` and `mock`. CI's Test lane caught that barring `mock` broke the
> ADR-045 hermetic lifecycle tests (which drive the admitted launch+audit
> path through `MockBackend`, no real VM). `mock` carries no real workload,
> so it is now a permitted `WorkloadBackend` (the test double); `qemu` (a
> real dev/test VMM) remains the meaningful carve-out. The bite-sized task
> code blocks below predate this refinement (they show `mock` barred) — the
> shipped code permits `mock` and bars only `qemu`.

- [x] Define `WorkloadBackend: VmBackend` (marker, no methods yet).
- [x] `impl WorkloadBackend` for Firecracker / libkrun / vz + `mock` (the
      ADR-045 test double); deliberately not for `qemu`.
- [x] Type-bar the admitted launch path: `AnyBackend::as_workload_backend`
      (exhaustive match) + `require_workload_backend` guard wired into all
      three admitted `up.rs` launch arms; `qemu`/`mock` refused before
      `.start()`. (Coverage verified incl. the warm-claim path, which is
      structurally workload-only.) Note: the "compile-fail" guarantee is the
      `as_workload_backend` `None` arm + the marker bound, not a trybuild case.
- [x] `BackendSecurityProfile` decision: kept **advisory** (drives `doctor`
      posture); enforcement is the type-bar. Recorded in its doc comment.
- [x] ADR amendment: ADR-083 added; ADR-002 tier matrix cross-refs it.

**Phase 2 — funnel-ize substitution + macOS build (spike ✅ done — see Task 7):**
- [x] Design spike: resolved. Terminator → rvproxy (not gvproxy/standalone);
      Phase 2 splits into **2a** (vsock substitution channel, mvm-side, ready)
      and **2b** (transparent :80/:443 terminator, rvproxy-gated, cross-repo).
- [ ] **Phase 2a (Task 8):** register `SUBSTITUTION_PORT` 5253 on libkrun + vz
      supervisors; add `egress_substitution_transport()` seam (FC = nft/TCP,
      macOS = `Uds` vsock-5253 channel); lift substitution into the funnel.
- [ ] **Phase 2b (Task 9):** rvproxy gains transparent :80/:443 interception
      (cross-repo requirement); then wire the macOS terminator transport.

## Testing

- Conversion test (Phase 1): `as_workload_backend` returns `Some` for
  FC/libkrun/vz and `None` for `qemu`/`mock`; `require_workload_backend`
  refuses the latter with a typed error.
- Phase 1 introduces **no behavior change** — the existing `up.rs` admitted
  launch suite must stay green after the guard is wired.
- Phase 2 (after the spike): per-backend behavior parity tests for the
  `egress_substitution_transport` seam, and a macOS-26 live test that a
  `SecretRef` workload on vz sees only the placeholder.

---

# Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:subagent-driven-development`
> (recommended) or `superpowers:executing-plans` to implement task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make it structurally impossible for a workload-bearing backend to
skip the shared security funnel, and close the egress-substitution gap by
moving substitution into that funnel.

**Architecture:** A `WorkloadBackend: VmBackend` marker gates the admitted
launch path (`&dyn WorkloadBackend` only); `qemu`/`mock` cannot satisfy it.
Substitution moves from per-backend `start()` into the shared funnel
(Phase 2), with the one per-backend mechanism difference behind a no-default
seam method.

**Tech stack:** Rust, `cargo nextest`, the existing `AnyBackend` enum
dispatch in `crates/mvm-backend/src/backend.rs`.

## Phase 1 — type-bar the funnel (executable now, no behavior change)

### Task 1: `WorkloadBackend` marker trait + impls

**Files:**
- Create: `crates/mvm-backend/src/workload_backend.rs`
- Modify: `crates/mvm-backend/src/lib.rs` (add `pub mod workload_backend;` + re-export)

- [ ] **Step 1 — write the trait + a compile-assertion test (will fail to compile).**

```rust
//! `WorkloadBackend`: the type-level permission to carry an untrusted
//! workload. Only backends that go through the full enforcement funnel
//! implement it; the admitted launch path accepts `&dyn WorkloadBackend`
//! only, so a non-workload backend cannot reach it.
use crate::backend::{FirecrackerBackend, LibkrunBackend, VzBackend};
use mvm_core::protocol::vm_backend::VmBackend;

pub trait WorkloadBackend: VmBackend {}

impl WorkloadBackend for FirecrackerBackend {}
impl WorkloadBackend for LibkrunBackend {}
impl WorkloadBackend for VzBackend {}

#[cfg(test)]
mod tests {
    use super::*;
    fn assert_is_workload_backend<T: WorkloadBackend>() {}

    #[test]
    fn workload_backends_implement_the_trait() {
        assert_is_workload_backend::<FirecrackerBackend>();
        assert_is_workload_backend::<LibkrunBackend>();
        assert_is_workload_backend::<VzBackend>();
    }
}
```

- [ ] **Step 2 — run, expect a compile error** if the concrete type paths are
      wrong (adjust the `use` paths to the real definitions in
      `backend.rs`), otherwise PASS. Run: `cargo nextest run -p mvm-backend workload_backends_implement`
- [ ] **Step 3 — wire the module.** In `crates/mvm-backend/src/lib.rs` add
      `pub mod workload_backend;` and `pub use workload_backend::WorkloadBackend;`.
- [ ] **Step 4 — run.** Run: `cargo nextest run -p mvm-backend workload_backends_implement` → PASS.
- [ ] **Step 5 — commit.** `git add -A && git commit -m "feat(backend): add WorkloadBackend marker trait"`

### Task 2: `AnyBackend::as_workload_backend`

**Files:**
- Modify: `crates/mvm-backend/src/backend.rs` (in the `impl AnyBackend` block, near `as_vm_backend` at ~:483)

- [ ] **Step 1 — write the failing test** (in `backend.rs` `#[cfg(test)]`):

```rust
#[test]
fn workload_backends_convert_and_qemu_mock_do_not() {
    assert!(AnyBackend::Firecracker(FirecrackerBackend).as_workload_backend().is_some());
    assert!(AnyBackend::Libkrun(LibkrunBackend).as_workload_backend().is_some());
    assert!(AnyBackend::Vz(VzBackend).as_workload_backend().is_some());
    assert!(AnyBackend::Qemu(QemuBackend).as_workload_backend().is_none());
    assert!(AnyBackend::Mock(MockBackend::default()).as_workload_backend().is_none());
}
```

- [ ] **Step 2 — run, expect FAIL** (method missing). Run:
      `cargo nextest run -p mvm-backend workload_backends_convert`
- [ ] **Step 3 — implement** in `impl AnyBackend`:

```rust
/// Borrow as `&dyn WorkloadBackend` — `Some` only for backends permitted
/// to carry an untrusted workload. The exhaustive match means a new
/// `AnyBackend` variant forces an explicit workload/non-workload decision
/// here (compile error otherwise).
pub fn as_workload_backend(&self) -> Option<&dyn crate::workload_backend::WorkloadBackend> {
    match self {
        AnyBackend::Firecracker(b) => Some(b),
        AnyBackend::Libkrun(b) => Some(b),
        AnyBackend::Vz(b) => Some(b),
        AnyBackend::Qemu(_) | AnyBackend::Mock(_) => None,
    }
}
```

- [ ] **Step 4 — run** → PASS.
- [ ] **Step 5 — commit.** `git commit -am "feat(backend): AnyBackend::as_workload_backend conversion boundary"`

### Task 3: the launch guard

**Files:**
- Modify: `crates/mvm-backend/src/workload_backend.rs`

- [ ] **Step 1 — write the failing test:**

```rust
#[test]
fn require_workload_backend_refuses_non_workload() {
    use crate::backend::AnyBackend;
    let err = require_workload_backend(&AnyBackend::Qemu(crate::backend::QemuBackend))
        .unwrap_err()
        .to_string();
    assert!(err.contains("not a workload backend"), "got: {err}");
    assert!(require_workload_backend(&AnyBackend::Firecracker(crate::backend::FirecrackerBackend)).is_ok());
}
```

- [ ] **Step 2 — run, expect FAIL** (fn missing).
- [ ] **Step 3 — implement** in `workload_backend.rs`:

```rust
use anyhow::{Result, anyhow};
use crate::backend::AnyBackend;

/// The single boundary the admitted launch path goes through. Returns the
/// backend as `&dyn WorkloadBackend` or a typed refusal for Tier-2 / test
/// backends that must never carry an untrusted workload.
pub fn require_workload_backend(backend: &AnyBackend) -> Result<&dyn WorkloadBackend> {
    backend.as_workload_backend().ok_or_else(|| {
        anyhow!(
            "backend `{}` is not a workload backend — Tier-2/test backends \
             cannot carry an untrusted workload",
            backend.name()
        )
    })
}
```

- [ ] **Step 4 — run** → PASS.
- [ ] **Step 5 — commit.** `git commit -am "feat(backend): require_workload_backend launch guard"`

### Task 4: route the admitted launch arms through the guard

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/up.rs` (the admitted-launch `backend.start(&start_config)` arms at ~:1589, ~:2154, ~:2419)

- [ ] **Step 1 — write a failing CLI-level test** asserting an admitted launch
      on a non-workload backend is refused before `start`. Add to the existing
      `up.rs` tests (mirror the nearby admitted-launch test harness):

```rust
#[test]
fn admitted_launch_refuses_non_workload_backend() {
    let backend = mvm_backend::backend::AnyBackend::Qemu(mvm_backend::backend::QemuBackend);
    let err = require_workload_backend(&backend).unwrap_err().to_string();
    assert!(err.contains("not a workload backend"));
}
```

- [ ] **Step 2 — run, expect FAIL** until the import + guard are wired. Run:
      `cargo nextest run -p mvm-cli admitted_launch_refuses_non_workload`
- [ ] **Step 3 — wire the guard at each admitted arm.** Immediately before each
      admitted `backend.start(&start_config)` (lines ~1589, ~2154, ~2419), add:

```rust
// Type-bar: only a WorkloadBackend may run an admitted workload.
let _workload = mvm_backend::workload_backend::require_workload_backend(&backend)?;
```

      (Keep the existing `backend.start(...)` call — the guard returns early on
      qemu/mock; the `_workload` binding documents the boundary. Do NOT add the
      guard to dev-only/non-admitted arms.)

- [ ] **Step 4 — run** the new test + the existing `up.rs` suite → PASS:
      `cargo nextest run -p mvm-cli`
- [ ] **Step 5 — commit.** `git commit -am "feat(cli): route admitted launch through the WorkloadBackend guard"`

### Task 5: `BackendSecurityProfile` decision (record, minimal code)

**Files:**
- Modify: `crates/mvm-core/src/protocol/vm_backend.rs` (doc comment on `BackendSecurityProfile`)

- [ ] **Step 1 — record the decision in a doc comment**: the frozen
      `claims: [ClaimStatus; 7]` array stays *advisory* for `doctor` display;
      the *enforcement* guarantee now lives in the `WorkloadBackend` type-bar,
      not this array. (No behavior change; this prevents a future reader from
      mistaking the array for the enforcement.)
- [ ] **Step 2 — run** `cargo nextest run -p mvm-core` → PASS (doc-only).
- [ ] **Step 3 — commit.** `git commit -am "docs(core): clarify BackendSecurityProfile is advisory; enforcement is the WorkloadBackend type-bar"`

### Task 6: ADR amendment

**Files:**
- Create: `specs/adrs/083-workload-backend-type-bar.md` (confirm 083 is free via `ls specs/adrs/`)
- Modify: `specs/adrs/002-microvm-security-posture.md` (per-backend tier matrix note)

- [ ] **Step 1 — write ADR-083**: core security enforcement is a compile-time
      obligation on workload backends; ADR-002's Tier-2 carve-out for `qemu`
      is now type-enforced via `WorkloadBackend` rather than prose. Cross-link
      from ADR-002's tier matrix.
- [ ] **Step 2 — run** `cargo run -p xtask -- check-spec-numbers` → PASS.
- [ ] **Step 3 — commit.** `git commit -am "docs(adr-083): type-enforced workload tier split"`

## Phase 2 — funnel-ize substitution + macOS build

### Task 7: design spike — ✅ DONE

The spike resolved both questions and **splits Phase 2 into a mvm-buildable
half (2a) and an rvproxy-gated half (2b).** Findings:

**The substitution mechanism has two halves; only one is mvm-side.**
- **Explicit channel (the vsock substitution channel).** The guest receives
  `HTTP_PROXY` + placeholders and dials `SUBSTITUTION_PORT` (5253) over
  AF_VSOCK; the host endpoint injects the real credential. This is fully
  buildable in mvm on macOS:
  - The endpoint already supports `EndpointTransport::Uds { path }`
    (`substitution_endpoint.rs`); on Linux/QEMU it uses `Vsock`, FC uses the
    per-port vsock→Uds proxy.
  - macOS supervisors already bridge each guest vsock port to a host unix
    socket at the `<vm_state_dir>/vsock-<port>.sock` convention
    (`mvm_core::config`), e.g. the agent on 5252.
  - **The only gap:** neither the libkrun nor vz supervisor registers port
    **5253**, and the backend never spawns the endpoint with the `Uds`
    transport pointing at `vsock-5253.sock`. That is the whole Phase 2a wiring.
- **Transparent :80/:443 terminator.** On Linux this is an nft PREROUTING
  REDIRECT (`egress_redirect.rs`, per-VM table, `iifname`-scoped) → a host
  TCP terminator on `0.0.0.0:<18080+slot>`. **macOS has no nftables, and the
  in-process bridge only sees post-gateway L2 frames — so the terminator
  cannot live mvm-side.** It must live in the userspace gateway's TCP/IP
  stack. gvproxy is vendored Go being retired, so the terminator belongs in
  **rvproxy** (the in-house Rust gateway — ADR-082 / Plan 193), where it also
  composes with rvproxy's native flow API. This is Phase 2b and is gated on
  rvproxy + a cross-repo requirement.

**Decision:** terminator → rvproxy (not gvproxy, not a standalone macOS
process). The explicit vsock channel ships first, independently.

### Task 8 (Phase 2a — vsock substitution channel; mvm-side, ready)

- [ ] Register `SUBSTITUTION_PORT` (5253) on the libkrun supervisor
      (`.add_vsock_port`) and the vz supervisor (`vz_objc.rs` bridge hop) so
      the guest→host channel lands at `<vm_state_dir>/vsock-5253.sock`.
- [ ] Add the no-default `egress_substitution_transport()` seam to
      `WorkloadBackend`; Firecracker returns its existing nft/TCP terminator
      transport, libkrun/vz return the `Uds { path: vsock-5253.sock }` channel
      transport (terminator absent until Phase 2b).
- [ ] Lift `spawn_substitution_endpoint` / `reap_substitution_endpoint` from
      `qemu.rs` + `microvm.rs` `start()` into the shared admitted-launch funnel;
      the funnel reads `egress_substitution_transport()` per backend.
- [ ] Live-validate on macOS-26: a `SecretRef` workload on `--hypervisor vz`
      with an explicit `HTTP_PROXY` sees only the placeholder; the host
      endpoint injects the real credential over the vsock channel.

### Task 9 (Phase 2b — transparent :80/:443 terminator; rvproxy-gated, cross-repo)

- [ ] **rvproxy requirement (separate repo):** rvproxy must support a
      transparent :80/:443 interception → host terminator port (the macOS
      analogue of the nft REDIRECT). Add this to rvproxy's mvm-adoption
      requirements; it is gated on the rvproxy migration (Plan 193 / ADR-082).
- [ ] Once rvproxy lands it: extend the macOS `egress_substitution_transport()`
      to carry the terminator endpoint, and wire the gateway to steer guest
      :80/:443 to it. Live-validate transparent (non-proxy-aware) egress
      substitution on vz/libkrun.
