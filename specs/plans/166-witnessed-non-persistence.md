# Plan 166 — Promote the cold-state guarantee to a witnessed non-persistence claim

**Source post:** *MicroVMs for Agent Sandboxing in Regulated Environments*
(kondasamy.com, 2026). The post argues the single thing microVMs give you
that containers cannot is **hardware-enforced data isolation between
sessions**, and that the load-bearing demo for a regulated buyer is:
*"when the session ends, the microVM is destroyed, filesystem gone — prove
the next session inherits no residual data."*

**Companion docs:** [`specs/adrs/002-microvm-security-posture.md`](../adrs/002-microvm-security-posture.md) §"cold-state guarantee" · [`specs/adrs/041-signed-audited-execution-plans.md`](../adrs/041-signed-audited-execution-plans.md) `post_run.destroy_on_exit` · [`specs/claims/claim-10-oci-image-provenance.md`](../claims/claim-10-oci-image-provenance.md) (the Planned→Preview→Shipped promotion precedent we mirror) · [`specs/plans/111-cardoso-gap-coordination.md`](111-cardoso-gap-coordination.md) Workstream B (snapshot/restore lifecycle — sibling).

## Goal

Convert the **cold-state guarantee** from a *structural property that is
explicitly not CI-gated* into a **witnessed, numbered security claim** with
a test in `specs/claims/catalog.md`. Today ADR-002 says the per-workload
fresh-boot / no-warm-pool property "is not in the table because it is not a
single CI gate; it is a structural property of the runtime." The blog's
auditor framing is correct that this is the property a regulated reviewer
most wants *demonstrated*, not asserted. This plan makes it demonstrable.

This is the cheapest credibility upgrade available: it converts "trust our
design" into "here is the test that fails if a run leaves residual state."

## Scope boundary (read first)

- **Per-workload non-persistence only.** mvm's model is *one guest = one
  workload*; ADR-002 lists "Multi-tenant guests" as out of scope. The claim
  this plan adds is strictly: *a workload's runtime state does not survive
  its own teardown, and the next boot on the same host is fresh.* It is
  **not** a between-tenant isolation claim.
- **Concurrent-session / cross-tenant residual-data isolation is mvmd's.**
  Fleet multiplexing (pools, instances, session reuse across tenants) lives
  in the mvmd repo. Do not add a multi-tenant claim here; if mvmd wants the
  cross-session version, it owns that witness.
- **No hypervisor/DRAM memory-zeroing claim.** "Memory zeroed" in the blog
  is a hardware/hypervisor property (guest RAM is freed by the VMM on exit).
  mvm does not control DRAM scrubbing and ADR-002 already scopes out "a
  malicious host." This claim witnesses **state-dir / overlay / warm-pool
  destruction at the mvm layer**, not physical memory sanitization. Say so
  explicitly in the claim text so it is not over-read.

## Why a new claim and not just prose

ADR-002 already documents the property; the gap is purely that nothing
*breaks* when it regresses. A future change that introduced a warm pool, or
left a `vm_state_dir` overlay on disk after exit, would pass CI today. The
catalog's machine-checked witness (`xtask check-claim-catalog`) is what
turns the property into a regression guard.

## Tasks

### Task 1 — Locate and pin the teardown contract

- [ ] **Step 1 — map the lifecycle.** Trace the `mvmctl run` / `mvmctl up`
  exit path through the `mvm` runtime crate and `AnyBackend::stop` /
  `VmBackend` teardown. Identify exactly what is created per run
  (`mvm_core::config::vm_state_dir(...)` and siblings — overlay, vsock
  socket, pid file) and what removes them on exit. Confirm the default is
  destroy-on-exit and that no warm-pool / reuse path exists on the
  `mvmctl run` lifecycle.
- [ ] **Step 2 — reconcile with ADR-041.** `post_run.destroy_on_exit: true`
  is a *future* `ExecutionPlan` field (ADR-041, "W5"). Decide whether the
  witness asserts the structural default (no reuse path exists) or the
  plan-driven field once it lands. The structural default is witnessable
  now and is the right first target; note the field as a follow-on.

### Task 2 — Author the witness test(s) (implementation — later)

- [ ] **Step 3 — write the test.** Add a test (proposed names, pick at
  implementation time) asserting:
  - `fn:run_teardown_removes_state_dir` — after a workload `stop`, its
    `vm_state_dir` (overlay, sockets, pid) is gone; a fresh run gets a new
    dir, not the previous one's contents.
  - `fn:no_warm_pool_reuse_on_run_path` — the `mvmctl run` lifecycle has no
    branch that reuses a prior guest's rootfs/overlay/memory; each
    invocation boots a fresh guest.
  Use the mock backend (`MockBackend`) for the lifecycle assertions so the
  test is host-independent and runs under `cargo nextest run --workspace`.
  Add a per-backend note for where the real (`AnyBackend`) teardown is
  exercised.
- [ ] **Step 4 — fuzz/negative not required.** This is a lifecycle/state
  invariant, not a parser surface; a positive teardown assertion + a
  "reuse path absent" assertion are sufficient. No `cargo-fuzz` target.

### Task 3 — Wire the claim into the ledger (implementation — later)

- [ ] **Step 5 — catalog entry.** Add a row to `specs/claims/catalog.md`
  mirroring the existing format
  (`| # | Claim | Witnesses | Authority | Status |`):
  - **Claim:** "A workload's runtime state does not survive its own
    teardown; each `mvmctl run` boots a fresh guest with no warm-pool reuse."
  - **Witnesses:** `fn:run_teardown_removes_state_dir`,
    `fn:no_warm_pool_reuse_on_run_path`.
  - **Authority:** "cold-state / non-persistence (ADR-002 §cold-state;
    ADR-041 `post_run`)".
  - **Status:** `Shipped` once the witnesses exist; until then track it as
    `Planned` the way `claim-10-oci-image-provenance.md` did.
  - **Number:** **do not hard-assign.** The catalog shows 15 as next-free on
    `main`, but Plan 165 (in-flight) earmarks claim 15 for the
    entrypoint/console sealed-prod claim. Assign the number at promotion,
    after reconciling open PRs — exactly as OCI provenance waited for slot
    14.
- [ ] **Step 6 — promote in ADR-002.** Flip the cold-state paragraph from
  "not a single CI gate; structural property" to "witnessed by claim N
  (`fn:…`)", bump the `revised:` date, and add a one-line revision note in
  `## Status`. (This plan's companion pass authors the *pending* form of
  that amendment — see "Doc-only deliverables" below.)

## Doc-only deliverables in this pass

This pass writes **docs only** — `specs/plans/` (this file) and
`specs/adrs/`. Concretely:

- This plan.
- An ADR-002 amendment that records the **decision** to promote cold-state
  to a witnessed claim and marks it **pending the Plan 166 witness** — it
  does *not* yet assert a CI gate that does not exist (that would be a false
  claim and would not survive `xtask check-claim-catalog`). Tasks 2–3 (the
  test, the catalog row, the final numbered promotion) are deferred to an
  implementation PR.

## Verification (when Tasks 2–3 land)

- `cargo nextest run --workspace` runs the new lifecycle test(s) host-independently.
- `cargo run -- xtask check-claim-catalog` passes (every named witness resolves).
- Manual demo for the auditor narrative: `mvmctl run …` a workload, record
  its `vm_state_dir`; after exit, confirm the dir is gone and a second run
  allocates a distinct dir. This is the "prove no residual data" demo in
  concrete form.

## Deferred follow-ups

- [ ] **Cross-tenant / session-reuse residual-data isolation** — mvmd's
  fleet layer; file there, not here.
- [ ] **Plan-driven `post_run.destroy_on_exit`** — witness the ADR-041 field
  once implemented (Task 1 Step 2), in addition to the structural default.
- [ ] **Snapshot/restore × non-persistence** — restoring from a snapshot is
  the one path that deliberately reintroduces prior state; its interaction
  with this claim (and entropy reuse, admission continuation) is Plan 111
  Workstream B / the warm-snapshot work (Plan 157 / ADR-072), not this claim.
- [ ] **Hypervisor/DRAM memory scrubbing** — explicitly out of scope (host
  is trusted; ADR-002). Do not let the claim text imply physical zeroing.
