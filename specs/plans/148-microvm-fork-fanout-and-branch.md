# Plan 148 — MicroVM fork fan-out + live BRANCH (fork/snapshot-sibling-inspired)

> Number 148 is the next free integer (145–147 are claimed: 145 app-deps-completion
> on `main`, 146 cloud-hypervisor-tier1-parity, 147 portable-runnable-artifacts).
> `xtask check-spec-numbers` is a Lint gate — re-confirm 148 is still free against
> open PRs + `main` before merge and renumber if taken.

## Context

The closest public sibling to mvm — a Rust Firecracker-microVM fork/snapshot tool
for AI-agent sandboxing with an explicit security posture (referred to obliquely per
[[feedback_no_competitor_names_anywhere]]; trait key in auto-memory
`reference_external_sandbox_control_plane_oblique_key`) — has one genuinely novel
mechanism: **fork fan-out** — pause a *warmed* parent, then
spawn N children as separate Firecracker processes that `mmap` the parent's memory
image `MAP_PRIVATE`, so the kernel does page-level copy-on-write and children share
the parent's resident RAM until they diverge ("100 microVMs in 101 ms," full KVM
isolation, fork-like spawn cost). Its second feature is **BRANCH** — pause a
*running* VM mid-execution and spawn divergent children inheriting in-flight state
(speculative agent branching).

mvm already does single-VM warm restore: `instance/snapshot.rs` stores a pool-level
base `mem.bin`/`vmstate.bin` and per-instance deltas; `instance_wake`
(`lifecycle.rs:604`) restores and resumes one instance. Plan 123 Phase C builds the
Firecracker UFFD/NBD/hugepages fast-resume substrate; Plan 140 closes the four
restore-correctness gaps (seccomp, entropy reseed, clock resync, wake-admission).
**What's missing is the fan-out: many children from one warm parent, and a
live-branch of a running workload.** That is the sibling's delta, and the agent
fan-out use case (parallel rollouts, code-interpreter swarms, SWE-bench evals) is
squarely mvm/mvmd territory.

**Decision up front — no vendored Firecracker.** The sibling vendors a patched
Firecracker branch to expose `mmap MAP_SHARED` on a memfd-backed *live* parent. That collides with three standing principles: keep VMM
specifics behind the backend trait (the trick is Firecracker/x86_64/Linux-only,
with no libkrun/Vz/AppleContainer analogue); replace a problematic dep rather than
maintain a fork against upstream; and don't pay a vendored-hypervisor tax for a win
we haven't measured as necessary. This plan therefore splits the two features by
how much they cost:

- **Phase A (fan-out from a *frozen* base)** needs no fork. N children stream their
  read-only base pages from **one shared content-addressed memfile via the OS page
  cache** (the base is resident once; each child COWs only divergent pages through
  its own `userfaultfd` handler). This reuses Plan 123 C2's substrate and delivers
  the "many-from-one" win on stock Firecracker.
- **Phase B (live BRANCH of a *running* parent)** is the part that genuinely wants a
  live shared-memory parent. Scoped here as a **bounded spike with a go/no-go**, not
  a commitment to vendoring.

Backend scope: Firecracker / cloud-hypervisor (`caps.snapshots == true`). Vz gets a
coarser save/restore-based fan-out (Phase A only, no live BRANCH). libkrun +
apple-container report `snapshots == false` — fan-out is N disk-snapshot cold-boots
there (Plan 139's shaving), surfaced honestly, never silently degraded.

**Prereqs:** Plan 123 Phase C (the UFFD/NBD/hugepages fast-resume substrate +
`snapshot_capability()` enum) and Plan 140 (the on-resume hook + wake-admission +
entropy/clock reseed). This plan **must sequence after both** — it is the fan-out
layer on top of a correct single-VM restore. Do not start it before 120's
`core_demo_e2e` is green and 123 C2 + 140 have landed.

## Phase A — fork fan-out from a frozen base (no vendored Firecracker)

The capability: from one warmed, paused base snapshot, spawn N children in a single
batched call, each fully isolated and security-correct, with the base RAM resident
once instead of N times.

### Task A1: shared read-only base memfile backing

Today `restore_snapshot` points each Firecracker at the base `mem.bin`; N restores
means N independent reads of a 1–4 GiB file. Back the base with a single
content-addressed, read-only memfile so all children's UFFD handlers fault against
the *same* page-cache pages; per-child writes go to a private COW overlay.

**Files:** `crates/mvm/src/vm/instance/snapshot.rs` (base memfile materialization),
the Plan 123 C2 `userfaultfd` page-fault handler.

- [ ] **Step 1:** Failing test — two children restored from one base read the same
      base pages (assert the base memfile is opened read-only/shared, one inode), and
      a write in child A is not visible in child B (private COW overlay).
- [ ] **Step 2:** Materialize the base mem image as a content-addressed read-only
      memfile (reuse Plan 123 C2's content-addressed memfile + signing, Plan 122 C);
      each child's UFFD handler faults shared base pages and writes private dirty
      pages to its own overlay. 2 MiB hugepages for the base per 123 C2. Commit.

### Task A2: batched fan-out spawn primitive

One call that spawns N children from a base, each getting the fresh per-instance
identity the single-restore path already mints (`lifecycle.rs:582-596`: fresh
secrets disk, config drive, unique IP/ID, cgroup).

**Files:** `crates/mvm/src/vm/instance/lifecycle.rs` (a `fork_fanout` over the
existing `instance_wake` body), `crates/mvm-core/src/protocol/vm_backend.rs` (a
fan-out capability surfaced on `VmCapabilities`).

- [ ] **Step 1:** Failing test — `fork_fanout(base, n)` returns N running instances
      with N distinct guest IPs/instance-IDs/secrets disks and N distinct cgroups;
      partial failure (child k fails) tears down only k's resources, not the batch.
- [ ] **Step 2:** Factor the per-instance setup out of `instance_wake` into a
      `spawn_child_from_base` and call it N times against the shared base (A1).
      Bound concurrency; fail-closed per child. Commit.

### Task A3: per-child divergence is security-correct (reuse Plan 140)

Each child is a *new workload*, not a clone that inherits the parent's secrets. Plan
140's on-resume hook already mints fresh entropy + clock + VMGenID and re-admits a
signed plan on wake — fan-out **must** invoke it once per child, never amortize it.

**Files:** the Plan 140 on-resume hook (`GuestRequest::Resume { unix_time_ms,
entropy_seed }`), `crates/mvm-core` plan/audit (`synthesize_plan` / `admit_for_run`
/ `AuditEmitter`).

- [ ] **Step 1:** Failing tests — N children from one base produce N **different**
      `/dev/random` draws (no shared-base RNG state); each child rotates VMGenID; each
      child emits its own `plan.launched` chain entry under a **fresh nonce** (no
      nonce reuse across the batch — would trip the G4 replay store); seccomp filter
      on each restored FC process is non-None (Plan 140 gap #1).
- [ ] **Step 2:** Wire the on-resume hook + wake-admission into `spawn_child_from_base`
      so a child cannot reach `Running` without its own admission + ACK'd reseed
      (bounded timeout, fail-closed). `verify_audit_chain` passes across a fan-out.
      Commit.

### Task A4: per-backend fan-out disposition + doctor

- [ ] **Step 1:** Failing test — fan-out reports `SharedBaseCoW` for Firecracker/CH,
      `SaveRestoreClone` for Vz (macOS 26+: N save/restore clones, no shared-page
      backing), `DiskColdBoot` for libkrun/apple-container (N cold boots from the
      disk snapshot, Plan 139); an unsupported live-memory fan-out returns the typed
      error with a recovery hint (ADR-053), never a silent cold-boot.
- [ ] **Step 2:** Extend the Plan 123 C1 `snapshot_capability()` enum with the
      fan-out disposition; `doctor` reports it per backend alongside warm-start.
      Commit.

## Phase B — live BRANCH (bounded spike, go/no-go)

Branching a **running** parent into divergent children inheriting in-flight state is
the sibling's speculative-branch feature and the one piece that wants a live shared-memory
parent. This phase is investigation, not a vendoring commitment.

### Task B1: feasibility spike on stock Firecracker

- [ ] **Step 1:** Measure stock Firecracker's pause → Diff-snapshot → resume window
      on a representative running workload (warmed deps, ~1–4 GiB RSS) at the dirty-
      page volumes a mid-execution branch produces. The sibling's own numbers: full-copy
      branch was 29.3 s, diff-snapshot dropped it to 205 ms, async UFFD_WP live mode
      to 56 ms. The question for us: **is upstream Firecracker's Diff snapshot
      pause-window acceptable** (children restore via Phase A's shared-base path from
      the branch point), or is a live shared-memory parent actually required?
- [ ] **Step 2:** Write the findings into the ADR (below) with a **go/no-go**: if the
      Diff-snapshot window is acceptable, BRANCH is just "snapshot a running VM, then
      Phase A fan-out from that snapshot" — no new mechanism. If not, B2.

### Task B2 (gated on B1 = no-go): scoped live-parent investigation

- [ ] **Step 1:** Only if B1 shows upstream is insufficient: evaluate the live
      shared-memory parent **as a Firecracker-backend-only optional capability flag**,
      behind the backend trait, never a core assumption. Weigh upstreaming the memfd
      `MAP_SHARED` change vs. the maintenance cost of a fork (replace-don't-workaround
      / keep-the-backend-trait apply). Document the recommendation; do **not** land a
      vendored fork without explicit sign-off. The deliverable here is a decision, not
      code.

## ADR

- [ ] Draft `specs/adrs/0NN-microvm-fork-and-branch.md` — the security model for
      forking/branching a workload: per-child divergence is mandatory (entropy,
      VMGenID, clock, fresh admission + nonce — never inherited); a branched child is a
      new admitted workload under ADR-002 claims 1/8/10, not an extension of the
      parent's grant; the no-vendored-Firecracker decision and its rationale; the
      per-backend fan-out matrix. This extends, and should cross-reference, Plan 140's
      wake-admission ADR and ADR-066.

## Files

- `crates/mvm/src/vm/instance/snapshot.rs` — content-addressed read-only base
  memfile; shared backing for N children.
- `crates/mvm/src/vm/instance/lifecycle.rs` — factor `spawn_child_from_base` out of
  `instance_wake` (`:604`); `fork_fanout`; per-child on-resume hook + admission.
- `crates/mvm-core/src/protocol/vm_backend.rs` — fan-out disposition on
  `VmCapabilities` / the Plan 123 `snapshot_capability()` enum.
- `crates/mvm-backend/src/vz.rs` — Vz `SaveRestoreClone` fan-out (macOS 26+).
- Plan 123 C2 UFFD handler — shared-base fault path.
- Plan 140 on-resume hook + `mvm-core` plan/audit — reused per child.

## Verification

- [ ] N children from one warm base spawn with the base RAM resident **once**
      (assert one shared base inode / page-cache footprint, not N×), each isolated:
      distinct IP/ID/secrets/cgroup, divergent writes invisible across children.
- [ ] N children produce N different `/dev/random` draws; each rotates VMGenID; each
      emits its own `plan.launched` under a fresh nonce; `verify_audit_chain` passes
      across a fan-out.
- [ ] Each restored FC process runs under the same seccomp filter as cold boot
      (Plan 140 gap #1 holds under fan-out).
- [ ] Per-backend disposition surfaced by `doctor`; unsupported live-memory fan-out
      returns the typed error, never a silent cold-boot.
- [ ] BRANCH spike (B1) produces a measured go/no-go in the ADR.
- [ ] `cargo fmt --all -- --check`, `cargo clippy --workspace -- -D warnings`,
      `cargo test --workspace` (host tiers) + the gated live-KVM lane green.

## Notes

- **Why this isn't just Plan 123/140 again:** 123 C2 and 140 make *one* VM resume
  fast and correct. This plan makes *N* children share *one* base's resident RAM and
  proves each diverges security-correctly — the fan-out the sibling is built around. The
  single-restore path is the prereq, not the feature.
- **The honest win:** Phase A gives the "many-from-one" amortized-warmup benefit on
  stock Firecracker via page-cache sharing of a frozen base. The sub-ms `mmap`
  fork-of-a-live-parent that needs the vendored hypervisor is deliberately deferred
  to a measured go/no-go (Phase B), because we don't yet know we need it.
- **Where it runs:** the warm-pool orchestration and the *policy* for what a
  fan-out/branch admission requires are mvmd's (fleet) — cross-reference the mvmd
  warm-pool plan. This plan wires the mvm-side fan-out primitive + per-child
  admission call; mvmd decides when and how many.
