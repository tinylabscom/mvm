# Live Firecracker warm-claim slice — design

**Plan 255 Phase 2, follow-on to the merged claim substrate (#1881).**
Companion: `specs/notes/2026-07-27-plan-255-phase2-warm-pool-substrate-design.md`
(the substrate data-flow + guard-layering source of truth). Parent plan:
`specs/plans/255-vsock-first-snapshot-egress-adoption.md`. Tracking: #1851.

## Goal

Make the Firecracker warm pool functional end to end and prove it on a live
KVM host: `spawn_standby` boots a clean factory parent and captures it as a
checkpoint; `claim_standby` forks a fresh, admitted, audited child that
actually boots on real Firecracker. Backend order is FC now, then HVF, then
libkrun.

## CORRECTION (2026-07-28) — this note's original scoping was wrong

The sections below were written against a **stale checkout** and asserted that
Firecracker memory restore was hard-disabled. It is not. Commit `5bfe4c426`
landed the restore un-bail *before* this branch was created:

- `warm_restore_instance_from_path` (`microvm/snapshot.rs:87`) is **live** —
  validates the VM name, runs `guarded_load_resume` (which enforces the no-NIC
  device-model guard between load and resume), and delivers the VMGenID reseed.
- `capture_vm_full` (`checkpoint/mod.rs:545`) and `fork_vm_full_fc` (`:406`)
  are live; `FcForkRestorer` (`firecracker.rs:436`) wires the rename +
  device-anchor remap.
- Only `restore_from_template_snapshot` and the bare `warm_restore_instance`
  remain refused, each needing its own signature/HMAC design.

**Consequence:** this slice does memory restore, not a cold boot. The child
skips kernel boot, init, and agent startup. The authoritative scoping is
`specs/plans/255-live-fc-warm-claim.md`; the two sections below are retained
only to record the superseded reasoning.

## Non-goals (superseded — see the correction above)

- ~~**Sub-second restore.** The child is a **cold boot** from the CoW-cloned
  parent rootfs, not a memory restore.~~ Superseded: restore is live and this
  slice uses it.
- **HVF / libkrun live forks.** Still out of scope — separate follow-on slices.
- **Any change to the guarded-claim core.** Still true: admission, lineage
  verify, CoW rootfs, identity minting, and audit emit are unchanged from the
  substrate.
- **The pre-spawned-VMM optimization, page-cache priming, density, and the
  CI-gated SLO.** These remain Plan 265's; each claim here still starts a fresh
  Firecracker and loads the snapshot into it.

## Why cold-boot first was believed honest (superseded)

The original reasoning: for a read-only dm-verity rootfs a cold-boot claim is
~equivalent to a cached cold boot, so the slice's value was framed as
de-risking rather than speed. That framing was a consequence of the stale read
— with restore live, the slice delivers the actual speedup as well.

## The five pieces

1. **`FcDriver::spawn_standby_parent`** (override the fail-closed default in
   `driver/traits.rs`). Boot a headless parent FC VM → await agent-ready via
   the existing `connect_to_port(GUEST_AGENT_PORT)` loop (`AGENT_READY_TIMEOUT`)
   → quiesce → `capture_fs_quick` → return the recorded `CheckpointId`.
   **Decision (approved): capture a *real* booted parent**, not a checkpoint
   synthesized straight from the content-addressed rootfs. Live-exercising
   boot → ready → capture is the validation value, and it is precisely the
   flow Plan 265 extends (swap `capture_fs_quick` for a memory-carrying
   capture). Cost: one parent boot per pool slot — the honest shape of a
   warm pool.

2. **`FcDriver::fork_standby_child`** (override the fail-closed default in
   `driver/traits.rs`). Cold-boot a fresh FC VM from the CoW-cloned child
   rootfs the runner already materialized (`ChildForkRequest`), with the
   fresh identity (`VmId` + VMGenID) the runner minted. No memory restore.

3. **`parent_checkpoint: CheckpointId` on `StandbyHandle`**
   (`protocol/vm_backend.rs`, `#[serde(default)]` like `image_sha256`) plus
   pool persistence, so a claim can locate the parent's checkpoint to verify
   lineage and materialize the child from it.

4. **CLI live `ClaimContext` assembly.** Open an `FsSnapshotStore`, thread the
   `parent_checkpoint` id, and route `claim_or_cold` / `try_warm_claim`
   (`commands/pool.rs`) through `claim_standby_via_runner` for the FC backend
   (today it calls the parameterless fail-closed `claim_standby`).

5. **Flip the capability — last.** `FcDriver.capabilities().standby_pool =
   true` (`driver/fc.rs`) only once 1–4 populate the pool, and update the
   guarding tests (`no_selectable_driver_advertises_standby_pool_yet`).
   Flipping early regresses a configured pool to a silent cold boot.

## Guard layering (unchanged — enforced off the runner)

Admission (fresh signed `ExecutionPlan`) is CLI + supervisor-layer;
verity-inherit is CLI-side; confinement is guest-init-inherited via the
post-init parent snapshot; the audit emit + replenish are the CLI caller's.
The runner owns only the runner-side host steps and the guarded claim. This
reuses the chain-anchored checkpoint lineage — no second provenance graph.
Never-promote stays structural: parents live under `~/.mvm/pool/`, workloads
under `~/.mvm/vms/`, `StandbySpec`/`StandbyHandle` carry no plan field, and
`claim_standby` always forks a fresh child.

## Live validation (acceptance gate on the KVM box)

Host: Hetzner `88.99.197.234` (`/dev/kvm` present). Use a **fresh checkout**
under `/root` — avoid the prior sessions' `/root/mvm`, `/root/mvm-plan265`,
`/root/mvm-plan255-warm-pool-*`. Build mvmctl on Linux/KVM, then run a scripted
`spawn_standby` → `claim_standby` and assert:

- the factory parent boots and its agent reaches ready;
- the parent is captured (a `CheckpointId` recorded, lineage anchor written);
- a claim mints a fresh `VmId` + VMGenID, materializes the child via CoW, and
  the child FC VM boots with its agent reaching ready;
- a fresh `ExecutionPlan` is admitted and `plan.admitted` / `plan.launched`
  audit entries land, with `verify_audit_chain` clean;
- `ClaimCleanup` behaves: a healthy reserved parent returns claimable, a
  tampered one is quarantined, a partial child dir is removed.

## How the speed actually arrives (corrected)

Not a future swap — the machinery is live and this slice calls it:

| Seam | What this slice does |
|---|---|
| `spawn_standby_parent` | boot a clean parent to agent-ready, leave it running |
| runner capture | `capture_vm_full` — pause → save memory → clone rootfs in the pause window → resume, writing `device-anchors.json`; then release the parent |
| `parent_checkpoint` | the `vm_full` checkpoint (`rootfs.ext4` + `memory.bin` + `vmstate.bin` + anchors) |
| `fork_standby_child` | delegate to `FcForkRestorer::restore_fork` → `warm_restore_instance_from_path` |

The child restores a fully-booted guest's memory, so it skips kernel boot,
init, and agent startup — that is where the time goes, not the rootfs clone.

The three guards are already enforced, not pending:

1. **No NIC on restore** — `assert_vsock_only_device_model` runs inside
   `guarded_load_resume`, between load and resume, so a snapshot carrying a
   network interface is refused before any vCPU executes.
2. **Fresh identity** — the restore path takes a `vmgenid` token and returns
   `ReseedStatus`; `restore_fork` passes an all-zero token and the caller
   delivers the real one over vsock once the agent answers.
3. **Device-anchor remap** — `capture_vm_full` writes `device-anchors.json` and
   copies the referenced anchor files, so a restored child binds its **own**
   copies rather than the parent's absolute paths.

**Density model:** snapshot-and-release — the parent is captured then killed,
so a pool slot costs disk, not RAM. The resident-paused model is Plan 265's.

**Still Plan 265's, deliberately not done here:** the pre-spawned-VMM
optimization (its WS2 item self-flags the overlap with this warm-pool work),
page-cache priming, density, and the CI-gated SLO. Each claim here starts a
fresh Firecracker; this slice measures that cost so 265 has a real baseline.

## Invariants honored

- vsock is the sole boundary (no NIC introduced; restore convergence keeps the
  no-NIC guard).
- one guest = one workload (fresh child per claim; parents are workload-agnostic
  factories).
- guest never sees secrets (unchanged; claim mints a fresh plan).
- fork/restore never bypasses admission (each claim admits a fresh signed plan;
  supervisor re-verifies on attach).

## Copy / attribution rules

No competitor proper nouns anywhere (code, comments, commits, PR, git history).
No plan/PR/ADR/`#NNNN`/`W#` references in code comments. No AI-tool attribution
or Claude co-author trailer.
