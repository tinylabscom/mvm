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

## Non-goals (explicit)

- **Sub-second restore.** The child is a **cold boot** from the CoW-cloned
  parent rootfs, not a memory restore. Firecracker memory restore is
  hard-disabled (`microvm/snapshot.rs`: `warm_restore_instance*`,
  `restore_from_template_snapshot` all `bail!`) pending Plan 265's re-enable
  behind the no-NIC + VMGenID guards. See "Convergence to sub-second" below.
- **HVF / libkrun live forks.** Separate follow-on slices.
- **Any change to the guarded-claim core.** Admission, lineage verify, CoW
  rootfs, identity minting, and audit emit are unchanged from the substrate.

## Why cold-boot first is honest about value

For a read-only dm-verity rootfs (already content-addressed and cached), a
cold-boot warm claim is ~equivalent to a cached cold boot — the child re-runs
the whole boot either way. The value of this slice is **de-risking, not
speed**: it runs the entire admission-safe fork chain against a real VMM for
the first time (the substrate has only run against the mock backend), and it
lays the exact seam Plan 265 upgrades to memory restore. Nobody should read
this slice as "the warm pool is fast now."

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

## Convergence to sub-second (the documented hook for Plan 265)

Sub-second is a **localized two-function swap** on top of this slice; nothing
between capture and fork changes. The capture side is already live; the
restore side is stubbed but pre-wired with the identity + no-NIC hooks.

| Seam | This slice (cold boot) | After Plan 265 (memory restore) |
|---|---|---|
| `spawn_standby_parent` | `capture_fs_quick` (rootfs-only) | pause + `create_snapshot_files` (Full: vmstate + guest memory, already live) + memory-carrying checkpoint |
| `fork_standby_child` | cold-boot from CoW rootfs | `warm_restore_instance_from_path` (today `bail!`) behind the three guards below |
| `parent_checkpoint` | the fs_quick checkpoint | the memory-carrying checkpoint |

Three guards Plan 265 must satisfy before un-disabling restore — each already
has its hook in the code:

1. **No NIC on restore** — `assert_vsock_only_device_model` (live, pure) must
   gate the snapshot load; a captured NIC would bypass the vsock-only egress
   boundary.
2. **Fresh identity** — the restore entry points already take a `vmgenid`
   token (`GENID_BYTES`) and return `ReseedStatus`; on resume the guest kernel
   sees a new VM-generation-ID and reseeds RNG/crypto so children are not
   twins (plus fresh machine-id/hostname).
3. **Post-resume hygiene** — drop stale in-memory connections, re-prime caches
   (Plan 265's other workstreams).

The same admitted, audited claim then yields a ~30–60ms restore instead of a
cold boot — no change to the admission, lineage, identity, or audit machinery.

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
