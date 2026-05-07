# Plan 47 — CoW snapshots via dm-thin pool

Status: **Proposed.** Implements ADR-008.

## Background

Today every microVM instance receives a full copy of its template's
ext4 rootfs (`mvm/crates/mvm-runtime/src/vm/image.rs`). Pause/resume
captures full `vmstate.bin + mem.bin` per snapshot. Storage cost
grows linearly with both instance count and snapshot count.

Sandbox-as-a-service workloads (frequent agent-loop checkpointing)
break this cost model. ADR-008 adopts dm-thin (device-mapper thin
provisioning) as the storage backend so snapshots are cheap and
chained.

## Goal

Replace per-instance ext4 copy with dm-thin clone of a verity-sealed
read-only base. Each pause point produces a chained thin snapshot.
Single shared pool at `~/.mvm/storage/pool/`. Hard cap on pool
utilization; pool-full surfaces as clean instance-create failure.

## Design

### On-disk layout

```
~/.mvm/storage/
├── pool/                          # the thin pool (sparse file or LV)
│   └── pool.img                   # default: 100 GiB sparse file
├── bases/                         # per-template seed volumes (RO)
│   └── <template-hash>/
│       ├── base.thin              # device-mapper handle
│       └── verity.json            # dm-verity sidecar
└── instances/                     # per-instance writable volumes
    └── <vm-name>/
        ├── rootfs.thin            # cloned from base
        └── snapshots/
            ├── 0.thin             # pause point 0 (chained from rootfs)
            └── 1.thin             # pause point 1 (chained from 0)
```

The legacy `~/.mvm/instances/<vm-name>/rootfs.ext4` layout continues
to work for instances created before this plan ships. Migration is
not forced — templates rebuild into the new layout naturally on
their next `mvmctl template build`.

### Pool bootstrap

On first run after upgrade:

1. Detect the running host (Linux directly vs Lima VM on macOS).
2. Create pool at `~/.mvm/storage/pool/` with default size (100 GiB
   sparse file via `truncate -s`, then `losetup` + `dmsetup` to mount
   as a thin pool device).
3. On macOS, run pool management *inside* the Lima VM, not on the
   macOS host directly — matches today's architecture where Linux is
   provided by Lima.
4. Pool size, auto-grow policy, and hard cap are configurable via a
   new `~/.mvm/config/storage.toml` (mode 0600).

Idempotent: subsequent runs detect existing pool and skip bootstrap.

### Base volumes

When a template is built (existing `mvmctl template build` flow):

1. Existing path produces `rootfs.ext4` (verity-sealed in prod).
2. New post-build step: `dmsetup` creates a thin volume from the
   pool, populates it from `rootfs.ext4`, marks it read-only.
3. Write `~/.mvm/storage/bases/<template-hash>/{base.thin,verity.json}`.
4. Garbage-collect older base volumes whose template revisions are
   no longer referenced (configurable retention; default keep last 3).

### Instance creation

Modify `mvm/crates/mvm-runtime/src/vm/image.rs`:

- Old: copy `rootfs.ext4` into instance dir.
- New: clone a thin volume from the base via the equivalent of
  `lvcreate -s <base.thin> -n <instance>.thin` (using `dmsetup`
  primitives directly; LVM2 not required).
- Firecracker drive points at the cloned thin volume's device path.

### Snapshots

Modify `mvm/crates/mvm-runtime/src/vm/instance_snapshot.rs` pause/
resume:

- At pause: in addition to today's `vmstate.bin + mem.bin` capture,
  take a thin volume snapshot chained from the previous one (or from
  `rootfs.thin` for snapshot 0).
- At resume: device-mapper handle for the snapshot-of-interest is
  re-attached; Firecracker resumes pointing at it.
- vmstate/mem images remain full-size (Firecracker doesn't expose
  delta memory snapshots in current versions). Rootfs delta is the
  cost win.

### CLI

Two new verbs (per ADR-008's CLI surface decision):

- `mvmctl storage info` — print pool utilization (used / committed /
  cap), per-instance volume sizes, base volume retention status.
  Read-only; exempt from audit-emit gate per `info.rs` suffix rule.
- `mvmctl storage gc` — reclaim unreferenced thin volumes (orphaned
  bases, abandoned instance volumes from crashed boots). Dry-run by
  default; `--apply` actually deletes. Audits via new
  `LocalAuditKind::StorageGc`.

### Doctor checks

Extend `mvmctl doctor`:

- Pool exists and is mountable.
- Pool utilization < 90% (warn ≥ 75%).
- No orphaned thin volumes.
- Verity sidecars match base hashes.

## Critical files

- New: `mvm/crates/mvm-runtime/src/storage/mod.rs`
- New: `mvm/crates/mvm-runtime/src/storage/thin.rs` — `dmsetup`
  invocations, error handling.
- New: `mvm/crates/mvm-runtime/src/storage/pool.rs` — pool lifecycle.
- Modified: `mvm/crates/mvm-runtime/src/vm/image.rs` — clone instead
  of copy.
- Modified: `mvm/crates/mvm-runtime/src/vm/instance_snapshot.rs` —
  chained snapshot at pause boundary.
- Modified: `mvm/crates/mvm-cli/src/commands/doctor.rs` — pool checks.
- New: `mvm/crates/mvm-cli/src/commands/storage/{mod,info,gc}.rs`
- Modified: `mvm/crates/mvm-core/src/policy/audit.rs` —
  `LocalAuditKind::StorageGc`.
- Modified: `mvm/CLAUDE.md` — document new layout under `~/.mvm/`.
- Reference: ADR-008.

## Verification

- Unit tests: `dmsetup` invocations mocked; assert correct argv shape.
- Integration test:
  - Bootstrap pool, create base, clone instance, take 10 snapshots.
  - Assert on-disk pool size grows sub-linearly with snapshot count.
  - Pause/resume across the snapshot chain succeeds; assert running
    workload sees consistent state at each pause point.
- Tampering test: corrupt a snapshot's data block; assert verity (on
  base layer) and HMAC (on vmstate) detect.
- Pool-full test: pre-fill pool to cap, attempt new instance; assert
  clean failure (not silent corruption).

## Effort

~1.5–2 sprints. Real research + KVM testing required; not a
mock-able codepath.

## Out of scope

- btrfs, overlayfs, qcow2 alternatives. Rejected in ADR-008.
- Cross-host snapshot replication. Separate plan if multi-host
  storage becomes a concern.
- Forced migration of legacy `rootfs.ext4` instances. Deferred until
  CoW path is stable; legacy continues under a legacy code path.
