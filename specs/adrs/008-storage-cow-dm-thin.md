---
title: "ADR-008: Copy-on-write storage via dm-thin pool"
status: Proposed
date: 2026-05-06
supersedes: none
related: ADR-002 (microVM security posture); ADR-007 (function-call entrypoints); plan 47-cow-snapshots-dm-thin
---

## Status

Proposed.

## Context

Today, every microVM instance receives a full copy of its template's
ext4 rootfs (`crates/mvm-runtime/src/vm/image.rs`). Pause/resume
captures full `vmstate.bin + mem.bin` per snapshot. Storage cost
grows linearly with both instance count and snapshot count — a
sandbox-as-a-service workload pattern (frequent agent-loop
checkpointing) breaks this cost model.

Sandbox-as-a-service products like sprites.dev advertise "incremental
checkpoints" as cheap because their snapshots are copy-on-write.
mvm/mvmd needs the same property to keep storage costs bounded as
agent loops accumulate pause points.

## Decision

Adopt **dm-thin** (device-mapper thin provisioning) as the storage
backend for instance rootfs and snapshots.

Concretely:

- Per-template **base volume** (read-only, dm-verity-sealed) at
  `~/.mvm/storage/bases/<template-hash>/`.
- Per-instance **thin volume** cloned from the base via the
  equivalent of `lvcreate -s` (using `dmsetup` primitives directly;
  LVM2 not required).
- Per-snapshot **chained thin volume** for each pause point.
- Single shared **thin pool** at `~/.mvm/storage/pool/`, backed by
  a sparse file (loop-mounted) on dev hosts and a real LV on
  production hosts.

dm-thin chosen over alternatives:

| Option | Verdict | Reason |
|---|---|---|
| dm-thin | **chosen** | Native chained COW, block-level (matches Firecracker drive model), host-fs-agnostic, mature (Docker used it for years) |
| btrfs subvolumes | rejected | Requires btrfs as the host fs — non-starter on most macOS dev hosts and many Linux servers |
| overlayfs | rejected | One-shot snapshots, not chained; poor block-device fit |
| qcow2 | rejected | Different Firecracker driver code path; gives up some ext4 + dm-verity tooling alignment |

## Invariants

- **Verity bases are immutable.** A thin volume cloned from a verity
  base inherits the base's read-only seal at the block layer. The
  instance's writable layer is unsealed by design (today's behavior).
- **Pool sizing has a hard cap.** Thin pools can be over-provisioned;
  a pool-full event must surface as a clean instance-create failure,
  not silent corruption. The supervisor enforces an auto-grow policy
  with a hard cap configured in `~/.mvm/config/storage.toml`.
- **macOS hosts manage the pool inside the Lima VM**, not the macOS
  host directly. The pool is a Linux concern; Lima provides the
  Linux. Mirrors today's architecture.
- **The on-disk layout under `~/.mvm/`** changes from a per-instance
  `instances/<vm>/rootfs.ext4` file to per-instance
  `instances/<vm>/rootfs.thin` block-device handle plus a pool
  reference. Migration is one-way (no downgrade once an instance is
  thin-backed).
- **Audit emit.** Pool operations (create, grow, gc) emit audit
  records via a new `LocalAuditKind::StorageGc` variant (and a
  `StoragePoolGrow` variant if needed); per the `mvm/CLAUDE.md`
  audit-emit gate.

## Consequences

- **Storage cost grows sub-linearly with snapshot count.** Only
  modified blocks consume space. Frequent agent-loop checkpointing
  becomes affordable.
- **Pause/resume captures only delta state for rootfs.** vmstate.bin
  + mem.bin remain full per snapshot for now (Firecracker doesn't
  expose delta memory snapshots in current versions); the rootfs
  delta is the big win.
- **New operational surface.** dmsetup commands, pool monitoring,
  pool-grow events. Add to `mvmctl doctor` checks.
- **Migration path.** Existing instances under
  `~/.mvm/instances/<vm>/rootfs.ext4` continue to work via a legacy
  code path; new instances use the thin layout. No forced migration
  — templates rebuild into the new layout naturally on their next
  `mvmctl template build`.
- **Out of scope:** btrfs/qcow2/overlayfs alternatives (rejected
  above); cross-host snapshot replication (separate plan if needed);
  forced migration of legacy instances (deferred until CoW path is
  stable).
