# Plan 324 — The builder store lock must outlive the process that takes it

**Status:** OPEN
**Date opened:** 2026-08-11
**Related:** Plan 323 (concurrent builds through one builder VM)

## Problem

The Nix store image (`~/.mvm/cache/builder-vm/nix-store-<arch>.img`) is attached
read-write by every builder VM, and two guests mounting one ext4 read-write
corrupts it. A sidecar `flock` enforces one writer.

That lock is owned by the wrong process. An `flock` belongs to the **open file
description**, which belongs to the `mvmctl` process that opened it. A
persistent builder is started by `mvmctl persistent-builder start`, which must
leak its handle and exit so the VM outlives the command — and at that exit the
kernel releases the lock. The VM keeps writing an unlocked store image.

The libkrun path already documents this on `leak_handle`
(`crates/mvm-cli/src/commands/build/persistent_builder.rs`), mitigated only by
the session record acting as a soft mutex: `start` refuses when a record
exists. Nothing stops a *one-shot* builder from taking the image while a
session owns it. `PersistentHvfSession` (Plan 323) inherits the identical gap.

Plan 323 Phase 1 raised the stakes. Contention used to fail fast; it now
**queues** and proceeds once the lock looks free. After the starting CLI exits,
it does look free — while a persistent builder VM is actively writing the
store. That is a path to two writers on one filesystem.

## Approach

Move ownership to the process that owns the VM. An `flock` survives as long as
*any* descriptor for its open file description is open, so a descriptor
inherited across `exec` keeps the lock alive after the parent exits — with no
window where neither process holds it.

- [ ] Pass the locked descriptor from the starting process to the supervisor it
      spawns (clear `FD_CLOEXEC` on the lock fd, tell the supervisor its number
      via config). The alternative — supervisor opens and locks the path itself
      — has a race: the parent must release before the child can take an
      exclusive lock, and another builder can win that gap.
- [ ] Apply it to both persistent paths, `mvm-libkrun-supervisor` and
      `mvm-hvf-supervisor`. The gap is not HVF-specific and fixing one backend
      would leave the documented libkrun hole open.
- [ ] Once the supervisor owns the lock, `leak_handle`'s comment and the
      module docs on `PersistentHvfSession` both stop being caveats and become
      descriptions.
- [ ] Test: start a session, drop the starting handle, and assert from a
      separate process that the image is still locked. That is the assertion
      that would fail today and is the point of the change.

## Why not just document it

Plan 323's whole concurrency story rests on "the store image has exactly one
writer". A soft mutex keyed on a JSON file is not that, and the queueing
behaviour added in 323 Phase 1 turns a fail-fast collision into a silent one.
