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

Move ownership to the process that owns the VM: **the supervisor acquires the
lock itself**, and the starting process never holds it on the persistent path.

The original sketch here was to pass the parent's locked descriptor across
`exec` (an `flock` survives as long as any descriptor for its open file
description does). That works, but it is the wrong shape once you notice why
the handoff seemed necessary. The race it was avoiding — parent releases, child
acquires, a third process wins the gap — only exists **because** the parent
takes the lock first. If the parent never takes it, there is no handoff and no
gap, and no `FD_CLOEXEC` manipulation or fd-number plumbing either.

What the parent loses is the ability to report contention itself. That is
acceptable here and only here: on the persistent path the parent's job is to
start a session and exit, so it waits for the supervisor's pid file anyway. A
supervisor that cannot take the lock exits, and the parent surfaces that.

The **one-shot** path keeps the parent holding the lock. There the CLI outlives
the VM, so the ownership is already correct, and it is where Plan 323's
queueing and its "waiting for `<holder>`" reporting live. Nothing about that
changes.

- [ ] `SupervisorConfig` (libkrun) carries the sidecar lock path; the
      supervisor acquires it in `dispatch_config`, the shared tail both
      entrypoints route through, and holds it for the process's lifetime.
- [ ] `HvfSupervisorConfig` carries the same, set through an inherent
      `HvfDriver` entry point for the persistent builder rather than a new
      `VmmSpec` field — 30 spec literals across the workspace would otherwise
      change for a property only one path sets.
- [ ] `LibkrunPersistentHostVm` / `HvfPersistentHostVm` stop acquiring the lock
      and instead ensure the image exists (a non-locking sparse create), then
      name the sidecar for the supervisor.
- [ ] Once the supervisor owns the lock, `leak_handle`'s comment and the module
      docs on `PersistentHvfSession` stop being caveats and become
      descriptions.
- [ ] Test: start a session, drop the starting handle, and assert from a
      separate process that the image is still locked. That is the assertion
      that fails today and is the point of the change.

## Why not just document it

Plan 323's whole concurrency story rests on "the store image has exactly one
writer". A soft mutex keyed on a JSON file is not that, and the queueing
behaviour added in 323 Phase 1 turns a fail-fast collision into a silent one.
