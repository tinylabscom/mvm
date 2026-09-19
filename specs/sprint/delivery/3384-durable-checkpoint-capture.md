# Durable checkpoint capture and parallel verify

Issue #3384. Plan: `specs/plans/2026-09-18-chunked-durable-checkpoints.md`,
workstream C0. W7 of `specs/plans/2026-09-16-sandbox-review-upgrades.md` now
points at that plan.

## What shipped

- **Staged capture.** `capture_vm_full` (all three variants) and
  `capture_fs_quick` write into `<checkpoints>/.staging/<pid>-<nanos>-<nonce>-<id>/`
  and publish it with one directory rename (`checkpoint/staging.rs`). Before
  the rename, every file in the content directory is synced (in parallel), then
  the content directory, then `meta.json` goes in through a synced temporary
  file, then the staging directory is synced. After the rename the store root
  is synced. A capture that fails or panics removes its staging; a crashed one
  is swept by the next capture once its process is gone. `list()` skips
  dot-named directories, and capture refuses an id that starts with `.` or
  contains a path separator.
- **Recapture no longer damages the checkpoint it replaces.** Recapturing into
  an existing id moves the old checkpoint aside, renames the new one in, then
  deletes the old one. Previously the new blobs were written over the old ones
  in place, so a capture that failed partway left a record that no longer
  verified. A red test on the unmodified tree reproduced it.
- **Durable record writes.** `CheckpointStore::write_meta`, which the fork
  paths use, is now temporary file, sync, rename, then syncs of the checkpoint
  directory and the store root. New `mvm_core::atomic_io::{sync_file,
  sync_dir, atomic_write_durable}` carry the sync steps.
- **Parallel hashing.** `verify_content` hashes blobs concurrently with
  `mvm_fs::parallel::par_map` and still reports the first failing blob in
  manifest order. Capture hashes the rootfs and memory image concurrently.

## Numbers

`cargo nextest run -p mvm-runtime --lib --run-ignored only verify_timing
--no-capture`, 16-core Apple Silicon Mac, load average 93–205 from unrelated
builds, best of three, warm cache:

| Checkpoint | Serial | Parallel | Speedup | Durable commit |
| --- | --- | --- | --- | --- |
| 2 GiB memory + 1 GiB rootfs | 6.26 s / 5.68 s | 3.10 s / 3.45 s | 2.01x / 1.65x | 57 ms / 47 ms |
| 1 GiB memory + 1 GiB rootfs | 5.92 s | 2.60 s | 2.28x | 66 ms |

The ceiling for one worker per blob is total size over largest blob (1.5x and
2x here); results above it come from the loaded host's scheduling. Chunked
hashing (C3) is what lifts the ceiling.

## Tests

`crates/mvm-runtime/src/checkpoint/durability_tests.rs` (8 tests plus the
ignored timing run) and `checkpoint/staging.rs` (5), `mvm_core::atomic_io`
(2). The four capture tests were red on the unmodified tree for the reasons
they name: blobs of a failed capture left under the checkpoint's name, a failed
recapture leaving a record that failed `sha256` verification, and no staging
area. The crash tests stop a commit after every prefix of its steps and assert
the store holds the complete old or new checkpoint or none, never a record
that fails verification or that `list()` cannot read. `NoMachineIdControl` in
the checkpoint tests now writes its extra blob beside the memory image, as
Firecracker writes `vmstate.bin`, instead of pre-seeding the final content
directory.

## Not done

Everything that stores chunks: the index and object pool, chunked capture and
verify, diff restore, object garbage collection, index anchoring, key domains,
and retiring the whole-blob layout. Workstreams C1–C8 of the plan track them,
with #3384's four acceptance criteria mapped to C2.3, C3.1, C3.3 and C2.4.
Abandoned staging is swept only by the next capture; `cache prune` sweeping it
is C5.1.

A recapture that crashes between moving the old checkpoint aside and renaming
the new one in leaves neither under the id. The old one sits in staging as
`<name>.replaced`, and the next capture's sweep deletes it once the owning
process is dead. The checkpoint is lost, never left half-written. Restoring it
from the aside copy instead would close that window, and nothing does yet.
