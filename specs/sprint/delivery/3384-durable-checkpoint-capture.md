# Durable, chunked checkpoint capture and parallel verify

Issue #3384. Plan: `specs/plans/2026-09-18-chunked-durable-checkpoints.md`,
workstreams C0–C3. W7 of
`specs/plans/2026-09-16-sandbox-review-upgrades.md` points at that plan.

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
- **Chunked large blobs.** Memory and rootfs images are fixed 1 MiB chunks.
  Zero chunks are represented without an object; non-zero chunks live in a
  per-key-domain object pool and each checkpoint hard-links the objects it
  uses. Small sidecars and machine-state files stay whole. Objects are `0400`,
  published without clobbering, and both their data and newly created
  directory entries are synced before an index can name them.
- **Authenticated indexes and domains.** Canonical compact JSON indexes carry
  the logical length and ordered object/zero entries. Their SHA-256 is the
  `ContentBlob` address sealed by `meta_digest`. `CheckpointMeta` carries a
  load-bearing key domain while omitting the default host domain from the wire
  so old host-domain digest fixtures retain their shape. Tenant-controlled
  names are hashed before becoming pool paths.
- **Verified materialization.** Verify hashes chunks in parallel and reports
  failures in manifest order. Fork, restore and warm-claim paths rebuild a
  private contiguous file while rechecking every non-zero chunk; zero chunks
  remain sparse holes. A copied snapshot cannot bypass this: chunked blobs are
  replaced from the authenticated index before use.

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

`chunk_verify_timing`, best of three on the same 16-core host under load:

| Logical memory | Serial | Parallel | Speedup |
| --- | --- | --- | --- |
| 1 GiB | 2.865 s | 272 ms | 10.53x |
| 2 GiB | 5.733 s | 527 ms | 10.88x |
| 4 GiB | 5.091 s | 991 ms | 5.14x |

The benchmark repeats one non-zero 1 MiB object through an index of the stated
logical size, retaining the full hash workload without consuming 7 GiB of
fixture storage. The 4 GiB serial number is non-monotonic under concurrent host
load; each acceptance comparison is within one row.

The live 512 MiB HVF measurement on a representative multi-layer rootfs stored
237,862,839 bytes for the first checkpoint and added 15,364,023 bytes for the
immediate idle recapture: 6.459%. A deliberately tiny rootfs measured 24.592%
because the same 11 MiB of resumed-guest memory churn dominates a 47.8 MiB
stored baseline.
On a live Linux/KVM Firecracker guest, the first checkpoint stored 452,050,904
bytes and the immediate idle recapture added 24,231,903 bytes: 5.360%. Two
sibling restores both completed the authenticated identity handshake and
reported distinct reseeded randomness.

## Tests

The full workspace test suite passes in deterministic single-threaded mode.
The checkpoint namespace passes 104 tests with two ignored timing witnesses;
host workspace Clippy, real Linux workspace all-target Clippy, the gated-target
check, BDD Clippy, formatting, and all 74 repository source gates pass. The
ignored live Firecracker test also passes on a real Linux/KVM host. The
original four C0 capture tests were red on the unmodified tree
for the reasons
they name: blobs of a failed capture left under the checkpoint's name, a failed
recapture leaving a record that failed `sha256` verification, and no staging
area. The crash tests stop a commit after every prefix of its steps and assert
the store holds the complete old or new checkpoint or none, never a record
that fails verification or that `list()` cannot read. Chunk-specific tests
cover canonical encoding, malformed digests and counts, path traversal,
zero elision, same-domain inode sharing, cross-domain isolation, object modes,
synthetic 5% growth, sparse materialization, warm-snapshot replacement, and
tampered, missing or re-encoded content. `NoMachineIdControl` in
the checkpoint tests now writes its extra blob beside the memory image, as
Firecracker writes `vmstate.bin`, instead of pre-seeding the final content
directory.

## Not done

Diff restore, object garbage collection, the audit-format decision,
admitted-tenant domain resolution, and retiring the whole-blob layout.
Workstreams C4–C8 track them.
Abandoned staging is swept only by the next capture; `cache prune` sweeping it
is C5.1. Capture currently resolves to the host domain; C7 threads the admitted
tenant into that already-separated pool layout.

A recapture that crashes between moving the old checkpoint aside and renaming
the new one in leaves neither under the id. The old one sits in staging as
`<name>.replaced`, and the next capture's sweep deletes it once the owning
process is dead. The checkpoint is lost, never left half-written. Restoring it
from the aside copy instead would close that window, and nothing does yet.
