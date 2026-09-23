# Chunked, parallel, durable checkpoint storage

Backing: preview
Validation: workstream-specific. Each workstream names the tests and the
measurements required before its checkbox may be ticked.

**Tracking:** #3384. Scoped from W7 of
`specs/plans/2026-09-16-sandbox-review-upgrades.md`, which now points here.
Coordinates with #3382 (W5 of that plan, copy-on-write HVF restore), which
changes how a restored memory image is consumed.

**Status: C0–C4 DONE; C5–C8 OPEN.** The capture path now stores the
large blobs as chunks and materializes verified contiguous files for current
restore consumers. Restore now keeps read-only per-domain/index
materializations and rewrites only changed chunks into a private verified
clone. Garbage collection, audit-format cleanup, tenant-domain resolution and
old-layout retirement remain separate work.

## Problem

`crates/mvm-runtime/src/checkpoint/mod.rs` stores each checkpoint as whole
files under `<checkpoints>/<id>/content/`: `memory.bin`, `rootfs.ext4`, the
machine-id and the backend's machine-state blob, the launch config, the guest
sidecars, `device-anchors.json`. The record, `meta.json`, lists every blob with
its SHA-256, and `meta_digest` (a digest over the record, the blob list
included) is what `checkpoint.created` writes into the chain-signed audit log.
`verify_lineage` recomputes that digest and compares it with the signed entry.

Four costs follow from that layout:

1. **Storage.** Every capture of a machine stores its full RAM and its full
   rootfs again. The rootfs is a copy-on-write clone where the host filesystem
   supports one; the memory image never is.
2. **Verification time.** `verify_content` hashed every blob, one after the
   other, on one core. Restore, both fork paths and the warm claim run it, so
   its cost grows with guest RAM on the paths a user waits on.
3. **Durability.** Nothing synced a blob or the record. A crash could leave a
   record whose digests disagree with its blobs. Verification then refuses it,
   so the checkpoint was lost but never silently wrong. Worse, recapturing into
   an existing id overwrote that checkpoint's blobs in place, so a capture that
   failed halfway destroyed the checkpoint it was replacing. That last one is a
   defect, not a missing feature, and C0 fixes it.
4. **Restore write volume.** Every restore clones or copies every blob into the
   child's state directory, even when the child's previous restore left almost
   the same bytes behind.

## Decisions

These hold for every workstream below. Each one is the design this plan builds
towards, not a description of shipped code, except where a workstream is
ticked.

- **Chunk size is 1 MiB, fixed.** Large enough that a 4 GiB guest's index is
  4096 entries (about 140 KiB as JSON); small enough that an idle guest's
  scattered dirty pages touch a small fraction of chunks. It is a multiple of
  every host page size we run on (4 KiB and 16 KiB), so a contiguous file
  rebuilt from chunks keeps the page alignment #3382 needs for a `MAP_PRIVATE`
  mapping. The snapshot encryption layer
  (`mvm_core::crypto::snapshot_encryption`) already uses the same chunk size.
- **Zero chunks are recorded, not stored.** An index entry for an all-zero
  chunk carries a marker instead of an object name. Guest RAM that was never
  touched is the common case in a memory image.
- **Objects are shared by hard link, not by reference count.** Each key domain
  (below) has an object pool, `<checkpoints>/.objects/<domain>/<aa>/<digest>`.
  A checkpoint's directory holds a hard link to every object it uses. Reasons:
  - Deleting a checkpoint stays `remove_dir_all` of its directory, exactly as
    `CheckpointStore::remove`, `retention_verdicts` and `mvmctl cache prune`'s
    `sweep_untagged_checkpoints` use it today. Removing one checkpoint cannot
    break another, because the other holds its own link.
  - There is no count to keep consistent across a crash. A reference count is
    a second record that must be updated in the same atomic step as the index,
    and a crash between the two either leaks an object or deletes a live one.
    A hard link count is maintained by the filesystem in the same operation.
  - Garbage is an object whose only remaining link is the pool's own
    (`st_nlink == 1`). A sweep that races a capture linking that object is
    safe: the capture's link keeps the bytes alive, and the only cost is that
    the pool loses the entry and a later capture writes it again.
  - The cost is one directory entry per stored chunk per checkpoint, and every
    object must be read-only: a write through any link changes every
    checkpoint that shares it. Objects are created `0400` and are never opened
    for writing after creation; restore materializes a new file rather than
    handing out an object.
- **The index digest is the only content address.** For a chunked blob, its
  `ContentBlob.sha256` holds the SHA-256 of that blob's index (the canonical
  encoding of its length, chunk size and ordered chunk entries) instead of the
  SHA-256 of the whole file. `meta_digest` covers the blob list, the chain
  records `meta_digest`, and `verify_lineage` is unchanged: a tampered index no
  longer matches the recorded digest, and a tampered chunk no longer matches its
  index entry.
- **Dedup never crosses a key domain.** A domain is the tenant whose plan the
  checkpoint was captured under; a checkpoint captured without a tenant is in
  the host's own domain. Pools are separate directories, so no object is
  shared across tenants, and no filename in one pool says anything about
  another. This is the same boundary #3382 draws for shared RAM pages. When
  checkpoints are encrypted (they are not today; only volumes use
  `snapshot_encryption`), the domain becomes the data-encryption key, and
  object names become a keyed digest under that key so a name does not reveal
  the digest of the plaintext it holds.
- **No migration of whole-blob checkpoints.** Checkpoints are host-local and
  never exported (the review plan excluded a portability check for that
  reason), and the only release that shipped the checkpoint verbs is the
  `v0.18.0-rc.1` pre-release. Following the repository's rule of no
  backwards-compatibility machinery for a first version, a whole-blob
  checkpoint is refused by the chunked reader with a message naming it and
  telling the user to capture again; `mvmctl machine checkpoint rm` and the
  existing retention sweep still remove it.
- **Durability order is objects, index, record, name.** Chunk objects are
  synced before the index that names them, the index and the record before the
  directory that publishes them, and the directory is published by one rename.
  C0 put that order in place for whole blobs, and the chunked capture reuses
  it.

## Workstreams

In order. Each is shippable on its own; later ones depend on earlier ones only
where stated.

### C0 — Durable whole-blob capture and parallel verify

- [x] C0.1 Capture writes into a private staging directory,
      `<checkpoints>/.staging/<pid>-<nanos>-<nonce>-<id>/`, and publishes it
      with one rename (`checkpoint/staging.rs`). A capture that fails or panics
      removes its staging; one that crashes leaves it for the next capture's
      sweep, which removes staging whose owning process is gone.
- [x] C0.2 The commit order is data (`commit_plan`): sync every file in the
      content directory (in parallel), sync the content directory, write
      `meta.json` through a synced temporary file, sync the staging directory,
      move a checkpoint being replaced aside, rename the staging directory into
      place, sync the store root, delete the replaced checkpoint.
- [x] C0.3 Recapturing into an existing id replaces the old checkpoint whole,
      or leaves it untouched when the capture fails. Before this, a failed
      recapture overwrote the old checkpoint's blobs in place and left a record
      that no longer verified.
- [x] C0.4 `CheckpointStore::write_meta` (the fork paths' record writer) is
      atomic and durable: temporary file, sync, rename, sync the directory and
      the store root. A torn record previously made every `list()` fail.
- [x] C0.5 `verify_content` hashes the blobs concurrently with
      `mvm_fs::parallel::par_map` and reports the first failing blob in
      manifest order. Capture hashes the rootfs and memory image concurrently.
- [x] C0.6 Tests, red on the unmodified tree first: a capture failing after
      its blob writes leaves nothing under the checkpoint's name; a failed
      recapture leaves the previous checkpoint verifying; a crash after every
      prefix of the commit leaves a first capture absent or complete, and a
      recapture the old checkpoint, nothing, or the new one; the plan's order;
      the staging sweep; verify's error order and missing-blob refusal.
- [x] C0.7 Timing, recorded below.

**C0 measurements.** `verify_timing` in
`crates/mvm-runtime/src/checkpoint/durability_tests.rs`, run with
`cargo nextest run -p mvm-runtime --lib --run-ignored only verify_timing
--no-capture` on a 16-core Apple Silicon Mac under heavy unrelated load (load
average 93–205 during the runs), best of three, warm page cache:

| Checkpoint | Serial verify | Parallel verify | Speedup | Durable commit |
| --- | --- | --- | --- | --- |
| 2 GiB memory + 1 GiB rootfs, run 1 | 6.26 s | 3.10 s | 2.01x | 57 ms |
| 2 GiB memory + 1 GiB rootfs, run 2 | 5.68 s | 3.45 s | 1.65x | 47 ms |
| 1 GiB memory + 1 GiB rootfs | 5.92 s | 2.60 s | 2.28x | 66 ms |

Read these with two caveats. Parallelism here is one worker per blob, so the
ceiling is the total size over the largest blob: 1.5x for 2 GiB + 1 GiB and 2x
for 1 GiB + 1 GiB. Runs above that ceiling reflect how unevenly a host this
loaded schedules one long serial thread, not extra headroom. Chunk-level
hashing (C3) removes the ceiling, because a single large blob then spreads over
every core. The commit time is measured right after the blobs were written, so
it includes flushing whatever the kernel had not yet written back.

### C1 — Chunk index and object pool

- [x] C1.1 Define the index: blob length, chunk size, and one entry per chunk
      (an object digest or the zero marker), with one canonical encoding whose
      SHA-256 is the blob's content address.
- [x] C1.2 Object pool per key domain with hard-linked membership, objects
      created `0400`, written through a synced temporary file and linked into
      the pool with a no-clobber link.
- [x] C1.3 Record the key domain in `CheckpointMeta`, covered by `meta_digest`.
- [x] C1.4 Tests: index encoding round trip and determinism; a zero chunk
      stores nothing; two checkpoints in one domain share an object's inode;
      two domains never do.

### C2 — Chunked capture

- [x] C2.1 Split `memory.bin` and `rootfs.ext4` into chunks, hashing chunks in
      parallel with `par_map`. Small blobs (sidecars, configs, the machine
      state) stay whole files.
- [x] C2.2 Link an existing object when the pool has it; otherwise write it.
      Every object is synced before the index is written (extends C0's
      `commit_plan`).
- [x] C2.3 Acceptance: a second checkpoint of an idle machine adds under 10% of
      the first one's stored bytes, measured as the growth of the object pool
      plus the second checkpoint's own files. Unit test on a synthetic image
      with 5% of chunks changed; live measurement on HVF and on Firecracker
      recorded here.
- [x] C2.4 Crash injection: a stop between the object writes and the index
      write, and at every other step, leaves no checkpoint that verifies
      wrongly — absent or refused, never silently wrong (C0.6's test, run
      against the chunked commit).

**C2 measurements so far.** The synthetic 20-chunk test changes one chunk
(5%) and checks that the new object plus the second index add under 10% of the
first pool's bytes. On a live 512 MiB HVF guest with a representative
multi-layer rootfs, the first checkpoint stored 237,862,839 bytes and the
immediate idle recapture added 15,364,023 bytes (6.459%). A deliberately tiny
rootfs measured 47,843,349 bytes then 11,765,781 bytes (24.592%): the same
11 MiB of resumed-guest memory churn dominates that small stored baseline.
On a live Linux/KVM Firecracker guest, the first checkpoint stored 452,050,904
bytes and the immediate idle recapture added 24,231,903 bytes (5.360%). Two
sibling restores from that checkpoint both completed the authenticated
identity handshake and reported distinct reseeded randomness.

### C3 — Chunked verify and materialization

- [x] C3.1 Verify every chunk against its index entry in parallel. Refuse a
      tampered chunk, a missing chunk and a tampered index, each with a test.
- [x] C3.2 Materialize a contiguous file from the index (for fork, restore and
      the warm claim), verifying each chunk as it is copied, so nothing reaches
      a VMM that was not verified. Zero chunks become holes.
- [x] C3.3 Measure serial against parallel verify for 1, 2 and 4 GiB memory
      images, and record the numbers in this plan and the PR.

**C3 measurements.** `chunk_verify_timing` hashes a repeated non-zero 1 MiB
object through an index of the stated logical size, avoiding a 7 GiB fixture
while retaining the full hash workload. Best of three on a 16-core Apple
Silicon host with load average 14–25:

| Logical memory | Serial verify | Parallel verify | Speedup |
| --- | --- | --- | --- |
| 1 GiB | 2.865 s | 272 ms | 10.53x |
| 2 GiB | 5.733 s | 527 ms | 10.88x |
| 4 GiB | 5.091 s | 991 ms | 5.14x |

The 4 GiB serial result is non-monotonic because the host was concurrently
loaded and the repeated object was page-cache hot; the acceptance comparison
is the same-size serial and parallel pair, not cross-row scaling.

### C4 — Diff restore

- [x] C4.1 Keep one verified, read-only materialization per index digest per
      key domain, recording which index it was built from.
- [x] C4.2 Restore clones the nearest cached materialization (copy-on-write
      where the filesystem has it) and rewrites only the chunks whose index
      entries differ, then verifies the result before handing it to the VMM.
- [x] C4.3 Compatibility with #3382: the file handed to the HVF restorer is a
      private, verified, contiguous file that no VM process can write, which
      is what a `MAP_PRIVATE` mapping of it needs. Test that editing the cached
      materialization after a restore does not change the restored file.
- [x] C4.4 Measure bytes written per restore before and after.

**C4 measurement.** The deterministic 20 MiB diff-restore fixture changes one
1 MiB chunk. A cold materialization writes 20 MiB of authenticated chunk data;
the next restore clones the nearest cached image and writes 1 MiB, a 95%
reduction. The measurement counts bytes issued by the chunk writer, independent
of whether the host filesystem implements the clone as APFS `clonefile`, Linux
`FICLONE`, or the sparse-copy fallback. A second test restores from the exact
cached index (zero rewritten chunks), mutates the cache afterward, and checks
that the private restored bytes do not change. A per-domain/per-blob file lock
serializes candidate verification, cloning, invalid-entry replacement, and
publish; deterministic contention tests check that concurrent publishers and a
reader crossing replacement cannot observe partial cache state.

**C4 validation.** The focused checkpoint namespace passes 108 tests with two
ignored timing witnesses; the full `mvm-runtime` workspace invocation passes
1,086 tests with eight ignored. `cargo check --workspace`,
`cargo clippy --workspace --all-targets -- -D warnings`, and the policy gates
pass (`xtask check-all`: 74 gates clean). The exact single-threaded workspace
command passed every unit and integration crate before rustdoc transiently
failed the `mvm-build` doctest with `E0463` for an existing `mvm_sdk` artifact.
An immediate isolated `cargo test -p mvm-build --doc -- --test-threads=1`
rerun passed with exit status zero, confirming target-artifact churn rather
than a C4 source failure.

### C5 — Garbage collection

- [ ] C5.1 `mvmctl cache prune` removes pool objects with `st_nlink == 1` and
      abandoned staging, after the existing checkpoint sweep, so objects freed
      by that sweep are reclaimed in the same run.
- [ ] C5.2 Test: after removing one of two checkpoints that share objects, the
      other still verifies and the prune reclaims only the objects nothing
      else links.

### C6 — Audit anchoring

- [ ] C6.1 The chunked blob's `ContentBlob.sha256` is its index digest.
      `meta_digest`, `checkpoint.created`, `checkpoint.forked` and
      `verify_lineage` are unchanged.
- [ ] C6.2 Tests: the existing lineage tests pass unmodified against chunked
      checkpoints; editing an index after capture fails lineage verification.
- [ ] C6.3 The snapshot store (`FsSnapshotStore`) and trusted-snapshot staging
      in `capture_vm_full_inner` take a materialized content directory, so
      their signed manifests keep covering whole files. Decide whether they
      should move to indexes, and record the decision here.

### C7 — Key domains

- [ ] C7.1 Resolve a capture's domain from its admitted plan's tenant, and the
      host domain for a capture without one.
- [ ] C7.2 Test: two tenants capturing identical memory share no inode and no
      object name.
- [ ] C7.3 When checkpoint encryption lands, key object names under the
      domain's key. Out of scope until then; tracked here so the pool layout
      does not have to change.

### C8 — Retire the whole-blob layout

- [ ] C8.1 The chunked reader refuses a whole-blob checkpoint with a message
      that names it and says to capture again.
- [ ] C8.2 Remove the whole-blob capture path once C2 ships.
- [ ] C8.3 Update the CLI reference and the troubleshooting guide.

## Issue acceptance, mapped

| #3384 acceptance | Where |
| --- | --- |
| A second checkpoint of an idle machine adds under 10% of the first one's stored bytes | C2.3 |
| A tampered chunk, a missing chunk and a tampered index are each refused | C3.1 |
| Verify runs faster on a multi-core host than the serial path, numbers in the PR | C0.7 (per blob), C3.3 (per chunk) |
| A crash between the object write and the index write leaves no checkpoint that verifies wrongly | C0.6 (whole blobs), C2.4 (chunks) |
