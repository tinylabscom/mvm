# Checkpoint diff restore

Issue #3384. Plan:
`specs/plans/2026-09-18-chunked-durable-checkpoints.md`, workstream C4.

## What shipped

- Chunked rootfs and memory restores retain one read-only contiguous
  materialization for each authenticated chunk-index digest, separated by the
  checkpoint key domain and blob name.
- A restore examines the cached indexes, chooses the one with the fewest
  differing chunk entries, makes a private copy-on-write clone where the host
  filesystem supports it, and overwrites only changed chunks. The portable
  sparse-copy fallback preserves the same private-file behavior.
- Every cached source is verified before it is selected. Every completed
  private result is verified chunk-by-chunk before a restore, fork, or warm
  claim can hand it to a backend. A cache entry records the canonical index it
  was built from and is published read-only only after the contiguous bytes
  verify.
- Candidate selection, verification, invalid-entry replacement, and publish
  are serialized by one per-domain/per-blob file lock. This deliberately
  covers the whole candidate set because nearest-index selection reads every
  entry in that set.
- Same-identity restore, checkpoint fork, VM-full fork, warm-snapshot claim,
  and durable-session resume all use the shared cached materializer. Small
  whole-file sidecars keep their existing copy-on-write clone path.
- The snapshots guide now describes chunk storage, domain isolation, diff
  materialization, final verification, and the private-file boundary.

## Measurement

The deterministic diff-restore test uses twenty non-zero 1 MiB chunks, changes
one chunk, and observes the byte count issued by the chunk writer:

| Restore | Chunk bytes written |
| --- | ---: |
| Cold materialization | 20 MiB |
| Nearest cached index, one changed chunk | 1 MiB |

That is a 95% reduction. Counting the materializer's writes makes the witness
stable across APFS `clonefile`, Linux `FICLONE`, and filesystems that take the
sparse-copy fallback. Restoring the exact cached index rewrites zero chunks.

## Tests

- `cached_materialization_rewrites_only_the_changed_chunks` proves nearest
  cached-index selection, the 20 MiB to 1 MiB reduction, canonical index
  recording, byte equality, and a read-only shared cache.
- `editing_the_cache_after_restore_cannot_change_the_private_result` restores
  from the exact cached index, edits the cache afterward, and proves the
  restored file is unchanged.
- `concurrent_publishers_wait_for_the_blob_cache_transaction` and
  `a_reader_cannot_observe_an_invalid_entry_being_replaced` use an OS-level
  contention event to prove publishers serialize and readers wait for an
  invalid-entry replacement transaction. Timeouts are deadlock guards only.
- The checkpoint namespace passes 108 tests with two ignored timing witnesses.
- `cargo check --workspace` and
  `cargo clippy --workspace --all-targets -- -D warnings` pass.
- The exact single-threaded workspace run,
  `source scripts/dev-env.sh && cargo test --workspace -- --test-threads=1`,
  passed every unit and integration crate, including `mvm-runtime` (1,086
  passed, eight ignored), then exited at the `mvm-build` doctest because
  rustdoc transiently reported `E0463` for an existing `mvm_sdk` artifact.
  The immediate isolated rerun,
  `source scripts/dev-env.sh && cargo test -p mvm-build --doc --
  --test-threads=1`, passed with exit status zero, confirming target-artifact
  churn rather than a source or checkpoint failure.
- `cargo fmt --all --check` passes, and
  `cargo run -q -p xtask -- check-all` reports 74 gates clean.

## Remaining work

C5–C8 remain open: object/staging garbage collection, the snapshot/audit
format decision, admitted-tenant domain resolution, and removal/refusal of the
old whole-blob layout. This slice materially advances #3384 but does not close
it.
