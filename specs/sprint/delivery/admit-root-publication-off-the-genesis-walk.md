# Admission stopped re-verifying the whole audit chain

**Status: COMPLETE**

## What was wrong

Every `mvmctl machine run` admission published a Merkle transparency-log root,
and publishing one walked the tenant's entire audit chain from genesis:
`publish_boundary_root` → `AuditEmitter::publish_root` → `sign_root_in` →
`build_root_in` → `read_leaves` → `read_verified_set`, which reads every
segment and Ed25519-verifies every line before the tree is built.

On a host with 22,481 accumulated entries across seven segments (26 MB) that
measured **912 ms of verification plus 18 ms of tree building**, on the boot
critical path, per launch:

```
admit             742.3ms      <- 956ms of it was publish_root
backend start     204.2ms
guest ready         2.9ms
command           163.6ms
teardown           52.5ms
total            1165.7ms
```

Each launch appends ~35 entries and then re-verifies everything before them, so
the cost grew with the host's whole launch history — quadratic over a host's
lifetime, and already 3.5x the 300 ms launch budget on its own.

## What changed

`read_leaves` now takes the last published root at its word for the prefix it
covers, and walks only what was appended since.

A published `SignedAuditRoot` is already a host-signed statement that the first
`tree_size` leaves hash to `root_hash`. When the leaves read now still hash to
that value under that signature, the prefix is attested at the same strength a
genesis walk would establish line by line — so only the suffix needs verifying.
The seed is a host signature rather than a stored integer, which makes it a
stronger anchor than the `ChainCheckpoint` that `doctor` resumes from, and is
why this one is not confined to a health check.

- `merkle::leaves_over_attested_prefix` — the fast path.
- `audit_set::read_topology_verified_set` — the set's bytes with every handoff,
  boundary signature and tip continuity still checked, no interior walked.
- `audit_file::verify_chain_bytes_resuming` — `verify_chain_bytes` seeded from
  an authenticated prefix instead of the genesis anchor.

It never accuses. Every doubt — no published root, one for another tenant, one
that will not verify, one reaching past the log or back before the live
segment, a prefix that no longer hashes to it, a suffix that will not walk —
declines to the genesis walk. So every refusal the module emits is still
anchored at genesis, and a mismatch caused by a stale root is never reported as
tampering.

## What did not change

- `mvmctl trust audit verify` (claim 8's witness) still calls
  `verify_segment_set` and still walks every interior from genesis.
- `record_admission` and the `plan.admitted` durability barrier are untouched;
  the control that claim 8 rests on is the entry, not the root.
- Published roots, root history, and inclusion proofs are byte-identical — the
  fast path returns the same leaves, which the tests assert directly.

## Measured

Same host, same 22.5k-entry chain, 20 consecutive launches:

| | before | after |
|---|---|---|
| admit | 742 ms | p50 **56 ms** (min 54.7, max 64.5) |
| total | 1166 ms | **286–308 ms** |

## Tests

Nine added in `mvm-hostd`'s `audit::merkle` suite. The first asserts the fast
path *engaged* before comparing leaves, because without that every other test
in the group would pass by silently falling back:

- `the_fast_path_takes_the_published_root_at_its_word_and_agrees_with_genesis`
- `a_line_appended_after_the_published_root_is_still_verified`
- `a_tampered_attested_prefix_declines_the_shortcut_and_then_refuses`
- `a_root_signed_by_another_key_does_not_shortcut_the_walk`
- `a_root_reaching_past_the_log_declines_rather_than_indexing_off_the_end`
- `no_published_root_leaves_the_genesis_walk_as_the_only_path`
- `the_fast_path_survives_a_rotation_by_falling_back_once`
- `raw_line_index_translates_leaf_numbering_across_blank_lines`

## Still open

- `backend start` is now the largest phase at ~185 ms, essentially all of it
  `vmm_create`. It is what stands between the current ~300 ms and the 200 ms
  target, and has not been investigated.
- The fast path still reads all 26 MB of segments and builds the tree over
  every leaf twice (once to check the attested prefix, once for the new root):
  ~55 ms, growing linearly with history. Caching sealed segments' leaf hashes,
  or carrying a Merkle frontier on the published root, would make publication
  `O(entries since the last root)`. Not needed for the current budget.
- One 74 s admission was observed on the first launch after a release build
  completed, with `backend start` simultaneously 3x its steady value. It did
  not recur in 26 subsequent launches (p50 56 ms, max 64.5 ms) and was not
  root-caused. No path in this change can account for it — the fallback is the
  genesis walk, measured at under 1 s on this chain.
