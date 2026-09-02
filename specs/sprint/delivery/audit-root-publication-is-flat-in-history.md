# Publishing an audit root stopped growing with the log

**Status: COMPLETE**

## What was left over

Taking the genesis walk off the admission path cut `admit` from 742 ms to
~57 ms, but left it `O(history)`: the fast path still read every segment's
bytes and folded every leaf twice — once to check the attested prefix against
the published root, once to build the new one. On the same host and the same
day that number went 57 ms → 68 ms as the chain grew. It would have returned to
where it started.

## What changed

The leaf hashes of the attested prefix are cached, and the cache is checked
rather than believed.

A published `SignedAuditRoot` is a host-signed statement that the first
`tree_size` leaves fold to `root_hash`. So the cache is validated by folding it
and comparing to that signature: a cache that is corrupt, truncated, replaced
or forged does not reproduce the signed root and is discarded. Nothing is taken
on the cache's word — the fold *is* the check.

That changes the cost model. Hashing leaves is proportional to the log's bytes;
folding leaf hashes is proportional to its entries, at 32 bytes each. So the
per-launch cost stops tracking the size of the log and starts tracking the size
of one run's append.

- `mvm_contract::merkle::merkle_root_of_leaf_hashes` — the fold, split out from
  `merkle_root`, which is now that plus one `leaf_hash` per line. Asserted
  identical for every tree size 0..40.
- `audit::leaf_cache` — the sidecar, its encoding, and the fingerprints.
- `audit_set::segment_shape` — the segment set from a directory listing, no
  segment opened.
- `merkle::root_over_cached_prefix` — the fold, guarded.

## What is still checked, and what is not

Three separate questions, answered three different ways on purpose:

- **Are these the attested leaves?** The fold against the host-signed root.
- **Is the live segment still what the cache says?** It is read in full every
  time and compared line by line. An edit there is caught at publish time,
  exactly as before — which is why
  `a_tampered_attested_prefix_declines_the_shortcut_and_then_refuses` still
  passes unmodified.
- **Are the sealed segments still what they were?** Sequence number, length and
  mtime. Not their contents: not reading them is the entire saving.

The third is a narrowing. A sealed segment edited in place, preserving length
and mtime, is no longer detected when a root is published. It is still detected
by `mvmctl trust audit verify`, by `read_leaves` when an inclusion proof is
built, and by any cache miss, all of which walk from genesis. And the root
published over a stale cache commits to the leaves the log actually had — so
this path never signs a statement blessing altered content; it fails to notice
it, which is the weaker failure of the two.

That boundary is a test rather than a paragraph:
`an_in_place_sealed_edit_is_missed_at_publish_but_caught_by_the_genesis_walk`.

The threat it gives up on is a malicious host writing under `~/.mvm/audit/`,
which ADR-001 places out of scope. No numbered claim cites publish-time
refusal; claim 8's witnesses are `verify_audit_chain` and
`mvmctl trust audit verify`, both untouched.

## Measured

Same host, `machine run --image alpine -- sh -c "echo hi"`, HVF. 30 launches:

| | start of day | after the genesis-walk fix | now |
|---|---|---|---|
| `admit` | 742 ms | 57→68 ms, rising | **22–30 ms** |
| total | 1166 ms | 209–228 ms | **p50 161, p95 169 ms** |
| dispatch window | 175 ms | 78–85 ms | **71–85 ms** |

Under the 200 ms target, and no longer a function of how long the host has been
running workloads. The residual ~25 ms of `admit` is the rest of admission —
plan synthesis, signing, the chain-entry fsync barrier, policy resolution —
which the earlier probe measured at ~26 ms with `publish_root` excluded. Root
publication is now a small part of that rather than all of it.

## Still open

- **Teardown is ~47 ms** and is now the largest phase after backend start. Most
  of it is the supervisor genuinely shutting down, observed via kqueue rather
  than polled, so it is real work rather than a scheduling artifact.
- **The first launch after a release build remains an outlier**, and the worst
  one yet was seen here: a 144 s `admit` on the first run against a freshly
  linked binary, against a 22 ms steady state. Five occurrences now across the
  day, always the first run after a build, always every phase affected. Still
  not root-caused. Discard the first sample when benchmarking.
- One total sample in 30 came in at 213 ms. p50 and p95 are inside the target;
  the tail on a developer host at load average ~10 is not.
