---

# Batch fork: `machine fork --count N`

Backing: shipped-source
Validation: check-sprint-append

Issue: tinylabscom/mvm#3641 — `machine fork --count N` — one capture, N live children

## Outcome

Add `--count N` flag to `machine fork` so a single capture can serve N
copy-on-write children, all resuming from the same point. This pattern (RL
rollouts, agent swarms) is now cheap — previously every `machine fork` call
re-captured the parent, pausing it N times for identical snapshots.

### What changes

- One `vm_full` capture serves the whole batch; each child forks through the
  **existing per-child arm unchanged** — fresh claim-8 plan, grant subset
  check, audit-chain verification, lineage record, post-restore identity
  delivery.
- Batch children: `<parent>-fork-<i>-<timestamp>` (1-based). `--as`/`--branch`
  refuse above 1 — one name cannot name N children, and siblings under one
  timestamp would collide.
- Fail-fast: a failed child aborts the batch; the error names the
  already-forked children (they are live VMs the caller must clean up).
- `--json` above 1 emits **one array-shaped document** (`fork-batch` → per-child
  entries) instead of N streamed objects; `count=1` is wire-identical to today,
  including output shape and fail-before-capture name validation.
- `fork_vm_full_machine` now returns the child's `CheckpointMeta`; the
  single-child callers ignore it.

## Validation

- New tests: CLI parsing (`--count 4`, the `1..` range refusal, default 1),
  batch naming, both conflict refusals, the JSON document shape, and two BDD
  scenarios (`machine fork --help` documents `--count`; `--count 0` exits 2).
- Full `mvm-cli` lib suite green (2123 passed, 0 failed) rebased on the #3642
  env-race fix; `clippy --all-targets` and `clippy-bdd` clean.

Live-hardware note: the per-child restore numbers come from the #3552 witness
runs (`just live-fork-witness root@<host>`); a batch-mode live witness
(fork N on real KVM in one call) is a sensible follow-up once this lands.

Closes #3641.
