# Fork batch: `machine fork --count N` — one capture, N live children

Issue: tinylabscom/mvm#3641. Unblocked by #3552: the live fork witness measures
39–47 ms per child restore on real KVM (8-core host), so a 32-child batch costs
~1.5 s of restore plus admission overhead.

## Design

- `--count N` (default 1) on `machine fork` only; `restore`/`warm-restore`
  stay single-child.
- One vm_full capture of the running parent (one pause window), then N child
  forks through the existing `fork_vm_full_machine` path — every current
  per-child invariant holds unchanged (fresh claim-8 plan, grant subset check,
  audit-chain verification, lineage record, post-restore identity delivery).
- Naming: count=1 keeps today's `resolve_child_name` exactly. count>1 names
  children `<parent>-fork-<i>-<ts>` (1-based); `--as` and `--branch` refuse
  with count>1 (one name cannot name N children; identical timestamps would
  collide).
- `fork_vm_full_machine` returns the child's `CheckpointMeta` instead of `()`;
  single-child callers ignore it, the batch loop collects it.
- Output: count=1 is wire-identical to today. count>1 emits one human success
  line per child (from the existing arm), and with `--json` a single
  `ForkBatchJson` array-shaped document built from the collected metas —
  never N streamed objects.
- Fail-fast: a child failure aborts the batch; the error names the children
  already forked (they are live VMs the caller must clean up).

## Tasks

- [x] CLI: `--count` with a 1.. range parser on `MachineForkArgs`.
- [x] `ForkMachineInput.count`; `fork_machine` batch loop + naming helper
      (`batch_child_name`, unit-tested) + conflict refusals.
- [x] `fork_vm_full_machine -> Result<CheckpointMeta>`.
- [x] Batch JSON document (`ForkBatchJson`) + human per-child lines.
- [x] Tests: CLI parse (count, range), conflict refusals, naming, JSON shape.
- [x] BDD: `machine fork --help` documents `--count` (s0_cli/verbs.feature).
- [x] Gates: clippy, mvm-cli tests, check-gated; plan/SPRINT/rollups updated.
- [x] PR referencing #3641.
