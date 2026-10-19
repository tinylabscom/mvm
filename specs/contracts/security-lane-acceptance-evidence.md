# Security lane acceptance evidence

Backing: preview
Validation: none — this records evidence for the parent issue; it is not a claim of complete enforcement.

This reconciles [#4464](https://github.com/tinylabscom/mvm/issues/4464) (the
`Security` workflow red on its schedule) against two manual runs. The issue owns
status.

## Acceptance evidence and its limits

| Criterion | Evidence | Limit |
|---|---|---|
| Every `Security` lane green on a tree carrying the fixes | [Run 39251464565](https://github.com/tinylabscom/mvm/actions/runs/39251464565), `workflow_dispatch` on `3cf2f8977e26f6da5b297b1e7cdb2ba5233e6e26`: 44 of 44 jobs succeeded, including supply chain (cargo-audit, cargo-deny), every mutation shard (the `mvm-cli` lane in four 0-based slices) and the fuzz lanes | One run on one commit. The `mvm-cli` shards were the longest and finished inside the 315-minute step limit; headroom was not measured. |
| The earlier failure was the slice numbering and nothing else | [Run 39229250912](https://github.com/tinylabscom/mvm/actions/runs/39229250912) on `29c641f42597779c5e74b623509d0b4c79bbf3e9`: 43 of 44 succeeded; the only failure was `mvm-cli/m4of4`, which passed a 1-based slice index to `cargo-mutants`. Run 39251464565 is the same lanes after the 0-based fix | Shows the failure was fixed, not that it cannot recur if the shard count changes. |
| The nightly schedule is green | Not witnessed. Both runs are dispatches, and a dispatch is not the scheduled run that [#4480](https://github.com/tinylabscom/mvm/issues/4480) watches | The next scheduled `Security` run is the evidence for the schedule; #4480 stays open until it passes. |
