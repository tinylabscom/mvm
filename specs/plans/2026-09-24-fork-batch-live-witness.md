# Batch live witness: fork N children from one running parent

Backing: shipped-source
Validation: check-sprint-append

Issue: tinylabscom/mvm#3641 (closed by #3645) — this is the evidence follow-up
the #3645 PR body named: the batch path has unit/BDD coverage but never ran
end-to-end against a live parent at N>1.

## What changes

- [x] `fc_fork_live.rs`: child count parameterized via `MVM_LIVE_FORK_CHILDREN`
      (default 4); one capture still serves all children; batch wall time
      printed as `FC_FORK_BATCH_MS` alongside per-child `FC_FORK_RESTORE_MS`.
      Assertions already scale pairwise (endpoints, egress keys, tokens,
      randomness) — they just see more children now.
- [x] Run on real KVM via `just live-fork-witness root@<host>`; record the
      numbers in the PR and on #3641.
- [ ] Gates + PR + queue + closeout.
      Numbers: 4 children, restores 46/38/38/39 ms, batch wall 35.9 s
      (per-child subprocess ~7-14 s; parallel spawn would cut the wall —
      the profiling note behind a possible parallel-fork follow-up).
