# Security lane acceptance evidence

Backing: preview
Validation: none — this records evidence for the parent issue; it is not a claim of complete enforcement.

This reconciles [#4464](https://github.com/tinylabscom/mvm/issues/4464) (the
`Security` workflow red on its schedule) against two manual runs and one scheduled run. The issue owns
status.

## Acceptance evidence and its limits

| Criterion | Evidence | Limit |
|---|---|---|
| Every `Security` lane green on a tree carrying the fixes | [Run 39251464565](https://github.com/tinylabscom/mvm/actions/runs/39251464565), `workflow_dispatch` on `3cf2f8977e26f6da5b297b1e7cdb2ba5233e6e26`: 44 of 44 jobs succeeded, including supply chain (cargo-audit, cargo-deny), every mutation shard (the `mvm-cli` lane in four 0-based slices) and the fuzz lanes | One run on one commit. The `mvm-cli` shards were the longest and finished inside the 315-minute step limit; headroom was not measured. |
| The earlier failure was the slice numbering and nothing else | [Run 39229250912](https://github.com/tinylabscom/mvm/actions/runs/39229250912) on `29c641f42597779c5e74b623509d0b4c79bbf3e9`: 43 of 44 succeeded; the only failure was `mvm-cli/m4of4`, which passed a 1-based slice index to `cargo-mutants`. Run 39251464565 is the same lanes after the 0-based fix | Shows the failure was fixed, not that it cannot recur if the shard count changes. |
| The nightly schedule is green | [Run 39722697842](https://github.com/tinylabscom/mvm/actions/runs/39722697842), `schedule` on `main` at `3ae4f85a08c11bbeff19953d107cf3bfaeba0efc` (created 2026-10-22T04:29:54Z, cron `17 4 * * *`): completed `success`, 45 of 45 jobs succeeded. That includes cargo-audit and cargo-deny, `Fuzz — parsers (vsock + OCI)`, `app-deps-audit`, all six `OCI hardening` lanes, `Verified boot artifacts`, `Seccomp tier functional denial`, `Reproducibility`, and every `Claim witnesses — mutation-tested` shard (including `mvm-build`, `mvm-cli` m1of4 to m4of4 and `mvm-hostd` 1of8 to 8of8) | One scheduled run. The two scheduled runs before it (39544413235 on 2026-10-21 and 39369861553 on 2026-10-20) failed, so a single green night is not a trend. Mutation survivors are held by the baseline ratchet in `xtask/mutation-witness-baseline.json`, which this run neither changed nor re-derived; green means no new survivor beyond the baseline, not zero survivors. The fuzz lane runs for a bounded duration per target. |
| The `mvm-build` mutation shard that failed the push run passes | Same run 39722697842: `Claim witnesses — mutation-tested (mvm-build)` succeeded. It was the failing job in the [push run 39338499448](https://github.com/tinylabscom/mvm/actions/runs/39338499448) on `61c07997a30b5e8a6d35e5952f02dc4b43c2a7ab` ([#4545](https://github.com/tinylabscom/mvm/issues/4545)) | Evidence is a later tree on a schedule, not a rerun of that commit. |
| The claim-witness freshness watcher is green | Not witnessed. The `Claim witness freshness` run 39756426869 (schedule, 2026-10-22T09:34:05Z) failed, and it started before the `Security` run above finished (that run took 5h20m from 04:29), so it judged the previous failed night | [#4480](https://github.com/tinylabscom/mvm/issues/4480) stays open until the watcher (cron `23 9 * * *`) passes on a day after a green scheduled `Security` run. |
