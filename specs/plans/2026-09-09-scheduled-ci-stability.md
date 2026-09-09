# Scheduled CI stability

Backing: shipped-source
Validation: check-sprint-append

**Opened:** 2026-09-09
**Baseline:** `main` at `e3abd2808f`

## Outcome

Close #3222 and #3223 by correcting the two independent failures in the
scheduled Extended and Security lanes, then restore the fresh claim-bearing
evidence required to close #3224. Artifact identity verification and builder
store single-writer exclusion remain fail closed.

## Verified failures

| Issue | Failure | Completion witness |
| --- | --- | --- |
| #3222 | A transient connection reset while fetching a published boot kernel exhausted the single curl attempt and was reported as a missing release asset. | The shared release downloader retries transient failures with a bounded policy, retains resumable partial files, and still requires signed-manifest and SHA-256 verification. |
| #3223 | The mutation lane's unmodified baseline observed immediate lock contention; the old witness could not distinguish a transient release from the deliberately outliving helper retaining the descriptor. | The witness allows only a short bounded release window and still fails while its deliberately outliving helper retains the lock. |
| #3224 | The claim freshness watcher rejected the failed Security schedule as stale claim-bearing evidence. | A fresh successful Security run restores every registered claim witness and the watcher reconciles the issue. |

## Tasks

- [x] Add a failing downloader-argument regression for bounded retries on
      connection resets.
- [x] Add bounded retry flags to the shared resumable curl downloader without
      bypassing signature or digest verification.
- [x] Stabilize the lock close-on-exec witness with a short explicit wait and
      prove the designated long-lived helper remains alive when reacquisition
      succeeds.
- [x] Run focused tests, workspace tests/check, zero-warning Clippy, formatting,
      gated/Linux checks where required, and repository policy gates.
- [x] Merge the issue-linked pull request after all protected-main checks pass.
- [x] Run fresh post-merge Extended and Security workflows, verify both
      issue-specific witnesses, and close #3222 and #3223 with run evidence.
- [ ] Observe a fresh successful scheduled Security run, verify the scheduled
      claim-freshness reconciliation, and close #3224 with schedule evidence.

## Local validation

- The retry-argument regression failed before the downloader change and passes
  afterward.
- `cargo test -p mvm-cli curl_download_args_request_resume -- --nocapture`
- `cargo test -p mvm-build one_shot_store_lock_is_not_inherited_by_spawned_helpers -- --nocapture`
- `cargo nextest run -p mvm-build` — 871 tests passed, including the exact
  mutation-lane baseline that failed in the scheduled Security run.
- `cargo test --workspace` — complete workspace and Rustdoc suite passed. An
  earlier isolated `mvm-build` Rustdoc dependency-link lookup failed once; the
  exact doctest target and the subsequent full rerun both passed.
- `cargo check --workspace`
- `cargo clippy --workspace -- -D warnings`
- `cargo fmt --all -- --check`
- `cargo run -p xtask -- check-all` — 67 gates clean.
- PR #3225 merged as `66a4a5dad1`; its pull-request and merge-group matrices
  completed successfully.
- Extended CI run `34375572530` completed successfully, including the Linux
  Firecracker documented-surface witness; #3222 is closed.
- Security run `34375571861` completed successfully, including the `mvm-build`
  mutation witness; #3223 is closed.
- `cargo run -p xtask -- check-claim-witness-freshness --check-reporting`
  confirms #3224 is waiting only on a successful `schedule`-event Security
  run; the successful manual verification does not satisfy that invariant.
