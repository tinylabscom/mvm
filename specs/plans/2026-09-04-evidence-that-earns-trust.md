# Evidence that earns trust

**Status: OPEN** — written 2026-09-04, after the 0.18 release candidate work.

## Why this exists

mvm advertises fifteen CI-enforced security claims and a README whose every
example is meant to work. Both are true only to the extent something checks
them. On 2026-09-03/04, cutting 0.18 turned up how thin that checking had
become:

- Two regressions reached `main` in one day and were found by the first person
  to run the documented-surface suite, not by CI.
- Nine numbered security claims had a green ledger entry and a red witness lane.
- The macOS documented-surface lane had never been configured for the host tier
  it runs on, so it attested the documented surface using a binary less capable
  than the one that ships.
- Four consecutive `Extended CI` runs cancelled each other, so the lane that
  would have caught the regressions could not finish.

None of that was a lie anyone told. Every piece was a green signal with nothing
behind it — which is worse than a red one, because a red signal gets fixed.

The goal here is not more tests. It is that **every claim we publish has
evidence a stranger could check**, and that the absence of evidence is loud.

## The immediate sequence (0.18.0-rc.1)

- [ ] Gate #3039 behind a declared capability, the way
      `@unenforceable_wall_clock` was gated. The skip line must name what is
      missing and why, so it appears in the "did NOT run" tally rather than
      vanishing. Gating is not suppression *only* if the reader can see it.
- [ ] Run `just e2e-docs` on macOS/HVF against the exact commit to be tagged,
      with a clean tree.
- [ ] `just record-e2e-evidence macos-hvf`, commit the record. It lands under
      `specs/evidence/e2e/`, which is outside `MATERIAL_PATHSPECS`, so recording
      cannot invalidate what it just attested.
- [ ] Obtain the Linux/Firecracker verdict. It does not exist today — not red,
      *absent*. See below.
- [ ] `just record-e2e-evidence linux-firecracker`, commit.
- [ ] Tag `v0.18.0-rc.1`.

## Why Linux has no verdict, and the fix

`ci-full.yml` sets:

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

The documented-surface Linux lane needs over an hour. Dispatches arrive every
40–75 minutes. Four consecutive runs were cancelled by their successors, each
reporting `cancelled` — which reads as a failure in the run list and as "the
lane is red" to anyone scanning. The lane is not red. It has never been allowed
to finish.

- [ ] Scope the concurrency group so a scheduled or dispatched Extended CI run
      is not cancelled by the next one, or exclude the long e2e lanes from
      cancellation. `cancel-in-progress` is right for PR pushes and wrong for a
      nightly whose lanes run for hours.
- [ ] Confirm with one uninterrupted run that the Linux lane completes and
      reports a scenario summary.

Note for whoever picks this up: `release.yml` has **no** concurrency group, so
the tag path already gets an uninterrupted e2e run. That is why a tag push would
produce the Linux verdict today. Do not treat that as the fix — it means the
only configuration that works is the one nobody exercises until it is too late
to act on what it says.

## The structural gap that let two regressions land

PR CI runs the hermetic BDD lane, which skips `@live`. `Extended CI` runs the
live lanes and cannot finish. So a `@live` regression has no gate between the
author and `main`.

Both of 2026-09-04's regressions were exactly that shape:

- Stage 0 silently built the builder-VM image when asked for a workload kernel,
  because `stage0-build.conf` stopped being delivered when the transport moved
  to a block device. Five minutes of building, then a host-side error naming a
  missing file rather than the delivery that never happened.
- `attempt_direct_start` required a probe PATH only a different step installs,
  so a scenario panicked on a precondition before reaching its subject.

- [ ] Decide what gates `@live` before merge. Options, roughly by cost:
      run a reduced live subset on PRs; run the full live lane on the merge
      queue rather than on every PR; or accept the gap explicitly and say so in
      `CONTRIBUTING`, so the next person knows the hermetic pass does not mean
      what it appears to mean.
- [ ] Whichever is chosen, write it down. The current situation is not a
      decision anyone made; it is two reasonable settings that combine badly.

## Making the evidence mean what it says

- [x] The lane builds with the shipped feature set (`user`), so it can verify
      published artifacts the way a released binary does. Before this, the lane
      attested the documented surface using a binary that could not check what
      it downloaded. (Landed in #3170.)
- [x] Declared host capabilities match the tier the lane runs on
      (`MVM_BDD_WALL_CLOCK` on macOS). An undeclared capability runs scenarios
      that assert the opposite of what the host does. (Landed in #3170.)
- [ ] Audit the remaining declared capabilities the same way. `dir_share`,
      `memory_snapshot`, `sdk_sidecar`, `guest_bin_dir`, `tls_tunnel_client`
      and `perf_budget_host` are all operator-declared. Each is a claim about
      the host that nothing checks. At minimum, record which lane declares what
      and why.
- [ ] Treat the "did NOT run" tally as part of the result, not a footnote. A
      green suite with 21 skips is not full coverage, and the runner already
      says so — `a skipped @live scenario is a documented command nothing
      booted`. Whoever reads an evidence record should see the skip count
      beside the pass count.

## Claim witnesses

`security.yml`'s scheduled run was failing `check-mutation-witnesses`, which
flags claims 1, 3, 4, 5, 6, 7, 10, 11 and 15 as having no live evidence. The
witnesses passed; four mutants proved they would not notice the code breaking —
audit decisions disabled, `plan_id` dropped from decision records and
attestation bindings, the secret substitution map emptied.

- [x] Close those four gaps with tests verified by applying the reported
      mutation and confirming failure. (Landed in #3170.)
- [ ] Get `security.yml` green and keep it there. While it is red, the ledger
      asserts nine claims with nothing behind them, and `check-claim-witness-freshness`
      is correct to say so.
- [ ] Never resolve a `check-mutation-witnesses` failure with
      `--write-baseline` unless the surface genuinely moved. The tool offers it;
      taking it converts a real gap into a green light. The baseline had not
      drifted — the witnesses were weaker than the ledger implied.

## What not to retry

- Do not conclude a lane is red because its runs say `cancelled`. Check the job
  duration against `timeout-minutes` first: a job cancelled at 60 minutes with a
  180-minute budget was killed from outside, not by its own timeout.
- Do not read `autoMergeRequest` to decide whether a PR is queued. The merge
  queue *consumes* the auto-merge request on acceptance, so a queued PR reports
  `null` — indistinguishable from a dropped one. Only `mergeQueueEntry`
  separates them. The state needing action is `auto=false` **and** `unqueued`.
- Do not trust `rc=0` from `just embed`. It prints `embedded host binaries are
  STALE` and continues, because the content store keys on the dependency closure
  and `Cargo.lock`, not on the payload's own sources. An edit to a guest binary
  needs `MVM_EMBED_NO_CACHE=1`; `just embed-refresh` alone is not enough.
- Do not run the e2e suite concurrently with anything else that invokes cargo,
  including another worktree. `xtask check-stubs` shells out to `cargo run`
  mid-suite and takes a machine-global lock; three concurrent suites deadlocked
  for minutes and read as a hang.
