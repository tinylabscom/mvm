# Security lane: cost-aware mutation shards, and a verdict that reports

Backing: shipped-source
Validation: check-claim-catalog

Two defects, found together while surveying the workflows for
consolidation. Both made the nightly `Security` lane report green — or
report nothing — while claim witnesses were not running.

## 1. Mutation shards were split by file count, not cost

`for_shard` assigned surface files to shards by stride (`i % total`) over a
path-sorted list. Mutation cost across one package's surface spans more
than an order of magnitude, so the assignment was effectively arbitrary.
On `mvm-hostd` it put the four most expensive files in the tree onto two
of the four shards:

| shard | measured | outcome |
| --- | --- | --- |
| `1of4` | 90 min | finished |
| `2of4` | 323 min | killed at `timeout-minutes: 330` |
| `3of4` | 24 min | finished |
| `4of4` | 324 min | killed at `timeout-minutes: 330` |

Measured from the artifacts of Security run 32448509693 (2026-08-21);
`2of4` was cancelled in all six of the runs sampled, `4of4` in four. The
mutants on those shards had not been verified since at least 2026-08-16 —
`mvm-hostd` carries claims 8, 12, 13, 17 and 18.

This had been diagnosed correctly once before and treated with the wrong
remedy: the shard count went 2 → 4 on 2026-08-16 on the note that "file
count is not cost". A cost-blind split of an unequal surface stays unequal
at any width, so it recurred.

Shards are now packed longest-first, heaviest file onto the lightest
shard, weighted by source size. Size needs nothing recorded or maintained
beside the surface and tracks mutant count closely enough to pack with.
Replaying the measured costs: 188/189/191/193 minutes against round-robin's
90/323/24/324 — 1.01x the ideal even split against 1.70x. `mvm-hostd` is
cut six ways on top of that, putting the worst shard at ~181 minutes, 55%
of budget. The headroom is deliberate: two of the per-file costs behind it
are lower bounds, taken from shards killed part-way through a file.

Witness: `cost_packing_balances_a_surface_that_round_robin_left_lopsided`
pins the balance ratio against the measured costs, and fails on the old
assignment. It asserts the ratio rather than a wall-clock budget on
purpose — round-robin's worst shard *measures* 324 and would slip under a
literal 330, because the number is truncated by the kill that produced it.

## 2. The watcher could not report the failure it was written for

`security-lane-watch.yml` selects failing jobs including `cancelled`,
deliberately, because Actions reports a job killed by `timeout-minutes`
that way. Above that selection sat a guard that exited early when the
*run* concluded `cancelled` — and Actions concludes the run `cancelled`
when any single job does. The one case the selection existed for could
never reach it.

Cost, on real runs:

- 32448509693 (2026-08-21, nightly): 29 success + 2 timed-out shards.
  Unreported.
- 32429533885 (2026-08-20): 29 success + **1 outright `failure`** + 1
  timed-out shard. The genuine failure was suppressed too.

Issue #2736 is consequently stale in both directions: it still names
`cargo-audit`, which now passes, and never learned about either run above.

The verdict now lives in `scripts/security-lane-verdict.sh` and skips only
when *no job reached a verdict at all* — which is what an operator
cancelling a whole run looks like, and is the case the old guard was
reaching for. `scripts/security-lane-verdict.test.sh` covers it against
the real payloads; four of its eight cases fail against the old logic.
Wired into `ci.yml`'s lint-policy lane, since the nightly lanes never run
on a PR.

## Not fixed here

Security run 32448509693 completed at 2026-08-21T11:36:49Z and **no
`Security lane watch` run was created for it** — no repo workflow run
exists in that window at all. Every other Security completion sampled did
trigger the watcher, including cancelled ones, so cancellation does not
explain it. The guard fix above means a delivered event now reports
correctly; it does not explain a `workflow_run` event that never arrived.
Tracked separately rather than guessed at.

## 3. The first completed old-layout run exposed seven missing witnesses

Security run 32552650847 finally completed the previous four-shard layout and
reported seven actionable survivors in `plan_admission.rs`: extension budget
conjunction, verified-contract identity, inclusive artifact-size bounds,
guest-extension plan identity and placement, mountpoint collision, and the
assurance proxy's duplicate-service check. These are authorization decisions,
so accepting them into the mutation baseline would hide real fail-open changes.

The predicates are now small, named units with boundary and one-field-at-a-time
witnesses. Attachment tests assert the signed plan identity, guest-only
placement, and duplicate mount refusal; the assurance proxy test pins exact
service equality. A bounded local mutation run exercised the twenty generated
mutants covering those predicates and adjacent provenance fields: 20/20 were
caught in seven minutes. The run also proved that the previously accepted
`replace * with + in admit_within_host_budget` mutant is now caught, so that
obsolete baseline entry is removed instead of retained as a waiver.
