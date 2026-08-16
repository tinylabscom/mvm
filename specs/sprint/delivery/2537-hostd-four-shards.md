# 2537 — two shards were not enough, and the timeout is how we know

## What the first run measured

The 2026-08-16 nightly ran the two-shard split for the first time:

| shard | files | outcome |
|---|---|---|
| `mvm-hostd/1of2` | 5 | finished in **100 min** |
| `mvm-hostd/2of2` | 5 | **330 min, stopped by `timeout-minutes`** — four files done, the fifth never started |

`2of2` drew `plan_admission` (93 mutants), `supervisor/audit_file` (107),
`supervisor/network/stages` (108) and `broker/registry` (27): 335 mutants at
roughly a minute each. `1of2`'s five files came to a fraction of that. Splitting
by file count does not split by cost, and this package's files differ by ~4x.

The previous delivery note said the shards were "expected to fit, not to be
equal." Half of that was wrong, and this is the correction.

## The fix

Four shards. Stride over the path-sorted list puts `plan_admission` and
`network/stages` — the two most expensive — in different jobs, and drops the
worst known load from 335 mutants to 201, about 200 minutes at the rate this
run measured.

That is a bound with a measurement behind it rather than a guess. It is still a
stride, though: if a shard breaches again, the next step is assignment by
measured cost, not more shards. `specs/VERIFICATION.md` says so.

## The two mechanisms from #2565 both paid out

Neither was hypothetical for long:

- **`timeout-minutes: 330`** turned what would have been
  `The runner has received a shutdown signal` at the six-hour cap into a
  bounded stop attributable to one named shard. Worth recording that GitHub
  reports a timeout kill as `cancelled`, not `failure` — reading it as
  infrastructure noise is easy and wrong.
- **The `always()` artifact upload** ran even on the timeout kill and produced
  the per-file `outcomes.json` that made the imbalance measurable. Without it
  the evidence died with the runner and the only available move would have been
  to guess at a shard count.

The same upload is what diagnosed the `mvm-vmm` failure earlier in the same run,
while job logs were still withheld because the run had not finished.

## Evidence

- `cargo test -p xtask --bin xtask shard` — 10 passed.
- `check-mutation-witnesses` accepts the four-way matrix (it is the gate that
  would reject an incomplete split).
- `actionlint`, `check-declared-backing`, `check-honesty`, `check-no-overclaim`,
  `check-doc-claims` clean.

## Not verified here

That `4of4` fits. Only the next nightly measures that. The estimate is ~200
minutes against a 330-minute bound, derived from this run's ~1 min/mutant.
