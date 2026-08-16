# 2537 — the shard that could not finish

## The half #2540 did not cover

Five shards of the nightly mutation lane failed on `bdff1866`. Four were the
ratchet doing its job and #2540 closed them. The fifth, `mvm-hostd`, was not a
mutant failure at all: it ran 3h17m, reached file **6 of 10**, and died on
`The runner has received a shutdown signal`.

No overlapping `Security` run existed to cancel it, so that was an infra
reclaim — but the shard was on track for ~5.5h against a six-hour cap, with no
`timeout-minutes` anywhere in `security.yml`. Baselining a mutant does not make
a shard faster. This one would have gone red again.

## What shipped

- **A package can be split further.** `mvm-hostd/1of2` wherever a package name
  is accepted, parsed by `parse_shard_spec` and passed through the existing
  `--package` flag. `mvm-hostd` becomes two matrix rows of five files each.
- **Membership is a property of the surface.** Files are sorted by path, then
  assigned by stride. Resolution order cannot move a file between shards, so a
  survivor cannot appear and vanish by shard. Stride rather than contiguous
  blocks because adjacent surface files tend to be siblings of similar cost.
- **The split must be total.** `check_shard_matrix` now rejects a missing
  index, a repeated one, disagreeing totals, and a bare entry alongside sharded
  ones. Each of those leaves files nothing mutates while every remaining shard
  reports success — the silent loss the package-level check already existed to
  prevent, one level in.
- **`timeout-minutes: 330`**, under the platform cap, so a shard that outgrows
  its budget fails as itself instead of as infrastructure.
- **The partial output survives.** `TMPDIR` is pinned and the cargo-mutants
  directory is uploaded on `always()`. A killed shard had measured most of its
  files and left no trace of it.

## A bug the gate caught in its own change

The first version put a YAML comment above the new matrix rows. `shard_entries`
treated any non-`- ` line as the end of the list, so everything below the
comment — `mvm-contract`, `mvm-runtime`, `mvm-sdk`, `mvm-vmm` — read as
unsharded and the gate went red. That is the parser silently truncating the
matrix, which is precisely what this check exists to catch, and it caught it.
Comments are now skipped, pinned by
`a_comment_between_entries_does_not_truncate_the_matrix`, which was confirmed
to fail with the fix reverted.

## Also

`security-lane-watch.yml` described the mutation lane as
`continue-on-error: true`. It is not, and `security.yml` has carried no
`continue-on-error` for months. The rationale for reading conclusions from the
API still holds on its own, so the comment keeps it and drops the false example.

## Evidence

- `cargo test -p xtask --bin xtask` — 599 passed, 0 failed.
- `check-mutation-witnesses` (PinOnly) accepts the new matrix; hand-broken
  variants produce, respectively: `declares shards {1} of 2 for mvm-hostd`,
  `mixes sharded and unsharded entries for mvm-hostd`, and `disagreeing
  totals`. Each was run and each went red.
- `cargo +nightly fmt --all --check`, `cargo clippy -p xtask --all-targets -D
  warnings`, `actionlint`, and the prose gates all clean.

## Not verified here

The shard is split by **file count, not cost** — the two most expensive files
measured so far both land in `2of2`. The shards are expected to fit under the
cap, not to be equal. Only the next nightly measures that, and
`specs/VERIFICATION.md` says to re-measure rather than re-quote.
