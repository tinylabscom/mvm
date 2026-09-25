# #3639 — pin the mutator, and name what a stopped shard never measured

The nightly mutation lane had two ways to report coverage it did not have.

## The mutator was unpinned

`security.yml` installed `cargo install --locked cargo-mutants`. `--locked` pins
the dependency tree of whichever release is newest, not the tool. Accepted
misses in `xtask/mutation-witness-baseline.json` are matched on the description
text cargo-mutants renders, and between the 2026-09-22 and 2026-09-23 runs a
release moved one known-equivalent mutant from `in is_some_and` to
`in install_announcement`. One upstream release can turn a baselined mutant into
a "new" survivor, or make a new one look accepted.

The version now lives once, as `cargo-mutants = "27.1.0"` under
`[workspace.metadata.mvm.toolchain]`. 27.1.0 is what the last fully green
nightly (run 35955924561, 2026-09-24) installed, so the committed baseline
descriptions are the ones it renders. Three places enforce it:

- the lane's install step reads the pin out of `Cargo.toml` and installs
  `cargo-mutants@<pin>`;
- `--run` refuses to start under any other installed version;
- every mode, including the per-PR surface pin, fails a workflow line that
  `cargo install`s cargo-mutants without a version, or with a literal that
  disagrees with the pin.

Bumping the pin is a deliberate change that carries any re-rendered baseline
descriptions with it.

## A stopped shard's tail read as clean

Files run in path order, so a shard stopped by its timeout loses an
alphabetical tail. The output it uploads has no directory for those files, and
`--run` never reaches its verdict at all. Read by a person, the artifact lists
survivors for the files the shard reached and nothing for the rest. That reads
as clean.

`check-mutation-witnesses --verify-outcomes <dir> --package <shard>` now
derives the shard's file set from the pinned surface with the same `for_shard`
packing the run used, and reads each file's evidence from `<dir>`. A file with
no finished result is **unmeasured**. It fails by name, separately from any
survivor. It is unmeasured when:

- no output directory exists, because the shard never reached it;
- there is no `outcomes.json`, or it does not parse;
- the baseline did not pass, or no mutants were tested;
- `end_time` is missing. cargo-mutants rewrites `outcomes.json` after every
  mutant and stamps `end_time` only when it finishes, so the file the shard was
  in when it stopped has a real running total and no end;
- the output was recorded by a cargo-mutants version other than the pin.

Survivors a stopped file did report still count as observed, so a new hole
found before the timeout is not lost with the rest of the file. An accepted miss
in an unmeasured file is not reported as now caught, because it was never
re-observed.

`--run` reads its own output back through the same function, so the two modes
cannot disagree. It also clears each shard file's earlier output first, so
output left by a previous run cannot stand in for a file this run never
reached.

In the lane, the mutation step gets a 315-minute step timeout under the job's
330. The new accounting step then runs `if: always()` and names the unreached
files even when the mutation step was cut off.

## Witnesses

`xtask/src/check_mutation_witnesses.rs`, `evidence_tests`:
`a_truncated_shard_fails_its_unreached_tail_as_unmeasured`,
`a_complete_shard_passes`,
`the_file_a_shard_stopped_in_is_unmeasured_but_its_survivors_count`,
`an_accepted_miss_in_an_unmeasured_file_is_not_reported_as_caught`,
`output_from_another_mutator_version_is_unmeasured`,
`the_workspace_pins_an_exact_mutator_version`,
`an_unpinned_mutator_install_is_reported`; and in `baseline_guard_tests`,
`a_run_interrupted_part_way_through_a_file_is_unmeasured`.
