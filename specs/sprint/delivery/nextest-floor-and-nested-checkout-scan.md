# Local test gate: 111 phantom failures, and a gate that scanned other checkouts

Two local-environment faults that made `just test` report failures that were
not in the code. Both were invisible in CI, which is what let them persist.

## 111 CLI tests "failing" under nextest

Every root-package CLI integration test failed with
`CARGO_BIN_EXE_mvmctl is unset` — 111 tests across 22 files — while
`cargo test --test <same>` passed. So the entire root CLI suite was gating
nothing under `just test`.

The pinned nightly cargo emits test binaries under
`target/debug/build/<pkg>/<hash>/out/` rather than `target/debug/deps/`.
`assert_cmd::Command::cargo_bin` first reads `CARGO_BIN_EXE_<name>` from the
environment, then falls back to popping one directory and expecting `deps`.
Under the new layout the fallback looks for `mvmctl` inside `.../out/` and
finds nothing; `cargo test` survives only because cargo exports the variable
into the child environment, and cargo-nextest 0.9.122 (2026-01) does not.

Not a code fault, and not fixable in the tests: it is a stale tool. Updating to
0.9.143 takes the suite from 111 failures to 0.

Guarded by `nextest-min` in `Cargo.toml`'s
`[workspace.metadata.mvm.toolchain]` plus `scripts/require-nextest.sh`, wired
into `test`, `test-ci`, `test-crate` and `test-filter`. The guard matters more
than the version bump: 111 red tests read as broken code, and CI never sees it
because the runner installs a current nextest every time — so local is red
while CI is green, which is the worst way for this to present. `0.9.143` is a
known-good floor, not a bisected minimum.

## A gate that walked into another checkout

`test_support_source_owners_match_the_targeted_ci_lane` failed with 34 paths
under `.claude/worktrees/site-isolation-headers/` — a gitignored worktree
belonging to another session, nested inside the repo.

The 12 source-scanning gates walk the filesystem rather than `git ls-files`,
and `fs_walk`'s skip list covered only `target`, `.git` and `node_modules`. So
any nested checkout got scanned and reported as findings in this tree.

`fs_walk::walk_files` now refuses to descend into a directory containing a
`.git` entry — a file for a linked worktree, a directory for a clone. The root
being scanned is never tested, so a normal run is unaffected. Verified both
ways: with the `.git` marker present the gate is green, and with it removed the
same tree turns the gate red, so the skip is what does the work.
