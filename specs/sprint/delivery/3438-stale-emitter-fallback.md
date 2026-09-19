# check-stubs no longer trusts a stale prebuilt emitter

Issue #3438.

`gen-stubs` and `check-stubs` run the schema emitter binary they find in
`target/debug/`, to avoid cargo's machine-wide package lock. The only test was
whether the file existed. After a merge, a leftover binary emitted the old
schema, so the gate reported drift that was not there. Running its suggested
`gen-stubs` would then have deleted the schema the merge brought in.

`prebuilt_emitter` now uses a binary only if it is current. Cargo writes
`<bin>.d` beside each binary, listing every source it was built from. The
binary is current when none of those sources, and not the workspace
`Cargo.lock`, is newer than it. The lock file is included because a dependency
bump points the build at different files and leaves the old ones, which the
`.d` still names, untouched. Anything that cannot be checked (no `.d`, or a
named source that is gone) counts as stale. A stale binary falls through to
`cargo run`, which rebuilds it, so the lock-free path still applies whenever the
binary is current.

## Witnesses

- `a_stale_prebuilt_emitter_is_not_run`
- `a_current_prebuilt_emitter_is_run_without_cargo`
- `a_lock_file_newer_than_the_emitter_makes_it_stale`
- `an_emitter_that_cannot_be_checked_is_not_run`
- `dep_file_sources_reads_the_rule_and_unescapes_spaces`

## Validation

- `cargo nextest run -p xtask gen_stubs`: 12/12 passed.
- `cargo clippy -p xtask --all-targets -- -D warnings`: clean.
- Live, in a worktree whose `target/debug/emit_*` binaries predated several
  branch switches: the first `check-stubs` judged them stale, rebuilt them
  through `cargo run`, and reported `no drift`. The second run used the rebuilt
  binaries directly (40 s against 8 min under a host load of ~280).
