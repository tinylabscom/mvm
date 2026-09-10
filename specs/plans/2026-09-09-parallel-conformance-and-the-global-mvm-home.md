# Parallel conformance, and the global `MVM_HOME` that prevents it

Scoped while cutting `v0.18.0-rc.1`, where the documented-surface suite ran five
times at ~35 minutes each. Not started: the scoping showed it is larger than it
looks, and the reason is worth writing down before anyone tries it.

## The cost this is about

`just e2e-docs` takes ~35 minutes locally and ~90 in CI. Five runs were needed
for one release — three of them because an unrelated PR landed on main and
invalidated the evidence record mid-flight, and the suite had to be re-run
against the new tree.

Suite runtime therefore multiplies twice: it is the cost of a run, and it is the
width of the window in which main can move underneath one. Halving it helps
both.

The suite spends most of that time booting real microVMs — ~15 live boots that
are I/O-bound, with the CPU idle while a guest boots, handshakes, runs and tears
down. It is a good candidate for concurrency.

## Why concurrency is currently impossible

`crates/mvm-conformance/tests/conformance.rs` pins the whole suite to one
scenario at a time:

```rust
// Warm-restore scenarios mutate the process `MVM_HOME` and call
// in-process seal/verify helpers. Run all scenarios sequentially so
// no other thread observes the environment mid-scenario.
.max_concurrent_scenarios(1)
```

This is correct, not an oversight. Raising it without removing the cause would
introduce races into live tests, and a flaky live suite is worse than a slow one.

The cause is `MvmHomeGuard` (`tests/world.rs:25`), which mutates the
process-global `MVM_HOME` and restores it on drop. Its own doc comment names the
constraint:

> ... via `mvm_core::config::mvm_home`, so they cannot pass a home directory as
> an argument.

Worth being precise about what is *not* the problem: **every scenario already
gets its own `tempfile::tempdir()`**, passed to subprocesses per-command via
`.isolated_home(&home)`. Per-test isolation exists. The gap is only that certain
*in-process* helpers can discover a home solely through the global.

## Scope

Three step files hold the guard, and they are not equally hard.

### Small: `steps/warm_restore.rs`

Calls `pause_and_seal(vm_name, io)`, which derives its directory from the global
home. Its sibling `verify_and_resume_from_dir(dir, io)` **already takes an
explicit path** — the convention exists, half-applied.

Add `pause_and_seal_in_dir(dir, io)` and make `pause_and_seal` a thin wrapper
that computes the dir from `mvm_home()`. This mirrors `verify_and_resume` /
`verify_and_resume_from_dir` exactly, and matches the `_at` / `_within` pattern
used elsewhere (`host_signer::load_or_init_at`,
`stage0_bootstrap_in_flight_at`, `acquire_nix_store_image_lock_named_within`).

### Large: `steps/verified_boot.rs` and `steps/apple_container.rs`

These go through backend construction — `AppleContainerBackend::new()`,
`VmStartConfig` — which reads the home transitively rather than directly.
`apple_container_backend.rs` contains no `mvm_home()` call of its own.

There are **45 `config::mvm_home()` call sites** in the workspace. Threading an
explicit home through backend construction reaches a large fraction of them plus
their callers.

### The part that makes this all-or-nothing

Fixing only the small one unlocks nothing. `max_concurrent_scenarios` is a
property of the whole suite, so **every** guard holder must stop mutating the
global before it can rise above 1.

## Two routes

**A. Remove the global (principled).** Give the helpers explicit-path variants
and thread a home through backend construction. Deletes `MvmHomeGuard` and its
four `unsafe { set_var }` blocks — worth something in a codebase that otherwise
forbids `unsafe`. Cost: the 45 call sites, and it touches the runtime backends.

**B. Shard by process (pragmatic).** Run N conformance processes, each with its
own `MVM_HOME` and a disjoint set of feature files. Sidesteps the in-process
global entirely instead of fighting it, and touches no runtime code.

B has a complication worth knowing before choosing it: the lane's accounting is
per-process. Each shard prints its own `[Summary]` block and its own "did NOT
run" tally, and `xtask record-release-evidence` parses exactly one `[Summary]`
and refuses a log without one. Sharding therefore requires merging those into a
single summary the recorder accepts, and merging the skip tallies so
`MVM_BDD_STRICT_SKIPS` still holds across the whole suite rather than per shard.

That merge is the real work in B, and it is bounded — unlike A, which is not.

## Recommendation

**B first, A later if the `unsafe` removal is wanted on its own merits.** B gets
the wall-clock win without touching runtime code or the 45 call sites, and its
one hard part (summary merging) is contained in the harness where a mistake
cannot reach a shipped binary.

Do not raise `max_concurrent_scenarios` under either route until every guard
holder is gone. A partially-migrated suite would be racy in exactly the
scenarios that seal and verify snapshots.

## What this is not

Not a fix for evidence staleness. Of the three cycles lost to it, one was a
comment-only change to an unrelated `Justfile` recipe — arguably a false
invalidation — but two were real material changes (a `scripts/` edit, a kernel
pin bump) where the gate was correctly refusing a record that no longer
described the tree. A faster suite makes those cheaper to absorb; it does not
make them wrong.
