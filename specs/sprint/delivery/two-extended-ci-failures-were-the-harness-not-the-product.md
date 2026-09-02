# Two of Extended CI's failures were the harness, and one could not be read at all

Extended CI's nightly is red on current main. Splitting the standing macOS
hardware gap out of the signal left three real failures to look at. Two of them
turn out not to be product defects, and this fixes both — plus the reason the
third could not be diagnosed.

## `doctor found issues` — the harness made the directory wrong

```
data dir mode: MISSING (expected 0700, got 0755 at /home/runner/.mvm)
```

`scripts/e2e-documented-surface.sh` resolves `E2E_HOME` to
`${MVM_E2E_HOME:-${MVM_HOME:-$HOME/.mvm}}`. On CI neither override is set, so
it is the real `$HOME/.mvm` — and the script created it with a bare `mkdir -p`,
which leaves the runner's umask on it. The suite then runs its own `mvmctl
doctor` scenario, which correctly reports a W1.5 violation on a directory the
harness itself had made wrong before mvmctl ever saw it.

The suite now creates it the way mvmctl would. The chmod is unconditional
rather than folded into `mkdir -m`, which applies a mode only to directories it
actually creates — a home left loose by an earlier run would otherwise keep
that mode forever. Verified under `umask 022`: bare creation gives 0755, the
helper gives 0700.

**This exposed something larger, which is filed as issue #3111 rather than
fixed here.** A 0755 home survived an entire suite run, through many `mvmctl`
invocations that wrote into it, because
`mvm_core::config::ensure_home_dir` — the helper that creates *and repairs* the
mode — has **no callers anywhere in the workspace**. W1.5 is enforced by
nothing; it holds only when the directory happens to be made by a path that
chmods. `cleanup.rs` even documents the repair as something that happens
("re-established... by whichever command next calls `ensure_home_dir()`"), and
no command does. Note the shape: `ensure_private_dir` is unit-tested and
passes, so the mechanism is proven while the wiring is absent — the same defect
CLAUDE.md records for claim 13, and invisible to a green test run either way.
Where the call belongs is a real design question (CLI startup writes `~/.mvm`
on `--help` and during hermetic tests; per-use is a list that rots), so it gets
its own issue rather than a guess appended to a CI fix.

## The aarch64 smoke printed nothing, so nobody could diagnose it

The job reported `Process completed with exit code 143` over a step with **no
output whatsoever**. The boot is redirected wholesale to
`/tmp/mvmctl-first-boot.log`, and the `tail` sat inside the `-ne 7` branch — so
a run killed before reaching that branch read the file never. Five minutes in,
SIGTERM, empty step, nothing to go on.

The dump now runs from an `EXIT` trap armed before the boot, so it fires on any
death. The exit-code assertion is unchanged. This does not fix whatever killed
the step; it is the prerequisite for finding out, and without it the next
nightly would have been equally silent.

## What this does not fix

- **The Linux job's termination** was not ours at all:
  `The runner has received a shutdown signal. This can happen when the runner
  service is stopped, or a manually started runner is canceled.` GitHub
  reclaimed the runner 81 minutes in, against a 120-minute job timeout and a
  3600-second suite watchdog that had not fired. The suite's own trap printed
  `!!! interrupted — cleaning up`, not `!!! TIMEOUT`.
- **Two genuine live-VM failures remain**, both needing reproduction on real
  hardware rather than log-reading:
  - `documented_build_live.feature:27` — `builder egress endpoint pid=… exited
    with status signal: 15 (SIGTERM)` then `Error: Booting VM for the
    entrypoint call`.
  - `hvf_egress_observable.feature:18` — `Error: control frame read failed`,
    `session i/o error: Resource temporarily unavailable (os error 11)`. Same
    EAGAIN signature as the closed #3052.

## Tests

Both fixes are structural and both are pinned, in
`tests/github_actions_extended_e2e.rs`:

- `the_documented_surface_creates_its_mvm_home_private` — refuses the bare
  creation and requires the unconditional chmod.
- `the_aarch64_smoke_prints_its_boot_log_on_any_failure` — requires the dump to
  be armed *before* the run, since a trap installed after it would have the
  same blind spot as the branch it replaces.

`actionlint` clean; `bash -n` clean.
