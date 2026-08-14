# 2484 — cold-boot latency ceiling gates a PR

## What was missing, and what already existed

No PR-gating check on launch latency, so a regression was found by hand months
late — Firecracker guest boot at 447ms against 58.6ms on the same image.

But the harness was already written. `tests/runtime_boot_bench.rs` measures
live Firecracker boot serially and under fan-out and asserts p50/p95/max
against `MVM_RUNTIME_BOOT_BUDGET_MS`. The issue proposed wiring
`crates/mvm-cli/src/bench/regression.rs` instead, not knowing this existed.

Worse, the one CI reference to it measured nothing. `ci-full.yml` ran
`cargo test --test runtime_boot_bench`, but `MVM_RUNTIME_BOOT_BENCH` is set
nowhere under `.github/`, so the test printed `skipped` and returned `Ok`. The
lane compiled a benchmark and asserted nothing, in a `workflow_dispatch`-only
workflow that does not gate a PR either way.

## What landed

`ci.yml` gains a `boot-latency` lane: pinned firecracker, `/dev/kvm` granted
the way the existing live-spawn lane does it, the pinned `v0.17.0`
default-microvm kernel + rootfs fetched and **sha256-verified against the
release's own manifest**, then the existing benchmark run for real with
`MVM_RUNTIME_BOOT_READY=guest-agent`. Gated on the existing `scope.outputs.code`
filter so it stays off unrelated PRs.

`ci-full.yml`'s comment now says what its invocation actually does — a compile
check, not latency coverage.

## Why the budget is loose

6000ms against a ~2.1s dedicated-host median. A shared runner's variance is
large, so a threshold that survives it cannot also catch a 20% drift. This lane
takes the coarse half deliberately: it catches the multiple-x class, which is
the class that has actually happened. p50/p95/max print on every run, so
tightening later is a reading exercise rather than a guess.

The precise relative-baseline comparison (`compare_to_baseline`,
host-descriptor-pinned) belongs on a dedicated host and is not this lane. One
threshold cannot do both jobs, and a gate that flakes is a gate that gets
switched off.

## First run: a build failure, not a boot failure

The lane's first run failed before booting anything. `mvm-cli`'s `build.rs`
cross-compiles the embedded host binaries and needs the pinned zig, which the
lane did not install — so the root package would not build. Fixed by adding the
existing `./.github/actions/install-zigbuild` step, the same one `bdd.yml` and
`cache-warm.yml` use.

Everything ahead of the boot did work on that run: firecracker installed,
`/dev/kvm` granted, and the pinned image fetched and sha256-verified against the
release manifest. So the lane's shape is right and only the toolchain step was
missing.

Worth noting for the workflow-linting gap tracked separately: no linter would
have caught this. The YAML was valid and `actionlint` passed both before and
after. A missing build dependency is only observable by running the job.

## Not verified here

**The budget has still never been exercised.** The first run died in the build step, so the
boot itself has still not happened. Specifically unproven: that the `v0.17.0`
default-microvm rootfs reaches guest-agent readiness under plain firecracker on
a hosted runner, and that 6000ms clears it there.

The relative-baseline half of the issue is not implemented, so #2484 stays open.
