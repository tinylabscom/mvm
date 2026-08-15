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

## Second run: the pinned image needs its sidecar

With zig installed the lane built and reached a real VM start, which then
refused:

```
refusing to start VM: rootfs at /tmp/boot-image has no `mvm-meta.json` sidecar
```

`admit_runtime_overlay_contract` reads `mvm-meta.json` from the rootfs's own
directory. The release does publish that sidecar, as
`default-microvm-meta-x86_64.json` — arch-qualified, because release assets
share one flat namespace — so the lane fetches it, verifies it under that name,
and copies it to the name the gate looks for. Its `overlayAware: true` is what
the gate needs under the default runtime-source policy.

Each failure has been one layer deeper than the last and none has been the
budget: first the build toolchain, then the image contract. That is the cost of
a lane that could not be exercised before landing.

## Third run: a Firecracker version too old for the launch path

The sidecar gate passed and Firecracker was actually invoked, then:

```
Firecracker API socket .../fc.socket did not appear within 3s
```

The launch path passes `--enable-pci`, which the pinned v1.10.1 rejects
outright — it exits before creating its API socket. The socket-wait timeout is
the only symptom, and it names nothing about the cause.

v1.10.1 came from copying `ci-full.yml`'s older spawn-smoke lane, which predates
the PCI flag. The canonical version is
`crates/mvm-core/src/config.rs::FC_VERSION_DEFAULT` (`v1.14.1`), which
`nix/ops/hetzner/cloud-init.yaml` already tracks with a comment saying so; this
lane now does too.

**The same stale pin is still in `ci-full.yml`'s `workload-spawn-smoke-linux`
lane.** It is `workflow_dispatch`-only, so nobody has run it into this. Not
changed here because this PR cannot verify that lane, but it is very likely
broken for the same one-line reason.

A `failure()` step now dumps `firecracker.log` and `console.log` from the per-VM
state dir. Firecracker's stderr goes there and never reached the job output,
which is why three runs produced symptoms rather than causes.

## Not verified here

**The budget has still never been exercised.** The first run died in the build step, so the
boot itself has still not happened. Specifically unproven: that the `v0.17.0`
default-microvm rootfs reaches guest-agent readiness under plain firecracker on
a hosted runner, and that 6000ms clears it there.

The relative-baseline half of the issue is not implemented, so #2484 stays open.
