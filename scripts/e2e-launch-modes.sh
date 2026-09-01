#!/usr/bin/env bash
# End-to-end launch gate: boot a real guest through every README-documented
# entry point, on whatever backend this host actually has.
#
# The gap this closes: the only pre-existing live README scenario is
# `@firecracker`-tagged, so it is skipped on every host without `/dev/kvm`.
# On macOS — where HVF is the default backend — that meant nothing in the suite
# ever booted a guest, and a launch regression on the default backend had no
# lane that could see it. Everything here runs wherever `mvmctl` can boot.
#
# Usage:
#   scripts/e2e-launch-modes.sh              # against ~/.mvm (warm, the real one)
#   MVM_E2E_HOME=/tmp/e2e scripts/e2e-launch-modes.sh
#
# Artifacts are acquired once into the chosen home; the scenarios then share it.
# A cold home pays a multi-minute bootstrap on the first run and is fast after.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO="$PWD"

# Prefer an explicit `MVM_E2E_HOME`, then `MVM_HOME`, then the real home.
#
# `scripts/dev-env.sh` gives each worktree its own `MVM_HOME` *and* its own
# `CARGO_TARGET_DIR`. Defaulting straight to `$HOME/.mvm` honoured the second
# half of that and ignored the first: a worktree built its own binaries and then
# pointed them at the main checkout's artifacts. The guest boots and the host
# session handshake dies with `Socket is not connected`, which reads as a broken
# backend rather than as two trees sharing one home.
#
# That made worktree-based e2e work impossible by construction, so every
# verification had to run in the main checkout.
E2E_HOME="${MVM_E2E_HOME:-${MVM_HOME:-$HOME/.mvm}}"

# A CHANGING value, exported for every cargo invocation below.
#
# `mvm-cli`'s build script reuses a previously cross-compiled embedded host
# binary whenever `PROFILE == debug` and one is on disk. That reuse is sound for
# ordinary development but not for a launch gate, which exists to measure this
# tree: `MVM_EMBED_NO_CACHE` (any non-empty value) forces the rebuild. Two traps,
# both of which produce a suite that passes against bytes it did not build:
#
#  * Set it on only the first build and the later `cargo build -p xtask` /
#    `cargo test -p mvm-conformance` re-run the build script without it and take
#    the reuse branch again.
#  * Export a constant `1` and the second run of this script is a no-op:
#    `cargo:rerun-if-env-changed` compares the value, `1 == 1`, so the build
#    script never re-runs at all. Setting a flag that is already set changes
#    nothing.
#
# A per-run value satisfies both: the value always differs from last run, so the
# build script re-runs, and it is non-empty, so the rebuild is forced. Costs a
# cross-compile per gate run, which is the price of measuring the tree.
export MVM_EMBED_NO_CACHE="e2e-$(date +%s)"

# The builder VM's wall-clock cap, raised from its 30-minute default.
#
# This lane can legitimately face a cold workload-kernel build, which is a
# half-hour of nix on an unloaded host and longer on a busy one. At the default
# the gate fails on a slow build rather than a broken one — and fails ~30
# minutes in, after the expensive part, which is the worst possible place to
# learn nothing. `ci-full.yml` already runs its builder lane at 7200 for the
# same reason; matching it keeps the two from disagreeing about how long a
# build is allowed to take.
#
# Respects an operator override so a bisect can still set it lower.
export MVM_BUILDER_VM_TIMEOUT_SECS="${MVM_BUILDER_VM_TIMEOUT_SECS:-7200}"

# Skips this lane will not tolerate.
#
# The tally printed after the suite is advice, and advice is not read at the
# moment it matters: a runner that quietly loses a capability produces a green
# run that proved less than the one before it, and nothing says so. Under
# `MVM_BDD_STRICT_SKIPS` the suite exits nonzero instead, naming the reason.
#
# The allow-list is only what is a genuine property of the host or a declared
# state of the work — never a capability this lane is supposed to provide.
# `needs-workload-kernel`, `needs-guest-bin-dir` and `needs-firecracker` are
# deliberately absent: if one of those fires, the lane did not boot what it
# claims to boot, and that has to be a failure rather than a footnote.
#
# `needs-perf-budget-host` is a latency threshold that measures the disk on
# rotational storage rather than the code. Nothing here is @wip any more, so
# `pending` is not tolerated: a scenario parked mid-change would otherwise
# reduce this lane's coverage silently.
#
# `needs-dir-share` is set below rather than tolerated blindly: libkrun and HVF
# serve virtio-fs directory shares and must run those scenarios, while
# Firecracker has no virtio-fs device and cannot. Opting in means a capable
# backend runs them and only a genuinely incapable one skips — the alternative,
# tolerating the skip without opting in, silently dropped the witness for the
# README's two `--mount` examples on a host that could have run it.
ALLOWED_SKIPS="needs-perf-budget-host,needs-dir-share"

# Floor on scenarios that must actually execute. See the assertion after the
# cucumber run for why a count, not just an exit status.
#
# EXECUTED, not authored. 26 scenarios are authored across the three feature
# files. Two are capability-gated — the launch-budget threshold on
# `MVM_BDD_PERF_BUDGET`, and the `--mount` share on `@dir_share`, which
# Firecracker cannot serve. So the least-capable host this lane is expected to
# pass on executes 24, and that is the floor. A floor set from the authored
# count fails everywhere a gated scenario is legitimately skipped.
#
# Raise this with every scenario added. It was 17 against an authored count of
# 17, so it had the same defect and had simply never been reached: `pipefail`
# fails the cucumber pipeline the moment any scenario fails, and the floor is
# only checked after a fully green run.
MIN_SCENARIOS=24
SCENARIO_LOG="$(mktemp -t mvm-e2e-scenarios)"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
MVMCTL="$TARGET_DIR/debug/mvmctl"

# Sweep this lane's guests too, on the way in and out. It boots the same kind of
# machine as `e2e-documented-surface.sh` and had no cleanup of its own, so a run
# killed at the wrong moment left a guest holding its name and the next run
# failed on a collision that reads as a broken verb. Scoped to the `bdd-` prefix
# every suite machine carries, so a machine you made by hand is never touched.
sweep() {
  [[ -x "$MVMCTL" ]] || return 0
  # Pass the home through explicitly: the cleaner defaults to ~/.mvm, which is
  # not necessarily the home this run is using.
  MVM_E2E_HOME="$E2E_HOME" ./scripts/e2e-documented-surface.sh --clean-only \
    >/dev/null 2>&1 || true
}
trap sweep EXIT
trap 'echo; echo "!!! interrupted — cleaning up"; exit 130' INT TERM

# Follow each guest's console as it boots. Cucumber only prints a step's output
# when the step fails, so without this a multi-minute boot shows nothing.
WATCHER_PID=""
if [[ "${MVM_E2E_FOLLOW:-$([[ -t 1 ]] && echo 1 || echo 0)}" == "1" ]]; then
  ./scripts/e2e-watch-vms.sh "$E2E_HOME" &
  WATCHER_PID=$!
  trap 'kill -TERM "$WATCHER_PID" 2>/dev/null || true; sweep' EXIT
fi

sweep   # clear anything a previous run left behind

echo "==> e2e launch gate"
echo "    repo:  $REPO"
echo "    home:  $E2E_HOME"

# ---------------------------------------------------------------------------
# 1. Build the binaries the suite drives.
# ---------------------------------------------------------------------------
# Deliberately no `just embed-refresh` here. That recipe clears the nested musl
# cross-compile of the *embedded* host-vm binaries, which is a different set
# from the per-VM helpers rebuilt below, and clearing it mid-tree makes the
# nested build fail outright:
#   could not write output to .../host-vm-target/.../deps/...: No such file or
#   directory
# The staleness this gate actually hits is the supervisor, handled below.
echo "==> building mvmctl + host helpers"
./scripts/cargo-fast.sh build --bin mvmctl --features embed-host-bins
./scripts/cargo-fast.sh build -p xtask

# Build the library-seam test targets here too, not when phase 2 reaches them.
# `cargo build --bin mvmctl` does not build another crate's test targets, so
# they were compiling *after* 23 scenarios had already booted guests — a minute
# of build output in the middle of a run, and a compile error there arriving
# only once the expensive part was already paid for.
./scripts/cargo-fast.sh build -p mvm-client --tests

# Always rebuild the per-VM helpers, never just check they exist.
#
# Presence is not freshness. `cargo build --bin mvmctl` regenerates some of them
# and not others, so a stale `mvm-hvf-supervisor` from an earlier build survives
# a refresh — and a stale one is worse than a missing one. It parses the config
# `mvmctl` hands it with `deny_unknown_fields`, so a field added on the host
# side makes it exit 1 with "unknown field", which the launch path reports only
# as "hvf supervisor exited before writing its PID file". That message names
# neither the binary nor its age, and the guest console is empty because the
# supervisor died before the guest ever ran — so nothing in the output points
# at the real cause.
#
# cargo makes this a no-op when they are already current, so always doing it
# costs a fingerprint check. The signing step below must follow it: a re-linked
# supervisor loses its Hypervisor.framework entitlement.
echo "==> building the per-VM host helpers"
just build-supervisors

# ---------------------------------------------------------------------------
# 2. Warm the shared artifact home.
#
# Every launch needs the workload kernel, the runtime overlay and the universal
# initramfs. Acquiring them inside a scenario would put minutes on each one, and
# a scenario that times out reads as a launch failure rather than a cold cache.
#
# Budget honestly: on a source checkout with a cold `~/.mvm` this is not a warm
# up, it is a build. `bootstrap` compiles the per-VM supervisors and then runs a
# Nix build inside the builder VM, which is tens of minutes and silent for most
# of it. A change touching `mvm-agentd` also re-fingerprints the guest binaries,
# so the runtime overlay and initramfs rebuild on the next boot even when the
# cache was warm before. Subsequent runs against an unchanged tree are fast.
# ---------------------------------------------------------------------------
# macOS kills an unentitled Hypervisor.framework binary with SIGKILL, and the
# only symptom is "hvf supervisor exited before writing its PID file (status:
# signal: 9)" — which names neither the signature nor the rebuild that dropped
# it. Read the status: `signal: 9` is this, an unentitled binary; `exit status:
# 1` is a *stale* supervisor refusing a config field it does not know. The two
# arrive through the same message and have nothing else in common.
#
# Signing must follow the helper build above, because re-linking drops the
# entitlement.
echo "==> signing VMM binaries"
"$MVMCTL" env sign

echo "==> warming artifacts in $E2E_HOME"
# A throwaway transient launch, not `bootstrap`.
#
# These scenarios boot OCI images. What they need warm is the workload kernel,
# the runtime overlay, the universal initramfs and an unpacked rootfs — exactly
# what one `machine run --image` acquires on first use. `bootstrap` additionally
# builds the Nix *builder VM* image, which no scenario here ever uses, so it made
# the gate depend on a heavyweight subsystem it does not exercise: a corrupt
# Stage 0 store ("persistent Stage 0 ext4 store reported N filesystem errors")
# failed the whole suite before a single scenario ran, for a reason unrelated to
# any launch mode.
MVM_HOME="$E2E_HOME" "$MVMCTL" machine run --image alpine -- true

echo "==> host posture"
MVM_HOME="$E2E_HOME" "$MVMCTL" doctor || true

# ---------------------------------------------------------------------------
# 3. The CLI + SDK launch modes, as cucumber scenarios.
#
# `MVM_BDD_LIVE=1` opts into scenarios that boot a real microVM. No
# `MVM_BDD_CI_LIVE_ONLY` here: that selector narrows to the merge-queue subset,
# which is the narrowing that hid this class of failure.
# ---------------------------------------------------------------------------
# Scoped to the launch suite with `-i`, deliberately. Unscoped, this ran the
# *entire* conformance suite under MVM_BDD_LIVE=1 — the doc-example checkers,
# the cross-language SDK surface comparison, the real Nix flake build. Those are
# `just bdd`'s job and they have their own prerequisites: this gate went red on
# a missing TypeScript toolchain and on a builder-VM Stage 0 store, neither of
# which is a launch mode. A gate that fails for things it does not test is one
# people stop believing, which is how the regression this suite exists for
# reached a release in the first place.
#
# The glob is ABSOLUTE. A `cargo test` binary runs with its *package* directory
# as cwd, not the workspace root, so a repo-relative glob matched nothing here —
# and cucumber reports "0 features / 0 scenarios" and exits 0. That is a green
# gate that ran nothing, which is worse than a red one: it is the precise shape
# of the failure this whole suite exists to prevent. Hence the floor below.
echo "==> CLI + SDK launch modes (cucumber, @live)"
CARGO_BIN_EXE_mvmctl="$MVMCTL" \
MVM_BDD_LIVE=1 \
MVM_BDD_DIR_SHARE=1 \
MVM_BDD_STRICT_SKIPS=1 \
MVM_BDD_ALLOWED_SKIPS="$ALLOWED_SKIPS" \
MVM_E2E_HOME="$E2E_HOME" \
  ./scripts/cargo-fast.sh test -p mvm-conformance --test conformance --features bdd \
  -- -i "$REPO/features/suites/s31_launch_e2e/*.feature" -c 1 \
  2>&1 | tee "$SCENARIO_LOG"

# Exit status alone cannot tell "everything passed" from "nothing ran". Assert a
# floor on the count actually executed. Update it when scenarios are added; a
# hard number is the point — a `-gt 0` check would pass on one scenario after a
# filter silently dropped the rest.
ran="$(sed -nE 's/^([0-9]+) scenarios? \(.*/\1/p' "$SCENARIO_LOG" | tail -1)"
ran="${ran:-0}"
if (( ran < MIN_SCENARIOS )); then
  echo "!!! only $ran launch scenario(s) ran, expected at least $MIN_SCENARIOS." >&2
  echo "!!! A gate that runs nothing and exits 0 is the failure this suite exists" >&2
  echo "!!! to catch. Check the -i glob resolves from this script's cwd." >&2
  exit 1
fi
echo "    $ran launch scenario(s) executed"

# ---------------------------------------------------------------------------
# 4. The Rust library seam.
#
# `MvmClient` + `LocalBackend` is the third README entry point, and driving it
# through a subprocess would prove nothing about linking the crate. The live
# lifecycle tests already cover it in-process; they are `#[ignore]`d behind
# kernel/rootfs env vars, which is why they had not been running. Resolve those
# from the home we just warmed and run them.
# ---------------------------------------------------------------------------
echo "==> Rust library seam (mvm-client, in-process)"
KERNEL="$(find "$E2E_HOME/cache/kernels" -name vmlinux -path '*workload*' 2>/dev/null | head -1 || true)"
ROOTFS="$(find "$E2E_HOME/cache/oci/rootfs" -name rootfs.ext4 2>/dev/null | head -1 || true)"

# Passed explicitly rather than left to `aux_bin::resolve`, which searches the
# running exe's neighbourhood — and a `cargo test -p mvm-client` binary lives in
# `target/debug/deps/`, not beside the supervisor. Without this the seam fails
# with "mvm-hvf-supervisor not found", which reads as a missing build rather
# than a lookup that cannot reach it.
#
# Absolute, and scoped to the debug profile: the test binaries are debug, and a
# release supervisor here fails as "not a file" once the test's own working
# directory differs from this script's. Resolved by `cd`+`pwd` rather than by
# prefixing `$REPO`, which would corrupt an absolute `CARGO_TARGET_DIR`.
SUPERVISOR=""
if [[ -f "$TARGET_DIR/debug/mvm-hvf-supervisor" ]]; then
  SUPERVISOR="$(cd "$TARGET_DIR/debug" && pwd)/mvm-hvf-supervisor"
fi

if [[ -n "$KERNEL" && -n "$ROOTFS" && -n "$SUPERVISOR" ]]; then
  echo "    kernel:     $KERNEL"
  echo "    rootfs:     $ROOTFS"
  echo "    supervisor: $SUPERVISOR"
  MVM_E2E_KERNEL="$KERNEL" \
  MVM_E2E_ROOTFS="$ROOTFS" \
  MVM_HVF_SUPERVISOR_PATH="$SUPERVISOR" \
  MVM_HOME="$E2E_HOME" \
    ./scripts/cargo-fast.sh test -p mvm-client --test launch_lifecycle_live \
      --test launch_lifecycle_live_hvf -- --ignored
else
  # Loud, not silent: a skipped library seam is a coverage hole, and reporting
  # it as nothing is how the last one stayed open.
  echo "!!! SKIPPED the Rust library seam. Missing:" >&2
  [[ -z "$KERNEL" ]]     && echo "!!!   workload kernel under $E2E_HOME/cache/kernels" >&2
  [[ -z "$ROOTFS" ]]     && echo "!!!   OCI rootfs under $E2E_HOME/cache/oci/rootfs" >&2
  [[ -z "$SUPERVISOR" ]] && echo "!!!   mvm-hvf-supervisor under $TARGET_DIR" >&2
  echo "!!! A skipped seam is a coverage hole, not a pass." >&2
  exit 1
fi

# The harness prints a per-reason tally of what it declined to run, so a `@wip`
# scenario is counted and named rather than silently absent. Two are pending on
# the persistent-machine defect — see
# specs/plans/2026-08-26-persistent-machine-path-on-hvf.md.
echo "==> e2e launch gate: all modes exercised"
echo "    check the scenario summary above for anything reported pending"
