#!/usr/bin/env bash
# Run every documented example against a real host, booting real microVMs.
#
# The hermetic lane proves a documented command parses. That cannot see a verb
# which parses and then refuses at runtime, which is what `machine forward` had
# become while `examples/obscura/README.md` still told a reader to run it. This
# runner is the lane that executes them.
#
# Usage:
#   scripts/e2e-documented-surface.sh            # against ~/.mvm (warm, the real one)
#   MVM_E2E_HOME=/tmp/e2e scripts/e2e-documented-surface.sh
#
# Artifacts are acquired once into the chosen home and the scenarios then share
# it. A cold home pays a multi-minute bootstrap on the first run, and is fast
# afterwards.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO="$PWD"

E2E_HOME="${MVM_E2E_HOME:-$HOME/.mvm}"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
MVMCTL="$TARGET_DIR/debug/mvmctl"

echo "==> e2e documented surface"
echo "    repo: $REPO"
echo "    home: $E2E_HOME"

# ---------------------------------------------------------------------------
# Cleanup.
#
# Scoped to the `bdd-` prefix every suite-created machine carries. This home
# defaults to the real `~/.mvm`, so an unscoped sweep would delete the machines
# the person running this actually cares about. Nothing here matches a name the
# suite did not create.
#
# Runs on the way in as well as the way out: a previous run killed at its
# timeout — or with ^C — leaves a guest holding a vsock socket, and the next
# run then fails on a name collision that looks like a broken verb.
# ---------------------------------------------------------------------------
reap() {
  local phase="$1"
  local names
  names="$(MVM_HOME="$E2E_HOME" "$MVMCTL" machine ls 2>/dev/null \
    | awk 'NR>1 && $1 ~ /^bdd-/ {print $1}' || true)"

  if [[ -n "$names" ]]; then
    echo "==> $phase cleanup: reaping $(echo "$names" | wc -w | tr -d ' ') bdd- machine(s)"
    while read -r name; do
      [[ -z "$name" ]] && continue
      echo "    - $name"
      MVM_HOME="$E2E_HOME" "$MVMCTL" machine stop "$name" --yes >/dev/null 2>&1 || true
      MVM_HOME="$E2E_HOME" "$MVMCTL" machine rm "$name" --yes >/dev/null 2>&1 || true
    done <<< "$names"
  elif [[ "$phase" == "pre-run" ]]; then
    echo "==> pre-run cleanup: no leftover bdd- machines"
  fi

  # State directories for suite machines, in case a spec was removed while its
  # runtime directory survived.
  if [[ -d "$E2E_HOME/vms" ]]; then
    find "$E2E_HOME/vms" -maxdepth 1 -name 'bdd-*' -type d -exec rm -rf {} + 2>/dev/null || true
  fi
}

# Per-VM supervisors outlive a killed suite and keep a vCPU thread and a vsock
# socket alive. Only those whose state directory is gone are reaped, so a
# supervisor belonging to someone else's machine is left alone.
reap_orphan_supervisors() {
  local pids
  pids="$(pgrep -f 'mvm-(hvf|libkrun)-supervisor' 2>/dev/null || true)"
  [[ -z "$pids" ]] && return 0
  for pid in $pids; do
    local args
    args="$(ps -o args= -p "$pid" 2>/dev/null || true)"
    case "$args" in
      *bdd-*) echo "    - reaping orphan supervisor $pid"; kill -TERM "$pid" 2>/dev/null || true ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# Following the run.
#
# Cucumber captures a step's output and only prints it when the step fails, so
# a multi-minute boot shows nothing at all while it happens. This watcher runs
# beside the suite instead of inside it: it notices each microVM's state
# directory appearing, announces it, and streams that guest's console with a
# name prefix. That is the part worth watching — the guest actually coming up.
#
# On by default when stdout is a terminal. MVM_E2E_FOLLOW=0 turns it off,
# MVM_E2E_FOLLOW=1 forces it on for a log file or CI.
# ---------------------------------------------------------------------------
if [[ -z "${MVM_E2E_FOLLOW:-}" ]]; then
  if [[ -t 1 ]]; then MVM_E2E_FOLLOW=1; else MVM_E2E_FOLLOW=0; fi
fi

WATCHER_PID=""

start_watcher() {
  [[ "$MVM_E2E_FOLLOW" == "1" ]] || return 0
  ./scripts/e2e-watch-vms.sh "$E2E_HOME" &
  WATCHER_PID=$!
  echo "==> following microVM lifecycle (MVM_E2E_FOLLOW=0 to silence)"
  echo "    the same view from another terminal:"
  echo "      scripts/e2e-watch-vms.sh $E2E_HOME"
}

stop_watcher() {
  [[ -n "$WATCHER_PID" ]] || return 0
  # The watcher's `tail` children are in its process group; kill the group.
  # The watcher's `tail` children sit in its process group; signal the group
  # so a follower does not outlive the run.
  # The watcher reaps its own console followers from its EXIT trap.
  kill -TERM "$WATCHER_PID" 2>/dev/null || true
  WATCHER_PID=""
}

on_exit() {
  local status=$?
  stop_watcher
  echo
  reap "post-run"
  reap_orphan_supervisors
  return "$status"
}
trap on_exit EXIT
trap 'echo; echo "!!! interrupted — cleaning up"; exit 130' INT TERM

# ---------------------------------------------------------------------------
# 1. Build what the suite drives.
#
# The conformance runner refuses to start against an `mvmctl` older than its own
# sources, so this has to happen before the test binary runs, not alongside it.
# ---------------------------------------------------------------------------
# `--clean-only` reaps and exits: the escape hatch for a run killed hard enough
# to skip its own trap. Deliberately before the build — cleaning up after an
# interrupted run must not depend on the tree compiling.
if [[ "${1:-}" == "--clean-only" ]]; then
  if [[ ! -x "$MVMCTL" ]]; then
    echo "no mvmctl at $MVMCTL — nothing to reap with" >&2
    trap - EXIT
    exit 1
  fi
  reap "manual"
  reap_orphan_supervisors
  trap - EXIT
  echo "==> clean"
  exit 0
fi

# `user` carries manifest-verify, which the verified-fetch path needs to accept
# the published builder VM image. It is off by default anyway: that feature
# pulls the sigstore/aws-lc stack, and on both hosts tested aws-lc-rs resolves
# while its native symbols do not, failing the link outright. A build that does
# not link runs nothing, which is strictly worse than losing the flake-build
# scenarios to an unverifiable fetch. Set MVM_E2E_FEATURES=user where that
# native toolchain is known good.
E2E_FEATURES="${MVM_E2E_FEATURES-}"
if [[ -n "$E2E_FEATURES" ]]; then
  echo "==> building mvmctl (--features $E2E_FEATURES)"
  ./scripts/cargo-fast.sh build --bin mvmctl --features "$E2E_FEATURES"
else
  echo "==> building mvmctl"
  ./scripts/cargo-fast.sh build --bin mvmctl
fi

# Now that `mvmctl` exists, clear anything a previous run left behind. A guest
# still holding its name makes the next run fail on a collision that reads as a
# broken verb.
reap "pre-run"
reap_orphan_supervisors
start_watcher

# The TypeScript SDK scenarios import the SDK's built `dist/`, which is absent
# in a fresh worktree. Without it they fail for a reason that has nothing to do
# with the documentation.
if [[ ! -f crates/mvm-sdk/sdks/typescript/dist/index.js ]]; then
  echo "==> building the TypeScript SDK (dist/ is absent)"
  just sdk-install-typescript
  just sdk-build-typescript
fi

# ---------------------------------------------------------------------------
# 2. Warm the shared artifact home.
#
# Every launch needs the workload kernel, the runtime overlay and the universal
# initramfs. Acquiring them inside a scenario would put minutes on each one, and
# a scenario that times out reads as a launch failure rather than a cold cache.
# ---------------------------------------------------------------------------
# This suite verifies the documented CLI surface, not the builder VM image.
# A source checkout otherwise rebuilds that image from the in-repo flake on
# every cold run, which couples the whole suite to an unrelated Nix build —
# and when that build cannot reach crates.io from inside Stage 0, nothing here
# runs at all. Fetch the published image instead. A contributor working *on*
# the image sets MVM_BOOT_IMAGE themselves and this defers to them.
export MVM_BOOT_IMAGE="${MVM_BOOT_IMAGE:-fetch}"
echo "    boot image: $MVM_BOOT_IMAGE"

# Bootstrap failure is reported, not fatal. It warms the builder VM image, which
# the flake-build scenarios need and the OCI-image ones do not — so aborting here
# would throw away every result that does not depend on it. The scenarios that do
# need it then fail on their own, naming themselves.
echo "==> warming artifacts in $E2E_HOME"
if ! MVM_HOME="$E2E_HOME" "$MVMCTL" bootstrap; then
  echo
  echo "!!! bootstrap FAILED — the builder VM image is unavailable."
  echo "!!! Flake-build scenarios will fail; OCI-image scenarios are unaffected."
  echo "!!! Continuing so the run still reports what it can prove."
  echo
  BOOTSTRAP_FAILED=1
fi

# ---------------------------------------------------------------------------
# Warm the launch artifacts, even when bootstrap did not get that far.
#
# `bootstrap` prepares the builder VM image *first* and deliberately skips the
# runtime/initramfs warm when that step fails — there is a test pinning that
# order. So a builder image that cannot be built leaves the universal
# initramfs unbuilt, and since it is required on every host, each scenario then
# cross-compiles the guest binaries itself: a multi-minute cargo build, inside
# a scenario, repeated for every live scenario in the suite.
#
# One warm-up launch populates that cache once. Both steps are best-effort and
# bounded: this is a warm-up, and a failure here should surface as the
# scenarios failing on their own terms rather than as a dead run.
# ---------------------------------------------------------------------------
warm_launch_artifacts() {
  echo "==> warming launch artifacts (runtime overlay + universal initramfs)"

  MVM_HOME="$E2E_HOME" "$MVMCTL" build runtime-overlay build >/dev/null 2>&1 \
    && echo "    runtime overlay ready" \
    || echo "    runtime overlay: not warmed (scenarios needing it will say so)"

  # Layout is cache/initramfs/<version>/<arch>/initramfs.cpio.gz. Globbed on
  # version rather than hardcoded, so a version bump does not silently turn
  # this check into "never cached" and pay the build every run.
  if find "$E2E_HOME/cache/initramfs" -name initramfs.cpio.gz -size +0c 2>/dev/null \
     | read -r _; then
    echo "    universal initramfs already cached"
    return 0
  fi

  echo "    building the universal initramfs once (cross-compiles guest binaries)"
  MVM_HOME="$E2E_HOME" "$MVMCTL" machine run --name bdd-warmup --image alpine \
    -- /bin/true >/dev/null 2>&1 &
  local warm_pid=$! waited=0
  while kill -0 "$warm_pid" 2>/dev/null; do
    if (( waited >= ${MVM_E2E_WARMUP_SECS:-900} )); then
      echo "    warm-up exceeded its budget; killing it and continuing"
      kill -TERM "$warm_pid" 2>/dev/null || true
      break
    fi
    sleep 10
    waited=$((waited + 10))
    (( waited % 60 == 0 )) && echo "    ... still warming (${waited}s)"
  done
  wait "$warm_pid" 2>/dev/null || true
  echo "    warm-up done (${waited}s)"
}
warm_launch_artifacts

echo "==> host posture"
# `doctor` exits nonzero precisely when it has something to report, so its
# status is information rather than a gate.
MVM_HOME="$E2E_HOME" "$MVMCTL" doctor || true

# ---------------------------------------------------------------------------
# 3. The documented surface, live.
#
# `MVM_BDD_LIVE=1` opts into the scenarios that boot a real microVM. No
# `MVM_BDD_CI_LIVE_ONLY` here: that selector narrows to the merge-queue subset,
# and narrowing is what let the macOS default backend go uncovered.
# ---------------------------------------------------------------------------
# Bounded, because a live scenario can hang rather than fail: a guest that
# never completes its request leaves the runner waiting forever, and a release
# gate that hangs is a gate nobody runs. Implemented here rather than with
# `timeout(1)`, which is absent from a stock macOS and from the macOS runners.
E2E_TIMEOUT_SECS="${MVM_E2E_TIMEOUT_SECS:-3600}"

echo "==> documented examples + machine journey (cucumber, @live)"
echo "    deadline: ${E2E_TIMEOUT_SECS}s"
set +e
CARGO_BIN_EXE_mvmctl="$MVMCTL" \
MVM_BDD_LIVE=1 \
MVM_E2E_HOME="$E2E_HOME" \
  ./scripts/cargo-fast.sh test -p mvm-conformance --test conformance --features bdd &
SUITE_PID=$!

waited=0
while kill -0 "$SUITE_PID" 2>/dev/null; do
  if (( waited >= E2E_TIMEOUT_SECS )); then
    echo
    echo "!!! TIMEOUT after ${E2E_TIMEOUT_SECS}s — killing the suite."
    echo "!!! A live scenario hung instead of failing. The last scenario printed"
    echo "!!! above is where it stopped; raise MVM_E2E_TIMEOUT_SECS if it needs longer."
    kill -TERM "$SUITE_PID" 2>/dev/null || true
    sleep 5
    kill -KILL "$SUITE_PID" 2>/dev/null || true
    # Leave no guest behind holding a vsock socket or a vCPU thread.
    pkill -f "mvm-hvf-supervisor" 2>/dev/null || true
    pkill -f "mvm-libkrun-supervisor" 2>/dev/null || true
    SUITE_STATUS=124
    break
  fi
  sleep 5
  waited=$((waited + 5))
done
if [[ -z "${SUITE_STATUS:-}" ]]; then
  wait "$SUITE_PID"
  SUITE_STATUS=$?
fi
set -e

echo
echo "==> done. Read the 'did NOT run' tally above, not just the pass count:"
echo "    a skipped @live scenario is a documented command nothing booted."
if [[ -n "${BOOTSTRAP_FAILED:-}" ]]; then
  echo
  echo "!!! REMINDER: bootstrap failed this run. Any flake-build failure above"
  echo "!!! is that, not a regression in the command under test."
fi
exit "$SUITE_STATUS"
