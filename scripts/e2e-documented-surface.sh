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
# Reaps exactly the machines this run created, by diffing the machine list
# against a snapshot taken before the suite starts. Prefix matching was the
# first attempt and it under-reaped: the SDK scenarios name their guests
# `sdk-<registry>-<digest>`, not `bdd-*`, so those leaked on every run.
# Snapshotting needs no list of prefixes to keep in sync with the suite.
#
# The snapshot lives in the home rather than in a shell variable so that
# `--clean-only` can still reap after a run was killed hard enough to skip its
# own trap.
#
# Runs on the way in as well as the way out: a guest left holding its name makes
# the next run fail on a collision that reads as a broken verb.
# ---------------------------------------------------------------------------
SNAPSHOT="$E2E_HOME/.e2e-machines-before"

machine_names() {
  MVM_HOME="$E2E_HOME" "$MVMCTL" machine ls 2>/dev/null \
    | awk 'NR>1 && NF {print $1}' | sort || true
}

snapshot_machines() {
  mkdir -p "$E2E_HOME"
  machine_names > "$SNAPSHOT" 2>/dev/null || : > "$SNAPSHOT"
}

reap() {
  local phase="$1"
  [[ -x "$MVMCTL" ]] || return 0

  # Without a snapshot there is no way to tell this run's machines from
  # someone else's, and deleting the wrong one is worse than leaking.
  if [[ ! -f "$SNAPSHOT" ]]; then
    echo "==> $phase cleanup: no snapshot to diff against, leaving machines alone"
    return 0
  fi

  local created
  created="$(comm -13 "$SNAPSHOT" <(machine_names) 2>/dev/null || true)"

  REAPED_NAMES="$created"
  if [[ -n "$created" ]]; then
    echo "==> $phase cleanup: reaping $(echo "$created" | wc -w | tr -d ' ') machine(s) this run created"
    while read -r name; do
      [[ -z "$name" ]] && continue
      echo "    - $name"
      MVM_HOME="$E2E_HOME" "$MVMCTL" machine stop "$name" --yes >/dev/null 2>&1 || true
      MVM_HOME="$E2E_HOME" "$MVMCTL" machine rm "$name" --yes >/dev/null 2>&1 || true
    done <<< "$created"
  elif [[ "$phase" == "pre-run" ]]; then
    echo "==> pre-run cleanup: nothing left over"
  fi

  # State directories whose spec is gone but whose runtime directory survived.
  if [[ -d "$E2E_HOME/vms" ]]; then
    while read -r name; do
      [[ -z "$name" ]] && continue
      rm -rf "$E2E_HOME/vms/$name" 2>/dev/null || true
    done <<< "$created"
  fi
}

# Per-VM supervisors outlive a killed suite and keep a vCPU thread and a vsock
# socket alive. Only supervisors for machines this run created are signalled —
# another session may be driving its own guests out of the same home, and its
# supervisor is not ours to kill.
REAPED_NAMES=""
reap_orphan_supervisors() {
  [[ -n "$REAPED_NAMES" ]] || return 0
  local pids
  pids="$(pgrep -f 'mvm-(hvf|libkrun)-supervisor' 2>/dev/null || true)"
  [[ -z "$pids" ]] && return 0
  for pid in $pids; do
    local args
    args="$(ps -o args= -p "$pid" 2>/dev/null || true)"
    while read -r name; do
      [[ -z "$name" ]] && continue
      case "$args" in
        *"$name"*)
          echo "    - reaping supervisor $pid for $name"
          kill -TERM "$pid" 2>/dev/null || true
          ;;
      esac
    done <<< "$REAPED_NAMES"
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
  release_lock
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

# Two runs against one home corrupt each other: they share the machine
# namespace, the artifact caches and the per-VM supervisors, and each one's
# cleanup then sees the other's guests. Refuse rather than interleave.
LOCK="$E2E_HOME/.e2e-run.lock"
if [[ -f "$LOCK" ]] && kill -0 "$(cat "$LOCK" 2>/dev/null)" 2>/dev/null; then
  echo "!!! another e2e run (pid $(cat "$LOCK")) is already using $E2E_HOME." >&2
  echo "!!! Set MVM_E2E_HOME to a different home, or wait for it to finish." >&2
  trap - EXIT
  exit 1
fi
mkdir -p "$E2E_HOME"
echo $$ > "$LOCK"
release_lock() { [[ -f "$LOCK" ]] && [[ "$(cat "$LOCK" 2>/dev/null)" == "$$" ]] && rm -f "$LOCK"; }

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

# The SDK codegen drift scenario shells out to `target/debug/xtask`; without it
# the step fails with a bare "NotFound" that says nothing about the SDK.
./scripts/cargo-fast.sh build -p xtask

# Drop the nested aux-helper target so the per-VM helpers are rebuilt against
# this source tree. `mvm-network-endpoint` and friends are separate `[[bin]]`s
# that cargo does not refresh when `mvmctl` is rebuilt, so a stale copy survives
# — and the launch path refuses it rather than booting a guest that ignores the
# current sources ("was reused from an earlier build"). That refusal failed six
# live scenarios on the Linux run, all of them reading as egress or DNS bugs.
echo "==> refreshing embedded aux helpers"
just embed-refresh

# Now that `mvmctl` exists, clear anything a previous run left behind. A guest
# still holding its name makes the next run fail on a collision that reads as a
# broken verb.
reap "pre-run"
reap_orphan_supervisors
# Baseline for this run: everything above is the previous run's mess, and
# everything that appears from here is ours.
snapshot_machines
start_watcher

# The TypeScript SDK scenarios import the SDK's built `dist/`, which is absent
# in a fresh worktree. Without it they fail for a reason that has nothing to do
# with the documentation.
#
# Rebuilt every run, not just when absent: a `dist/` left over from an earlier
# checkout is *stale*, not missing, and an existence check cannot tell the
# difference. A stale one makes the golden-argv scenarios report SDK drift that
# is really just an old build — which is exactly how it read the first time.
# `tsc` is incremental, so the cost when nothing changed is small.
echo "==> building the TypeScript SDK"
if [[ ! -d crates/mvm-sdk/sdks/typescript/node_modules ]]; then
  just sdk-install-typescript
fi
just sdk-build-typescript

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
    # `(( ... )) && echo` returns 1 whenever the arithmetic is false, and under
    # `set -e` that ends the run — at the very first tick, ten seconds in.
    if (( waited % 60 == 0 )); then
      echo "    ... still warming (${waited}s)"
    fi
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

# A run that dies before the suite starts must not look like a pass. This has
# happened twice: a stray token from a bad edit, and a `(( ... )) && echo` that
# returns 1 under `set -e`. Both ended the script early, and both left an exit
# status that read as success from the outside. The marker is checked after the
# suite and turns "never ran" into a loud failure.
SUITE_STARTED=""

echo "==> documented examples + machine journey (cucumber, @live)"
SUITE_STARTED=1
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
if [[ -z "${SUITE_STARTED:-}" ]]; then
  echo
  echo "!!! the suite never started — this run proves nothing." >&2
  echo "!!! Something above ended the script early; read the last line of output." >&2
  exit 70
fi

if [[ -n "${BOOTSTRAP_FAILED:-}" ]]; then
  echo
  echo "!!! REMINDER: bootstrap failed this run. Any flake-build failure above"
  echo "!!! is that, not a regression in the command under test."
fi
exit "$SUITE_STATUS"
