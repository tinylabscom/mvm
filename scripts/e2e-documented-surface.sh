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
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
MVMCTL="$TARGET_DIR/debug/mvmctl"
UNEMBEDDED_MVMCTL="$E2E_HOME/mvmctl-unembedded-e2e"

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

# Drop the nested aux-helper target *before* building, so `mvmctl`'s build
# script regenerates the per-VM helpers as part of the build that follows.
#
# `mvm-network-endpoint` and `mvm-hvf-supervisor` are separate `[[bin]]`s that
# cargo does not refresh when `mvmctl` is rebuilt, so a copy from an earlier
# build survives and the launch path refuses it rather than booting a guest
# that ignores the current sources.
#
# Order matters and cost me a run: with this *after* the build, the clear
# deleted helpers the build had just produced and every launch then failed with
# "mvm-hvf-supervisor not found" — a worse failure than the stale one it was
# meant to fix.
echo "==> refreshing embedded aux helpers"
just embed-refresh

# `user` carries manifest-verify, which the verified-fetch path needs to accept
# the published builder VM image. Its sigstore/aws-lc dependency must use the
# standard compiler/linker path: the nightly fast-codegen wrapper leaves the
# native aws-lc symbols unresolved. The featureless local path can retain the
# faster wrapper because it does not link that stack.
# Preserve a feature-off binary first. Its SDK-sidecar warm is the regression
# for the contributor path: that command must re-exec the isolated embedded
# helper for the complete HVF/Nix build, not resume in this payload-free parent.
# The main suite binary is then rebuilt with the payload because later workload
# launches consume the extracted host helpers directly.
E2E_FEATURES="${MVM_E2E_FEATURES-}"
if [[ -n "$E2E_FEATURES" ]]; then
  echo "==> building unembedded mvmctl (--features $E2E_FEATURES)"
  cargo build --bin mvmctl --features "$E2E_FEATURES"
  cp "$MVMCTL" "$UNEMBEDDED_MVMCTL"
  echo "==> building mvmctl (--features $E2E_FEATURES,embed-host-bins)"
  cargo build --bin mvmctl --features "$E2E_FEATURES,embed-host-bins"
else
  echo "==> building unembedded mvmctl"
  ./scripts/cargo-fast.sh build --bin mvmctl
  cp "$MVMCTL" "$UNEMBEDDED_MVMCTL"
  echo "==> building mvmctl"
  ./scripts/cargo-fast.sh build --bin mvmctl --features embed-host-bins
fi

# Always rebuild the per-VM helpers, never just check they exist.
#
# Presence is not freshness. `cargo build --bin mvmctl` regenerates some of them
# and not others, so a stale `mvm-hvf-supervisor` from an earlier build survives
# a refresh — and a stale one is worse than a missing one. It parses the config
# `mvmctl` hands it with `deny_unknown_fields`, so a field added on the host side
# makes it exit 1 with "unknown field `vcpus`", which the launch path reports as
# "hvf supervisor exited before writing its PID file". Thirty-three scenarios
# failed that way, none of them naming the stale binary.
#
# cargo makes this a no-op when they are already current, so the cost of always
# doing it is a fingerprint check.
echo "==> building the per-VM host helpers"
just build-supervisors

helpers_present() {
  local root="${CARGO_TARGET_DIR:-target}"
  find "$root" -type f -name mvm-network-endpoint 2>/dev/null | grep -q . || return 1
  if [[ "$(uname -s)" == "Darwin" ]]; then
    find "$root" -type f -name mvm-hvf-supervisor 2>/dev/null | grep -q . || return 1
  fi
  return 0
}
if ! helpers_present; then
  echo "!!! per-VM aux helpers are still missing; every launch would fail." >&2
  exit 1
fi

# macOS kills an unentitled Hypervisor.framework binary, and the only symptom is
# "hvf supervisor exited before writing its PID file" — which names neither the
# signature nor the rebuild that dropped it. Every build step above re-links the
# per-VM supervisor without re-signing it, and the aux-helper refresh deletes it
# outright, so signing has to follow the builds or every HVF boot dies.
if [[ "$(uname -s)" == "Darwin" ]]; then
  echo "==> signing VMM binaries"
  MVM_HOME="$E2E_HOME" "$MVMCTL" env sign
fi

# The generated-SDK drift scenario invokes the compiled xtask binary directly.
# `cargo test` builds the conformance runner but does not materialize that
# sibling workspace binary, so a clean runner otherwise reports ENOENT rather
# than an SDK drift result.
cargo build -p xtask

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
# This suite verifies the documented CLI surface, not the builder VM image, so
# fetching a published image instead of rebuilding it from the in-repo flake is
# the cheaper shape — a source checkout otherwise couples the whole suite to an
# unrelated Nix build.
#
# But it is only cheaper where it works. A contributor `mvmctl` is built without
# `release-artifact-bootstrap` and *cannot* fetch, so forcing `fetch` there does
# not trade a slow build for a fast download; it trades a slow build for no
# builder VM at all, and every flake-build scenario fails. That is the common
# case, not the exotic one.
#
# So let the resolver decide from the checkout, which is the job it exists to
# do: a source tree builds, an installed binary fetches. Anyone holding a
# fetch-capable binary can still set MVM_BOOT_IMAGE=fetch and this defers to it.
if [[ -n "${MVM_BOOT_IMAGE:-}" ]]; then
  export MVM_BOOT_IMAGE
fi
echo "    boot image: ${MVM_BOOT_IMAGE:-auto (resolver decides from the checkout)}"

# Bootstrap failure is reported, not fatal. It warms the builder VM image, which
# the flake-build scenarios need and the OCI-image ones do not — so aborting here
# would throw away every result that does not depend on it. The scenarios that do
# need it then fail on their own, naming themselves.
echo "==> warming artifacts in $E2E_HOME"

# This is deliberately before the explicit bootstrap. A cold cache proves the
# unembedded public command can hand the entire source build to its embedded
# helper, including Stage 0, HVF image baking, and both Nix sidecar variants.
echo "==> warming source-matched SDK sidecar through unembedded mvmctl"
MVM_HOME="$E2E_HOME" "$UNEMBEDDED_MVMCTL" build sdk-sidecar build

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

  # Always enter launch resolution. The initramfs cache key includes a source
  # fingerprint that evicts an artifact containing guest binaries from an
  # older checkout. A plain file-existence check bypasses that validation and
  # can boot stale guest-agent behavior while testing a new host binary.
  echo "    validating the source-matched universal initramfs"
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
# This lane drives the whole suite, so it tolerates more than the launch lane:
# a backend with no memory-snapshot tier (Firecracker reports `unsupported`;
# the macOS job sets MVM_BDD_SNAPSHOT and does not skip these), and the two
# fixtures that need material this lane does not publish.
#
# `needs-dir-share` is set below rather than tolerated blindly: libkrun and HVF
# serve virtio-fs directory shares and must run those scenarios, while
# Firecracker has no virtio-fs device and cannot. Opting in means a capable
# backend runs them and only a genuinely incapable one skips — the alternative,
# tolerating the skip without opting in, silently dropped the witness for the
# README's two `--mount` examples on a host that could have run it.
ALLOWED_SKIPS="pending,needs-perf-budget-host,needs-memory-snapshot,needs-bundle-fixture,needs-tls-tunnel-client,needs-dir-share"

echo "==> documented examples + machine journey (cucumber, @live)"
SUITE_STARTED=1
echo "    deadline: ${E2E_TIMEOUT_SECS}s"
set +e
# Tee'd so the run can afterwards assert the suite actually produced a summary.
# "no failures" is not the same as "nothing ran": the conformance binary
# refuses to start against a stale `mvmctl`, and that refusal prints no
# scenarios at all — which reads as a clean run to anyone counting failures.
SUITE_LOG="$(mktemp "${TMPDIR:-/tmp}/mvm-e2e-suite.XXXXXX")"
CARGO_BIN_EXE_mvmctl="$MVMCTL" \
MVM_BDD_LIVE=1 \
MVM_BDD_DIR_SHARE=1 \
MVM_BDD_STRICT_SKIPS=1 \
MVM_BDD_ALLOWED_SKIPS="$ALLOWED_SKIPS" \
MVM_E2E_HOME="$E2E_HOME" \
  ./scripts/cargo-fast.sh test -p mvm-conformance --test conformance --features bdd \
  2>&1 | tee "$SUITE_LOG" &
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
# A run that produced no scenario summary proved nothing, whatever its failure
# count says. This is the shape that fooled a reader once already: the suite was
# invoked, refused to start against a stale binary, and the log showed zero
# failures because it showed zero scenarios.
if [[ -n "${SUITE_LOG:-}" ]] && ! grep -q '^\[Summary\]' "$SUITE_LOG"; then
  echo
  echo "!!! the suite produced no scenario summary — this run proves nothing." >&2
  echo "!!! Zero failures here means zero scenarios, not a clean run." >&2
  rm -f "$SUITE_LOG"
  exit 70
fi
rm -f "${SUITE_LOG:-}"

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
