#!/usr/bin/env bash
# Follow microVM lifecycle in an MVM_HOME: announce each guest as its state
# directory appears, stream its console, and say when it goes away.
#
# Cucumber captures a step's output and prints it only when the step fails, so
# a multi-minute boot shows nothing at all while it happens. This watches the
# filesystem instead of the test runner, which means it works against any run —
# `just e2e-docs`, a bare `mvmctl machine start`, or someone else's session.
#
# Usage:
#   scripts/e2e-watch-vms.sh                 # watch ~/.mvm
#   scripts/e2e-watch-vms.sh /tmp/e2e-home   # watch a specific home
#   MVM_E2E_HOME=/tmp/e2e scripts/e2e-watch-vms.sh
#
# Runs until interrupted. Safe to start before the run does.

set -uo pipefail
# No job-control notifications: bash otherwise prints a "Done ..." block naming
# each console follower's source when the watcher is signalled, dumping shell
# code into the middle of the run's output.
set +m

HOME_DIR="${1:-${MVM_E2E_HOME:-$HOME/.mvm}}"
VMS="$HOME_DIR/vms"

# bash 3.2 on macOS has no associative arrays, so "have I seen this guest" is a
# marker file rather than a map.
STATE="$(mktemp -d "${TMPDIR:-/tmp}/mvm-vm-watch.XXXXXX")"

cleanup() {
  # Silence this phase entirely. Reaping the followers makes bash report each
  # job's status, which prints the pipeline's source code; nothing said during
  # teardown is worth that noise.
  exec >/dev/null 2>&1
  # `pkill -P $$` is not enough: each follower is a `tail | while` pipeline, so
  # the `tail` is a grandchild and survives its parent being signalled. Match on
  # the command line instead, scoped to this home's path so a watcher on another
  # MVM_HOME is left alone.
  # Match on the watched path, not on the tail invocation: `pkill -f` takes a
  # regex, and `-n +1` contains a `+`, which silently matches nothing.
  pkill -f "$VMS/" >/dev/null 2>&1 || true
  pkill -P $$ >/dev/null 2>&1 || true
  rm -rf "$STATE"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

echo "==> watching $VMS"
echo "    (ctrl-c to stop)"
mkdir -p "$VMS"

while true; do
  for dir in "$VMS"/*/; do
    [ -d "$dir" ] || continue
    name="$(basename "$dir")"
    [ -e "$STATE/$name" ] && continue
    : > "$STATE/$name"
    printf '  [vm] %s — microVM starting\n' "$name"
    # One process per guest rather than a backgrounded pipeline: bash reports a
    # finished job by printing its source, and a pipeline's source is the whole
    # loop body. Wrapping it in `sh -c` keeps that notice to a single line.
    #
    # From the first line, not the end — the point is to watch a guest come up,
    # and the console is usually already a few lines old by the time the state
    # directory appears. `-F` keeps following across the truncate-and-recreate
    # a restart does. The prefix is applied by a read loop rather than `sed -u`,
    # which is GNU-only: BSD `sed` buffers and defeats the point of following.
    sh -c 'tail -n +1 -F "$1" 2>/dev/null | while IFS= read -r line; do
             printf "  [%s] %s\n" "$2" "$line"
           done' _ "$dir/console.log" "$name" &
  done

  for marker in "$STATE"/*; do
    [ -e "$marker" ] || continue
    name="$(basename "$marker")"
    if [ ! -d "$VMS/$name" ]; then
      printf '  [vm] %s — microVM gone\n' "$name"
      rm -f "$marker"
    fi
  done

  sleep 2
done
