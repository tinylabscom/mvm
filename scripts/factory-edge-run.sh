#!/usr/bin/env bash
# Run the whole factory-edge demo with one command: stage the three workloads,
# run the demo against them, and remove them again, even if the demo fails.
#
#   scripts/factory-edge-run.sh
#
# This is the version for someone who just wants to see it work. A presenter
# who wants no waiting on stage runs the two scripts separately instead: stage
# about ten minutes ahead with scripts/factory-edge-stage.sh, present with
# scripts/factory-edge-demo-live.sh, then remove with
# scripts/factory-edge-stage.sh --down.
#
# It assumes what the two scripts assume: an installed mvmctl and a prepared
# demo home. Nothing here installs or prepares anything. See
# scripts/factory-edge-demo.md for the one-time setup.
#
# Every setting of the two scripts is passed through (MVMCTL, MVM_HOME,
# HYPERVISOR, IMAGE and the rest). ATTEMPT_AFTER and INSPECT_EVERY default to 3
# and 2 seconds here, so the maintenance workload makes its request soon after
# staging and the inspection workloads report often, and the run does not wait.
# A presenter staging ahead wants longer ones, because every lookup is a signed
# audit entry and the record grows for as long as the workloads run; a run of
# about a minute does not grow it meaningfully.
#
# The exit status is the demo's: 0 only if every check passed.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
export ATTEMPT_AFTER="${ATTEMPT_AFTER:-3}" INSPECT_EVERY="${INSPECT_EVERY:-2}"

# Remove the staged workloads on any exit, including an interrupt.
cleanup() {
  "$here/factory-edge-stage.sh" --down >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM

t0=$SECONDS
echo "Step 1 of 2: staging the three workloads"
"$here/factory-edge-stage.sh" || { echo "The workloads could not be staged, so the demo was not run." >&2; exit 1; }

staged_in=$((SECONDS - t0))
echo
echo "Step 2 of 2: running the demo"
"$here/factory-edge-demo-live.sh"
status=$?

echo
if [ "$status" -eq 0 ]; then
  echo "The demo passed in $((SECONDS - t0)) seconds ($staged_in to stage, the rest to run). The staged workloads have been removed."
else
  echo "The demo did not pass (see the line starting FAIL or FINDING above). The staged workloads have been removed." >&2
fi
exit "$status"
