#!/usr/bin/env bash
# Phase timings for the live end-to-end harnesses. Sourced, not executed.
#
# A run that finishes in two hours says nothing about where the two hours went.
# The documented-surface lane was twice cut down by its job budget while the
# log showed only that the suite never started, and the cost turned out to be
# builder image preparation rather than the scenarios. Each phase now reports
# its own duration, so comparing two runs is a matter of reading two tables.
#
# The per-phase line is a fixed, grep-able shape:
#
#   [phase] name=<name> seconds=<n>
#
# A phase ends when the next one begins or when the summary is printed, so a
# run interrupted mid-phase still reports how long that phase had been running.

E2E_PHASES=()
E2E_PHASE_NAME=""
E2E_PHASE_STARTED=0

# Begin a named phase, ending whichever one was running.
e2e_phase() {
  e2e_phase_end
  E2E_PHASE_NAME="$1"
  E2E_PHASE_STARTED=$SECONDS
  echo "==> [phase] $1"
}

# End the running phase, if any, and record its duration.
e2e_phase_end() {
  [[ -n "$E2E_PHASE_NAME" ]] || return 0
  local seconds=$(( SECONDS - E2E_PHASE_STARTED ))
  E2E_PHASES+=("$E2E_PHASE_NAME=$seconds")
  echo "[phase] name=$E2E_PHASE_NAME seconds=$seconds"
  E2E_PHASE_NAME=""
}

# Print every recorded phase and the total. `$1` titles the GitHub step summary
# when one is available, so two lanes writing into one run stay distinguishable.
e2e_phase_summary() {
  e2e_phase_end
  # Checked before expanding the array: an empty "${arr[@]}" is an unbound
  # variable under `set -u` on the bash 3.2 that macOS ships.
  (( ${#E2E_PHASES[@]} > 0 )) || return 0

  local total=0 entry name seconds
  echo "==> phase timings"
  for entry in "${E2E_PHASES[@]}"; do
    name="${entry%%=*}"
    seconds="${entry#*=}"
    total=$(( total + seconds ))
    printf '    %-20s %6ss\n' "$name" "$seconds"
  done
  printf '    %-20s %6ss\n' total "$total"

  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo "### ${1:-Phase timings}"
      echo
      echo "| phase | seconds |"
      echo "|---|---:|"
      for entry in "${E2E_PHASES[@]}"; do
        echo "| ${entry%%=*} | ${entry#*=} |"
      done
      echo "| total | $total |"
    } >> "$GITHUB_STEP_SUMMARY"
  fi
}
