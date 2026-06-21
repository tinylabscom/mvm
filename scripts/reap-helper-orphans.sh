#!/usr/bin/env bash
# Reap leaked host-side helper subprocesses (the process-moat bins) older than a
# threshold. These are spawned per-test / per-VM by a supervisor; when that
# supervisor dies abnormally (SIGKILL from amfid codesign, panic-abort) the
# helpers reparent to init/launchd and leak. The in-binary parent-death watchdog
# prevents new leaks; this is the backstop that clears history and covers any
# helper built before the watchdog landed.
#
# Age is the safety discriminator: every process in one dead test tree shares a
# spawn time, so an age cutoff reaps whole dead trees while sparing the young
# helpers of a test run in flight. Default cutoff 30 minutes; override with the
# first argument (minutes) or MINUTES=.
#
# Usage:
#   scripts/reap-helper-orphans.sh           # reap helpers older than 30 min
#   scripts/reap-helper-orphans.sh 5         # reap helpers older than 5 min
#   DRY_RUN=1 scripts/reap-helper-orphans.sh # list what would be reaped
set -euo pipefail

minutes="${1:-${MINUTES:-30}}"
cutoff=$(( minutes * 60 ))

# Match the helper bins by path component. The leading [m] bracket means this
# pattern text never matches the `ps`/`awk` pipeline's own argv, so the reaper
# cannot self-select. `args` (not `comm`) avoids Linux's 15-char comm truncation.
pattern='/[m]vm-(host-agent|host-signer|signer-helper|audit-signer|broker|substitution-endpoint)([ ]|$)'

# Emit "pid age_seconds args" for matching processes at or over the cutoff.
mapfile -t victims < <(
  ps -axo pid=,etime=,args= | awk -v cutoff="$cutoff" -v pat="$pattern" '
    function secs(e,   d,t,n,a,p) {
      d = 0
      if (e ~ /-/) { split(e, p, "-"); d = p[1]; e = p[2] }
      n = split(e, a, ":")
      if (n == 3)      t = a[1]*3600 + a[2]*60 + a[3]
      else if (n == 2) t = a[1]*60 + a[2]
      else             t = a[1]
      return d*86400 + t
    }
    {
      pid = $1; age = secs($2)
      args = $0; sub(/^[ ]*[0-9]+[ ]+[^ ]+[ ]+/, "", args)
      if (args ~ pat && age >= cutoff) printf "%s %s\n", pid, age
    }'
)

if [ "${#victims[@]}" -eq 0 ]; then
  echo "reap-helper-orphans: no helper subprocesses older than ${minutes}m"
  exit 0
fi

pids=()
for v in "${victims[@]}"; do pids+=("${v%% *}"); done

if [ -n "${DRY_RUN:-}" ]; then
  echo "reap-helper-orphans: would reap ${#pids[@]} helper(s) older than ${minutes}m:"
  for v in "${victims[@]}"; do echo "  pid ${v%% *} (${v##* }s old)"; done
  exit 0
fi

echo "reap-helper-orphans: reaping ${#pids[@]} helper(s) older than ${minutes}m"
# SIGTERM is enough — these bins install no handler that would swallow it.
kill "${pids[@]}" 2>/dev/null || true
