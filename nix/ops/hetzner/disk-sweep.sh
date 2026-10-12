#!/usr/bin/env bash
# Hourly safety net for the shared KVM box: remove test and runner temporary
# directories that nothing is using any more.
#
# Each CI job cleans up after itself (job-cleanup.sh) and each person or agent
# working on the box by hand is expected to as well (README.md, "Working on
# the shared box"). This catches what both miss: a job killed before its
# cleanup step, a test that wrote to /tmp directly, a session that ended
# without deleting its directory.
#
# A candidate is removed only when all of these hold:
#   - it matches a test/temp name pattern (see `candidates`);
#   - no process has it, or anything under it, open, as its working directory,
#     as a mapped file, or as a bound unix socket;
#   - nothing under it was modified in the last MAX_AGE_HOURS;
#   - it is not a mount point.
# Runner work leftovers are only considered while no runner job is running.
#
# It never kills a process. A VMM that outlived its job is logged as leaked so
# someone can decide; its directory stays because the VMM holds it open.
#
# Environment:
#   MAX_AGE_HOURS  idle time before a directory is stale (default 6)
#   RUNNER_ROOT    runner installation (default /opt/actions-runner)
#   SWEEP_LOG      append-only record of removals (default /var/log/mvm-disk-sweep.log)
#   DRY_RUN=1      log what would be removed, remove nothing

set -uo pipefail

max_age=${MAX_AGE_HOURS:-6}
runner_root=${RUNNER_ROOT:-/opt/actions-runner}
sweep_log=${SWEEP_LOG:-/var/log/mvm-disk-sweep.log}
dry_run=${DRY_RUN:-0}

if [[ ! "$max_age" =~ ^[0-9]+$ ]] || [ "$max_age" -lt 1 ]; then
  echo "disk-sweep: MAX_AGE_HOURS must be a whole number of hours >= 1" >&2
  exit 2
fi

log() {
  local line
  line="$(date -u +%FT%TZ) $*"
  printf '%s\n' "$line"
  [ "$dry_run" = 1 ] || printf '%s\n' "$line" >>"$sweep_log" 2>/dev/null || true
}

held=$(mktemp)
trap 'rm -f "$held"' EXIT

# Every path a live process is using, written to $1.
collect_held_into() {
  {
    local proc
    for proc in /proc/[0-9]*; do
      readlink "$proc/cwd"
      find "$proc/fd" -mindepth 1 -maxdepth 1 -printf '%l\n'
      awk '$6 ~ /^\// { print $6 }' "$proc/maps"
    done
    awk 'NR > 1 && $8 ~ /^\// { print $8 }' /proc/net/unix
  } 2>/dev/null | sed 's/ (deleted)$//' | grep '^/' | sort -u >"$1"
}

is_held() {
  grep -qxF -- "$1" "$held" || grep -qF -- "$1/" "$held"
}

recently_modified() {
  [ -n "$(find "$1" -xdev -newermt "-${max_age} hours" -print -quit 2>/dev/null)" ]
}

runner_job_active() {
  pgrep -f 'Runner\.Worker' >/dev/null
}

# NUL-separated candidate paths.
candidates() {
  find /tmp -mindepth 1 -maxdepth 1 \
    \( -name '.tmp*' -o -name 'tmp.*' -o -name 'mvm-w-*' -o -name 'mvm-workspace-*' \
    -o -name 'mvm-sock-*' -o -name 'mvm-test-*' \) -print0 2>/dev/null
  if [ -d "$runner_root/_work" ] && ! runner_job_active; then
    find "$runner_root/_work/_temp" -mindepth 1 -maxdepth 1 -print0 2>/dev/null
    find "$runner_root/_work" -mindepth 3 -maxdepth 3 -name '.mvm-test' -type d -print0 2>/dev/null
  fi
}

report_leaked_vmms() {
  local pid age ppid
  for pid in $(pgrep -x firecracker; pgrep -f '^qemu-system-'); do
    age=$(ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ')
    [[ "$age" =~ ^[0-9]+$ ]] || continue
    [ "$age" -ge $((max_age * 3600)) ] || continue
    ppid=$(ps -o ppid= -p "$pid" | tr -d ' ')
    log "leaked-vmm pid=$pid ppid=$ppid age=${age}s cpu=$(ps -o pcpu= -p "$pid" | tr -d ' ')% \
cmd=$({ tr '\0' ' ' <"/proc/$pid/cmdline"; } 2>/dev/null | cut -c1-200)"
  done
}

main() {
  local path kib removed=0 freed=0 kept_held=0 kept_recent=0
  collect_held_into "$held"
  while IFS= read -r -d '' path; do
    if is_held "$path"; then
      kept_held=$((kept_held + 1))
      continue
    fi
    if recently_modified "$path"; then
      kept_recent=$((kept_recent + 1))
      continue
    fi
    if mountpoint -q -- "$path" 2>/dev/null; then
      log "skip mount point $path"
      continue
    fi
    kib=$(du -xsk -- "$path" 2>/dev/null | cut -f1)
    kib=${kib:-0}
    if [ "$dry_run" = 1 ]; then
      log "would remove ${kib}KiB $path"
    elif rm -rf --one-file-system -- "$path"; then
      log "removed ${kib}KiB $path"
    else
      log "failed to remove $path"
      continue
    fi
    removed=$((removed + 1))
    freed=$((freed + kib))
  done < <(candidates)
  report_leaked_vmms
  log "sweep done: removed=$removed freed=$((freed / 1024))MiB kept_in_use=$kept_held kept_recent=$kept_recent max_age=${max_age}h dry_run=$dry_run"
}

main
