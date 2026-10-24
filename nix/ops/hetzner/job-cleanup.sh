#!/usr/bin/env bash
# Leave the self-hosted KVM runner as a job found it.
#
# Usage: job-cleanup.sh <isolated-base>
#
# <isolated-base> is the per-job directory the workflow pointed HOME, MVM_HOME
# and TMPDIR at ($RUNNER_TEMP/mvm-w-<run>-<attempt>-<shard>). Every workflow job that
# can run on the KVM pool calls this from an `if: always()` final step;
# tests/github_actions_self_hosted_runner.rs fails the build when one does not.
#
# The runner kills the job's process tree when the job ends, but a VMM started
# through `sudo setsid nohup` is not in that tree. Such a VMM keeps running at
# full CPU for days and pins its temporary directory, so this kills, by PID,
# every process whose command line names a path this job owned, and only then
# removes those paths.
#
# Optional environment:
#   ARCHIVE_ROOT          extracted test archive to remove (under RUNNER_TEMP)
#   MVM_TARGET_BUDGET_GIB size above which the workspace target directory is
#                         removed rather than kept warm for the next job
#                         (default 40)
#   DRY_RUN=1             report what would be killed and removed, change nothing

set -uo pipefail

base=${1:-}
budget_gib=${MVM_TARGET_BUDGET_GIB:-40}
dry_run=${DRY_RUN:-0}
status=0

log() { printf 'job-cleanup: %s\n' "$*"; }

base_is_valid=0
if [[ "$base" =~ ^/tmp/mvm-w-[0-9]+-[0-9]+-[1-9]$ ]]; then
  # Accept the historical /tmp location while older workflows are updated.
  base_is_valid=1
elif [ -n "${RUNNER_TEMP:-}" ]; then
  runner_temp=${RUNNER_TEMP%/}
  prefix="$runner_temp/mvm-w-"
  if [[ "$base" == "$prefix"* ]]; then
    suffix=${base#"$prefix"}
    [[ "$suffix" =~ ^[0-9]+-[0-9]+-[1-9]$ ]] && base_is_valid=1
  fi
fi
if [ "$base_is_valid" != 1 ]; then
  log "refusing isolated base ${base@Q}: expected ${RUNNER_TEMP:-RUNNER_TEMP}/mvm-w-<run>-<attempt>-<shard>"
  exit 2
fi
if [[ ! "$budget_gib" =~ ^[0-9]+$ ]]; then
  log "refusing MVM_TARGET_BUDGET_GIB=${budget_gib@Q}: expected whole GiB"
  exit 2
fi

archive_root=${ARCHIVE_ROOT:-}
if [ -n "$archive_root" ] &&
  [[ ! "$archive_root" =~ ^"${RUNNER_TEMP:-/nonexistent}"/mvm-workspace-[0-9]+$ ]]; then
  log "ignoring ARCHIVE_ROOT ${archive_root@Q}: not a test archive under RUNNER_TEMP"
  archive_root=
fi

workspace_target=
if [ -n "${GITHUB_WORKSPACE:-}" ] && [ -d "$GITHUB_WORKSPACE" ]; then
  workspace_target="$GITHUB_WORKSPACE/target"
fi

# Paths whose appearance in a command line marks a process as this job's.
owned=("$base/")
[ -n "$archive_root" ] && owned+=("$archive_root/")
[ -n "$workspace_target" ] && owned+=("$workspace_target/")

# This script and the shells above it name the base in their own arguments.
declare -A spare=()
pid=$$
while [[ "$pid" =~ ^[0-9]+$ ]] && [ "$pid" -gt 1 ]; do
  spare[$pid]=1
  pid=$(awk '/^PPid:/ { print $2 }' "/proc/$pid/status" 2>/dev/null) || break
done

names_owned_path() {
  local cmdline
  cmdline=$({ tr '\0' ' ' <"/proc/$1/cmdline"; } 2>/dev/null) || return 1
  local path
  for path in "${owned[@]}"; do
    [[ "$cmdline" == *"$path"* ]] && return 0
  done
  return 1
}

# Candidates come from two places: the pid files mvm writes beside each VM,
# and a scan of every command line. Either way a PID is only signalled while
# its command line still names a path this job owned, so a recycled PID is
# never touched.
job_pids() {
  local file pid
  {
    if [ -d "$base" ]; then
      while IFS= read -r -d '' file; do
        read -r pid <"$file" 2>/dev/null && printf '%s\n' "$pid"
      done < <(find "$base" -xdev -type f -name '*.pid' -print0 2>/dev/null)
    fi
    for pid in /proc/[0-9]*; do
      printf '%s\n' "${pid#/proc/}"
    done
  } | sort -un | while IFS= read -r pid; do
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    [ -n "${spare[$pid]:-}" ] && continue
    names_owned_path "$pid" && printf '%s\n' "$pid"
  done
}

signal() {
  local sig=$1 pid=$2
  kill "-$sig" "$pid" 2>/dev/null && return 0
  # A VMM started through sudo belongs to root.
  sudo -n kill "-$sig" "$pid" 2>/dev/null
}

stop_job_processes() {
  local pids pid
  mapfile -t pids < <(job_pids)
  [ "${#pids[@]}" -eq 0 ] && { log "no leftover processes"; return; }
  for pid in "${pids[@]}"; do
    log "stopping pid $pid: $({ tr '\0' ' ' <"/proc/$pid/cmdline"; } 2>/dev/null | cut -c1-200)"
    [ "$dry_run" = 1 ] || signal TERM "$pid"
  done
  [ "$dry_run" = 1 ] && return
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    mapfile -t pids < <(job_pids)
    [ "${#pids[@]}" -eq 0 ] && return
    sleep 1
  done
  for pid in "${pids[@]}"; do
    log "killing pid $pid, still running after SIGTERM"
    signal KILL "$pid" || { log "could not kill pid $pid"; status=1; }
  done
}

remove_dir() {
  local path=$1
  [ -e "$path" ] || [ -L "$path" ] || return 0
  if [ -L "$path" ] || [ ! -d "$path" ]; then
    log "not removing $path: not a plain directory"
    status=1
    return
  fi
  log "removing $path ($(du -xsh -- "$path" 2>/dev/null | cut -f1))"
  [ "$dry_run" = 1 ] && return
  chmod -R u+rwX -- "$path" 2>/dev/null
  rm -rf --one-file-system -- "$path" 2>/dev/null ||
    sudo -n rm -rf --one-file-system -- "$path" 2>/dev/null ||
    { log "could not remove $path"; status=1; }
}

stop_job_processes
remove_dir "$base"
[ -n "$archive_root" ] && remove_dir "$archive_root"
[ -n "${GITHUB_WORKSPACE:-}" ] && remove_dir "$GITHUB_WORKSPACE/.mvm-test"

# The workspace target directory is the one thing deliberately kept between
# jobs: the KVM pool exists to run the suite against a warm build. It is kept
# only while it stays inside the budget.
if [ -n "$workspace_target" ] && [ -d "$workspace_target" ]; then
  used_kib=$(du -xsk -- "$workspace_target" 2>/dev/null | cut -f1)
  if [[ "$used_kib" =~ ^[0-9]+$ ]] && [ "$used_kib" -gt $((budget_gib * 1024 * 1024)) ]; then
    log "target is $((used_kib / 1024 / 1024)) GiB, over the ${budget_gib} GiB budget"
    remove_dir "$workspace_target"
  else
    log "keeping warm target ($((${used_kib:-0} / 1024 / 1024)) GiB of ${budget_gib} GiB)"
  fi
fi

df -h / /tmp 2>/dev/null
exit "$status"
