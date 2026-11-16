#!/usr/bin/env bash
# The factory-edge demo, raw.
#
# Three small workloads run side by side. Two do inspection work and each may
# reach only its own destination. The third, the maintenance workload, asks for a
# destination it was not given. The host refuses that and records it, `mvmctl
# explain` shows it, and the other two carry on.
#
#   scripts/factory-edge-demo.sh           start the three workloads and show the result
#   scripts/factory-edge-demo.sh --down    remove them again
#
# It assumes an installed mvmctl and a prepared home (see factory-edge-demo.md).
# MVMCTL, MVM_HOME and IMAGE can be overridden.
set -euo pipefail

# `mvmctl` can resolve to a source build in this checkout's target/ directory
# (a PATH entry like ./target/release). A source build compiles its own guest
# runtime on first use, which takes twenty minutes or more; the installed
# release does not. Prefer the installed release unless MVMCTL says otherwise.
mvm="${MVMCTL:-mvmctl}"
if [ -z "${MVMCTL:-}" ]; then
  resolved="$(cd "$(dirname "$0")/.." && command -v mvmctl || true)"
  case "$resolved" in
    */target/* | ./*)
      if [ -x "$HOME/.local/bin/mvmctl" ]; then
        mvm="$HOME/.local/bin/mvmctl"
        echo "note: mvmctl here is a source build ($resolved); using the installed release $mvm" >&2
      else
        echo "note: mvmctl here is a source build ($resolved); its first run compiles the guest runtime (20+ minutes). Install a release, or set MVMCTL." >&2
      fi ;;
  esac
fi
image="${IMAGE:-curlimages/curl:8.21.0}"
export MVM_HOME="${MVM_HOME:-$HOME/.mvm-demo}" MVM_RESIDENCY=cold

if [ "${1:-}" = --down ]; then
  for m in $($mvm machine ls | awk '$1 ~ /^(line-a|line-b|maintenance)-/ { print $1 }'); do
    $mvm machine stop "$m" --yes >/dev/null 2>&1 || true
    $mvm machine rm "$m" --yes >/dev/null 2>&1 || true
  done
  echo "removed"; exit 0
fi

# Every `explain` and `trust audit` call verifies the whole audit chain, so on a
# home whose chain has grown large each one takes many seconds.
if [ "$(du -sk "$MVM_HOME/audit" 2>/dev/null | cut -f1)" -gt 20000 ] 2>/dev/null; then
  echo "note: $MVM_HOME/audit is large, so each explain will be slow." >&2
  echo "      Start a fresh chain with: mv $MVM_HOME/audit $MVM_HOME/audit-archive" >&2
fi

# macOS can cache a bad code-signature verdict for one installed helper file and
# kill it on every start, which mvmctl reports as "does not answer the contract
# probe (... signal: 9)". A fresh copy with identical bytes (same signature, new
# file) clears it. Check the VM helper next to the mvmctl in use and refresh it
# only if it is killed and the copy is byte-identical.
heal_helper() {
  [ "$(uname -s)" = Darwin ] || return 0
  local real helper fresh
  real="$(python3 -c 'import os,shutil,sys; p=shutil.which(sys.argv[1]) or sys.argv[1]; print(os.path.realpath(p))' "$mvm" 2>/dev/null)" || return 0
  helper="$(dirname "$real")/mvm-hvf-supervisor"
  [ -x "$helper" ] || return 0
  probe() { bash -c 'perl -e "alarm 10; exec @ARGV" "$0" --contract-version </dev/null >/dev/null 2>&1' "$1" 2>/dev/null; }
  probe "$helper" && return 0
  fresh="$helper.fresh.$$"
  if cp -p "$helper" "$fresh" && cmp -s "$helper" "$fresh" && probe "$fresh" && mv -f "$fresh" "$helper"; then
    echo "note: refreshed $helper (macOS had stopped it from starting)" >&2
  else
    rm -f "$fresh"
    echo "warning: $helper does not start; the launches below will fail" >&2
  fi
}
heal_helper

# Firecracker refuses to run as root, and the Linux host needs /dev/kvm access
# and a systemd user session (for the CPU and memory scope around each VM).
if [ "$(uname -s)" = Linux ]; then
  if [ "$(id -u)" = 0 ]; then
    echo "error: on Linux run this as a normal user in the kvm group, not as root." >&2; exit 1
  fi
  [ -r /dev/kvm ] && [ -w /dev/kvm ] || { echo "error: /dev/kvm is not accessible to $(id -un); add the user to the kvm group." >&2; exit 1; }
fi

id="$(date +%H%M%S)"   # names are unique per run, so `explain <name>` is never ambiguous
a="line-a-$id"; b="line-b-$id"; m="maintenance-$id"

# One workload: a name, the one destination it is allowed, and what it does.
# Launches overlap; a release that still serializes them on the volume lock
# refuses the loser, so a refused launch is retried. Status 3 means this home
# has not been prepared yet, which `prepare` below fixes once.
launch() {
  local out
  for _ in 1 2 3 4 5; do
    out="$($mvm machine run -d --image "$image" --name "$1" --allow-host "$2" -- sh -c "$3" 2>&1 </dev/null)" && return
    case "$out" in *"is not prepared"*) return 3 ;; esac
    sleep 2
  done
  echo "could not start $1:" >&2; echo "$out" >&2; return 1
}
work() { echo "while true; do curl -sS -m 10 -o /dev/null https://$1/; sleep 2; done"; }

# First use of a home: fetch the image and build the workload runtime, which a
# throwaway run does. Every later run of the script skips this.
prepare() {
  echo "Preparing this machine once (image and runtime); this takes a few minutes"
  local out
  out="$($mvm image pull "$image" 2>&1)" || { echo "could not pull $image:" >&2; echo "$out" >&2; return 1; }
  out="$($mvm run --image "$image" -- true 2>&1 </dev/null)" || { echo "the first run on this machine failed:" >&2; echo "$out" >&2; return 1; }
}

# Start the three workloads at once. Sets `unprepared` when any was refused
# only because the home is not prepared, and `failed` for any other failure.
start_all() {
  local pids=() statuses=() i
  launch "$a" pypi.org:443 "$(work pypi.org)" & pids+=($!)
  launch "$b" files.pythonhosted.org:443 "$(work files.pythonhosted.org)" & pids+=($!)
  launch "$m" api.github.com:443 "while true; do curl -sS -m 10 https://example.com/ >/dev/null 2>&1; sleep 3; done" & pids+=($!)
  unprepared=""; failed=""
  for i in "${!pids[@]}"; do
    wait "${pids[$i]}" && continue
    [ "$?" -eq 3 ] && unprepared=1 || failed=1
  done
}

echo "Starting three workloads at once, each allowed one destination"
start_all
if [ -n "$unprepared" ]; then
  prepare || exit 1
  echo "Starting three workloads at once, each allowed one destination"
  start_all
fi
[ -z "$failed$unprepared" ] || { echo "a workload did not start; see above (clean up with --down)" >&2; exit 1; }

echo; echo "== 1. All three are running"
$mvm machine ls | grep -E "^NAME|-$id "

echo; echo "== 2. What each is allowed to reach"
for n in "$a" "$b" "$m"; do $mvm machine inspect "$n" | grep -E "^(name|allow-host):"; done

echo; echo "== 3. The maintenance workload asks for example.com, which it was not given"
# Wait at most 60 s for the first refusal, however long each explain takes.
SECONDS=0
while [ "$SECONDS" -lt 60 ]; do
  [ "$($mvm explain "$m" 2>/dev/null | grep -c "egress denied")" -gt 0 ] && break
  sleep 1
done
$mvm explain "$m" | sed -n '/^outcome:/,$p'

echo; echo "== 4. The inspection workloads are unaffected"
for n in "$a" "$b"; do
  echo "-- $n"; $mvm explain "$n" | sed -n '/^outcome:/,$p'
done

echo; echo "== 5. The audit record (every entry the host signed for the maintenance workload)"
session="$($mvm trust audit sessions | awk -v n="$m" '$NF == n { print $1 }')"
$mvm trust audit show "$session" | cut -c1-150
$mvm trust audit verify | tail -1
