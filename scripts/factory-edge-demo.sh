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

mvm="${MVMCTL:-mvmctl}"
image="${IMAGE:-curlimages/curl:8.21.0}"
export MVM_HOME="${MVM_HOME:-$HOME/.mvm-demo}" MVM_RESIDENCY=cold

if [ "${1:-}" = --down ]; then
  for m in $($mvm machine ls | awk '$1 ~ /^(line-a|line-b|maintenance)-/ { print $1 }'); do
    $mvm machine stop "$m" --yes >/dev/null 2>&1 || true
    $mvm machine rm "$m" --yes >/dev/null 2>&1 || true
  done
  echo "removed"; exit 0
fi

id="$(date +%H%M%S)"   # names are unique per run, so `explain <name>` is never ambiguous
a="line-a-$id"; b="line-b-$id"; m="maintenance-$id"

# One workload: a name, the one destination it is allowed, and what it does.
launch() { $mvm machine run -d --image "$image" --name "$1" --allow-host "$2" -- sh -c "$3" >/dev/null; }
work() { echo "while true; do curl -sS -m 10 -o /dev/null https://$1/; sleep 2; done"; }

echo "Starting three workloads, each allowed one destination"
launch "$a" pypi.org:443 "$(work pypi.org)"
launch "$b" files.pythonhosted.org:443 "$(work files.pythonhosted.org)"
launch "$m" api.github.com:443 "while true; do curl -sS -m 10 https://example.com/ >/dev/null 2>&1; sleep 3; done"

echo; echo "== 1. All three are running"
$mvm machine ls | grep -E "^NAME|-$id "

echo; echo "== 2. What each is allowed to reach"
for n in "$a" "$b" "$m"; do $mvm machine inspect "$n" | grep -E "^(name|allow-host):"; done

echo; echo "== 3. The maintenance workload asks for example.com, which it was not given"
for _ in $(seq 1 30); do
  $mvm explain "$m" 2>/dev/null | grep -q "egress denied" && break
  sleep 1
done
$mvm explain "$m" | sed -n '/^outcome:/,$p'

echo; echo "== 4. The inspection workloads are unaffected"
for n in "$a" "$b"; do
  echo "-- $n"; $mvm explain "$n" | sed -n '/^outcome:/,$p'
done
