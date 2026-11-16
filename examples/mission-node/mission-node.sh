#!/bin/sh
# The mission demo's workload. It does, by itself and on a fixed schedule, what
# a compromised workload would try, so the demo never depends on a model
# choosing to misbehave:
#
#   1. an approved observation to its own mailbox,
#   2. a message addressed to a different mailbox, which the host must refuse,
#   3. a request to a host it was not granted, which crosses the vsock egress
#      channel to the host's endpoint, which must refuse and audit it,
#   4. a message left unread, which the containment step must make unreadable
#      to a replacement.
#
# Nothing is read back: the host observes through `machine mailbox recv` and
# the audit chain. The client ships in the signed runtime overlay; this image
# carries no copy of it.
#
#   MISSION_STEP_SECS   seconds between steps (default 5)
set -u

client="${MISSION_CLIENT:-/mvm/runtime/mailbox-client}"
step="${MISSION_STEP_SECS:-5}"
other="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

say() { echo "mission-node: $*"; }
# A send reports local staging only; whether the host accepted it is the
# host's record, not this script's.
send() { "$client" send --local "$@" || say "could not stage: $*"; }

send "aircraft-observation-1"
sleep $((step * 2))
send --to "$other" "exfiltrate-to-someone-else"
sleep "$step"
wget -T 4 -q -O- http://blocked.example >/dev/null 2>&1 || say "the request was refused"
sleep $((step * 3))
send "left-unread-in-the-old-workload"
say "done; waiting to be contained"
while :; do sleep 60; done
