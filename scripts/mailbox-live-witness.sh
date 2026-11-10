#!/usr/bin/env bash
# Live witness for the guest mailbox on an INSTALLED mvmctl, with no
# `mvmctl bootstrap`. It boots a granted guest, has the guest write messages,
# reads them back on the host, and proves the refusals and the audit chain.
#
# Needs a host that boots a VM (Linux with KVM, or macOS on HVF) and a fresh
# install. It never runs bootstrap and uses an empty MVM_HOME, so whatever
# the install alone provides is all it gets. A failure on a first run is a
# finding about the install, not about this script.
#
# What it shows: a granted guest on this host delivers to this host's mailbox.
# It does NOT show node-to-node delivery; that needs a destination guest and a
# cross-host link.
#
#   MVMCTL       the mvmctl to drive (default: mvmctl on PATH)
#   HYPERVISOR   passed as --hypervisor when set (firecracker, hvf)
#   MVM_HOME     default: a new empty directory, removed on exit
set -euo pipefail

MVMCTL="${MVMCTL:-mvmctl}"
IMAGE="${IMAGE:-alpine}"
WAIT_SECS="${WAIT_SECS:-120}"
NAME="mbx-witness-$$"
CONTROL="mbx-witness-ungranted-$$"
FIRST="witness-message-one"
SECOND="witness-message-two"
hyp=(); [ -z "${HYPERVISOR:-}" ] || hyp=(--hypervisor "$HYPERVISOR")

own_home=""
if [ -z "${MVM_HOME:-}" ]; then
  own_home="$(mktemp -d)"; export MVM_HOME="$own_home"
fi
mvm() { "$MVMCTL" "$@"; }
say() { echo "PASS $*"; }
fail() { echo "FAIL $*" >&2; exit 1; }

cleanup() {
  for vm in "$NAME" "$CONTROL"; do mvm machine stop "$vm" --yes >/dev/null 2>&1 || true; done
  for vm in "$NAME" "$CONTROL"; do mvm machine rm "$vm" --yes >/dev/null 2>&1 || true; done
  [ -z "$own_home" ] || rm -rf "$own_home"
}
trap cleanup EXIT

# Run until `cmd` succeeds or WAIT_SECS pass.
wait_for() { # <what> <cmd...>
  local what="$1" end=$((SECONDS + WAIT_SECS)); shift
  until "$@" >/dev/null 2>&1; do
    [ "$SECONDS" -lt "$end" ] || fail "timed out waiting for $what"
    sleep 2
  done
}

# Leave one outbox frame in the guest: a 32-byte recipient (every byte is the
# octal <fill>), then the body, put in place with a rename so the agent never
# reads half a frame. Written as the directory's own owner, which is the
# identity that may use it.
write_frame() { # <vm> <fill: 000 = own mailbox, 377 = anyone else> <body>
  # The script expands in the guest, not here.
  # shellcheck disable=SC2016
  mvm machine exec "$1" -- sh -c '
    d=/run/mvm/mailbox; owner=$(stat -c %u "$d"); t="$d/.witness.$$"
    { head -c 32 /dev/zero | tr "\\0" "\\$1"; printf "%s" "$2"; } > "$t"
    [ "$(id -u)" != 0 ] || chown "$owner" "$t"
    chmod 640 "$t"; mv "$t" "$d/outbox"' _ "$2" "$3"
}

recv() { mvm machine mailbox recv "$1"; }
got() { [ "$(recv "$NAME")" = "$1" ]; }
OWN=000     # the guest's own mailbox
OTHER=377   # anyone else: must be refused
MAILBOX_ID="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"

echo "mvmctl: $(mvm --version)"
mvm image pull "$IMAGE" >/dev/null
mvm machine run -d --image "$IMAGE" --mailbox "$MAILBOX_ID" "${hyp[@]}" --name "$NAME" -- sleep 900 >/dev/null
wait_for "the guest to take commands" mvm machine exec "$NAME" -- true
say "granted guest booted from an install with no bootstrap"

cmdline="$(mvm machine exec "$NAME" -- cat /proc/cmdline)"
[ "$(grep -o 'mvm.mailbox=1' <<<"$cmdline" | wc -l)" -eq 1 ] || fail "cmdline does not carry exactly one mvm.mailbox=1"
say "kernel command line carries exactly one mvm.mailbox=1"

write_frame "$NAME" "$OWN" "$FIRST"
wait_for "the first message" got "$FIRST"
say "first message arrived exactly"

write_frame "$NAME" "$OWN" "$SECOND"
wait_for "the second message (the port keeps serving)" got "$SECOND"
say "second message arrived exactly"

[ -z "$(recv "$NAME")" ] || fail "mailbox not empty after both messages were read"
say "mailbox empty after reading"

write_frame "$NAME" "$OTHER" "must-not-arrive"
sleep 10
[ -z "$(recv "$NAME")" ] || fail "a message to another recipient was queued"
say "a message addressed to another mailbox was refused"

mvm trust audit verify >/dev/null || fail "audit chain does not verify"
audit="${MVM_HOME}/audit"
grep -rqF "mailbox.read" "$audit" || fail "no mailbox.read entry in the audit log"
! grep -rqF -e "$FIRST" -e "$SECOND" "$audit" || fail "a message body is in the audit log"
say "audit chain verifies; reads are recorded without the body"

pidfile="${MVM_HOME}/vms/${NAME}/mailbox.pid"
[ -s "$pidfile" ] || fail "no mailbox process was recorded for the granted guest"
pid="$(cat "$pidfile")"
mvm machine stop "$NAME" --yes >/dev/null
wait_for "the mailbox process to exit" sh -c "! kill -0 $pid"
say "stopping the machine stopped its mailbox process"

mvm machine run -d --image "$IMAGE" "${hyp[@]}" --name "$CONTROL" -- sleep 900 >/dev/null
wait_for "the control guest to take commands" mvm machine exec "$CONTROL" -- true
mvm machine exec "$CONTROL" -- test ! -e /run/mvm/mailbox || fail "an ungranted guest has a mailbox directory"
! mvm machine exec "$CONTROL" -- grep -q 'mvm.mailbox=1' /proc/cmdline || fail "an ungranted guest carries the token"
[ ! -e "${MVM_HOME}/vms/${CONTROL}/mailbox.pid" ] || fail "an ungranted guest has a mailbox process"
say "an ungranted guest has no token, directory or process"

echo "WITNESS_RESULT=pass"
