# shellcheck shell=bash
# The one place that knows how a workload leaves a message for the host.
#
# Sourced by scripts/mailbox-live-witness.sh and scripts/mission-demo-live.sh.
# The caller defines `mvm`, a function that runs its mvmctl. When the outbox
# layout changes, this is the only function to change.

# Leave one outbox frame in the guest: a 32-byte recipient (every byte is the
# octal <fill>), then the body, put in place with a rename so the agent never
# reads half a frame. Written as the directory's own owner, which is the
# identity that may use it.
mailbox_write_frame() { # <vm> <fill: 000 = own mailbox, 377 = anyone else> <body>
  # The script expands in the guest, not here.
  # shellcheck disable=SC2016
  mvm machine exec "$1" -- sh -c '
    d=/run/mvm/mailbox; owner=$(stat -c %u "$d"); t="$d/.frame.$$"
    { head -c 32 /dev/zero | tr "\\0" "\\$1"; printf "%s" "$2"; } > "$t"
    [ "$(id -u)" != 0 ] || chown "$owner" "$t"
    chmod 640 "$t"
    # BusyBox date has no %N: seconds plus the pid keeps names unique per exec
    # and ordered across execs; the temp name is dotted so it is never read.
    mv "$t" "$d/outbox/$(date +%s)-$$"' _ "$2" "$3"
}
