# shellcheck shell=bash
# The one place that knows how a workload leaves a message for the host.
#
# Sourced by scripts/mission-demo-live.sh.
# The caller defines `mvm`, a function that runs its mvmctl. When the outbox
# layout changes, this is the only function to change.

# Leave one outbox frame in the guest: a 32-byte recipient (every byte is the
# octal <fill>), then the body, put in place with a rename so the agent never
# reads half a frame. Written as the directory's own owner, which is the
# identity that may use it.
# The same recipe as shell text a guest can run itself: it defines `mbx_write
# <fill> <body>`. A workload that leaves its own frames (the entrypoint-driven
# path) sources this instead of being driven through `machine exec`, so the
# layout is still known in one place.
mailbox_guest_writer() {
  cat <<'EOS'
mbx_write() {
    d=/run/mvm/mailbox; owner=$(stat -c %u "$d") || return
    t="$d/.frame.$$"
    { head -c 32 /dev/zero | tr "\\0" "\\$1"; printf "%s" "$2"; } > "$t" || return
    if [ "$(id -u)" = 0 ]; then chown "$owner" "$t" || return; fi
    chmod 640 "$t" || return
    # One workload may stage multiple reports in the same second.
    mbx_sequence=$((${mbx_sequence:-0} + 1))
    suffix=$(printf '%010d' "$mbx_sequence") || return
    mv "$t" "$d/outbox/$(date +%s)-$$-$suffix"
}
EOS
}

mailbox_write_frame() { # <vm> <fill: 000 = own mailbox, 377 = anyone else> <body>
  # The script expands in the guest, not here.
  # shellcheck disable=SC2016
  mvm machine exec "$1" -- sh -c "$(mailbox_guest_writer)"'
    mbx_write "$1" "$2"' _ "$2" "$3"
}
