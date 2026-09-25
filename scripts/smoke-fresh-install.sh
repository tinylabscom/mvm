#!/bin/sh
# Fresh-install smoke: what a new user gets from the one-line install and the
# first command the README gives them.
#
#   smoke-fresh-install.sh [version]
#
# A throwaway HOME under /tmp stands in for a machine that has never had mvm.
# The installer runs the way the README runs it — piped into `sh`, with the
# builder VM bootstrap it performs by default — pinned to `version` when one
# is given, otherwise choosing the release the one-liner would choose today.
# Then `mvmctl machine run --image alpine -- echo <token>` runs from that HOME
# with stdin redirected from /dev/null, and must print the token on stdout
# within its time budget.
#
# The environment is rebuilt from nothing (`env -i`): no MVM_* knob, cache
# directory or tool the developer's shell happens to carry can make a broken
# release look working. Nothing outside the throwaway root is written.
#
# Environment:
#   MVM_SMOKE_INSTALLER            install.sh to run, as a path or an http(s)
#                                  URL; default: this checkout's install.sh
#   MVM_SMOKE_OUT                  directory for the transcript and VM logs;
#                                  default: a new directory under /tmp
#   MVM_SMOKE_INSTALL_BUDGET_SECS  install + bootstrap budget; default 1200
#   MVM_SMOKE_RUN_BUDGET_SECS      first-command budget; default 600
#   MVM_SMOKE_KEEP                 set to 1 to keep the throwaway HOME
#   MVM_SMOKE_NO_HOMEBREW          set to 1 to leave Homebrew off the PATH
#
# Exit status: 0 when the first command printed the token in budget, 1 when
# it did not, 2 on a usage error.
set -eu

usage() {
  sed -n '5p' "$0" | sed 's/^# *//' >&2
  exit 2
}

[ "$#" -le 1 ] || usage
VERSION="${1:-}"
case "$VERSION" in
  -*) usage ;;
  '') ;;
  *[!A-Za-z0-9._+-]*) echo "not a release tag: $VERSION" >&2; exit 2 ;;
esac

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
BOUNDED="$REPO_ROOT/scripts/run-bounded-command.py"
INSTALLER="${MVM_SMOKE_INSTALLER:-$REPO_ROOT/install.sh}"
INSTALL_BUDGET="${MVM_SMOKE_INSTALL_BUDGET_SECS:-1200}"
RUN_BUDGET="${MVM_SMOKE_RUN_BUDGET_SECS:-600}"
IMAGE="alpine"

for budget in "$INSTALL_BUDGET" "$RUN_BUDGET"; do
  case "$budget" in
    ''|*[!0-9]*|0) echo "time budgets must be positive whole seconds, got: $budget" >&2; exit 2 ;;
  esac
done
command -v python3 >/dev/null 2>&1 || { echo "python3 is required to bound the smoke's commands" >&2; exit 2; }

# A short root: the machine's sockets live under it, and a Unix socket path
# must fit in 104 bytes on macOS.
ROOT="$(mktemp -d /tmp/mvm-fresh.XXXXXX)"
ROOT="$(cd "$ROOT" && pwd -P)"
SMOKE_HOME="$ROOT/home"
mkdir -p "$SMOKE_HOME" "$ROOT/tmp"
if [ -n "${MVM_SMOKE_OUT:-}" ]; then
  OUT="$MVM_SMOKE_OUT"
  mkdir -p "$OUT"
else
  OUT="$(mktemp -d /tmp/mvm-fresh-install-out.XXXXXX)"
fi
OUT="$(cd "$OUT" && pwd -P)"
TRANSCRIPT="$OUT/transcript.log"
: > "$TRANSCRIPT"

cleanup() {
  status=$?
  if [ "${MVM_SMOKE_KEEP:-}" = "1" ]; then
    printf '[smoke] kept the throwaway HOME at %s\n' "$SMOKE_HOME" >&2
  else
    case "$ROOT" in
      /tmp/mvm-fresh.*|/private/tmp/mvm-fresh.*) rm -rf "$ROOT" ;;
    esac
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

log() { printf '%s\n' "$*" | tee -a "$TRANSCRIPT"; }
section() { log ""; log "=== $* ==="; }
append() {
  if [ -s "$1" ]; then
    tee -a "$TRANSCRIPT" < "$1"
  else
    log "(empty)"
  fi
}
verdict() {
  section "verdict"
  log "$*"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY"
  fi
}
fail() {
  verdict "FAIL: $*"
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    printf '::error::fresh-install smoke: %s\n' "$*"
  fi
  printf '[smoke] transcript: %s\n' "$TRANSCRIPT" >&2
  exit 1
}

# The only variables a new user's shell is assumed to have. PATH is a login
# shell's: the install dir, as the installer tells a user to arrange, the
# system directories, and Homebrew's when the host has it — most Macs do, and
# what an installed Homebrew changes about a first run is part of what a user
# sees. MVM_SMOKE_NO_HOMEBREW=1 leaves it off, for the host that has none.
PATH_FOR_USER="$SMOKE_HOME/.local/bin"
if [ "${MVM_SMOKE_NO_HOMEBREW:-}" != "1" ]; then
  for brew_bin in /opt/homebrew/bin /home/linuxbrew/.linuxbrew/bin; do
    if [ -d "$brew_bin" ]; then
      PATH_FOR_USER="$PATH_FOR_USER:$brew_bin"
    fi
  done
fi
PATH_FOR_USER="$PATH_FOR_USER:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
SMOKE_USER="${USER:-$(id -un)}"
in_fresh_home() {
  env -i \
    HOME="$SMOKE_HOME" \
    USER="$SMOKE_USER" \
    LOGNAME="$SMOKE_USER" \
    SHELL=/bin/sh \
    TERM=dumb \
    LANG=C \
    TMPDIR="$ROOT/tmp" \
    PATH="$PATH_FOR_USER" \
    "$@"
}

# Run "$@" in the rebuilt environment and a fresh session, bounded by $1
# seconds, stdout to $2, stderr to $3, stdin from /dev/null. Sets BOUNDED_ELAPSED to the seconds it took, and
# returns the command's status, or 124 when the budget ran out. The bounding
# helper ends the whole session afterwards, so nothing the command left
# running outlives the smoke.
#
# The inner `sh -c` expands its own positional parameters, and the helper
# never reads the stderr file both append to.
# shellcheck disable=SC2016,SC2094
bounded() {
  bounded_budget="$1"
  bounded_stdout="$2"
  bounded_stderr="$3"
  shift 3
  : > "$bounded_stderr"
  bounded_started="$(date +%s)"
  set +e
  python3 "$BOUNDED" --timeout "$bounded_budget" --log "$bounded_stdout" -- \
    env -i \
    HOME="$SMOKE_HOME" \
    USER="$SMOKE_USER" \
    LOGNAME="$SMOKE_USER" \
    SHELL=/bin/sh \
    TERM=dumb \
    LANG=C \
    TMPDIR="$ROOT/tmp" \
    PATH="$PATH_FOR_USER" \
    sh -c 'err="$1"; shift; exec "$@" 2>>"$err"' sh "$bounded_stderr" "$@" \
    </dev/null >/dev/null 2>>"$bounded_stderr"
  bounded_status=$?
  set -e
  BOUNDED_ELAPSED=$(( $(date +%s) - bounded_started ))
  return "$bounded_status"
}

section "fresh-install smoke"
log "date:       $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "host:       $(uname -s) $(uname -r) $(uname -m)"
log "installer:  $INSTALLER"
log "release:    ${VERSION:-(unpinned: what the one-liner installs today)}"
log "HOME:       $SMOKE_HOME"
log "budgets:    install ${INSTALL_BUDGET}s, first command ${RUN_BUDGET}s"
log "PATH:       $PATH_FOR_USER"

case "$INSTALLER" in
  http://*|https://*)
    curl -fsSL "$INSTALLER" -o "$ROOT/install.sh" || fail "could not download the installer from $INSTALLER"
    ;;
  *)
    [ -f "$INSTALLER" ] || fail "no installer at $INSTALLER"
    cp "$INSTALLER" "$ROOT/install.sh"
    ;;
esac

# `curl ... | sh`: the script arrives on the shell's stdin, so anything the
# installer runs inherits that pipe as its own stdin — as it does for a user.
section "install ($([ -n "$VERSION" ] && printf 'MVM_VERSION=%s ' "$VERSION")sh install.sh)"
# shellcheck disable=SC2016 # the inner shell expands its own "$1"
if bounded "$INSTALL_BUDGET" "$ROOT/install.out" "$ROOT/install.err" \
  env ${VERSION:+"MVM_VERSION=$VERSION"} sh -c 'cat "$1" | sh' sh "$ROOT/install.sh"; then
  install_status=0
else
  install_status=$?
fi
append "$ROOT/install.out"
log "--- stderr ---"
append "$ROOT/install.err"
log "--- install exited $install_status after ${BOUNDED_ELAPSED}s ---"
INSTALL_ELAPSED="$BOUNDED_ELAPSED"
[ "$install_status" -ne 124 ] || fail "the install did not finish within ${INSTALL_BUDGET}s"
[ "$install_status" -eq 0 ] || fail "the install exited $install_status"
[ -x "$SMOKE_HOME/.local/bin/mvmctl" ] || fail "the install reported success and left no $SMOKE_HOME/.local/bin/mvmctl"
INSTALLED="$(in_fresh_home mvmctl --version 2>&1)" || fail "the installed mvmctl does not run: $INSTALLED"
log "installed:  $INSTALLED"
if [ -n "$VERSION" ] && [ "$INSTALLED" != "mvmctl ${VERSION#v}" ]; then
  fail "the install pinned to $VERSION left '$INSTALLED' on PATH"
fi
if grep -q 'bootstrap failed' "$ROOT/install.err"; then
  log "note: the installer's bootstrap failed; the first command must recover on its own"
fi

TOKEN="mvm-fresh-install-$(date +%s)-$$"
section "first command (mvmctl machine run --image $IMAGE -- echo $TOKEN </dev/null)"
if bounded "$RUN_BUDGET" "$ROOT/run.out" "$ROOT/run.err" \
  mvmctl machine run --image "$IMAGE" -- echo "$TOKEN"; then
  run_status=0
else
  run_status=$?
fi
append "$ROOT/run.out"
log "--- stderr ---"
append "$ROOT/run.err"
log "--- first command exited $run_status after ${BOUNDED_ELAPSED}s ---"
RUN_ELAPSED="$BOUNDED_ELAPSED"

# Keep what the guest and its supervisor said before the throwaway HOME goes.
for vm_log in "$SMOKE_HOME"/.mvm/vms/*/console.log "$SMOKE_HOME"/.mvm/vms/*/supervisor.log; do
  [ -f "$vm_log" ] || continue
  vm_name="$(basename "$(dirname "$vm_log")")"
  mkdir -p "$OUT/vms/$vm_name"
  cp "$vm_log" "$OUT/vms/$vm_name/"
done

[ "$run_status" -ne 124 ] || fail "the first command did not finish within ${RUN_BUDGET}s"
[ "$run_status" -eq 0 ] || fail "the first command exited $run_status"
tr -d '\r' < "$ROOT/run.out" | grep -qxF "$TOKEN" \
  || fail "the first command exited 0 without printing $TOKEN on stdout"

verdict "PASS: $INSTALLED installed in ${INSTALL_ELAPSED}s; its first microVM printed the token in ${RUN_ELAPSED}s"
printf '[smoke] transcript: %s\n' "$TRANSCRIPT" >&2
