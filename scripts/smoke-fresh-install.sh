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
# Two more boots follow from the same HOME, each with its own token and
# budget, because a release binary's downloads are not checked by its first
# boot. That boot runs the runtime overlay and initramfs it has just fetched.
# The second is the first to resolve them from the cache, which fetches again,
# or refuses, an artifact whose VERSION is not the binary's own. So the second
# boot must print its token and must not have replaced any file the first left
# under ~/.mvm/cache/runtime-overlay or ~/.mvm/cache/initramfs. The third binds
# an SDK host service (`--host-service host.time.v1`), which downloads the
# published SDK sidecar, and the guest must find the SDK library under
# /mvm/sdk. A source checkout builds all three locally, so CI's e2e lanes
# cannot see this class of bug.
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
#   MVM_SMOKE_SECOND_RUN_BUDGET_SECS
#                                  second-boot budget; default 300
#   MVM_SMOKE_SDK_RUN_BUDGET_SECS  SDK-boot budget; default 300
#   MVM_SMOKE_KEEP                 set to 1 to keep the throwaway HOME
#   MVM_SMOKE_NO_HOMEBREW          set to 1 to leave Homebrew off the PATH
#
# Exit status: 0 when all three boots printed their tokens in budget and the
# second fetched nothing again, 1 when any of that failed, 2 on a usage error.
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
SECOND_RUN_BUDGET="${MVM_SMOKE_SECOND_RUN_BUDGET_SECS:-300}"
SDK_RUN_BUDGET="${MVM_SMOKE_SDK_RUN_BUDGET_SECS:-300}"
IMAGE="alpine"

for budget in "$INSTALL_BUDGET" "$RUN_BUDGET" "$SECOND_RUN_BUDGET" "$SDK_RUN_BUDGET"; do
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
log "budgets:    install ${INSTALL_BUDGET}s, first command ${RUN_BUDGET}s, second boot ${SECOND_RUN_BUDGET}s, SDK boot ${SDK_RUN_BUDGET}s"
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

# Keep what the guests and their supervisors said before the throwaway HOME
# goes. Every boot is its own machine directory, so this runs after each one.
keep_vm_logs() {
  for vm_log in "$SMOKE_HOME"/.mvm/vms/*/console.log "$SMOKE_HOME"/.mvm/vms/*/supervisor.log; do
    [ -f "$vm_log" ] || continue
    vm_name="$(basename "$(dirname "$vm_log")")"
    mkdir -p "$OUT/vms/$vm_name"
    cp "$vm_log" "$OUT/vms/$vm_name/"
  done
}

# Boot a microVM and require it to print a token on stdout: $1 names the step
# in the transcript and in its failure, $2 is its budget, $3 the token, $4 the
# stem of its output files under the throwaway root, and the rest is the
# command. Sets STEP_ELAPSED, and fails the smoke on a timeout, a nonzero exit,
# or a missing token.
boot_and_expect() {
  step="$1"
  step_budget="$2"
  step_token="$3"
  step_stem="$4"
  shift 4
  if bounded "$step_budget" "$ROOT/$step_stem.out" "$ROOT/$step_stem.err" "$@"; then
    step_status=0
  else
    step_status=$?
  fi
  append "$ROOT/$step_stem.out"
  log "--- stderr ---"
  append "$ROOT/$step_stem.err"
  log "--- $step exited $step_status after ${BOUNDED_ELAPSED}s ---"
  STEP_ELAPSED="$BOUNDED_ELAPSED"
  keep_vm_logs
  [ "$step_status" -ne 124 ] || fail "the $step did not finish within ${step_budget}s"
  [ "$step_status" -eq 0 ] || fail "the $step exited $step_status"
  tr -d '\r' < "$ROOT/$step_stem.out" | grep -qxF "$step_token" \
    || fail "the $step exited 0 without printing $step_token on stdout"
}

# The artifacts a release binary downloads on its first boot and must find in
# the cache on every later one, one line per file: inode, size, and path under
# ~/.mvm/cache. Both installers stage a new directory and rename it over the
# old one, so a re-fetch gives every file a new inode even when the bytes are
# identical; booting from an artifact changes none of the three. The inode is
# the signal because it holds whatever mvmctl chooses to log. Dotfiles are left
# out: they are the resolver's own validation stamps and staging files, which
# it may rewrite on any boot without fetching anything.
snapshot_download_caches() {
  python3 - "$SMOKE_HOME/.mvm/cache" runtime-overlay initramfs <<'SNAPSHOT' | LC_ALL=C sort
import os
import stat
import sys

root = sys.argv[1]
for cache in sys.argv[2:]:
    for directory, _, files in os.walk(os.path.join(root, cache)):
        for name in files:
            if name.startswith("."):
                continue
            path = os.path.join(directory, name)
            info = os.lstat(path)
            if stat.S_ISREG(info.st_mode):
                print(info.st_ino, info.st_size, os.path.relpath(path, root))
SNAPSHOT
}

TOKEN="mvm-fresh-install-$(date +%s)-$$"
section "first command (mvmctl machine run --image $IMAGE -- echo $TOKEN </dev/null)"
boot_and_expect "first command" "$RUN_BUDGET" "$TOKEN" run \
  mvmctl machine run --image "$IMAGE" -- echo "$TOKEN"
RUN_ELAPSED="$STEP_ELAPSED"

CACHES_FIRST="$OUT/download-caches-after-first.txt"
CACHES_SECOND="$OUT/download-caches-after-second.txt"
section "download caches after the first command (inode size path, under ~/.mvm/cache)"
snapshot_download_caches > "$CACHES_FIRST"
append "$CACHES_FIRST"
[ -s "$CACHES_FIRST" ] \
  || fail "the first command cached no runtime overlay or initramfs under $SMOKE_HOME/.mvm/cache, so a second boot has nothing to reuse"

# A release binary accepts a cached artifact only when its VERSION is the
# binary's own. The first boot runs whatever it has just downloaded; only a
# later one resolves the cache, and that is where a mismatched artifact is
# fetched again on every boot, or refused outright.
TOKEN2="$TOKEN-second"
section "second boot from the same HOME (mvmctl machine run --image $IMAGE -- echo $TOKEN2 </dev/null)"
boot_and_expect "second boot" "$SECOND_RUN_BUDGET" "$TOKEN2" run-second \
  mvmctl machine run --image "$IMAGE" -- echo "$TOKEN2"
SECOND_RUN_ELAPSED="$STEP_ELAPSED"

section "download caches after the second boot"
snapshot_download_caches > "$CACHES_SECOND"
append "$CACHES_SECOND"
REFETCHED="$(LC_ALL=C comm -23 "$CACHES_FIRST" "$CACHES_SECOND" | cut -d' ' -f3- | tr '\n' ' ')"
[ -z "$REFETCHED" ] \
  || fail "the second boot replaced or removed what the first cached, so it fetched it again: $REFETCHED"

# The documented way to give a workload the SDK: binding an SDK-served host
# service attaches the sidecar read-only at /mvm/sdk, downloading the published
# one on a cold cache. The guest proves the library is there.
TOKEN3="$TOKEN-sdk"
SDK_SERVICE="host.time.v1"
SDK_LIB="/mvm/sdk/lib/libmvm_host_services.so"
SDK_SCRIPT="if test -r $SDK_LIB; then echo $TOKEN3; else echo 'no SDK sidecar library at $SDK_LIB' >&2; exit 3; fi"
section "SDK boot (mvmctl machine run --image $IMAGE --host-service $SDK_SERVICE -- sh -c \"$SDK_SCRIPT\" </dev/null)"
boot_and_expect "SDK boot" "$SDK_RUN_BUDGET" "$TOKEN3" run-sdk \
  mvmctl machine run --image "$IMAGE" --host-service "$SDK_SERVICE" -- sh -c "$SDK_SCRIPT"
SDK_RUN_ELAPSED="$STEP_ELAPSED"

section "timings"
log "install:        ${INSTALL_ELAPSED}s of ${INSTALL_BUDGET}s"
log "first command:  ${RUN_ELAPSED}s of ${RUN_BUDGET}s"
log "second boot:    ${SECOND_RUN_ELAPSED}s of ${SECOND_RUN_BUDGET}s"
log "SDK boot:       ${SDK_RUN_ELAPSED}s of ${SDK_RUN_BUDGET}s"

verdict "PASS: $INSTALLED installed in ${INSTALL_ELAPSED}s; its first microVM printed the token in ${RUN_ELAPSED}s, a second boot from the same HOME in ${SECOND_RUN_ELAPSED}s without fetching anything again, and a boot binding $SDK_SERVICE saw the SDK sidecar in ${SDK_RUN_ELAPSED}s"
printf '[smoke] transcript: %s\n' "$TRANSCRIPT" >&2
