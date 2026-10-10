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
# Three more boots follow from the same HOME, each with its own token and
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
# The fourth grants egress to one host (`--allow-host example.com`) and the
# guest must fetch it over HTTPS. That starts the per-VM network endpoint
# shipped beside mvmctl, which confines itself with a seccomp filter before it
# answers the guest. A syscall the release's libc makes and a source build's
# does not kills the endpoint there, so only the shipped binary can show it.
#
# MVM_SMOKE_ARCHIVE runs the same boots against a release archive that has not
# been published yet: the archive is unpacked, mvmctl is linked into the
# throwaway HOME's ~/.local/bin the way the installer links it, and `mvmctl
# bootstrap` runs as the installer would run it. The installer itself cannot
# take that archive, because it refuses anything without the signature the
# publish step adds.
#
# MVM_SMOKE_GUEST_RUNTIME adds the release's unpublished guest runtime to that
# archive: it is staged in guest-runtime/ beside the unpacked mvmctl, where the
# installer puts the published one, and `mvmctl bootstrap` must adopt it there
# rather than look for it in a release that does not exist yet. That pairs the
# CLI with the guest runtime it will ship with before either is published.
#
# The environment is rebuilt from nothing (`env -i`): no MVM_* knob, cache
# directory or tool the developer's shell happens to carry can make a broken
# release look working. Nothing outside the throwaway root is written.
#
# Environment:
#   MVM_SMOKE_INSTALLER            install.sh to run, as a path or an http(s)
#                                  URL; default: this checkout's install.sh
#   MVM_SMOKE_ARCHIVE              release archive (mvmctl-<target>.tar.gz) to
#                                  unpack instead of running an installer
#   MVM_SMOKE_GUEST_RUNTIME        the release's guest runtime archive
#                                  (mvm-guest-bins-v<version>.tar.gz) to stage
#                                  beside the unpacked mvmctl; archive mode only
#   MVM_SMOKE_OUT                  directory for the transcript and VM logs;
#                                  default: a new directory under /tmp
#   MVM_SMOKE_INSTALL_BUDGET_SECS  install + bootstrap budget; default 1200
#   MVM_SMOKE_RUN_BUDGET_SECS      first-command budget; default 600
#   MVM_SMOKE_SECOND_RUN_BUDGET_SECS
#                                  second-boot budget; default 300
#   MVM_SMOKE_SDK_RUN_BUDGET_SECS  SDK-boot budget; default 300
#   MVM_SMOKE_EGRESS_RUN_BUDGET_SECS
#                                  egress-boot budget; default 300
#   MVM_SMOKE_KEEP                 set to 1 to keep the throwaway HOME
#   MVM_SMOKE_NO_HOMEBREW          set to 1 to leave Homebrew off the PATH
#
# Exit status: 0 when all four boots printed their tokens in budget and the
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
ARCHIVE="${MVM_SMOKE_ARCHIVE:-}"
GUEST_RUNTIME="${MVM_SMOKE_GUEST_RUNTIME:-}"
if [ -n "$GUEST_RUNTIME" ] && [ -z "$ARCHIVE" ]; then
  echo "MVM_SMOKE_GUEST_RUNTIME is staged beside an unpacked MVM_SMOKE_ARCHIVE; set both" >&2
  exit 2
fi
if [ -n "$ARCHIVE" ] && [ -n "${MVM_SMOKE_INSTALLER:-}" ]; then
  echo "MVM_SMOKE_ARCHIVE and MVM_SMOKE_INSTALLER each name what to install; set one" >&2
  exit 2
fi
INSTALLER="${MVM_SMOKE_INSTALLER:-$REPO_ROOT/install.sh}"
INSTALL_BUDGET="${MVM_SMOKE_INSTALL_BUDGET_SECS:-1200}"
RUN_BUDGET="${MVM_SMOKE_RUN_BUDGET_SECS:-600}"
SECOND_RUN_BUDGET="${MVM_SMOKE_SECOND_RUN_BUDGET_SECS:-300}"
SDK_RUN_BUDGET="${MVM_SMOKE_SDK_RUN_BUDGET_SECS:-300}"
EGRESS_RUN_BUDGET="${MVM_SMOKE_EGRESS_RUN_BUDGET_SECS:-300}"
IMAGE="alpine"
# The image and host the documented egress examples use; alpine's busybox
# wget cannot be relied on to speak HTTPS through the guest's proxy.
EGRESS_IMAGE="curlimages/curl:8.21.0"
EGRESS_HOST="example.com"

for budget in "$INSTALL_BUDGET" "$RUN_BUDGET" "$SECOND_RUN_BUDGET" "$SDK_RUN_BUDGET" "$EGRESS_RUN_BUDGET"; do
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
if [ -n "$ARCHIVE" ]; then
  log "archive:    $ARCHIVE"
  log "release:    ${VERSION:-(the version its mvmctl reports)}"
else
  log "installer:  $INSTALLER"
  log "release:    ${VERSION:-(unpinned: what the one-liner installs today)}"
fi
log "HOME:       $SMOKE_HOME"
log "budgets:    install ${INSTALL_BUDGET}s, first command ${RUN_BUDGET}s, second boot ${SECOND_RUN_BUDGET}s, SDK boot ${SDK_RUN_BUDGET}s, egress boot ${EGRESS_RUN_BUDGET}s"
log "PATH:       $PATH_FOR_USER"

# Run the installer the way the README does.
install_with_installer() {
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
}

# Do by hand what the installer does once it has verified an archive: unpack
# it, link mvmctl onto PATH from beside the binaries it ships with, and run
# `mvmctl bootstrap`. mvmctl finds the per-VM host binaries next to its own
# resolved path, so the link has to point into the unpacked directory.
install_from_archive() {
  section "install (unpack $ARCHIVE, link mvmctl, mvmctl bootstrap)"
  [ -f "$ARCHIVE" ] || fail "no release archive at $ARCHIVE"
  mkdir -p "$ROOT/release" "$SMOKE_HOME/.local/bin"
  tar -xzf "$ARCHIVE" -C "$ROOT/release" || fail "could not unpack $ARCHIVE"
  unpacked=""
  for candidate in "$ROOT"/release/mvmctl-*/mvmctl; do
    [ -f "$candidate" ] || continue
    [ -z "$unpacked" ] || fail "$ARCHIVE holds more than one mvmctl-<target>/mvmctl"
    unpacked="$candidate"
  done
  [ -n "$unpacked" ] || fail "$ARCHIVE holds no mvmctl-<target>/mvmctl"
  ln -s "$unpacked" "$SMOKE_HOME/.local/bin/mvmctl"
  if [ -n "$GUEST_RUNTIME" ]; then
    [ -f "$GUEST_RUNTIME" ] || fail "no guest runtime at $GUEST_RUNTIME"
    mkdir -p "$(dirname "$unpacked")/guest-runtime"
    cp "$GUEST_RUNTIME" "$(dirname "$unpacked")/guest-runtime/" \
      || fail "could not stage $GUEST_RUNTIME beside mvmctl"
  fi
  shipped=""
  for entry in "$(dirname "$unpacked")"/*; do
    shipped="$shipped $(basename "$entry")"
  done
  log "unpacked:  $shipped"

  # Like the installer, a failed bootstrap is left for the first command to
  # recover from; one that outlives its budget is not.
  if bounded "$INSTALL_BUDGET" "$ROOT/install.out" "$ROOT/install.err" mvmctl bootstrap; then
    install_status=0
  else
    install_status=$?
    if [ "$install_status" -ne 124 ]; then
      printf 'bootstrap failed (mvmctl bootstrap exited %s)\n' "$install_status" >> "$ROOT/install.err"
      install_status=0
    fi
  fi
}

if [ -n "$ARCHIVE" ]; then
  install_from_archive
else
  install_with_installer
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
if [ -n "$GUEST_RUNTIME" ]; then
  runtime_name="$(basename "$GUEST_RUNTIME")"
  grep -q "Guest runtime $runtime_name ready (installed beside mvmctl)" "$ROOT/install.out" "$ROOT/install.err" \
    || fail "bootstrap did not adopt the unpublished guest runtime $runtime_name staged beside mvmctl"
  log "guest runtime: $runtime_name adopted from beside mvmctl"
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

# What every --allow-host, --net, --secret and --policy run depends on: the
# guest's traffic leaves only through the network endpoint the release ships,
# so the token is printed only after a fetch through it succeeded.
TOKEN4="$TOKEN-egress"
EGRESS_SCRIPT="curl -fsS -o /dev/null https://$EGRESS_HOST/ && echo $TOKEN4"
section "egress boot (mvmctl machine run --image $EGRESS_IMAGE --allow-host $EGRESS_HOST -- sh -c \"$EGRESS_SCRIPT\" </dev/null)"
boot_and_expect "egress boot" "$EGRESS_RUN_BUDGET" "$TOKEN4" run-egress \
  mvmctl machine run --image "$EGRESS_IMAGE" --allow-host "$EGRESS_HOST" -- sh -c "$EGRESS_SCRIPT"
EGRESS_RUN_ELAPSED="$STEP_ELAPSED"

section "timings"
log "install:        ${INSTALL_ELAPSED}s of ${INSTALL_BUDGET}s"
log "first command:  ${RUN_ELAPSED}s of ${RUN_BUDGET}s"
log "second boot:    ${SECOND_RUN_ELAPSED}s of ${SECOND_RUN_BUDGET}s"
log "SDK boot:       ${SDK_RUN_ELAPSED}s of ${SDK_RUN_BUDGET}s"
log "egress boot:    ${EGRESS_RUN_ELAPSED}s of ${EGRESS_RUN_BUDGET}s"

verdict "PASS: $INSTALLED installed in ${INSTALL_ELAPSED}s; its first microVM printed the token in ${RUN_ELAPSED}s, a second boot from the same HOME in ${SECOND_RUN_ELAPSED}s without fetching anything again, a boot binding $SDK_SERVICE saw the SDK sidecar in ${SDK_RUN_ELAPSED}s, and a boot allowed $EGRESS_HOST fetched it in ${EGRESS_RUN_ELAPSED}s"
printf '[smoke] transcript: %s\n' "$TRANSCRIPT" >&2
