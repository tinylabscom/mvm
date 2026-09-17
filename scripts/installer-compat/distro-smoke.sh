#!/bin/sh
# Run published Linux releases on this distribution: install each with the
# checkout's install.sh, run it, and report the glibc it needs against the
# glibc this distribution has. Meant for a throwaway container, as root.
#
#   distro-smoke.sh <install.sh> "<tags>" [summary-file]
#
# The loader check does not rely on the install succeeding. Every executable in
# the release archive goes through `ldd -v` first, so a `GLIBC_x.y not found`
# is reported per binary even when install.sh then refuses — which it does,
# because it runs the staged mvmctl before switching to it.
#
# Exits non-zero on any loader error, failed install, or wrong version.
set -eu

[ "$#" -ge 2 ] || { echo "usage: $0 <install.sh> \"<tags>\" [summary-file]" >&2; exit 2; }
INSTALLER="$1"
TAGS="$2"
SUMMARY="${3:-/dev/null}"
REPO="${COMPAT_REPO:-tinylabscom/mvm}"
DOWNLOAD_BASE="${MVM_UPDATE_DOWNLOAD_URL:-https://github.com}"

say() { printf '[distro] %s\n' "$*"; }
error() {
  printf '[distro] ERROR: %s\n' "$*" >&2
  # Workflow commands are read from the container's stdout too.
  printf '::error::%s\n' "$*"
}

install_tools() {
  missing=""
  for tool in curl tar gzip ldd getconf; do
    command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
  done
  [ -n "$missing" ] || return 0
  say "installing:$missing"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates tar gzip libc-bin >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    # Rocky ships curl-minimal, which conflicts with `curl`; ask only for what
    # is absent, by the file it provides.
    for tool in $missing; do
      case "$tool" in
        getconf|ldd) dnf install -y -q /usr/bin/"$tool" >/dev/null ;;
        *) dnf install -y -q "$tool" >/dev/null ;;
      esac
    done
  else
    error "no apt-get or dnf to install:$missing"
    exit 1
  fi
}

case "$(uname -m)" in
  x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
  aarch64|arm64) TARGET="aarch64-unknown-linux-gnu" ;;
  *) error "unsupported arch $(uname -m)"; exit 1 ;;
esac

install_tools
# shellcheck disable=SC1091 # the container's own file
DISTRO="$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-$ID}")"
GLIBC="$(getconf GNU_LIBC_VERSION 2>/dev/null || ldd --version 2>&1 | head -n1)"
say "$DISTRO, $GLIBC, $TARGET"

requirements="$(cd "$(dirname "$0")" && pwd -P)/glibc-requirements.sh"

status=0
rows=""
for tag in $TAGS; do
  work="$(mktemp -d)"
  archive="$work/archive.tar.gz"
  if ! curl -fsSL --retry 3 --retry-delay 2 -o "$archive" \
    "$DOWNLOAD_BASE/$REPO/releases/download/$tag/mvmctl-$TARGET.tar.gz"; then
    error "$tag: could not download mvmctl-$TARGET.tar.gz"
    status=1
    continue
  fi
  mkdir -p "$work/unpacked"
  tar xzf "$archive" -C "$work/unpacked"

  highest=""
  loader_errors=""
  for binary in "$work/unpacked/mvmctl-$TARGET"/*; do
    if [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
      continue
    fi
    name="${binary##*/}"
    report="$(sh "$requirements" "$binary")"
    need="$(printf '%s\n' "$report" | sed -n 's/^required //p')"
    if [ -n "$need" ]; then
      highest="$(printf '%s\n%s\n' "$highest" "$need" | sed '/^$/d' | sort -V | tail -n1)"
    fi
    missing="$(printf '%s\n' "$report" | sed -n 's/^missing //p' | tr '\n' ' ')"
    if [ -n "$missing" ]; then
      loader_errors="$loader_errors $name needs ${missing% };"
      error "$tag on $DISTRO ($GLIBC): $name fails to load — ${missing% } not found"
    fi
  done

  bin="$work/prefix/bin"
  outcome="installed"
  set +e
  env HOME="$work/home" MVM_HOME="$work/home/.mvm" MVM_INSTALL_DIR="$bin" \
    MVM_VERSION="$tag" MVM_SKIP_BOOTSTRAP=1 MVM_UPDATE_DOWNLOAD_URL="$DOWNLOAD_BASE" \
    sh "$INSTALLER" </dev/null >"$work/install.log" 2>&1
  installed=$?
  set -e
  if [ "$installed" -ne 0 ]; then
    cat "$work/install.log"
    outcome="install failed"
    status=1
    loader_line="$(grep -m1 "GLIBC_[0-9.]*' not found" "$work/install.log" || true)"
    if [ -n "$loader_line" ]; then
      error "$tag: install.sh could not run mvmctl on $DISTRO: $loader_line"
    else
      error "$tag: install.sh failed on $DISTRO (exit $installed)"
    fi
  else
    want="mvmctl ${tag#v}"
    got="$(env HOME="$work/home" MVM_HOME="$work/home/.mvm" "$bin/mvmctl" --version 2>&1 || true)"
    if [ "$got" != "$want" ]; then
      error "$tag: mvmctl --version printed '$got', expected '$want'"
      outcome="wrong version"
      status=1
    elif ! env HOME="$work/home" MVM_HOME="$work/home/.mvm" "$bin/mvmctl" --help >/dev/null 2>"$work/help.log"; then
      cat "$work/help.log"
      error "$tag: mvmctl --help failed on $DISTRO"
      outcome="--help failed"
      status=1
    else
      set +e
      env HOME="$work/home" MVM_HOME="$work/home/.mvm" "$bin/mvmctl" doctor </dev/null >"$work/doctor.log" 2>&1
      doctor=$?
      set -e
      # 1 is doctor reporting host problems, which a container without KVM has.
      if [ "$doctor" -gt 1 ]; then
        cat "$work/doctor.log"
        error "$tag: mvmctl doctor exited $doctor on $DISTRO"
        outcome="doctor exited $doctor"
        status=1
      else
        outcome="installed; --version, --help, doctor (exit $doctor) ran"
      fi
    fi
  fi

  if [ -n "$loader_errors" ]; then
    status=1
  fi
  rows="$rows| \`$tag\` | $DISTRO | $GLIBC | ${highest:-unknown} | ${loader_errors:-none} | $outcome |
"
  say "$tag: needs ${highest:-unknown}; loader errors: ${loader_errors:-none}; $outcome"
done

header=""
if [ ! -s "$SUMMARY" ]; then
  header="| Release | Distribution | Host glibc | Highest glibc required | Loader errors | Result |
| --- | --- | --- | --- | --- | --- |
"
fi
printf '%s%s' "$header" "$rows" >> "$SUMMARY"

exit "$status"
