# shellcheck shell=sh
# Shared by the installer compat lanes. Sourced, never executed.
#
# Several variables set here (COMPAT_DIR, CURRENT_DIR, REFUSED_PROFILE,
# UNINSTALL_MODE) are read by the scripts that source this file.
# shellcheck disable=SC2034
#
# Every expectation here is read from the release under test — its archive,
# or the installer's own source — rather than from a list kept in this file.
# Releases differ: older ones predate the versioned layout, carry binaries
# later releases dropped, and put their entitlement profiles somewhere the
# current installer does not look.

REPO="${COMPAT_REPO:-tinylabscom/mvm}"
DOWNLOAD_BASE="${MVM_UPDATE_DOWNLOAD_URL:-https://github.com}"
COMPAT_DIR="$(cd "$(dirname "$0")" && pwd -P)"

say() { printf '[compat] %s\n' "$*"; }
fail() {
  printf '[compat] FAIL: %s\n' "$*" >&2
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    printf '::error::%s\n' "$*"
  fi
  exit 1
}

# Append a line to the job summary when there is one.
summary() {
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY"
  fi
}

# A fresh directory with every link in its path resolved. install.sh records
# physical paths in its links, and macOS's temporary directory sits behind
# /var -> /private/var, so comparing against the unresolved path would fail.
physical_tmpdir() {
  created="$(mktemp -d "${TMPDIR:-/tmp}/mvm-compat.XXXXXX")"
  (cd "$created" && pwd -P)
}

# The version string `mvmctl --version` prints for a release tag.
expected_version() {
  printf 'mvmctl %s\n' "${1#v}"
}

# The newest stable CLI release publishing the archive for target $1, read
# from the releases API — the release install.sh installs when nothing is
# pinned. Deliberately a second reader rather than install.sh's own, so a
# fault in the installer's selection shows up as a mismatch instead of
# agreeing with itself. Prints nothing when no release qualifies.
newest_stable_release() {
  newest_list="$(curl -fsSL --retry 3 --retry-delay 2 \
    "${MVM_UPDATE_API_URL:-https://api.github.com}/repos/$REPO/releases?per_page=100")" \
    || return 1
  printf '%s\n' "$newest_list" | jq -r --arg archive "mvmctl-$1.tar.gz" '
        [ .[]
          | select(.tag_name | test("^v[0-9]+\\.[0-9]+\\.[0-9]+$"))
          | select((.draft | not) and (.prerelease | not))
          | select(any(.assets[]?; .name == $archive))
          | .tag_name ]
        | sort_by(ltrimstr("v") | split(".") | map(tonumber))
        | last // empty'
}

# Download the archive a release publishes for a target.
fetch_archive() {
  fetch_tag="$1"
  fetch_target="$2"
  fetch_dest="$3"
  curl -fsSL --retry 3 --retry-delay 2 -o "$fetch_dest" \
    "$DOWNLOAD_BASE/$REPO/releases/download/$fetch_tag/mvmctl-$fetch_target.tar.gz" \
    || fail "could not download mvmctl-$fetch_target.tar.gz for $fetch_tag"
}

# Lines of `archive-facts.sh` output with the given kind, values only.
facts_of() {
  printf '%s\n' "$1" | sed -n "s/^$2 //p"
}

# Whether a whitespace-delimited list contains one exact word. Compatibility
# baselines use release tags, so a prefix or prerelease-neighbour must not
# inherit another tag's exception.
word_list_contains() {
  case " $1 " in
    *" $2 "*) return 0 ;;
    *) return 1 ;;
  esac
}

# A prefix laid out the way a user's would be: an install dir already holding
# files that are not mvm's, which every install and uninstall must leave alone.
make_prefix() {
  PREFIX_ROOT="$(physical_tmpdir)"
  PREFIX_HOME="$PREFIX_ROOT/home"
  PREFIX_BIN="$PREFIX_ROOT/prefix/bin"
  PREFIX_LIB="$PREFIX_ROOT/prefix/lib/mvm"
  mkdir -p "$PREFIX_HOME" "$PREFIX_BIN"
  printf 'not mvm\n' > "$PREFIX_BIN/notes.txt"
  printf '#!/bin/sh\necho unrelated\n' > "$PREFIX_BIN/unrelated-tool"
  chmod 0755 "$PREFIX_BIN/unrelated-tool"
  UNRELATED_LISTING="$(printf 'notes.txt\nunrelated-tool')"
}

# Run a command with the prefix's HOME and state directory, so nothing the
# release does can reach the runner's own.
in_prefix() {
  env HOME="$PREFIX_HOME" MVM_HOME="$PREFIX_HOME/.mvm" "$@"
}

# Install a release into the prefix. Only MVM_INSTALL_DIR is set, so the
# library directory comes from the installer's own default — the same default
# uninstall.sh has to derive independently.
run_install() {
  install_tag="$1"
  install_log="$2"
  set +e
  in_prefix MVM_INSTALL_DIR="$PREFIX_BIN" MVM_VERSION="$install_tag" \
    MVM_SKIP_BOOTSTRAP=1 MVM_UPDATE_DOWNLOAD_URL="$DOWNLOAD_BASE" \
    sh "$INSTALLER" </dev/null >"$install_log" 2>&1
  install_status=$?
  set -e
  return "$install_status"
}

# The entitlement profile an install refused over, when that was the reason.
refused_profile() {
  sed -n 's/.*missing entitlement profile: .*\/\([^/]*\)$/\1/p' "$1" | head -n1
}

# Whether a failed install is the one refusal an old release is allowed: the
# current installer requires an entitlement profile the release's own archive
# does not carry. A refusal naming a profile the archive *does* carry is a bug
# in the installer, not an old layout.
is_tolerated_refusal() {
  tolerated_log="$1"
  tolerated_facts="$2"
  tolerated_profile="$(refused_profile "$tolerated_log")"
  [ -n "$tolerated_profile" ] || return 1
  if facts_of "$tolerated_facts" profile | grep -Fxq "$tolerated_profile"; then
    return 1
  fi
  REFUSED_PROFILE="$tolerated_profile"
  return 0
}

# The directory `current` points at, which must be a complete release
# directory named for the tag.
assert_current_is() {
  current_tag="$1"
  [ -L "$PREFIX_LIB/current" ] || fail "$PREFIX_LIB/current is not a link after installing $current_tag"
  CURRENT_DIR="$(readlink "$PREFIX_LIB/current")"
  case "$CURRENT_DIR" in
    "$PREFIX_LIB"/[1-9]*-"$current_tag") ;;
    *) fail "current -> $CURRENT_DIR, expected a release directory for $current_tag under $PREFIX_LIB" ;;
  esac
  [ "$(cat "$CURRENT_DIR/.mvm-release" 2>/dev/null)" = "complete" ] \
    || fail "$CURRENT_DIR is not marked complete"
}

# The installed command reports the release.
assert_version() {
  version_tag="$1"
  want="$(expected_version "$version_tag")"
  got="$(in_prefix "$PREFIX_BIN/mvmctl" --version 2>&1)" \
    || fail "$PREFIX_BIN/mvmctl --version failed for $version_tag: $got"
  [ "$got" = "$want" ] || fail "$PREFIX_BIN/mvmctl --version printed '$got', expected '$want'"
}

# Every entry the archive carries is on PATH through `current`, and every
# payload the installer excludes is nowhere.
assert_entries_linked() {
  linked_facts="$1"
  for name in $(facts_of "$linked_facts" entry); do
    link="$PREFIX_BIN/$name"
    [ -L "$link" ] || fail "$link is missing or not a link"
    [ "$(readlink "$link")" = "$PREFIX_LIB/current/$name" ] \
      || fail "$link -> $(readlink "$link"), expected $PREFIX_LIB/current/$name"
    if [ "$name" = "assets" ]; then
      [ -d "$PREFIX_LIB/current/assets" ] || fail "$PREFIX_LIB/current/assets is not a directory"
    else
      if [ ! -f "$PREFIX_LIB/current/$name" ] || [ ! -x "$PREFIX_LIB/current/$name" ]; then
        fail "$PREFIX_LIB/current/$name is not an executable file"
      fi
    fi
  done
  for name in $(facts_of "$linked_facts" excluded); do
    if [ -e "$PREFIX_BIN/$name" ] || [ -L "$PREFIX_BIN/$name" ] || [ -e "$PREFIX_LIB/current/$name" ]; then
      fail "$name is excluded by the installer but was installed"
    fi
  done
}

# macOS: the binaries that launch a VM carry the keys their profile grants.
assert_signed() {
  [ "$(uname -s)" = "Darwin" ] || return 0
  for pair in mvmctl:mvmctl.entitlements mvm-hvf-supervisor:mvm-supervisor.entitlements; do
    binary="$PREFIX_LIB/current/${pair%%:*}"
    profile="$PREFIX_LIB/current/assets/${pair#*:}"
    [ -f "$binary" ] || continue
    [ -f "$profile" ] || fail "$profile is missing beside $binary"
    signed="$(codesign -d --entitlements - "$binary" 2>&1)" \
      || fail "codesign could not read $binary: $signed"
    sed -n 's:.*<key>\(.*\)</key>.*:\1:p' "$profile" > "$PREFIX_ROOT/profile-keys"
    while IFS= read -r key; do
      printf '%s' "$signed" | grep -Fq "$key" \
        || fail "$binary is not signed with $key from ${pair#*:}"
    done < "$PREFIX_ROOT/profile-keys"
  done
}

# `doctor` runs to completion. It exits 1 when it finds host problems, which
# a hosted runner has (no KVM on macOS, no builder backend); anything else —
# a panic's 101, a signal — is a broken binary.
assert_doctor_runs() {
  doctor_log="$1"
  set +e
  in_prefix "$PREFIX_BIN/mvmctl" doctor </dev/null >"$doctor_log" 2>&1
  doctor_status=$?
  set -e
  case "$doctor_status" in
    0|1) say "doctor exited $doctor_status" ;;
    *)
      cat "$doctor_log" >&2
      fail "mvmctl doctor exited $doctor_status"
      ;;
  esac
}

# Uninstall with a state directory present, as a user's would be. A release
# older than the pre-uninstall check cannot confirm no machine is running, so
# uninstall.sh must refuse and change nothing; --force then removes it.
run_uninstall() {
  uninstall_tag="$1"
  uninstall_log="$2"
  mkdir -p "$PREFIX_HOME/.mvm"
  set +e
  in_prefix MVM_INSTALL_DIR="$PREFIX_BIN" sh "$UNINSTALLER" </dev/null >"$uninstall_log" 2>&1
  uninstall_status=$?
  set -e
  UNINSTALL_MODE="checked"
  if [ "$uninstall_status" -ne 0 ]; then
    if ! grep -q "predates the pre-uninstall check" "$uninstall_log"; then
      cat "$uninstall_log" >&2
      fail "uninstall.sh failed for $uninstall_tag (exit $uninstall_status)"
    fi
    assert_version "$uninstall_tag"
    [ -L "$PREFIX_LIB/current" ] || fail "uninstall.sh refused but still removed $PREFIX_LIB/current"
    set +e
    in_prefix MVM_INSTALL_DIR="$PREFIX_BIN" sh "$UNINSTALLER" --force </dev/null >>"$uninstall_log" 2>&1
    uninstall_status=$?
    set -e
    if [ "$uninstall_status" -ne 0 ]; then
      cat "$uninstall_log" >&2
      fail "uninstall.sh --force failed for $uninstall_tag (exit $uninstall_status)"
    fi
    UNINSTALL_MODE="refused, then --force"
  fi
}

# Only the unrelated files are left, byte for byte, and the state directory
# was kept because --purge was not passed.
assert_uninstalled() {
  listing="$(ls -A "$PREFIX_BIN")"
  [ "$listing" = "$UNRELATED_LISTING" ] \
    || fail "install dir after uninstall holds: $(printf '%s' "$listing" | tr '\n' ' ')"
  [ "$(cat "$PREFIX_BIN/notes.txt")" = "not mvm" ] || fail "uninstall changed an unrelated file"
  # shellcheck disable=SC2012 # the listing is only printed
  [ ! -e "$PREFIX_LIB" ] || fail "$PREFIX_LIB still exists after uninstall: $(ls -A "$PREFIX_LIB" | tr '\n' ' ')"
  [ -d "$PREFIX_HOME/.mvm" ] || fail "uninstall removed the state directory without --purge"
}

# A refused install left the prefix exactly as it found it.
assert_untouched() {
  listing="$(ls -A "$PREFIX_BIN")"
  [ "$listing" = "$UNRELATED_LISTING" ] \
    || fail "a refused install left entries behind: $(printf '%s' "$listing" | tr '\n' ' ')"
  [ ! -e "$PREFIX_LIB" ] || fail "a refused first install left $PREFIX_LIB behind"
}
