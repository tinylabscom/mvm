#!/bin/sh
# Install one published release with the current installer, check what landed,
# then uninstall it with the current uninstaller.
#
#   check-release.sh <release-tag> <target-triple> <strict:true|false>
#
# Env: INSTALLER and UNINSTALLER (default: the checkout's scripts),
# MVM_UPDATE_DOWNLOAD_URL (default https://github.com).
#
# Everything happens under a fresh temporary prefix with its own HOME and state
# directory. The install dir starts out holding two unrelated files, and they
# have to survive both the install and the uninstall.
set -eu

[ "$#" -eq 3 ] || { echo "usage: $0 <release-tag> <target-triple> <strict:true|false>" >&2; exit 2; }
TAG="$1"
TARGET="$2"
STRICT="$3"

# shellcheck disable=SC1091 # lib.sh is shellchecked on its own
. "$(dirname "$0")/lib.sh"
INSTALLER="${INSTALLER:-$COMPAT_DIR/../../install.sh}"
UNINSTALLER="${UNINSTALLER:-$COMPAT_DIR/../../uninstall.sh}"

make_prefix
logs="$PREFIX_ROOT/logs"
mkdir -p "$logs"

fetch_archive "$TAG" "$TARGET" "$PREFIX_ROOT/archive.tar.gz"
facts="$(sh "$COMPAT_DIR/archive-facts.sh" "$PREFIX_ROOT/archive.tar.gz" "$TARGET" "$INSTALLER")"
say "$TAG ($TARGET) carries: $(facts_of "$facts" entry | tr '\n' ' ')"

if ! run_install "$TAG" "$logs/install.log"; then
  if is_tolerated_refusal "$logs/install.log" "$facts"; then
    if [ "$STRICT" = "true" ]; then
      cat "$logs/install.log" >&2
      fail "the installer cannot install $TAG on $TARGET: its archive has no assets/$REFUSED_PROFILE. $TAG is the installer's baked default or newer, so the documented one-liner hits this."
    fi
    assert_untouched
    say "$TAG refused cleanly: its archive predates assets/$REFUSED_PROFILE"
    summary "| \`$TAG\` | \`$TARGET\` | refused cleanly (archive has no \`assets/$REFUSED_PROFILE\`) | — |"
    exit 0
  fi
  cat "$logs/install.log" >&2
  fail "install.sh failed for $TAG on $TARGET"
fi

assert_current_is "$TAG"
assert_version "$TAG"
assert_entries_linked "$facts"
assert_signed
[ "$(cat "$PREFIX_BIN/notes.txt")" = "not mvm" ] || fail "install changed an unrelated file"
assert_doctor_runs "$logs/doctor.log"

run_uninstall "$TAG" "$logs/uninstall.log"
assert_uninstalled
say "$TAG installed, verified and uninstalled ($UNINSTALL_MODE)"
summary "| \`$TAG\` | \`$TARGET\` | installed: $(facts_of "$facts" entry | tr '\n' ' ') | $UNINSTALL_MODE |"
