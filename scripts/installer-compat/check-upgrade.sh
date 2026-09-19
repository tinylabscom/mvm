#!/bin/sh
# Walk one prefix through a series of published releases with the current
# installer, oldest to newest, then roll back to the previous one and
# uninstall.
#
#   check-upgrade.sh <target-triple> "<tags oldest..newest>" "<tolerated tags>"
#
# Env: INSTALLER, UNINSTALLER, MVM_UPDATE_DOWNLOAD_URL as for check-release.sh.
#
# After each upgrade: the new release is current and reports itself, the
# release it replaced is still on disk, complete and runnable (the history a
# rollback needs), and any PATH entry the older release had and the newer one
# dropped is gone. A tolerated release the installer refuses must leave the
# previous install exactly as it was.
#
# The rollback is the supported one — re-running the installer pinned to the
# previous tag — and it must keep the newer release in the history too.
set -eu

[ "$#" -eq 3 ] || { echo "usage: $0 <target-triple> \"<tags oldest..newest>\" \"<tolerated tags>\"" >&2; exit 2; }
TARGET="$1"
TAGS="$2"
TOLERATED="$3"

# shellcheck disable=SC1091 # lib.sh is shellchecked on its own
. "$(dirname "$0")/lib.sh"
INSTALLER="${INSTALLER:-$COMPAT_DIR/../../install.sh}"
UNINSTALLER="${UNINSTALLER:-$COMPAT_DIR/../../uninstall.sh}"

make_prefix
logs="$PREFIX_ROOT/logs"
mkdir -p "$logs" "$PREFIX_ROOT/facts"

previous_tag=""
previous_dir=""
installed=""

for tag in $TAGS; do
  fetch_archive "$tag" "$TARGET" "$PREFIX_ROOT/$tag.tar.gz"
  sh "$COMPAT_DIR/archive-facts.sh" "$PREFIX_ROOT/$tag.tar.gz" "$TARGET" "$INSTALLER" \
    > "$PREFIX_ROOT/facts/$tag"
  facts="$(cat "$PREFIX_ROOT/facts/$tag")"

  if ! run_install "$tag" "$logs/install-$tag.log"; then
    case " $TOLERATED " in
      *" $tag "*) tolerated=1 ;;
      *) tolerated=0 ;;
    esac
    if [ "$tolerated" = "1" ] && is_tolerated_refusal "$logs/install-$tag.log" "$facts"; then
      if [ -n "$previous_tag" ]; then
        assert_current_is "$previous_tag"
        [ "$CURRENT_DIR" = "$previous_dir" ] || fail "a refused $tag install moved current off $previous_dir"
        assert_version "$previous_tag"
        assert_entries_linked "$(cat "$PREFIX_ROOT/facts/$previous_tag")"
      else
        assert_untouched
      fi
      say "$tag refused cleanly (no assets/$REFUSED_PROFILE); previous install intact"
      summary "| \`$TARGET\` | \`$tag\` | refused cleanly, previous install intact |"
      continue
    fi
    cat "$logs/install-$tag.log" >&2
    fail "install.sh failed upgrading ${previous_tag:-an empty prefix} to $tag on $TARGET"
  fi

  assert_current_is "$tag"
  assert_version "$tag"
  assert_entries_linked "$facts"
  assert_signed

  if [ -n "$previous_tag" ]; then
    [ "$CURRENT_DIR" != "$previous_dir" ] || fail "upgrading to $tag reused $previous_dir"
    [ "$(cat "$previous_dir/.mvm-release" 2>/dev/null)" = "complete" ] \
      || fail "upgrading to $tag did not keep $previous_dir as a complete release"
    kept="$(in_prefix "$previous_dir/mvmctl" --version 2>&1)" \
      || fail "the kept $previous_tag no longer runs: $kept"
    [ "$kept" = "$(expected_version "$previous_tag")" ] \
      || fail "the kept release directory for $previous_tag reports '$kept'"
    for name in $(facts_of "$(cat "$PREFIX_ROOT/facts/$previous_tag")" entry); do
      if ! facts_of "$facts" entry | grep -Fxq "$name"; then
        if [ -e "$PREFIX_BIN/$name" ] || [ -L "$PREFIX_BIN/$name" ]; then
          fail "$name was dropped by $tag but is still in the install dir"
        fi
      fi
    done
    say "upgraded $previous_tag -> $tag; $previous_dir kept"
    summary "| \`$TARGET\` | \`$previous_tag\` → \`$tag\` | swapped, previous release kept |"
  else
    say "installed $tag"
    summary "| \`$TARGET\` | \`$tag\` | installed |"
  fi
  installed="$installed $tag"
  previous_tag="$tag"
  previous_dir="$CURRENT_DIR"
done

# Tags are single words (install.sh refuses anything else), so splitting is the
# intent: the last two installed are the rollback target and the newest.
# shellcheck disable=SC2086
set -- $installed
[ "$#" -ge 2 ] || fail "fewer than two releases installed on $TARGET, so no upgrade was exercised"
while [ "$#" -gt 2 ]; do shift; done
rollback_tag="$1"
newest_dir="$previous_dir"

if ! run_install "$rollback_tag" "$logs/rollback.log"; then
  cat "$logs/rollback.log" >&2
  fail "rolling back to $rollback_tag failed"
fi
assert_current_is "$rollback_tag"
assert_version "$rollback_tag"
assert_entries_linked "$(cat "$PREFIX_ROOT/facts/$rollback_tag")"
[ "$(cat "$newest_dir/.mvm-release" 2>/dev/null)" = "complete" ] \
  || fail "rolling back to $rollback_tag did not keep $newest_dir"
say "rolled back to $rollback_tag; $newest_dir kept"
summary "| \`$TARGET\` | rollback → \`$rollback_tag\` | current switched back, newer release kept |"

run_uninstall "$rollback_tag" "$logs/uninstall.log"
assert_uninstalled
summary "| \`$TARGET\` | uninstall | $UNINSTALL_MODE; unrelated files kept |"
