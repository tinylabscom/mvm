#!/bin/sh
# What a release archive obliges an install to produce, read from the archive
# itself and from the installer that will install it.
#
#   archive-facts.sh <archive.tar.gz> <target-triple> <install.sh>
#
# Prints one fact per line:
#
#   entry <name>     a top-level executable, or the assets directory — each must
#                    land on PATH
#   excluded <name>  a top-level executable the installer deliberately leaves out
#                    (its EXCLUDED_PAYLOADS), which must land nowhere
#   profile <name>   an entitlement profile the archive carries under assets/
#
# The excluded set is read out of install.sh rather than repeated here, so the
# lane follows the installer's policy instead of a copy of it.
set -eu

[ "$#" -eq 3 ] || { echo "usage: $0 <archive.tar.gz> <target-triple> <install.sh>" >&2; exit 2; }
archive="$1"
target="$2"
installer="$3"

excluded="$(sed -n 's/^EXCLUDED_PAYLOADS="\(.*\)"$/\1/p' "$installer")"
if ! grep -q '^EXCLUDED_PAYLOADS=' "$installer"; then
  echo "$installer defines no EXCLUDED_PAYLOADS; the lane cannot tell which payloads it skips" >&2
  exit 1
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/mvm-facts.XXXXXX")"
trap 'rm -rf "$work"' EXIT
tar xzf "$archive" -C "$work"
root="$work/mvmctl-$target"
if [ ! -f "$root/mvmctl" ]; then
  echo "$archive has no mvmctl-$target/mvmctl" >&2
  exit 1
fi

for path in "$root"/*; do
  [ -e "$path" ] || continue
  name="${path##*/}"
  if [ -f "$path" ] && [ -x "$path" ]; then
    case " $excluded " in
      *" $name "*) printf 'excluded %s\n' "$name" ;;
      *) printf 'entry %s\n' "$name" ;;
    esac
  elif [ "$name" = "assets" ] && [ -d "$path" ]; then
    printf 'entry assets\n'
  fi
done | sort

if [ -d "$root/assets" ]; then
  for profile in "$root"/assets/*.entitlements; do
    [ -f "$profile" ] || continue
    printf 'profile %s\n' "${profile##*/}"
  done | sort
fi
