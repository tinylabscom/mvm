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
#   excluded <name>  a top-level executable the installer deliberately leaves
#                    out (the component table's unselected rows, or the legacy
#                    exclusion list for archives predating components.tsv),
#                    which must land nowhere
#   profile <name>   an entitlement profile the archive carries under assets/
#                    or the legacy resources/ location
#
# The excluded set follows the archive's own components.tsv (with the archive's
# mvmctl answering `backend detect --plain`) or the installer's legacy list,
# so the lane follows the installer's policy instead of a copy of it.
set -eu

[ "$#" -eq 3 ] || { echo "usage: $0 <archive.tar.gz> <target-triple> <install.sh>" >&2; exit 2; }
archive="$1"
target="$2"
installer="$3"

work="$(mktemp -d "${TMPDIR:-/tmp}/mvm-facts.XXXXXX")"
trap 'rm -rf "$work"' EXIT
tar xzf "$archive" -C "$work"
root="$work/mvmctl-$target"
if [ ! -f "$root/mvmctl" ]; then
  echo "$archive has no mvmctl-$target/mvmctl" >&2
  exit 1
fi

# The set the installer deliberately leaves out. An archive carrying
# components.tsv stages only the detected backend's components, so every other
# backend's bin: entries on this target are excluded; ask the archive's own
# mvmctl for the detection answer. An older archive is governed by the
# installer's LEGACY_LIBKRUN_TIER_PAYLOADS list, read by name so the lane
# follows the installer's policy instead of a copy of it.
if [ -f "$root/components.tsv" ]; then
  if ! detected="$("$root/mvmctl" backend detect --plain 2>/dev/null)" || [ -z "$detected" ]; then
    echo "$root/mvmctl cannot answer backend detect --plain on this host" >&2
    exit 1
  fi
  excluded="$(awk -F'\t' -v target="$target" -v keep="$detected" '
    /^#/ || NF == 0 { next }
    $2 != target { next }
    $1 == keep { next }
    $8 == "-" { next }
    {
      n = split($8, entries, " ")
      for (i = 1; i <= n; i++) {
        split(entries[i], kv, ":")
        if (kv[1] == "bin") print kv[2]
      }
    }
  ' "$root/components.tsv")"
else
  excluded="$(sed -n 's/^LEGACY_LIBKRUN_TIER_PAYLOADS="\(.*\)"$/\1/p' "$installer")"
  if ! grep -q '^LEGACY_LIBKRUN_TIER_PAYLOADS=' "$installer"; then
    echo "$installer defines no LEGACY_LIBKRUN_TIER_PAYLOADS; the lane cannot tell which payloads it skips" >&2
    exit 1
  fi
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

for profile_dir in "$root/assets" "$root/resources"; do
  [ -d "$profile_dir" ] || continue
  for profile in "$profile_dir"/*.entitlements; do
    [ -f "$profile" ] || continue
    printf 'profile %s\n' "${profile##*/}"
  done
done | sort -u
