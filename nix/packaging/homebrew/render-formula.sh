#!/bin/sh
# Render mvmctl.rb from the template + a checksums-sha256.txt file.
# Usage: render-formula.sh <version-no-v> <checksums-file> <out.rb>
set -eu
[ "$#" -eq 3 ] || { echo "usage: render-formula.sh VERSION CHECKSUMS OUT" >&2; exit 1; }
VERSION="$1"; CHECKSUMS="$2"; OUT="$3"
HERE="$(cd "$(dirname "$0")" && pwd)"

case "$VERSION" in
  *[!0-9.]*) echo "expected a stable CLI version" >&2; exit 1 ;;
esac
printf '%s\n' "$VERSION" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' ||
  { echo "expected a stable CLI version" >&2; exit 1; }

# The caller authenticates this manifest before rendering. Reject ambiguous or
# malformed records rather than silently choosing the first duplicate.
sha_for() {
  awk -v name="$1" '
    $2 == name {
      count++
      if (NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-f]/) bad=1
      digest=$1
    }
    END {
      if (count != 1 || bad) exit 1
      print digest
    }
  ' "$CHECKSUMS"
}

# x86_64-apple-darwin (Intel mac) is deferred — no asset / checksum for it.
A_DARWIN="$(sha_for mvmctl-aarch64-apple-darwin.tar.gz)"
A_LINUX="$(sha_for mvmctl-aarch64-unknown-linux-gnu.tar.gz)"
X_LINUX="$(sha_for mvmctl-x86_64-unknown-linux-gnu.tar.gz)"

for v in "$A_DARWIN" "$A_LINUX" "$X_LINUX"; do
  [ -n "$v" ] || { echo "missing a checksum in $CHECKSUMS" >&2; exit 1; }
done

sed \
  -e "s/@@VERSION@@/$VERSION/g" \
  -e "s/@@SHA_AARCH64_DARWIN@@/$A_DARWIN/g" \
  -e "s/@@SHA_AARCH64_LINUX@@/$A_LINUX/g" \
  -e "s/@@SHA_X86_64_LINUX@@/$X_LINUX/g" \
  "$HERE/mvmctl.rb.tmpl" > "$OUT"
