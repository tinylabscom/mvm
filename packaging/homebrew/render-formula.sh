#!/bin/sh
# Render mvmctl.rb from the template + a checksums-sha256.txt file.
# Usage: render-formula.sh <version-no-v> <checksums-file> <out.rb>
set -eu
VERSION="$1"; CHECKSUMS="$2"; OUT="$3"
HERE="$(cd "$(dirname "$0")" && pwd)"

sha_for() { grep " $1\$" "$CHECKSUMS" | awk '{print $1}' | head -n1; }

A_DARWIN="$(sha_for mvmctl-aarch64-apple-darwin.tar.gz)"
X_DARWIN="$(sha_for mvmctl-x86_64-apple-darwin.tar.gz)"
A_LINUX="$(sha_for mvmctl-aarch64-unknown-linux-gnu.tar.gz)"
X_LINUX="$(sha_for mvmctl-x86_64-unknown-linux-gnu.tar.gz)"

for v in "$A_DARWIN" "$X_DARWIN" "$A_LINUX" "$X_LINUX"; do
  [ -n "$v" ] || { echo "missing a checksum in $CHECKSUMS" >&2; exit 1; }
done

sed \
  -e "s/@@VERSION@@/$VERSION/g" \
  -e "s/@@SHA_AARCH64_DARWIN@@/$A_DARWIN/g" \
  -e "s/@@SHA_X86_64_DARWIN@@/$X_DARWIN/g" \
  -e "s/@@SHA_AARCH64_LINUX@@/$A_LINUX/g" \
  -e "s/@@SHA_X86_64_LINUX@@/$X_LINUX/g" \
  "$HERE/mvmctl.rb.tmpl" > "$OUT"
