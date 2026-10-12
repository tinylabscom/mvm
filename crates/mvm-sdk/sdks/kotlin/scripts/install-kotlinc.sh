#!/usr/bin/env bash
# Install the pinned Kotlin compiler into $1 (default: $RUNNER_TEMP or /tmp)
# and print its bin directory. The archive is checked against a pinned SHA-256
# before it is unpacked.
set -euo pipefail
version="2.2.21"
sha256="a623871f1cd9c938946948b70ef9170879f0758043885bbd30c32f024e511714"
dest="${1:-${RUNNER_TEMP:-/tmp}}/kotlinc-$version"
if [ ! -x "$dest/kotlinc/bin/kotlinc" ]; then
  mkdir -p "$dest"
  zip="$dest/kotlin-compiler.zip"
  curl -fsSL --retry 3 -o "$zip" \
    "https://github.com/JetBrains/kotlin/releases/download/v$version/kotlin-compiler-$version.zip"
  echo "$sha256  $zip" | sha256sum -c - >&2
  unzip -q -o "$zip" -d "$dest"
  rm -f "$zip"
fi
echo "$dest/kotlinc/bin"
