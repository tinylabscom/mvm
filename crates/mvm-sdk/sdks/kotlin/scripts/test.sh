#!/usr/bin/env bash
# Compile the Kotlin pack SDK and its suite with kotlinc and run it on the JVM.
# Needs only a JDK and the Kotlin compiler; no build tool or dependency fetch.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
goldens="$here/../../../mvm-contract/tests/fixtures/pack-spec-v1/canonical"
if ! command -v kotlinc >/dev/null 2>&1; then
  echo "kotlinc not found: install the Kotlin compiler (the version in $here/.kotlin-version)" >&2
  exit 1
fi
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
kotlinc -nowarn "$here/src/main/kotlin" "$here/src/test/kotlin" -include-runtime -d "$out/packs-test.jar"
java -cp "$out/packs-test.jar" com.runmvm.packs.PackSpecTestKt "$goldens"
