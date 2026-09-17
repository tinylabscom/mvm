#!/usr/bin/env bash
# Prove a source checkout can build its own builder image from nothing.
#
# The documented-surface release lane fetches the pinned, signed builder image,
# because its scenarios exercise the CLI rather than the image. That leaves the
# cold source path — Stage 0 building the builder image from the in-tree flake,
# and an unembedded `mvmctl` handing the whole build to its embedded helper —
# with no witness of its own. This is that witness, and nothing else:
#
#   1. build an unembedded and an embedded `mvmctl`;
#   2. build the SDK sidecar through the unembedded one, against a cold home;
#   3. bootstrap the builder image from source;
#   4. build a user flake through the builder that step produced.
#
# Every step is fatal. Unlike the release lane, there is no other result here
# worth salvaging from a run whose bootstrap failed.
#
# Usage:
#   MVM_E2E_HOME=/tmp/source-bootstrap scripts/e2e-source-bootstrap.sh
#
# The home must be empty or absent: a warm cache would let a broken source
# bootstrap pass on the strength of an image an earlier run produced.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO="$PWD"
# shellcheck source=scripts/e2e-phase-timings.sh
source "$REPO/scripts/e2e-phase-timings.sh"

HOME_DIR="${MVM_E2E_HOME:?set MVM_E2E_HOME to an empty directory for the cold source bootstrap}"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
MVMCTL="$TARGET_DIR/debug/mvmctl"
UNEMBEDDED_MVMCTL="$TARGET_DIR/mvmctl-unembedded-source-bootstrap"
FEATURES="${MVM_E2E_FEATURES:-user,release-artifact-bootstrap}"
FLAKE="${MVM_E2E_SOURCE_FLAKE:-examples/exit_code}"

# A caller asking this witness to fetch has asked it to prove nothing.
if [[ -n "${MVM_BOOT_IMAGE:-}" && "${MVM_BOOT_IMAGE}" != "build" ]]; then
  echo "!!! MVM_BOOT_IMAGE=${MVM_BOOT_IMAGE}: the source bootstrap witness only runs with build" >&2
  exit 2
fi
export MVM_BOOT_IMAGE=build

if [[ -d "$HOME_DIR" ]] && [[ -n "$(ls -A "$HOME_DIR" 2>/dev/null)" ]]; then
  echo "!!! $HOME_DIR is not empty; a cold source bootstrap needs a cold home" >&2
  exit 2
fi
mkdir -p "$HOME_DIR"
chmod 700 "$HOME_DIR"
export MVM_HOME="$HOME_DIR"

trap 'e2e_phase_summary "Source bootstrap phase timings ($(uname -s))"' EXIT
trap 'echo; echo "!!! interrupted"; exit 130' INT TERM

echo "==> cold source bootstrap"
echo "    repo:  $REPO"
echo "    home:  $HOME_DIR"
echo "    flake: $FLAKE"

e2e_phase build
just embed-refresh
cargo build --bin mvmctl --features "$FEATURES"
cp "$MVMCTL" "$UNEMBEDDED_MVMCTL"
cargo build --bin mvmctl --features "$FEATURES,embed-host-bins"
just build-supervisors

# Against a cold home, the unembedded command owns no payload, so it must hand
# Stage 0, the builder image and both sidecar variants to its embedded helper.
e2e_phase sdk-sidecar
"$UNEMBEDDED_MVMCTL" build sdk-sidecar build

e2e_phase builder-image
"$MVMCTL" bootstrap

e2e_phase flake-build
"$MVMCTL" machine build --flake "$FLAKE"

e2e_phase_end
echo "==> cold source bootstrap passed"
