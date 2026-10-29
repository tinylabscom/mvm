#!/usr/bin/env bash
# Prove a source checkout can build its own builder image from nothing.
#
# The documented-surface release lane fetches the pinned, signed builder image,
# because its scenarios exercise the CLI rather than the image. That leaves the
# cold source path — Stage 0 building the builder image from an mvm-images
# checkout, and an unembedded `mvmctl` handing the whole build to its embedded
# helper — with no witness of its own. This is that witness, and nothing else:
#
#   1. build an unembedded and an embedded `mvmctl`;
#   2. pack the SDK sidecars through the unembedded one, against a cold home:
#      the guest runtime compiles on the host and no builder VM starts;
#   3. bootstrap the builder image from source through the unembedded one: it
#      owns no payload, so Stage 0 and the builder image are handed to the
#      helper payload it produces from this checkout. The runtime overlay and
#      the initramfs are assembled on the host from the guest runtime step 2
#      compiled, never pair-built through the image checkout or installed
#      from the image set;
#   4. build a user flake through the embedded one, on the builder image step 3
#      produced.
#
# The image checkout supplies the Linux layer only — here, the builder image's
# recipe. The guest runtime is this tree's and ships with `mvmctl`.
#
# Every step is fatal. Unlike the release lane, there is no other result here
# worth salvaging from a run whose bootstrap failed.
#
# Usage:
#   MVM_E2E_HOME=/tmp/source-bootstrap MVM_IMAGES_DIR=/path/to/mvm-images \
#     scripts/e2e-source-bootstrap.sh
#
# The home must be empty or absent: a warm cache would let a broken source
# bootstrap pass on the strength of an image an earlier run produced.
#
# The builder image's recipe lives in tinylabscom/mvm-images. Name a checkout
# with MVM_IMAGES_DIR, or keep one beside this checkout; without either there is
# nothing to build it from, and the witness says so before compiling anything.

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
# A local builder-image build is opt-in, and `build` without the opt-in is
# refused rather than answered with the published image. Building it locally
# is the one thing this witness exists to prove.
export MVM_ALLOW_LOCAL_BUILDER_BUILD=1
# Every guest piece bootstrap prepares comes from this checkout's guest
# runtime. Launch acquisition otherwise defaults to the image set's members,
# and this witness would then boot guest bytes some other commit built.
export MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build

if [[ -d "$HOME_DIR" ]] && [[ -n "$(ls -A "$HOME_DIR" 2>/dev/null)" ]]; then
  echo "!!! $HOME_DIR is not empty; a cold source bootstrap needs a cold home" >&2
  exit 2
fi
IMAGES_DIR="${MVM_IMAGES_DIR:-$REPO/../mvm-images}"
if [[ ! -d "$IMAGES_DIR" ]]; then
  echo "!!! no mvm-images checkout at $IMAGES_DIR; the builder image is built from" >&2
  echo "!!! its recipes. Set MVM_IMAGES_DIR to a tinylabscom/mvm-images checkout." >&2
  exit 2
fi
export MVM_IMAGES_DIR="$IMAGES_DIR"

mkdir -p "$HOME_DIR"
chmod 700 "$HOME_DIR"
export MVM_HOME="$HOME_DIR"

trap 'e2e_phase_summary "Source bootstrap phase timings ($(uname -s))"' EXIT
trap 'echo; echo "!!! interrupted"; exit 130' INT TERM

echo "==> cold source bootstrap"
echo "    repo:  $REPO"
echo "    home:  $HOME_DIR"
echo "    images: $IMAGES_DIR"
echo "    flake: $FLAKE"

e2e_phase build
just payload::refresh
cargo build --bin mvmctl --features "$FEATURES"
cp "$MVMCTL" "$UNEMBEDDED_MVMCTL"
cargo build --bin mvmctl --features "$FEATURES,embed-host-bins"
just payload::supervisors

# Against a cold home, the unembedded command packs both sidecar variants from
# a guest runtime it compiles on the host. It needs neither the image checkout
# nor a builder VM, so Stage 0 is first reached by the bootstrap below.
e2e_phase sdk-sidecar
"$UNEMBEDDED_MVMCTL" dev sdk-sidecar build

# Stage 0 is first reached here, by the binary that carries no payload. That
# is the handoff step 2 no longer exercises now that sidecars pack on the host.
e2e_phase builder-image
"$UNEMBEDDED_MVMCTL" bootstrap

e2e_phase flake-build
"$MVMCTL" machine build --flake "$FLAKE"

e2e_phase_end
echo "==> cold source bootstrap passed"
