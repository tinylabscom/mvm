#!/usr/bin/env bash
# Run every documented example against a real host, booting real microVMs.
#
# The hermetic lane proves a documented command parses. That cannot see a verb
# which parses and then refuses at runtime, which is what `machine forward` had
# become while `examples/obscura/README.md` still told a reader to run it. This
# runner is the lane that executes them.
#
# Usage:
#   scripts/e2e-documented-surface.sh            # against ~/.mvm (warm, the real one)
#   MVM_E2E_HOME=/tmp/e2e scripts/e2e-documented-surface.sh
#
# Artifacts are acquired once into the chosen home and the scenarios then share
# it. A cold home pays a multi-minute bootstrap on the first run, and is fast
# afterwards.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO="$PWD"

E2E_HOME="${MVM_E2E_HOME:-$HOME/.mvm}"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
MVMCTL="$TARGET_DIR/debug/mvmctl"

echo "==> e2e documented surface"
echo "    repo: $REPO"
echo "    home: $E2E_HOME"

# ---------------------------------------------------------------------------
# 1. Build what the suite drives.
#
# The conformance runner refuses to start against an `mvmctl` older than its own
# sources, so this has to happen before the test binary runs, not alongside it.
# ---------------------------------------------------------------------------
echo "==> building mvmctl"
./scripts/cargo-fast.sh build --bin mvmctl

# The TypeScript SDK scenarios import the SDK's built `dist/`, which is absent
# in a fresh worktree. Without it they fail for a reason that has nothing to do
# with the documentation.
if [[ ! -f crates/mvm-sdk/sdks/typescript/dist/index.js ]]; then
  echo "==> building the TypeScript SDK (dist/ is absent)"
  just sdk-install-typescript
  just sdk-build-typescript
fi

# ---------------------------------------------------------------------------
# 2. Warm the shared artifact home.
#
# Every launch needs the workload kernel, the runtime overlay and the universal
# initramfs. Acquiring them inside a scenario would put minutes on each one, and
# a scenario that times out reads as a launch failure rather than a cold cache.
# ---------------------------------------------------------------------------
# This suite verifies the documented CLI surface, not the builder VM image.
# A source checkout otherwise rebuilds that image from the in-repo flake on
# every cold run, which couples the whole suite to an unrelated Nix build —
# and when that build cannot reach crates.io from inside Stage 0, nothing here
# runs at all. Fetch the published image instead. A contributor working *on*
# the image sets MVM_BOOT_IMAGE themselves and this defers to them.
export MVM_BOOT_IMAGE="${MVM_BOOT_IMAGE:-fetch}"
echo "    boot image: $MVM_BOOT_IMAGE"

# Bootstrap failure is reported, not fatal. It warms the builder VM image, which
# the flake-build scenarios need and the OCI-image ones do not — so aborting here
# would throw away every result that does not depend on it. The scenarios that do
# need it then fail on their own, naming themselves.
echo "==> warming artifacts in $E2E_HOME"
if ! MVM_HOME="$E2E_HOME" "$MVMCTL" bootstrap; then
  echo
  echo "!!! bootstrap FAILED — the builder VM image is unavailable."
  echo "!!! Flake-build scenarios will fail; OCI-image scenarios are unaffected."
  echo "!!! Continuing so the run still reports what it can prove."
  echo
  BOOTSTRAP_FAILED=1
fi

echo "==> host posture"
# `doctor` exits nonzero precisely when it has something to report, so its
# status is information rather than a gate.
MVM_HOME="$E2E_HOME" "$MVMCTL" doctor || true

# ---------------------------------------------------------------------------
# 3. The documented surface, live.
#
# `MVM_BDD_LIVE=1` opts into the scenarios that boot a real microVM. No
# `MVM_BDD_CI_LIVE_ONLY` here: that selector narrows to the merge-queue subset,
# and narrowing is what let the macOS default backend go uncovered.
# ---------------------------------------------------------------------------
echo "==> documented examples + machine journey (cucumber, @live)"
CARGO_BIN_EXE_mvmctl="$MVMCTL" \
MVM_BDD_LIVE=1 \
MVM_E2E_HOME="$E2E_HOME" \
  ./scripts/cargo-fast.sh test -p mvm-conformance --test conformance --features bdd

echo
echo "==> done. Read the 'did NOT run' tally above, not just the pass count:"
echo "    a skipped @live scenario is a documented command nothing booted."
if [[ -n "${BOOTSTRAP_FAILED:-}" ]]; then
  echo
  echo "!!! REMINDER: bootstrap failed this run. Any flake-build failure above"
  echo "!!! is that, not a regression in the command under test."
fi
