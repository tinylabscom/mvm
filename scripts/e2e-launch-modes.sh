#!/usr/bin/env bash
# End-to-end launch gate: boot a real guest through every README-documented
# entry point, on whatever backend this host actually has.
#
# The gap this closes: the only pre-existing live README scenario is
# `@firecracker`-tagged, so it is skipped on every host without `/dev/kvm`.
# On macOS — where HVF is the default backend — that meant nothing in the suite
# ever booted a guest, and a launch regression on the default backend had no
# lane that could see it. Everything here runs wherever `mvmctl` can boot.
#
# Usage:
#   scripts/e2e-launch-modes.sh              # against ~/.mvm (warm, the real one)
#   MVM_E2E_HOME=/tmp/e2e scripts/e2e-launch-modes.sh
#
# Artifacts are acquired once into the chosen home; the scenarios then share it.
# A cold home pays a multi-minute bootstrap on the first run and is fast after.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO="$PWD"

E2E_HOME="${MVM_E2E_HOME:-$HOME/.mvm}"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
MVMCTL="$TARGET_DIR/debug/mvmctl"

echo "==> e2e launch gate"
echo "    repo:  $REPO"
echo "    home:  $E2E_HOME"

# ---------------------------------------------------------------------------
# 1. Build the binaries the suite drives.
# ---------------------------------------------------------------------------
echo "==> building mvmctl + host helpers"
./scripts/cargo-fast.sh build --bin mvmctl
./scripts/cargo-fast.sh build -p xtask

# ---------------------------------------------------------------------------
# 2. Warm the shared artifact home.
#
# Every launch needs the workload kernel, the runtime overlay and the universal
# initramfs. Acquiring them inside a scenario would put minutes on each one, and
# a scenario that times out reads as a launch failure rather than a cold cache.
# ---------------------------------------------------------------------------
echo "==> warming artifacts in $E2E_HOME"
MVM_HOME="$E2E_HOME" "$MVMCTL" bootstrap

echo "==> host posture"
MVM_HOME="$E2E_HOME" "$MVMCTL" doctor || true

# ---------------------------------------------------------------------------
# 3. The CLI + SDK launch modes, as cucumber scenarios.
#
# `MVM_BDD_LIVE=1` opts into scenarios that boot a real microVM. No
# `MVM_BDD_CI_LIVE_ONLY` here: that selector narrows to the merge-queue subset,
# which is the narrowing that hid this class of failure.
# ---------------------------------------------------------------------------
echo "==> CLI + SDK launch modes (cucumber, @live)"
CARGO_BIN_EXE_mvmctl="$MVMCTL" \
MVM_BDD_LIVE=1 \
MVM_E2E_HOME="$E2E_HOME" \
  ./scripts/cargo-fast.sh test -p mvm-conformance --test conformance --features bdd

# ---------------------------------------------------------------------------
# 4. The Rust library seam.
#
# `MvmClient` + `LocalBackend` is the third README entry point, and driving it
# through a subprocess would prove nothing about linking the crate. The live
# lifecycle tests already cover it in-process; they are `#[ignore]`d behind
# kernel/rootfs env vars, which is why they had not been running. Resolve those
# from the home we just warmed and run them.
# ---------------------------------------------------------------------------
echo "==> Rust library seam (mvm-client, in-process)"
KERNEL="$(find "$E2E_HOME/cache/builder-vm" -name vmlinux -path '*workload*' 2>/dev/null | head -1 || true)"
ROOTFS="$(find "$E2E_HOME/cache/oci/rootfs" -name rootfs.ext4 2>/dev/null | head -1 || true)"

if [[ -n "$KERNEL" && -n "$ROOTFS" ]]; then
  echo "    kernel: $KERNEL"
  echo "    rootfs: $ROOTFS"
  MVM_E2E_KERNEL="$KERNEL" \
  MVM_E2E_ROOTFS="$ROOTFS" \
  MVM_HOME="$E2E_HOME" \
    ./scripts/cargo-fast.sh test -p mvm-client --test launch_lifecycle_live \
      --test launch_lifecycle_live_hvf -- --ignored
else
  # Loud, not silent: a skipped library seam is a coverage hole, and reporting
  # it as nothing is how the last one stayed open.
  echo "!!! SKIPPED the Rust library seam: no workload kernel and/or OCI rootfs" >&2
  echo "!!! under $E2E_HOME. Run a `machine run --image alpine` first." >&2
  exit 1
fi

# The harness prints a per-reason tally of what it declined to run, so a `@wip`
# scenario is counted and named rather than silently absent. Two are pending on
# the persistent-machine defect — see
# specs/plans/2026-08-26-persistent-machine-path-on-hvf.md.
echo "==> e2e launch gate: all modes exercised"
echo "    check the scenario summary above for anything reported pending"
