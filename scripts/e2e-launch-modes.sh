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

# Floor on scenarios that must actually execute. See the assertion after the
# cucumber run for why a count, not just an exit status.
MIN_SCENARIOS=12
SCENARIO_LOG="$(mktemp -t mvm-e2e-scenarios)"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
MVMCTL="$TARGET_DIR/debug/mvmctl"

# Sweep this lane's guests too, on the way in and out. It boots the same kind of
# machine as `e2e-documented-surface.sh` and had no cleanup of its own, so a run
# killed at the wrong moment left a guest holding its name and the next run
# failed on a collision that reads as a broken verb. Scoped to the `bdd-` prefix
# every suite machine carries, so a machine you made by hand is never touched.
sweep() {
  [[ -x "$MVMCTL" ]] || return 0
  # Pass the home through explicitly: the cleaner defaults to ~/.mvm, which is
  # not necessarily the home this run is using.
  MVM_E2E_HOME="$E2E_HOME" ./scripts/e2e-documented-surface.sh --clean-only \
    >/dev/null 2>&1 || true
}
trap sweep EXIT
trap 'echo; echo "!!! interrupted — cleaning up"; exit 130' INT TERM

# Follow each guest's console as it boots. Cucumber only prints a step's output
# when the step fails, so without this a multi-minute boot shows nothing.
WATCHER_PID=""
if [[ "${MVM_E2E_FOLLOW:-$([[ -t 1 ]] && echo 1 || echo 0)}" == "1" ]]; then
  ./scripts/e2e-watch-vms.sh "$E2E_HOME" &
  WATCHER_PID=$!
  trap 'kill -TERM "$WATCHER_PID" 2>/dev/null || true; sweep' EXIT
fi

sweep   # clear anything a previous run left behind

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
#
# Budget honestly: on a source checkout with a cold `~/.mvm` this is not a warm
# up, it is a build. `bootstrap` compiles the per-VM supervisors and then runs a
# Nix build inside the builder VM, which is tens of minutes and silent for most
# of it. A change touching `mvm-agentd` also re-fingerprints the guest binaries,
# so the runtime overlay and initramfs rebuild on the next boot even when the
# cache was warm before. Subsequent runs against an unchanged tree are fast.
# ---------------------------------------------------------------------------
# macOS kills an unentitled Hypervisor.framework binary with SIGKILL, and the
# only symptom is "hvf supervisor exited before writing its PID file (status:
# signal: 9)" — which names neither the signature nor the rebuild that dropped
# it. `cargo build` re-links the per-VM supervisor whenever its dependency graph
# changes and does not re-sign it, so a build step must always be followed by
# this one or every HVF boot dies.
echo "==> signing VMM binaries"
"$MVMCTL" env sign

echo "==> warming artifacts in $E2E_HOME"
# A throwaway transient launch, not `bootstrap`.
#
# These scenarios boot OCI images. What they need warm is the workload kernel,
# the runtime overlay, the universal initramfs and an unpacked rootfs — exactly
# what one `machine run --image` acquires on first use. `bootstrap` additionally
# builds the Nix *builder VM* image, which no scenario here ever uses, so it made
# the gate depend on a heavyweight subsystem it does not exercise: a corrupt
# Stage 0 store ("persistent Stage 0 ext4 store reported N filesystem errors")
# failed the whole suite before a single scenario ran, for a reason unrelated to
# any launch mode.
MVM_HOME="$E2E_HOME" "$MVMCTL" machine run --image alpine -- true

echo "==> host posture"
MVM_HOME="$E2E_HOME" "$MVMCTL" doctor || true

# ---------------------------------------------------------------------------
# 3. The CLI + SDK launch modes, as cucumber scenarios.
#
# `MVM_BDD_LIVE=1` opts into scenarios that boot a real microVM. No
# `MVM_BDD_CI_LIVE_ONLY` here: that selector narrows to the merge-queue subset,
# which is the narrowing that hid this class of failure.
# ---------------------------------------------------------------------------
# Scoped to the launch suite with `-i`, deliberately. Unscoped, this ran the
# *entire* conformance suite under MVM_BDD_LIVE=1 — the doc-example checkers,
# the cross-language SDK surface comparison, the real Nix flake build. Those are
# `just bdd`'s job and they have their own prerequisites: this gate went red on
# a missing TypeScript toolchain and on a builder-VM Stage 0 store, neither of
# which is a launch mode. A gate that fails for things it does not test is one
# people stop believing, which is how the regression this suite exists for
# reached a release in the first place.
#
# The glob is ABSOLUTE. A `cargo test` binary runs with its *package* directory
# as cwd, not the workspace root, so a repo-relative glob matched nothing here —
# and cucumber reports "0 features / 0 scenarios" and exits 0. That is a green
# gate that ran nothing, which is worse than a red one: it is the precise shape
# of the failure this whole suite exists to prevent. Hence the floor below.
echo "==> CLI + SDK launch modes (cucumber, @live)"
CARGO_BIN_EXE_mvmctl="$MVMCTL" \
MVM_BDD_LIVE=1 \
MVM_E2E_HOME="$E2E_HOME" \
  ./scripts/cargo-fast.sh test -p mvm-conformance --test conformance --features bdd \
  -- -i "$REPO/features/suites/s31_launch_e2e/*.feature" -c 1 \
  2>&1 | tee "$SCENARIO_LOG"

# Exit status alone cannot tell "everything passed" from "nothing ran". Assert a
# floor on the count actually executed. Update it when scenarios are added; a
# hard number is the point — a `-gt 0` check would pass on one scenario after a
# filter silently dropped the rest.
ran="$(sed -nE 's/^([0-9]+) scenarios? \(.*/\1/p' "$SCENARIO_LOG" | tail -1)"
ran="${ran:-0}"
if (( ran < MIN_SCENARIOS )); then
  echo "!!! only $ran launch scenario(s) ran, expected at least $MIN_SCENARIOS." >&2
  echo "!!! A gate that runs nothing and exits 0 is the failure this suite exists" >&2
  echo "!!! to catch. Check the -i glob resolves from this script's cwd." >&2
  exit 1
fi
echo "    $ran launch scenario(s) executed"

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

# The supervisor is not in `target/<profile>/`. mvmctl's build script puts it in
# a nested aux-helper target dir, and `aux_bin::resolve` finds it from the
# *mvmctl* exe's neighbourhood — which a `cargo test -p mvm-client` binary is
# not in. Without this the seam fails with "mvm-hvf-supervisor not found",
# which reads as a missing build rather than a lookup that cannot reach it.
#
# Absolute, and scoped to the debug profile: the test binaries are debug, and a
# release supervisor here fails as "not a file" once the test's own working
# directory differs from this script's.
SUPERVISOR="$(cd "$REPO" && find "$TARGET_DIR/debug" -type f -name mvm-hvf-supervisor \
  -path '*aux-helper-target*' 2>/dev/null | head -1 || true)"
[[ -n "$SUPERVISOR" ]] && SUPERVISOR="$REPO/$SUPERVISOR"

if [[ -n "$KERNEL" && -n "$ROOTFS" && -n "$SUPERVISOR" ]]; then
  echo "    kernel:     $KERNEL"
  echo "    rootfs:     $ROOTFS"
  echo "    supervisor: $SUPERVISOR"
  MVM_E2E_KERNEL="$KERNEL" \
  MVM_E2E_ROOTFS="$ROOTFS" \
  MVM_HVF_SUPERVISOR_PATH="$SUPERVISOR" \
  MVM_HOME="$E2E_HOME" \
    ./scripts/cargo-fast.sh test -p mvm-client --test launch_lifecycle_live \
      --test launch_lifecycle_live_hvf -- --ignored
else
  # Loud, not silent: a skipped library seam is a coverage hole, and reporting
  # it as nothing is how the last one stayed open.
  echo "!!! SKIPPED the Rust library seam. Missing:" >&2
  [[ -z "$KERNEL" ]]     && echo "!!!   workload kernel under $E2E_HOME/cache/builder-vm" >&2
  [[ -z "$ROOTFS" ]]     && echo "!!!   OCI rootfs under $E2E_HOME/cache/oci/rootfs" >&2
  [[ -z "$SUPERVISOR" ]] && echo "!!!   mvm-hvf-supervisor under $TARGET_DIR" >&2
  echo "!!! A skipped seam is a coverage hole, not a pass." >&2
  exit 1
fi

# The harness prints a per-reason tally of what it declined to run, so a `@wip`
# scenario is counted and named rather than silently absent. Two are pending on
# the persistent-machine defect — see
# specs/plans/2026-08-26-persistent-machine-path-on-hvf.md.
echo "==> e2e launch gate: all modes exercised"
echo "    check the scenario summary above for anything reported pending"
