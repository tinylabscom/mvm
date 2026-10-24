#!/usr/bin/env bash
# One bounded, offline 2-then-6 worker comparison. Run from the checkout root.
# Requires RUNNER_TEMP, numeric GITHUB_RUN_ID/GITHUB_RUN_ATTEMPT and existing
# Rust/nextest dependencies. Optional GITHUB_STEP_SUMMARY receives the report.
# BENCHMARK_COMMIT_SHA must be the full SHA of the checked-out source.
# No provisioning, installation, shared targets, or persistent settings edits.
set -euo pipefail

report() {
  printf '%s\n' "$*"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY"
  fi
}
die() { report "Benchmark failed: $*"; exit 1; }

[[ $# == 0 ]] || die "no arguments accepted; configure the runner environment"
[[ -f Cargo.toml && -f rust-toolchain.toml ]] || die "run from checkout root"
[[ ${BENCHMARK_COMMIT_SHA:-} =~ ^[0-9a-fA-F]{40}$ ]] ||
  die "BENCHMARK_COMMIT_SHA must be the checked-out source's full SHA"
[[ ${GITHUB_RUN_ID:-} =~ ^[0-9]+$ && ${GITHUB_RUN_ATTEMPT:-} =~ ^[0-9]+$ ]] ||
  die "numeric GITHUB_RUN_ID and GITHUB_RUN_ATTEMPT required"
[[ -n "${RUNNER_TEMP:-}" && "$RUNNER_TEMP" == /* && -d "$RUNNER_TEMP" ]] ||
  die "RUNNER_TEMP must be an existing absolute directory"
runner_temp=$(cd "$RUNNER_TEMP" && pwd -P)
base="$runner_temp/mvm-w-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-1"
[[ ! -e "$base" && ! -L "$base" ]] || die "refusing pre-existing isolated base: $base"

original_home=${HOME:?HOME required}
[[ ! -d "$original_home/.cargo/bin" ]] || export PATH="$original_home/.cargo/bin:$PATH"
export CARGO_HOME=${CARGO_HOME:-$original_home/.cargo}
export RUSTUP_HOME=${RUSTUP_HOME:-$original_home/.rustup}
[[ "$CARGO_HOME" == /* && "$RUSTUP_HOME" == /* ]] ||
  die "CARGO_HOME and RUSTUP_HOME must be absolute"
export RUSTUP_AUTO_INSTALL=0 CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0
export CARGO_CACHE_AUTO_CLEAN_FREQUENCY=never
toolchain=$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)
[[ "$toolchain" == nightly-2026-08-25 ]] || die "unexpected toolchain pin: $toolchain"
export RUSTUP_TOOLCHAIN="$toolchain"
for tool in rustup cargo cargo-nextest timeout setsid; do
  command -v "$tool" >/dev/null || die "missing installed tool: $tool (will not install)"
done
/usr/bin/time --version 2>&1 | grep -q 'GNU' || die "/usr/bin/time must be GNU time"
timeout --version >/dev/null || die "GNU timeout required"
rustup run --no-install "$toolchain" rustc --version ||
  die "pinned toolchain unavailable (will not install)"
rustup run --no-install "$toolchain" cargo nextest --version ||
  die "installed nextest unavailable (will not install)"

check_disk() {
  local free
  free=$(df -Pk "$runner_temp" | awk 'NR==2 {print $4}')
  [[ "$free" =~ ^[0-9]+$ ]] || die "cannot determine free disk"
  # Only one target exists at a time. Leave substantial headroom for linking.
  (( free >= 80 * 1024 * 1024 )) || die "need at least 80 GiB free for one private target"
}
check_disk
umask 077
mkdir -- "$base"
active=
# Invoked indirectly by the EXIT trap, including failed commands and signals.
# shellcheck disable=SC2329
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$active" ]]; then
    # setsid owns this group; do not signal unrelated runner processes.
    kill -KILL -- "-$active" 2>/dev/null || true
    wait "$active" 2>/dev/null || true
  fi
  if [[ -d "$base" && ! -L "$base" &&
        "$base" == "$runner_temp/mvm-w-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-1" ]]; then
    rm -rf --one-file-system -- "$base" || status=1
  else
    report "Cleanup refused changed isolated base: $base"
    status=1
  fi
  report "Benchmark exit status: $status"
  exit "$status"
}
trap 'cleanup' EXIT
trap 'report "Benchmark interrupted (130)"; exit 130' INT
trap 'report "Benchmark terminated (143)"; exit 143' TERM

report "## Cargo worker benchmark"
report "Source SHA (supplied by checkout step): $BENCHMARK_COMMIT_SHA; toolchain: $toolchain"
report "Order: 2 then 6; private cold targets; test concurrency: 2; incremental: 0."
report "Flags: nextest run --workspace --all-targets --frozen --offline --test-threads 2 (build adds --no-run)."
report "Build limit: 20m; test limit: 8m; each timeout has 10s kill grace."
report "GNU time maxRSS is a per-process high-water statistic, NOT simultaneous total process-tree memory."
report "Sequential runs share existing registry/toolchains and OS caches; this is one ordered pair, not a statistically controlled speedup estimate."
report "| Workers | Phase | Exit | Wall seconds | GNU time elapsed / maxRSS KiB |"
report "| --- | --- | --- | --- | --- |"

run_phase() {
  local phase=$1 limit=$2 status=0 started=$SECONDS metrics
  shift 2
  metrics="$base/metrics"
  rm -f -- "$metrics"
  # timeout is the session leader and supervises the full build/test group.
  setsid timeout --signal=TERM --kill-after=10s "$limit" \
    /usr/bin/time -o "$metrics" -f '%e / %M' \
    rustup run --no-install "$toolchain" cargo nextest run \
    --workspace --all-targets --frozen --offline --test-threads 2 "$@" &
  active=$!
  wait "$active" || status=$?
  # Reap any descendants left after an early exit, before deleting their files.
  kill -KILL -- "-$active" 2>/dev/null || true
  active=
  local measurement="unavailable (terminated before time report)"
  if [[ -s "$metrics" ]]; then
    measurement=$(tr '\n' ' ' < "$metrics")
  fi
  report "| $CARGO_BUILD_JOBS | $phase | $status | $((SECONDS - started)) | $measurement |"
  return "$status"
}

result=0
for workers in 2 6; do
  check_disk
  arm="$base/workers-$workers"
  mkdir -p -- "$arm/home" "$arm/mvm" "$arm/tmp" "$arm/target"
  export HOME="$arm/home" MVM_HOME="$arm/mvm" TMPDIR="$arm/tmp"
  export CARGO_TARGET_DIR="$arm/target" CARGO_BUILD_JOBS="$workers"
  status=0
  run_phase build 20m --no-run || status=$?
  if (( status == 0 )); then
    run_phase test 8m || status=$?
  else
    report "| $workers | test | skipped (build failed) | — | — |"
  fi
  if (( status != 0 && result == 0 )); then result=$status; fi
  # Fixed child of our exclusively created base; never touch workspace targets.
  [[ -d "$arm" && ! -L "$arm" && ! -L "$base" ]] || die "unsafe arm cleanup"
  rm -rf --one-file-system -- "$arm"
done
if (( result != 0 )); then
  report "At least one arm failed; no speedup conclusion is valid. See nextest output above for test results and missing offline dependencies."
fi
exit "$result"
