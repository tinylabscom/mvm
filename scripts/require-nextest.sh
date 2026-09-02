#!/usr/bin/env bash
# Refuse to run the suite under a cargo-nextest too old for this workspace's
# cargo. The floor lives in Cargo.toml's `[workspace.metadata.mvm.toolchain]`
# as `nextest-min`, beside the other tool pins.
#
# Why this guard earns its keep: the failure it catches does not look like a
# tooling problem. Under an old nextest every root-package CLI integration test
# fails with "CARGO_BIN_EXE_mvmctl is unset", which reads as 111 broken tests
# rather than one stale binary — and it is invisible in CI, where the runner
# installs a current nextest every time.
set -euo pipefail

workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

required="$(sed -n 's/^nextest-min = "\([^"]*\)"$/\1/p' "${workspace_root}/Cargo.toml")"
if [[ -z "${required}" ]]; then
  echo "require-nextest: no nextest-min in Cargo.toml [workspace.metadata.mvm.toolchain]" >&2
  exit 1
fi

if ! command -v cargo-nextest >/dev/null 2>&1; then
  echo "require-nextest: cargo-nextest not installed. Install with:" >&2
  echo "    cargo install cargo-nextest --locked" >&2
  exit 1
fi

# `cargo-nextest 0.9.143 (60fa45f63 2026-08-04)` -> `0.9.143`
found="$(cargo nextest --version | head -1 | awk '{print $2}')"
if [[ -z "${found}" ]]; then
  echo "require-nextest: could not parse 'cargo nextest --version'" >&2
  exit 1
fi

# `sort -V` puts the lower version first; if that is not the floor, we are below it.
if [[ "$(printf '%s\n%s\n' "${required}" "${found}" | sort -V | head -1)" != "${required}" ]]; then
  cat >&2 <<EOF
require-nextest: cargo-nextest ${found} is older than the required ${required}.

  This workspace's pinned nightly cargo emits test binaries under
  target/debug/build/<pkg>/<hash>/out/ instead of target/debug/deps/. An older
  nextest does not export CARGO_BIN_EXE_<name> for that layout, so every
  root-package CLI integration test fails with:

      CARGO_BIN_EXE_mvmctl is unset

  Those failures are the tool, not your code. Fix with:

      cargo install cargo-nextest --locked
EOF
  exit 1
fi
