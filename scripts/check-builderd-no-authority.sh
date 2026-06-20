#!/usr/bin/env bash
# Builder-daemon authority contract.
#
# mvm-builderd is the builder-VM control daemon: it runs Nix/build work and
# serves a typed allowlisted protocol with no shell surface. It is trusted to
# BUILD, never to sign or admit — so it must link none of the host-only
# authority symbols. This is the builder tier of the trust gradient
# (host > builder > workload); authority never reaches a daemon below the host.
#
#   canary: the mvm_builderd crate's own symbols are present, proving the symbol
#           table is populated so the absence checks below are not vacuous.
#   absent: load_host_signing_key, host_signer, admit_for_run — host-side
#           authority that lives above the host->builder boundary.
set -euo pipefail

PKG=mvm-build
BIN=mvm-builderd

echo "::group::Build mvm-builderd (release)"
CARGO_PROFILE_RELEASE_STRIP=false \
  cargo build --release --locked -p "$PKG" --bin "$BIN"
echo "::endgroup::"
syms=$(nm "target/release/$BIN")

fail=0

if grep -q 'mvm_builderd' <<<"$syms"; then
  echo "ok: mvm_builderd symbols present (symbol table populated)"
else
  echo "::error::no mvm_builderd symbols — table stripped; absence checks would be vacuous." >&2
  fail=1
fi

for sym in load_host_signing_key host_signer admit_for_run; do
  if grep -qE "mvm_(builderd|build|core|hostd|backend|cli).*${sym}" <<<"$syms"; then
    echo "::error::host authority symbol \`${sym}\` is PRESENT in mvm-builderd." >&2
    grep -E "mvm_(builderd|build|core|hostd|backend|cli).*${sym}" <<<"$syms" >&2 || true
    fail=1
  else
    echo "ok: ${sym} absent from mvm-builderd"
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "::error::Builder-daemon authority contract FAILED — see annotations above." >&2
  exit 1
fi
echo "All assertions passed: mvm-builderd carries no host-authority symbols."
