#!/usr/bin/env bash
# Produce the `.mvmpkg` fixture the `@bundle` conformance scenarios install,
# together with the publisher key it is sealed under.
#
# Sealing a bundle is a full image build, which is why the suite takes the
# archive from the operator rather than building one inline. This script is the
# supported way to make one.
#
#   ./scripts/make-bundle-fixture.sh [<template>] [<outdir>]
#
# <template> defaults to the most recently built template in ~/.mvm/templates.
# Prints the two `export` lines to feed the suite.
set -euo pipefail

MVMCTL="${MVMCTL:-${CARGO_TARGET_DIR:-target}/debug/mvmctl}"
[ -x "$MVMCTL" ] || { echo "no mvmctl at $MVMCTL — run: cargo build --bin mvmctl" >&2; exit 1; }

TEMPLATES="$("$MVMCTL" --help >/dev/null 2>&1 && echo "${MVM_HOME:-$HOME/.mvm}/templates")"
TEMPLATE="${1:-}"
if [ -z "$TEMPLATE" ]; then
    # A sealed bundle is exported from a built template slot, named by its
    # 64-char content hash. Anything shorter in this directory is an alias.
    TEMPLATE="$(ls -t "$TEMPLATES" 2>/dev/null | grep -E '^[0-9a-f]{64}$' | head -1 || true)"
fi
if [ -z "$TEMPLATE" ]; then
    echo "no built template found in $TEMPLATES." >&2
    echo "Build one first, e.g.: $MVMCTL machine build --flake examples/exit_code" >&2
    exit 1
fi

OUT="${2:-${TMPDIR:-/tmp}}"
mkdir -p "$OUT"
PKG="$OUT/mvm-bdd-fixture.mvmpkg"
PUB="$OUT/mvm-bdd-fixture.pub"

"$MVMCTL" bundle export "$TEMPLATE" --out "$PKG"

# The archive is signed by this host's signer; its public half is the trust
# anchor a fresh MVM_HOME needs before `bundle install` will admit the archive.
SIGNER="${MVM_HOME:-$HOME/.mvm}/keys/host-signer.pub"
[ -f "$SIGNER" ] || { echo "no host signer public key at $SIGNER" >&2; exit 1; }
cp "$SIGNER" "$PUB"

echo
echo "export MVM_BDD_BUNDLE=$PKG"
echo "export MVM_BDD_BUNDLE_PUBKEY=$PUB"
