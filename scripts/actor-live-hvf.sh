#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
    echo "actor live witness requires native Apple Silicon HVF" >&2
    exit 64
fi
: "${MVM_ACTOR_KERNEL:?set the absolute path of the verified AArch64 workload kernel}"
[[ "$MVM_ACTOR_KERNEL" = /* && -f "$MVM_ACTOR_KERNEL" ]] || {
    echo "MVM_ACTOR_KERNEL must be an existing absolute kernel path" >&2
    exit 65
}
command -v cargo-zigbuild >/dev/null || {
    echo "the pinned cargo-zigbuild/Zig toolchain must already be installed (see just setup toolchain)" >&2
    exit 65
}

# This is an explicit native HVF witness. All builds below are Cargo builds;
# the rootfs, runtime overlay and initramfs use existing pure-Rust assemblers.
# No Nix evaluation/build or Linux syscall is run on the host.
source "$ROOT/scripts/dev-env.sh"
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
"$ROOT/scripts/cargo.sh" zigbuild --release --target aarch64-unknown-linux-musl \
    -p mvm-agentd --example actor_live_parent --example actor_live_worker
"$ROOT/scripts/cargo.sh" build --release -p mvm-hostd --features hvf-live-validation \
    --bins --example actor_live_hvf

umask 077
container="$(mktemp -d /tmp/actor-hvf.XXXXXX)"
evidence="$container/evidence"
export MVM_HOME="$evidence/mvm"
export MVM_AUX_BIN_DIR="$CARGO_TARGET_DIR/release"
export MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build
unset MVM_SKIP_HASH_VERIFY MVM_SKIP_COSIGN_VERIFY
echo "native actor evidence will be retained at $evidence"
exec "$CARGO_TARGET_DIR/release/examples/actor_live_hvf" \
    "$ROOT" "$evidence" "$MVM_ACTOR_KERNEL" \
    "$CARGO_TARGET_DIR/aarch64-unknown-linux-musl/release/examples/actor_live_parent" \
    "$CARGO_TARGET_DIR/aarch64-unknown-linux-musl/release/examples/actor_live_worker"
