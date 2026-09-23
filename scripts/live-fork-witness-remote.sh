#!/usr/bin/env bash
# Run the Firecracker live-parent fork witness on a real Linux KVM host over
# ssh. The witness (`crates/mvm-runtime/tests/fc_fork_live.rs`) is `#[ignore]`d
# because it needs `/dev/kvm`; neither the macOS builder VM (an HVF/libkrun
# guest exposes no KVM) nor GitHub-hosted runners can run it. This script makes
# a real-hardware run one command from any checkout:
#
#   scripts/live-fork-witness-remote.sh root@<kvm-host>
#   just live-fork-witness root@<kvm-host>
#
# Everything is idempotent; re-runs after the first complete in minutes because
# the remote caches the toolchain, guest-agent builds, and images.
#
# What it stages on the remote (default /root):
#   deps      rustup + the pinned guest toolchain (workspace.metadata.mvm.
#             toolchain.rust) with its musl target + cargo-zigbuild. C
#             toolchain, lld, and zig must exist (apt: build-essential lld;
#             zig from https://ziglang.org if the distro lacks it).
#   kernel    the mvm workload kernel from the boot-image release train,
#             sha256-verified against the release checksums. The upstream
#             Firecracker-CI kernel CANNOT run this witness: it has no
#             CONFIG_BLK_DEV_DM, and the runtime overlay needs dm-verity.
#   rootfs    an ubuntu ext4 with python3 (debootstrap) if none is present,
#             plus /mvm/runtime pre-created — the root drive is read-only,
#             so the activation overlay mountpoint must already exist.
#   tree      rsync of this checkout to /root/mvm. Excludes are ANCHORED so
#             source directories that share a name with scratch dirs
#             (crates/mvm-fs/src/output/, out/) are never clobbered.
#
# Env overrides: BOOT_IMAGE_TAG (default the value below), REMOTE_DIR,
# REMOTE_MICROVM_DIR, SSH_OPTS, KEEP_REMOTE_PATCHES=1 to skip the tree sync.
#
# Evidence from runs with this script's exact shape: two children forked from
# one running parent restored in 39-47 ms (FC_FORK_RESTORE_MS), the parent
# served alongside both children, and per-child generation tokens and
# post-restore kernel randomness diverged. See issue #3552.

set -euo pipefail

BOOT_IMAGE_TAG_DEFAULT="boot-image/v0.1.5"

if [ $# -lt 1 ]; then
    echo "usage: $0 <ssh-target> [boot-image-tag]" >&2
    echo "  e.g. $0 root@my-kvm-host" >&2
    exit 64
fi

TARGET="$1"
BOOT_IMAGE_TAG="${2:-${BOOT_IMAGE_TAG:-$BOOT_IMAGE_TAG_DEFAULT}}"
REMOTE_DIR="${REMOTE_DIR:-/root/mvm}"
REMOTE_MICROVM_DIR="${REMOTE_MICROVM_DIR:-/root/microvm}"
SSH_OPTS="${SSH_OPTS:--o BatchMode=yes -o ConnectTimeout=10}"
SSH="ssh $SSH_OPTS"

# The checkout holding this script (anchored excludes are relative to it).
SRC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "== target $TARGET, boot image $BOOT_IMAGE_TAG =="

REMOTE=$(cat <<'REMOTE_SCRIPT'
set -euo pipefail
exec > >(tee -a /root/live-fork-witness.log) 2>&1

BOOT_IMAGE_TAG="$1"; REMOTE_DIR="$2"; MICROVM="$3"
export HOME=/root
. "$HOME/.cargo/env" 2>/dev/null || true

echo "=== remote deps $(date) ==="
need_pkgs=0
for tool in cc ld.lld curl mkfs.ext4; do
    command -v "$tool" >/dev/null || need_pkgs=1
done
# Only touch apt when something is missing: on hosts with a stale or
# unreachable mirror, apt-get update can hang for a long time.
if [ "$need_pkgs" -eq 1 ] && command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null
    apt-get install -y --no-install-recommends \
        build-essential lld debootstrap ubuntu-keyring e2fsprogs \
        curl xz-utils ca-certificates file >/dev/null
fi
for tool in cc ld.lld curl mkfs.ext4; do
    command -v "$tool" >/dev/null || { echo "missing $tool on remote" >&2; exit 1; }
done
if ! command -v zig >/dev/null 2>&1; then
    zig_arch="$(uname -m)"
    curl -fsSL -o /tmp/zig.tar.xz "https://ziglang.org/download/0.14.1/zig-${zig_arch}-linux-0.14.1.tar.xz"
    tar -xJf /tmp/zig.tar.xz -C /usr/local
    ln -sf "/usr/local/zig-${zig_arch}-linux-0.14.1/zig" /usr/local/bin/zig
fi
if ! command -v cargo >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --profile minimal
    . "$HOME/.cargo/env"
fi
# The guest-agent cross-compile pins its own toolchain via
# workspace.metadata.mvm.toolchain.rust; it needs the musl std for it.
guest_toolchain=$(awk '/^\[workspace.metadata.mvm.toolchain\]/{in_toolchain=1; next}
    /^\[/{in_toolchain=0}
    in_toolchain && /^rust = /{gsub(/"/, "", $3); print $3}' "$REMOTE_DIR/Cargo.toml")
host_arch="$(uname -m)"
musl_target="${host_arch}-unknown-linux-musl"
rustup toolchain install "$guest_toolchain" --profile minimal 2>&1 | tail -1
rustup target add "$musl_target" --toolchain "$guest_toolchain" 2>&1 | tail -1
if ! cargo zigbuild --help >/dev/null 2>&1; then
    cargo install cargo-zigbuild --locked 2>&1 | tail -2
fi

echo "=== kernel $(date) ==="
mkdir -p "$MICROVM"
if [ ! -f "$MICROVM/vmlinux-mvm" ]; then
    checksums="default-microvm-${host_arch}-checksums-sha256.txt"
    asset="default-microvm-vmlinux-${host_arch}"
    base="https://github.com/tinylabscom/mvm/releases/download/${BOOT_IMAGE_TAG}"
    curl -fsSL -o "/tmp/$checksums" "$base/$checksums"
    curl -fL -o "$MICROVM/vmlinux-mvm" "$base/$asset"
    expected=$(grep " ${asset}$" "/tmp/$checksums" | awk '{print $1}')
    actual=$(sha256sum "$MICROVM/vmlinux-mvm" | awk '{print $1}')
    [ "$expected" = "$actual" ] || { echo "kernel digest mismatch" >&2; exit 1; }
    echo "kernel $asset sha256-verified"
fi

echo "=== rootfs $(date) ==="
if [ ! -f "$MICROVM/ubuntu-24.04.ext4" ]; then
    mirror="http://archive.ubuntu.com/ubuntu"
    [ "$host_arch" = "aarch64" ] && mirror="http://ports.ubuntu.com/ubuntu-ports"
    truncate -s 3G "$MICROVM/ubuntu-24.04.ext4"
    mkfs.ext4 -F -q "$MICROVM/ubuntu-24.04.ext4"
    mkdir -p /mnt/witness-rootfs
    mount -o loop "$MICROVM/ubuntu-24.04.ext4" /mnt/witness-rootfs
    debootstrap --include=python3,ca-certificates noble /mnt/witness-rootfs "$mirror"
    umount /mnt/witness-rootfs
fi
# The root drive is read-only in the guest; the activation's runtime-overlay
# mountpoint must pre-exist in the image.
mkdir -p /mnt/witness-rootfs
mount -o loop "$MICROVM/ubuntu-24.04.ext4" /mnt/witness-rootfs
mkdir -p /mnt/witness-rootfs/mvm/runtime
umount /mnt/witness-rootfs

echo "=== witness $(date) ==="
cd "$REMOTE_DIR"
export CARGO_TARGET_DIR=/root/mvm-target
export CARGO_NET_GIT_FETCH_WITH_CLI=true
# After an rsync the workspace must rebuild from real content: source mtimes
# can be older than the cache (checkout switches), and cargo would otherwise
# relink stale objects. Clean FIRST, with the target dir already exported —
# `cargo clean` without it would no-op on the default ./target.
cargo clean --workspace
export MVM_LIVE_KERNEL="$MICROVM/vmlinux-mvm"
export MVM_LIVE_ROOTFS="$MICROVM/ubuntu-24.04.ext4"
export MVM_LIVE_HOME="$MICROVM/live-home"
mkdir -p "$MVM_LIVE_HOME"
cargo test -p mvm-runtime --test fc_fork_live -- --ignored --nocapture --test-threads=1
echo "=== DONE $(date) ==="
REMOTE_SCRIPT
)

if [ "${KEEP_REMOTE_PATCHES:-0}" != "1" ]; then
    echo "== syncing tree to $TARGET:$REMOTE_DIR =="
    # Anchored excludes: a bare `out`/`output` pattern would also delete
    # crates/mvm-fs/src/output/ at any depth (it did, once).
    #
    # rsync -a preserves source mtimes, which can be OLDER than the remote
    # build cache (switching between local checkouts does this) — cargo would
    # then see no change and run a stale binary. `cargo clean --workspace`
    # after the sync is the deterministic fix: workspace crates rebuild from
    # real content, third-party dependency artifacts stay cached.
    rsync -a -e "$SSH" \
        --exclude='/.git' --exclude='/target' --exclude='/.mvm-test' \
        --exclude='/.venv' --exclude='/.ruff_cache' --exclude='/out' \
        --exclude='/output' --exclude='/artifacts' --exclude='/graft/.cache' \
        --exclude='/.lima' --exclude='/.claude' --exclude='node_modules' \
        "$SRC_ROOT/" "$TARGET:$REMOTE_DIR/"
fi

echo "== running witness on $TARGET (log: /root/live-fork-witness.log) =="
# shellcheck disable=SC2086
$SSH "$TARGET" "bash -s -- '$BOOT_IMAGE_TAG' '$REMOTE_DIR' '$REMOTE_MICROVM_DIR'" <<<"$REMOTE"
