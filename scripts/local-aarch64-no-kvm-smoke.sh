#!/bin/bash
# Local aarch64 no-KVM smoke test.
#
# Runs the same path as the CI `aarch64-no-kvm-smoke` job inside an
# arm64 Ubuntu container. Docker Desktop on Apple Silicon does not expose
# /dev/kvm to containers, so the guest boots via QEMU TCG — the same
# fallback a Raspberry Pi without /dev/kvm would take.
#
# This is intentionally slow on the first run (cold kernel / rootfs builds
# under TCG). Use it for spot-checks, not rapid iteration.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
container_name="mvm-aarch64-smoke-$(date +%s)"

if ! docker info >/dev/null 2>&1; then
    echo "Docker is not running. Start Docker Desktop and try again." >&2
    exit 1
fi

cleanup() {
    docker rm -f "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Starting arm64 Ubuntu container (QEMU TCG smoke test) ..."
docker run -d --rm --platform linux/arm64 \
    --name "$container_name" \
    --device /dev/vhost-vsock:/dev/vhost-vsock \
    -v "$repo_root":/work \
    -w /work \
    ubuntu:24.04 \
    tail -f /dev/null >/dev/null

docker exec -it "$container_name" bash -c '
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "Installing system dependencies ..."
apt-get update -qq
apt-get install -y -qq \
    curl git build-essential pkg-config \
    qemu-system-arm ipxe-qemu virtiofsd e2fsprogs attr jq

echo "Installing Rust nightly + musl targets ..."
curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain nightly >/dev/null
source "$HOME/.cargo/env"
rustup target add aarch64-unknown-linux-musl

echo "Installing cargo-zigbuild ..."
cargo install cargo-zigbuild --version 0.23.0 --locked

cd /work

echo "Building mvmctl ..."
cargo build --release -p mvmctl --features user,embed-host-bins
cp target/release/mvmctl /tmp/mvmctl-source-under-test
cargo build --release -p mvmctl --features user,release-artifact-bootstrap,release-channel,embed-host-bins
cp target/release/mvmctl /tmp/mvmctl-release-helper

# The source-checkout bootstrap path would rebuild the builder VM image from
# scratch under TCG. Hide the in-repo flake so mvmctl downloads the published
# image instead.
mv nix/images/builder-vm nix/images/builder-vm.hidden
restore_builder_flake() {
    if [ -d nix/images/builder-vm.hidden ] && [ ! -e nix/images/builder-vm ]; then
        mv nix/images/builder-vm.hidden nix/images/builder-vm
    fi
}
trap restore_builder_flake EXIT

export MVM_HOME=/work/.mvm-local-smoke
export MVM_KERNEL_SOURCE=auto
rm -rf "$MVM_HOME"
mkdir -p "$MVM_HOME"

echo "Downloading published builder VM ..."
/tmp/mvmctl-release-helper --builder qemu __builder-vm-bootstrap -v

echo "Bootstrapping source-matched launch artifacts ..."
/tmp/mvmctl-source-under-test --builder qemu bootstrap --production -v

echo "Booting sealed exit_code workload under QEMU TCG ..."
set +e
/tmp/mvmctl-source-under-test machine run \
    --flake examples/exit_code \
    --builder qemu \
    --hypervisor qemu \
    --entrypoint \
    -v \
    > /tmp/mvmctl-first-boot.log 2>&1
actual=$?
set -e

if [ "$actual" -ne 7 ]; then
    echo "FAIL: expected guest exit code 7 from first boot, got $actual" >&2
    tail -250 /tmp/mvmctl-first-boot.log >&2
    exit 1
fi
echo "OK: sealed workload exited $actual under QEMU TCG"

echo "Exporting, installing, and re-running the bundle ..."
slot_hash=$(/tmp/mvmctl-source-under-test manifest ls --json 2>&1 \
    | sed '"'"'s/\x1b\[[0-9;]*m//g'"'"' \
    | jq -r '"'"'.[0].slot_hash'"'"')
/tmp/mvmctl-source-under-test bundle export "$slot_hash" \
    --out /tmp/exit-code-aarch64.mvmpkg \
    > /tmp/mvmctl-export.log 2>&1

/tmp/mvmctl-source-under-test trust add "$MVM_HOME/keys/host-signer.pub"

install_output=$(/tmp/mvmctl-source-under-test bundle install /tmp/exit-code-aarch64.mvmpkg 2>&1 \
    | tee /tmp/mvmctl-install.log)
installed_sha=$(printf '"'"'%s'"'"' "$install_output" \
    | sed '"'"'s/\x1b\[[0-9;]*m//g'"'"' \
    | awk '"'"'/Installed bundle / {print $3}'"'"')

echo "Installed bundle content address: $installed_sha"

set +e
/tmp/mvmctl-source-under-test machine run \
    --manifest "$installed_sha" \
    --hypervisor qemu \
    --entrypoint \
    -v \
    > /tmp/mvmctl-bundle-run.log 2>&1
actual=$?
set -e

if [ "$actual" -ne 7 ]; then
    echo "FAIL: expected guest exit code 7 from installed bundle, got $actual" >&2
    tail -250 /tmp/mvmctl-bundle-run.log >&2
    exit 1
fi
echo "OK: installed bundle exited $actual under QEMU TCG"
'
