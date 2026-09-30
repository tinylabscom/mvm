#!/usr/bin/env bash
# Prepare a disposable GCP nested-KVM host and execute an argv request created
# by run-gcp-kvm-test.sh. This script is not an interactive entry point.
set -euo pipefail

repo=/opt/mvm
request=${1:?command argv file is required}
results=/var/tmp/mvm-gcp-kvm-results
bundle=/var/tmp/mvm-gcp-kvm-results.tar.gz

rm -rf "$results"
mkdir -p "$results"
export MVM_GCP_KVM_RESULTS_DIR="$results"
exec > >(tee -a "$results/bootstrap.log") 2>&1

# Invoked indirectly by the EXIT trap installed below.
# shellcheck disable=SC2329
bundle_results() {
  status=$?
  trap - EXIT
  printf '%s\n' "$status" >"$results/exit-status"
  tar -C /var/tmp -czf "$bundle" mvm-gcp-kvm-results || true
  chmod 0644 "$bundle" 2>/dev/null || true
  exit "$status"
}
trap bundle_results EXIT

if [[ "$(uname -m)" != "x86_64" ]]; then
  echo "error: disposable KVM tests require x86_64" >&2
  exit 1
fi
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  echo "error: nested /dev/kvm is unavailable or not writable" >&2
  exit 1
fi
if ! grep -q '^flags.*\<vmx\>' /proc/cpuinfo; then
  echo "error: Intel VMX is not exposed to the disposable host" >&2
  exit 1
fi

{
  date -u +'%Y-%m-%dT%H:%M:%SZ'
  uname -srmo
  lscpu
  stat /dev/kvm
} >"$results/host.txt"

echo ">> installing repository test dependencies"
export DEBIAN_FRONTEND=noninteractive
apt_opts=(
  -o Acquire::Retries=2
  -o Acquire::http::Timeout=15
  -o Acquire::https::Timeout=15
)
timeout 240 apt-get "${apt_opts[@]}" update
timeout 300 apt-get "${apt_opts[@]}" install -y --no-install-recommends \
  build-essential ca-certificates clang cmake curl file git lld \
  libcap-ng-dev libssl-dev musl-tools pkg-config protobuf-compiler \
  qemu-system-x86 qemu-utils xz-utils zstd dpkg-dev cpio gzip perl \
  coreutils busybox-static just

firecracker_version=1.17.0
if ! command -v firecracker >/dev/null 2>&1 \
  || [[ "$(firecracker --version 2>/dev/null)" != *"v$firecracker_version"* ]]; then
  firecracker_archive="firecracker-v${firecracker_version}-x86_64.tgz"
  firecracker_dir="release-v${firecracker_version}-x86_64"
  curl -fsSL -o "/tmp/$firecracker_archive" \
    "https://github.com/firecracker-microvm/firecracker/releases/download/v${firecracker_version}/$firecracker_archive"
  rm -rf "/tmp/$firecracker_dir"
  tar -xzf "/tmp/$firecracker_archive" -C /tmp
  install -m 0755 \
    "/tmp/$firecracker_dir/firecracker-v${firecracker_version}-x86_64" \
    /usr/local/bin/firecracker
  install -m 0755 \
    "/tmp/$firecracker_dir/jailer-v${firecracker_version}-x86_64" \
    /usr/local/bin/jailer
fi

if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain stable
fi
# The file is installed by rustup immediately above.
# shellcheck source=/dev/null
. /root/.cargo/env

guest_rust="$(awk '/^\[workspace\.metadata\.mvm\.toolchain\]/{p=1; next}
  /^\[/{p=0} p && $1 == "rust" {gsub(/"/, "", $3); print $3}' "$repo/Cargo.toml")"
zig_version="$(awk '/^\[workspace\.metadata\.mvm\.toolchain\]/{p=1; next}
  /^\[/{p=0} p && $1 == "zig" {gsub(/"/, "", $3); print $3}' "$repo/Cargo.toml")"
zigbuild_version="$(awk '/^\[workspace\.metadata\.mvm\.toolchain\]/{p=1; next}
  /^\[/{p=0} p && $1 == "cargo-zigbuild" {gsub(/"/, "", $3); print $3}' "$repo/Cargo.toml")"
if [[ -z "$guest_rust" || -z "$zig_version" || -z "$zigbuild_version" ]]; then
  echo "error: repository cross-toolchain pins are incomplete" >&2
  exit 1
fi

rustup toolchain install "$guest_rust" --profile minimal
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl \
  --toolchain "$guest_rust"

if ! command -v zig >/dev/null 2>&1 || [[ "$(zig version)" != "$zig_version" ]]; then
  zig_dir="zig-linux-x86_64-$zig_version"
  curl -fsSL "https://ziglang.org/download/$zig_version/$zig_dir.tar.xz" \
    | tar xJ -C /opt
  ln -sf "/opt/$zig_dir/zig" /usr/local/bin/zig
fi
if ! cargo zigbuild --version 2>/dev/null | grep -q "$zigbuild_version"; then
  cargo install cargo-zigbuild --version "$zigbuild_version" --locked
fi

command_argv=()
while IFS= read -r -d '' argument; do
  command_argv+=("$argument")
done <"$request"
if ((${#command_argv[@]} == 0)); then
  echo "error: command argv file is empty" >&2
  exit 1
fi

cd "$repo"
# Repository-owned worktree isolation helper.
# shellcheck source=/dev/null
source scripts/dev-env.sh
printf '>> running:'
printf ' %q' "${command_argv[@]}"
printf '\n'
set +e
"${command_argv[@]}" 2>&1 | tee "$results/command.log"
run_status=${PIPESTATUS[0]}
set -e
exit "$run_status"
