#!/usr/bin/env bash
set -euo pipefail

arch="${1:?usage: build-kernel-artifacts.sh <aarch64|x86_64>}"
case "$arch" in
  aarch64|x86_64) ;;
  *) echo "unsupported kernel architecture: $arch" >&2; exit 2 ;;
esac

system="${arch}-linux"
mkdir -p staging
for variant in builder workload; do
  store=$(nix build \
    "./nix/images/builder-vm#packages.${system}.${variant}-kernel" \
    --impure --no-link --print-out-paths | head -1)
  if [[ -f "$store/Image" ]]; then
    src="$store/Image"
  elif [[ -f "$store/bzImage" ]]; then
    src="$store/bzImage"
  else
    echo "no kernel image (Image/bzImage) in $store" >&2
    ls -la "$store" >&2
    exit 1
  fi
  cp "$src" "staging/vmlinux-${arch}-${variant}"
done

config=$(nix build \
  "./nix/images/builder-vm#packages.${system}.workload-kernel-configfile" \
  --impure --no-link --print-out-paths | head -1)
kernel_version=$(basename "$store" | sed -E 's/^linux-//')
config_hash=$(sha256sum "$config" | cut -d' ' -f1)
artifact_hash=$(sha256sum "staging/vmlinux-${arch}-workload" | cut -d' ' -f1)
printf '{"kernel_version":"%s","config_hash":"%s","artifact_hash":"%s"}\n' \
  "$kernel_version" "$config_hash" "$artifact_hash" > "staging/kernel-${arch}.json"
cp "$config" "staging/workload-config-${arch}"

symbol_count=$(grep -c '=y$' "$config")
budget_name="BUDGET_${arch^^}"
budget=$(grep -oP "${budget_name}: usize = \K[0-9]+" \
  xtask/src/check_kernel_config_budget.rs)
echo "workload kernel ${arch}: ${symbol_count} =y symbols (budget ${budget})"
if [[ "$symbol_count" -gt "$budget" ]]; then
  echo "workload kernel ${arch} has ${symbol_count} built-in symbols, over budget ${budget}" >&2
  exit 1
fi

raw_bytes=$(stat -c%s "staging/vmlinux-${arch}-workload")
gzip_bytes=$(gzip -c "staging/vmlinux-${arch}-workload" | wc -c)
printf '{"arch":"%s","y_symbol_count":%d,"vmlinux_bytes":%d,"vmlinux_gz_bytes":%d}\n' \
  "$arch" "$symbol_count" "$raw_bytes" "$gzip_bytes" \
  > "staging/kernel-metrics-${arch}.json"

(
  cd staging
  sha256sum "vmlinux-${arch}-"* > "kernel-${arch}-checksums-sha256.txt"
  cat "kernel-${arch}-checksums-sha256.txt" \
    "kernel-${arch}.json" \
    "kernel-metrics-${arch}.json"
  du -h "vmlinux-${arch}-"*
)
