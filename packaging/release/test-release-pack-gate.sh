#!/usr/bin/env bash
# Fixture-driven tests for the release pack builder and release asset verifier.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ASSETS="$TMP/assets"
mkdir -p "$ASSETS"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

write_asset() {
  local name="$1"
  printf 'fixture:%s\n' "$name" > "$ASSETS/$name"
}

write_binary_release() {
  local target="$1"
  local dir="$TMP/mvmctl-$target"
  mkdir -p "$dir"
  cat > "$dir/mvmctl" <<'SH'
#!/usr/bin/env bash
echo "mvmctl 1.2.3"
SH
  chmod +x "$dir/mvmctl"
  tar czf "$ASSETS/mvmctl-$target.tar.gz" -C "$TMP" "mvmctl-$target"
  sha256_of "$ASSETS/mvmctl-$target.tar.gz" | awk -v file="mvmctl-$target.tar.gz" '{print $1 "  " file}' > "$ASSETS/mvmctl-$target.tar.gz.sha256"
  printf 'fixture bundle\n' > "$ASSETS/mvmctl-$target.tar.gz.bundle"
}

for arch in aarch64 x86_64; do
  write_asset "builder-vm-vmlinux-$arch"
  write_asset "builder-vm-rootfs-$arch.ext4"
  write_asset "builder-vm-$arch.cmdline.txt"
  write_asset "builder-vm-$arch.manifest.json"
  write_asset "default-microvm-vmlinux-$arch"
  write_asset "default-microvm-rootfs-$arch.ext4"
  write_asset "default-microvm-rootfs-$arch.verity"
  write_asset "default-microvm-rootfs-$arch.roothash"
  write_asset "default-microvm-meta-$arch.json"
  write_asset "runtime-overlay-$arch.ext4"
  write_asset "runtime-overlay-$arch.verity"
  write_asset "runtime-overlay-$arch.roothash"
  write_asset "runtime-overlay-$arch.VERSION"
done

for target in aarch64-apple-darwin x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do
  write_binary_release "$target"
done

cat > "$TMP/sbom.cdx.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}
JSON
cp "$TMP/sbom.cdx.json" "$ASSETS/sbom.cdx.json"
printf 'fixture bundle\n' > "$ASSETS/sbom.cdx.json.bundle"

bash "$ROOT/packaging/release/build-release-packs.sh" \
  --assets-dir "$ASSETS" \
  --version "1.2.3" \
  --git-revision "0123456789abcdef0123456789abcdef01234567" \
  --sbom "$ASSETS/sbom.cdx.json"

for blob in "$ASSETS"/*.tar.gz "$ASSETS"/mvm-*-pack-*.manifest.json "$ASSETS"/mvm-*-pack-*.provenance.json; do
  [ -e "$blob" ] || continue
  printf 'fixture bundle\n' > "$blob.bundle"
done

cat "$ASSETS"/*.sha256 > "$ASSETS/checksums-sha256.txt"

bash "$ROOT/packaging/release/verify-release-assets.sh" \
  --assets-dir "$ASSETS" \
  --expect-version "1.2.3"

NEG="$TMP/negative"
cp -R "$ASSETS" "$NEG"
rm "$NEG/mvm-runtime-pack-aarch64-vz.manifest.json.bundle"
if bash "$ROOT/packaging/release/verify-release-assets.sh" --assets-dir "$NEG" --expect-version "1.2.3" >/tmp/mvm-release-pack-negative.log 2>&1; then
  echo "expected missing pack manifest bundle to fail" >&2
  exit 1
fi

NEG_VERSION="$TMP/negative-version"
cp -R "$ASSETS" "$NEG_VERSION"
python3 - "$NEG_VERSION/mvm-builder-pack-aarch64.manifest.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    doc = json.load(f)
doc["version"] = "9.9.9"
with open(path, "w", encoding="utf-8") as f:
    json.dump(doc, f)
    f.write("\n")
PY
if bash "$ROOT/packaging/release/verify-release-assets.sh" --assets-dir "$NEG_VERSION" --expect-version "1.2.3" >/tmp/mvm-release-pack-negative-version.log 2>&1; then
  echo "expected mismatched pack manifest version to fail" >&2
  exit 1
fi

NEG_INPUT="$TMP/negative-input"
cp -R "$ASSETS" "$NEG_INPUT"
rm "$NEG_INPUT/runtime-overlay-aarch64.ext4"
if bash "$ROOT/packaging/release/build-release-packs.sh" --assets-dir "$NEG_INPUT" --version "1.2.3" --git-revision "0123456789abcdef0123456789abcdef01234567" --sbom "$NEG_INPUT/sbom.cdx.json" >/tmp/mvm-release-pack-negative-input.log 2>&1; then
  echo "expected missing runtime pack input to fail" >&2
  exit 1
fi

echo "release pack gate self-test passed"
