#!/usr/bin/env bash
# Build Plan 213 release pack archives from the image artifacts already
# downloaded into the release job's staging directory.
set -euo pipefail

ASSETS_DIR=""
VERSION=""
GIT_REVISION=""
SBOM_PATH=""
RUNTIME_PACKS="aarch64:vz aarch64:libkrun aarch64:firecracker x86_64:firecracker"
BUILDER_ARCHES="aarch64 x86_64"

while [ $# -gt 0 ]; do
  case "$1" in
    --assets-dir) ASSETS_DIR="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --git-revision) GIT_REVISION="$2"; shift 2 ;;
    --sbom) SBOM_PATH="$2"; shift 2 ;;
    --runtime-packs) RUNTIME_PACKS="$2"; shift 2 ;;
    --builder-arches) BUILDER_ARCHES="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ -n "$ASSETS_DIR" ] || { echo "error: --assets-dir is required" >&2; exit 2; }
[ -n "$VERSION" ] || { echo "error: --version is required" >&2; exit 2; }
[ -d "$ASSETS_DIR" ] || { echo "error: assets dir not found: $ASSETS_DIR" >&2; exit 2; }

if [ -z "$GIT_REVISION" ]; then
  GIT_REVISION="$(git rev-parse HEAD)"
fi
if [ -z "$SBOM_PATH" ]; then
  SBOM_PATH="sbom.cdx.json"
fi
[ -f "$SBOM_PATH" ] || { echo "error: SBOM not found: $SBOM_PATH" >&2; exit 2; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

size_of() {
  wc -c < "$1" | tr -d ' '
}

require_asset() {
  local file="$ASSETS_DIR/$1"
  [ -f "$file" ] || { echo "error: required release-pack input missing: $1" >&2; exit 1; }
}

json_files_array() {
  python3 - "$ASSETS_DIR" "$@" <<'PY'
import json
import os
import sys

assets_dir = sys.argv[1]
rows = []
for rel in sys.argv[2:]:
    path = os.path.join(assets_dir, rel)
    with open(path, "rb") as f:
        import hashlib

        data = f.read()
    rows.append({
        "path": rel,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    })
print(json.dumps(rows, indent=2))
PY
}

write_manifest() {
  local path="$1"
  local kind="$2"
  local name="$3"
  local arch="$4"
  local backend="$5"
  local archive="$6"
  local provenance="$7"
  shift 7
  local files_json
  files_json="$(json_files_array "$@")"
  local archive_sha sbom_sha
  archive_sha="$(sha256_of "$ASSETS_DIR/$archive")"
  sbom_sha="$(sha256_of "$SBOM_PATH")"
  FILES_JSON="$files_json" python3 - "$path" "$kind" "$name" "$arch" "$backend" "$VERSION" "$GIT_REVISION" "$archive" "$archive_sha" "$provenance" "$sbom_sha" <<'PY'
import json
import os
import sys

(
    path,
    kind,
    name,
    arch,
    backend,
    version,
    git_revision,
    archive,
    archive_sha,
    provenance,
    sbom_sha,
) = sys.argv[1:]
doc = {
    "schema_version": 1,
    "pack_kind": kind,
    "pack_name": name,
    "version": version,
    "git_revision": git_revision,
    "architecture": arch,
    "backend": backend or None,
    "channel": "github_release",
    "archive": {"path": archive, "sha256": archive_sha},
    "files": json.loads(os.environ["FILES_JSON"]),
    "sbom": {"path": "sbom.cdx.json", "sha256": sbom_sha},
    "provenance": {"path": provenance},
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
PY
}

write_provenance() {
  local path="$1"
  local kind="$2"
  local name="$3"
  local arch="$4"
  local backend="$5"
  python3 - "$path" "$kind" "$name" "$arch" "$backend" "$VERSION" "$GIT_REVISION" <<'PY'
import json
import sys

path, kind, name, arch, backend, version, git_revision = sys.argv[1:]
doc = {
    "schema_version": 1,
    "pack_kind": kind,
    "pack_name": name,
    "version": version,
    "git_revision": git_revision,
    "source_workflow": ".github/workflows/release.yml",
    "builder_identity": "github-actions-release",
    "build_environment_identity": "github-hosted-runner",
    "architecture": arch,
    "backend": backend or None,
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
PY
}

build_archive() {
  local name="$1"
  shift
  local tmp
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/$name"
  for rel in "$@"; do
    cp "$ASSETS_DIR/$rel" "$tmp/$name/$rel"
  done
  tar czf "$ASSETS_DIR/$name.tar.gz" -C "$tmp" "$name"
  rm -rf "$tmp"
  sha256_of "$ASSETS_DIR/$name.tar.gz" | awk -v file="$name.tar.gz" '{print $1 "  " file}' > "$ASSETS_DIR/$name.tar.gz.sha256"
}

for item in $RUNTIME_PACKS; do
  arch="${item%%:*}"
  backend="${item#*:}"
  name="mvm-runtime-pack-${arch}-${backend}"
  files=(
    "default-microvm-vmlinux-${arch}"
    "default-microvm-rootfs-${arch}.ext4"
    "default-microvm-rootfs-${arch}.verity"
    "default-microvm-rootfs-${arch}.roothash"
    "default-microvm-meta-${arch}.json"
    "runtime-overlay-${arch}.ext4"
    "runtime-overlay-${arch}.verity"
    "runtime-overlay-${arch}.roothash"
    "runtime-overlay-${arch}.VERSION"
  )
  for file in "${files[@]}"; do require_asset "$file"; done
  build_archive "$name" "${files[@]}"
  write_provenance "$ASSETS_DIR/$name.provenance.json" "runtime" "$name" "$arch" "$backend"
  write_manifest "$ASSETS_DIR/$name.manifest.json" "runtime" "$name" "$arch" "$backend" "$name.tar.gz" "$name.provenance.json" "${files[@]}"
  echo "built release runtime pack: $name"
done

for arch in $BUILDER_ARCHES; do
  name="mvm-builder-pack-${arch}"
  files=(
    "builder-vm-vmlinux-${arch}"
    "builder-vm-rootfs-${arch}.ext4"
  )
  require_asset "${files[0]}"
  require_asset "${files[1]}"
  if [ -f "$ASSETS_DIR/builder-vm-${arch}.cmdline.txt" ]; then
    files+=("builder-vm-${arch}.cmdline.txt")
  fi
  if [ -f "$ASSETS_DIR/builder-vm-${arch}.manifest.json" ]; then
    files+=("builder-vm-${arch}.manifest.json")
  fi
  build_archive "$name" "${files[@]}"
  write_provenance "$ASSETS_DIR/$name.provenance.json" "builder" "$name" "$arch" ""
  write_manifest "$ASSETS_DIR/$name.manifest.json" "builder" "$name" "$arch" "" "$name.tar.gz" "$name.provenance.json" "${files[@]}"
  echo "built release builder pack: $name"
done
