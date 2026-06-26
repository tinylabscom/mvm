#!/usr/bin/env bash
# Verify a published mvm release's asset set is complete and self-consistent:
# every binary target tarball has a SHA256 file that matches, a cosign
# signature bundle, and an entry in the combined checksums manifest; every
# release pack has its archive, manifest, provenance, checksum, signature
# bundles, expected version metadata, and SBOM reference; the signed SBOM is
# present. Fail-closed — any missing or mismatched asset is a nonzero exit. Run
# post-publish (release.yml `verify-release` job) against a directory of
# downloaded release assets, or locally against a staging dir.
#
# Usage:
#   verify-release-assets.sh --assets-dir DIR [--targets "t1 t2 ..."] [--cosign]
#
# --targets defaults to the release.yml build matrix. --cosign additionally
# runs `cosign verify-blob` against each bundle (needs cosign on PATH and the
# expected OIDC identity in COSIGN_IDENTITY / COSIGN_OIDC_ISSUER).
set -euo pipefail

ASSETS_DIR=""
# Keep in lockstep with the release.yml `build` matrix. x86_64-apple-darwin is
# deferred there (no Intel runner), so it is deliberately absent here too.
TARGETS="aarch64-apple-darwin x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu"
RUNTIME_PACKS="aarch64:vz aarch64:libkrun aarch64:firecracker x86_64:firecracker"
BUILDER_PACK_ARCHES="aarch64 x86_64"
DO_COSIGN=0
EXPECT_VERSION=""

while [ $# -gt 0 ]; do
  case "$1" in
    --assets-dir)     ASSETS_DIR="$2"; shift 2 ;;
    --targets)        TARGETS="$2"; shift 2 ;;
    --runtime-packs)  RUNTIME_PACKS="$2"; shift 2 ;;
    --builder-arches) BUILDER_PACK_ARCHES="$2"; shift 2 ;;
    --cosign)         DO_COSIGN=1; shift ;;
    # Assert the packaged binary reports this version. Only the target that
    # matches the host can be executed; cross-arch targets are skipped (their
    # `--version` is covered by the build-job smoke test before packaging).
    --expect-version) EXPECT_VERSION="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# Which release target, if any, can run on this host?
host_target() {
  case "$(uname -s)/$(uname -m)" in
    Linux/x86_64)          echo "x86_64-unknown-linux-gnu" ;;
    Linux/aarch64)         echo "aarch64-unknown-linux-gnu" ;;
    Darwin/arm64)          echo "aarch64-apple-darwin" ;;
    *)                     echo "" ;;
  esac
}
HOST_TARGET="$(host_target)"

[ -n "$ASSETS_DIR" ] || { echo "error: --assets-dir is required" >&2; exit 2; }
[ -d "$ASSETS_DIR" ] || { echo "error: assets dir not found: $ASSETS_DIR" >&2; exit 2; }

fail() { echo "::error::$*" >&2; FAILED=1; }
FAILED=0

# Prefer sha256sum (Linux), fall back to shasum -a 256 (macOS).
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

verify_cosign_bundle() {
  local subject="$1"
  local bundle="$2"
  local label="$3"
  if [ "$DO_COSIGN" = 1 ] && [ -f "$bundle" ]; then
    command -v cosign >/dev/null 2>&1 || { fail "--cosign given but cosign not on PATH"; return; }
    cosign verify-blob --bundle "$bundle" \
      ${COSIGN_IDENTITY_REGEXP:+--certificate-identity-regexp "$COSIGN_IDENTITY_REGEXP"} \
      ${COSIGN_IDENTITY:+--certificate-identity "$COSIGN_IDENTITY"} \
      ${COSIGN_OIDC_ISSUER:+--certificate-oidc-issuer "$COSIGN_OIDC_ISSUER"} \
      "$subject" >/dev/null 2>&1 \
      || fail "[$label] cosign verify-blob failed"
  fi
}

verify_pack_manifest() {
  local manifest="$1"
  local expected_kind="$2"
  local expected_name="$3"
  local expected_arch="$4"
  local expected_backend="$5"
  local archive="$6"
  local provenance="$7"
  local label="$8"
  local sbom="$ASSETS_DIR/sbom.cdx.json"
  [ -f "$sbom" ] || return 0
  if ! python3 - "$manifest" "$expected_kind" "$expected_name" "$expected_arch" "$expected_backend" "$EXPECT_VERSION" "$archive" "$provenance" "$(sha256_of "$archive")" "$(sha256_of "$sbom")" <<'PY'
import json
import sys

(
    manifest_path,
    expected_kind,
    expected_name,
    expected_arch,
    expected_backend,
    expected_version,
    archive_path,
    provenance_path,
    archive_sha,
    sbom_sha,
) = sys.argv[1:]
with open(manifest_path, encoding="utf-8") as f:
    doc = json.load(f)
errors = []
def check(condition, message):
    if not condition:
        errors.append(message)

check(doc.get("schema_version") == 1, "schema_version must be 1")
check(doc.get("pack_kind") == expected_kind, "pack_kind mismatch")
check(doc.get("pack_name") == expected_name, "pack_name mismatch")
check(doc.get("architecture") == expected_arch, "architecture mismatch")
backend = doc.get("backend")
check((backend or "") == expected_backend, "backend mismatch")
if expected_version:
    check(doc.get("version") == expected_version, "version mismatch")
archive = doc.get("archive") or {}
check(archive.get("path") == archive_path.split("/")[-1], "archive path mismatch")
check(archive.get("sha256") == archive_sha, "archive sha256 mismatch")
sbom = doc.get("sbom") or {}
check(sbom.get("path") == "sbom.cdx.json", "sbom path mismatch")
check(sbom.get("sha256") == sbom_sha, "sbom sha256 mismatch")
provenance = doc.get("provenance") or {}
check(provenance.get("path") == provenance_path.split("/")[-1], "provenance path mismatch")
files = doc.get("files")
check(isinstance(files, list) and len(files) > 0, "files must be non-empty")
if errors:
    for error in errors:
        print(error, file=sys.stderr)
    sys.exit(1)
PY
  then
    fail "[$label] manifest metadata invalid"
  fi
}

verify_pack_provenance() {
  local provenance="$1"
  local expected_kind="$2"
  local expected_name="$3"
  local expected_arch="$4"
  local expected_backend="$5"
  local label="$6"
  if ! python3 - "$provenance" "$expected_kind" "$expected_name" "$expected_arch" "$expected_backend" "$EXPECT_VERSION" <<'PY'
import json
import sys

path, kind, name, arch, backend, version = sys.argv[1:]
with open(path, encoding="utf-8") as f:
    doc = json.load(f)
checks = [
    (doc.get("schema_version") == 1, "schema_version must be 1"),
    (doc.get("pack_kind") == kind, "pack_kind mismatch"),
    (doc.get("pack_name") == name, "pack_name mismatch"),
    (doc.get("architecture") == arch, "architecture mismatch"),
    ((doc.get("backend") or "") == backend, "backend mismatch"),
    (doc.get("source_workflow") == ".github/workflows/release.yml", "source_workflow mismatch"),
]
if version:
    checks.append((doc.get("version") == version, "version mismatch"))
errors = [message for ok, message in checks if not ok]
if errors:
    for error in errors:
        print(error, file=sys.stderr)
    sys.exit(1)
PY
  then
    fail "[$label] provenance metadata invalid"
  fi
}

verify_release_pack() {
  local kind="$1"
  local name="$2"
  local arch="$3"
  local backend="$4"
  local label="$name"
  local archive="$ASSETS_DIR/$name.tar.gz"
  local sha="$archive.sha256"
  local archive_bundle="$archive.bundle"
  local manifest="$ASSETS_DIR/$name.manifest.json"
  local manifest_bundle="$manifest.bundle"
  local provenance="$ASSETS_DIR/$name.provenance.json"
  local provenance_bundle="$provenance.bundle"

  [ -f "$archive" ] || { fail "[$label] pack archive missing: $(basename "$archive")"; return; }
  [ -f "$sha" ] || fail "[$label] pack checksum file missing: $(basename "$sha")"
  [ -f "$archive_bundle" ] || fail "[$label] pack archive signature bundle missing: $(basename "$archive_bundle")"
  [ -f "$manifest" ] || fail "[$label] pack manifest missing: $(basename "$manifest")"
  [ -f "$manifest_bundle" ] || fail "[$label] pack manifest signature bundle missing: $(basename "$manifest_bundle")"
  [ -f "$provenance" ] || fail "[$label] pack provenance missing: $(basename "$provenance")"
  [ -f "$provenance_bundle" ] || fail "[$label] pack provenance signature bundle missing: $(basename "$provenance_bundle")"

  if [ -f "$sha" ]; then
    want=$(awk '{print $1}' "$sha")
    got=$(sha256_of "$archive")
    [ "$want" = "$got" ] || fail "[$label] pack sha256 mismatch: recorded=$want actual=$got"
  fi

  if [ -f "$COMBINED" ]; then
    grep -q "$name.tar.gz" "$COMBINED" \
      || fail "[$label] not listed in checksums-sha256.txt"
  fi

  [ -f "$manifest" ] && verify_pack_manifest "$manifest" "$kind" "$name" "$arch" "$backend" "$archive" "$provenance" "$label"
  [ -f "$provenance" ] && verify_pack_provenance "$provenance" "$kind" "$name" "$arch" "$backend" "$label"
  verify_cosign_bundle "$archive" "$archive_bundle" "$label archive"
  verify_cosign_bundle "$manifest" "$manifest_bundle" "$label manifest"
  verify_cosign_bundle "$provenance" "$provenance_bundle" "$label provenance"
}

COMBINED="$ASSETS_DIR/checksums-sha256.txt"
[ -f "$COMBINED" ] || fail "combined checksums manifest missing: checksums-sha256.txt"

for target in $TARGETS; do
  tarball="$ASSETS_DIR/mvmctl-${target}.tar.gz"
  sha="$tarball.sha256"
  bundle="$tarball.bundle"

  [ -f "$tarball" ] || { fail "[$target] tarball missing: $(basename "$tarball")"; continue; }
  [ -f "$sha" ]     || fail "[$target] checksum file missing: $(basename "$sha")"
  [ -f "$bundle" ]  || fail "[$target] cosign signature bundle missing: $(basename "$bundle")"

  # The .sha256 file records the SHA over the tarball — recompute and compare.
  if [ -f "$sha" ]; then
    want=$(awk '{print $1}' "$sha")
    got=$(sha256_of "$tarball")
    [ "$want" = "$got" ] || fail "[$target] sha256 mismatch: recorded=$want actual=$got"
  fi

  # The combined manifest must cover this tarball (download-path integrity).
  if [ -f "$COMBINED" ]; then
    grep -q "mvmctl-${target}.tar.gz" "$COMBINED" \
      || fail "[$target] not listed in checksums-sha256.txt"
  fi

  verify_cosign_bundle "$tarball" "$bundle" "$target"

  if [ -n "$EXPECT_VERSION" ] && [ "$target" = "$HOST_TARGET" ] && [ -f "$tarball" ]; then
    tmp=$(mktemp -d)
    if tar xzf "$tarball" -C "$tmp" 2>/dev/null; then
      bin="$tmp/mvmctl-${target}/mvmctl"
      if [ -x "$bin" ]; then
        ver=$("$bin" --version 2>/dev/null || true)
        case "$ver" in
          *"$EXPECT_VERSION"*) : ;;
          *) fail "[$target] --version mismatch: expected to contain '$EXPECT_VERSION', got '$ver'" ;;
        esac
      else
        fail "[$target] packaged mvmctl binary missing or not executable"
      fi
    else
      fail "[$target] tarball failed to extract"
    fi
    rm -rf "$tmp"
  fi
done

# The SBOM ships signed alongside the binaries on every release.
[ -f "$ASSETS_DIR/sbom.cdx.json" ]        || fail "SBOM missing: sbom.cdx.json"
[ -f "$ASSETS_DIR/sbom.cdx.json.bundle" ] || fail "SBOM signature bundle missing: sbom.cdx.json.bundle"

for item in $RUNTIME_PACKS; do
  arch="${item%%:*}"
  backend="${item#*:}"
  verify_release_pack "runtime" "mvm-runtime-pack-${arch}-${backend}" "$arch" "$backend"
done

for arch in $BUILDER_PACK_ARCHES; do
  verify_release_pack "builder" "mvm-builder-pack-${arch}" "$arch" ""
done

if [ "$FAILED" = 0 ]; then
  echo "ok: all $(echo "$TARGETS" | wc -w | tr -d ' ') target(s) and release packs have matching sha256, signature bundles, manifest entries, provenance, and signed SBOM."
else
  echo "release asset verification FAILED" >&2
  exit 1
fi
