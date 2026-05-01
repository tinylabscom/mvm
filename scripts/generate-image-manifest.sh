#!/usr/bin/env bash
# Generate a SignedManifest JSON for a built dev/builder image.
#
# Plan 36 / ADR 005. Output schema must stay in lock-step with
# `crates/mvm-security/src/image_verify.rs::SignedManifest` — both
# sides parse the same JSON, and this script is the only producer.
#
# The mvmctl release pipeline calls this once per (arch, variant) pair
# after building the image. It hashes the artifacts, walks every
# `flake.lock` in the repo, computes a not_after stamp, and emits a
# manifest JSON ready for `cosign sign-blob --bundle`.
#
# Inputs (env vars):
#   ARCH         e.g. "aarch64" or "x86_64"
#   VARIANT      "dev" or "builder"
#   ROOTFS_EXT   "ext4" or "squashfs"
#   STORE_PATH   the Nix store path of the build output
#                (e.g. /nix/store/abc123-mvm-mvm-dev-dev)
#   STAGING_DIR  directory holding the renamed artifacts
#                (`{variant}-vmlinux-{arch}`, `{variant}-rootfs-{arch}.{ext}`)
#   VERSION      version string without the leading `v`
#                (e.g. "0.14.0"). Defaults to GITHUB_REF_NAME minus `v`.
#   SOURCE_GIT_SHA  full git sha of the build commit; defaults to GITHUB_SHA.
#   NOT_AFTER_DAYS  optional integer (default 90); manifest's max-age window.
#
# Output:
#   Writes `${VARIANT}-image-${ARCH}.manifest.json` into STAGING_DIR.
#   Prints the path on stdout.

set -euo pipefail

: "${ARCH:?ARCH must be set}"
: "${VARIANT:?VARIANT must be set}"
: "${ROOTFS_EXT:?ROOTFS_EXT must be set}"
: "${STORE_PATH:?STORE_PATH must be set}"
: "${STAGING_DIR:?STAGING_DIR must be set}"

case "${VARIANT}" in
  dev|builder) ;;
  *) echo "VARIANT must be 'dev' or 'builder' (got '${VARIANT}')" >&2; exit 2 ;;
esac

case "${ROOTFS_EXT}" in
  ext4|squashfs) ;;
  *) echo "ROOTFS_EXT must be 'ext4' or 'squashfs' (got '${ROOTFS_EXT}')" >&2; exit 2 ;;
esac

VERSION="${VERSION:-${GITHUB_REF_NAME:-}}"
VERSION="${VERSION#v}"
if [ -z "${VERSION}" ]; then
  echo "VERSION (or GITHUB_REF_NAME) must be set to the release version" >&2
  exit 2
fi

SOURCE_GIT_SHA="${SOURCE_GIT_SHA:-${GITHUB_SHA:-}}"
if [ -z "${SOURCE_GIT_SHA}" ]; then
  echo "SOURCE_GIT_SHA (or GITHUB_SHA) must be set" >&2
  exit 2
fi

NOT_AFTER_DAYS="${NOT_AFTER_DAYS:-90}"

KERNEL_NAME="${VARIANT}-vmlinux-${ARCH}"
ROOTFS_NAME="${VARIANT}-rootfs-${ARCH}.${ROOTFS_EXT}"

if [ ! -f "${STAGING_DIR}/${KERNEL_NAME}" ] || [ ! -f "${STAGING_DIR}/${ROOTFS_NAME}" ]; then
  echo "Expected artifacts in ${STAGING_DIR}: ${KERNEL_NAME}, ${ROOTFS_NAME}" >&2
  ls -la "${STAGING_DIR}" >&2 || true
  exit 2
fi

KERNEL_SHA=$(cd "${STAGING_DIR}" && sha256sum "${KERNEL_NAME}" | awk '{print $1}')
ROOTFS_SHA=$(cd "${STAGING_DIR}" && sha256sum "${ROOTFS_NAME}" | awk '{print $1}')

# Extract the input-addressed hash from a Nix store path:
# /nix/store/<hash>-name → <hash>
NIX_STORE_HASH=$(basename "${STORE_PATH}" | cut -d- -f1)

BUILT_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# GNU date and BSD/macOS date have different `+N days` syntax. Try both.
NOT_AFTER=$(date -u -d "+${NOT_AFTER_DAYS} days" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
  || date -u -v"+${NOT_AFTER_DAYS}d" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
  || { echo "could not compute not_after; date(1) syntax incompatible" >&2; exit 1; })

# Walk every flake.lock in the repo, hash its content, build a {path: sha256:...} object.
# Skip target/, .git/, node_modules/, and any worktree caches.
FLAKE_LOCKS=$(
  find . -name flake.lock \
    -not -path './target/*' \
    -not -path './.git/*' \
    -not -path './node_modules/*' \
    -not -path './.claude/*' \
    -not -path './*/resources/template_scaffold/*' \
    -not -path './resources/template_scaffold/*' \
    | sort \
    | while read -r f; do
        rel="${f#./}"
        h=$(sha256sum "${f}" | awk '{print $1}')
        jq -n --arg path "${rel}" --arg sha "sha256:${h}" '{($path): $sha}'
      done \
    | jq -s 'add // {}'
)

OUT="${STAGING_DIR}/${VARIANT}-image-${ARCH}.manifest.json"
jq -n \
  --argjson schema_version 1 \
  --arg version "${VERSION}" \
  --arg arch "${ARCH}" \
  --arg variant "${VARIANT}" \
  --arg rootfs_format "${ROOTFS_EXT}" \
  --arg kernel_name "${KERNEL_NAME}" \
  --arg kernel_sha "${KERNEL_SHA}" \
  --arg rootfs_name "${ROOTFS_NAME}" \
  --arg rootfs_sha "${ROOTFS_SHA}" \
  --arg nix_store_hash "${NIX_STORE_HASH}" \
  --arg source_git_sha "${SOURCE_GIT_SHA}" \
  --argjson flake_locks "${FLAKE_LOCKS}" \
  --arg built_at "${BUILT_AT}" \
  --arg not_after "${NOT_AFTER}" \
  '{
    schema_version: $schema_version,
    version: $version,
    arch: $arch,
    variant: $variant,
    rootfs_format: $rootfs_format,
    artifacts: [
      {name: $kernel_name, sha256: $kernel_sha},
      {name: $rootfs_name, sha256: $rootfs_sha}
    ],
    nix_store_hash: $nix_store_hash,
    source_git_sha: $source_git_sha,
    flake_locks: $flake_locks,
    addressed_advisories: [],
    built_at: $built_at,
    not_after: $not_after
  }' > "${OUT}"

echo "${OUT}"
