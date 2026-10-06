#!/usr/bin/env bash
# Refuse to publish crates from a tree that cannot produce a coherent
# crates.io release. publish-crates.yml runs it before any `cargo package` or
# `cargo publish`.
#
#   deploy-guard.sh [tag]
#
# With a tag (a real publish, or a dry run of one), the tree must be exactly
# that tag: `cargo publish` uploads the working tree, so a dirty or shifted
# checkout would put bytes nobody tagged under the tag's version. The
# workspace version must equal the tag's, because every published crate
# inherits it and claims to be that release.
#
# Always, the manifests must pass `xtask check-publish-readiness`: the
# publish order, the metadata crates.io requires, and no crate reading source
# from outside its own directory. That gate is what makes the plan the
# workflow publishes from trustworthy, so it runs here as well as in CI lint.
set -euo pipefail

tag="${1:-}"
fail() { echo "deploy-guard: $*" >&2; exit 1; }

if [ ! -f Cargo.toml ] || [ ! -d xtask ]; then fail "run from the workspace root"; fi

if [ -n "$(git status --porcelain)" ]; then
  git status --porcelain >&2
  fail "the working tree is dirty; cargo publish would upload uncommitted bytes"
fi

if [ -n "${tag}" ]; then
  tag_commit="$(git rev-parse --verify --quiet "refs/tags/${tag}^{commit}")" \
    || fail "tag ${tag} does not exist"
  head_commit="$(git rev-parse HEAD)"
  [ "${head_commit}" = "${tag_commit}" ] \
    || fail "HEAD ${head_commit} is not ${tag} (${tag_commit})"

  workspace_version="$(cargo metadata --no-deps --format-version 1 \
    | jq -r '.packages[] | select(.name == "mvmctl") | .version')"
  [ -n "${workspace_version}" ] || fail "could not read the workspace version"
  [ "${tag#v}" = "${workspace_version}" ] \
    || fail "tag ${tag} does not match the workspace version ${workspace_version}"
fi

cargo run --quiet --package xtask -- check-publish-readiness
echo "deploy-guard: ok${tag:+ for ${tag}}"
