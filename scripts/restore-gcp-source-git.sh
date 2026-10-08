#!/usr/bin/env bash
# Restore the public commit identity for a tracked-files-only GCP upload.
# A mixed reset populates Git's index without touching the uploaded tree.
set -euo pipefail

source_root=${1:?source root is required}
identity_file=${2:?source identity file is required}
remote=${3:?source remote is required}

if [[ -e "$source_root/.git" ]]; then
  echo 'error: source already has Git metadata' >&2
  exit 1
fi

source_commit=$(cat "$identity_file")
if [[ ! "$source_commit" =~ ^[0-9a-f]{40}$ ]]; then
  echo 'error: invalid source commit' >&2
  exit 1
fi

cleanup_on_failure() {
  status=$?
  trap - EXIT
  if ((status != 0)); then
    rm -rf -- "$source_root/.git"
  fi
  exit "$status"
}
trap cleanup_on_failure EXIT

git -C "$source_root" init --quiet
git -C "$source_root" fetch --quiet --depth=1 "$remote" "$source_commit"
fetched_commit=$(git -C "$source_root" rev-parse --verify 'FETCH_HEAD^{commit}')
if [[ "$fetched_commit" != "$source_commit" ]]; then
  echo 'error: fetched source commit differs from the requested identity' >&2
  exit 1
fi
git -C "$source_root" reset --quiet --mixed "$source_commit"
echo "verified source commit: $source_commit"
