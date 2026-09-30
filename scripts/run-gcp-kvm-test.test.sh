#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fake_bin="$repo_root/tests/fixtures/cve-gcloud-bin"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/mvm-gcp-kvm-test.XXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT

run_case() {
  name="$1"
  expected_status="$2"
  create_status="$3"
  upload_status="$4"
  remote_status="$5"
  download_status="$6"
  expected_deletes="$7"
  case_dir="$scratch/$name"
  mkdir -p "$case_dir/results"
  log="$case_dir/gcloud.log"
  output="$case_dir/output.log"

  set +e
  PATH="$fake_bin:$PATH" \
    MVM_CVE_FAKE_LOG="$log" \
    MVM_CVE_FAKE_CREATE_STATUS="$create_status" \
    MVM_CVE_FAKE_UPLOAD_STATUS="$upload_status" \
    MVM_CVE_FAKE_REMOTE_STATUS="$remote_status" \
    MVM_CVE_FAKE_DOWNLOAD_STATUS="$download_status" \
    bash "$repo_root/scripts/run-gcp-kvm-test.sh" \
      --project test-project \
      --zone us-central1-a \
      --results-dir "$case_dir/results" \
      -- printf '%s\n' 'argument with spaces' '; touch /tmp/not-executed' \
      >"$output" 2>&1
  actual_status=$?
  set -e

  [[ "$actual_status" -eq "$expected_status" ]] || {
    printf '%s: expected status %s, got %s\n' "$name" "$expected_status" "$actual_status" >&2
    sed -n '1,200p' "$output" >&2
    exit 1
  }
  actual_deletes="$(grep -c '^compute instances delete ' "$log" || true)"
  [[ "$actual_deletes" -eq "$expected_deletes" ]] || {
    printf '%s: expected %s instance deletions, got %s\n' \
      "$name" "$expected_deletes" "$actual_deletes" >&2
    sed -n '1,200p' "$log" >&2
    exit 1
  }
  grep -q -- '--no-service-account' "$log"
  grep -q -- '--no-scopes' "$log"
  grep -q -- '--metadata=block-project-ssh-keys=true' "$log"
}

run_case success 0 0 0 0 0 1
run_case create-failure 13 13 0 0 0 0
run_case upload-failure 17 0 17 0 0 1
run_case remote-failure 23 0 0 23 0 1
run_case results-failure 1 0 0 0 29 1

argv_log="$scratch/success/gcloud.log.argv"
grep -Fxq 'printf' "$argv_log"
grep -Fxq '%s\n' "$argv_log"
grep -Fxq 'argument with spaces' "$argv_log"
grep -Fxq '; touch /tmp/not-executed' "$argv_log"

set +e
PATH="$fake_bin:$PATH" MVM_CVE_FAKE_LOG="$scratch/missing.log" \
  bash "$repo_root/scripts/run-gcp-kvm-test.sh" --project test-project \
  >"$scratch/missing.out" 2>&1
missing_status=$?
PATH="$fake_bin:$PATH" MVM_CVE_FAKE_LOG="$scratch/name.log" \
  bash "$repo_root/scripts/run-gcp-kvm-test.sh" --project test-project \
    --run-name 'INVALID/name' -- true >"$scratch/name.out" 2>&1
name_status=$?
set -e
[[ "$missing_status" -eq 64 ]]
grep -Fq "PROGRAM is required after '--'" "$scratch/missing.out"
[[ "$name_status" -eq 64 ]]
grep -Fq -- '--run-name must be' "$scratch/name.out"

runner="$repo_root/scripts/run-gcp-kvm-test.sh"
grep -Fq 'git -C "$repo_root" ls-files -z' "$runner"
grep -Fq -- '--from0 --files-from="$tracked_files"' "$runner"
grep -Fq 'COPYFILE_DISABLE=1 tar' "$runner"
remote_runner="$repo_root/scripts/run-gcp-kvm-test-remote.sh"
grep -Fq 'selecting the canonical Ubuntu archive mirror' "$remote_runner"
grep -Fq 'archive.ubuntu.com/ubuntu' "$remote_runner"
grep -Fq 'firecracker_sha256=06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558' "$remote_runner"
grep -Fq '| sha256sum -c -' "$remote_runner"

echo "disposable GCP KVM runner lifecycle tests passed"
