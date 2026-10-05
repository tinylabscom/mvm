#!/usr/bin/env bash
# Run one repository test command on a disposable Google Cloud Spot VM with
# nested KVM. Only git-tracked files from the current checkout are uploaded,
# results are
# downloaded, and the VM is deleted on every exit unless explicitly retained.
set -euo pipefail

usage() {
  printf '%s\n' \
    'usage: scripts/run-gcp-kvm-test.sh [options] -- PROGRAM [ARG ...]' \
    '' \
    'Options:' \
    '  --project PROJECT       GCP project (default: active gcloud project)' \
    '  --zone ZONE             GCP zone (default: us-central1-a)' \
    '  --machine-type TYPE     Compute Engine type (default: c3-standard-4)' \
    '  --run-name NAME         Short instance/result label (default: test)' \
    '  --results-dir DIR       Local result destination (default: /tmp/...)' \
    '  --keep-instance         Leave the instance running for diagnosis' \
    '  --dry-run               Validate and print the plan without cloud changes' \
    '  -h, --help              Show this help' \
    '' \
    'PROGRAM and each ARG are transferred without shell interpolation. Invoke' \
    "'bash -lc' explicitly only when shell syntax is required. The remote command" \
    'runs from /opt/mvm with worktree-isolated MVM_HOME and Cargo directories.' \
    "Write retained artifacts to \$MVM_GCP_KVM_RESULTS_DIR."
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project="${MVM_GCP_KVM_PROJECT:-}"
zone="${MVM_GCP_KVM_ZONE:-us-central1-a}"
machine_type="${MVM_GCP_KVM_MACHINE_TYPE:-c3-standard-4}"
run_name="${MVM_GCP_KVM_RUN_NAME:-test}"
keep_instance=0
dry_run=0
results_dir="${MVM_GCP_KVM_RESULTS_DIR:-}"

while (($#)); do
  case "$1" in
    --project)
      [[ $# -ge 2 ]] || { echo "error: --project needs a value" >&2; exit 64; }
      project="$2"
      shift 2
      ;;
    --zone)
      [[ $# -ge 2 ]] || { echo "error: --zone needs a value" >&2; exit 64; }
      zone="$2"
      shift 2
      ;;
    --machine-type)
      [[ $# -ge 2 ]] || { echo "error: --machine-type needs a value" >&2; exit 64; }
      machine_type="$2"
      shift 2
      ;;
    --run-name)
      [[ $# -ge 2 ]] || { echo "error: --run-name needs a value" >&2; exit 64; }
      run_name="$2"
      shift 2
      ;;
    --results-dir|--evidence-dir)
      [[ $# -ge 2 ]] || { echo "error: --results-dir needs a value" >&2; exit 64; }
      results_dir="$2"
      shift 2
      ;;
    --keep-instance)
      keep_instance=1
      shift
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "error: unknown option before '--': $1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

if (($# == 0)); then
  echo "error: PROGRAM is required after '--'" >&2
  usage >&2
  exit 64
fi
remote_command=("$@")

if [[ ! "$run_name" =~ ^[a-z0-9][a-z0-9-]{0,19}$ ]]; then
  echo "error: --run-name must be 1-20 lowercase letters, digits, or hyphens" >&2
  exit 64
fi

for tool in gcloud git rsync tar; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "error: required command '$tool' is not installed" >&2
    exit 1
  }
done

if [[ -z "$project" ]]; then
  project="$(gcloud config get-value project 2>/dev/null)"
fi
if [[ -z "$project" || "$project" == "(unset)" ]]; then
  echo "error: no GCP project; pass --project or run 'gcloud config set project PROJECT'" >&2
  exit 1
fi

account="$(gcloud config get-value account 2>/dev/null)"
if [[ -z "$account" || "$account" == "(unset)" ]]; then
  echo "error: gcloud has no active account; run 'gcloud auth login'" >&2
  exit 1
fi

case "$machine_type" in
  c2-*|c3-*|c4-*|n1-*|n2-*) ;;
  *)
    echo "error: '$machine_type' is not an approved Intel Compute Engine series" >&2
    echo "Use c3-standard-4 unless a reviewed replacement is required." >&2
    exit 1
    ;;
esac

run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
# Compute Engine instance names must be lowercase. `tr` rather than the
# `${var,,}` expansion, which macOS's stock bash 3.2 rejects.
instance="mvm-${run_name}-$(printf '%s' "$run_id" | tr '[:upper:]' '[:lower:]')"
if [[ -z "$results_dir" ]]; then
  results_dir="${TMPDIR:-/tmp}/mvm-gcp-kvm-results/$run_id"
fi
mkdir -p "$results_dir"

create_args=(
  compute instances create "$instance"
  --project="$project"
  --zone="$zone"
  --machine-type="$machine_type"
  --provisioning-model=SPOT
  --instance-termination-action=DELETE
  --maintenance-policy=TERMINATE
  --enable-nested-virtualization
  --no-service-account
  --no-scopes
  --image-family=ubuntu-2404-lts-amd64
  --image-project=ubuntu-os-cloud
  --boot-disk-size=80GB
  --boot-disk-type=pd-balanced
  --metadata=block-project-ssh-keys=true
  "--labels=mvm-purpose=kvm-test,mvm-run=${run_name},mvm-disposable=true"
)

echo "GCP disposable KVM test plan"
echo "  account:       $account"
echo "  project:       $project"
echo "  zone:          $zone"
echo "  machine:       $machine_type (Spot, nested KVM)"
echo "  instance:      $instance"
echo "  results:       $results_dir"
echo "  source:        $repo_root"
printf '  command:'
printf ' %q' "${remote_command[@]}"
printf '\n'

if ((dry_run)); then
  printf '  create command:'
  printf ' %q' gcloud "${create_args[@]}"
  printf '\n'
  exit 0
fi

instance_created=0
local_stage="$(mktemp -d "${TMPDIR:-/tmp}/mvm-gcp-kvm.XXXXXX")"

# Invoked indirectly by the EXIT/INT/TERM trap installed below.
# ShellCheck renamed this diagnostic from SC2317 to SC2329; CI's distro
# version and newer local versions must both understand the suppression.
# shellcheck disable=SC2317,SC2329
cleanup() {
  status=$?
  trap - EXIT INT TERM
  rm -rf -- "$local_stage"
  if ((instance_created)) && ((keep_instance == 0)); then
    echo ">> deleting disposable instance $instance"
    if ! gcloud compute instances delete "$instance" \
      --project="$project" --zone="$zone" --quiet; then
      echo "error: automatic deletion failed; delete $instance manually" >&2
      printf '  gcloud compute instances delete %q --project=%q --zone=%q --quiet\n' \
        "$instance" "$project" "$zone" >&2
      status=1
    fi
  elif ((instance_created)); then
    echo "warning: --keep-instance left $instance running and billable" >&2
    printf '  access: gcloud compute ssh %q --project=%q --zone=%q\n' \
      "$instance" "$project" "$zone" >&2
    printf '  delete: gcloud compute instances delete %q --project=%q --zone=%q --quiet\n' \
      "$instance" "$project" "$zone" >&2
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo ">> creating the Spot instance"
gcloud "${create_args[@]}"
instance_created=1

# Compute RUNNING does not mean the independently owned guest sshd is ready.
# Google exposes no sshd-ready event, so reconcile it at most five times with
# a bounded, escalating delay.
ssh_ready=0
delays=(0 5 10 20 40)
for delay in "${delays[@]}"; do
  if ((delay)); then
    sleep "$delay"
  fi
  if gcloud compute ssh "$instance" --project="$project" --zone="$zone" \
    --quiet --ssh-flag=-oConnectTimeout=10 --command=true >/dev/null 2>&1; then
    ssh_ready=1
    break
  fi
done
if ((ssh_ready == 0)); then
  echo "error: $instance never accepted SSH after five bounded probes" >&2
  exit 1
fi

echo ">> preparing a tracked-source archive and exact command argv"
mkdir -p "$local_stage/tree"
tracked_files="$local_stage/tracked-files.nul"
git -C "$repo_root" ls-files -z >"$tracked_files"
if [[ ! -s "$tracked_files" ]]; then
  echo "error: repository tracked-file allowlist is empty" >&2
  exit 1
fi
rsync -a --from0 --files-from="$tracked_files" \
  "$repo_root/" "$local_stage/tree/"
# macOS libarchive otherwise emits AppleDouble `._*` entries for source-file
# extended attributes; those look like feature files to the Linux BDD parser.
COPYFILE_DISABLE=1 tar -C "$local_stage" -czf "$local_stage/mvm-source.tar.gz" tree
printf '%s\0' "${remote_command[@]}" >"$local_stage/mvm-command.argv"

gcloud compute scp \
  "$local_stage/mvm-source.tar.gz" "$local_stage/mvm-command.argv" \
  "$instance:/tmp/" --project="$project" --zone="$zone" --quiet

echo ">> preparing the host and running the requested test"
set +e
gcloud compute ssh "$instance" --project="$project" --zone="$zone" --quiet \
  --command='sudo rm -rf /opt/mvm && sudo mkdir -p /opt/mvm && sudo tar -xzf /tmp/mvm-source.tar.gz -C /opt/mvm --strip-components=1 && sudo bash /opt/mvm/scripts/run-gcp-kvm-test-remote.sh /tmp/mvm-command.argv'
run_status=$?
set -e

echo ">> downloading the result bundle"
set +e
gcloud compute scp "$instance:/var/tmp/mvm-gcp-kvm-results.tar.gz" \
  "$results_dir/" --project="$project" --zone="$zone" --quiet
copy_status=$?
set -e
if ((copy_status != 0)); then
  echo "error: remote run status $run_status and result download failed" >&2
  exit 1
fi

echo "results: $results_dir/mvm-gcp-kvm-results.tar.gz"
if ((run_status != 0)); then
  echo "remote test did not pass; inspect the downloaded result bundle" >&2
fi
exit "$run_status"
